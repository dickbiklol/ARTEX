package db

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestEmbeddedRecipesAreWellFormed guards db/toolrecipes.json, which is generated
// by scripts/yaml2artex and embedded into the binary. A broken row here would ship
// a tool that either can't be called or calls the wrong command line, and the
// failure would only show up at runtime on a target.
func TestEmbeddedRecipesAreWellFormed(t *testing.T) {
	recipes, err := ToolRecipes()
	if err != nil {
		t.Fatalf("ToolRecipes: %v", err)
	}
	if len(recipes) == 0 {
		t.Fatal("no recipes embedded")
	}

	seen := map[string]bool{}
	for _, r := range recipes {
		if r.Key == "" {
			t.Error("recipe with empty key")
			continue
		}
		if seen[r.Key] {
			t.Errorf("duplicate recipe key %q", r.Key)
		}
		seen[r.Key] = true

		if strings.TrimSpace(r.Description) == "" {
			t.Errorf("%s: empty description", r.Key)
		}

		var exec struct {
			Command   string `json:"command"`
			TimeoutMs int    `json:"timeout_ms"`
		}
		if err := json.Unmarshal(r.Exec, &exec); err != nil {
			t.Errorf("%s: bad exec spec: %v", r.Key, err)
			continue
		}
		if strings.TrimSpace(exec.Command) == "" {
			t.Errorf("%s: empty command", r.Key)
		}
		if strings.HasPrefix(strings.TrimSpace(exec.Command), "{") {
			t.Errorf("%s: command starts with a placeholder: %q", r.Key, exec.Command)
		}
		if exec.TimeoutMs <= 0 {
			t.Errorf("%s: timeout_ms must be positive, got %d", r.Key, exec.TimeoutMs)
		}

		var schema struct {
			Type       string                    `json:"type"`
			Properties map[string]json.RawMessage `json:"properties"`
			Required   []string                  `json:"required"`
		}
		if err := json.Unmarshal(r.Schema, &schema); err != nil {
			t.Errorf("%s: bad schema: %v", r.Key, err)
			continue
		}
		if schema.Type != "object" {
			t.Errorf("%s: schema type = %q, want object", r.Key, schema.Type)
		}
		for _, req := range schema.Required {
			if _, ok := schema.Properties[req]; !ok {
				t.Errorf("%s: required param %q missing from properties", r.Key, req)
			}
			// A required param must actually appear in the command line.
			if !strings.Contains(exec.Command, "{"+req+"}") {
				t.Errorf("%s: required param %q never appears in command %q", r.Key, req, exec.Command)
			}
		}
		for name := range schema.Properties {
			// A param is "used" if it appears as a value placeholder or as a
			// conditional group. Boolean switches render the bare flag inside the
			// group ({{#extract}}-e{{/extract}}), so only the group tag mentions
			// the name — checking for "{name}" alone would false-positive.
			if !strings.Contains(exec.Command, "{"+name+"}") && !strings.Contains(exec.Command, "{{#"+name+"}}") {
				t.Errorf("%s: schema declares %q but the command never uses it: %q", r.Key, name, exec.Command)
			}
		}
		if len(r.Agents) == 0 {
			t.Errorf("%s: no agent binding (would be unreachable)", r.Key)
		}
	}
}
