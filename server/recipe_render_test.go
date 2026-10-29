package server

import (
	"encoding/json"
	"strings"
	"testing"

	pgdb "github.com/Autumn-27/artex/db"
)

// TestRecipeCommandsRender renders every seeded recipe the way runCommandTool will:
// dummy values for the required params, nothing for the optional ones. It catches
// the two ways a generated template breaks at runtime — an unresolved {{#…}} group
// reaching the shell, and an omitted optional flag rendering as `-s ''`.
func TestRecipeCommandsRender(t *testing.T) {
	recipes, err := pgdb.ToolRecipes()
	if err != nil {
		t.Fatalf("ToolRecipes: %v", err)
	}

	for _, r := range recipes {
		t.Run(r.Key, func(t *testing.T) {
			var exec struct {
				Command string `json:"command"`
			}
			if err := json.Unmarshal(r.Exec, &exec); err != nil {
				t.Fatalf("exec: %v", err)
			}
			var schema struct {
				Properties map[string]struct {
					Type string `json:"type"`
				} `json:"properties"`
				Required []string `json:"required"`
			}
			if err := json.Unmarshal(r.Schema, &schema); err != nil {
				t.Fatalf("schema: %v", err)
			}

			params := map[string]any{}
			for _, name := range schema.Required {
				switch schema.Properties[name].Type {
				case "integer":
					params[name] = 1
				case "boolean":
					params[name] = true
				default:
					params[name] = "1.2.3.4:80"
				}
			}

			// Required-only pass: every optional group must vanish.
			got := renderTemplate(exec.Command, params, shellQuote)
			assertRenderedOK(t, r.Key, got)

			// All-params pass: every declared param supplied, so nothing may be left
			// unrendered even in the branch the first pass skipped.
			all := map[string]any{}
			for name, prop := range schema.Properties {
				switch prop.Type {
				case "integer":
					all[name] = 1
				case "boolean":
					all[name] = true
				case "array":
					all[name] = []any{"x"}
				default:
					all[name] = "1.2.3.4:80"
				}
			}
			got = renderTemplate(exec.Command, all, shellQuote)
			assertRenderedOK(t, r.Key, got)
			if strings.Contains(got, "''") {
				t.Errorf("%s: rendered command contains an empty quoted arg: %q", r.Key, got)
			}
		})
	}
}

func assertRenderedOK(t *testing.T, key, cmd string) {
	t.Helper()
	if strings.Contains(cmd, "{{") || strings.Contains(cmd, "}}") {
		t.Errorf("%s: unresolved template group: %q", key, cmd)
	}
	if strings.Contains(cmd, "{") || strings.Contains(cmd, "}") {
		t.Errorf("%s: unresolved placeholder: %q", key, cmd)
	}
	if strings.Contains(cmd, "''") {
		t.Errorf("%s: empty quoted argument (dangling optional flag): %q", key, cmd)
	}
	if strings.TrimSpace(cmd) == "" {
		t.Errorf("%s: rendered to empty command", key)
	}
}
