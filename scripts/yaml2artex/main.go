// Command yaml2artex converts a CyberStrikeAI tools/*.yaml tree into ARTEX
// built-in command recipes (db/toolrecipes.json).
//
// It is a development tool, not part of the server. Run it whenever the upstream
// recipe set changes:
//
//	go run ./scripts/yaml2artex -src ../CyberStrikeAI/tools -dst db/toolrecipes.json
//
// Mapping notes:
//   - `command` + `args` become the literal prefix of the shell template.
//   - a required parameter becomes `{name}` (always rendered, shell-quoted).
//   - an optional parameter becomes `{{#name}}...{{/name}}`, which ARTEX's
//     renderTemplate drops entirely when the param is absent — otherwise every
//     omitted optional flag would render as `-s ''`.
//   - `additional_args` / `scan_type` free-text escape hatches are dropped: ARTEX
//     shell-quotes every placeholder, so a multi-token free-text slot would reach
//     the shell as ONE quoted argument. Explicit typed flags are the point here.
//   - parameters whose flag is missing and position is unknown are dropped rather
//     than emitted as a dangling token.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type paramYAML struct {
	Name        string   `yaml:"name"`
	Type        string   `yaml:"type"`
	Description string   `yaml:"description"`
	Required    bool     `yaml:"required"`
	Default     any      `yaml:"default"`
	Flag        string   `yaml:"flag"`
	Position    *int     `yaml:"position"`
	Format      string   `yaml:"format"`
	Template    string   `yaml:"template"`
	Options     []string `yaml:"options"`
}

type toolYAML struct {
	Name             string      `yaml:"name"`
	Command          string      `yaml:"command"`
	Enabled          bool        `yaml:"enabled"`
	ShortDescription string      `yaml:"short_description"`
	Description      string      `yaml:"description"`
	Args             []string    `yaml:"args"`
	Parameters       []paramYAML `yaml:"parameters"`
}

// recipe mirrors db.Recipe.
type recipe struct {
	Key         string          `json:"key"`
	Description string          `json:"description"`
	Schema      json.RawMessage `json:"schema"`
	Exec        json.RawMessage `json:"exec"`
	Agents      []string        `json:"agents"`
	Deferred    bool            `json:"deferred"`
}

// coreTools stay non-deferred: their schemas ship in the agent's tool block.
// Everything else is deferred and pulled in on demand via SearchExtraTools, so the
// worker's prompt doesn't carry 90 tool schemas.
var coreTools = map[string]bool{
	"nuclei": true, "ffuf": true, "feroxbuster": true, "dirsearch": true,
	"gobuster": true, "katana": true, "gau": true, "waybackurls": true,
	"paramspider": true, "arjun": true, "x8": true, "dalfox": true,
	"sqlmap": true, "nikto": true, "wpscan": true, "nmap": true,
	"subfinder": true, "amass": true, "wafw00f": true, "jwt-analyzer": true,
	"graphql-scanner": true, "http-framework-test": true, "api-schema-analyzer": true,
	"dnsenum": true, "fierce": true, "jaeles": true, "dotdotpwn": true,
}

// skippedTools have no useful recipe form in ARTEX: the platform already exposes
// Bash, create_custom_tool / update_custom_tool and the traffic tools. The last two
// embed an entire Python program as their `command`, which belongs in a script file
// (or a script-kind custom tool), not in a tool template.
var skippedTools = map[string]bool{
	"exec": true, "execute-python-script": true, "install-python-package": true,
	"query-execution-result": true, "query_execution_result": true,
	"http-framework-test": true, "dnslog": true,
}

// maxCommandLen rejects recipes whose `command` is really an embedded script. A tool
// template has no business being kilobyes long: it bloats every prompt that lists
// the tool and is impossible to audit.
const maxCommandLen = 1500

// droppedParams are free-text escape hatches that cannot survive shell-quoting of
// placeholders (see the package comment).
var droppedParams = map[string]bool{"additional_args": true, "scan_type": true}

// longRunning get a longer per-call timeout than the 180s default.
var longRunning = map[string]bool{
	"nmap": true, "masscan": true, "rustscan": true, "nuclei": true,
	"ffuf": true, "feroxbuster": true, "dirsearch": true, "gobuster": true,
	"sqlmap": true, "nikto": true, "wpscan": true, "jaeles": true,
	"katana": true, "amass": true, "subfinder": true, "fscan": true,
	"hydra": true, "john": true, "hashcat": true, "zap": true,
	"prowler": true, "trivy": true, "checkov": true, "scout-suite": true,
	"volatility3": true, "ghidra": true, "radare2": true, "angr": true,
}

func main() {
	src := flag.String("src", "../CyberStrikeAI/tools", "directory of CyberStrikeAI tool YAML files")
	dst := flag.String("dst", "db/toolrecipes.json", "output JSON path")
	flag.Parse()

	entries, err := os.ReadDir(*src)
	if err != nil {
		log.Fatalf("read %s: %v", *src, err)
	}

	var out []recipe
	var skipped []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".yaml") {
			continue
		}
		path := filepath.Join(*src, e.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			log.Printf("skip %s: %v", e.Name(), err)
			continue
		}
		var t toolYAML
		if err := yaml.Unmarshal(raw, &t); err != nil {
			log.Printf("skip %s: bad yaml: %v", e.Name(), err)
			continue
		}
		if t.Name == "" || t.Command == "" || !t.Enabled {
			skipped = append(skipped, t.Name+" (disabled/incomplete)")
			continue
		}
		if skippedTools[t.Name] {
			skipped = append(skipped, t.Name+" (replaced by platform tools)")
			continue
		}
		r, err := convert(t)
		if err != nil {
			log.Printf("skip %s: %v", t.Name, err)
			continue
		}
		var ex struct {
			Command string `json:"command"`
		}
		_ = json.Unmarshal(r.Exec, &ex)
		// "internal:<handler>" is not a shell command — it names a host-side handler
		// in the source project. Running it here would just fail as "command not found".
		if strings.HasPrefix(strings.TrimSpace(ex.Command), "internal:") {
			skipped = append(skipped, t.Name+" (internal host handler, not a shell command)")
			continue
		}
		// Inline interpreter invocations (`python3 -c <script>`) are emulations, not
		// real tool wrappers: they embed code, break the placeholder rules, and give
		// the model nothing better than plain Bash.
		if isInlineInterpreter(ex.Command) {
			skipped = append(skipped, t.Name+" (inline interpreter script, not a tool wrapper)")
			continue
		}
		if len(ex.Command) > maxCommandLen {
			skipped = append(skipped, fmt.Sprintf("%s (command is %d bytes — an embedded script, not a template)", t.Name, len(ex.Command)))
			continue
		}
		out = append(out, r)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	blob, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		log.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(*dst, append(blob, '\n'), 0o644); err != nil {
		log.Fatalf("write %s: %v", *dst, err)
	}
	for _, s := range skipped {
		fmt.Println("skipped:", s)
	}
	fmt.Printf("wrote %d recipes → %s\n", len(out), *dst)
}

func convert(t toolYAML) (recipe, error) {
	var cmd strings.Builder
	cmd.WriteString(t.Command)
	for _, a := range t.Args {
		cmd.WriteString(" ")
		cmd.WriteString(a)
	}

	props := map[string]any{}
	var required []string

	// Positional params must be emitted in position order, after the named flags.
	type positional struct {
		pos   int
		param string // schema/template name, used for the {{#name}} group tag
		frag  string // shell text, e.g. "{mode}"
		req   bool
	}
	var positionals []positional

	for _, p := range t.Parameters {
		name := strings.TrimSpace(p.Name)
		if name == "" || droppedParams[name] {
			continue
		}
		typ, enum := jsonType(p)
		prop := map[string]any{"type": typ, "description": paramDesc(p)}
		if enum != nil {
			prop["enum"] = enum
		}
		if p.Default != nil {
			prop["default"] = p.Default
		}
		props[name] = prop
		if p.Required {
			required = append(required, name)
		}

		frag, positionalOnly := fragment(p)
		if frag == "" {
			continue
		}
		if positionalOnly {
			pos := len(positionals)
			if p.Position != nil {
				pos = *p.Position
			}
			positionals = append(positionals, positional{pos: pos, param: name, frag: frag, req: p.Required})
			continue
		}
		cmd.WriteString(" ")
		if p.Required {
			cmd.WriteString(frag)
		} else {
			cmd.WriteString("{{#" + name + "}}" + frag + "{{/" + name + "}}")
		}
	}

	sort.SliceStable(positionals, func(i, j int) bool { return positionals[i].pos < positionals[j].pos })
	for _, p := range positionals {
		cmd.WriteString(" ")
		if p.req {
			cmd.WriteString(p.frag)
		} else {
			cmd.WriteString("{{#" + p.param + "}}" + p.frag + "{{/" + p.param + "}}")
		}
	}

	schema := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		schema["required"] = required
	}
	schemaJSON, err := json.Marshal(schema)
	if err != nil {
		return recipe{}, err
	}

	timeout := 180000
	if longRunning[t.Name] {
		timeout = 600000
	}
	execJSON, err := json.Marshal(map[string]any{
		"command":    cmd.String(),
		"timeout_ms": timeout,
	})
	if err != nil {
		return recipe{}, err
	}

	return recipe{
		Key:         t.Name,
		Description: describe(t),
		Schema:      schemaJSON,
		Exec:        execJSON,
		Agents:      []string{"worker", "pentest"},
		Deferred:    !coreTools[t.Name],
	}, nil
}

// fragment renders one parameter into shell-template text. positionalOnly means the
// caller should place it by position rather than inline.
func fragment(p paramYAML) (frag string, positionalOnly bool) {
	format := strings.ToLower(strings.TrimSpace(p.Format))
	switch format {
	case "positional":
		return "{" + p.Name + "}", true
	case "combined":
		if p.Flag == "" {
			return "", false
		}
		return p.Flag + "={" + p.Name + "}", false
	case "template":
		if p.Template == "" {
			return "", false
		}
		s := strings.ReplaceAll(p.Template, "{flag}", p.Flag)
		return strings.ReplaceAll(s, "{value}", "{"+p.Name+"}"), false
	default: // "flag" or unset
		if p.Flag == "" {
			if p.Position != nil {
				return "{" + p.Name + "}", true
			}
			return "", false // no flag, no position → unusable
		}
		// A boolean switch takes no value: emit the bare flag, and let the
		// conditional group drop it when the model passes false. Without this,
		// `-O true` / `--batch true` reaches the tool as a bogus extra argument.
		if isBoolType(p.Type) {
			return p.Flag, false
		}
		return p.Flag + " {" + p.Name + "}", false
	}
}

func isBoolType(t string) bool {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "bool", "boolean":
		return true
	}
	return false
}

func jsonType(p paramYAML) (typ string, enum []string) {
	switch strings.ToLower(strings.TrimSpace(p.Type)) {
	case "int", "integer", "number":
		typ = "integer"
	case "bool", "boolean":
		typ = "boolean"
	case "array", "list":
		typ = "array"
	default:
		typ = "string"
	}
	if len(p.Options) > 0 && typ == "string" {
		enum = p.Options
	}
	return typ, enum
}

func paramDesc(p paramYAML) string {
	d := strings.TrimSpace(p.Description)
	if d == "" {
		d = p.Name
	}
	return d
}

func describe(t toolYAML) string {
	short := strings.TrimSpace(t.ShortDescription)
	body := strings.TrimSpace(t.Description)
	if short == "" {
		short = firstLine(body)
	}
	if body == "" || body == short {
		return short
	}
	if len([]rune(body)) > 700 {
		body = string([]rune(body)[:700]) + "…"
	}
	return short + "\n\n" + body
}

func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if l := strings.TrimSpace(line); l != "" {
			return l
		}
	}
	return ""
}

// isInlineInterpreter reports whether the command is an interpreter invoked with
// `-c`/`-e` and an inline program, rather than a real scanner binary.
func isInlineInterpreter(cmd string) bool {
	f := strings.Fields(cmd)
	if len(f) < 2 {
		return false
	}
	bin := strings.ToLower(filepath.Base(f[0]))
	switch bin {
	case "python", "python3", "python2", "perl", "ruby", "node", "sh", "bash", "pwsh", "powershell":
	default:
		return false
	}
	for _, a := range f[1:] {
		if a == "-c" || a == "-e" {
			return true
		}
	}
	return false
}
