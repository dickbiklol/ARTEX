package server

import (
	"strings"
	"testing"
)

// TestRenderTemplateConditionalGroups covers the {{#name}}...{{/name}} form used by
// the seeded command recipes: an omitted optional param must remove its flag, not
// leave "-s ''" behind.
func TestRenderTemplateConditionalGroups(t *testing.T) {
	cases := []struct {
		name   string
		tmpl   string
		params map[string]any
		want   string
	}{
		{
			name:   "required placeholder quoted",
			tmpl:   "nuclei -u {target}",
			params: map[string]any{"target": "https://a/b", "severity": nil},
			want:   "nuclei -u 'https://a/b'",
		},
		{
			name:   "optional absent drops flag",
			tmpl:   "nuclei -u {target} {{#severity}}-s {severity}{{/severity}}",
			params: map[string]any{"target": "https://a"},
			want:   "nuclei -u 'https://a' ",
		},
		{
			name:   "optional empty string drops flag",
			tmpl:   "nuclei -u {target} {{#severity}}-s {severity}{{/severity}}",
			params: map[string]any{"target": "https://a", "severity": "  "},
			want:   "nuclei -u 'https://a' ",
		},
		{
			name:   "optional present keeps flag",
			tmpl:   "nuclei -u {target} {{#severity}}-s {severity}{{/severity}}",
			params: map[string]any{"target": "https://a", "severity": "high,critical"},
			want:   "nuclei -u 'https://a' -s 'high,critical'",
		},
		{
			name:   "two groups independent",
			tmpl:   "ffuf -u {url} {{#wordlist}}-w {wordlist}{{/wordlist}}{{#filter}}-fs {filter}{{/filter}}",
			params: map[string]any{"url": "https://a/FUZZ", "filter": "1234"},
			want:   "ffuf -u 'https://a/FUZZ' -fs '1234'",
		},
		{
			name:   "quotes inside value escaped",
			tmpl:   "curl -d {body}",
			params: map[string]any{"body": "a'b"},
			want:   `curl -d 'a'\''b'`,
		},
		{
			name:   "malformed group left intact",
			tmpl:   "x {{#open",
			params: map[string]any{},
			want:   "x {{#open",
		},
		{
			name:   "legacy args shell unchanged",
			tmpl:   "sqlmap {args}",
			params: map[string]any{"args": "-u http://t/?id=1 --batch"},
			want:   "sqlmap '-u http://t/?id=1 --batch'",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := renderTemplate(tc.tmpl, tc.params, shellQuote)
			if got != tc.want {
				t.Fatalf("renderTemplate()\n got: %q\nwant: %q", got, tc.want)
			}
			// Malformed markup is intentionally passed through, so only assert
			// full resolution when the expected output has no group tags either.
			if !strings.Contains(tc.want, "{{#") && (strings.Contains(got, "{{#") || strings.Contains(got, "{{/")) {
				t.Fatalf("unresolved conditional group left in %q", got)
			}
		})
	}
}
