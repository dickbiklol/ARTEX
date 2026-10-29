package agent

import (
	"strings"
	"testing"
)

// TestBatchRenderTemplate pins the rule that every swept intent names its target.
// A sweep whose summaries are identical ("查一下 IDOR") is unreadable in the graph
// and unclaimable in a useful way, so a template without the placeholder must still
// get the asset appended.
func TestBatchRenderTemplate(t *testing.T) {
	cases := []struct {
		name  string
		tmpl  string
		label string
		id    int64
		want  []string // substrings that must all be present
		notIn []string // substrings that must be absent
	}{
		{
			name:  "asset placeholder",
			tmpl:  "测 {asset} 的 IDOR：替换 id 遍历",
			label: "https://a.example.com/api/user",
			id:    7,
			want:  []string{"https://a.example.com/api/user", "IDOR"},
			notIn: []string{"{asset}"},
		},
		{
			name:  "asset_id placeholder",
			tmpl:  "对资产 {asset_id} 跑 nuclei 的 cve 模板",
			label: "b.example.com",
			id:    42,
			want:  []string{"42"},
			notIn: []string{"{asset_id}"},
		},
		{
			name:  "no placeholder appends target",
			tmpl:  "查越权",
			label: "c.example.com",
			id:    9,
			want:  []string{"c.example.com"},
		},
		{
			name:  "empty label falls back to id",
			tmpl:  "查 {asset} 的 SSRF",
			label: "",
			id:    13,
			want:  []string{"#13"},
			notIn: []string{"{asset}"},
		},
		{
			name:  "both placeholders",
			tmpl:  "{asset} (#{asset_id}) 查未授权",
			label: "d.example.com",
			id:    5,
			want:  []string{"d.example.com", "5"},
			notIn: []string{"{asset}", "{asset_id}"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := batchRenderTemplate(c.tmpl, c.label, c.id)
			for _, w := range c.want {
				if !strings.Contains(got, w) {
					t.Errorf("result %q missing %q", got, w)
				}
			}
			for _, n := range c.notIn {
				if strings.Contains(got, n) {
					t.Errorf("result %q still contains placeholder %q", got, n)
				}
			}
		})
	}
}

// TestBatchSweepIsPlannerOnly enforces the deliberate asymmetry: batch_sweep is the
// one tool that bypasses the per-call intent cap, so a worker must never have it
// (otherwise one claimed intent could spawn an unbounded queue).
func TestBatchSweepIsPlannerOnly(t *testing.T) {
	seeds := BuiltinToolSeeds()
	var found bool
	for _, s := range seeds {
		if s.Key != "batch_sweep" {
			continue
		}
		found = true
		for _, a := range s.Agents {
			if a != "planner" {
				t.Errorf("batch_sweep bound to %q, want planner only", a)
			}
		}
		if len(s.Agents) == 0 {
			t.Error("batch_sweep has no agent binding")
		}
	}
	if !found {
		t.Fatal("batch_sweep not seeded into the tool catalog")
	}
}
