package server

import (
	"path/filepath"
	"sort"
	"testing"

	"github.com/Autumn-27/norma/skill"
)

// TestBuiltinSkillsLoad guards the shipped skills directory. Skills are loaded at
// runtime by norma's filesystem loader, so a malformed frontmatter block or a
// directory whose name disagrees with its `name:` field fails silently in
// production — the agent just never sees that skill. This test makes it loud.
//
// It also asserts every skill the DB binds by default (builtinSkillVisibility in
// db/db.go) actually exists on disk: a binding row pointing at a missing directory
// is a no-op, so a typo there would quietly cost the planner its methodology.
func TestBuiltinSkillsLoad(t *testing.T) {
	dir := filepath.Join("..", "skills")
	reg, err := skill.LoadDir(dir)
	if err != nil {
		t.Fatalf("load %s: %v", dir, err)
	}
	if reg == nil {
		t.Fatalf("load %s: nil registry", dir)
	}

	got := map[string]bool{}
	for _, s := range reg.List() {
		if s.Dir == "" {
			t.Errorf("skill %q has empty Dir", s.Name)
			continue
		}
		base := filepath.Base(s.Dir)
		if s.Name != base {
			t.Errorf("skill dir %q declares name %q (must match directory)", base, s.Name)
		}
		if s.Description == "" {
			t.Errorf("skill %q has empty description", s.Name)
		}
		got[base] = true
	}

	// Skills the platform binds by default. Keep in sync with
	// db.builtinSkillVisibility.
	want := []string{
		"active-directory-attack",
		"ai-llm-app-attack",
		"api-recon",
		"attack-surface-recon",
		"binary-mobile-reversing",
		"blockchain-contract-attack",
		"capability-primitive-search",
		"cloud-attack-methods",
		"component-vuln-intel",
		"initial-access-phishing",
		"pentest-agent-os",
		"pentest-blackboard",
		"pentest-output-standards",
		"pentest-verification",
		"post-exploitation",
		"redteam-opsec",
		"source-code-hunting",
		"specialized-attack-playbooks",
		"vulnclass-coverage",
		"web-attack-methods",
		"wireless-hardware-attack",
		"zero-day-discovery",
	}
	sort.Strings(want)
	for _, name := range want {
		if !got[name] {
			t.Errorf("skill %q is bound in builtinSkillVisibility but did not load from %s", name, dir)
		}
	}
}
