package server

import (
	"strings"
	"testing"
)

const sampleForeignSkill = `---
name: sql-injection-master
description: >-
  SQL 注入完整打法：从探测到数据提取，含 WAF 绕过与盲注优化。
metadata:
  tags: [pentest]
---

# SQL 注入

## 步骤

1. 先探测：` + "`" + `terminal` + "`" + ` 里跑 ` + "`" + `curl https://t/?id=1'` + "`" + `
2. 确认后调用 ` + "`" + `upsert_project_fact` + "`" + ` 记录结论
3. 确认漏洞时调用 ` + "`" + `record_vulnerability(...)` + "`" + ` 上报
`

func TestSkillDocDescription(t *testing.T) {
	cases := []struct{ name, md, want string }{
		{
			name: "single line",
			md:   "---\nname: a\ndescription: hello world\n---\nbody",
			want: "hello world",
		},
		{
			name: "quoted",
			md:   "---\nname: a\ndescription: \"quoted desc\"\n---\nbody",
			want: "quoted desc",
		},
		{
			name: "folded block",
			md:   "---\nname: a\ndescription: >-\n  line one\n  line two\nlicense: MIT\n---\nbody",
			want: "line one line two",
		},
		{
			name: "literal block",
			md:   "---\nname: a\ndescription: |\n  中文描述\n  第二行\n---\nbody",
			want: "中文描述 第二行",
		},
		{
			name: "no frontmatter",
			md:   "# Title\n\nbody",
			want: "",
		},
		{
			name: "missing description",
			md:   "---\nname: a\nlicense: MIT\n---\nbody",
			want: "",
		},
	}
	for _, tc := range cases {
		if got := skillDocDescription([]byte(tc.md)); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestEnsureSkillFrontmatter(t *testing.T) {
	out, name, desc, err := ensureSkillFrontmatter([]byte(sampleForeignSkill), "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "sql-injection-master" {
		t.Errorf("name = %q", name)
	}
	if !strings.Contains(desc, "SQL 注入完整打法") {
		t.Errorf("folded description not joined: %q", desc)
	}
	body := string(out)
	if !strings.HasPrefix(body, "---\nname: sql-injection-master\ndescription: ") {
		t.Errorf("frontmatter not normalised:\n%s", body[:120])
	}
	// the description must be a single line — multi-line breaks the YAML block
	if strings.Count(strings.Split(body, "---")[1], "\n") < 2 {
		t.Errorf("description should be on one line with name")
	}
	// other frontmatter keys survive
	if !strings.Contains(body, "metadata:") {
		t.Errorf("extra frontmatter key dropped:\n%s", body[:200])
	}
	// body preserved
	if !strings.Contains(body, "upsert_project_fact") {
		t.Errorf("body lost")
	}
}

func TestEnsureSkillFrontmatterValidation(t *testing.T) {
	// no name anywhere
	if _, _, _, err := ensureSkillFrontmatter([]byte("# just a body"), "", ""); err == nil {
		t.Error("expected error for missing name")
	}
	// no description anywhere
	if _, _, _, err := ensureSkillFrontmatter([]byte("---\nname: ok\n---\nbody"), "", ""); err == nil {
		t.Error("expected error for missing description")
	}
	// body-less skill is useless
	if _, _, _, err := ensureSkillFrontmatter([]byte("---\nname: ok\ndescription: d\n---\n   \n"), "", ""); err == nil {
		t.Error("expected error for empty body")
	}
	// invalid name
	if _, _, _, err := ensureSkillFrontmatter([]byte("---\nname: Bad Name\ndescription: d\n---\nbody"), "", ""); err == nil {
		t.Error("expected error for invalid name")
	}
	// fallbacks applied
	out, name, _, err := ensureSkillFrontmatter([]byte("## 正文\n内容"), "fallback-name", "fallback desc")
	if err != nil || name != "fallback-name" {
		t.Fatalf("fallback failed: name=%q err=%v", name, err)
	}
	if !strings.Contains(string(out), "fallback desc") {
		t.Errorf("fallback description missing:\n%s", out)
	}
}

func TestUnknownSkillToolRefs(t *testing.T) {
	known := map[string]bool{"record_fact": true, "report_finding": true, "curl": true}
	refs := unknownSkillToolRefs([]byte(sampleForeignSkill), known)
	got := strings.Join(refs, ",")
	// upsert_project_fact (bare backticked) and record_vulnerability(...) are both
	// foreign to ARTEX and must be flagged; `terminal` is a bare word with no
	// underscore, so it is intentionally not reported.
	for _, want := range []string{"upsert_project_fact", "record_vulnerability"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in refs %v", want, refs)
		}
	}
	if strings.Contains(got, "record_fact") {
		t.Errorf("known tool wrongly reported: %v", refs)
	}
	if strings.Contains(got, "curl") {
		t.Errorf("known CLI wrongly reported: %v", refs)
	}
}

func TestStripOuterFence(t *testing.T) {
	in := "```markdown\n---\nname: a\ndescription: d\n---\nbody\n```"
	got := stripOuterFence(in)
	if !strings.HasPrefix(got, "---") || strings.Contains(got, "```") {
		t.Fatalf("fence not stripped: %q", got)
	}
	if plain := "---\nname: a\n---\n"; stripOuterFence(plain) != plain {
		t.Fatal("plain doc must be untouched")
	}
}

// TestSkillLearnPromptListsRealTools guards the learn prompt: it must carry the tool
// whitelist and the vulnclass ids, otherwise the model has nothing to normalise to.
func TestSkillLearnPromptListsRealTools(t *testing.T) {
	sys := skillLearnSystemPrompt([]string{"nuclei — 模板化漏洞扫描", "record_fact — 写结论"}, vulnClassKeys())
	if !strings.Contains(sys, "nuclei") || !strings.Contains(sys, "record_fact") {
		t.Error("tool whitelist missing from prompt")
	}
	if !strings.Contains(sys, "sqli") || !strings.Contains(sys, "subdomain_takeover") {
		t.Error("vulnclass ids missing from prompt")
	}
}
