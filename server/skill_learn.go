package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/llmrec"
	"github.com/Autumn-27/norma/llm"
)

// Skill import / learn.
//
// Why this exists: the existing skill endpoints (fsCreateSkill, fsUploadSkill) write
// a SKILL.md to disk but never touch agent_skill_visibility, so an imported skill is
// fully loaded and completely invisible to every agent until a human ticks a box in
// the UI. "Import it so it can use it" was therefore a two-step workflow with a
// silent second step.
//
// Two modes:
//   - plain import: parse the doc, normalise its frontmatter, save, and bind it.
//   - learn (learn=true): first re-author the doc against ARTEX's actual tool
//     vocabulary, then do the same. Raw third-party skills routinely reference tools
//     that do not exist here (upsert_project_fact, browser_navigate, …), and a skill
//     that teaches agents to call nonexistent tools is worse than no skill at all.

// maxSkillDocBytes caps a single imported markdown document.
const maxSkillDocBytes = 2 << 20 // 2MB

// defaultImportAgents is who an imported skill is bound to when the caller doesn't
// say. worker+pentest is the useful default: the planner already routes via the
// methodology skills, and a new domain playbook is normally for executors.
var defaultImportAgents = []string{"worker", "pentest"}

// importRequest is the decoded import call.
type importRequest struct {
	Doc       []byte
	Name      string   // fallback when the doc has no frontmatter name
	Desc      string   // fallback when the doc has no frontmatter description
	Agents    []string // nil = defaultImportAgents; empty slice = bind nobody
	AgentsSet bool
	Learn     bool
	Overwrite bool
}

// --- pure helpers (unit-tested without a server) ---

// skillDocDescription extracts `description:` from a SKILL.md frontmatter block.
// Handles both `description: text` and the folded `description: >-` form.
func skillDocDescription(md []byte) string {
	lines := strings.Split(string(md), "\n")
	if len(lines) < 2 || strings.TrimSpace(lines[0]) != "---" {
		return ""
	}
	end := -1
	for i := 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "---" {
			end = i
			break
		}
	}
	if end < 0 {
		return ""
	}
	for i := 1; i < end; i++ {
		t := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(t, "description:") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(t, "description:"))
		if rest != "" && !isBlockScalarMarker(rest) {
			return strings.Trim(rest, `"'`)
		}
		var parts []string
		for j := i + 1; j < end; j++ {
			cont := lines[j]
			if strings.TrimSpace(cont) == "" {
				continue
			}
			// a dedented line starts a new key → the block is over
			if cont == strings.TrimLeft(cont, " \t") {
				break
			}
			parts = append(parts, strings.TrimSpace(cont))
		}
		return strings.Join(parts, " ")
	}
	return ""
}

func isBlockScalarMarker(s string) bool {
	switch s {
	case ">", ">-", ">+", "|", "|-", "|+":
		return true
	}
	return false
}

// looksLikeSkillFrontmatter reports whether the doc opens with a closed YAML block.
func looksLikeSkillFrontmatter(md []byte) bool {
	lines := strings.Split(string(md), "\n")
	if len(lines) < 3 || strings.TrimSpace(lines[0]) != "---" {
		return false
	}
	for _, ln := range lines[1:] {
		if strings.TrimSpace(ln) == "---" {
			return true
		}
	}
	return false
}

// skillDocBody returns the markdown after the frontmatter (the whole doc when there
// is no frontmatter).
func skillDocBody(md []byte) string {
	lines := strings.Split(string(md), "\n")
	if len(lines) < 2 || strings.TrimSpace(lines[0]) != "---" {
		return string(md)
	}
	for i := 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "---" {
			return strings.Join(lines[i+1:], "\n")
		}
	}
	return string(md)
}

// ensureSkillFrontmatter returns a document with a well-formed frontmatter block
// whose name matches the directory we are about to create. Existing non-conflicting
// frontmatter (license/compatibility/metadata) is preserved verbatim.
func ensureSkillFrontmatter(md []byte, fallbackName, fallbackDesc string) (out []byte, name, desc string, err error) {
	name = strings.TrimSpace(skillNameFromFrontmatter(md))
	if name == "" {
		name = strings.TrimSpace(fallbackName)
	}
	if name == "" {
		return nil, "", "", fmt.Errorf("无法确定 skill 名称：文档 frontmatter 里没有 name，请求里也没提供")
	}
	if !validSkillName(name) {
		return nil, "", "", fmt.Errorf("skill 名称不合法 %q（≤64 字符，小写字母或中文开头，只能用小写字母/数字/连字符/中文，不能有空格或路径分隔符）", name)
	}

	desc = skillDocDescription(md)
	if desc == "" {
		desc = strings.TrimSpace(fallbackDesc)
	}
	if desc == "" {
		// Deliberately NOT derived from the body: description is the only thing the
		// model sees when choosing a skill (progressive disclosure), so a made-up
		// one-liner from the first body line is worse than asking for a real one.
		return nil, "", "", fmt.Errorf("SKILL.md 缺少 description：它是模型发现技能的唯一入口，必须显式提供（frontmatter 或请求里带 description）")
	}
	// One line only: a multi-line description breaks the YAML block.
	desc = strings.Join(strings.Fields(desc), " ")

	body := strings.TrimLeft(skillDocBody(md), "\n")
	if strings.TrimSpace(body) == "" {
		return nil, "", "", fmt.Errorf("SKILL.md 正文为空：只有 frontmatter 的技能没有任何可执行指导")
	}

	var sb strings.Builder
	sb.WriteString("---\n")
	fmt.Fprintf(&sb, "name: %s\n", name)
	fmt.Fprintf(&sb, "description: %s\n", desc)
	// preserve other simple frontmatter keys from the source doc
	for _, ln := range frontmatterExtraKeys(md, "name", "description") {
		sb.WriteString(ln)
		sb.WriteByte('\n')
	}
	sb.WriteString("---\n\n")
	sb.WriteString(body)
	if !strings.HasSuffix(body, "\n") {
		sb.WriteByte('\n')
	}
	return []byte(sb.String()), name, desc, nil
}

// frontmatterExtraKeys copies simple `key: value` lines out of the source
// frontmatter, skipping the ones we regenerate.
func frontmatterExtraKeys(md []byte, skip ...string) []string {
	skipSet := map[string]bool{}
	for _, s := range skip {
		skipSet[s] = true
	}
	lines := strings.Split(string(md), "\n")
	if len(lines) < 2 || strings.TrimSpace(lines[0]) != "---" {
		return nil
	}
	var out []string
	for _, ln := range lines[1:] {
		t := strings.TrimSpace(ln)
		if t == "---" {
			break
		}
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		idx := strings.IndexByte(t, ':')
		if idx <= 0 {
			continue // nested block / list item — not copyable line-wise
		}
		key := strings.TrimSpace(t[:idx])
		if skipSet[key] {
			continue
		}
		out = append(out, t)
	}
	return out
}

// reToolCallRef matches `name(` — how a skill refers to a tool it wants called.
// reToolNameRef matches a backticked snake_case identifier: skills very often name a
// tool inline without parentheses ("先用 `list_facts` 翻一遍"), which the call-form
// regex would miss entirely. Requiring an underscore keeps ordinary backticked words
// (`payload`, `true`) out of the warning list.
var (
	reToolCallRef = regexp.MustCompile(`\b[a-z][a-z0-9_]{2,}\s*\(`)
	reToolNameRef = regexp.MustCompile("`([a-z][a-z0-9]*(?:_[a-z0-9]+)+)`")
)

// unknownSkillToolRefs returns tool-looking references in the doc that are not in
// the platform catalog. Warnings only: a doc may legitimately mention a CLI, and the
// caller adds vulnclass ids to `known` so categories aren't reported as tools.
func unknownSkillToolRefs(doc []byte, known map[string]bool) []string {
	body := skillDocBody(doc)
	seen := map[string]bool{}
	var out []string
	add := func(ref string) {
		if ref == "" || known[ref] || seen[ref] {
			return
		}
		seen[ref] = true
		out = append(out, ref)
	}
	for _, m := range reToolCallRef.FindAllString(body, -1) {
		add(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(m), "(")))
	}
	for _, m := range reToolNameRef.FindAllStringSubmatch(body, -1) {
		add(m[1])
	}
	sort.Strings(out)
	if len(out) > 20 {
		out = out[:20]
	}
	return out
}

// --- learn pass ---

// collectCompletion runs one bounded completion and returns its text. Same shape as
// streamCollectText but with a caller-chosen output budget (a skill rewrite needs
// far more than the 1024 tokens the judge uses).
func collectCompletion(ctx context.Context, prov llm.Provider, system, user string, maxTokens int) (string, error) {
	temp := 0.0
	req := llm.CompletionRequest{
		System:      []string{system},
		Messages:    []llm.Message{llm.UserText(user)},
		MaxTokens:   maxTokens,
		Temperature: &temp,
		Thinking:    "disabled",
	}
	var sb strings.Builder
	for ev, err := range prov.Stream(ctx, req) {
		if err != nil {
			return "", err
		}
		if ev.Type == llm.SETextDelta {
			sb.WriteString(ev.Text)
		}
	}
	return sb.String(), nil
}

// skillLearnSystemPrompt builds the re-authoring instruction. The tool list and the
// vulnclass ids are injected because that is exactly what a foreign skill gets wrong:
// it names tools and categories that this platform doesn't have.
func skillLearnSystemPrompt(tools []string, vulnClasses []string) string {
	var b strings.Builder
	b.WriteString(`你是 ARTEX 渗透测试平台的 SKILL.md 编辑器。我会给你一份来自其它平台/其它工具的技能文档，你要把它改写成能在 ARTEX 上直接使用的 SKILL.md。

## 输出格式（严格遵守）
只输出 SKILL.md 全文，不要任何解释、不要代码围栏包裹整篇文档：
---
name: <与给定名称一致，小写或中文，不含空格>
description: <一句话，说明它做什么、什么时候用；这是模型发现技能的唯一入口，必须具体>
---

<Markdown 正文>

## 改写规则
1. **工具词汇必须换成平台真实存在的工具**：下面给出白名单，只能使用其中或通用的 shell/文件工具。原文里出现的其它平台工具名（例如 upsert_project_fact / record_vulnerability / browser_navigate / terminal / query_db）必须映射到白名单里语义最接近的工具；映射不了的动作改写成"用 Bash 执行 <具体命令>"。
2. **写回动作要对齐本平台**：探索结论用 record_fact（含 summary/detail/evidence/confidence/probe_attempts）；确认漏洞用 report_finding（vulnclass/name/severity/summary/evidence/traffic_refs）；资产用 insert_assets；覆盖进度用 mark_coverage。不要把"判断"写进 insert_assets。
3. **漏洞类必须用标准 id**：下面给出 class 白名单。原文用中文类别名的，映射到最近的 id。
4. **保留原文的实操价值**：具体的命令、payload、判据、误判提醒要留住；删掉空话、营销话术、与本平台无关的章节。
5. **每条打法要给出可判定的成功标准**（看到什么才算成立），以及常见的假阳性。
6. 不要编造工具名、不要编造不存在的 CVE。
7. 正文用 Markdown，小标题 + 表格/清单优先，长度控制在 200 行以内。

## 工具白名单
`)
	for _, t := range tools {
		b.WriteString("- ")
		b.WriteString(t)
		b.WriteByte('\n')
	}
	b.WriteString("\n## 漏洞类白名单（mark_coverage / report_finding 的 vulnclass 取值）\n")
	b.WriteString(strings.Join(vulnClasses, ", "))
	b.WriteString("\n")
	return b.String()
}

// oneShotProvider resolves the active LLM profile for a single non-agent call.
func (s *Server) oneShotProvider() (llm.Provider, error) {
	if s.m == nil || s.m.pg == nil {
		return nil, fmt.Errorf("PostgreSQL 未连接，无法调用模型")
	}
	p, err := s.m.pg.ActiveProfile()
	if err != nil || p == nil {
		return nil, fmt.Errorf("没有可用的激活 LLM 配置")
	}
	prov, _, ok := s.providerForProfile(p.ID)
	if !ok || prov == nil {
		return nil, fmt.Errorf("LLM 配置 %d 不可用", p.ID)
	}
	return prov, nil
}

// toolCatalogLines renders "name — first line of description" for the learn prompt.
func toolCatalogLines(pg *db.DB) []string {
	tools, err := pg.ListTools()
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(tools))
	for _, t := range tools {
		if !t.Enabled {
			continue
		}
		desc := strings.TrimSpace(t.Description)
		if i := strings.IndexByte(desc, '\n'); i >= 0 {
			desc = desc[:i]
		}
		if len([]rune(desc)) > 60 {
			desc = string([]rune(desc)[:60])
		}
		if desc == "" {
			out = append(out, t.Key)
			continue
		}
		out = append(out, t.Key+" — "+desc)
	}
	return out
}

// vulnClassKeys lists the catalog ids for the learn prompt.
func vulnClassKeys() []string {
	out := make([]string, 0, len(db.VulnClasses))
	for _, c := range db.VulnClasses {
		out = append(out, c.Key)
	}
	return out
}

// --- handler ---

// fsImportSkill handles POST /api/skills/import.
//
// Accepts either multipart/form-data (field "file" = the .md, optional "name",
// "description", "agents", "learn", "overwrite") or JSON
// {markdown, name, description, agents:[], learn, overwrite}.
//
// Response: {name, description, agents, warnings[], learned}
func (s *Server) fsImportSkill(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	req, err := parseImportRequest(w, r)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}

	doc := req.Doc
	warnings := []string{}
	learned := false

	if req.Learn {
		prov, err := s.oneShotProvider()
		if err != nil {
			writeErr(w, 503, "learn 需要可用的 LLM 配置："+err.Error())
			return
		}
		name := strings.TrimSpace(skillNameFromFrontmatter(doc))
		if name == "" {
			name = req.Name
		}
		sys := skillLearnSystemPrompt(toolCatalogLines(pg), vulnClassKeys())
		user := "技能名称: " + name + "\n\n原始文档:\n" + string(doc)
		ctx := llmrec.WithWorker(r.Context(), "skill-learn")
		out, err := collectCompletion(ctx, prov, sys, user, 6000)
		if err != nil {
			writeErr(w, 502, "skill 重写失败："+err.Error())
			return
		}
		out = stripOuterFence(strings.TrimSpace(out))
		if !looksLikeSkillFrontmatter([]byte(out)) {
			writeErr(w, 502, "模型返回的不是合法的 SKILL.md（缺少 frontmatter）。原文已保留，未写入任何文件")
			return
		}
		doc = []byte(out)
		learned = true
	}

	final, name, desc, err := ensureSkillFrontmatter(doc, req.Name, req.Desc)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}

	skillPath := filepath.Join(s.skillDir, name)
	if _, statErr := os.Stat(skillPath); statErr == nil && !req.Overwrite {
		writeErr(w, 409, "skill 已存在："+name+"（如需覆盖请带 overwrite=true）")
		return
	}

	// Write to a temp dir first, then swap in: a failure must never leave a
	// half-written skill behind (same policy as fsUploadSkill).
	if err := os.MkdirAll(s.skillDir, 0o755); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	tmp, err := os.MkdirTemp(s.skillDir, ".import-*")
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer os.RemoveAll(tmp)
	if err := os.WriteFile(filepath.Join(tmp, "SKILL.md"), final, 0o644); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if err := os.RemoveAll(skillPath); err != nil && !os.IsNotExist(err) {
		writeErr(w, 500, err.Error())
		return
	}
	if err := os.Rename(tmp, skillPath); err != nil {
		writeErr(w, 500, err.Error())
		return
	}

	// Warn (don't fail) about tool references the platform doesn't have.
	known := map[string]bool{}
	for _, t := range toolCatalogLines(pg) {
		if i := strings.Index(t, " — "); i > 0 {
			known[t[:i]] = true
		} else {
			known[t] = true
		}
	}
	// vulnclass ids are backticked in skills too; they are not tools.
	for _, c := range db.VulnClasses {
		known[c.Key] = true
	}
	for _, ref := range unknownSkillToolRefs(final, known) {
		warnings = append(warnings, "文档引用了平台上不存在的工具调用写法："+ref+" —— 请确认它是 shell 命令而不是工具名")
	}

	// Bind to agents. This is the step the old import path was missing: without it
	// the skill loads on disk but no agent ever sees it.
	agents := defaultImportAgents
	if req.AgentsSet {
		agents = req.Agents
	}
	bound := []string{}
	for _, key := range cleanStrs(agents) {
		a, err := pg.GetAgentByKey(key)
		if err != nil || a == nil {
			warnings = append(warnings, "未知的 agent key，未绑定："+key)
			continue
		}
		if err := pg.ToggleSkillVisibility(a.ID, name, true); err != nil {
			warnings = append(warnings, "绑定 "+key+" 失败："+err.Error())
			continue
		}
		bound = append(bound, key)
	}

	writeJSON(w, 200, map[string]any{
		"name":        name,
		"description": desc,
		"agents":      bound,
		"warnings":    warnings,
		"learned":     learned,
	})
}

// stripOuterFence removes a ```markdown wrapper some models add around the whole doc.
func stripOuterFence(s string) string {
	if !strings.HasPrefix(s, "```") {
		return s
	}
	nl := strings.IndexByte(s, '\n')
	if nl < 0 {
		return s
	}
	body := s[nl+1:]
	if i := strings.LastIndex(body, "```"); i >= 0 {
		body = body[:i]
	}
	return strings.TrimSpace(body)
}

// parseImportRequest decodes either multipart or JSON input.
func parseImportRequest(w http.ResponseWriter, r *http.Request) (importRequest, error) {
	var out importRequest
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "multipart/form-data") {
		r.Body = http.MaxBytesReader(w, r.Body, maxSkillDocBytes+1<<16)
		if err := r.ParseMultipartForm(maxSkillDocBytes); err != nil {
			return out, fmt.Errorf("解析上传失败：%w", err)
		}
		f, _, err := r.FormFile("file")
		if err != nil {
			return out, fmt.Errorf("缺少字段 file（SKILL.md 文件）")
		}
		defer f.Close()
		buf, err := io.ReadAll(io.LimitReader(f, maxSkillDocBytes))
		if err != nil {
			return out, err
		}
		out.Doc = buf
		out.Name = r.FormValue("name")
		out.Desc = r.FormValue("description")
		if v, ok := r.MultipartForm.Value["agents"]; ok {
			out.AgentsSet = true
			for _, one := range v {
				for _, k := range strings.Split(one, ",") {
					if t := strings.TrimSpace(k); t != "" {
						out.Agents = append(out.Agents, t)
					}
				}
			}
		}
		out.Learn = truthy(r.FormValue("learn"))
		out.Overwrite = truthy(r.FormValue("overwrite"))
	} else {
		var body struct {
			Markdown    string    `json:"markdown"`
			Name        string    `json:"name"`
			Description string    `json:"description"`
			Agents      *[]string `json:"agents"`
			Learn       bool      `json:"learn"`
			Overwrite   bool      `json:"overwrite"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, maxSkillDocBytes)).Decode(&body); err != nil {
			return out, fmt.Errorf("解析 JSON 失败：%w", err)
		}
		out.Doc = []byte(body.Markdown)
		out.Name = body.Name
		out.Desc = body.Description
		if body.Agents != nil {
			out.AgentsSet = true
			out.Agents = *body.Agents
		}
		out.Learn = body.Learn
		out.Overwrite = body.Overwrite
	}
	if len(out.Doc) == 0 {
		return out, fmt.Errorf("文档内容为空")
	}
	if len(out.Doc) > maxSkillDocBytes {
		return out, fmt.Errorf("文档超过 %d 字节上限", maxSkillDocBytes)
	}
	if out.Name != "" && !validSkillName(out.Name) {
		out.Name = "" // silently ignore a bad fallback; the doc's own name wins anyway
	}
	return out, nil
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
