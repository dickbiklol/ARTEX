package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/llmrec"
	actool "github.com/Autumn-27/norma/tool"
)

// 目标发现（target discovery）.
//
// 流程：一句意图 → LLM 自己产关键词 → 跑搜索 → 抓域名并按主域收敛 → 过滤（拦截规则 /
// 是否测过 / 存活 / 相关性）→ 落到 discovery_candidates 等人工审批 → 审批后建任务。
//
// 三条不可动摇的边界：
//  1. 搜索只打搜索引擎，走 web_search_proxy（可以是住宅代理）；存活探测打的是【目标】，
//     走直连，绝不复用搜索代理——否则流量记录与拦截判断都建立在非扫描出口 IP 上。
//  2. 候选不等于授权。task_scope 才是授权边界，所以本文件【不】创建任务；/start 是
//     另一个显式动作，且只消费 status=approved 的行。
//  3. 上限在服务端强制，不靠前端。

const (
	discoveryMaxQueries    = 12
	discoveryMaxCandidates = 500
	discoveryPerQueryLimit = 20
	discoveryRelevanceGap  = 20  // hosts per relevance-scoring call
	discoveryMaxTasks      = 50  // per_domain 形态的最多任务数
	discoveryMaxHostsTask  = 200 // 单个任务最多塞多少个域名
	discoveryAbortOn429    = 3   // 连续这么多次被限流就中止整轮
	// discoveryMaxRounds 是"补齐"轮数上限：一轮搜索下来的候选被过滤掉一部分后，
	// 再让模型换角度补搜，直到凑够目标数量。3 轮 = 最多几十次搜索，既够用又不至于
	// 把一个 IP 打成黑名单。
	discoveryMaxRounds = 3
	// discoverySeenHint 是把"已经处理过的主机"回喂给模型的条数上限。给太多会挤占
	// 上下文，给太少模型容易换汤不换药。
	discoverySeenHint = 40
)

var discoveryRunTimeout = 30 * time.Minute

// discoveryParams is the run configuration (persisted in discovery_runs.params).
// Query is carried in memory only — the pipeline needs the original intent for the
// keyword and relevance prompts, and discovery_runs.query already stores it.
type discoveryParams struct {
	TargetCount  int      `json:"target_count"`
	Shape        string   `json:"shape"` // single | per_domain | batches
	BatchSize    int      `json:"batch_size"`
	Exclude      []string `json:"exclude"`
	Liveness     bool     `json:"liveness"`
	MinRelevance int      `json:"min_relevance"`
	Queries      int      `json:"queries"`
	MaxRounds    int      `json:"max_rounds"`
	// TestGoal 是【建任务时用的测试目标】，与搜索意图彻底分开：
	//   Query    = “找什么样的站点”（只喂给搜索/相关性打分）
	//   TestGoal = “对它们测什么”（写进 task.goal，规划者据此拆目标）
	// 以前直接拿 Query 当 goal，规划者会去“找站点”而不是“测站点”。
	TestGoal string `json:"test_goal"`

	Query string `json:"-"` // not persisted here; discovery_runs.query owns it
}

func (p *discoveryParams) normalize() {
	if p.Queries <= 0 || p.Queries > discoveryMaxQueries {
		p.Queries = 8
	}
	if p.TargetCount <= 0 || p.TargetCount > discoveryMaxCandidates {
		p.TargetCount = 100
	}
	switch p.Shape {
	case "single", "per_domain", "batches":
	default:
		p.Shape = "single"
	}
	if p.BatchSize <= 0 || p.BatchSize > discoveryMaxHostsTask {
		p.BatchSize = 25
	}
	if p.MinRelevance < 0 || p.MinRelevance > 100 {
		p.MinRelevance = 40
	}
	if p.MaxRounds <= 0 || p.MaxRounds > discoveryMaxRounds {
		p.MaxRounds = discoveryMaxRounds
	}
	if p.TestGoal = strings.TrimSpace(p.TestGoal); p.TestGoal == "" {
		p.TestGoal = discoveryDefaultGoal(p.Query)
	}
}

// ── HTTP handlers ────────────────────────────────────────────────────────────

type discoveryCreateReq struct {
	Query        string   `json:"query"`
	TargetCount  int      `json:"target_count"`
	Shape        string   `json:"shape"`
	BatchSize    int      `json:"batch_size"`
	Exclude      []string `json:"exclude"`
	Liveness     *bool    `json:"liveness"`
	MinRelevance int      `json:"min_relevance"`
	Queries      int      `json:"queries"`
	MaxRounds    int      `json:"max_rounds"`
	TestGoal     string   `json:"test_goal"`
}

// discoveryCreateRun starts a run and returns immediately; the pipeline runs in the
// background and the page polls GET /runs/{id} for live progress.
func (s *Server) discoveryCreateRun(w http.ResponseWriter, r *http.Request) {
	var req discoveryCreateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	req.Query = strings.TrimSpace(req.Query)
	if req.Query == "" {
		writeErr(w, 400, "query 不能为空：写清你要找什么样的站点")
		return
	}
	on, backend, _, _, _ := s.m.WebSearch()
	if !on {
		writeErr(w, 400, "Web 搜索未启用：先在 系统设置 → Web 搜索 打开并测试连通")
		return
	}

	p := discoveryParams{
		TargetCount: req.TargetCount, Shape: req.Shape, BatchSize: req.BatchSize,
		Exclude: req.Exclude, MinRelevance: req.MinRelevance, Queries: req.Queries,
		MaxRounds: req.MaxRounds, Liveness: true, Query: req.Query, TestGoal: req.TestGoal,
	}
	if req.Liveness != nil {
		p.Liveness = *req.Liveness
	}
	p.normalize()

	params := map[string]any{
		"target_count": p.TargetCount, "shape": p.Shape, "batch_size": p.BatchSize,
		"exclude": p.Exclude, "liveness": p.Liveness, "min_relevance": p.MinRelevance,
		"queries": p.Queries, "max_rounds": p.MaxRounds, "backend": backend,
		"test_goal": p.TestGoal,
	}
	run, err := s.m.pg.CreateDiscoveryRun(req.Query, params)
	if err != nil {
		writeErr(w, 500, "创建发现任务失败："+err.Error())
		return
	}
	go s.runDiscoveryPipeline(run.ID, p)
	writeJSON(w, 201, run)
}

func (s *Server) discoveryListRuns(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	runs, err := s.m.pg.ListDiscoveryRuns(limit)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"runs": runs})
}

func (s *Server) discoveryGetRun(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "无效的 run id")
		return
	}
	run, err := s.m.pg.GetDiscoveryRun(id)
	if err != nil {
		writeErr(w, 404, "未找到该发现任务")
		return
	}
	counts, _ := s.m.pg.DiscoveryCandidateCounts(id)
	writeJSON(w, 200, map[string]any{"run": run, "counts": counts})
}

func (s *Server) discoveryListCandidates(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "无效的 run id")
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	cands, total, err := s.m.pg.ListDiscoveryCandidates(id, q.Get("status"), limit, offset)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"candidates": cands, "total": total})
}

type discoveryCandidatePatch struct {
	Status string `json:"status"`
}

func (s *Server) discoveryPatchCandidate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "无效的 candidate id")
		return
	}
	var req discoveryCandidatePatch
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	ok, err := s.m.pg.SetDiscoveryCandidateStatus(id, strings.TrimSpace(req.Status))
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if !ok {
		writeErr(w, 404, "未找到该候选")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

type discoveryBulkReq struct {
	IDs    []int64 `json:"ids"`
	Status string  `json:"status"`
}

// discoveryBulkStatus approves/rejects many candidates at once (the UI's 全选).
func (s *Server) discoveryBulkStatus(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "无效的 run id")
		return
	}
	var req discoveryBulkReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	n, err := s.m.pg.SetDiscoveryCandidatesStatus(id, req.IDs, strings.TrimSpace(req.Status))
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"updated": n})
}

func (s *Server) discoveryDeleteRun(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "无效的 run id")
		return
	}
	if _, err := s.m.pg.DeleteDiscoveryRun(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": id})
}

type discoveryStartReq struct {
	Shape     string `json:"shape"`
	BatchSize int    `json:"batch_size"`
	// Goal 覆盖本轮运行登记的测试目标（写进 task.goal）；空则用创建时填的 test_goal。
	Goal string `json:"goal"`
	// Name 覆盖任务名（可选）。
	Name string `json:"name"`
}

// discoveryStart turns APPROVED candidates into tasks. This is the only path from
// discovery to testing, and it is deliberately a separate, explicit call.
func (s *Server) discoveryStart(w http.ResponseWriter, r *http.Request) {
	runID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || runID <= 0 {
		writeErr(w, 400, "无效的 run id")
		return
	}
	run, err := s.m.pg.GetDiscoveryRun(runID)
	if err != nil {
		writeErr(w, 404, "未找到该发现任务")
		return
	}
	if run.Status == db.DiscStatusStarted {
		writeErr(w, 400, "该轮发现已经启动过任务了：如需再测，请新建一轮发现")
		return
	}
	var req discoveryStartReq
	if e := json.NewDecoder(r.Body).Decode(&req); e != nil && e != io.EOF {
		writeErr(w, 400, "bad json: "+e.Error())
		return
	}

	p := discoveryParams{}
	_ = json.Unmarshal(run.Params, &p)
	if strings.TrimSpace(req.Shape) != "" {
		p.Shape = strings.TrimSpace(req.Shape)
	}
	if req.BatchSize > 0 {
		p.BatchSize = req.BatchSize
	}
	p.normalize()
	if g := strings.TrimSpace(req.Goal); g != "" {
		p.TestGoal = g
	}

	approved, err := s.m.pg.ApprovedDiscoveryCandidates(runID, discoveryMaxCandidates)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if len(approved) == 0 {
		writeErr(w, 400, "没有已批准的候选：先在列表里勾选 approve，再开始测试")
		return
	}

	groups := discoveryGroupHosts(approved, p)
	if len(groups) > discoveryMaxTasks {
		writeErr(w, 400, fmt.Sprintf("按当前形态会创建 %d 个任务（上限 %d）：改用 single，或调大 batch_size",
			len(groups), discoveryMaxTasks))
		return
	}

	type startedGroup struct {
		TaskID string   `json:"task_id"`
		Hosts  []string `json:"hosts"`
	}
	results := make([]startedGroup, 0, len(groups))
	failed := 0

	for i, g := range groups {
		name := strings.TrimSpace(req.Name)
		if name == "" {
			name = fmt.Sprintf("目标发现：%s（run #%d", run.Query, runID)
			if len(groups) > 1 {
				name += fmt.Sprintf(" · 第 %d/%d 批", i+1, len(groups))
			}
			name += "）"
		} else if len(groups) > 1 {
			name = fmt.Sprintf("%s · 第 %d/%d 批", name, i+1, len(groups))
		}
		// 任务 goal 用【测试目标】，不是搜索意图：规划者拆目标时看的是这里。
		task, err := s.m.CreateTaskWithOptions(name, p.TestGoal, db.TaskCreateOptions{})
		if err != nil {
			log.Printf("[discovery] run %d: 建任务失败: %v", runID, err)
			failed++
			continue
		}
		taskID, _ := strconv.ParseInt(task.ID, 10, 64)
		inputs := make([]db.ScopeInput, 0, len(g.hosts))
		for _, h := range g.hosts {
			inputs = append(inputs, db.ScopeInput{Kind: "domain", Value: h})
		}
		// 唯一一处“建全局资产 + 挂到任务 + 写 task_scope”的原子操作。
		if _, err := s.m.Assets().RegisterTaskAssetScopes(taskID, inputs); err != nil {
			log.Printf("[discovery] run %d task %d: 写范围失败: %v", runID, taskID, err)
		}
		s.launchTask(task, name, false)

		ids := make([]int64, 0, len(g.candidates))
		for _, c := range g.candidates {
			ids = append(ids, c.ID)
		}
		if _, err := s.m.pg.MarkDiscoveryCandidatesUsed(ids, taskID); err != nil {
			log.Printf("[discovery] run %d: 标记候选已用失败: %v", runID, err)
		}
		results = append(results, startedGroup{TaskID: task.ID, Hosts: g.hosts})
	}

	if len(results) == 0 {
		writeErr(w, 500, "没有成功创建任何任务，详见服务端日志")
		return
	}
	_ = s.m.pg.SetDiscoveryRunStatus(runID, db.DiscStatusStarted, "")
	writeJSON(w, 201, map[string]any{"tasks": results, "created": len(results), "failed": failed})
}

// discoveryGroup is one task's worth of approved hosts.
type discoveryGroup struct {
	hosts      []string
	candidates []*db.DiscoveryCandidate
}

// discoveryGroupHosts splits approved candidates per the run's task shape.
func discoveryGroupHosts(approved []*db.DiscoveryCandidate, p discoveryParams) []discoveryGroup {
	toGroup := func(sub []*db.DiscoveryCandidate) discoveryGroup {
		g := discoveryGroup{candidates: make([]*db.DiscoveryCandidate, 0, len(sub))}
		for _, c := range sub {
			g.hosts = append(g.hosts, c.Host)
			g.candidates = append(g.candidates, c)
		}
		return g
	}
	switch p.Shape {
	case "per_domain":
		out := make([]discoveryGroup, 0, len(approved))
		for _, c := range approved {
			out = append(out, toGroup([]*db.DiscoveryCandidate{c}))
		}
		return out
	case "batches":
		size := p.BatchSize
		if size <= 0 {
			size = 25
		}
		out := make([]discoveryGroup, 0, (len(approved)+size-1)/size)
		for i := 0; i < len(approved); i += size {
			end := i + size
			if end > len(approved) {
				end = len(approved)
			}
			out = append(out, toGroup(approved[i:end]))
		}
		return out
	default: // single
		return []discoveryGroup{toGroup(approved)}
	}
}

// ── pipeline ─────────────────────────────────────────────────────────────────

// discoveryHarvested is one candidate host after harvesting, before filtering.
type discoveryHarvested struct {
	Host    string
	Root    string
	Query   string
	URL     string
	Title   string
	Snippet string
}

// runProgress keeps the run's stats map and flushes it to the DB so the page can
// poll live progress. One pipeline goroutine per run, so no locking is needed.
type runProgress struct {
	stats map[string]any
	save  func(map[string]any)
}

func newRunProgress(runID int64, save func(int64, map[string]any) error) *runProgress {
	rp := &runProgress{stats: map[string]any{}, save: nil}
	rp.save = func(m map[string]any) { _ = save(runID, m) }
	return rp
}

func (r *runProgress) set(k string, v any) { r.stats[k] = v }
func (r *runProgress) add(k string, n int) {
	r.stats[k] = toInt(r.stats[k]) + n
}
func (r *runProgress) flush() { r.save(r.stats) }

// runDiscoveryPipeline executes one run end-to-end in the background.
//
// It runs in ROUNDS: search → filter, then if not enough fresh candidates were kept,
// ask the model for different angles (excluding the queries and hosts already seen)
// and search again. Without this top-up, a run that discarded 60 of 100 hits as
// "already tested" would just deliver 40 and stop.
//
// Every stage and every individual query updates the run's stats, so the panel can
// show live progress (round N/M, query i/K, current keyword) while it crawls.
func (s *Server) runDiscoveryPipeline(runID int64, p discoveryParams) {
	ctx, cancel := context.WithTimeout(context.Background(), discoveryRunTimeout)
	defer cancel()

	progress := newRunProgress(runID, s.m.pg.SetDiscoveryRunStats)
	progress.set("target_count", p.TargetCount)
	progress.set("max_rounds", p.MaxRounds)
	progress.set("round", 0)
	progress.set("queries_done", 0)
	progress.set("queries_total", 0)
	progress.set("hits", 0)
	progress.set("hosts_raw", 0)
	progress.set("pending", 0)
	progress.flush()

	fail := func(stage string, err error) {
		log.Printf("[discovery] run %d 在 %s 阶段失败: %v", runID, stage, err)
		progress.set("stage", stage)
		progress.set("stopped_reason", stage+"失败："+err.Error())
		progress.flush()
		_ = s.m.pg.SetDiscoveryRunStatus(runID, db.DiscStatusFailed, stage+": "+err.Error())
	}

	accepted := make([]db.DiscoveryCandidate, 0, p.TargetCount)
	skipped := make([]db.DiscoveryCandidate, 0, 64)
	seen := map[string]bool{} // root domains already produced a candidate row
	seenOrder := make([]string, 0, 128)
	usedQueries := make([]string, 0, p.Queries*p.MaxRounds)
	allKeywords := make([]string, 0, p.Queries*p.MaxRounds)

	remember := func(host string) {
		if host == "" || seen[host] {
			return
		}
		seen[host] = true
		seenOrder = append(seenOrder, host)
	}

	for round := 1; round <= p.MaxRounds; round++ {
		if len(accepted) >= p.TargetCount {
			break
		}
		progress.set("round", round)

		// 1) keywords (round 2+ is steered away from what we already tried)
		_ = s.m.pg.SetDiscoveryRunStatus(runID, db.DiscStatusKeywords, "")
		progress.set("stage", "keywords")
		progress.set("current_query", "")
		progress.flush()
		queries, err := s.discoveryKeywords(ctx, p, usedQueries, seenOrder, round)
		if err != nil {
			if round == 1 {
				fail("关键词生成", err)
				return
			}
			progress.set("stopped_reason", fmt.Sprintf("第 %d 轮关键词生成失败：%v", round, err))
			break
		}
		if len(queries) == 0 {
			break
		}
		usedQueries = append(usedQueries, queries...)
		allKeywords = append(allKeywords, queries...)
		_ = s.m.pg.SetDiscoveryRunKeywords(runID, allKeywords)
		progress.set("queries_total", len(allKeywords))
		progress.flush()

		// 2) search
		_ = s.m.pg.SetDiscoveryRunStatus(runID, db.DiscStatusSearching, "")
		progress.set("stage", "searching")
		progress.flush()
		harvested, err := s.discoverySearchRound(ctx, queries, seen, progress)
		if err != nil {
			// 限流中止：第一轮直接失败；后续轮次保留已得成果，标记原因后收尾。
			if round == 1 {
				fail("搜索", err)
				return
			}
			progress.set("stopped_reason", fmt.Sprintf("第 %d 轮搜索被中止：%v", round, err))
			break
		}
		if len(harvested) == 0 {
			progress.add("empty_rounds", 1)
			progress.flush()
			continue
		}

		// 3) filter this round's new hosts only
		_ = s.m.pg.SetDiscoveryRunStatus(runID, db.DiscStatusFiltering, "")
		progress.set("stage", "filtering")
		progress.flush()
		remaining := p.TargetCount - len(accepted)
		pending, rejected, tally, err := s.discoveryFilter(ctx, p, harvested, remaining)
		if err != nil {
			if round == 1 {
				fail("过滤", err)
				return
			}
			progress.set("stopped_reason", fmt.Sprintf("第 %d 轮过滤失败：%v", round, err))
			break
		}
		for _, c := range pending {
			remember(c.Host)
		}
		for _, c := range rejected {
			remember(c.Host)
		}
		accepted = append(accepted, pending...)
		skipped = append(skipped, rejected...)
		for k, v := range tally {
			if n, ok := v.(int); ok {
				progress.stats[k] = toInt(progress.stats[k]) + n
			} else {
				progress.stats[k] = v
			}
		}
		progress.set("pending", len(accepted))
		progress.set("skipped_total", len(skipped))
		progress.set("hosts_raw", len(seenOrder))
		progress.flush()
	}

	if len(accepted) == 0 && len(skipped) == 0 {
		progress.set("stopped_reason", "没有找到任何候选：换一个意图描述，或调低相关性阈值/关闭排除词后重试")
		progress.flush()
		_ = s.m.pg.SetDiscoveryRunStatus(runID, db.DiscStatusReady, "")
		return
	}

	// 4) persist (accepted first so the pending list is never empty when a target was met)
	out := make([]db.DiscoveryCandidate, 0, len(accepted)+len(skipped))
	out = append(out, accepted...)
	out = append(out, skipped...)
	n, err := s.m.pg.InsertDiscoveryCandidates(runID, out)
	if err != nil {
		fail("入库", err)
		return
	}
	progress.set("persisted", n)
	progress.set("stage", "done")
	progress.set("current_query", "")
	if _, ok := progress.stats["stopped_reason"]; !ok && len(accepted) < p.TargetCount {
		progress.set("stopped_reason", fmt.Sprintf("搜索已跑满 %d 轮，只凑到 %d/%d 个符合条件的新站点",
			p.MaxRounds, len(accepted), p.TargetCount))
	}
	progress.flush()
	_ = s.m.pg.SetDiscoveryRunStatus(runID, db.DiscStatusReady, "")
	log.Printf("[discovery] run %d 完成：%d 条候选入库（pending %d，跳过 %d，搜索词 %d 个）",
		runID, n, len(accepted), len(skipped), len(allKeywords))
}

// discoveryKeywords asks the model for the search queries to run.
//
// From round 2 on the prompt carries the queries already used and the hosts already
// processed, which is what makes the top-up actually fetch NEW sites instead of
// repeating the same results.
func (s *Server) discoveryKeywords(ctx context.Context, p discoveryParams,
	usedQueries, seenHosts []string, round int) ([]string, error) {
	prov, err := s.oneShotProvider()
	if err != nil {
		return nil, fmt.Errorf("关键词生成需要可用的 LLM 配置：%w", err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "目标数量：约 %d 个站点\n希望排除：%s\n\n用户意图：\n%s\n",
		p.TargetCount, orNone(strings.Join(p.Exclude, "、")), p.Query)
	if round > 1 {
		b.WriteString("\n【重要】这是第 ")
		b.WriteString(strconv.Itoa(round))
		b.WriteString(" 轮补搜。上一轮的搜索结果已经包含下面这些站点，请不要再用会搜出同样结果的词：\n")
		if len(seenHosts) > discoverySeenHint {
			seenHosts = seenHosts[len(seenHosts)-discoverySeenHint:]
		}
		b.WriteString("已处理站点：" + strings.Join(seenHosts, "、") + "\n")
		if len(usedQueries) > 0 {
			b.WriteString("已用过的搜索词：" + strings.Join(usedQueries, "、") + "\n")
		}
		b.WriteString("请换【不同角度】的查询词（不同同义词、不同细分场景、英文表述、行业黑话），目标是找到前面没出现过的站点。\n")
		b.WriteString("继续使用 intitle: / inurl: / site: 等搜索算子，不要退回泛词。\n")
	}
	cctx := llmrec.WithWorker(ctx, "discovery-keywords")
	out, err := collectCompletion(cctx, prov, discoveryKeywordSystem(p.Queries), b.String(), 1500)
	if err != nil {
		return nil, err
	}
	var raw []string
	if arr := discoveryJSONArray(out); arr != "" {
		_ = json.Unmarshal([]byte(arr), &raw)
	}
	isUsed := map[string]bool{}
	for _, q := range usedQueries {
		isUsed[strings.ToLower(strings.TrimSpace(q))] = true
	}
	queries := make([]string, 0, len(raw))
	seenQ := map[string]bool{}
	for _, q := range raw {
		q = strings.TrimSpace(q)
		key := strings.ToLower(q)
		if q == "" || len([]rune(q)) > 120 || seenQ[key] || isUsed[key] {
			continue
		}
		seenQ[key] = true
		queries = append(queries, q)
		if len(queries) >= p.Queries {
			break
		}
	}
	if len(queries) == 0 {
		return nil, fmt.Errorf("模型没有产出任何可用的搜索词（重复或无法解析）")
	}
	return queries, nil
}

// discoverySearchRound runs one round's queries and returns the hosts that are NEW to
// this run (already-seen root domains are dropped so later rounds don't re-filter them).
//
// Sequential with a jittered gap on purpose: DuckDuckGo rate-limits by IP, and a burst
// of parallel queries from one IP is the fastest route to 429s. Consecutive rate-limit
// failures abort the round rather than burning the remaining queries — a short list
// that silently looks "done" is worse than a clear failure telling the operator to
// configure a search proxy.
func (s *Server) discoverySearchRound(ctx context.Context, queries []string,
	seen map[string]bool, progress *runProgress) ([]discoveryHarvested, error) {
	opts := s.m.WebSearchOpts()
	cfg := actool.WebSearchConfig{
		Backend: opts.Backend, BraveAPIKey: opts.BraveKey, TavilyAPIKey: opts.TavilyKey,
		Proxy:           opts.Proxy,
		DeepSeekBaseURL: opts.DeepSeekBaseURL, DeepSeekAPIKey: opts.DeepSeekAPIKey,
		DeepSeekModel: opts.DeepSeekModel,
	}
	out := make([]discoveryHarvested, 0, len(queries)*8)
	localSeen := map[string]bool{}
	consecutiveRateLimits := 0

	for i, q := range queries {
		if i > 0 {
			time.Sleep(discoveryJitter())
		}
		// live progress: which keyword is being searched right now
		progress.set("current_query", q)
		progress.set("query_index", toInt(progress.stats["queries_done"])+1)
		progress.flush()

		res, qerr := s.discoveryRunQuery(ctx, cfg, q)
		progress.add("queries_done", 1)
		if qerr != nil {
			progress.add("query_failures", 1)
			progress.flush()
			if isRateLimitErr(qerr) {
				consecutiveRateLimits++
				if consecutiveRateLimits >= discoveryAbortOn429 {
					return out, fmt.Errorf(
						"连续 %d 个查询被搜索引擎限流（%v）。建议：在 系统设置 → Web 搜索 配一个可用的搜索代理（住宅代理可用），或减少查询数后重试",
						consecutiveRateLimits, qerr)
				}
			}
			log.Printf("[discovery] 查询 %q 失败: %v", q, qerr)
			continue
		}
		consecutiveRateLimits = 0
		progress.add("hits", len(res))
		for _, r := range res {
			h, herr := db.NormalizeHost(r.URL)
			if herr != nil {
				continue
			}
			// 按主域收敛：a.example.com 与 b.example.com 是同一个"站点"，只留一条。
			root, _ := db.RootDomain(h)
			if root == "" || seen[root] || localSeen[root] {
				continue
			}
			localSeen[root] = true
			out = append(out, discoveryHarvested{
				Host: root, Root: root, Query: q, URL: r.URL,
				Title: r.Title, Snippet: r.Description,
			})
		}
		progress.set("new_hosts", len(out))
		progress.flush()
	}
	return out, nil
}

func isRateLimitErr(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "rate-limiting") || strings.Contains(s, "429") ||
		strings.Contains(s, "too many requests")
}

// discoveryRunQuery wraps one search call with bounded retries.
func (s *Server) discoveryRunQuery(ctx context.Context, cfg actool.WebSearchConfig, q string) ([]actool.SearchResult, error) {
	var lastErr error
	for attempt := 0; attempt <= 2; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt*attempt) * 2 * time.Second)
		}
		res, err := actool.WebSearchProbe(ctx, cfg, q, discoveryPerQueryLimit)
		if err == nil {
			return res, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// filterTally accumulates per-reason skip counts for the run stats.
func newFilterTally() map[string]any { return map[string]any{} }

func tallyAdd(m map[string]any, key string) { m[key] = toInt(m[key]) + 1 }

// discoveryFilter applies the skip chain to one round's hosts, keeping at most
// `remaining` of them as pending. It returns the two groups separately so the caller
// can accumulate accepted candidates across rounds (the DB insert happens once, at
// the end, so a failed run never leaves half a candidate list behind).
//
// Every dropped host keeps a reason so the operator can see WHY it was not proposed —
// a silently short list is unauditable.
func (s *Server) discoveryFilter(ctx context.Context, p discoveryParams,
	harvested []discoveryHarvested, remaining int) (
	pending []db.DiscoveryCandidate, skipped []db.DiscoveryCandidate, tally map[string]any, err error,
) {
	tally = newFilterTally()
	relevance := map[string]int{}
	pending = make([]db.DiscoveryCandidate, 0, len(harvested))
	skipped = make([]db.DiscoveryCandidate, 0, len(harvested))

	makeCand := func(h discoveryHarvested, status, reason string) db.DiscoveryCandidate {
		return db.DiscoveryCandidate{
			Host: h.Host, RootDomain: h.Root, SourceQuery: h.Query, SourceURL: h.URL,
			Title: h.Title, Snippet: h.Snippet, Relevance: relevance[h.Host],
			Status: status, SkipReason: reason,
		}
	}
	drop := func(h discoveryHarvested, reason, key string) {
		skipped = append(skipped, makeCand(h, db.DiscCandSkipped, reason))
		tallyAdd(tally, key)
	}

	gateway := s.llmHost()
	exclude := make([]string, 0, len(p.Exclude))
	for _, e := range p.Exclude {
		if e = strings.ToLower(strings.TrimSpace(e)); e != "" {
			exclude = append(exclude, e)
		}
	}

	// a) 网关 / 排除词
	stage1 := make([]discoveryHarvested, 0, len(harvested))
	for _, h := range harvested {
		if gateway != "" && h.Host == gateway {
			drop(h, "是当前 LLM 网关地址，不能作为测试目标", "skipped_gateway")
			continue
		}
		haystack := strings.ToLower(h.Host + " " + h.Title + " " + h.Snippet)
		hitWord := ""
		for _, e := range exclude {
			if strings.Contains(haystack, e) {
				hitWord = e
				break
			}
		}
		if hitWord != "" {
			drop(h, "命中排除词："+hitWord, "skipped_exclude")
			continue
		}
		stage1 = append(stage1, h)
	}

	// a2) 聚合/百科/内容农场：关键词再准也挡不住（一篇「十大在线教育平台」就命中所有词），
	// 所以按域名直接丢。放在拦截规则之前：这些域名本来也不会命中拦截，先筛掉省事。
	stage1b := make([]discoveryHarvested, 0, len(stage1))
	for _, h := range stage1 {
		if discoveryIsAggregator(h.Host) {
			drop(h, "聚合/百科/内容站，不是目标站点", "skipped_aggregator")
			continue
		}
		stage1b = append(stage1b, h)
	}
	stage1 = stage1b

	// b) 资产拦截规则（全局）。任务级 allow 列表此刻还不存在——那要等任务建了才有。
	block, err := s.m.pg.ListAssetInterceptRules()
	if err != nil {
		return nil, nil, tally, err
	}
	stage2 := make([]discoveryHarvested, 0, len(stage1))
	for _, h := range stage1 {
		decision := db.EvaluateAssetGate(block, nil, []string{h.Host}, nil, nil)
		if !decision.Allowed {
			drop(h, "命中资产拦截规则："+decision.Reason, "skipped_intercept")
			continue
		}
		stage2 = append(stage2, h)
	}

	// c) 是否测过（跨任务）——本平台以前回答不了的问题。
	hosts := make([]string, 0, len(stage2))
	for _, h := range stage2 {
		hosts = append(hosts, h.Host)
	}
	history, err := s.m.Assets().HostsTestHistory(hosts)
	if err != nil {
		return nil, nil, tally, err
	}
	stage3 := make([]discoveryHarvested, 0, len(stage2))
	for _, h := range stage2 {
		hist := history[h.Host]
		if hist.Tested {
			drop(h, fmt.Sprintf("此前已在 %d 个任务里测过", hist.TaskCount), "skipped_tested")
			continue
		}
		if hist.Known {
			tallyAdd(tally, "known_but_untested") // 已知资产但从没被真正测过：保留
		}
		stage3 = append(stage3, h)
	}

	// d) 存活探测。打的是【目标】而不是搜索引擎，所以走直连、不用搜索代理。
	if p.Liveness {
		alive := make([]discoveryHarvested, 0, len(stage3))
		for _, h := range stage3 {
			if !discoveryAlive(ctx, h.Host) {
				drop(h, "HTTP 探测不通（域名解析失败或站点不可达）", "skipped_dead")
				continue
			}
			alive = append(alive, h)
		}
		stage3 = alive
	}

	// e) 相关性评分。失败则全部保留——评分是精度手段，不能变成新的失败点。
	if p.MinRelevance > 0 && len(stage3) > 0 {
		scores, serr := s.discoveryRelevance(ctx, p, stage3)
		if serr != nil {
			log.Printf("[discovery] 相关性评分失败，保留全部候选: %v", serr)
			tally["relevance_error"] = serr.Error()
		}
		for k, v := range scores {
			relevance[k] = v
		}
		if len(scores) > 0 {
			stage4 := make([]discoveryHarvested, 0, len(stage3))
			for _, h := range stage3 {
				sc, ok := scores[h.Host]
				if !ok { // 没评到的不惩罚
					stage4 = append(stage4, h)
					continue
				}
				if sc < p.MinRelevance {
					drop(h, fmt.Sprintf("相关性 %d 低于阈值 %d", sc, p.MinRelevance), "skipped_irrelevant")
					continue
				}
				stage4 = append(stage4, h)
			}
			stage3 = stage4
		}
	}

	// f) 本轮剩余名额
	if remaining < 0 {
		remaining = 0
	}
	for _, h := range stage3 {
		if len(pending) >= remaining {
			drop(h, "已凑够本轮目标数量", "skipped_over_target")
			continue
		}
		pending = append(pending, makeCand(h, db.DiscCandPending, ""))
	}
	return pending, skipped, tally, nil
}

// discoveryRelevance scores hosts against the intent in batches.
func (s *Server) discoveryRelevance(ctx context.Context, p discoveryParams,
	hosts []discoveryHarvested) (map[string]int, error,
) {
	prov, err := s.oneShotProvider()
	if err != nil {
		return nil, err
	}
	scores := map[string]int{}
	for i := 0; i < len(hosts); i += discoveryRelevanceGap {
		end := i + discoveryRelevanceGap
		if end > len(hosts) {
			end = len(hosts)
		}
		var b strings.Builder
		for _, h := range hosts[i:end] {
			fmt.Fprintf(&b, "- %s | %s | %s\n", h.Host, truncateRunes(h.Title, 120), truncateRunes(h.Snippet, 200))
		}
		user := "用户意图：\n" + p.Query + "\n\n候选站点：\n" + b.String()
		cctx := llmrec.WithWorker(ctx, "discovery-relevance")
		out, err := collectCompletion(cctx, prov, discoveryRelevanceSystem(), user, 1200)
		if err != nil {
			return scores, err
		}
		var rows []struct {
			H string `json:"h"`
			S int    `json:"s"`
		}
		if arr := discoveryJSONArray(out); arr != "" {
			_ = json.Unmarshal([]byte(arr), &rows)
		}
		for _, r := range rows {
			h, err := db.NormalizeHost(r.H)
			if err != nil {
				continue
			}
			sc := r.S
			if sc < 0 {
				sc = 0
			}
			if sc > 100 {
				sc = 100
			}
			scores[h] = sc
		}
	}
	return scores, nil
}

// discoveryAlive does a plain HTTP GET (https, then http). No proxy: this request
// targets the candidate itself, so it must not ride the residential search pool.
func discoveryAlive(ctx context.Context, host string) bool {
	client := &http.Client{Timeout: 5 * time.Second}
	for _, scheme := range []string{"https", "http"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+host+"/", nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; artex-discovery/1.0)")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		return true
	}
	return false
}

// ── small helpers ────────────────────────────────────────────────────────────

func discoveryJitter() time.Duration {
	base := 1500 + rand.Intn(1500) // 1.5s..3.0s
	return time.Duration(base) * time.Millisecond
}

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "无"
	}
	return s
}

// discoveryDefaultGoal 是没填测试目标时的兵底。它必须是【测试目标】而不是搜索意图——
// 之前直接拿 "找 100 个某某站点" 当 task.goal，规划者会把“找站点”当成任务去拆。
func discoveryDefaultGoal(query string) string {
	const base = "对本次发现的站点做授权渗透测试：找出可利用的高危漏洞（远程代码执行、注入、未授权访问、敏感信息泄露等），每个漏洞都要有可复现的执行证据。"
	if q := strings.TrimSpace(query); q != "" {
		return base + "范围来源：" + q
	}
	return base
}

func toInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return 0
}

func truncateRunes(s string, max int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) <= max {
		return string(r)
	}
	return string(r[:max]) + "…"
}

// discoveryJSONArray pulls the first top-level JSON array out of a model reply,
// tolerating fenced blocks and leading prose.
func discoveryJSONArray(text string) string {
	start := strings.Index(text, "[")
	end := strings.LastIndex(text, "]")
	if start < 0 || end <= start {
		return ""
	}
	return text[start : end+1]
}

// discoveryAggregatorDomains 是被 DDG/Bing 高频返回、但几乎不可能是渗透目标的内容站。
// 关键词再精准也挡不住它们（一篇文章「十大在线教育平台」就命中所有词），所以按域名直接丢。
// 匹配规则：主机名等于域名，或以 "."+域名 结尾（覆盖 zhihu.com / www.zhihu.com / baike.baidu.com）。
var discoveryAggregatorDomains = []string{
	// 百科 / 问答 / 社区
	"wikipedia.org", "wikiwand.com", "fandom.com", "quora.com", "reddit.com", "zhihu.com", "baidu.com",
	// 新闻 / 门户 / 内容农场
	"sohu.com", "163.com", "qq.com", "sina.com.cn", "ifeng.com", "thepaper.cn", "people.com.cn",
	"xinhuanet.com", "chinadaily.com.cn", "36kr.com", "huxiu.com", "ithome.com", "cnbeta.com", "tmtpost.com",
	// 技术内容站
	"csdn.net", "cnblogs.com", "jianshu.com", "juejin.cn", "51cto.com", "oschina.net", "segmentfault.com",
	"stackoverflow.com", "stackexchange.com", "medium.com", "dev.to", "github.com", "gitee.com",
	// 社交 / 视频
	"weibo.com", "douban.com", "bilibili.com", "douyin.com", "youtube.com", "facebook.com",
	"x.com", "twitter.com", "linkedin.com", "instagram.com", "pinterest.com", "tiktok.com",
	// 招聘 / 电商 / 点评 / 文档
	"zhaopin.com", "51job.com", "liepin.com", "zhipin.com", "58.com", "indeed.com", "glassdoor.com",
	"taobao.com", "tmall.com", "jd.com", "amazon.com", "aliexpress.com", "yelp.com", "tripadvisor.com",
	"docin.com", "doc88.com", "book118.com", "cnki.net", "wanfangdata.com.cn",
	// 企业库 / 榜单
	"crunchbase.com", "g2.com", "capterra.com", "producthunt.com",
}

// discoveryIsAggregator 判断一个主机是否属于上述内容站。
func discoveryIsAggregator(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return false
	}
	for _, d := range discoveryAggregatorDomains {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}

func discoveryKeywordSystem(n int) string {
	return `你是 ARTEX 渗透测试平台的目标发现助手。用户会用自然语言描述"想找什么样的站点"，
你要把它翻译成**多条可直接喂给搜索引擎的查询式（dork）**。

目标永远是：【尽可能多地命中不同的真实站点域名】，而不是写漂亮的搜索短语。
泛词（"教育"、"平台"、"系统"）只会搜出百科、新闻、招聘、聚合站——那是失败的查询。

## 一、必须使用搜索语法（本任务的核心）
当前后端是 DuckDuckGo / Bing 系，下列算子有效：
- 精确短语："在线教育平台"
- 标题匹配：intitle:"在线教育"   ← 最有效：标题命中说明整站主题就是它
- URL 匹配：inurl:login、inurl:admin、inurl:about、inurl:register
- 站点限定：site:.edu.cn
- 排除：-新闻 -百科、-site:zhihu.com -site:baidu.com

## 二、必须覆盖的组合（每个角度至少一条）
1. intitle:"X"                    —— 整站主题就是 X
2. "X" 官网 / "X" official site     —— 直达企业/产品站
3. "X" 平台 / "X" 系统 / "X" SaaS   —— 产品站
4. inurl:login "X" / inurl:admin "X" —— 该垂直行业的登录/后台入口
5. "X" 有限公司 / "X" 公司           —— 企业站
6. 英文同义词：intitle:"X in english"

## 三、硬性要求
1. 只输出 JSON 字符串数组，不要解释、不要代码围栏：["查询1","查询2"]
2. 输出 ` + strconv.Itoa(n) + ` 条，每条不超过 80 个字符。
3. **至少 2/3 的查询必须带算子**（intitle: / inurl: / site: / 引号短语）。
4. 禁止出现只由 1-2 个泛词构成的查询。
5. 各条要**角度不同**（换算子、换同义词、换行业黑话），不要只改语序或大小写。
6. 不要写任何攻击/漏洞利用相关的内容——这一步只找目标。

## 四、示例（意图：找在线教育平台）
["intitle:\"在线教育\" -新闻 -百科",
 "\"在线教育平台\" 官网",
 "inurl:login \"网校\"",
 "\"在线教育\" 有限公司",
 "intitle:\"在线学习平台\"",
 "inurl:course \"在线教育\""]`
}

func discoveryRelevanceSystem() string {
	return `你是 ARTEX 渗透测试平台的候选目标筛选器。给定用户的意图和一批候选站点
（域名 | 网页标题 | 摘要），判断每个站点与意图的相关程度。

要求：
1. 只输出一个 JSON 数组，不要解释、不要代码围栏：例 [{"h":"example.com","s":85}]
2. 每个候选都要给一个 0-100 的整数分：
   - 90+  明确是用户要找的那类**独立站点 / 产品 / 企业官网**
   - 60-89 大概率相关
   - 40-59 可能相关
   - <40  不相关：百科、新闻媒体、内容农场、问答/论坛/社交、招聘、电商平台、
          文档分享站、导航站，以及任何"只是提到"该主题而非"就是"该主题的站
3. 判断依据优先看**域名本身 + 标题是否就是这个主体**；标题只是文章标题
   （含"如何/什么/十大/排行榜/教程"）一律 <40。
4. h 必须原样使用给定的域名，不要改写、不要补 http、不要加 www。
5. 不要因为站点看起来"有漏洞"就加分——这里只判相关性。`
}
