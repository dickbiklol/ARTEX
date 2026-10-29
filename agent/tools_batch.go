package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// batch_sweep — queue one vulnerability class across many assets in a single call.
//
// Why this exists: add_intent is deliberately capped (DefaultIntentBatchMax) because
// the planner is invoked every time the graph changes, and letting one wake-up emit
// 200 intents would flood the frontier faster than workers can drain it (starvation,
// stale intents, wasted claims). But "run one check across 80 endpoints" or "probe
// every endpoint that takes an id for IDOR" is a **single** decision that legitimately
// needs many intents — expressing it one-at-a-time either burns the planner's batch
// budget or forces several wake-ups to say the same thing.
//
// So this tool is the one sanctioned bypass of the per-call cap, and it earns that by
// being narrow:
//   - one vulnclass per call (no free-form multi-direction dump),
//   - summaries are generated from a template, so it is a sweep, not a plan,
//   - it de-duplicates against the coverage ledger and against live intents, so
//     calling it twice is cheap,
//   - it is bound to the planner only — a worker can never widen its own queue.
//
// Everything it creates goes through addOneIntent, so asset-scope interception,
// anchor validation and lineage all still apply. There is no back door around the
// scope guard.

const (
	batchSweepDefaultLimit = 50
	batchSweepMaxLimit     = 200
)

// batchCandidate is one asset considered for the sweep.
type batchCandidate struct {
	ID    int64
	Label string
}

func (t *ToolSet) batchSweep() actool.CoreTool {
	return t.writeExpTool("batch_sweep",
		"【批量扫荡】把【同一类漏洞】一次性铺到多个资产上，绕过单次 add_intent 的条数上限。\n"+
			"适用：一条判据要打很多资产（「所有 JSON 接口查 mass assignment」「所有上传点查扩展名校验」「所有带 id 参数的接口查 IDOR」）。\n"+
			"**不适用**：方向各异的多个新方向（用 add_intent 逐条权衡）；串行利用链的下一步（用 add_intent 单条派）。\n\n"+
			"参数：\n"+
			"  · vulnclass 必填，标准类 id（见 vulnclass-coverage）。整批共用同一个类。\n"+
			"  · template 必填，一句话意图模板，用 {asset} 占位（如「测 {asset} 的 IDOR：遍历 id 参数查越权」）。\n"+
			"  · 资产来源三选一（优先级从高到低）：asset_ids 直接列举 | dsl+type 走资产 DSL | 都不传则默认取【该类覆盖台账的缺口资产】。\n"+
			"  · specialist 可选（web|api|ad|cloud|code|infra）；priority 可选（默认 5）。\n"+
			"  · limit 本批最多派多少条，默认 "+strconv.Itoa(batchSweepDefaultLimit)+"，上限 "+strconv.Itoa(batchSweepMaxLimit)+"。\n\n"+
			"**自动去重**（这是它敢一次派很多的原因）：\n"+
			"  · 台账里该类已 confirmed / na / 否定且 attempts 已够 的资产会被跳过；\n"+
			"  · 已有 open/running 意图覆盖「同资产+同类」的会被跳过。\n"+
			"返回 {created, created_ids, considered, skipped:{already_swept, in_flight, rejected}}。",
		obj(map[string]any{
			"vulnclass":  str("必填：整批共用的漏洞类标准 id（sqli / idor / ssrf / file_upload / mass_assignment …）"),
			"template":   str("必填：意图模板，用 {asset} 占位资产标签，如「测 {asset} 的越权：替换 id 遍历」"),
			"asset_ids":  map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "直接指定资产 id 列表（与 dsl 互斥，优先）"},
			"dsl":        str("资产 DSL（见 list_assets 语法），如 method==POST；与 asset_ids 互斥"),
			"type":       str("资产类型过滤：root_domain|ip|subdomain|app|service|endpoint（可与 dsl 叠加）"),
			"specialist": str("本批的方法域（可选）：web|api|ad|cloud|code|infra"),
			"priority":   intp("优先级 0-10，默认 5"),
			"limit":      intp("本批最多派多少条，默认 50，上限 200"),
		}, "vulnclass", "template"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				VulnClass  string  `json:"vulnclass"`
				Template   string  `json:"template"`
				AssetIDs   []int64 `json:"asset_ids"`
				DSL        string  `json:"dsl"`
				Type       string  `json:"type"`
				Specialist string  `json:"specialist"`
				Priority   int     `json:"priority"`
				Limit      int     `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)

			vc := strings.TrimSpace(a.VulnClass)
			if vc == "" {
				return actool.Errorf("vulnclass 必填：整批必须共用同一个漏洞类"), nil
			}
			if !db.IsKnownVulnClass(vc) {
				return actool.Errorf(fmt.Sprintf("未知的 vulnclass %q：请用 vulnclass-coverage 表里的标准 id", vc)), nil
			}
			tmpl := strings.TrimSpace(a.Template)
			if tmpl == "" {
				return actool.Errorf("template 必填：写一句带 {asset} 占位的意图模板"), nil
			}
			if a.Limit <= 0 {
				a.Limit = batchSweepDefaultLimit
			}
			if a.Limit > batchSweepMaxLimit {
				a.Limit = batchSweepMaxLimit
			}
			if t.as == nil || t.taskID <= 0 || t.ts == nil {
				return actool.Errorf("batch_sweep 需要任务上下文（AssetStore 未初始化或没有 task_id）"), nil
			}

			// 前沿背压：本工具是唯一被允许一次派几百条的入口，所以必须和 add_intent 受同一
			// 个上限约束，把额度裁剪到"剩余空间"。不裁剪的话它一调用就能把队列堆到几十上百
			// 条，反过来让"pending 永远跑不到"更严重。
			openNow := 0
			if n, cerr := t.ts.CountOpenIntents(); cerr == nil {
				openNow = n
			}
			if capLimit := t.openIntentCapLimit(); capLimit > 0 {
				remaining := capLimit - openNow
				if remaining <= 0 {
					return jsonResult(map[string]any{
						"refused": true, "open": openNow, "cap": capLimit,
						"message": "前沿已有 " + strconv.Itoa(openNow) + " 条待办（上限 " + strconv.Itoa(capLimit) +
							" = workers×4），本轮不扫荡。等 worker 消化后再扫，或用 add_intent 精确派 1–2 条最关键的。",
					})
				}
				if a.Limit > remaining {
					a.Limit = remaining
				}
			}

			// --- 1) 取候选资产 -------------------------------------------------
			var cands []batchCandidate
			var err error
			switch {
			case len(a.AssetIDs) > 0:
				cands, err = t.batchCandidatesByIDs(a.AssetIDs)
			case strings.TrimSpace(a.DSL) != "":
				cands, err = t.batchCandidatesByDSL(a.DSL, a.Type, a.Limit)
			default:
				cands, err = t.batchCandidatesFromLedger(vc, a.Limit)
			}
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			considered := len(cands)

			// --- 2) 去重：台账已打透 / 已有在跑意图 -----------------------------
			swept := map[int64]bool{}
			ledgerCells := 0
			if !t.coverageDisabled {
				if gapAssets, cells, gerr := t.as.CoverageGapAssets(t.taskID, vc); gerr == nil {
					ledgerCells = cells
					if cells > 0 {
						for _, c := range cands {
							if !gapAssets[c.ID] {
								swept[c.ID] = true // 该类在本资产上已无缺口
							}
						}
					}
				}
			}
			inFlight := t.batchInFlightAssets(vc)

			// --- 3) 生成意图 ---------------------------------------------------
			created := make([]int64, 0, a.Limit)
			skippedSwept, skippedFlight, skippedErr := 0, 0, 0
			for _, c := range cands {
				if len(created) >= a.Limit {
					break
				}
				if swept[c.ID] {
					skippedSwept++
					continue
				}
				if inFlight[c.ID] {
					skippedFlight++
					continue
				}
				it := intentItem{
					Summary:    batchRenderTemplate(tmpl, c.Label, c.ID),
					AssetIDs:   []json.RawMessage{json.RawMessage(strconv.FormatInt(c.ID, 10))},
					Priority:   a.Priority,
					VulnClass:  vc,
					Specialist: a.Specialist,
				}
				id, aerr := t.addOneIntent(it)
				if aerr != nil {
					// 单条失败（多半是资产拦截命中）不该打断整批：跳过并计数，
					// 让 planner 知道有多少条没派成。
					skippedErr++
					continue
				}
				created = append(created, id)
			}

			out := map[string]any{
				"created":     len(created),
				"created_ids": created,
				"considered":  considered,
				"skipped": map[string]int{
					"already_swept": skippedSwept,
					"in_flight":     skippedFlight,
					"rejected":      skippedErr,
				},
				"vulnclass": vc,
			}
			if ledgerCells == 0 && !t.coverageDisabled {
				out["note"] = "该类在覆盖台账里还没有单元格（未展开），因此未做台账去重，仅按在跑意图去重。"
			}
			if len(created) == 0 {
				out["hint"] = "没有派任何意图：候选要么已被打透/在跑/被拦截，要么资产来源为空。换 dsl 或 asset_ids，或等在跑的意图跑完。"
			}
			return jsonResult(out)
		})
}

// batchCandidatesByIDs resolves explicit ids, preserving caller order and dropping
// out-of-scope ids here (rather than at intent creation) so one bad id cannot fail
// the whole batch.
func (t *ToolSet) batchCandidatesByIDs(ids []int64) ([]batchCandidate, error) {
	assets, err := t.as.GetByIDsInScope(t.taskID, ids)
	if err != nil {
		return nil, fmt.Errorf("按 id 取资产失败：%w", err)
	}
	label := make(map[int64]string, len(assets))
	for _, a := range assets {
		label[a.ID] = batchAssetLabel(a)
	}
	out := make([]batchCandidate, 0, len(ids))
	seen := map[int64]bool{}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		if lbl, ok := label[id]; ok {
			seen[id] = true
			out = append(out, batchCandidate{ID: id, Label: lbl})
		}
	}
	return out, nil
}

// batchCandidatesByDSL runs an asset query. It over-fetches because dedupe may drop
// many candidates and the caller's limit applies to *created* intents, not to
// candidates examined.
func (t *ToolSet) batchCandidatesByDSL(dsl, typ string, limit int) ([]batchCandidate, error) {
	fetch := limit * 3
	if fetch > 600 {
		fetch = 600
	}
	assets, err := t.as.QueryDSLInScope(dsl, typ, t.taskID, fetch, 0)
	if err != nil {
		return nil, fmt.Errorf("资产 DSL 错误：%w", err)
	}
	out := make([]batchCandidate, 0, len(assets))
	for _, a := range assets {
		out = append(out, batchCandidate{ID: a.ID, Label: batchAssetLabel(a)})
	}
	return out, nil
}

// batchCandidatesFromLedger is the default source: the assets that still have a gap
// for this class. This is the "sweep whatever is left" mode and needs no DSL.
func (t *ToolSet) batchCandidatesFromLedger(vulnclass string, limit int) ([]batchCandidate, error) {
	gaps, _, err := t.as.ListCoverageGaps(t.taskID, vulnclass, 0, batchSweepMaxLimit)
	if err != nil {
		return nil, fmt.Errorf("查询覆盖缺口失败：%w", err)
	}
	maxCands := limit * 2
	if maxCands > batchSweepMaxLimit {
		maxCands = batchSweepMaxLimit
	}
	out := make([]batchCandidate, 0, len(gaps))
	seen := map[int64]bool{}
	for _, g := range gaps {
		if seen[g.AssetID] {
			continue
		}
		seen[g.AssetID] = true
		out = append(out, batchCandidate{ID: g.AssetID, Label: g.Label})
		if len(out) >= maxCands {
			break
		}
	}
	return out, nil
}

// batchInFlightAssets returns the assets already targeted by an open/running intent
// of the same vulnclass. Without this, two consecutive sweep calls would queue the
// same asset twice and one intent would be pure waste.
func (t *ToolSet) batchInFlightAssets(vulnclass string) map[int64]bool {
	out := map[int64]bool{}
	if t.ts == nil {
		return out
	}
	// The intent payload carries both asset_ids and vulnclass (set by addOneIntent),
	// so this needs no anchor join. Paged because a long task has many intents.
	const pageSize = 200
	for page := 1; page <= 5; page++ {
		nodes, total, err := t.ts.NodesPage(db.NodeFilter{
			Kinds:  []string{db.KindIntent},
			States: []string{"open", "running"},
		}, page, pageSize)
		if err != nil || len(nodes) == 0 {
			break
		}
		for _, n := range nodes {
			if len(n.Payload) == 0 {
				continue
			}
			var p struct {
				VulnClass string  `json:"vulnclass"`
				AssetIDs  []int64 `json:"asset_ids"`
			}
			if err := json.Unmarshal(n.Payload, &p); err != nil {
				continue
			}
			if p.VulnClass != vulnclass {
				continue
			}
			for _, id := range p.AssetIDs {
				out[id] = true
			}
		}
		if page*pageSize >= total {
			break
		}
	}
	return out
}

// batchAssetLabel renders a human-usable name for an asset. Mirrors the COALESCE in
// db.ListCoverageGaps so a swept intent reads the same as the gap row it came from.
func batchAssetLabel(a *db.Asset) string {
	if a == nil {
		return ""
	}
	for _, s := range []string{a.URL, a.Domain, a.IP, a.AppName} {
		if s = strings.TrimSpace(s); s != "" {
			return s
		}
	}
	return ""
}

// batchRenderTemplate fills {asset}/{asset_id} and guarantees the asset is named even
// when the template forgot the placeholder — a sweep whose summaries don't identify
// the target is useless to the worker that claims it.
func batchRenderTemplate(tmpl, label string, id int64) string {
	if label == "" {
		label = "#" + strconv.FormatInt(id, 10)
	}
	hasPlaceholder := strings.Contains(tmpl, "{asset}") || strings.Contains(tmpl, "{asset_id}")
	s := strings.ReplaceAll(tmpl, "{asset}", label)
	s = strings.ReplaceAll(s, "{asset_id}", strconv.FormatInt(id, 10))
	if !hasPlaceholder {
		s = s + "（目标：" + label + "）"
	}
	return s
}
