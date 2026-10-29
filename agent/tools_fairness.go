package agent

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// Per-asset fairness and frontier backpressure.
//
// The failure this file exists to prevent: with several targets in one task, the
// planner kept producing intents for whichever target it had just heard about, every
// window in its overview was filled by that target, and the claim path handed all
// workers that target's intents in creation order. The other targets got one intent
// each — or none — and were never revisited.
//
// Three mechanisms, each addressing a different layer:
//   - assetFocus / balancedFacts: make every target VISIBLE in the overview.
//   - per-asset intent quota:      stop one target from consuming the whole batch.
//   - open-intent cap:            stop the frontier from growing past what workers
//     can drain, which is what "many intents pending" actually was.

// perAssetOpenIntentCap is how many open+running intents one target may accumulate
// before the planner is told to work on something else. Three is deliberate: enough
// for parallel angles on a promising target, not enough to monopolise a 5-worker pool.
const perAssetOpenIntentCap = 3

// OpenIntentCap, if set, returns the maximum number of simultaneously open intents
// for a task. Beyond it add_intent refuses new work so the frontier cannot outrun the
// worker pool. nil = unlimited (previous behaviour). Wired in server/assembly.go.
var OpenIntentCap func() int

// openIntentCapLimit resolves the cap for this task (0 = unlimited).
func (t *ToolSet) openIntentCapLimit() int {
	if OpenIntentCap == nil {
		return 0
	}
	return OpenIntentCap()
}

// assetIntentCounts reads intent activity per asset for this exploration. Best-effort:
// a store error degrades to "no counts", which disables the quota but never blocks
// planning (fairness must not become a new failure mode).
func (t *ToolSet) assetIntentCounts() map[int64]*db.IntentAssetCounts {
	if t.ts == nil {
		return nil
	}
	counts, err := t.ts.IntentCountsByAsset()
	if err != nil {
		return nil
	}
	return counts
}

// assetQuotaExceeded reports why an intent may not be created, or "" when it may.
// counts is threaded through a batch so 8 intents for the same target cannot each see
// the pre-batch count and all pass.
func (t *ToolSet) assetQuotaExceeded(counts map[int64]*db.IntentAssetCounts, assetIDs []json.RawMessage) string {
	if len(counts) == 0 {
		return ""
	}
	for _, raw := range assetIDs {
		id := pid(raw)
		if id <= 0 {
			continue // unanchored intents are global recon; the per-asset rule doesn't apply
		}
		if c := counts[id]; c != nil && c.Open+c.Running >= perAssetOpenIntentCap {
			return "该资产已有 " + strconv.Itoa(c.Open+c.Running) + " 条待办/在跑的意图（上限 " +
				strconv.Itoa(perAssetOpenIntentCap) + "）：先把它们跑完，或换一个还没被覆盖的资产"
		}
	}
	return ""
}

// bumpAssetCounts keeps the in-batch view current after a successful create.
func (t *ToolSet) bumpAssetCounts(counts map[int64]*db.IntentAssetCounts, assetIDs []json.RawMessage) {
	for _, raw := range assetIDs {
		id := pid(raw)
		if id <= 0 {
			continue
		}
		c := counts[id]
		if c == nil {
			c = &db.IntentAssetCounts{}
			counts[id] = c
		}
		c.Open++
	}
}

// assetFocus builds the per-target fairness view for the planner's overview.
//
// Returns (focus, untouched): focus is every target with its intent counts and
// coverage, ordered LEAST-explored first; untouched is the subset that no intent has
// ever run against. Both are intentionally compact — this rides along in every round.
func (t *ToolSet) assetFocus(limit int) ([]map[string]any, []map[string]any) {
	if t.as == nil || t.ts == nil || t.taskID <= 0 {
		return nil, nil
	}
	if limit <= 0 || limit > 40 {
		limit = 20
	}
	counts := t.assetIntentCounts()

	covByAsset := map[int64]db.CoverageAssetStat{}
	if !t.coverageDisabled {
		if stats, err := t.as.CoverageByAsset(t.taskID, 200); err == nil {
			for _, st := range stats {
				covByAsset[st.AssetID] = st
			}
		}
	}

	// QueryByTask returns the assets attached to this task (seeded targets plus
	// whatever discovery added). Over-fetch so ordering by "least explored" happens
	// over the whole set rather than an arbitrary prefix.
	assets, err := t.as.QueryByTask(t.taskID, "", limit*8, 0)
	if err != nil {
		return nil, nil
	}

	type row struct {
		m       map[string]any
		explored int
		assetID int64
	}
	rows := make([]row, 0, len(assets))
	for _, a := range assets {
		var c db.IntentAssetCounts
		if cc := counts[a.ID]; cc != nil {
			c = *cc
		}
		m := map[string]any{
			"asset_id": a.ID,
			"label":    batchAssetLabel(a),
			"type":     a.Type,
			"open":     c.Open,
			"running":  c.Running,
			"finished": c.Finished,
		}
		if st, ok := covByAsset[a.ID]; ok {
			m["cov_total"] = st.Total
			m["cov_touched"] = st.Touched
			if st.Confirmed > 0 {
				m["cov_confirmed"] = st.Confirmed
			}
		}
		rows = append(rows, row{m: m, explored: c.Total(), assetID: a.ID})
	}

	// Least explored first, then by id for stability. This is what makes the
	// overlooked target impossible to miss in the overview.
	for i := 1; i < len(rows); i++ {
		for j := i; j > 0; j-- {
			if rows[j].explored > rows[j-1].explored {
				break
			}
			if rows[j].explored == rows[j-1].explored && rows[j].assetID > rows[j-1].assetID {
				break
			}
			rows[j], rows[j-1] = rows[j-1], rows[j]
		}
	}

	focus := make([]map[string]any, 0, limit)
	untouched := make([]map[string]any, 0, 8)
	for _, r := range rows {
		if r.explored == 0 && len(untouched) < 12 {
			untouched = append(untouched, map[string]any{
				"asset_id": r.m["asset_id"], "label": r.m["label"], "type": r.m["type"],
			})
		}
		if len(focus) < limit {
			focus = append(focus, r.m)
		}
	}
	return focus, untouched
}

// untouchedScopeAssets lists in-scope assets that no intent has ever run against.
// Best-effort: a query error returns nil rather than blocking task completion on
// infrastructure trouble.
func (t *ToolSet) untouchedScopeAssets(limit int) []db.CoverageGap {
	if t.ts == nil || t.taskID <= 0 {
		return nil
	}
	assets, err := t.ts.AssetsWithoutFinishedIntent(t.taskID, limit)
	if err != nil {
		return nil
	}
	return assets
}

// completionBlockedMsg returns a refusal message when the task must not be closed yet,
// or "" when it may. This is the gate that stops "all goals met" from stranding work:
// goals are decomposed once at task start, so proving them says nothing about whether
// every target was actually examined.
func (t *ToolSet) completionBlockedMsg() string {
	untouched := t.untouchedScopeAssets(50)
	if len(untouched) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("还不能收官：范围内还有 ")
	b.WriteString(strconv.Itoa(len(untouched)))
	b.WriteString(" 个资产从未跑过任何意图（有 open 目标不等于真的测过它们）——")
	for i, a := range untouched {
		if i >= 8 {
			b.WriteString(" …等")
			break
		}
		if i > 0 {
			b.WriteString("、")
		}
		b.WriteString(a.Label)
		if a.Label == "" {
			b.WriteString("#")
			b.WriteString(strconv.FormatInt(a.AssetID, 10))
		}
	}
	b.WriteString("。请先用 add_intent 或 batch_sweep 给它们派意图（确属不适用的资产可用 mark_coverage state=na 说明理由排除）。")
	return b.String()
}

// balancedFacts produces the planner's recent-facts window with a per-asset
// round-robin instead of a global "newest N".
//
// A global window is why one busy target could evict every other target from the
// planner's view: its 20 newest facts were all one domain's, so the overview looked
// like the task only had that domain. Round-robin keeps each target represented while
// still preferring the newest fact of each.
func (t *ToolSet) balancedFacts(
	factNodes []*db.Node,
	hidden func(int64) bool,
	factFrom map[int64]int64,
	capacity int,
) []map[string]any {
	if capacity <= 0 {
		return nil
	}
	ids := make([]int64, 0, len(factNodes))
	for _, n := range factNodes {
		if hidden(n.ID) {
			continue
		}
		ids = append(ids, n.ID)
	}
	anchors := map[int64][]int64{}
	if t.ts != nil && len(ids) > 0 {
		if m, err := t.ts.NodeAssets(ids); err == nil {
			anchors = m
		}
	}
	picked := interleaveByAsset(factNodes, anchors, hidden, capacity)
	out := make([]map[string]any, 0, len(picked))
	for _, n := range picked {
		m := compactNode(n)
		if from := factFrom[n.ID]; from > 0 {
			m["from_intent"] = from
		}
		addFactTrustFields(m, n)
		out = append(out, m)
	}
	return out
}

// interleaveByAsset is the pure core of balancedFacts: given nodes ordered newest-first
// and a node→asset map, take up to capacity nodes round-robin across assets.
//
// Unanchored nodes share key 0 and therefore interleave among themselves in the
// original (newest-first) order, degrading gracefully to the old behaviour when no
// anchors exist.
func interleaveByAsset(
	nodes []*db.Node,
	anchors map[int64][]int64,
	hidden func(int64) bool,
	capacity int,
) []*db.Node {
	if capacity <= 0 {
		return nil
	}
	lists := map[int64][]*db.Node{}
	order := make([]int64, 0, 8)
	for _, n := range nodes {
		if hidden != nil && hidden(n.ID) {
			continue
		}
		key := int64(0)
		if as := anchors[n.ID]; len(as) > 0 {
			key = as[0]
		}
		if _, ok := lists[key]; !ok {
			order = append(order, key)
		}
		lists[key] = append(lists[key], n)
	}

	out := make([]*db.Node, 0, capacity)
	for len(out) < capacity {
		progressed := false
		for _, key := range order {
			list := lists[key]
			if len(list) == 0 {
				continue
			}
			out = append(out, list[0])
			lists[key] = list[1:]
			progressed = true
			if len(out) >= capacity {
				break
			}
		}
		if !progressed {
			break
		}
	}
	return out
}
