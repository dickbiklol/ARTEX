package db

import (
	"fmt"
)

// Fairness queries.
//
// Why these exist: the graph used to expose only GLOBAL windows to the planner
// ("20 newest facts", "30 oldest open intents") and the claim path offered only the
// global top-20 intents. With several targets in one task, the busiest target fills
// every window and every claim slot, so the other targets are never worked on. These
// helpers add the missing per-asset dimension:
//   - IntentCountsByAsset  → who is being worked on, who is not
//   - NodeAssets           → which asset a fact/finding belongs to
//   - FrontierBalanced     → hand workers a different asset each time
//
// All of them read exploration_anchors, which every intent/fact writes via
// AddNode/Anchor, so no new bookkeeping column is needed.

// IntentAssetCounts is one asset's intent activity.
type IntentAssetCounts struct {
	Open     int `json:"open"`
	Running  int `json:"running"`
	Finished int `json:"finished"`
}

// Total is the number of intents that ever touched this asset.
func (c IntentAssetCounts) Total() int { return c.Open + c.Running + c.Finished }

// finishedIntentStates are the states that count as "a worker actually ran this and
// produced a terminal outcome". `deleted` is excluded on purpose: a deleted intent is
// not evidence the asset was examined.
var finishedIntentStates = []string{"done", "exhausted", "blocked", "stopped"}

// IntentCountsByAsset aggregates intent states per anchored asset for this
// exploration. An intent anchored to several assets counts for each of them — that is
// intended: working on a shared intent does mean those assets are being touched.
func (s *ExplorationStore) IntentCountsByAsset() (map[int64]*IntentAssetCounts, error) {
	out := map[int64]*IntentAssetCounts{}
	rows, err := s.db.Query(`
SELECT ea.asset_id,
       count(*) FILTER (WHERE n.state = 'open')     AS open_n,
       count(*) FILTER (WHERE n.state = 'running')  AS running_n,
       count(*) FILTER (WHERE n.state = ANY($2))    AS finished_n
FROM exploration_nodes n
JOIN exploration_anchors ea ON ea.node_id = n.id
WHERE n.exploration_id = $1 AND n.kind = 'intent'
GROUP BY ea.asset_id`, s.expID, finishedIntentStates)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var c IntentAssetCounts
		if err := rows.Scan(&id, &c.Open, &c.Running, &c.Finished); err != nil {
			return nil, err
		}
		out[id] = &c
	}
	return out, rows.Err()
}

// AssetsWithoutFinishedIntent lists in-scope assets that no intent has ever run
// against. This is the task-completion gate: closing a task while a target was never
// examined is exactly how "the other domain ran one intent and stopped" became
// permanent.
//
// `na` ledger coverage counts as examined — an operator/agent that deliberately ruled
// a whole asset out should not block completion.
func (s *ExplorationStore) AssetsWithoutFinishedIntent(taskID int64, limit int) ([]CoverageGap, error) {
	if taskID <= 0 {
		return nil, fmt.Errorf("task id required")
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.Query(`WITH `+covTargetCTE+`
SELECT t.id, t.type, t.label
FROM target t
WHERE NOT EXISTS (
        SELECT 1
        FROM exploration_anchors ea
        JOIN exploration_nodes n ON n.id = ea.node_id
        WHERE ea.asset_id = t.id
          AND n.exploration_id = $2
          AND n.kind = 'intent'
          AND n.state = ANY($3))
  AND NOT EXISTS (
        SELECT 1 FROM coverage_ledger cl
        WHERE cl.task_id = $1 AND cl.asset_id = t.id AND cl.state = 'na')
ORDER BY t.id
LIMIT $4`, taskID, s.expID, finishedIntentStates, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CoverageGap
	for rows.Next() {
		var g CoverageGap
		if err := rows.Scan(&g.AssetID, &g.AssetType, &g.Label); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// NodeAssets already exists in digest.go (node id → anchored asset ids); it is used
// here as-is to group facts/findings by asset, so no duplicate is defined.

// nodeColsQualified is nodeCols qualified with the `n` alias, for queries that join.
const nodeColsQualified = `n.id, n.kind, n.payload, n.priority, n.state,
       COALESCE(n.origin,''), COALESCE(n.owner,''), COALESCE(n.blocked_reason,''),
       COALESCE(n.delete_reason,''), n.created_at`

// FrontierBalanced returns up to limit open intents, interleaved across target
// assets instead of strictly by creation order.
//
// Frontier's `priority DESC, id ASC` is global, so a planner round that emitted 8
// intents for one domain hands workers 8 intents for that same domain even when other
// domains have queued work. This variant ranks intents *within* each asset and then
// orders by that rank: every asset's best intent comes first, then every asset's
// second, and so on. FIFO order is preserved inside a single asset, so the "oldest
// intent first" guarantee still holds where it matters.
//
// Intents with no anchored asset share the partition key 0 and therefore interleave
// among themselves exactly as before.
func (s *ExplorationStore) FrontierBalanced(limit int) ([]*Node, error) {
	if limit <= 0 {
		limit = 60
	}
	rows, err := s.db.Query(`
WITH cand AS (
  SELECT n.id, n.priority,
         COALESCE((SELECT min(ea.asset_id)
                   FROM exploration_anchors ea
                   WHERE ea.node_id = n.id), 0) AS asset_key
  FROM exploration_nodes n
  WHERE n.exploration_id = $1 AND n.kind = 'intent' AND n.state = 'open'
), ranked AS (
  SELECT id, priority, asset_key,
         ROW_NUMBER() OVER (PARTITION BY asset_key ORDER BY priority DESC, id ASC) AS rn
  FROM cand
)
SELECT `+nodeColsQualified+`
FROM exploration_nodes n
JOIN ranked r ON r.id = n.id
ORDER BY r.rn ASC, r.priority DESC, r.id ASC
LIMIT $2`, s.expID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanNodes(rows)
}
