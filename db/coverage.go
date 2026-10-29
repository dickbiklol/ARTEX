package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// Coverage ledger store.
//
// The ledger turns "coverage" from a per-asset boolean into a per-cell state
// machine over (asset, param, vulnclass). Asset-level coverage answered "has
// anyone looked at this host"; the ledger answers "has anyone tried SSRF on this
// parameter" — which is the question that actually decides whether a vuln class
// got missed.
//
// Rows are expanded lazily from the task's scope, never hand-maintained: the
// planner reads gaps, the worker writes back states.

// CoverageCell is one unit of (asset, param, vulnclass).
type CoverageCell struct {
	AssetID   int64
	Param     string
	VulnClass string
}

// CoverageGap is a row the planner should consider working on.
type CoverageGap struct {
	AssetID   int64  `json:"asset_id"`
	AssetType string `json:"asset_type"`
	Label     string `json:"label"`
	Param     string `json:"param,omitempty"`
	VulnClass string `json:"vulnclass"`
	State     string `json:"state"`
	Attempts  int    `json:"attempts"`
}

// CoverageClassStat is the per-class rollup injected into the planner's overview.
type CoverageClassStat struct {
	VulnClass string `json:"vulnclass"`
	Total     int    `json:"total"`
	Touched   int    `json:"touched"`
	Negative  int    `json:"negative"`
	Confirmed int    `json:"confirmed"`
	Attempts  int    `json:"attempts"`
}

// CoverageSummary is the whole-task rollup.
type CoverageSummary struct {
	Cells     int                `json:"cells"`
	Touched   int                `json:"touched"`
	Confirmed int                `json:"confirmed"`
	Pct       *float64           `json:"pct"`
	ByClass   []CoverageClassStat `json:"by_class,omitempty"`
}

// covScopeAssetsSQL lists the in-scope assets of a task together with their params.
// The join predicate intentionally mirrors covTargetCTE (task_scope.go) so the
// ledger's denominator and the legacy asset-coverage figure agree.
const covScopeAssetsSQL = `
SELECT DISTINCT a.id, a.type, COALESCE(to_jsonb(a.params), '[]'::jsonb)::text
FROM assets a
JOIN task_scope ts ON ts.task_id = $1 AND (
     (ts.kind='company'     AND a.company_id  = ts.company_id)
  OR (ts.kind='root_domain' AND a.root_domain = ts.domain)
  OR (ts.kind='subdomain'   AND a.domain      = ts.domain)
  OR (ts.kind IN ('ip','cidr') AND ts.net >>= try_inet(a.ip))
  OR (ts.kind='icp' AND (
       lower(regexp_replace(COALESCE(a.icp,''),     '[[:space:]]+', '', 'g')) = ts.value
    OR lower(regexp_replace(COALESCE(a.app_icp,''), '[[:space:]]+', '', 'g')) = ts.value
     ))
)
ORDER BY a.id`

// scopeAsset is the shape ExpandCoverage needs per asset.
type scopeAsset struct {
	ID     int64
	Type   string
	Params []string // param names, de-duplicated and ordered
}

func (s *AssetStore) scopeAssets(taskID int64) ([]scopeAsset, error) {
	rows, err := s.db.Query(covScopeAssetsSQL, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []scopeAsset
	for rows.Next() {
		var a scopeAsset
		var raw string
		if err := rows.Scan(&a.ID, &a.Type, &raw); err != nil {
			return nil, err
		}
		a.Params = paramNamesFromJSON(raw)
		out = append(out, a)
	}
	return out, rows.Err()
}

// paramNamesFromJSON pulls the `name` field out of each element of an
// assets.params JSON array, preserving first-seen order and dropping blanks.
func paramNamesFromJSON(raw string) []string {
	var items []map[string]any
	if err := json.Unmarshal([]byte(raw), &items); err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, it := range items {
		name, _ := it["name"].(string)
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// DefaultCoverageCellCap bounds how many cells one task may expand to. Past this,
// expansion degrades to asset-level cells (param="") rather than exploding.
const DefaultCoverageCellCap = 20000

// ExpandCoverage builds any missing ledger cells for a task's in-scope assets.
// It is idempotent (ON CONFLICT DO NOTHING) and safe to call every planner round:
// when nothing new is in scope it issues one read and no writes.
//
// Returns the number of cells inserted.
func (s *AssetStore) ExpandCoverage(taskID int64) (int, error) {
	if taskID <= 0 {
		return 0, nil
	}
	assets, err := s.scopeAssets(taskID)
	if err != nil {
		return 0, err
	}
	if len(assets) == 0 {
		return 0, nil
	}

	// Decide granularity first: param-level only while the total stays under the
	// cap, otherwise collapse to one row per (asset, class).
	paramLevel := 0
	for _, a := range assets {
		n := len(ClassKeysForAsset(a))
		if len(a.Params) == 0 {
			paramLevel += n
		} else {
			paramLevel += n * len(a.Params)
		}
	}
	useParams := paramLevel <= DefaultCoverageCellCap

	var cells []CoverageCell
	for _, a := range assets {
		classes := ClassKeysForAsset(a)
		if len(classes) == 0 {
			continue
		}
		if !useParams || len(a.Params) == 0 {
			for _, c := range classes {
				cells = append(cells, CoverageCell{AssetID: a.ID, VulnClass: c})
			}
			continue
		}
		for _, p := range a.Params {
			for _, c := range classes {
				cells = append(cells, CoverageCell{AssetID: a.ID, Param: p, VulnClass: c})
			}
		}
	}
	if len(cells) == 0 {
		return 0, nil
	}
	return s.insertCoverageCells(taskID, cells)
}

// ClassKeysForAsset resolves the catalog for one scope asset. A non-HTTP service
// only gets the credential/crypto/component families — everything web-facing is
// meaningless against SSH.
func ClassKeysForAsset(a scopeAsset) []string {
	if a.Type == AssetService {
		return serviceClasses
	}
	return ClassesForAssetType(a.Type)
}

// insertCoverageCells writes cells in chunks, ignoring duplicates.
func (s *AssetStore) insertCoverageCells(taskID int64, cells []CoverageCell) (int, error) {
	const chunk = 400 // 400 rows × 4 placeholders = 1600 params, well under the PG limit
	total := 0
	for start := 0; start < len(cells); start += chunk {
		end := start + chunk
		if end > len(cells) {
			end = len(cells)
		}
		var b strings.Builder
		b.WriteString(`INSERT INTO coverage_ledger(task_id, asset_id, param, vulnclass) VALUES `)
		args := make([]any, 0, (end-start)*4)
		for i, c := range cells[start:end] {
			if i > 0 {
				b.WriteString(",")
			}
			n := len(args)
			fmt.Fprintf(&b, "($%d,$%d,$%d,$%d)", n+1, n+2, n+3, n+4)
			args = append(args, taskID, c.AssetID, c.Param, c.VulnClass)
		}
		b.WriteString(` ON CONFLICT (task_id, asset_id, param, vulnclass) DO NOTHING`)
		res, err := s.db.Exec(b.String(), args...)
		if err != nil {
			return total, fmt.Errorf("expand coverage cells: %w", err)
		}
		if n, err := res.RowsAffected(); err == nil {
			total += int(n)
		}
	}
	return total, nil
}

// CoverageMark is one worker write-back into the ledger.
type CoverageMark struct {
	AssetID   int64
	Param     string
	VulnClass string
	State     string
	Attempts  int
	IntentID  int64
	FactID    int64
	FindingID int64 // finding *node* id; required when State == confirmed
	Note      string
}

// MarkCoverage upserts one cell. attempts keeps the max ever observed (a re-test
// that tried fewer techniques must not erase an earlier deeper attempt), and the
// provenance pointers only move forward.
func (s *AssetStore) MarkCoverage(taskID int64, m CoverageMark) error {
	if taskID <= 0 {
		return fmt.Errorf("task id required")
	}
	if m.AssetID <= 0 {
		return fmt.Errorf("asset_id 必填")
	}
	if !IsKnownVulnClass(m.VulnClass) {
		return fmt.Errorf("未知的 vulnclass %q：请使用 vulnclass-coverage 表里的标准 id", m.VulnClass)
	}
	switch m.State {
	case CovUntested, CovTriedNegative, CovSuspected, CovConfirmed, CovNA:
	default:
		return fmt.Errorf("非法 state %q：只能是 untested/tried_negative/suspected/confirmed/na", m.State)
	}
	if m.State == CovConfirmed && m.FindingID <= 0 {
		return fmt.Errorf("state=confirmed 必须带 finding_node_id：先 report_finding，再用它返回的节点 id 标记覆盖")
	}
	if m.State == CovTriedNegative && m.Attempts <= 0 {
		return fmt.Errorf("state=tried_negative 必须带 attempts（本次试过几种彼此不同的打法）")
	}
	_, err := s.db.Exec(`
INSERT INTO coverage_ledger(task_id, asset_id, param, vulnclass, state, attempts,
                            last_intent_id, last_fact_id, finding_node_id, note)
VALUES ($1,$2,$3,$4,$5,$6, NULLIF($7::bigint,0), NULLIF($8::bigint,0), NULLIF($9::bigint,0), $10)
ON CONFLICT (task_id, asset_id, param, vulnclass) DO UPDATE SET
  state           = EXCLUDED.state,
  attempts        = GREATEST(coverage_ledger.attempts, EXCLUDED.attempts),
  last_intent_id  = COALESCE(EXCLUDED.last_intent_id, coverage_ledger.last_intent_id),
  last_fact_id    = COALESCE(EXCLUDED.last_fact_id,   coverage_ledger.last_fact_id),
  finding_node_id = COALESCE(EXCLUDED.finding_node_id, coverage_ledger.finding_node_id),
  note            = CASE WHEN EXCLUDED.note <> '' THEN EXCLUDED.note ELSE coverage_ledger.note END,
  updated_at      = now()`,
		taskID, m.AssetID, strings.TrimSpace(m.Param), m.VulnClass, m.State, m.Attempts,
		m.IntentID, m.FactID, m.FindingID, strings.TrimSpace(m.Note))
	if err != nil {
		return fmt.Errorf("mark coverage: %w", err)
	}
	return nil
}

// ListCoverageGaps returns the cells the planner should consider:
// untested, suspected (a lead exists), and tried_negative cells that never met the
// attempts bar. Confirmed/na cells are excluded — they need no work.
func (s *AssetStore) ListCoverageGaps(taskID int64, vulnclass string, assetID int64, limit int) ([]CoverageGap, int, error) {
	if limit <= 0 {
		limit = 40
	}
	if limit > 200 {
		limit = 200
	}
	const where = `
WHERE cl.task_id = $1
  AND (cl.state IN ('untested','suspected')
       OR (cl.state = 'tried_negative' AND cl.attempts < $2))
  AND ($3 = '' OR cl.vulnclass = $3)
  AND ($4 = 0  OR cl.asset_id  = $4)`

	var total int
	if err := s.db.QueryRow(`SELECT count(*) FROM coverage_ledger cl`+where,
		taskID, CoverageAttemptsBar, vulnclass, assetID).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := s.db.Query(`
SELECT cl.asset_id, a.type,
       COALESCE(NULLIF(a.url,''), NULLIF(a.domain,''), NULLIF(a.ip,''), NULLIF(a.app_name,''), '') AS label,
       cl.param, cl.vulnclass, cl.state, cl.attempts
FROM coverage_ledger cl
JOIN assets a ON a.id = cl.asset_id`+where+`
ORDER BY (cl.state = 'suspected') DESC, cl.attempts ASC, cl.vulnclass, cl.asset_id, cl.param
LIMIT $5`, taskID, CoverageAttemptsBar, vulnclass, assetID, limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make([]CoverageGap, 0, limit)
	for rows.Next() {
		var g CoverageGap
		if err := rows.Scan(&g.AssetID, &g.AssetType, &g.Label, &g.Param, &g.VulnClass, &g.State, &g.Attempts); err != nil {
			return nil, 0, err
		}
		out = append(out, g)
	}
	return out, total, rows.Err()
}

// CoverageGapAssets returns, for one vulnerability class, the set of assets that
// still have at least one cell needing work, plus the number of ledger cells that
// exist for the class. Used by batch_sweep to avoid queueing an asset that is
// already exhausted for that class.
//
// The second return value is what makes "no data" distinguishable from "no gaps":
// when a class has never been expanded there are no cells at all, and callers must
// treat that as "unknown" (sweep everything) rather than "nothing left to do".
//
// Granularity note: the set is per asset, not per asset×param. A cell counts as
// needing work if it is untested, suspected, or a shallow negative — matching
// ListCoverageGaps exactly, so the two never disagree about what is left.
func (s *AssetStore) CoverageGapAssets(taskID int64, vulnclass string) (map[int64]bool, int, error) {
	out := map[int64]bool{}
	if taskID <= 0 || strings.TrimSpace(vulnclass) == "" {
		return out, 0, nil
	}

	var cells int
	if err := s.db.QueryRow(
		`SELECT count(*) FROM coverage_ledger WHERE task_id = $1 AND vulnclass = $2`,
		taskID, vulnclass).Scan(&cells); err != nil {
		return out, 0, err
	}
	if cells == 0 {
		return out, 0, nil // class never expanded → caller decides
	}

	rows, err := s.db.Query(`
SELECT DISTINCT asset_id
FROM coverage_ledger
WHERE task_id = $1 AND vulnclass = $2
  AND (state IN ('untested','suspected')
       OR (state = 'tried_negative' AND attempts < $3))`,
		taskID, vulnclass, CoverageAttemptsBar)
	if err != nil {
		return out, cells, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return out, cells, err
		}
		out[id] = true
	}
	return out, cells, rows.Err()
}

// CoverageAssetStat is one asset's ledger rollup — the per-asset counterpart of
// CoverageClassStat. The class rollup answers "which vulnerability class is
// untouched"; this one answers "which target is untouched", which is the question a
// multi-domain task actually needs.
type CoverageAssetStat struct {
	AssetID   int64  `json:"asset_id"`
	Label     string `json:"label,omitempty"`
	Total     int    `json:"total"`
	Touched   int    `json:"touched"`
	Confirmed int    `json:"confirmed"`
}

// CoverageByAsset rolls the ledger up per asset, least-explored first, so the planner
// sees the neglected target instead of only the busiest one.
func (s *AssetStore) CoverageByAsset(taskID int64, limit int) ([]CoverageAssetStat, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.Query(`
SELECT cl.asset_id,
       COALESCE(NULLIF(a.url,''), NULLIF(a.domain,''), NULLIF(a.ip,''), NULLIF(a.app_name,''), '') AS label,
       count(*)                                          AS total,
       count(*) FILTER (WHERE cl.state <> 'untested')     AS touched,
       count(*) FILTER (WHERE cl.state = 'confirmed')     AS confirmed
FROM coverage_ledger cl
JOIN assets a ON a.id = cl.asset_id
WHERE cl.task_id = $1
GROUP BY cl.asset_id, label
ORDER BY (count(*) FILTER (WHERE cl.state <> 'untested'))::float8 / GREATEST(count(*), 1) ASC,
         cl.asset_id ASC
LIMIT $2`, taskID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]CoverageAssetStat, 0, limit)
	for rows.Next() {
		var c CoverageAssetStat
		if err := rows.Scan(&c.AssetID, &c.Label, &c.Total, &c.Touched, &c.Confirmed); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CoverageByClass rolls the ledger up per vulnerability class.
func (s *AssetStore) CoverageByClass(taskID int64) ([]CoverageClassStat, error) {
	rows, err := s.db.Query(`
SELECT vulnclass,
       count(*)                                            AS total,
       count(*) FILTER (WHERE state <> 'untested')         AS touched,
       count(*) FILTER (WHERE state = 'tried_negative')    AS negative,
       count(*) FILTER (WHERE state = 'confirmed')         AS confirmed,
       COALESCE(sum(attempts),0)                           AS attempts
FROM coverage_ledger
WHERE task_id = $1
GROUP BY vulnclass
ORDER BY vulnclass`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CoverageClassStat
	for rows.Next() {
		var c CoverageClassStat
		if err := rows.Scan(&c.VulnClass, &c.Total, &c.Touched, &c.Negative, &c.Confirmed, &c.Attempts); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CoverageSummary returns the whole-task rollup, including per-class detail. The
// pct is "cells with any state other than untested", i.e. a floor — see the
// vulnclass-coverage skill for why a high pct is not a clean bill of health.
func (s *AssetStore) CoverageSummary(taskID int64) (*CoverageSummary, error) {
	sum := &CoverageSummary{}
	if err := s.db.QueryRow(`
SELECT count(*),
       count(*) FILTER (WHERE state <> 'untested'),
       count(*) FILTER (WHERE state = 'confirmed')
FROM coverage_ledger WHERE task_id = $1`, taskID).
		Scan(&sum.Cells, &sum.Touched, &sum.Confirmed); err != nil {
		if err == sql.ErrNoRows {
			return sum, nil
		}
		return nil, err
	}
	if sum.Cells > 0 {
		p := float64(sum.Touched) / float64(sum.Cells)
		sum.Pct = &p
	}
	byClass, err := s.CoverageByClass(taskID)
	if err != nil {
		return sum, err
	}
	sum.ByClass = byClass
	return sum, nil
}

// ReopenNegativesOnCapability flips tried_negative cells back to untested for a set
// of assets. Called when a new fact brings a *capability* (credentials, token,
// internal route, upload primitive): a direction that was closed without that
// capability may well be open with it.
//
// Only cells that never met the attempts bar are reopened — a genuinely exhausted
// direction stays closed unless the caller passes includeDeep.
func (s *AssetStore) ReopenNegativesOnCapability(taskID int64, assetIDs []int64, includeDeep bool) (int, error) {
	if taskID <= 0 || len(assetIDs) == 0 {
		return 0, nil
	}
	bar := CoverageAttemptsBar
	if includeDeep {
		bar = 1 << 30
	}
	res, err := s.db.Exec(`
UPDATE coverage_ledger
   SET state = 'untested', updated_at = now()
 WHERE task_id = $1
   AND asset_id = ANY($2)
   AND state = 'tried_negative'
   AND attempts < $3`,
		taskID, assetIDs, bar)
	if err != nil {
		return 0, fmt.Errorf("reopen negatives: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
