package db

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Target-discovery persistence.
//
// A discovery run is a two-phase object by design: the pipeline fills it with
// candidates (status=pending) and STOPS. Turning candidates into a task is a
// separate, explicit operator action. Nothing here ever creates a task or touches
// task_scope — that separation is what keeps "found on the internet" from silently
// becoming "authorized to test".

// Discovery run statuses, in pipeline order.
const (
	DiscStatusQueued    = "queued"
	DiscStatusKeywords  = "keywords"
	DiscStatusSearching = "searching"
	DiscStatusFiltering = "filtering"
	DiscStatusReady     = "ready"
	DiscStatusStarted   = "started"
	DiscStatusFailed    = "failed"
)

// Discovery candidate statuses. `skipped` = filtered out by policy, `pending` =
// awaiting a human, `approved`/`rejected` = human verdict, `used` = already in a task.
const (
	DiscCandPending  = "pending"
	DiscCandApproved = "approved"
	DiscCandRejected = "rejected"
	DiscCandSkipped  = "skipped"
	DiscCandUsed     = "used"
)

// DiscoveryRun is one search→filter pass.
type DiscoveryRun struct {
	ID        int64           `json:"id"`
	Query     string          `json:"query"`
	Params    json.RawMessage `json:"params"`
	Status    string          `json:"status"`
	Keywords  json.RawMessage `json:"keywords"`
	Stats     json.RawMessage `json:"stats"`
	Error     string          `json:"error,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// DiscoveryCandidate is one host proposed by a run.
type DiscoveryCandidate struct {
	ID          int64     `json:"id"`
	RunID       int64     `json:"run_id"`
	Host        string    `json:"host"`
	RootDomain  string    `json:"root_domain,omitempty"`
	SourceQuery string    `json:"source_query,omitempty"`
	SourceURL   string    `json:"source_url,omitempty"`
	Title       string    `json:"title,omitempty"`
	Snippet     string    `json:"snippet,omitempty"`
	Relevance   int       `json:"relevance"`
	Status      string    `json:"status"`
	SkipReason  string    `json:"skip_reason,omitempty"`
	AssetID     *int64    `json:"asset_id,omitempty"`
	TaskID      *int64    `json:"task_id,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

const discoveryRunCols = `id, query, params, status, keywords, stats, error, created_at, updated_at`

func scanDiscoveryRun(sc interface{ Scan(...any) error }) (*DiscoveryRun, error) {
	var r DiscoveryRun
	var params, keywords, stats []byte
	if err := sc.Scan(&r.ID, &r.Query, &params, &r.Status, &keywords, &stats,
		&r.Error, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return nil, err
	}
	r.Params = json.RawMessage(params)
	r.Keywords = json.RawMessage(keywords)
	r.Stats = json.RawMessage(stats)
	return &r, nil
}

// CreateDiscoveryRun inserts a run in status=queued.
func (d *DB) CreateDiscoveryRun(query string, params map[string]any) (*DiscoveryRun, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, fmt.Errorf("query 不能为空")
	}
	if params == nil {
		params = map[string]any{}
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	return scanDiscoveryRun(d.QueryRow(`
INSERT INTO discovery_runs(query, params) VALUES ($1,$2)
RETURNING `+discoveryRunCols, query, string(raw)))
}

// GetDiscoveryRun loads one run.
func (d *DB) GetDiscoveryRun(id int64) (*DiscoveryRun, error) {
	return scanDiscoveryRun(d.QueryRow(`SELECT `+discoveryRunCols+` FROM discovery_runs WHERE id=$1`, id))
}

// ListDiscoveryRuns returns the newest runs first.
func (d *DB) ListDiscoveryRuns(limit int) ([]*DiscoveryRun, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := d.Query(`SELECT `+discoveryRunCols+` FROM discovery_runs ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*DiscoveryRun, 0, limit)
	for rows.Next() {
		r, err := scanDiscoveryRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SetDiscoveryRunStatus moves a run through the pipeline stages.
func (d *DB) SetDiscoveryRunStatus(id int64, status, errMsg string) error {
	_, err := d.Exec(`UPDATE discovery_runs SET status=$2, error=$3 WHERE id=$1`, id, status, errMsg)
	return err
}

// SetDiscoveryRunKeywords records the queries the model actually produced, so the
// operator can judge result quality ("it searched for the wrong things").
func (d *DB) SetDiscoveryRunKeywords(id int64, keywords []string) error {
	if keywords == nil {
		keywords = []string{}
	}
	raw, err := json.Marshal(keywords)
	if err != nil {
		return err
	}
	_, err = d.Exec(`UPDATE discovery_runs SET keywords=$2 WHERE id=$1`, id, string(raw))
	return err
}

// SetDiscoveryRunStats records per-stage counters for the UI.
func (d *DB) SetDiscoveryRunStats(id int64, stats map[string]any) error {
	if stats == nil {
		stats = map[string]any{}
	}
	raw, err := json.Marshal(stats)
	if err != nil {
		return err
	}
	_, err = d.Exec(`UPDATE discovery_runs SET stats=$2 WHERE id=$1`, id, string(raw))
	return err
}

// DeleteDiscoveryRun removes a run and (via cascade) its candidates.
func (d *DB) DeleteDiscoveryRun(id int64) (bool, error) {
	res, err := d.Exec(`DELETE FROM discovery_runs WHERE id=$1`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// InsertDiscoveryCandidates bulk-inserts candidates, ignoring hosts already present
// for the run (multiple queries routinely hit the same site).
func (d *DB) InsertDiscoveryCandidates(runID int64, cands []DiscoveryCandidate) (int, error) {
	if runID <= 0 || len(cands) == 0 {
		return 0, nil
	}
	inserted := 0
	for _, c := range cands {
		host := DomainKey(c.Host)
		if host == "" {
			continue
		}
		res, err := d.Exec(`
INSERT INTO discovery_candidates(run_id, host, root_domain, source_query, source_url, title, snippet, relevance, status, skip_reason, asset_id)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
ON CONFLICT (run_id, host) DO NOTHING`,
			runID, host, DomainKey(c.RootDomain), c.SourceQuery, c.SourceURL,
			c.Title, c.Snippet, c.Relevance, c.Status, c.SkipReason, c.AssetID)
		if err != nil {
			return inserted, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			inserted++
		}
	}
	return inserted, nil
}

const discoveryCandCols = `id, run_id, host, root_domain, source_query, source_url, title,
       snippet, relevance, status, skip_reason, asset_id, task_id, created_at`

func scanDiscoveryCandidates(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) ([]*DiscoveryCandidate, error) {
	out := []*DiscoveryCandidate{}
	for rows.Next() {
		var c DiscoveryCandidate
		if err := rows.Scan(&c.ID, &c.RunID, &c.Host, &c.RootDomain, &c.SourceQuery,
			&c.SourceURL, &c.Title, &c.Snippet, &c.Relevance, &c.Status,
			&c.SkipReason, &c.AssetID, &c.TaskID, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &c)
	}
	return out, rows.Err()
}

// ListDiscoveryCandidates returns one page of candidates, newest-relevance first.
// status="" returns all statuses.
func (d *DB) ListDiscoveryCandidates(runID int64, status string, limit, offset int) ([]*DiscoveryCandidate, int, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	where := `WHERE run_id=$1`
	args := []any{runID}
	if s := strings.TrimSpace(status); s != "" {
		args = append(args, s)
		where += fmt.Sprintf(" AND status=$%d", len(args))
	}
	var total int
	if err := d.QueryRow(`SELECT count(*) FROM discovery_candidates `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, limit, offset)
	rows, err := d.Query(`SELECT `+discoveryCandCols+` FROM discovery_candidates `+where+
		fmt.Sprintf(` ORDER BY relevance DESC, id ASC LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out, err := scanDiscoveryCandidates(rows)
	return out, total, err
}

// ApprovedDiscoveryCandidates returns the hosts a human approved, in page order.
func (d *DB) ApprovedDiscoveryCandidates(runID int64, limit int) ([]*DiscoveryCandidate, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	rows, err := d.Query(`SELECT `+discoveryCandCols+`
FROM discovery_candidates
WHERE run_id=$1 AND status=$2
ORDER BY id ASC LIMIT $3`, runID, DiscCandApproved, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanDiscoveryCandidates(rows)
}

// SetDiscoveryCandidateStatus sets one candidate's status. Only pending/approved/
// rejected are settable from outside: `skipped` and `used` are pipeline/engine
// states, and letting an API caller write them would corrupt the audit trail.
func (d *DB) SetDiscoveryCandidateStatus(id int64, status string) (bool, error) {
	switch status {
	case DiscCandApproved, DiscCandRejected, DiscCandPending:
	default:
		return false, fmt.Errorf("非法状态 %q：只能设为 approved / rejected / pending", status)
	}
	res, err := d.Exec(`UPDATE discovery_candidates SET status=$2 WHERE id=$1`, id, status)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// SetDiscoveryCandidatesStatus approves/rejects a batch in one statement.
func (d *DB) SetDiscoveryCandidatesStatus(runID int64, ids []int64, status string) (int, error) {
	switch status {
	case DiscCandApproved, DiscCandRejected, DiscCandPending:
	default:
		return 0, fmt.Errorf("非法状态 %q：只能设为 approved / rejected / pending", status)
	}
	if len(ids) == 0 {
		return 0, nil
	}
	res, err := d.Exec(`
UPDATE discovery_candidates SET status=$3
WHERE run_id=$1 AND id = ANY($2::bigint[])`, runID, ids, status)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// MarkDiscoveryCandidatesUsed records that the approved hosts entered a task, so a
// second /start cannot double-create the same scope.
func (d *DB) MarkDiscoveryCandidatesUsed(ids []int64, taskID int64) (int, error) {
	if len(ids) == 0 || taskID <= 0 {
		return 0, nil
	}
	res, err := d.Exec(`
UPDATE discovery_candidates SET status=$2, task_id=$3
WHERE id = ANY($1::bigint[])`, ids, DiscCandUsed, taskID)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// DiscoveryCandidateCounts returns status→count for one run (drives the UI badges).
func (d *DB) DiscoveryCandidateCounts(runID int64) (map[string]int, error) {
	rows, err := d.Query(`SELECT status, count(*) FROM discovery_candidates WHERE run_id=$1 GROUP BY status`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var s string
		var n int
		if err := rows.Scan(&s, &n); err != nil {
			return nil, err
		}
		out[s] = n
	}
	return out, rows.Err()
}
