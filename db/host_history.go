package db

import (
	"time"
)

// HostTestHistory answers a question the codebase previously could not answer:
// "do we already know this host, and has any LIVE task actually tested it?"
//
// Every other "tested" predicate in this repo is confined to one task
// (covTargetCTE.tested filters en.exploration_id = $2, AssetsWithoutFinishedIntent
// filters n.exploration_id, every coverage_ledger query filters task_id = $1). That
// is correct for planning inside a task, but it means a candidate discovered today
// cannot be checked against last month's engagement — which is exactly what target
// discovery needs before it proposes a domain again.
//
// Matching is deliberately host-level and slightly generous: a host matches any
// asset whose domain, root_domain or ip equals it. So for the root domain
// "example.com", a previously tested "api.example.com" row contributes (its
// root_domain is example.com) and the host counts as tested. For a subdomain
// candidate, only exact `domain` matches apply. That asymmetry is intentional: "we
// already worked on this site" is the question being asked.
type HostTestHistory struct {
	Host      string    `json:"host"`
	AssetIDs  []int64   `json:"asset_ids,omitempty"`
	Known     bool      `json:"known"`  // exists in the global asset table
	Tested    bool      `json:"tested"` // a fact/finding anchor or a touched ledger cell, in a live task
	TaskCount int       `json:"task_count"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
}

// HostsTestHistory resolves history for a batch of hosts in two queries.
//
// "Tested" means EITHER a fact/finding node anchored to one of the host's assets
// inside a live (non-deleted) task, OR a coverage_ledger cell for it that is not
// 'untested'. Both are real evidence a worker examined the host; a bare `task_ids`
// association is not (task creation and asset registration both append it).
func (s *AssetStore) HostsTestHistory(hosts []string) (map[string]HostTestHistory, error) {
	out := map[string]HostTestHistory{}
	clean := make([]string, 0, len(hosts))
	seen := map[string]bool{}
	for _, h := range hosts {
		h = DomainKey(h)
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		clean = append(clean, h)
		out[h] = HostTestHistory{Host: h}
	}
	if len(clean) == 0 {
		return out, nil
	}

	// 1) Known assets per host.
	rows, err := s.db.Query(`
SELECT x.host, a.id
FROM unnest($1::text[]) AS x(host)
JOIN assets a
  ON a.domain = x.host OR a.root_domain = x.host OR a.ip = x.host
ORDER BY a.id`, clean)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var host string
		var id int64
		if err := rows.Scan(&host, &id); err != nil {
			rows.Close()
			return nil, err
		}
		h := out[host]
		h.Known = true
		h.AssetIDs = append(h.AssetIDs, id)
		out[host] = h
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	// 2) Test evidence across all live tasks.
	rows, err = s.db.Query(`
WITH x AS (
    SELECT unnest($1::text[]) AS host
),
a AS (
    SELECT x.host, ass.id AS asset_id
    FROM x
    JOIN assets ass
      ON ass.domain = x.host OR ass.root_domain = x.host OR ass.ip = x.host
),
fact_evidence AS (
    SELECT a.host, t.id AS task_id, max(n.created_at) AS at
    FROM a
    JOIN exploration_anchors ea ON ea.asset_id = a.asset_id
    JOIN exploration_nodes n ON n.id = ea.node_id
    JOIN tasks t ON t.exploration_id = n.exploration_id
    WHERE n.kind IN ('fact','finding') AND t.deleted_at IS NULL
    GROUP BY a.host, t.id
),
ledger_evidence AS (
    SELECT a.host, cl.task_id, max(cl.updated_at) AS at
    FROM a
    JOIN coverage_ledger cl ON cl.asset_id = a.asset_id
    JOIN tasks t ON t.id = cl.task_id
    WHERE cl.state <> 'untested' AND t.deleted_at IS NULL
    GROUP BY a.host, cl.task_id
)
SELECT host, count(DISTINCT task_id) AS task_count, max(at) AS last_at
FROM (SELECT * FROM fact_evidence UNION ALL SELECT * FROM ledger_evidence) u
GROUP BY host`, clean)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var host string
		var taskCount int
		var lastAt *time.Time
		if err := rows.Scan(&host, &taskCount, &lastAt); err != nil {
			return nil, err
		}
		h := out[host]
		h.TaskCount = taskCount
		h.Tested = taskCount > 0
		if lastAt != nil {
			h.LastSeen = *lastAt
		}
		out[host] = h
	}
	return out, rows.Err()
}
