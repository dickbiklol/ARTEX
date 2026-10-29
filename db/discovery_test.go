package db

import (
	"strings"
	"testing"
)

// TestDiscoveryRunAndCandidateRoundTrip covers the persistence layer end-to-end:
// jsonb params/keywords/stats (the easiest thing to get wrong with pgx), candidate
// dedupe per run, the approval flow, and the used-marker that prevents a second
// /start from re-queuing the same hosts.
func TestDiscoveryRunAndCandidateRoundTrip(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	run, err := d.CreateDiscoveryRun("找 100 个在线教育平台官网", map[string]any{
		"shape": "single", "target_count": 100, "liveness": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.DeleteDiscoveryRun(run.ID) })

	if run.Status != DiscStatusQueued {
		t.Fatalf("new run status = %q, want %q", run.Status, DiscStatusQueued)
	}
	if !strings.Contains(string(run.Params), "target_count") {
		t.Fatalf("params not persisted as jsonb: %s", run.Params)
	}

	if err := d.SetDiscoveryRunKeywords(run.ID, []string{"在线教育平台", "网校 官网"}); err != nil {
		t.Fatal(err)
	}
	if err := d.SetDiscoveryRunStats(run.ID, map[string]any{"queries": 2, "hits": 41}); err != nil {
		t.Fatal(err)
	}
	if err := d.SetDiscoveryRunStatus(run.ID, DiscStatusReady, ""); err != nil {
		t.Fatal(err)
	}

	got, err := d.GetDiscoveryRun(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != DiscStatusReady {
		t.Errorf("status = %q, want ready", got.Status)
	}
	if !strings.Contains(string(got.Keywords), "在线教育平台") {
		t.Errorf("keywords not persisted: %s", got.Keywords)
	}
	if !strings.Contains(string(got.Stats), `"hits"`) {
		t.Errorf("stats not persisted: %s", got.Stats)
	}

	seed := []DiscoveryCandidate{
		{Host: "Alpha.example.com", RootDomain: "alpha.example.com", Status: DiscCandPending, Relevance: 88},
		{Host: "beta.example.com", RootDomain: "beta.example.com", Status: DiscCandPending, Relevance: 52},
		{Host: "news.example.net", RootDomain: "example.net", Status: DiscCandSkipped, SkipReason: "命中排除词：新闻"},
	}
	n, err := d.InsertDiscoveryCandidates(run.ID, seed)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("inserted %d, want 3", n)
	}
	// Re-inserting the same hosts must be a no-op: multiple queries hit the same site.
	again, err := d.InsertDiscoveryCandidates(run.ID, seed)
	if err != nil {
		t.Fatal(err)
	}
	if again != 0 {
		t.Fatalf("duplicate insert added %d rows, want 0", again)
	}

	// Hosts are stored lowercased so later lookups match.
	pending, total, err := d.ListDiscoveryCandidates(run.ID, DiscCandPending, 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(pending) != 2 {
		t.Fatalf("pending total=%d len=%d, want 2/2", total, len(pending))
	}
	if pending[0].Host != "beta.example.com" && pending[0].Host != "alpha.example.com" {
		t.Errorf("unexpected host %q", pending[0].Host)
	}
	for _, c := range pending {
		if c.Host != strings.ToLower(c.Host) {
			t.Errorf("host %q not lowercased", c.Host)
		}
	}

	counts, err := d.DiscoveryCandidateCounts(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if counts[DiscCandPending] != 2 || counts[DiscCandSkipped] != 1 {
		t.Fatalf("counts = %v, want pending=2 skipped=1", counts)
	}

	// Approve one by id, one by the bulk path.
	if ok, err := d.SetDiscoveryCandidateStatus(pending[0].ID, DiscCandApproved); err != nil || !ok {
		t.Fatalf("approve one: ok=%v err=%v", ok, err)
	}
	if _, err := d.SetDiscoveryCandidatesStatus(run.ID, []int64{pending[1].ID}, DiscCandApproved); err != nil {
		t.Fatal(err)
	}
	// `used`/`skipped` are engine states, not API-settable.
	if _, err := d.SetDiscoveryCandidateStatus(pending[0].ID, DiscCandSkipped); err == nil {
		t.Error("SetDiscoveryCandidateStatus must reject engine-only states")
	}

	approved, err := d.ApprovedDiscoveryCandidates(run.ID, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(approved) != 2 {
		t.Fatalf("approved = %d, want 2", len(approved))
	}

	ids := []int64{approved[0].ID, approved[1].ID}
	marked, err := d.MarkDiscoveryCandidatesUsed(ids, 4242)
	if err != nil {
		t.Fatal(err)
	}
	if marked != 2 {
		t.Fatalf("marked %d, want 2", marked)
	}
	if again, err := d.ApprovedDiscoveryCandidates(run.ID, 100); err != nil || len(again) != 0 {
		t.Fatalf("after use approved=%d err=%v, want 0", len(again), err)
	}

	runs, err := d.ListDiscoveryRuns(10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range runs {
		if r.ID == run.ID {
			found = true
		}
	}
	if !found {
		t.Error("run missing from list")
	}

	if ok, err := d.DeleteDiscoveryRun(run.ID); err != nil || !ok {
		t.Fatalf("delete: ok=%v err=%v", ok, err)
	}
	// Cascade must have removed the candidates.
	if _, total, err := d.ListDiscoveryCandidates(run.ID, "", 10, 0); err != nil || total != 0 {
		t.Fatalf("candidates survived run deletion: total=%d err=%v", total, err)
	}
}

// TestHostsTestHistoryEmpty keeps the vacuous case safe: no input must not query.
func TestHostsTestHistoryEmpty(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	got, err := d.Assets().HostsTestHistory(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty map, got %+v", got)
	}
}
