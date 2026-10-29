package db

import (
	"fmt"
	"testing"
	"time"
)

// fairnessFixture builds a task with three assets and an exploration, so the
// per-asset queries have something real to group by (exploration_anchors FKs assets).
type fairnessFixture struct {
	d        *DB
	task     *Task
	expID    int64
	es       *ExplorationStore
	assetIDs []int64
}

func newFairnessFixture(t *testing.T, name string) *fairnessFixture {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	task, err := d.CreateTask(name, "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	suffix := time.Now().UnixNano()
	ids := make([]int64, 0, 3)
	for i := 0; i < 3; i++ {
		id, err := d.Assets().UpsertHTTPService(UpsertHTTPServiceReq{
			URL:    fmt.Sprintf("https://fair-%d-%d.example.test", suffix, i),
			TaskID: task.ID,
		})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	t.Cleanup(func() { _, _ = d.Assets().DeleteByIDs(ids) })

	expID, err := d.CreateExploration(name, "goal")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, expID) })

	return &fairnessFixture{d: d, task: task, expID: expID, es: d.Exploration(expID), assetIDs: ids}
}

func (f *fairnessFixture) intent(t *testing.T, summary string, assetID int64, state string) int64 {
	t.Helper()
	id, err := f.es.AddIntent(map[string]any{"summary": summary}, 5, []int64{assetID}, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if state != "open" {
		if err := f.es.SetIntentState(id, state); err != nil {
			t.Fatal(err)
		}
	}
	return id
}

// TestIntentCountsByAsset covers the per-asset aggregation the planner's fairness
// view and the per-asset intent quota are built on.
func TestIntentCountsByAsset(t *testing.T) {
	f := newFairnessFixture(t, "intent counts by asset")
	a, b, c := f.assetIDs[0], f.assetIDs[1], f.assetIDs[2]

	f.intent(t, "a open 1", a, "open")
	f.intent(t, "a open 2", a, "open")
	f.intent(t, "a running", a, "running")
	f.intent(t, "b open", b, "open")
	f.intent(t, "c done", c, "done")

	counts, err := f.es.IntentCountsByAsset()
	if err != nil {
		t.Fatal(err)
	}
	if got := counts[a]; got == nil || got.Open != 2 || got.Running != 1 || got.Finished != 0 {
		t.Fatalf("asset a counts = %+v, want open=2 running=1 finished=0", got)
	}
	if got := counts[b]; got == nil || got.Open != 1 {
		t.Fatalf("asset b counts = %+v, want open=1", got)
	}
	if got := counts[c]; got == nil || got.Finished != 1 || got.Open != 0 {
		t.Fatalf("asset c counts = %+v, want finished=1 open=0", got)
	}
}

// TestFrontierBalancedInterleavesAcrossAssets is the core regression test: with three
// open intents where two belong to the same asset, a plain global FIFO frontier hands
// out a, a, b — which is exactly how one target monopolises the worker pool. The
// balanced frontier must hand out a then b (then a) instead.
func TestFrontierBalancedInterleavesAcrossAssets(t *testing.T) {
	f := newFairnessFixture(t, "frontier balanced")
	a, b := f.assetIDs[0], f.assetIDs[1]

	a1 := f.intent(t, "a first", a, "open")
	a2 := f.intent(t, "a second", a, "open")
	b1 := f.intent(t, "b first", b, "open")

	assetOf := func(nodeID int64) int64 {
		m, err := f.es.NodeAssets([]int64{nodeID})
		if err != nil || len(m[nodeID]) == 0 {
			t.Fatalf("no anchor for node %d: %v", nodeID, err)
		}
		return m[nodeID][0]
	}

	balanced, err := f.es.FrontierBalanced(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(balanced) != 3 {
		t.Fatalf("want 3 open intents, got %d", len(balanced))
	}
	// Position 0 and 1 must target different assets; with global FIFO (a1,a2,b1) they
	// would be the same asset.
	if assetOf(balanced[0].ID) == assetOf(balanced[1].ID) {
		ids := make([]int64, 0, len(balanced))
		for _, n := range balanced {
			ids = append(ids, n.ID)
		}
		t.Fatalf("first two intents hit the same asset (order %v, created a1=%d a2=%d b1=%d)", ids, a1, a2, b1)
	}
	// Every open intent is still returned exactly once.
	seen := map[int64]bool{}
	for _, n := range balanced {
		if seen[n.ID] {
			t.Fatalf("intent %d returned twice", n.ID)
		}
		seen[n.ID] = true
	}
	for _, want := range []int64{a1, a2, b1} {
		if !seen[want] {
			t.Errorf("intent %d missing from balanced frontier", want)
		}
	}
	// FIFO order is preserved inside one asset: a1 before a2.
	pos := map[int64]int{}
	for i, n := range balanced {
		pos[n.ID] = i
	}
	if pos[a1] > pos[a2] {
		t.Errorf("intra-asset FIFO broken: a1 at %d, a2 at %d", pos[a1], pos[a2])
	}
}

// TestAssetsWithoutFinishedIntent covers the task-completion gate: an asset no intent
// ever ran against must be reported, and running one intent clears it.
func TestAssetsWithoutFinishedIntent(t *testing.T) {
	f := newFairnessFixture(t, "untouched assets gate")
	a, b, c := f.assetIDs[0], f.assetIDs[1], f.assetIDs[2]

	// Scope rows are what the gate enumerates over. AddAutoScope mirrors what seed()
	// does for each target.
	for _, id := range f.assetIDs {
		assets, err := f.d.Assets().GetByIDs([]int64{id})
		if err != nil || len(assets) != 1 {
			t.Fatalf("load asset %d: %v", id, err)
		}
		as := assets[0]
		if err := f.d.Assets().AddAutoScope(f.task.ID, "service", as.Domain, as.URL, as.IP); err != nil {
			t.Fatalf("AddAutoScope for %d: %v", id, err)
		}
	}
	scopes, err := f.d.Assets().ListTaskScope(f.task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(scopes) == 0 {
		t.Skip("no task scope rows materialised — scope semantics differ in this build")
	}

	// Only asset a has a finished intent.
	f.intent(t, "a done", a, "done")

	untouched, err := f.es.AssetsWithoutFinishedIntent(f.task.ID, 50)
	if err != nil {
		t.Fatal(err)
	}
	blocked := map[int64]bool{}
	for _, g := range untouched {
		blocked[g.AssetID] = true
	}
	if blocked[a] {
		t.Errorf("asset %d has a finished intent and must not block completion", a)
	}
	if !blocked[b] || !blocked[c] {
		t.Errorf("assets b=%v c=%v must block completion (untouched=%v)", blocked[b], blocked[c], untouched)
	}

	// An explicit `na` ledger verdict is also enough to clear an asset.
	if err := f.d.Assets().MarkCoverage(f.task.ID, CoverageMark{
		AssetID: c, VulnClass: "sqli", State: CovNA, Note: "不适用",
	}); err != nil {
		t.Fatal(err)
	}
	untouched, err = f.es.AssetsWithoutFinishedIntent(f.task.ID, 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range untouched {
		if g.AssetID == c {
			t.Errorf("asset %d marked na must not block completion", c)
		}
	}
}

// TestCoverageByAssetOrdersLeastExploredFirst keeps the planner's per-target view
// honest: the neglected target must come first, or the view repeats the same
// bias it is meant to fix.
func TestCoverageByAssetOrdersLeastExploredFirst(t *testing.T) {
	f := newFairnessFixture(t, "coverage by asset")
	a, b := f.assetIDs[0], f.assetIDs[1]

	// a: fully touched. b: untouched.
	for _, vc := range []string{"sqli", "idor"} {
		if err := f.d.Assets().MarkCoverage(f.task.ID, CoverageMark{
			AssetID: a, VulnClass: vc, State: CovTriedNegative, Attempts: 3,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.d.Assets().MarkCoverage(f.task.ID, CoverageMark{AssetID: b, VulnClass: "sqli"}); err != nil {
		t.Fatal(err)
	}

	stats, err := f.d.Assets().CoverageByAsset(f.task.ID, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) < 2 {
		t.Fatalf("want 2 asset rows, got %d: %+v", len(stats), stats)
	}
	if stats[0].AssetID != b {
		t.Errorf("least-explored asset should be first: got %d, want %d (%+v)", stats[0].AssetID, b, stats)
	}
	if stats[0].Touched != 0 {
		t.Errorf("asset b touched = %d, want 0", stats[0].Touched)
	}
	for _, st := range stats {
		if st.AssetID == a && (st.Total != 2 || st.Touched != 2) {
			t.Errorf("asset a stats = %+v, want total=2 touched=2", st)
		}
	}
}
