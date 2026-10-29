package agent

import (
	"encoding/json"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func factNodesRange(ids ...int64) []*db.Node {
	out := make([]*db.Node, 0, len(ids))
	for _, id := range ids {
		out = append(out, &db.Node{ID: id, Kind: db.KindFact})
	}
	return out
}

// TestInterleaveByAssetBalancesWindow is the regression test for the reported
// symptom: one busy domain filling the planner's whole "recent facts" window so the
// other domains looked like they did not exist.
//
// 30 facts from asset A (newest first, so they occupy the head of the list) plus 2
// each from B/C/D/E. A global "newest 20" would return 20 A-facts and zero from the
// others; the balanced window must represent every asset.
func TestInterleaveByAssetBalancesWindow(t *testing.T) {
	var nodes []*db.Node
	anchors := map[int64][]int64{}
	// ids descend so the slice is "newest first"
	id := int64(10_000)
	for i := 0; i < 30; i++ {
		nodes = append(nodes, &db.Node{ID: id})
		anchors[id] = []int64{100} // busy asset A
		id--
	}
	for _, asset := range []int64{200, 300, 400, 500} {
		for i := 0; i < 2; i++ {
			nodes = append(nodes, &db.Node{ID: id})
			anchors[id] = []int64{asset}
			id--
		}
	}

	got := interleaveByAsset(nodes, anchors, func(int64) bool { return false }, 20)
	if len(got) != 20 {
		t.Fatalf("want 20 nodes, got %d", len(got))
	}
	perAsset := map[int64]int{}
	for _, n := range got {
		perAsset[anchors[n.ID][0]]++
	}
	if len(perAsset) != 5 {
		t.Fatalf("want all 5 assets represented, got %d: %v", len(perAsset), perAsset)
	}
	// Each of B..E has only 2 facts, so A should fill the remainder.
	for _, asset := range []int64{200, 300, 400, 500} {
		if perAsset[asset] != 2 {
			t.Errorf("asset %d contributed %d facts, want its 2", asset, perAsset[asset])
		}
	}
	if perAsset[100] != 12 {
		t.Errorf("asset 100 contributed %d facts, want 12 (the remainder)", perAsset[100])
	}
}

// TestInterleaveByAssetUnanchored pins the graceful degradation: with no anchors
// everything lands in partition 0 and order is the original newest-first order.
func TestInterleaveByAssetUnanchored(t *testing.T) {
	nodes := factNodesRange(9, 8, 7, 6)
	got := interleaveByAsset(nodes, map[int64][]int64{}, nil, 4)
	if len(got) != 4 {
		t.Fatalf("want 4, got %d", len(got))
	}
	for i, want := range []int64{9, 8, 7, 6} {
		if got[i].ID != want {
			t.Errorf("got[%d] = %d, want %d (newest-first order preserved)", i, got[i].ID, want)
		}
	}
}

// TestInterleaveByAssetHonoursHidden ensures facts folded into a cold digest are not
// resurrected into the overview window.
func TestInterleaveByAssetHonoursHidden(t *testing.T) {
	nodes := factNodesRange(5, 4, 3)
	anchors := map[int64][]int64{5: {1}, 4: {1}, 3: {2}}
	hidden := func(id int64) bool { return id == 5 }
	got := interleaveByAsset(nodes, anchors, hidden, 10)
	if len(got) != 2 {
		t.Fatalf("want 2 visible, got %d", len(got))
	}
	for _, n := range got {
		if n.ID == 5 {
			t.Fatal("hidden node leaked into the window")
		}
	}
}

// TestAssetQuotaExceeded covers the per-asset intent quota that stops one target from
// consuming a whole planner batch.
func TestAssetQuotaExceeded(t *testing.T) {
	raw := func(id int64) json.RawMessage {
		b, _ := json.Marshal(id)
		return b
	}
	counts := map[int64]*db.IntentAssetCounts{
		7: {Open: 2, Running: 1}, // at the cap
		8: {Open: 1},             // room left
	}
	var ts ToolSet

	if msg := ts.assetQuotaExceeded(counts, []json.RawMessage{raw(7)}); msg == "" {
		t.Error("asset at the cap must be refused")
	}
	if msg := ts.assetQuotaExceeded(counts, []json.RawMessage{raw(8)}); msg != "" {
		t.Errorf("asset with room must be allowed, got %q", msg)
	}
	// unknown asset → allowed
	if msg := ts.assetQuotaExceeded(counts, []json.RawMessage{raw(999)}); msg != "" {
		t.Errorf("unknown asset must be allowed, got %q", msg)
	}
	// no asset anchor (global recon) → allowed
	if msg := ts.assetQuotaExceeded(counts, nil); msg != "" {
		t.Errorf("global intent must be allowed, got %q", msg)
	}
	// nil counts (store unavailable) → never blocks planning
	if msg := ts.assetQuotaExceeded(nil, []json.RawMessage{raw(7)}); msg != "" {
		t.Errorf("nil counts must not block, got %q", msg)
	}
}

// TestBumpAssetCountsKeepsBatchViewCurrent makes sure 8 intents for the same asset in
// one batch cannot each see the pre-batch count and all pass the quota.
func TestBumpAssetCountsKeepsBatchViewCurrent(t *testing.T) {
	id := int64(42)
	raw := json.RawMessage("42")
	var ts ToolSet
	counts := map[int64]*db.IntentAssetCounts{id: {Open: perAssetOpenIntentCap - 2}}
	for i := 0; i < 2; i++ {
		if msg := ts.assetQuotaExceeded(counts, []json.RawMessage{raw}); msg != "" {
			t.Fatalf("step %d unexpectedly refused: %s", i, msg)
		}
		ts.bumpAssetCounts(counts, []json.RawMessage{raw})
	}
	if msg := ts.assetQuotaExceeded(counts, []json.RawMessage{raw}); msg == "" {
		t.Fatal("third intent for the same asset in one batch must be refused")
	}
}
