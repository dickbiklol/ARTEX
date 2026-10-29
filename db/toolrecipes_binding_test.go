package db

import "testing"

// TestCoreScannersAreReachableByWorkers guards the wiring that makes the recipe set
// actually usable: a recipe that is deferred *and* unbound is dead weight, and a
// recipe bound to an agent that doesn't exist is the same. These are the scanners a
// worker is expected to reach for without a discovery step.
func TestCoreScannersAreReachableByWorkers(t *testing.T) {
	recipes, err := ToolRecipes()
	if err != nil {
		t.Fatalf("ToolRecipes: %v", err)
	}
	byKey := map[string]Recipe{}
	for _, r := range recipes {
		byKey[r.Key] = r
	}

	// The scanners that should be in the worker's default tool block: the HTTP/API
	// recon and injection set. Ordered by how often they should be used.
	want := []string{
		"nuclei", "ffuf", "dirsearch", "katana", "gau", "waybackurls",
		"paramspider", "arjun", "x8", "dalfox", "sqlmap", "nikto",
		"wpscan", "nmap", "subfinder", "jwt-analyzer", "graphql-scanner",
	}
	for _, key := range want {
		r, ok := byKey[key]
		if !ok {
			t.Errorf("%s: recipe missing (was it excluded by the converter?)", key)
			continue
		}
		if r.Deferred {
			t.Errorf("%s: marked deferred — a worker can't reach it without tool_search", key)
		}
		hasWorker := false
		for _, a := range r.Agents {
			if a == "worker" {
				hasWorker = true
			}
		}
		if !hasWorker {
			t.Errorf("%s: not bound to worker (agents=%v) — it would never surface to a work agent", key, r.Agents)
		}
	}

	// Every recipe must be bound to something, or it is unreachable dead config.
	for _, r := range recipes {
		if len(r.Agents) == 0 {
			t.Errorf("%s: no agent binding", r.Key)
		}
	}

	core := 0
	for _, r := range recipes {
		if !r.Deferred {
			core++
		}
	}
	t.Logf("%d recipes total, %d core (always in the prompt), %d deferred", len(recipes), core, len(recipes)-core)
	if core < 15 {
		t.Errorf("only %d core recipes; workers would fall back to hand-written bash", core)
	}
	if core > 40 {
		t.Errorf("%d core recipes is too many — tool schemas would crowd out the task", core)
	}
}
