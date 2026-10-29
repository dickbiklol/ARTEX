package server

import (
	"fmt"
	"strings"
	"testing"
)

// TestParseTargetsMultiDomain is the regression test for the reported bug: a task
// naming several domains must yield ALL of them, not just the first. Previously
// parseTarget returned only the first match, so extra domains never became assets
// and the planner could not see them.
func TestParseTargetsMultiDomain(t *testing.T) {
	got := parseTargets("对 a.example.com b.example.com c.example.com 做渗透测试")
	if len(got) != 3 {
		t.Fatalf("want 3 targets, got %d: %+v", len(got), got)
	}
	want := []string{"a.example.com", "b.example.com", "c.example.com"}
	for i, w := range want {
		if got[i].Host != w {
			t.Errorf("target[%d] host = %q, want %q", i, got[i].Host, w)
		}
		if got[i].Scheme != "https" || got[i].Port != 443 {
			t.Errorf("target[%d] = %s:%d, want https:443", i, got[i].Scheme, got[i].Port)
		}
	}
}

// TestParseTargetsMixedForms covers the scan order (URL → IP → domain) and the
// dedupe rule: the domain-shaped match inside a URL must not create a second,
// port-less entry for the same host, or we would seed the same asset twice with
// conflicting ports.
func TestParseTargetsMixedForms(t *testing.T) {
	text := "先看 http://1.2.3.4:8080/x 和 10.0.0.5:22，再看 https://app.example.com/login 以及 db.example.com:5432"
	got := parseTargets(text)

	byHost := map[string]seedTarget{}
	for _, tg := range got {
		if _, dup := byHost[tg.Host]; dup {
			t.Fatalf("duplicate host %q in %+v", tg.Host, got)
		}
		byHost[tg.Host] = tg
	}
	if len(got) != 4 {
		t.Fatalf("want 4 unique targets, got %d: %+v", len(got), got)
	}

	if tg := byHost["1.2.3.4"]; tg.Scheme != "http" || tg.Port != 8080 {
		t.Errorf("1.2.3.4 = %s:%d, want http:8080 (URL form wins over bare IP)", tg.Scheme, tg.Port)
	}
	if tg := byHost["10.0.0.5"]; tg.Port != 22 {
		t.Errorf("10.0.0.5 port = %d, want 22", tg.Port)
	}
	if tg := byHost["app.example.com"]; tg.Scheme != "https" || tg.Port != 443 {
		t.Errorf("app.example.com = %s:%d, want https:443", tg.Scheme, tg.Port)
	}
	if tg := byHost["db.example.com"]; tg.Port != 5432 || tg.Scheme != "http" {
		t.Errorf("db.example.com = %s:%d, want http:5432", tg.Scheme, tg.Port)
	}
}

// TestParseTargetsDeduplicatesRepeatedHost makes repeated mentions idempotent: a
// domain written twice (e.g. in both description and goal) must seed one asset.
func TestParseTargetsDeduplicatesRepeatedHost(t *testing.T) {
	got := parseTargets("example.com 和 https://example.com/x 和 EXAMPLE.COM")
	if len(got) != 1 {
		t.Fatalf("want 1 deduped target, got %d: %+v", len(got), got)
	}
	if got[0].Host != "example.com" {
		t.Errorf("host = %q, want lowercased example.com", got[0].Host)
	}
}

// TestParseTargetsNoTarget keeps the "prose without a target" path honest: seeding
// nothing is better than seeding garbage, and the caller logs it.
func TestParseTargetsNoTarget(t *testing.T) {
	for _, text := range []string{"", "   ", "扫描一下这台机器", "找出所有高危漏洞"} {
		if got := parseTargets(text); len(got) != 0 {
			t.Errorf("%q: want no targets, got %+v", text, got)
		}
	}
}

// TestParseTargetsCap bounds the blast radius of pasting prose: the cap must be
// enforced and must still return a full, deterministic prefix.
func TestParseTargetsCap(t *testing.T) {
	var b strings.Builder
	for i := 0; i < MaxSeedTargets+15; i++ {
		fmt.Fprintf(&b, "h%d.example.com ", i)
	}
	got := parseTargets(b.String())
	if len(got) != MaxSeedTargets {
		t.Fatalf("want %d targets (cap), got %d", MaxSeedTargets, len(got))
	}
	if got[0].Host != "h0.example.com" {
		t.Errorf("first target = %q, want h0.example.com", got[0].Host)
	}
}

// TestParseTargetStillSingle pins the back-compat wrapper used by the delete-files
// test helper and any other single-target caller.
func TestParseTargetStillSingle(t *testing.T) {
	scheme, host, port, ok := parseTarget("https://one.example.com:8443/path 和 two.example.com")
	if !ok || host != "one.example.com" || scheme != "https" || port != 8443 {
		t.Fatalf("parseTarget = %s %s %d %v, want https one.example.com 8443 true", scheme, host, port, ok)
	}
}
