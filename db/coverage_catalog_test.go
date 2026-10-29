package db

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var validAssetTypes = map[string]bool{
	AssetEndpoint: true, AssetService: true, AssetSubdomain: true,
	AssetIP: true, AssetRootDomain: true, AssetApp: true,
}

// TestVulnClassCatalogIsCoherent guards the catalog: duplicate keys, unknown asset
// types, or a class that applies to nothing would all silently distort coverage
// (an unusable score is worse than no score, because the planner trusts it).
func TestVulnClassCatalogIsCoherent(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range VulnClasses {
		if c.Key == "" {
			t.Error("class with empty key")
			continue
		}
		if seen[c.Key] {
			t.Errorf("duplicate class key %q", c.Key)
		}
		seen[c.Key] = true

		if !regexp.MustCompile(`^[a-z][a-z0-9_]*$`).MatchString(c.Key) {
			t.Errorf("class key %q must be lower_snake_case", c.Key)
		}
		if strings.TrimSpace(c.Name) == "" {
			t.Errorf("%s: empty display name", c.Key)
		}
		if len(c.AppliesTo) == 0 {
			t.Errorf("%s: applies to no asset type (would never be expanded)", c.Key)
		}
		for _, at := range c.AppliesTo {
			if !validAssetTypes[at] {
				t.Errorf("%s: unknown asset type %q", c.Key, at)
			}
		}
	}
	if len(VulnClasses) < 25 {
		t.Errorf("catalog shrank to %d classes; the 30-class taxonomy is the coverage contract", len(VulnClasses))
	}
}

// TestClassesForAssetType pins the expansion rules that decide which cells exist.
func TestClassesForAssetType(t *testing.T) {
	cases := []struct {
		assetType string
		want      []string
		notWant   []string
	}{
		{AssetEndpoint, []string{"sqli", "idor", "ssrf"}, []string{"subdomain_takeover", "misconfig"}},
		{AssetService, []string{"misconfig", "default_creds", "dependency_cve"}, []string{"sqli", "idor"}},
		{AssetSubdomain, []string{"subdomain_takeover"}, []string{"sqli", "ssrf"}},
		{AssetIP, nil, []string{"sqli", "subdomain_takeover"}},
	}
	for _, tc := range cases {
		got := ClassesForAssetType(tc.assetType)
		set := map[string]bool{}
		for _, g := range got {
			set[g] = true
		}
		for _, w := range tc.want {
			if !set[w] {
				t.Errorf("%s: missing class %q (got %v)", tc.assetType, w, got)
			}
		}
		for _, nw := range tc.notWant {
			if set[nw] {
				t.Errorf("%s: should not include %q", tc.assetType, nw)
			}
		}
	}
}

// TestParamNamesFromJSON covers the assets.params shape (JSONB[] of
// {location,name,value,type}) — a parse miss here silently collapses every
// param-level cell into one asset-level cell, which hides per-parameter gaps.
func TestParamNamesFromJSON(t *testing.T) {
	raw := `[{"location":"query","name":"uid","type":"int"},
	          {"location":"body","name":"uid"},
	          {"location":"query","name":"  "},
	          {"location":"header","name":"X-Token"}]`
	got := paramNamesFromJSON(raw)
	want := []string{"uid", "X-Token"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if p := paramNamesFromJSON("not json"); p != nil {
		t.Fatalf("malformed params should yield nil, got %v", p)
	}
	if p := paramNamesFromJSON("[]"); len(p) != 0 {
		t.Fatalf("empty params should yield none, got %v", p)
	}
}

// TestSkillDocMatchesCatalog keeps skills/vulnclass-coverage/SKILL.md and the Go
// catalog in lockstep. The skill is what agents read; the catalog is what the
// ledger enforces. If they drift, a worker writes a class id the ledger rejects
// (or worse, one the planner never sees).
func TestSkillDocMatchesCatalog(t *testing.T) {
	path := filepath.Join("..", "skills", "vulnclass-coverage", "SKILL.md")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("skill doc not available: %v", err)
	}
	doc := string(raw)

	for _, c := range VulnClasses {
		if !strings.Contains(doc, "`"+c.Key+"`") {
			t.Errorf("class %q is in the Go catalog but not documented in %s", c.Key, path)
		}
	}
	// Every `backticked` id in the class table must exist in the catalog.
	row := regexp.MustCompile("(?m)^\\|\\s*\\d+\\s*\\|\\s*`([a-z0-9_]+)`")
	for _, m := range row.FindAllStringSubmatch(doc, -1) {
		if !IsKnownVulnClass(m[1]) {
			t.Errorf("skill doc lists class %q that the Go catalog does not have", m[1])
		}
	}
}
