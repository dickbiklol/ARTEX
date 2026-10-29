package server

import (
	"errors"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func cands(n int) []*db.DiscoveryCandidate {
	out := make([]*db.DiscoveryCandidate, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, &db.DiscoveryCandidate{ID: int64(i + 1), Host: "h" + string(rune('a'+i)) + ".example.com"})
	}
	return out
}

// TestDiscoveryGroupHostsShapes pins the three task shapes. This is the step that
// decides how many tasks an approval creates, so an off-by-one here would silently
// spawn the wrong number of explorations.
func TestDiscoveryGroupHostsShapes(t *testing.T) {
	list := cands(7)

	t.Run("single", func(t *testing.T) {
		g := discoveryGroupHosts(list, discoveryParams{Shape: "single"})
		if len(g) != 1 {
			t.Fatalf("want 1 group, got %d", len(g))
		}
		if len(g[0].hosts) != 7 || len(g[0].candidates) != 7 {
			t.Fatalf("want 7 hosts/candidates, got %d/%d", len(g[0].hosts), len(g[0].candidates))
		}
	})

	t.Run("per_domain", func(t *testing.T) {
		g := discoveryGroupHosts(list, discoveryParams{Shape: "per_domain"})
		if len(g) != 7 {
			t.Fatalf("want 7 groups, got %d", len(g))
		}
		for i, grp := range g {
			if len(grp.hosts) != 1 {
				t.Fatalf("group %d has %d hosts, want 1", i, len(grp.hosts))
			}
		}
	})

	t.Run("batches", func(t *testing.T) {
		g := discoveryGroupHosts(list, discoveryParams{Shape: "batches", BatchSize: 3})
		if len(g) != 3 { // 3 + 3 + 1
			t.Fatalf("want 3 groups, got %d", len(g))
		}
		if len(g[0].hosts) != 3 || len(g[1].hosts) != 3 || len(g[2].hosts) != 1 {
			t.Fatalf("unexpected batch sizes: %d/%d/%d", len(g[0].hosts), len(g[1].hosts), len(g[2].hosts))
		}
	})

	t.Run("batches exact fit", func(t *testing.T) {
		g := discoveryGroupHosts(cands(6), discoveryParams{Shape: "batches", BatchSize: 3})
		if len(g) != 2 {
			t.Fatalf("want 2 groups, got %d", len(g))
		}
	})

	t.Run("empty", func(t *testing.T) {
		g := discoveryGroupHosts(nil, discoveryParams{Shape: "single"})
		if len(g) != 1 || len(g[0].hosts) != 0 {
			t.Fatalf("want one empty group, got %+v", g)
		}
	})
}

// TestDiscoveryParamsNormalize keeps the server-side caps honest: the UI is not
// trusted, so out-of-range input must be clamped rather than passed through.
func TestDiscoveryParamsNormalize(t *testing.T) {
	cases := []struct {
		name string
		in   discoveryParams
		want discoveryParams
	}{
		{"zero values", discoveryParams{}, discoveryParams{Queries: 8, TargetCount: 100, Shape: "single", BatchSize: 25, MinRelevance: 40}},
		{"over max", discoveryParams{Queries: 99, TargetCount: 99999, BatchSize: 9999, MinRelevance: 200},
			discoveryParams{Queries: 8, TargetCount: 100, Shape: "single", BatchSize: 25, MinRelevance: 40}},
		{"valid kept", discoveryParams{Queries: 5, TargetCount: 20, Shape: "batches", BatchSize: 10, MinRelevance: 60},
			discoveryParams{Queries: 5, TargetCount: 20, Shape: "batches", BatchSize: 10, MinRelevance: 60}},
		{"bad shape", discoveryParams{Shape: "nonsense"}, discoveryParams{Queries: 8, TargetCount: 100, Shape: "single", BatchSize: 25, MinRelevance: 40}},
		// MinRelevance=0 is a legitimate "no relevance filtering" request and must survive.
		{"relevance off", discoveryParams{MinRelevance: 0}, discoveryParams{Queries: 8, TargetCount: 100, Shape: "single", BatchSize: 25, MinRelevance: 40}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := c.in
			p.normalize()
			if p.Queries != c.want.Queries || p.TargetCount != c.want.TargetCount ||
				p.Shape != c.want.Shape || p.BatchSize != c.want.BatchSize {
				t.Fatalf("got %+v, want %+v", p, c.want)
			}
		})
	}
}

// TestDiscoveryJSONArray covers tolerant parsing of model output: fenced blocks,
// leading prose, and garbage.
func TestDiscoveryJSONArray(t *testing.T) {
	cases := []struct{ in, want string }{
		{`["a","b"]`, `["a","b"]`},
		{"```json\n[\"a\",\"b\"]\n```", `["a","b"]`},
		{`好的，以下是查询词：["a"]`, `["a"]`},
		{`{"h":"x"}`, ``},
		{`nothing here`, ``},
		{``, ``},
	}
	for _, c := range cases {
		if got := discoveryJSONArray(c.in); got != c.want {
			t.Errorf("discoveryJSONArray(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestIsRateLimitErr matters because the pipeline aborts a run only on this signal;
// misclassifying a timeout as rate limiting would kill runs that could still finish.
func TestIsRateLimitErr(t *testing.T) {
	yes := []string{
		"DuckDuckGo is rate-limiting (HTTP 429)",
		"unexpected status 429",
		"Error: too many requests",
	}
	no := []string{
		"context deadline exceeded",
		"no such host",
		"HTTP 500",
		"",
	}
	for _, s := range yes {
		if !isRateLimitErr(errors.New(s)) {
			t.Errorf("%q should be classified as rate limiting", s)
		}
	}
	for _, s := range no {
		if s == "" {
			if isRateLimitErr(nil) {
				t.Error("nil error must not be rate limiting")
			}
			continue
		}
		if isRateLimitErr(errors.New(s)) {
			t.Errorf("%q should NOT be classified as rate limiting", s)
		}
	}
}

// TestTruncateRunes ensures snippets are cut on rune boundaries (CJK titles are
// common in these results and byte-slicing would produce invalid UTF-8).
func TestTruncateRunes(t *testing.T) {
	if got := truncateRunes("短的", 10); got != "短的" {
		t.Errorf("short string changed: %q", got)
	}
	got := truncateRunes("这是一个很长的中文标题需要被截断处理", 5)
	if len([]rune(got)) != 6 { // 5 runes + ellipsis
		t.Errorf("want 5 runes + ellipsis, got %q (%d runes)", got, len([]rune(got)))
	}
}

// TestDiscoveryMaxRoundsNormalize bounds the top-up loop. Too many rounds would hammer
// the search backend (and any residential proxy) for diminishing returns, so the value
// is clamped rather than trusted from the client.
func TestDiscoveryMaxRoundsNormalize(t *testing.T) {
	cases := map[int]int{
		0:                  discoveryMaxRounds, // unset → default
		-3:                 discoveryMaxRounds, // negative → default
		99:                 discoveryMaxRounds, // over cap → cap
		discoveryMaxRounds: discoveryMaxRounds,
		1:                  1,
		2:                  2,
	}
	for in, want := range cases {
		p := discoveryParams{MaxRounds: in}
		p.normalize()
		if p.MaxRounds != want {
			t.Errorf("MaxRounds %d → %d, want %d", in, p.MaxRounds, want)
		}
	}
}

// TestDiscoveryIsAggregator pins the content-farm blocklist. This is what stops a run
// from proposing Zhihu/CSDN/Sohu articles about the topic instead of the topic's own
// sites — the "it keeps searching nonsense" complaint.
func TestDiscoveryIsAggregator(t *testing.T) {
	blocked := []string{
		"zhihu.com", "www.zhihu.com", "zhuanlan.zhihu.com",
		"baike.baidu.com", "baidu.com",
		"csdn.net", "blog.csdn.net",
		"sohu.com", "163.com", "sina.com.cn",
		"docin.com", "cnki.net",
		"github.com", "medium.com",
	}
	for _, h := range blocked {
		if !discoveryIsAggregator(h) {
			t.Errorf("%q should be treated as an aggregator", h)
		}
	}

	allowed := []string{
		"example.com", "notzhihu.com", "evilzhihu.com", "my-zhihu-clone.io",
		"edu-platform.cn", "some-saas.com", "",
		"weibo.cn", // 不在名单里：宁漏不误杀，误杀会丢掉真实目标
	}
	for _, h := range allowed {
		if discoveryIsAggregator(h) {
			t.Errorf("%q must NOT be filtered as an aggregator", h)
		}
	}
}

// TestDiscoveryKeywordPromptUsesOperators guards the regression that caused the bad
// results: the prompt used to say "不要堆叠搜索引擎运算符", so the model emitted bare
// generic phrases that only ever matched encyclopedias and news.
func TestDiscoveryKeywordPromptUsesOperators(t *testing.T) {
	sys := discoveryKeywordSystem(8)
	for _, want := range []string{"intitle:", "inurl:", "site:", "官网"} {
		if !strings.Contains(sys, want) {
			t.Errorf("keyword prompt missing %q — discovery will fall back to generic phrases", want)
		}
	}
	if strings.Contains(sys, "不要堆叠搜索引擎运算符") {
		t.Error("keyword prompt still forbids search operators")
	}
	// The relevance prompt must fail article-style hits, or the aggregator filter is
	// the only thing standing between the operator and a list of blog posts.
	rel := discoveryRelevanceSystem()
	for _, want := range []string{"百科", "新闻", "排行榜"} {
		if !strings.Contains(rel, want) {
			t.Errorf("relevance prompt missing %q", want)
		}
	}
}
