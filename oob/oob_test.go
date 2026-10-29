package oob

import (
	"strings"
	"testing"
)

// TestMatchRecords covers the dnslog.cn record shape and, more importantly, the
// isolation rule: a hit for another token must never be attributed to this one.
// A false positive here would turn "someone else's callback" into a confirmed
// vulnerability in a report.
func TestMatchRecords(t *testing.T) {
	body := `[["1.2.3.4","aaaa1111bbbb2222.abc.dnslog.cn","2026-10-27 12:00:00"],
	          ["5.6.7.8","othertoken999999.abc.dnslog.cn","2026-10-27 12:00:01"],
	          ["9.9.9.9","AAAA1111BBBB2222.abc.dnslog.cn","2026-10-27 12:00:02"]]`

	hits, err := matchRecords(body, "aaaa1111bbbb2222")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hits) != 2 {
		t.Fatalf("want 2 hits (case-insensitive, same token), got %d: %+v", len(hits), hits)
	}
	if hits[0].Remote != "1.2.3.4" || hits[0].Kind != "dns" {
		t.Errorf("unexpected first hit: %+v", hits[0])
	}
	for _, h := range hits {
		// matching is case-insensitive (DNS is), so compare on the lowered query
		if !strings.Contains(strings.ToLower(h.Query), "aaaa1111bbbb2222") {
			t.Errorf("hit from another token leaked in: %+v", h)
		}
	}
}

func TestMatchRecordsEmptyAndMalformed(t *testing.T) {
	for _, body := range []string{"", "null", "[]", "not json", `{"data":[]}`} {
		hits, err := matchRecords(body, "abc123")
		if err != nil {
			t.Errorf("%q: unexpected error %v", body, err)
		}
		if len(hits) != 0 {
			t.Errorf("%q: want no hits, got %+v", body, hits)
		}
	}
	// wrapped form still parses
	hits, _ := matchRecords(`{"data":[["1.1.1.1","abc123.x.dnslog.cn","t"]]}`, "abc123")
	if len(hits) != 1 {
		t.Errorf("wrapped data form not parsed: %+v", hits)
	}
}

// TestTokenShape guards the DNS-label constraints: the token is prepended to a
// hostname, so it must be a valid label (lowercase hex here).
func TestTokenShape(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		tok, err := newToken()
		if err != nil {
			t.Fatalf("newToken: %v", err)
		}
		if len(tok) != TokenLen {
			t.Fatalf("token length %d, want %d", len(tok), TokenLen)
		}
		for _, r := range tok {
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
				t.Fatalf("token %q is not lowercase hex", tok)
			}
		}
		if seen[tok] {
			t.Fatalf("duplicate token %q", tok)
		}
		seen[tok] = true
	}
}

// TestPollRequiresToken pins the guard that prevents an unfiltered poll: polling
// with an empty token would match every record and report everything as a hit.
func TestPollRequiresToken(t *testing.T) {
	if _, err := Poll(t.Context(), "  ", 0); err == nil {
		t.Fatal("expected an error for an empty token")
	}
}

// TestEndpointOverride covers the two operator escape hatches: a self-hosted
// callback backend, and fully-off.
func TestEndpointOverride(t *testing.T) {
	t.Setenv("ARTEX_OOB_BASE_URL", "")
	t.Setenv("ARTEX_OOB_DISABLED", "")
	if got, err := endpoint(); err != nil || got != baseURL {
		t.Fatalf("default endpoint = %q, %v; want %q", got, err, baseURL)
	}

	t.Setenv("ARTEX_OOB_BASE_URL", "https://oob.example.com/")
	if got, err := endpoint(); err != nil || got != "https://oob.example.com" {
		t.Fatalf("override endpoint = %q, %v; want trailing slash trimmed", got, err)
	}

	t.Setenv("ARTEX_OOB_DISABLED", "true")
	if _, err := endpoint(); err != ErrDisabled {
		t.Fatalf("disabled endpoint err = %v; want ErrDisabled", err)
	}
	// disabled must short-circuit before any network call
	if _, err := NewSession(t.Context()); err != ErrDisabled {
		t.Fatalf("NewSession while disabled = %v; want ErrDisabled", err)
	}
}
