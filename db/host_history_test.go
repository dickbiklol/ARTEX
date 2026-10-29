package db

import "testing"

// TestNormalizeHost covers the strict host parser used to turn untrusted search
// results into candidate domains. Anything that slips through becomes an asset row,
// so junk rejection matters more here than convenience.
func TestNormalizeHost(t *testing.T) {
	ok := map[string]string{
		"https://Example.COM/path?q=1": "example.com",
		"http://example.com:8080/x":    "example.com",
		"example.com":                  "example.com",
		"example.com.":                 "example.com",       // trailing dot
		"  example.com  ":              "example.com",       // padding
		"//example.com/x":              "example.com",       // scheme-relative
		"sub.example.co.uk":            "sub.example.co.uk", // multi-label TLD
		"9.9.9.9":                      "9.9.9.9",           // IP literal, kept as-is
	}
	for in, want := range ok {
		got, err := NormalizeHost(in)
		if err != nil {
			t.Errorf("NormalizeHost(%q) unexpected error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", in, got, want)
		}
	}

	// Rejections: single label, empty labels, bad characters, oversized label.
	bad := []string{
		"", "   ", "localhost", "example", "foo..bar.com",
		"-bad.example.com", "bad-.example.com", "exa mple.com",
		"http://", "http:///path",
	}
	for _, in := range bad {
		if got, err := NormalizeHost(in); err == nil {
			t.Errorf("NormalizeHost(%q) = %q, want an error", in, got)
		}
	}
}

// TestNormalizeHostRootRoundTrip makes sure the two helpers compose the way the
// discovery pipeline uses them: normalise a search-hit URL, then collapse to eTLD+1.
func TestNormalizeHostRootRoundTrip(t *testing.T) {
	h, err := NormalizeHost("https://api.shop.example.co.uk/v1/users")
	if err != nil {
		t.Fatal(err)
	}
	root, isApex := RootDomain(h)
	if isApex {
		t.Errorf("%q should not be treated as an apex", h)
	}
	if root != "example.co.uk" {
		t.Errorf("RootDomain(%q) = %q, want example.co.uk", h, root)
	}
}
