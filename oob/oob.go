// Package oob provides out-of-band (OOB) callback verification.
//
// Why this exists: a large class of vulnerabilities produces no response on the
// attacking connection at all — blind SSRF, blind XXE, blind SQLi, blind command
// injection, Log4j/JNDI. Without an external party that can observe the target
// reaching out, those findings cannot be confirmed, so an agent either drops them
// or records them as `inferred` forever. That is the single biggest reason a
// platform "misses" vulnerabilities that another one reports.
//
// Design: the agent asks for a unique hostname, embeds it in a payload, then polls
// for records. Each request gets its own token so concurrent workers never see
// each other's hits, and the token stays correlatable back to the intent that
// created it.
//
// The default backend is dnslog.cn (a public DNS-logging service, the same one the
// upstream project uses) because it needs no infrastructure on our side. Note it
// only proves that a DNS lookup happened — which is exactly the signal blind vulns
// give. Callers must NOT send the target's hostname to the service: the token is
// random and carries no target information.
package oob

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"sync"
	"time"
)

// Hit is one observed callback.
type Hit struct {
	Kind   string `json:"kind"`        // dns (this backend only observes DNS)
	Remote string `json:"remote"`      // source address, when the service reports it
	Query  string `json:"query"`       // the full name that was resolved
	At     string `json:"at"`          // timestamp as reported by the service
}

// Session is one allocated OOB hostname.
type Session struct {
	Token string `json:"token"` // correlates a poll back to the payload that used it
	Host  string `json:"host"`  // embed this in the payload
}

// ErrDisabled is returned when no OOB backend is configured.
var ErrDisabled = errors.New("OOB 后端未启用")

// baseURL is overridable in tests.
var baseURL = "http://www.dnslog.cn"

// endpoint resolves the backend root:
//   - ARTEX_OOB_DISABLED=1  → ErrDisabled (operator opted out)
//   - ARTEX_OOB_BASE_URL=…  → self-hosted dnslog/interactsh-compatible service
//   - otherwise             → the public default
//
// The override matters on VPSs whose egress is restricted or whose case requires
// the callbacks to land on infrastructure the client controls.
func endpoint() (string, error) {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ARTEX_OOB_DISABLED"))) {
	case "1", "true", "yes", "on":
		return "", ErrDisabled
	}
	if v := strings.TrimSpace(os.Getenv("ARTEX_OOB_BASE_URL")); v != "" {
		return strings.TrimRight(v, "/"), nil
	}
	return baseURL, nil
}

// TokenLen is the token length; 16 hex chars is plenty of collision resistance and
// stays a legal DNS label.
const TokenLen = 16

var (
	mu       sync.Mutex
	shared   *http.Client
	baseOnce string // cached dnslog base domain for this process
)

// client returns a shared HTTP client with a cookie jar (dnslog scopes records to
// the session cookie). Proxy is explicitly disabled: these calls are ours, not
// target traffic, and must never be routed through the recording proxy.
func client() *http.Client {
	mu.Lock()
	defer mu.Unlock()
	if shared == nil {
		jar, _ := cookiejar.New(nil)
		shared = &http.Client{
			Timeout: 15 * time.Second,
			Jar:     jar,
			Transport: &http.Transport{
				Proxy:               nil,
				MaxIdleConns:        4,
				IdleConnTimeout:     30 * time.Second,
				TLSHandshakeTimeout: 10 * time.Second,
			},
		}
	}
	return shared
}

// newToken returns a random lowercase hex token.
func newToken() (string, error) {
	b := make([]byte, TokenLen/2)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

// NewSession allocates a fresh OOB hostname.
func NewSession(ctx context.Context) (*Session, error) {
	tok, err := newToken()
	if err != nil {
		return nil, err
	}
	base, err := baseDomain(ctx)
	if err != nil {
		return nil, err
	}
	return &Session{Token: tok, Host: tok + "." + base}, nil
}

// baseDomain fetches (and caches) the session's base logging domain.
func baseDomain(ctx context.Context) (string, error) {
	mu.Lock()
	if baseOnce != "" {
		b := baseOnce
		mu.Unlock()
		return b, nil
	}
	mu.Unlock()

	root, err := endpoint()
	if err != nil {
		return "", err
	}
	body, err := get(ctx, root+"/getdomain.php")
	if err != nil {
		return "", fmt.Errorf("获取 OOB 域名失败：%w", err)
	}
	base := strings.TrimSpace(strings.Trim(string(body), "%\r\n "))
	if base == "" || !strings.Contains(base, ".") {
		return "", fmt.Errorf("OOB 服务返回了无效域名：%q", body)
	}
	mu.Lock()
	baseOnce = base
	mu.Unlock()
	return base, nil
}

func get(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; artex-oob/1.0)")
	resp, err := client().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return string(body), nil
}

// Poll returns the hits that mention token's hostname.
//
// wait is a courtesy delay: DNS propagation and the target's own async processing
// mean an immediate poll usually comes back empty even when the bug is real. The
// caller-supplied wait is capped so a misbehaving tool call cannot hang a run.
func Poll(ctx context.Context, token string, wait time.Duration) ([]Hit, error) {
	token = strings.TrimSpace(strings.ToLower(token))
	if token == "" {
		return nil, errors.New("token 必填")
	}
	if wait > 60*time.Second {
		wait = 60 * time.Second
	}
	if wait > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}

	root, err := endpoint()
	if err != nil {
		return nil, err
	}
	body, err := get(ctx, root+"/getrecords.php")
	if err != nil {
		return nil, fmt.Errorf("查询 OOB 记录失败：%w", err)
	}
	return matchRecords(body, token)
}

// matchRecords filters the service's record list down to this token.
//
// The service returns a JSON array of rows; each row is an array of cells such as
// ["1.2.3.4", "token.abc.dnslog.cn", "2026-10-27 12:00:00"]. The shape is not
// guaranteed, so parsing degrades to "no hits" rather than erroring — a parsing
// quirk must never look like a confirmed vulnerability.
func matchRecords(body, token string) ([]Hit, error) {
	body = strings.TrimSpace(body)
	if body == "" || body == "null" || body == "[]" {
		return nil, nil
	}
	var rows [][]any
	if err := json.Unmarshal([]byte(body), &rows); err != nil {
		// tolerate a wrapped object: {"data": [...]}
		var wrapped struct {
			Data [][]any `json:"data"`
		}
		if e2 := json.Unmarshal([]byte(body), &wrapped); e2 != nil {
			return nil, nil
		}
		rows = wrapped.Data
	}

	want := strings.ToLower(token) + "."
	var out []Hit
	for _, row := range rows {
		var remote, query, at string
		for i, cell := range row {
			s, ok := cell.(string)
			if !ok {
				continue
			}
			switch i {
			case 0:
				remote = s
			case 1:
				query = s
			case 2:
				at = s
			}
		}
		if query == "" || !strings.Contains(strings.ToLower(query), want) {
			continue
		}
		out = append(out, Hit{Kind: "dns", Remote: remote, Query: query, At: at})
	}
	return out, nil
}

// ResetForTest clears cached state (test helper).
func ResetForTest() {
	mu.Lock()
	shared = nil
	baseOnce = ""
	mu.Unlock()
}
