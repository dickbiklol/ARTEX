package db

// Vulnerability-class catalog — the single source of truth for `vulnclass` values
// in coverage_ledger, and the thing skills/vulnclass-coverage/SKILL.md documents.
//
// A class is only expanded into the ledger for asset types where it can actually
// apply: a bare IP has no "file upload" cell, and an endpoint has no
// "subdomain takeover" cell. Getting AppliesTo wrong either explodes the ledger
// with meaningless rows (which inflates coverage) or silently skips a class that
// should have been tested.

// VulnClass is one testable vulnerability category.
type VulnClass struct {
	Key       string   `json:"key"`
	Name      string   `json:"name"`
	AppliesTo []string `json:"applies_to"` // asset types: endpoint|service|subdomain|ip|root_domain|app
}

// Asset types as stored in assets.type.
const (
	AssetEndpoint   = "endpoint"
	AssetService    = "service"
	AssetSubdomain  = "subdomain"
	AssetIP         = "ip"
	AssetRootDomain = "root_domain"
	AssetApp        = "app"
)

var endpointClasses = []string{
	"sqli", "xss_reflected", "xss_stored", "xss_dom", "ssti", "cmdi", "lfi",
	"ssrf", "xxe", "file_upload", "deserialization", "idor", "auth_bypass",
	"authz_missing", "csrf", "open_redirect", "jwt_oauth", "business_logic",
	"graphql", "host_header", "cors", "rate_limit",
}

var serviceClasses = []string{
	"info_disclosure", "misconfig", "default_creds", "cors", "cache_poisoning",
	"http_smuggling", "weak_crypto", "host_header", "dependency_cve", "rate_limit",
}

var offhostServiceClasses = []string{
	"default_creds", "dependency_cve", "weak_crypto", "misconfig",
}

// VulnClasses is the canonical catalog. Order is display order.
var VulnClasses = []VulnClass{
	{Key: "sqli", Name: "SQL 注入", AppliesTo: []string{AssetEndpoint}},
	{Key: "xss_reflected", Name: "反射型 XSS", AppliesTo: []string{AssetEndpoint}},
	{Key: "xss_stored", Name: "存储型 XSS", AppliesTo: []string{AssetEndpoint, AssetApp}},
	{Key: "xss_dom", Name: "DOM XSS", AppliesTo: []string{AssetEndpoint}},
	{Key: "ssti", Name: "模板注入", AppliesTo: []string{AssetEndpoint}},
	{Key: "cmdi", Name: "命令注入/RCE", AppliesTo: []string{AssetEndpoint}},
	{Key: "lfi", Name: "路径穿越/任意文件读", AppliesTo: []string{AssetEndpoint}},
	{Key: "ssrf", Name: "SSRF", AppliesTo: []string{AssetEndpoint}},
	{Key: "xxe", Name: "XXE", AppliesTo: []string{AssetEndpoint}},
	{Key: "file_upload", Name: "文件上传", AppliesTo: []string{AssetEndpoint}},
	{Key: "deserialization", Name: "反序列化/表达式注入", AppliesTo: []string{AssetEndpoint}},
	{Key: "idor", Name: "越权访问 IDOR/BOLA", AppliesTo: []string{AssetEndpoint}},
	{Key: "auth_bypass", Name: "认证绕过", AppliesTo: []string{AssetEndpoint, AssetService}},
	{Key: "authz_missing", Name: "缺失鉴权", AppliesTo: []string{AssetEndpoint}},
	{Key: "csrf", Name: "CSRF", AppliesTo: []string{AssetEndpoint}},
	{Key: "open_redirect", Name: "开放重定向", AppliesTo: []string{AssetEndpoint}},
	{Key: "jwt_oauth", Name: "JWT/OAuth 缺陷", AppliesTo: []string{AssetEndpoint, AssetService}},
	{Key: "business_logic", Name: "业务逻辑", AppliesTo: []string{AssetEndpoint}},
	{Key: "info_disclosure", Name: "信息泄露", AppliesTo: []string{AssetEndpoint, AssetService}},
	{Key: "misconfig", Name: "配置缺陷", AppliesTo: []string{AssetService}},
	{Key: "default_creds", Name: "默认/弱口令", AppliesTo: []string{AssetService}},
	{Key: "rate_limit", Name: "无速率限制", AppliesTo: []string{AssetEndpoint, AssetService}},
	{Key: "subdomain_takeover", Name: "子域接管", AppliesTo: []string{AssetSubdomain}},
	{Key: "cors", Name: "CORS 配置错误", AppliesTo: []string{AssetEndpoint, AssetService}},
	{Key: "cache_poisoning", Name: "Web 缓存投毒", AppliesTo: []string{AssetService}},
	{Key: "http_smuggling", Name: "HTTP 请求走私", AppliesTo: []string{AssetService}},
	{Key: "graphql", Name: "GraphQL 缺陷", AppliesTo: []string{AssetEndpoint}},
	{Key: "dependency_cve", Name: "第三方组件已知漏洞", AppliesTo: []string{AssetService}},
	{Key: "weak_crypto", Name: "弱加密/明文传输", AppliesTo: []string{AssetService}},
	{Key: "host_header", Name: "Host 头注入", AppliesTo: []string{AssetEndpoint, AssetService}},
}

// Coverage ledger cell states.
const (
	CovUntested      = "untested"
	CovTriedNegative = "tried_negative"
	CovSuspected     = "suspected"
	CovConfirmed     = "confirmed"
	CovNA            = "na"
)

// CoverageAttemptsBar is how many distinct techniques a `tried_negative` cell needs
// before the planner may treat that direction as closed. Mirrors
// agent.minProbeAttemptsForNegative — keep the two in sync; the planner reads
// facts, the ledger reads attempts, and a mismatch makes them disagree about
// whether a direction is dead.
const CoverageAttemptsBar = 3

var vulnClassByKey = func() map[string]VulnClass {
	m := make(map[string]VulnClass, len(VulnClasses))
	for _, c := range VulnClasses {
		m[c.Key] = c
	}
	return m
}()

// VulnClassByKey looks up a catalog entry.
func VulnClassByKey(key string) (VulnClass, bool) {
	c, ok := vulnClassByKey[key]
	return c, ok
}

// IsKnownVulnClass reports whether key is in the catalog.
func IsKnownVulnClass(key string) bool {
	_, ok := vulnClassByKey[key]
	return ok
}

// ClassesForAssetType returns the class keys that can apply to an asset type.
func ClassesForAssetType(assetType string) []string {
	var out []string
	for _, c := range VulnClasses {
		for _, t := range c.AppliesTo {
			if t == assetType {
				out = append(out, c.Key)
				break
			}
		}
	}
	return out
}
