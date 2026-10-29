---
name: vulnclass-coverage
description: 漏洞类覆盖矩阵（30 类，含标准 class id）——规划者据此找"哪类还没打"，worker 据此确认自己这一条属于哪类、该类还有哪些打法没试。
---

# 漏洞类覆盖矩阵

本表是平台覆盖率台账（coverage ledger）的**唯一标准**。代码里的 `vulnclass` 取值必须与下表
`class id` 完全一致——写错名字等于这条覆盖记录丢了。

## 如何用（两种角色两种用法）

**规划者**：
1. 拿到覆盖缺口（`list_coverage_gaps`）后，先补 `untested` 里**按资产类型适用**的类。
2. 派意图时，在 summary 里说清"打哪个资产的哪一类"，并在 `vulnclass` 字段填标准 id。
3. 同一个参数上已有 `tried_negative` 且有 ≥3 次尝试 + evidence 的，不重复派；
   `probe_attempts < 3` 的，派"补齐手段"的意图而不是"重新试一遍"。

**worker**：
1. 开工先认领：本条意图属于哪个 class id。
2. 打开 `web-attack-methods` 对应小节，把"最少试探"清单当待办逐条走。
3. 走完 → `mark_coverage(vulnclass, asset_id, param, state, evidence_fact_id)`。
4. 没走完就被预算掐断 → 记 `tried_negative` 且 `probe_attempts` 填真实次数（<3），
   让规划者知道"这条还没探够"，而不是"这条探过没用"。

## 标准类目

| # | class id | 名称 | 适用资产类型 | 对应打法 |
|---|---|---|---|---|
| 1 | `sqli` | SQL 注入 | endpoint, service | web-attack-methods §1 |
| 2 | `xss_reflected` | 反射型 XSS | endpoint | §2 |
| 3 | `xss_stored` | 存储型 XSS | endpoint, app | §2 |
| 4 | `xss_dom` | DOM XSS | endpoint (SPA) | §2 + api-recon |
| 5 | `ssti` | 模板注入 | endpoint | §3 |
| 6 | `cmdi` | 命令注入 / RCE | endpoint, service | §4 |
| 7 | `lfi` | 路径穿越 / 任意文件读 | endpoint | §5 |
| 8 | `ssrf` | SSRF | endpoint | §6 |
| 9 | `xxe` | XXE | endpoint (XML 接口) | 上传/解析类接口 |
| 10 | `file_upload` | 文件上传 | endpoint | §7 |
| 11 | `deserialization` | 反序列化 / 表达式注入 | endpoint, service | §11 |
| 12 | `idor` | 越权访问（IDOR/BOLA） | endpoint | §8 |
| 13 | `auth_bypass` | 认证绕过 | endpoint, service | §9 |
| 14 | `authz_missing` | 缺失鉴权（未挂中间件） | endpoint | §8 + zero-day 路径 E |
| 15 | `csrf` | CSRF（有状态操作） | endpoint | 表单类端点 |
| 16 | `open_redirect` | 开放重定向 | endpoint | `redirect`/`return`/`next` 参数 |
| 17 | `jwt_oauth` | JWT / OAuth 缺陷 | endpoint, service | §9 |
| 18 | `business_logic` | 业务逻辑 | endpoint | §10 |
| 19 | `info_disclosure` | 信息泄露 | endpoint, service | §12 |
| 20 | `misconfig` | 配置缺陷（actuator/debug/目录列表） | service | §12 |
| 21 | `default_creds` | 默认 / 弱口令 | service | §9 |
| 22 | `rate_limit` | 无速率限制（可爆破/可枚举） | endpoint | §9 |
| 23 | `subdomain_takeover` | 子域接管 | subdomain | 悬空 CNAME/云 bucket |
| 24 | `cors` | CORS 配置错误 | service, endpoint | `Origin` 反射 + `credentials` |
| 25 | `cache_poisoning` | Web 缓存投毒 | service | 非 key 头（`X-Forwarded-Host` 等）|
| 26 | `http_smuggling` | HTTP 请求走私 | service | CL/TE 冲突 |
| 27 | `graphql` | GraphQL 缺陷（内省/批量/深度） | endpoint | 内省 + 别名批量 |
| 28 | `dependency_cve` | 第三方组件已知漏洞 | service, service(非HTTP) | component-vuln-intel |
| 29 | `weak_crypto` | 弱加密 / 明文传输 | service | TLS/哈希/签名 |
| 30 | `host_header` | Host 头注入 | service, endpoint | 密码重置/缓存/路由 |

## 状态定义（写进台账的 state）

| state | 含义 | 谁写 |
|---|---|---|
| `untested` | 范围内、还没人碰 | 系统初始化 |
| `tried_negative` | 试过、无信号。**必须带 attempts** | worker |
| `suspected` | 有线索但没验证（inferred 事实指向它） | worker |
| `confirmed` | 已确认漏洞，**必须带 finding id** | worker |
| `na` | 该类对该资产不适用（如 IP 资产无 file_upload） | 系统/规划者 |

## 三条纪律

1. **`tried_negative` 必须带 attempts**，且 attempts < 3 的会被自动当作"未探够"重新派工。
2. **`confirmed` 必须带 finding id**，否则服务端拒绝写入——这是防"报表注水"的硬门槛。
3. **`na` 要写理由**。一堆 `na` 会让覆盖率虚高；规划者会抽查理由是否成立。

## 无回显类的额外纪律（易漏报区）

下列类目的"最少试探"里**必须包含一次带外回调**，否则这一条算不上探过：

`ssrf`、`xxe`、`sqli`（盲态）、`cmdi`（盲态）、`deserialization`（JNDI/Log4j）、
`open_redirect` 的后端跟随、以及任何"提交后由服务端异步抓取/渲染"的入口。

做法固定三步：`oob_request` → 把返回的 host 拼进 payload 实际发送 → `oob_poll`。
`count>0` 才可写 `confirmed`；`count=0` **只能**写 `suspected` 或 `tried_negative(attempts<3)`，
**绝不能**当作 `tried_negative` 封口——目标不出网、WAF 拦、DNS 走内网解析都会让回调为空，
而漏洞依然存在。详见 skill `pentest-verification` §6。

> 反过来也成立：只在"盲态"成立。若该类已经有回显证据（报错、延迟、内容读取），
> 不必强求回调，直接按对应 class 的确认标准写。

## 覆盖率读法

```
pct = (confirmed + tried_negative + na) / 适用单元格总数
```

- `pct` 是**下限**，不是成绩单。`tried_negative` 撑起来的高覆盖率可能毫无价值
  （30 个参数各试了 1 次 SQLi 就全标 negative）。
- 真正该看的是：**每个 class 的 confirmed 数 + 每个 class 的 attempts 分布**。
  某类全是大面积 `tried_negative` 且 attempts=1 → 那一类整体没探够，该重做。
- 规划者不得在 `pct < 100%` 时给"覆盖率达标"类目标盖章（见 planner 提示的量化验收核对）。
