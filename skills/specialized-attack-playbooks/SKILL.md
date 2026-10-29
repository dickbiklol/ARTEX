---
name: specialized-attack-playbooks
description: 专项场景打法索引——网关/中间件钥匙泄露、中间人、CDN 回源与云存储链、未授权访问面板、源码/备份泄露、供应链与 CI。用于"通用 web 打法打不动"时换思路。
---

# 专项场景打法索引

通用打法（`web-attack-methods`）覆盖不了的场景，按图索骥换思路。
每条给的是**入口信号 → 打点 → 确认标准**。

## 1. 网关 / 中间件钥匙泄露（GoEdge、APISIX、Kong、Nginx 配置）

**信号**：响应头带 `GoEdge`/`APISIX`/`Server: openresty`，或管理端口 8000/9080/9180 可达。

- GoEdge：`/` 管理面板未改默认凭据 → 进面板后可改所有站点规则、看全部证书私钥。
- APISIX：`/apisix/admin/routes` 无 token → 可增删路由（等于改所有流量走向）。
- Kong：`/` 8001 管理端口暴露 → 同上。

**确认标准**：能**读到一个真实的配置项并改回来**（改→读→还原），或读到证书私钥。
只看到登录页不算。

## 2. 中间人 / 流量劫持（授权内网）

**信号**：与目标在同一广播域，且存在 ARP/LLMNR/NBT-NS 请求。
- 只做**被动监听 + 一次可控验证**（自己的测试机发一个请求，看能否抓到）。
- 不做 ARP 泛洪污染生产网络（会让业务中断）。

## 3. CDN 回源 / 云存储链

**信号**：站点走 CDN；`X-Cache`/`Via` 头；静态资源域名与主站不同。
1. 找真实源站 IP（历史 DNS、证书透明日志、子域直连、邮件头）。
2. 源站未限制只允许 CDN 回源 → 可绕过 WAF 直接打源站。
3. 云存储（OSS/S3/COS）权限错误 → 见 `cloud-attack-methods` §3。

**确认标准**：直连源站拿到与 CDN 一致的内容，且 WAF 规则确实不再生效。

## 4. 未授权访问面板

**信号**：`/actuator`、`/druid`、`/swagger-ui`、`/jenkins`、`/nacos`、`/eureka`、`/hystrix`、
`/phpmyadmin`、`/solr`、`/kibana`、`/grafana`、`/zabbix`、Elasticsearch 9200。

| 面板 | 高价值端点 | 影响 |
|---|---|---|
| Spring actuator | `/actuator/env`、`/actuator/heapdump` | 凭据/密钥泄露（heapdump 里常有明文） |
| Druid | `/druid/index.html`、`/druid/sql.html` | SQL 语句与会话泄露 |
| Nacos | `/nacos/v1/auth/users`、`/nacos/v1/cs/configs` | 配置与账号泄露 |
| Jenkins | `/script`（需权限） | 代码执行 |
| Elasticsearch | `/_cat/indices`、`/_search` | 全量数据 |

**确认标准**：拿到真实配置/凭据/数据。catch-all 返回 200 的假页面不算（先定尺）。

## 5. 源码 / 备份 / 配置泄露

**信号**：`/.git/HEAD`、`/.svn/entries`、`/www.zip`、`/.env`、`/config.php.bak`、`/WEB-INF/web.xml`。

```bash
Bash: curl -s -o /dev/null -w '%{http_code}' https://{host}/.git/HEAD
Bash: git-dumper https://{host}/.git/ ./src   # 能 dump 下来才算
```
**确认标准**：dump 出源码并能找到凭据/接口。只有 200 不算（很多站点 catch-all）。

## 6. 供应链 / CI-CD

**信号**：GitHub/GitLab 组织可见、有公开 CI 配置、npm/PyPI 包名与目标相近。
- 公开仓库的 CI 日志是否有密钥（`gh run view --log`）。
- 依赖混淆（内部包名未在公共源注册）。
- **只做只读验证**：不发布任何包、不提交 PR、不改 CI。

## 7. 组合链（本 skill 的真正价值）

单项往往"没什么用"，组合起来是 critical：

```
面板未授权(/actuator/env) → 读 DB 凭据 → 登录后台 → 上传点 → RCE
源码泄露(.git) → 找到内部接口 + 测试账号 → 越权读数据 → 提权
子域接管 → 钓鱼页 → 员工凭据 → VPN → 内网
```

组合链写成一条 `inferred` fact（见 `capability-primitive-search` §5），交规划者分步派工。

## 8. 使用原则

- 先判断**这个场景在不在范围内**（面板暴露 ≠ 可以登录进去改东西）。
- 每个场景的"确认标准"都是**拿到真实数据/配置/执行结果**，不是"能访问"。
- 不做破坏性变更（改配置要改回来；面板里只看不改）。
