---
name: attack-surface-recon
description: 攻击面测绘流水线——子域/端口/服务/指纹/目录/参数的系统化枚举与指纹判别技巧（catch-all 定尺、CDN 干扰、框架识别），以及何时该立刻转 component-vuln-intel。
---

# 攻击面测绘（广度优先，先画全图再深入）

## 与其他 skill 的分工

| 你要做的事 | 用哪个 |
|---|---|
| 前端 JS / SPA 里挖 API 与参数 | `api-recon`（有脚本与门禁，优先用它，别手写提取器） |
| 子域、端口、服务、目录、指纹、参数 | **本 skill** |
| 拿到组件+版本之后 | 立刻转 `component-vuln-intel`，别继续本地扫 |

## 标准流水线（按顺序，每步都有产出物）

**1. 子域面**
```
Bash: subfinder -d {root} -all -silent -o subs.txt 2>/dev/null || curl -s "https://crt.sh/?q=%25.{root}&output=json" | head -c 200000
Bash: dnsx -l subs.txt -a -resp -silent
```
产出：`insert_assets` 一批 `subdomain`（domain + record_type + record_value）。
DNS 解析不到的子域也要登记（可能是接管目标），状态写进 detail。

**2. 存活与端口**
```
Bash: httpx -l subs.txt -sc -title -td -cl -silent -o live.txt
Bash: naabu -l subs.txt -top-ports 1000 -silent -o ports.txt 2>/dev/null || nmap -iL subs.txt --top-ports 200 -Pn -oG - 
```
产出：`service`(HTTP→url；非 HTTP→service_name+port)。

**3. 指纹**
```
Bash: whatweb -i live.txt --aggression 3 --log-brief=- 2>/dev/null | head -200
```
产出：`service` 的 `technologies[]`、`status_code`、`page_title`、`content_length`。
**一旦出现"组件 + 版本"，立即转 `component-vuln-intel`。**

**4. 内容面**
```
Bash: ffuf -u https://{host}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc all -fs {catch_all_size} -t 40 -o ffuf.json
Bash: katana -u https://{host} -jc -d 3 -silent | tee urls.txt
Bash: gau {host} | tee gau.txt
```
产出：`endpoint`（url + method），带 `params` 的必须填 params。

**5. 参数面**
```
Bash: arjun -u https://{host}{path} -m GET,POST --stable -oT arjun.txt
Bash: x8 -u "https://{host}{path}" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
```
产出：`endpoint` 的 `params`（location/name/value/type）。
**参数是后续所有注入类漏洞的入口，漏掉参数等于漏掉整类漏洞。**

## 指纹判别技巧（这几条最常踩坑）

| 现象 | 含义 | 做法 |
|---|---|---|
| 任意路径都返回 200 且长度相同 | catch-all 兜底 | 先用一个随机长串测出基准长度 `{catch_all_size}`，所有扫描器加 `-fs {catch_all_size}`，否则 100% 全是假阳性 |
| 404 与 200 长度差异巨大 | 正常 | 用 `-fc 404` 或 `-mc 200,301,302,401,403` |
| 所有请求都 502 / 522 / 云厂商报错页 | CDN/WAF 前置，源站没通 | 不存在"站点挂了"，先 `dig` 找源站 IP、试 `Host:` 直连、查历史 DNS |
| 站点是 SPA，`curl` 拿不到内容 | 前端渲染 | 转 `api-recon`（它有 Puppeteer 与 mock 登录） |
| 同 IP 多个域名返回同一套内容 | 虚拟主机/反代 | 逐个域名带 `Host:` 头单独建 `service`，别合并 |
| `Server` 头缺失或伪造 | 安全加固 / 中间件 | 别信头，用 favicon mmh3 + 页面特征 + 报错页判 |
| 一处页面有 ICP 备案号 | 可反查同主体资产 | 用 `list_assets(dsl:"icp==...")` 找同主体，别自己猜 |

## 完成判据（否则不许说"侦察完了"）

- [ ] 子域：`subs.txt` 有内容，且已 `insert_assets` 为 `subdomain`
- [ ] 存活：每个子域有 alive/dead 结论（dead 也要写入 fact，含探测方式）
- [ ] 端口：至少 top-100 扫过，开放端口已登记 `service`
- [ ] 指纹：每个存活服务有 `technologies`，**有版本的都过了 `component-vuln-intel`**
- [ ] 目录：至少一轮 raft-medium 级别字典，且已用 catch-all 定尺去假阳性
- [ ] 端点：`katana`/`gau` 产出的 URL 已登记为 `endpoint`
- [ ] 参数：主要业务路径的参数已用 `arjun` 或 `x8` 枚举，并写进 endpoint 的 `params`

## 写回要点

- 一个子域的 5 个观察（解析 IP、状态码、指纹、标题、长度）→ **一条** `service` 资产 + **一条** fact，
  不要拆成 5 条 fact。
- 枚举结果很长时，detail 写"共 137 条，样例前 10 条…，完整清单见工作目录 `{file}`"，
  **不要把 137 行全塞进 detail**——图谱会被撑爆，而且后来人读不动。
- `probe_attempts` 只对**否定结论**有意义（例如"该子域无 80/443"），正向枚举不用填。
