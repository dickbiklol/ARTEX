---
name: component-vuln-intel
description: 识别出框架/组件/版本后，必须联网做过情报（CVE/搜索引擎/中文社区/GitHub PoC/资产引擎/依赖扩展）再动手利用；含受阻换路的阶梯。
---

# 联网情报收集（识别组件 → 立刻全网搜；结果只是线索）

**触发条件（硬性）**：只要拿到明确的 **组件名 + 版本**（Nginx 1.18 / Fastjson 1.2.47 /
用友 NC6.5 / Spring Boot 2.x …），**在本地继续扫之前**先把下面 7 步走完。

跳过这 7 步直接打 = 盲打。但也别搞反了：这一步的产出**永远是 `confidence=inferred` 的
线索事实**，不是 finding。能不能确认，看 `pentest-verification`。

## 可用工具

| 用途 | 工具 |
|---|---|
| 搜索后端（若开启） | `web_search` |
| 取网页 | `WebFetch` |
| 任意 curl / searchsploit / API | `Bash`（走录制代理，流量自动留痕） |
| 记住结论 | `record_fact`（confidence=inferred） |

`WebFetch` 与 `Bash curl` 都经录制代理，**优先用它们而不是重新推一遍**——后面
`traffic_search host=<目标> body_contains=...` 能直接翻出你抓到的原文。

## 七步（全部执行，不是选做）

设 `{C}` = 组件名，`{V}` = 版本。

**1. 漏洞库（必做）**
```
Bash: searchsploit {C} {V}
Bash: curl -s "https://cve.circl.lu/api/search/{C}/{V}" | head -c 4000
WebFetch: https://github.com/advisories?query={C}+{V}
```

**2. 搜索引擎（至少 3 个，找分析文 + PoC）**
```
web_search: "{C} {V} exploit PoC RCE"
web_search: "{C} {V} 漏洞 复现 getshell"
WebFetch: https://www.bing.com/search?q={C}+{V}+CVE+exploit
WebFetch: https://duckduckgo.com/html/?q={C}+{V}+vulnerability+exploit
```

**3. 中文安全社区（中文首发多、复现细节全）**
```
WebFetch: https://xz.aliyun.com/search?keyword={C}+漏洞      # 先知
WebFetch: https://www.seebug.org/search/?keywords={C}
WebFetch: https://paper.seebug.org/search/?keyword={C}
WebFetch: https://www.freebuf.com/search?search={C}+{V}
WebFetch: https://ti.qianxin.com/vulnerability?keyword={C}
```

**4. GitHub PoC / 利用代码（最直接）**
```
Bash: curl -s "https://api.github.com/search/repositories?q={C}+{V}+exploit+OR+poc&sort=updated&per_page=10"
Bash: curl -s "https://api.github.com/search/repositories?q={C}+CVE&sort=stars&per_page=5"
# 找到仓库后直接读 README / 关键文件，不要靠猜：
Bash: curl -s "https://raw.githubusercontent.com/{owner}/{repo}/main/README.md" | head -c 8000
```

**5. 资产引擎（看真实在野目标、确认指纹写法）**
```
web_search: "{C} {V} body=\"{特征串}\""
WebFetch: https://www.shodan.io/search?query={C}+{V}
WebFetch: https://www.zoomeye.org/searchResult?q={C}
```

**6. 即时情报（最新 0day / 在野利用）**
```
WebFetch: https://www.exploit-db.com/search?q={C}
WebFetch: https://www.reddit.com/r/netsec/search/?q={C}&restrict_sr=1&sort=new
```

**7. 依赖扩展（必做）**
拿到目标的技术栈清单（`insert_assets` 的 technologies）或依赖文件
（package.json / pom.xml / requirements.txt / go.mod）后，
**对每一个依赖重复第 1–6 步**。组件链上的洞通常不在主组件上。

## 受阻换路阶梯（403 / 验证码 / 空结果 / 超时，按序执行，不许直接放弃）

```
① 换 UA：
   Bash: curl -s -H "User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" "{URL}"
② 只读渲染器（绕前端 JS / 反爬）：
   WebFetch: https://r.jina.ai/{原始URL}
③ 网页快照 / 存档：
   WebFetch: https://web.archive.org/web/2024/{URL}
④ GitHub 页面被拦但 API 不拦 → 改用第 4 步的 api.github.com
⑤ 换引擎：Google 拦 → Bing / DuckDuckGo / 百度；反之亦然
⑥ 走已有代理：Bash 里加 -x "$HTTPS_PROXY" 重试（录制代理已注入环境变量，通常直接生效）
⑦ 仍失败 → 记负事实：
   record_fact(summary:"已对 {C} {V} 全渠道搜索无公开漏洞/无可用 PoC",
               detail:"试过 searchsploit / cve.circl.lu / GH advisories / Bing / DDG / 先知 /
                       seebug / freebuf / GH API / exploit-db，均无匹配",
               evidence:"各渠道返回 0 条", confidence:observed, probe_attempts:7)
   → 转向 zero-day-discovery（指纹差分 / 变体分析 / 参数模糊）
```

## 落库要求

- 每条有名字的 CVE/PoC 都是一条 `inferred` 事实，detail 里带：**组件+版本、CVE 编号、
  PoC 链接、所需前置条件（认证？特定配置？特定参数？）、验证方法**。
- 找到 PoC 代码 → **先读代码确认它打的是不是这个版本、这个路径、这个参数**，
  再决定派不派工。错版 PoC 直接打只会烧掉预算。
- 什么都搜不到 → 也是一条事实（见上面第 ⑦ 步）。"搜过" 必须留痕，否则下一个人会重搜一遍。
