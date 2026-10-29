---
name: zero-day-discovery
description: 公开情报打不动时的深挖路径——指纹差分、变体分析、补丁缺口、参数模糊、源码审计、taint 追踪。产出仍是线索事实，确认前不是 finding。
---

# 零日 / 未公开漏洞发现

**什么时候用**：`component-vuln-intel` 的 7 步走完仍无可用 CVE/PoC；或者你手里有源码/二进制；
或者目标是自研系统（本来就没有公开漏洞库覆盖）。

**不要用来做什么**：不要拿本 skill 当作"跳过情报收集"的借口。先搜完再谈深挖。

---

## 路径 A：指纹差分（无源码、黑盒，最快见效）

同一款组件在不同版本/不同配置下的行为差异，往往就是洞。

1. **找对照组**：用资产引擎（FOFA/Shodan/ZoomEye，见 `component-vuln-intel` 第 5 步）找
   **同组件、不同版本**的其它公网实例；或者自己起一个干净版本做本地对照。
2. **差分维度**：错误页文案、响应头、默认路径、`Server` 版本、静态资源 hash、JS 里的版本常量、
   API 返回字段、权限判定逻辑。
3. **找异常**：目标比对照组少了哪个补丁特征（少一个校验、少一个 header、错误页版本更低）。
4. **验证**：把"少掉的那个校验"作为参数直接打——这是最容易出真洞的一条路。

```
Bash: curl -sI https://{target} | tee t.hdr
Bash: curl -sI http://{your_clean_instance} | tee c.hdr
Bash: diff t.hdr c.hdr
```

## 路径 B：变体分析（已知 CVE 的"表亲"）

拿到一个公开 CVE 的 PoC 后，**不要只打那一个点**：

1. 读 PoC 源码，找到它的**根因**（是缺校验？是解析器 bug？是路径拼接？）。
2. 问：**同一个根因在这个产品的其它接口上还存在吗？** 通常同一个作者会在 5 个地方犯同一个错。
3. 把 PoC 的 payload 参数化，对枚举出的所有同类端点批量试（注意节制，别把目标打挂）。
4. 对同厂商**其它产品**试同一个根因。

## 路径 C：补丁缺口（有版本号、能拿到 diff）

1. 定位修复版本：`component-vuln-intel` 第 1 步里的 changelog / release notes /
   GitHub commits / 安全公告里的 "fixed in X.Y.Z"。
2. 拿到 `X.Y.Z` 与 `X.Y.(Z-1)` 的源码或二进制，**diff 出安全相关改动**
   （加了 `escape()`、加了 `authz` 检查、换了序列化器、加了 `path.Clean`）。
3. 反推：补丁前那个参数可以传什么 → 构造 payload。
4. 找**同一补丁没覆盖到的调用点**（补丁只改了一个入口，同函数还有两个调用者没改）。

```
Bash: git clone --depth 200 {repo} && cd {repo}
Bash: git log --oneline --all --grep="security\|CVE\|fix\|sanitize" | head -40
Bash: git diff {fixed_commit}^ {fixed_commit} -- '*.{java,go,py,js,php}'
```

## 路径 D：参数模糊（黑盒、无版本信息）

1. 从 `attack-surface-recon` 的 `params` 里挑**高风险语义**的参数：
   `file`/`path`/`url`/`redirect`/`cmd`/`template`/`callback`/`format`/`sort`/`filter`。
2. 对每个参数按 `web-attack-methods` 对应类别的"最少试探"清单跑。
3. 观察**任何**差异：状态码、长度、耗时、`Set-Cookie`、错误文案、响应头。
4. 差异稳定复现 → 记 inferred 事实，写清"哪个参数、哪种输入、什么差异"，交规划者深挖。

## 路径 E：源码审计（有源码时最强）

优先看**输入到危险汇聚点**的路径，而不是逐行读：

| 汇聚点 | 关注 |
|---|---|
| SQL 拼接 | 字符串拼接 + 用户输入；`ORDER BY`/`LIMIT` 拼接 |
| 命令执行 | `exec`/`system`/`popen`/`Runtime.exec`/`ProcessBuilder` |
| 反序列化 | `readObject`/`unmarshal`/`pickle.loads`/`yaml.load` |
| 文件操作 | `open`/`File`/`readFile` 路径是否拼接用户输入 |
| 模板 | `render(template_from_user)` |
| 鉴权 | 每个敏感路由是否真的经过 authz 中间件（**漏挂中间件是最常见的高危**） |
| SSRF | `http.Get(user_url)` / `requests.get(user_url)` |

```bash
Bash: grep -rn --include=*.java -E "Runtime\.getRuntime|ProcessBuilder|readObject" src/ | head -50
Bash: grep -rn --include=*.py -E "pickle\.loads|yaml\.load\(|subprocess\.|os\.system" . | head -50
Bash: grep -rn --include=*.go -E "exec\.Command|template\.HTML|filepath\.Join" . | head -50
```

**反查鉴权覆盖**（高价值、低工作量）：
```bash
Bash: grep -rn "router\.\|app\.\(get\|post\|put\|delete\)\|@RequestMapping" src/ | head -80
# 逐个对照哪些路径挂了 auth 中间件 —— 没挂的那几条就是重点
```

## 路径 F：Taint 追踪（有源码 + 有时间）

1. 列出 source（`request.getParameter`、`@RequestParam`、`req.body`、`r.URL.Query()`…）
2. 列出 sink（上面那张表）
3. 手动或半自动跟一遍中间是否有 sanitize；有 sanitize 就看能不能绕过它
   （黑名单漏字符、`strip_tags` 后二次拼接、编码后再解码）。

## 产出要求（关键）

深挖路径的产出**默认都是 `inferred` 线索**，不是 finding：

```
record_fact(
  summary: "疑似 Fastjson 1.2.47 autoType 绕过：/api/parse 直接把 body 传给 JSON.parse",
  detail:  "依据：① 报错栈里有 com.alibaba.fastjson.JSON.parse(第 3 行)
            ② 版本常量 '1.2.47' 出现在 /static/app.js
            ③ 该版本在 1.2.48 才修 autoType 白名单
            未做：未实际发送 @type payload（本意图预算用尽）",
  evidence: "curl -s https://t/api/parse -d '{' → {\"error\":\"...at com.alibaba.fastjson.JSON.parse...\"}",
  confidence: inferred,
  probe_attempts: 0,
  asset_ids: [目标]
)
```

下次规划者会带着这条事实派出"发 @type payload 验证"的精确意图 —— 这才是正确的分工。
**深挖的产出是"精确的下一步"，不是"跳过验证的结论"。**
