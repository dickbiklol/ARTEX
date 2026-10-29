---
name: source-code-hunting
description: 有源码时的审计方法——从危险汇聚点反查输入、查鉴权中间件覆盖、找硬编码凭据与依赖漏洞，产出可验证的利用假设。
---

# 源码审计（有代码时最强的路径）

源码在手时，**不要逐行读**。用"汇聚点 → 输入"的反查法，两小时内能找到别人黑盒打一个月找不到的洞。

## 一、先建立索引（10 分钟，后面全靠它）

```bash
Bash: find . -type f \( -name '*.java' -o -name '*.go' -o -name '*.py' -o -name '*.js' -o -name '*.php' \) | wc -l
Bash: find . -name 'pom.xml' -o -name 'package.json' -o -name 'go.mod' -o -name 'requirements.txt' -o -name 'composer.json'
# 路由/入口清单
Bash: grep -rn --include=*.java -E '@(Get|Post|Put|Delete|Request)Mapping' . | head -100
Bash: grep -rn --include=*.go -E '\.(GET|POST|PUT|DELETE|HandleFunc)\(' . | head -100
Bash: grep -rn --include=*.py -E '@(app|router)\.(get|post|route)' . | head -80
```

## 二、汇聚点反查（核心方法）

对每个汇聚点，问三件事：**输入从哪来？中间有没有过滤？过滤能不能绕？**

```bash
# 命令执行
Bash: grep -rn --include=*.{java,go,py,js,php} -E 'Runtime\.getRuntime|ProcessBuilder|exec\.Command|subprocess\.|os\.system|child_process|shell_exec|system\(' . | head -80
# SQL 拼接（找字符串拼进查询的地方，ORM 参数化一般安全）
Bash: grep -rn --include=*.{java,go,py,php} -E '\+ *"?\s*(select|SELECT|insert|INSERT|update|UPDATE|delete|DELETE)' . | head -60
Bash: grep -rn -E 'ORDER BY|LIMIT' --include=*.{java,go,py,php} . | grep -v '?' | head -40
# 反序列化
Bash: grep -rn --include=*.{java,py,php} -E 'readObject|ObjectInputStream|pickle\.loads|yaml\.load\(|unserialize\(' . | head -40
# 文件读写（路径拼接）
Bash: grep -rn --include=*.{java,go,py,php} -E 'new File\(|os\.Open|filepath\.Join|open\(' . | head -80
# 模板渲染（用户可控模板 = SSTI）
Bash: grep -rn --include=*.{java,py,js} -E 'render_template_string|Template\(|eval\(|Function\(' . | head -40
# SSRF（用户可控 URL 直接请求）
Bash: grep -rn --include=*.{java,go,py,js} -E 'http\.Get|requests\.get|axios\.|fetch\(|HttpClient' . | head -60
```

## 三、鉴权覆盖反查（最高性价比）

漏挂中间件是真实系统里最常见的高危。做法：**把所有路由列出来，逐个标记"有没有 auth"**。

```bash
# Spring：看 SecurityConfig / 拦截器注册，找出 permitAll / 排除路径
Bash: grep -rn -E 'permitAll|antMatchers|requestMatchers|excludePathPatterns|addPathPatterns' . | head -60
# Go：看中间件链，找出没挂 auth 的 group
Bash: grep -rn -E '\.Group\(|Use\(|middleware' . | head -80
# Django/Flask：找 @login_required / @permission_required 缺失的视图
Bash: grep -rn -E 'def .*\(request' --include=*.py . | head -80
# 通用：注释掉的鉴权
Bash: grep -rn -E '//\s*@PreAuthorize|#\s*@login_required|TODO.*auth|FIXME.*auth' . | head -40
```
**输出必须是一张表**：`路径 | 方法 | 是否需要登录 | 实际是否校验 | 依据文件:行`。
未校验的那几行就是待验证目标。

## 四、硬编码与配置

```bash
Bash: grep -rn -E 'AKIA[0-9A-Z]{16}|LTAI[0-9A-Za-z]{12,}|password\s*=\s*"[^"]+"|secret\s*=\s*"' . | head -40
Bash: find . -name '.env*' -o -name 'application*.yml' -o -name 'config*.json' -o -name '*.pem' -o -name 'id_rsa'
Bash: grep -rn -E 'jdbc:|mongodb://|redis://|amqp://' . | head -30
```

## 五、依赖漏洞

```bash
Bash: grep -A2 '<dependency>' pom.xml | grep -E 'artifactId|version' | head -60
Bash: cat package-lock.json | head -5; grep -E '"lodash"|"axios"|"jsonwebtoken"' package.json
Bash: go list -m all 2>/dev/null | head -60
```
拿到 `组件+版本` → 立刻转 `component-vuln-intel` 的七步，不要凭记忆。

## 六、产出：一条"可验证的假设"，不是"这里可能有洞"

```
record_fact(
  summary: "OrderController.export() 未挂鉴权，且 fileName 直接拼进 new File()，疑似任意文件读取",
  detail:  "路径: /api/order/export (GET)
            鉴权: SecurityConfig 里 /api/order/** 是 permitAll，且 export 方法上没有 @PreAuthorize
            汇聚点: OrderController.java:142 new File(baseDir + req.getParameter("fileName"))
            无过滤: 未做 path.Clean，未做白名单
            验证方法: GET /api/order/export?fileName=../../../../etc/passwd",
  evidence: "src/main/java/.../OrderController.java:138-146（代码片段见工作目录 snippet.txt）",
  confidence: inferred,
  asset_ids: [目标]
)
```

**代码里看到 ≠ 线上可利用**：可能有网关层鉴权、可能该方法没暴露。
所以结论是 `inferred`，把"验证方法"写成一句话交给规划者派工——这才是正确分工。

## 七、禁忌

- 不要把整段源码贴进 fact（图谱会被撑爆）；贴**关键 3–5 行 + 文件:行**。
- 不要因为"代码里没过滤"就直接 `report_finding`（那是静态推断，不是触发）。
- 不要审计与本任务无关的模块（范围之外，且会烧光预算）。
