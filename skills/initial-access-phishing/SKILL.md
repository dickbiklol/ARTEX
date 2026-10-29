---
name: initial-access-phishing
description: 钓鱼与社工的可行性验证——只做"能验证到哪一步"的最小动作（域名相似度、邮件网关、SPF/DMARC、凭据采集页是否可用），不做真实投递。
---

# 初始访问 / 钓鱼可行性

**本 skill 的边界**：验证"这条路走不走得通"，**不做真实投递**。
不要给真实员工发钓鱼邮件、不要搭建真实采集页、不要注册真实仿冒域名——
除非授权文件明确写着社会工程学测试，并且有明确的投递清单与停止条件。

## 一、可安全验证的四件事

| 项目 | 做法 | 判据 |
|---|---|---|
| 邮件网关存在性 | `dig MX {domain}`、SMTP 握手看 banner | 识别出网关厂商（Mimecast/Proofpoint/腾讯企业邮…） |
| SPF/DMARC 配置 | `dig TXT {domain}`、`dig TXT _dmarc.{domain}` | SPF 缺失/`~all`、DMARC `p=none` → 可伪造 |
| 相似域名可用性 | `dig` + `whois` 检查 typosquat 域名是否已被注册 | 只查，不注册 |
| 凭据采集页可行性 | 只用本地 HTML 文件 + 自己访问，不部署到公网 | 技术可行即可，不实际使用 |

## 二、判据与影响分级

| 发现 | 影响 |
|---|---|
| DMARC `p=none` + SPF 缺失 | medium（可伪造发件人，是真实风险） |
| 网关可被相似域名绕过 | medium |
| 已注册的相似域名属于目标且可注册者持有 | medium/high（取决于是否已被滥用） |
| 无 MFA 的 VPN/邮箱入口 | high（配合已知口令即为接管路径） |

## 三、写回要求

```
record_fact(
  summary: "corp.example.com 的 DMARC 为 p=none、SPF 缺失，理论上可伪造发件人；邮件网关为 Proofpoint",
  detail:  "_dmarc.corp.example.com TXT → v=DMARC1; p=none; rua=...
            SPF: 无 TXT 记录
            MX: proofpoint 网关
            未做: 未实际发送任何邮件、未注册相似域名（授权未覆盖投递）",
  evidence: "dig +short TXT _dmarc.corp.example.com → \"v=DMARC1; p=none;\"",
  confidence: observed,
  asset_ids: [root_domain_asset]
)
```

## 四、红线（违反即越界）

1. **不投递**任何邮件/短信/IM 消息。
2. **不注册**仿冒域名，**不部署**采集页到公网。
3. **不收集**任何真实员工的凭据或个人信息。
4. 不针对具体个人做画像（那是另一类需要单独授权的工作）。

超出以上范围的动作，必须由人明确批准后在平台外执行——不是你该做的。
