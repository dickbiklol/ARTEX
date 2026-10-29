---
name: wireless-hardware-attack
description: 无线与硬件评估——WiFi 扫描/握手/企业认证、蓝牙与 RFID 侦察、固件与调试口；强调只在授权场地、不干扰他人。
---

# 无线 / 硬件评估手册

**适用条件**：授权明确覆盖物理场地与射频范围。**在共享办公区/公寓楼做无线测试
等于影响他人**——先确认场地边界，否则不做。

## 一、WiFi 侦察（只读阶段）

```bash
Bash: iw dev                                     # 网卡是否支持监听/注入
Bash: airmon-ng start wlan0                      # 监听模式
Bash: airodump-ng wlan0mon --band abg -w cap     # 被动收集：SSID/BSSID/加密/客户端
```
| 观察 | 含义 |
|---|---|
| 开放网络 / WEP | 直接可接（WEP 只是形式） |
| WPA2-PSK + 客户端在线 | 可尝试抓握手（需等待重连，**不要**主动 deauth 商用环境） |
| WPA3 | 降级攻击（Dragonblood）仅实验室可测 |
| 企业 802.1X | 见下节 |
| 孤立 SSID（同名多 BSSID） | 疑似 evil twin 的目标 |

## 二、企业无线（802.1X）

- 应先确认是否开启**证书校验**：不校验服务端证书 → 可搭 Rogue AP 骗取凭据。
- 只做"是否能被诱导连接"的**可行性判断**，不做实际凭据收割（除非授权明确）。

## 三、蓝牙 / RFID

```bash
Bash: hcitool scan; bluetoothctl devices          # 被动
Bash: bettercap -iface hci0                       # 交互（谨慎）
```
- 只做**发现与识别**（设备名、服务 UUID、固件版本）。
- 不做配对劫持、不做录音/录音重放（涉及隐私与他人设备）。

## 四、硬件与固件

- 物理接触时：找调试口（UART/JTAG）、看启动日志、读 flash。
- 固件：`binwalk -e` 拆包 → 找硬编码凭据、启动脚本、更新签名校验（无签名 = 可刷恶意固件）。
- **只在明确给你的那台设备上做**，不要碰现场其它设备。

## 五、写回要求

```
record_fact(
  summary: "办公区发现有 3 个 WPA2-PSK 网络，其中 'Guest-WiFi' 无客户端隔离；企业 SSID 未校验服务端证书（疑似可被 Rogue AP 诱导）",
  detail:  "被动扫描 10 分钟，未发送 deauth、未尝试破解
            Guest-WiFi: 开放注册页，接入后可达 10.0.0.0/24（未做进一步测试）
            企业 SSID: EAP 方法 PEAP，未验证服务端证书（需 rogue AP 才能确认，未执行）",
  evidence: "airodump-ng 输出前 10 行（见工作目录 wifi.csv）",
  confidence: observed,
  asset_ids: [office_subdomain_asset]
)
```

## 六、红线

1. 不在授权范围外的射频环境操作（含"顺手扫一下隔壁"）。
2. 不发 deauth / 不干扰正常业务网络。
3. 不录音、不截获他人通信内容。
4. 不拆解非授权设备，不留固件后门。
