---
name: binary-mobile-reversing
description: 二进制与移动端逆向——静态字符串/符号、动态调试、Frida hook、APK/IPA 加固与接口提取；产出是接口与密钥线索，不是"逆向完成"。
---

# 二进制 / 移动端逆向手册

**大多数情况下你要的不是"破解"，而是从客户端里找出服务端的接口、密钥、鉴权逻辑**——
那才是能打的东西。所以优先级是：**找接口 > 找密钥 > 找逻辑漏洞 > 找内存破坏**。

## 一、Android

```bash
# 1. 拆包与清单（最高性价比，先做这个）
Bash: apktool d -f app.apk -o app_dec
Bash: cat app_dec/AndroidManifest.xml | grep -E 'android:name|exported|permission'
# 2. 找接口与密钥（字符串是最快的路）
Bash: strings -a app.apk | grep -Eo 'https?://[a-zA-Z0-9./_?=&%-]+' | sort -u | head -100
Bash: grep -rn -E 'AKIA|LTAI|api[_-]?key|secret|token' app_dec/assets app_dec/res app_dec/smali 2>/dev/null | head -40
# 3. 加固判定
Bash: unzip -l app.apk | grep -E 'libjiagu|libshell|libDexHelper|libmobisec' 
```
- **未加固** → `jadx-gui` 直接读；重点看 `retrofit`/`OkHttp` 接口定义、加密工具类。
- **加固** → 走动态：Frida hook `okhttp3.Request` 或脱壳后再静态。
- `exported=true` 的 Activity/Provider/Receiver → 组件劫持面，单独测。

## 二、iOS

```bash
Bash: unzip -o app.ipa -d ipa_dec
Bash: strings -a ipa_dec/Payload/*.app/* | grep -Eo 'https?://[^" ]+' | sort -u | head -80
Bash: grep -rn -E 'NSAppTransportSecurity|NSAllowsArbitraryLoads' ipa_dec/Payload/*.app/Info.plist
```
- 越狱设备 + `frida` / `objection`：`ios sslpinning disable`、`ios hooking watch class_method`。
- 未越狱：只能做静态 + 网络侧（走录制代理看真实流量）。

## 三、原生二进制（so / ELF / PE）

```bash
Bash: checksec --file=target.so
Bash: strings -a -n 6 target.so | grep -E 'http|api|key|secret|password' | head -50
Bash: objdump -d target.so | head -100          # 或 radare2/ghidra headless
Bash: readelf -sW target.so | grep -E 'FUNC.*GLOBAL' | head -40
```
- 先看 `strings` + 符号表，80% 的线索在这里，不必上反编译器。
- 有符号 → 直接定位关键函数；无符号 → 从字符串交叉引用（xref）倒推。
- 加密/签名逻辑 → 目标是**复现算法**（用 Frida hook 输入输出更快，别硬读汇编）。

## 四、动态 hook（最快拿到真相）

```javascript
// Frida: 抓所有 OkHttp 请求（Android）
Java.perform(() => {
  const Builder = Java.use('okhttp3.Request$Builder');
  Java.use('okhttp3.Request').url.implementation = function () {
    const u = this.url(); console.log('[URL] ' + u); return u;
  };
});
```
```bash
Bash: frida -U -f {package} -l hook.js --no-pause
```
抓到接口后**立刻** `insert_assets` 登记 `endpoint`（url + method + params），
后续所有测试都在这些端点上做——这是移动端渗透的主要产出。

## 五、网络侧（不逆向也能拿到很多）

手机设代理指向本平台录制代理（或 `global_proxy`），装 CA 证书：
- 能看到明文 → 直接读接口，跳过逆向。
- 只有 pinned 流量看不到 → 才需要 Frida 去 pinning。

## 六、写回要求

```
record_fact(
  summary: "APK 提取出 37 个后端接口，其中 3 个带明文 API Key，接口域名 api.{target}",
  detail:  "来源: strings + jadx 反编译 ApiService.java
            接口清单已 insert_assets（endpoint）
            发现的密钥: /assets/config.json 里 "apiKey": "xxx"（用于 X-Api-Key 头）
            未做: 未验证密钥权限、未测接口越权",
  evidence: "grep -rn 'apiKey' app_dec/assets/config.json → {\"apiKey\":\"...\"}",
  confidence: observed,
  capability: ["token"],
  asset_ids: [app_asset]
)
```

## 七、禁忌

- 不要把整个 APK 的 strings 输出贴进 fact（几万行）；只写**结论 + 清单文件路径**。
- 不要为了"逆向完成"而反编译整个 so；先确认目标（找接口/找密钥/复现算法）。
- 不要在真实设备上做破坏性 hook（改内存、跳过支付校验）——只做读取与复现。
