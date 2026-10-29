---
name: blockchain-contract-attack
description: 智能合约审计——重入、访问控制、整数/精度、预言机操纵、闪电贷组合、签名重放；本地复现为主，链上只读。
---

# 智能合约审计手册

**铁律：只在本地 fork / 测试网上复现。绝对不在主网发起真实攻击交易。**
主网只做**只读**分析（读源码、读状态、读交易历史）。

## 一、拿到合约之后（只读）

```bash
Bash: cast code {address} --rpc-url {rpc} | head -c 200        # 是否已验证源码
Bash: cast implementation {address} --rpc-url {rpc}            # 是否代理（proxy）
Bash: cast storage {address} 0 --rpc-url {rpc}                 # 读 slot 0（代理的 impl 地址常在这里）
Bash: cast logs --address {address} --from-block {n} --rpc-url {rpc} | head -20   # 历史事件
```
代理合约要**同时审实现合约和升级权限**（`upgradeTo` 谁能调，往往就是最高危的点）。

## 二、高频漏洞（按真实损失排序）

| 类别 | 检查点 |
|---|---|
| **访问控制缺失** | 关键函数（mint/withdraw/setFee/upgrade）有没有 `onlyOwner`/role 检查 |
| **重入** | 外部调用（`call`/`transfer`）之后还改状态？有没有 `nonReentrant` |
| **预言机操纵** | 价格来自单一 DEX 池的 `getReserves`（可被闪电贷砸） |
| **精度/取整** | 除法在乘法前、share 计算向下取整导致少付/多取 |
| **签名重放** | `ecrecover` 校验了 nonce/chainId/deadline 吗 |
| **闪电贷组合** | 单笔交易内可操纵价格/抵押率 |
| **代理存储冲突** | 升级后 slot 错位 |
| **未初始化的 implementation** | `initialize()` 可被任何人调用 |

## 三、静态检查（先跑工具，再人工）

```bash
Bash: slither . --print human-summary 2>/dev/null | head -60
Bash: slither . --detect reentrancy-eth,arbitrary-send,controlled-delegatecall,uninitialized-state 2>/dev/null
Bash: forge test -vvv 2>/dev/null | tail -20
```
Slither 的告警**不是漏洞**，要逐个看是否能构造出真实资金影响。

## 四、本地复现（唯一允许的验证方式）

```solidity
// 用 Foundry fork 主网状态，在本地"攻击"一次
function testExploit() public {
    vm.createSelectFork(vm.envString("RPC_URL"), 19_000_000);
    uint256 before = token.balanceOf(address(this));
    attacker.run();
    assertGt(token.balanceOf(address(this)), before);   // 用断言证明，而不是用真金白银
}
```

**判据**：本地 fork 上余额/状态的断言通过 → 才能 `report_finding`。
没有本地复现的"看起来能重入"，只能 `record_fact(confidence:inferred)`。

## 五、写回要求

```
report_finding(
  vulnclass: "business_logic",
  name: "Vault.withdraw() 缺少 nonReentrant，可重入提取全部资金",
  severity: "critical",
  summary: "在 Foundry fork(block 19000000) 上复现：单笔交易内重入 3 次，提取 2.4x 本金",
  evidence: "forge test --match-test testExploit -vvv → PASS
             before=0.1 ETH, after=0.24 ETH
             PoC 见工作目录 poc/Vault.t.sol"
)
```

## 六、红线

1. **不在主网发交易**（包括"用 1 wei 验证一下"）。
2. 不部署攻击合约到任何公共网络。
3. 不在测试网留下可利用的合约（用完自毁或注明）。
4. 报告里给 PoC 时**去掉可直接执行的主网参数**。
