# 设计：Rust SDK calldata 构建模块 + workspace 重构

**日期：** 2026-06-17
**状态：** 待 review
**作者：** wink@invisipay.fi（+ Claude 协作 brainstorm）

## 关联

| 仓库 / 文档 | 关系 |
|---|---|
| `../invisi-sdk-ts`（`@invisi-labs/core` + `@invisi-labs/payer`） | 命名 + 功能对齐的权威参照 |
| `../invisi-protocol/contracts/src/InvisiProtocol.sol` | `payOpen` / `payBlind` 合约签名（calldata 字节级真相源） |
| `../invisi-protocol/circuits/shielded_payment/src/main.nr` | `change_commitment` 派生公式 |
| `../invisi-nexus/tests/e2e/onchain/onchain-pay-open` | app 付款侧逻辑的 Go 参考实现 |
| `../invisi-nexus/services/account-service/.../wallet_crypto.go` | masterKey 派生（app 侧职责，**本 SDK 不实现**） |
| 后续 spec ②（prover） | 本 spec 的姊妹子项目，独立交付 |

---

## 1. 背景与目标

app 端做隐私支付时，需要**在本地构建发往合约的 calldata**（用户已确认：merkle tree 不需要本地建，但 calldata 必须本地算）。当前 Rust SDK 只有密码学派生（Poseidon2 / commitment / nullifier / AEAD），**缺 EVM calldata 构建能力**。

通过对 `../invisi-nexus` e2e 闭环（`wallet_personal_payment_test.go` + `onchain-*` 工具）的分析，确认三条支付路径的 calldata 归属：

| 路径 | proof | merkle | calldata 谁构建 |
|---|---|---|---|
| **payOpen**（公开支付） | 无 | 无 | **客户端本地**（静态 ABI） |
| **payBlind**（隐藏支付） | 本地生成（隐私要求） | 无（电路不需要） | **客户端本地**（动态 ABI，proof 作入参） |
| **withdraw / settle**（提现/找零结算） | 服务端 | 服务端 | **服务端返回完整 calldata**（客户端只注入 nullifier） |

> 提现 calldata 由 `protocol-service` 的 `GenerateSettlementProof` 直接返回（`ProofGroup.calldata`），客户端只签名广播。因此 **本 SDK 只负责 payOpen + payBlind + approve 三种 calldata**。

本设计是**两个子项目中的第①个**（核心 crate，范围明确、可独立交付）。子项目②（ZK prover）单独立 spec。

### 目标

1. 把单 crate 仓库重构为 **Cargo workspace 多 crate**，与 `invisi-sdk-ts` monorepo 结构一致。
2. 核心 crate 新增 `keccak256` + EVM ABI 编码器 + 三个 calldata builder + `compute_change_commitment` + `generate_nonce` 导出。
3. 现有派生函数**改名对齐** `@invisi-labs/core`。
4. calldata 输出与合约真实 ABI 编码**字节级对齐**（硬门测试）。

---

## 2. 非目标（明确不做）

遵循「SDK 单一原则：只接收参数 + 计算」。以下**不进本 SDK**：

- **ZK prover**（Noir/bb proof 生成）→ 子项目②，独立 crate `invisi-sdk-prover`。
- **merkle tree / proof path** → 服务端提供。
- **withdraw / settle calldata** → 服务端返回。
- **网络 / HTTP / IPP client** → app 层。
- **交易签名 / 广播** → app 钱包层（Keyring / WalletConnect）。
- **masterKey 派生与认证策略**（`keccak256(签名)`、认证签名 vs 隐私签名是否分离）→ app 侧实现细节。本 SDK 只接收 `masterKey: &[u8; 32]`。
- **Keychain / Keystore 读写** → bridge 层。

---

## 3. 架构：workspace 多 crate

```
invisi-sdk-rust/                       # 仓库 = Cargo workspace（"同一套"）
├── Cargo.toml                         # [workspace] virtual manifest
├── crates/
│   ├── invisi-sdk-core/               # 核心：轻量、纯算、可编 WASM、无 bb
│   │   ├── Cargo.toml                 # package = "invisi-sdk-core", [lib] name = "invisi_sdk"
│   │   └── src/                       # 现有 src/ 整体迁入
│   └── invisi-sdk-prover/             # 子项目②（本 spec 不实现，占位说明）
└── docs/superpowers/specs/
```

### 命名对齐 `invisi-sdk-ts`

| TS 包 | Rust crate | 说明 |
|---|---|---|
| `@invisi-labs/core` | `invisi-sdk-core` | 直接对齐 |
| `@invisi-labs/node` | `invisi-sdk-prover` | **故意不照搬 `node`**——`node` 是 Node.js 运行时语义，搬到 Rust 会误导 |

- **`[lib] name = "invisi_sdk"` 保持不变**：FFI `#[no_mangle]` 符号、staticlib/cdylib 产物名（`libinvisi_sdk.a`）稳定，app 的 iOS/Android native 链接配置不破，app 里 `use invisi_sdk::...` 不变。
- app 迁移成本：仅改 `apps/mobile/rust/Cargo.toml` 一行：
  ```diff
  - invisi-sdk = { path = "../../../../invisi-sdk-rust" }
  + invisi-sdk-core = { path = "../../../../invisi-sdk-rust/crates/invisi-sdk-core" }
  ```

---

## 4. 函数命名对齐

现有 lib 内部函数只通过 FFI `privacy_*` 被 app 消费，改内部名不破跨语言契约。`_raw` 后缀已多余（整个 SDK 都非托管、都收 raw masterKey）。

| TS `@invisi-labs/core` | 现 Rust | 对齐后 |
|---|---|---|
| `computeIdentityCommitment` | `identity_commitment` | `compute_identity_commitment` |
| `computePaymentCommitment` | `payment_commitment` | `compute_payment_commitment` |
| `computePaymentNullifier` | `payment_nullifier` | `compute_payment_nullifier` |
| `computeChangeCommitment` | — | `compute_change_commitment`（新增） |
| `deriveNullifierKey` | `nullifier_key_raw` | `derive_nullifier_key` |
| `generateNonce` | （pool 内部） | `generate_nonce`（导出） |

FFI 导出名**保持现状**（`privacy_compute_*` 已镜像 TS），新增项延续规则。

---

## 5. 模块设计

### 5.1 `keccak256` 原语

- 新依赖 `tiny-keccak`（轻量、no_std 友好）。
- 用途：ABI 函数选择器。
- 不暴露 masterKey 专用 helper（masterKey 派生归 app）；如需要，app 可自行用通用 keccak256 组合。

### 5.2 `abi.rs` — 极简 EVM ABI 编码器

实现 EVM ABI 规范的最小子集（只覆盖本 SDK 用到的类型）：

- **静态类型**（每个占 32 字节 word）：
  - `bytes32` → 原样 32 字节
  - `uint256` → 右对齐大端（输入 `&[u8; 32]` 或 `u64` 左填充）
  - `address` → 20 字节右对齐（左填充 12 字节 0）
- **动态类型**：
  - `bytes`（proof 用）→ head 段写 offset，tail 段写 `length(32B) + 数据(32B 对齐右填充 0)`
- **函数选择器**：`keccak256(signature)[0..4]`

编码器以「参数列表」为单位组装：先算静态 head 区总长，动态参数 head 放 offset、数据追加到 tail。

### 5.3 `calldata.rs` — 三个 builder + FFI 导出

合约签名（真相源 `InvisiProtocol.sol` + ERC20）：

```solidity
approve(address spender, uint256 amount)                              // 0x095ea7b3
payOpen(bytes32 identityCommitment, uint256 amount, bytes32 nonce,
        uint256 treeId, bytes32 refundLink)
payBlind(bytes proof, bytes32 paymentCommitment, bytes32 changeCommitment,
         uint256 inputAmount, uint256 treeId, bytes32 refundLink)
```

Rust API（返回 calldata 字节，`to` 地址由调用方决定）：

```rust
pub fn build_approve_calldata(spender: &[u8; 20], amount: &[u8; 32]) -> Vec<u8>;

pub fn build_pay_open_calldata(
    identity_commitment: &[u8; 32],
    amount: &[u8; 32],
    nonce: &[u8; 32],          // bytes32 field element（见 §5.5 nonce 表示）
    tree_id: u64,
    refund_link: &[u8; 32],
) -> Vec<u8>;

pub fn build_pay_blind_calldata(
    proof: &[u8],              // 调用方传入，本 SDK 不生成
    payment_commitment: &[u8; 32],
    change_commitment: &[u8; 32],
    input_amount: &[u8; 32],
    tree_id: u64,
    refund_link: &[u8; 32],
) -> Vec<u8>;
```

FFI 导出（hex I/O，沿用现有约定）：
`privacy_build_approve_calldata` / `privacy_build_pay_open_calldata` / `privacy_build_pay_blind_calldata`（app 侧 `privacyBuildPayOpenCalldata` 等）。

### 5.4 `compute_change_commitment` 派生

对齐电路 `shielded_payment/main.nr:71-72`：

```
change_rcv        = Poseidon2(D_IDENT, change_nullifier_key, change_receiving_address)
change_commitment = Poseidon2(D_PAY, chain_id, change_rcv, token, change_amount, change_nonce)
```

即复用已有 `compute_identity_commitment` + `compute_payment_commitment` 组合：

```rust
pub fn compute_change_commitment(
    chain_id: u64,
    change_nullifier_key: &[u8; 32],
    change_receiving_address: &[u8; 20],
    token: &[u8; 20],
    change_amount: &[u8; 32],
    change_nonce: &[u8; 32],
) -> [u8; 32];
```

### 5.5 `generate_nonce` 导出 + nonce 表示

- `generate_nonce() -> [u8; 32]`：BN254 标量域内随机 32 字节 field element（`< FIELD_MODULUS`），对齐 TS `generateNonce`（`crypto.getRandomValues(32B) % FIELD_MODULUS`，大端 32 字节编码）。
- **nonce 表示统一为 32 字节 field element**贯穿 calldata + derive。
- **已对账 TS（`@invisi-labs/payer` `buildPayOpenCalldata`）**：TS 用**同一个** `nonce: bigint` 同时喂给 `computePaymentCommitment(..., nonce)` 和 calldata 的 `nonceHex = "0x"+nonce.toString(16).padStart(64,"0")`（即 bytes32）。证实 nonce 是 32 字节 field element、且派生与 calldata 必须用同一值。
- ⚠️ **对齐硬约束**：合约 `payOpen` 内部会用 on-chain 的 `nonce`（bytes32）重算 `paymentCommitment`。因此「`build_pay_open_calldata` 传入的 nonce」与「`compute_payment_commitment` 用的 nonce」必须是**同一个 field element 编码**，否则合约重算的承诺不匹配 → 交易 revert。现有 `compute_payment_commitment` 的 nonce 形参（历史为 `[u8;16]`）需统一到 `[u8;32]` field 编码，并由对齐测试钉死。
- nonce 可选来源：`propose` 模式 / mode=single 由服务端预分配；否则本地 `generate_nonce()`（与 TS `params.nonce ?? generateNonce()` 一致）。

---

## 6. 错误处理

新增稳定错误码（FFI 契约，`&'static str`）：

- `ABI_INPUT_INVALID`（输入长度/格式非法）
- 复用现有 `INPUT_INVALID` / `BUFFER_TOO_SMALL`（FFI hex I/O）

calldata builder 本身是纯函数、定长输入，正常路径不产生错误；FFI 层负责 hex 解析校验。

---

## 7. 数据流（app 如何使用）

**payOpen（公开支付，纯本地）：**
```
1. (mode=single) 从服务端拿 identity_commitment / nonce / tree_id
2. build_approve_calldata(protocol, amount)        → approve calldata，to=token
3. build_pay_open_calldata(...)                    → payOpen calldata，to=protocol
4. app 钱包层签名 + 广播两笔
```

**payBlind（隐藏支付）：**
```
1. compute_change_commitment(...)                  → change_commitment（本地）
2. [子项目② prover] 本地生成 proof bytes（payment_amount 不出设备）
3. build_pay_blind_calldata(proof, ...)            → payBlind calldata
4. build_approve_calldata + 签名广播
```

---

## 8. 测试策略

1. **单元测试**：ABI 编码各类型、选择器、动态 bytes 的 offset/padding、空 proof、roundtrip。
2. **跨语言 calldata 对齐（硬门）**：与 Poseidon2 三向量同性质——用 `go-ethereum` 绑定或 viem `encodeFunctionData` 产出 expected calldata，对 `build_*_calldata` 做**字节级 `assert_eq`**。任何一个不过即代表与合约 ABI 不兼容，必须修编码器，不得改 expected。
3. **nonce 一致性测试**：构造一组 (identity, amount, nonce)，验证「本地 `compute_payment_commitment`」== 「合约用同 nonce 重算的 paymentCommitment」（用合约/电路侧 fixture 对账）。
4. **FFI 烟雾测试**：hex I/O roundtrip + 坏输入拒绝（沿用现有 `ffi` 测试风格）。

---

## 9. 迁移影响

- 本仓库：`src/` → `crates/invisi-sdk-core/src/`；根 `Cargo.toml` 变 `[workspace]`。
- `../invisi-pay-app`：改 `apps/mobile/rust/Cargo.toml` 依赖一行（package 名 + path）。`use invisi_sdk::...` 与 native 链接不变。
- 现有 56 个测试随 `src/` 一并迁移，应全绿。

---

## 10. 后续（子项目②，独立 spec）

`invisi-sdk-prover` crate：
- bb（Barretenberg）FFI 绑定到 Rust 的**可行性 spike**。
- 本地生成的 proof 与 `shielded_payment_verifier.sol`（UltraHonk）**bit 兼容验证**。
- 打包 `shielded_payment` 电路 artifact。
- 风险与工作量集中在此，**先 spike 验证可行性再谈实现**。本子项目①不依赖②，可独立交付公开支付闭环。
