# 设计：Rust SDK 镜像 invisi-sdk-ts 结构 — workspace + payer(calldata)

**日期：** 2026-06-17
**状态：** 待 review
**作者：** wink@invisipay.fi（+ Claude 协作 brainstorm）

## 关联

| 仓库 / 文档 | 关系 |
|---|---|
| `../invisi-sdk-ts`（`core` / `payer` / `node`） | **镜像对象** —— 结构 + 命名 + 功能对齐的权威参照 |
| `../invisi-protocol/contracts/src/InvisiProtocol.sol` | `payOpen` / `payBlind` 合约签名（calldata 字节级真相源） |
| `../invisi-protocol/circuits/shielded_payment/src/main.nr` | `change_commitment` 派生公式 |
| `../invisi-nexus/tests/e2e/onchain/*` | app 支付侧逻辑的 Go 参考实现 |
| `../invisi-nexus/.../account-service/wallet_crypto.go` | masterKey 派生（app 侧职责，**本 SDK 不实现**） |
| 后续 spec ②（prover） | 姊妹子项目，独立交付 |

---

## 1. 背景与设计原则

app 端做隐私支付需要在本地：**扫码解析(IPP)** → **派生/算承诺** → **构建 calldata**。其中：
- **扫码解析**：IPP 二维码内是**公开数据**（identityCommitment / token / treeId / amount / endpoint），解析不碰任何 secret、不泄漏隐私 → **RN app 直接用 JS `@invisi-labs/ipp` 解，不进 Rust**（见 §2 留白）。
- **派生 / 算承诺 / 构建 calldata**：碰 masterKey、需与合约字节级对齐 → 进 Rust SDK。
- **Merkle tree**：服务端给，不本地建。
- **ZK proof**：子项目②。

**范围原则（brainstorm 提炼）：进 Rust SDK 的只有「碰 secret 的密码学计算」与「无 JS 路径的消费者(CLI/desktop/嵌入式)必需项」。** 纯公开数据的解析、网络 I/O、签名、存储 → 留 app 层。

**镜像结构决策**：Rust SDK 镜像 `invisi-sdk-ts` 的 monorepo —— 一个 Cargo workspace、多 crate，crate 与 TS 包一一对应，跨语言维护心智零成本。但**不是"照搬全部实现再砍"**：TS `payer` 依赖 viem，Rust 无对应物只能用生态库重写；照搬未用代码 = 死代码。故 **镜像「结构」，移植「需要的函数」到正确 crate，其余不建死桩、文档标注**。

**SDK 单一原则**：只接收参数 + 计算。无网络、无签名、无存储、无 masterKey 派生策略。

---

## 2. crate 结构（镜像 TS）

```
invisi-sdk-rust/                   # 仓库 = Cargo workspace（"同一套"）
├── Cargo.toml                     # [workspace] virtual manifest
└── crates/
    ├── invisi-sdk-core/           # ← @invisi-labs/core
    │     compute_*/derive_*/generate_nonce/poseidon
    │     + Rust 特有：cipher(AEAD) / pool / ffi（平台差异，保留）
    │     约束：轻量、纯算、可编 WASM、无重 eth 依赖
    │     [lib] name = "invisi_sdk"（FFI 符号 + 链接产物名稳定，不变）
    ├── invisi-sdk-payer/          # ← @invisi-labs/payer
    │     build_{pay_open,pay_blind,approve}_calldata
    │     依赖 core + alloy（Rust 版 viem，做 ABI 编码 + keccak）
    └── invisi-sdk-prover/         # ← @invisi-labs/node（子项目②，本 spec 不实现）
```

### crate ↔ TS 映射 + 取舍

| TS 包 | Rust crate | 本轮 | 说明 |
|---|---|---|---|
| `@invisi-labs/core` | `invisi-sdk-core` | ✅ 重构+改名 | 现有 src/ 迁入；派生函数改名对齐 |
| `@invisi-labs/payer` | `invisi-sdk-payer` | ✅ 新建 | 仅移植 3 个 calldata builder（用 alloy） |
| `@invisi-labs/node` | `invisi-sdk-prover` | ⏭️ 子项目② | 占位，先做选型 spike |
| `@invisi-labs/ipp` | `invisi-sdk-ipp` | ⏭️ 留白 | 解析公开数据、不碰 secret；RN 用 JS 解即可。**待出现 CLI/desktop/嵌入式（无 JS）消费者再建** |
| `@invisi-labs/receiver` | `invisi-sdk-receiver` | ⏭️ 留白 | 需要时再建（generateInvoice 等收款侧） |
| `@invisi-labs/react` `vue` | — | ❌ 砍 | 纯 JS，无对应 |
| `@invisi-labs/tree` | — | ❌ 砍 | merkle 服务端给，不需本地建 |
| `@invisi-labs/contracts` `deployments` | — | ❌ 砍 | ABI/部署表，Rust 用到再说 |
| payer 的 userOp / metaTx / credit / fromRequest | — | ⏭️ 留白 | 暂不需要，不建死桩 |

### 命名对齐 + lib 名稳定

- crate 名直接对齐 TS（`core`/`payer`）；prover **故意不叫 `node`**（Node.js 运行时语义，搬到 Rust 误导）。
- `[lib] name = "invisi_sdk"` 不变 → app 的 `use invisi_sdk::...`、native 链接产物 `libinvisi_sdk.a` 全稳定。
- app 迁移：改 `apps/mobile/rust/Cargo.toml` 依赖行（package 名 + path 指向 `crates/invisi-sdk-core`；新增 payer）。

### 函数命名对齐 `@invisi-labs/core`

| TS | 现 Rust | 对齐后 |
|---|---|---|
| `computeIdentityCommitment` | `identity_commitment` | `compute_identity_commitment` |
| `computePaymentCommitment` | `payment_commitment` | `compute_payment_commitment` |
| `computePaymentNullifier` | `payment_nullifier` | `compute_payment_nullifier` |
| `computeChangeCommitment` | — | `compute_change_commitment`（新增） |
| `deriveNullifierKey` | `nullifier_key_raw` | `derive_nullifier_key`（去掉多余 `_raw`） |
| `generateNonce` | （pool 内部） | `generate_nonce`（导出） |

FFI 导出名保持现状（`privacy_compute_*` 已镜像 TS），新增项延续 `privacy_build_*`。

---

## 3. 三条支付路径的 calldata/proof 归属

（经 `../invisi-nexus` e2e 闭环确认）

| 路径 | proof | merkle | calldata 谁构建 |
|---|---|---|---|
| **payOpen** | 无 | 无 | 客户端本地（payer crate，静态 ABI） |
| **payBlind** | 本地生成（隐私，子项目②） | 无（电路不需要） | 客户端本地（payer crate，动态 `bytes proof` 入参） |
| **withdraw/settle** | 服务端 | 服务端 | **服务端返回完整 calldata**，客户端只注入 nullifier |

→ 本 SDK 只负责 payOpen + payBlind + approve 三种 calldata。

---

## 4. `invisi-sdk-payer` 模块设计

### 4.1 ABI 编码：用 alloy（对齐 TS 用 viem）

payer crate 依赖 `alloy-primitives`（keccak256 / Address / U256）+ `alloy-sol-types`（`sol!` 宏做 ABI 编码）。这是 Rust 生态的 viem 等价物，比手写 ABI 编码器更稳、更对齐 TS 的 `encodeFunctionData`。重依赖只落在 payer，**core 保持轻量、可 WASM 不受影响**。

### 4.2 三个 builder

合约签名（真相源 `InvisiProtocol.sol` + ERC20）：

```solidity
approve(address spender, uint256 amount)                               // 0x095ea7b3
payOpen(bytes32 identityCommitment, uint256 amount, bytes32 nonce,
        uint256 treeId, bytes32 refundLink)
payBlind(bytes proof, bytes32 paymentCommitment, bytes32 changeCommitment,
         uint256 inputAmount, uint256 treeId, bytes32 refundLink)
```

```rust
pub fn build_approve_calldata(spender: &[u8;20], amount: &[u8;32]) -> Vec<u8>;
pub fn build_pay_open_calldata(
    identity_commitment: &[u8;32], amount: &[u8;32],
    nonce: &[u8;32], tree_id: u64, refund_link: &[u8;32]) -> Vec<u8>;
pub fn build_pay_blind_calldata(
    proof: &[u8],                      // 调用方传入，本 SDK 不生成
    payment_commitment: &[u8;32], change_commitment: &[u8;32],
    input_amount: &[u8;32], tree_id: u64, refund_link: &[u8;32]) -> Vec<u8>;
```

FFI 导出（hex I/O）：`privacy_build_approve_calldata` / `privacy_build_pay_open_calldata` / `privacy_build_pay_blind_calldata`。

---

## 5. `invisi-sdk-core` 新增派生

### `compute_change_commitment`（对齐电路 `main.nr:71-72`）

```
change_rcv        = Poseidon2(D_IDENT, change_nullifier_key, change_receiving_address)
change_commitment = Poseidon2(D_PAY, chain_id, change_rcv, token, change_amount, change_nonce)
```
复用 `compute_identity_commitment` + `compute_payment_commitment`。

### `generate_nonce` + nonce 表示

- `generate_nonce() -> [u8;32]`：BN254 标量域随机 field element（`< FIELD_MODULUS`，大端 32 字节），对齐 TS `generateNonce`。
- **已对账 TS `buildPayOpenCalldata`**：同一个 `nonce` 同时喂 `computePaymentCommitment` 和 calldata `nonceHex`(bytes32)。证实 nonce = 32 字节 field element 且派生/calldata 必须同值。
- ⚠️ **对齐硬约束**：合约 `payOpen` 用 on-chain nonce 重算 `paymentCommitment`，两处 nonce 编码不一致 → revert。现有 `compute_payment_commitment` 的 nonce 形参（`[u8;16]`）需统一到 `[u8;32]` field 编码，由对齐测试钉死。
- nonce 来源：propose / mode=single 服务端给；否则本地 `generate_nonce()`。

---

## 6. 数据流（app 隐私支付，本地部分）

```
扫码 → [app JS] @invisi-labs/ipp decodeIPPRequest        → IPPRequest（identity/tree_id/nonce/...）
[需 propose 时] app 调服务端拿 nonce+paymentCommitment（网络，非 SDK）
[payOpen]  payer::build_approve_calldata + build_pay_open_calldata
[payBlind] core::compute_change_commitment
         → [子项目② prover] 本地 proof（payment_amount 不出设备）
         → payer::build_pay_blind_calldata
→ app 钱包层签名 + 广播（非 SDK）
```

---

## 7. 非目标

- **ZK prover** → 子项目② `invisi-sdk-prover`。
- **IPP 二维码解析** → RN app JS（`@invisi-labs/ipp`）；公开数据不泄漏，无需进 Rust。未来非 JS 消费者再补。
- **网络 HTTP / IPPClient** → app 层。
- **merkle tree / withdraw calldata** → 服务端。
- **签名 / 广播 / Keychain / masterKey 派生策略** → app 钱包层。本 SDK 只收 `masterKey: &[u8;32]`（与 TS `@invisi-labs/core` 一致 —— masterKey 纯入参，不签名不派生）。
- **receiver / userOp / metaTx / credit / tree / react / vue / contracts** → 砍或留白。

---

## 8. 测试策略

1. **单元**：core 派生；payer ABI 各类型/选择器/动态 bytes/roundtrip。
2. **跨语言 calldata 对齐（硬门）**：payer `build_*_calldata` 字节级 `assert_eq` 对账 go-ethereum/viem 产出，与 Poseidon2 向量同性质，不得改 expected。
3. **nonce 一致性**：本地 `compute_payment_commitment` == 合约用同 nonce 重算的承诺（fixture 对账）。
4. **FFI 烟雾**：hex I/O roundtrip + 坏输入拒绝（沿用现有 `ffi` 测试风格）。

---

## 9. 迁移影响

- 本仓库：`src/` → `crates/invisi-sdk-core/src/`；根 `Cargo.toml` 变 `[workspace]`；新建 payer/prover crate。现有 56 测试随迁应全绿。
- `../invisi-pay-app`：改 `apps/mobile/rust/Cargo.toml` 依赖（core 改 path+名；新增 payer）。`use invisi_sdk::...` 与 native 链接不变。

---

## 10. 后续（子项目②，独立 spec）

`invisi-sdk-prover`：bb(Barretenberg) FFI 绑定可行性 spike → 本地 proof 与 `shielded_payment_verifier.sol`(UltraHonk) bit 兼容验证 → 打包电路 artifact。风险集中于此，先 spike 再实现。子项目①不依赖②。
