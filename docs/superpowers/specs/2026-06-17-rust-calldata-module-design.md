# 设计：Rust SDK 镜像 invisi-sdk-ts 结构 — workspace + payer(calldata) + ipp

**日期：** 2026-06-17
**状态：** 待 review
**作者：** wink@invisipay.fi（+ Claude 协作 brainstorm）

## 关联

| 仓库 / 文档 | 关系 |
|---|---|
| `../invisi-sdk-ts`（`core` / `payer` / `ipp` / `node`） | **镜像对象** —— 结构 + 命名 + 功能对齐的权威参照 |
| `../invisi-protocol/contracts/src/InvisiProtocol.sol` | `payOpen` / `payBlind` 合约签名（calldata 字节级真相源） |
| `../invisi-protocol/circuits/shielded_payment/src/main.nr` | `change_commitment` 派生公式 |
| `../invisi-nexus/tests/e2e/onchain/*` | app 支付侧逻辑的 Go 参考实现 |
| `../invisi-nexus/.../account-service/wallet_crypto.go` | masterKey 派生（app 侧职责，**本 SDK 不实现**） |
| 后续 spec ②（prover） | 姊妹子项目，独立交付 |

---

## 1. 背景与设计原则

app 端做隐私支付需要在本地：**扫码解析(IPP)** → **派生/算承诺** → **构建 calldata**。Merkle tree 不需本地建（服务端给），ZK proof 见子项目②。

**核心设计决策（brainstorm 定）：Rust SDK 镜像 `invisi-sdk-ts` 的 monorepo 结构** —— 一个 Cargo workspace、多 crate，crate 与 TS 包一一对应。这样跨语言维护时 TS 改哪个包就改 Rust 对应 crate，心智零成本。

**但不是"照搬全部实现再砍"**，原因：
1. TS `payer`/`ipp` 大量依赖 viem / msgpack 等 JS 库，Rust 无对应物，**只能用 Rust 生态库重写，无法机械翻译**。
2. 照搬未用代码 = 死代码、无测试、是负债。
3. Rust core 因平台差异**合理地多出** TS core 没有的东西（`cipher`/`pool`/`ffi`，服务原生移动端）。两边永远不是字面 1:1。

**因此策略 = 镜像「结构」，移植「需要的函数」到正确的 crate，不需要的不建死桩、文档标注。**

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
    ├── invisi-sdk-ipp/            # ← @invisi-labs/ipp（去掉网络 client）
    │     types / codec / validate / caip2 / meta
    │     依赖 rmp-serde(msgpack) + base64 + serde
    └── invisi-sdk-prover/         # ← @invisi-labs/node（子项目②，本 spec 不实现）
```

### crate ↔ TS 映射 + 取舍

| TS 包 | Rust crate | 本轮 | 说明 |
|---|---|---|---|
| `@invisi-labs/core` | `invisi-sdk-core` | ✅ 重构+改名 | 现有 src/ 迁入；派生函数改名对齐 |
| `@invisi-labs/payer` | `invisi-sdk-payer` | ✅ 新建 | 仅移植 3 个 calldata builder |
| `@invisi-labs/ipp` | `invisi-sdk-ipp` | ✅ 新建 | 移植 codec/validate/caip2/types/meta，**不含 client(网络)** |
| `@invisi-labs/node` | `invisi-sdk-prover` | ⏭️ 子项目② | 占位，先做选型 spike |
| `@invisi-labs/receiver` | `invisi-sdk-receiver` | ⏭️ 留白 | 需要时再建（generateInvoice 等收款侧） |
| `@invisi-labs/react` `vue` | — | ❌ 砍 | 纯 JS，无对应 |
| `@invisi-labs/tree` | — | ❌ 砍 | merkle 服务端给，不需本地建 |
| `@invisi-labs/contracts` `deployments` | — | ❌ 砍 | ABI/部署表，Rust 用到再说 |
| payer 的 userOp / metaTx / credit / fromRequest | — | ⏭️ 留白 | 暂不需要，不建死桩 |

### 命名对齐 + lib 名稳定

- crate 名直接对齐 TS（`core`/`payer`/`ipp`）；prover **故意不叫 `node`**（Node.js 运行时语义，搬到 Rust 误导）。
- `[lib] name = "invisi_sdk"` 不变 → app 的 `use invisi_sdk::...`、native 链接产物 `libinvisi_sdk.a` 全稳定。
- app 迁移：改 `apps/mobile/rust/Cargo.toml` 依赖行（package 名 + path 指向 `crates/invisi-sdk-core`）。

### 函数命名对齐 `@invisi-labs/core`

| TS | 现 Rust | 对齐后 |
|---|---|---|
| `computeIdentityCommitment` | `identity_commitment` | `compute_identity_commitment` |
| `computePaymentCommitment` | `payment_commitment` | `compute_payment_commitment` |
| `computePaymentNullifier` | `payment_nullifier` | `compute_payment_nullifier` |
| `computeChangeCommitment` | — | `compute_change_commitment`（新增） |
| `deriveNullifierKey` | `nullifier_key_raw` | `derive_nullifier_key`（去掉多余 `_raw`） |
| `generateNonce` | （pool 内部） | `generate_nonce`（导出） |

FFI 导出名保持现状（`privacy_compute_*` 已镜像 TS），新增项延续 `privacy_build_*` / `privacy_decode_ipp_qr`。

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

## 6. `invisi-sdk-ipp` 模块设计

移植 `@invisi-labs/ipp` 的纯函数部分（**`client.ts` 网络部分不移植**，HTTP 归 app 层）：

- **`types`**：`IPPRequest { v, network, meta?, payload }`、`IPPPayloadV1 { identityCommitment, tokenAddress, operator, treeId, paymentTypes, amount?, nonce?, paymentCommitment?, endpoint? }`。
- **`codec`**：`encode_ipp_request` / `decode_ipp_request`。compact 格式 = `ipp{v}:` + base64url(MessagePack(request))（`rmp-serde` + `base64`）；JSON 格式 = serde_json。decode 自动检测（`{` → JSON，`ipp` → compact）。**这就是二维码内容。**
- **`validate`**：三模式校验 —— ①a `nonce`+`paymentCommitment`（扫码即付）；①b/② 仅 `endpoint`（需调 propose）；`nonce`/`paymentCommitment` 必须同时有或同时无。
- **`caip2`**：`chain_id_to_caip2` / `caip2_to_chain_id`（如 `eip155:84532`）。
- **`meta`**：meta keys 常量。

FFI 导出：`privacy_decode_ipp_qr`（输入二维码字符串，输出解析字段 JSON 给 app 用）。

---

## 7. 数据流（app 隐私支付，全本地部分）

```
扫码 → invisi-sdk-ipp::decode_ipp_request           → IPPRequest（identity/tree_id/nonce/...）
     → invisi-sdk-ipp::validate                     → 判定扫码即付 / 需 propose
[需 propose 时] app 调服务端拿 nonce+paymentCommitment（网络，非 SDK）
[payOpen] payer::build_approve_calldata + build_pay_open_calldata
[payBlind] core::compute_change_commitment
         → [子项目② prover] 本地 proof（payment_amount 不出设备）
         → payer::build_pay_blind_calldata
→ app 钱包层签名 + 广播（非 SDK）
```

---

## 8. 非目标

- **ZK prover** → 子项目② `invisi-sdk-prover`。
- **IPPClient / 任何网络 HTTP** → app 层。
- **merkle tree / withdraw calldata** → 服务端。
- **签名 / 广播 / Keychain / masterKey 派生策略** → app 钱包层。本 SDK 只收 `masterKey: &[u8;32]`（与 TS `@invisi-labs/core` 一致 —— masterKey 纯入参，不签名不派生）。
- **receiver / userOp / metaTx / credit / tree / react / vue / contracts** → 砍或留白。

---

## 9. 测试策略

1. **单元**：core 派生、payer ABI 各类型/选择器/动态 bytes、ipp codec roundtrip + 三模式 validate + caip2。
2. **跨语言 calldata 对齐（硬门）**：payer `build_*_calldata` 字节级 `assert_eq` 对账 go-ethereum/viem 产出，与 Poseidon2 向量同性质，不得改 expected。
3. **IPP 互通**：用 TS `encodeIPPRequest` 产的 `ippN:` 串喂 Rust `decode_ipp_request`，字段一致；反向亦然。
4. **nonce 一致性**：本地 `compute_payment_commitment` == 合约用同 nonce 重算的承诺（fixture 对账）。
5. **FFI 烟雾**：hex/JSON I/O roundtrip + 坏输入拒绝。

---

## 10. 迁移影响

- 本仓库：`src/` → `crates/invisi-sdk-core/src/`；根 `Cargo.toml` 变 `[workspace]`；新建 payer/ipp/prover crate。现有 56 测试随迁应全绿。
- `../invisi-pay-app`：改 `apps/mobile/rust/Cargo.toml` 依赖（core 改 path+名；新增 payer/ipp）。`use invisi_sdk::...` 与 native 链接不变。

---

## 11. 后续（子项目②，独立 spec）

`invisi-sdk-prover`：bb(Barretenberg) FFI 绑定可行性 spike → 本地 proof 与 `shielded_payment_verifier.sol`(UltraHonk) bit 兼容验证 → 打包电路 artifact。风险集中于此，先 spike 再实现。子项目①不依赖②。
