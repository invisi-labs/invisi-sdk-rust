# invisi-sdk-rust

InvisiPay 协议层 Rust SDK — 隐私支付的密码学原语 + 派生函数 + AEAD 字段加密。

与同生态项目对称：
- `invisi-sdk-ts` (browser/node, @aztec/bb.js WASM) — Web 钱包、商户网页、Node 后端
- **`invisi-sdk-rust`（本仓库）** — iOS / Android RN / Desktop / CLI / 嵌入式

## Workspace 结构

本仓库是 Cargo workspace，包含三个 crate：

| Crate | 位置 | 类型 | 职责 | 依赖 |
|---|---|---|---|---|
| `invisi-sdk-core` | `crates/invisi-sdk-core/` | rlib | 轻量密码学 + 派生 + 随机数：`poseidon2` hash / `derive::{compute_identity_commitment, compute_payment_commitment, compute_payment_nullifier, derive_nullifier_key, compute_change_commitment}` / `nonce::generate_nonce` / `cipher::xchachapoly1305` / `pool` | 无 alloy；**可编译 WASM** |
| `invisi-sdk-payer` | `crates/invisi-sdk-payer/` | rlib | 链上交互：`build_approve_calldata` / `build_pay_open_calldata` / `build_pay_blind_calldata` | `invisi-sdk-core` + alloy |
| `invisi-sdk-ffi` | `crates/invisi-sdk-ffi/` | staticlib + cdylib | FFI C ABI 导出 — iOS Swift / Android JNI：`privacy_compute_*` + `privacy_build_*_calldata`；并 `pub use invisi_sdk_core::*` 重导出 | `invisi-sdk-core` + `invisi-sdk-payer` |

## 包含的能力

core crate 的密码学模块：

| 模块 | 功能 | 与协议层对齐 |
|---|---|---|
| `poseidon` | Aztec Barretenberg BN254 t=4 Poseidon2 sponge | ✅ 与 nexus/Noir 电路/@aztec/bb.js bit-perfect |
| `domain` | 域分离常量 D_NKEY/D_IDENT/D_PAY/D_NULL/D_DERIVE | ✅ protocol-docs 1.2-commitment.md |
| `derive` | nullifierKey / identityCommitment / paymentCommitment / paymentNullifier / changeCommitment | ✅ SPEC-085 派生模型 |
| `pool` | ReceiverCommitment 批生成 (1..=500 nonces) | 待 nexus 对齐 pool 格式 |
| `cipher` | XChaCha20Poly1305 AEAD 字段加密 + dbEncKey 派生 | App 独立 (DB 字段保护) |
| `nonce` | 付款方随机 nonce 生成 | ✅ 与合约 nonce 校验对齐 |

payer crate 的链上接口：

| 模块 | 功能 | 与协议层对齐 |
|---|---|---|
| `calldata` | `build_approve_calldata` / `build_pay_open_calldata` / `build_pay_blind_calldata` | ✅ 字节级对齐 Solidity 合约 ABI；foundry `cast` 验证 |

## 设计原则

1. **non-custodial**：masterKey 由调用方从 OS 安全存储（Keychain/Keystore）读取后传入；SDK 不接触持久化。
2. **无 panic in production**：所有错误返回 `Result<T, Error>` 含稳定字符串错误码（`NULLIFIER_ZERO` 等）。
3. **跨平台**：no_std-friendly（预留），可编译到 iOS / Android / Linux / macOS / Windows / WASM。
4. **单向兼容**：底层 hash 升级时（如换 Poseidon2 backend）外部接口 `h(domain, inputs)` 不变。

## 安全性

| 维度 | 实现 |
|---|---|
| 域分离 | 5 个 Poseidon2 domain tag（D_NKEY=1, D_IDENT=2, D_PAY=3, D_NULL=4, D_DERIVE=8） |
| nullifier ≠ 0 不变式 | 协议 1.3:17-23 要求 — 强制断言；零值意味 invoiceId 复用 → 拒绝 |
| AEAD | XChaCha20Poly1305（NIST 推荐，24-byte nonce，16-byte tag） |
| 跨密钥隔离 | dbEncKey 与 nullifierKey 域分离派生 — masterKey 泄漏不影响 DB 加密反推 |
| 测试 vectors | 3 个 Aztec 标准向量（hash2/hash4/hash2-zeros）+ 4 个 SPEC-085 向量 |

## 使用

### Cargo 依赖 — 内部（invisi-pay-app）

若需调用本 SDK 的 C ABI（通过 FFI），依赖 `invisi-sdk-ffi` crate：

```toml
[dependencies]
invisi-sdk-ffi = { package = "invisi-sdk-ffi", path = "../../../../invisi-sdk-rust/crates/invisi-sdk-ffi" }
```

在 Rust 代码中：
```rust
use invisi_sdk::derive::{compute_identity_commitment, compute_payment_commitment};
use invisi_sdk::nonce::generate_nonce;
```

C/Swift/Kotlin 侧通过 FFI bridge 调用：
```rust
// FFI exported (in invisi-sdk-ffi)
#[no_mangle]
pub extern "C" fn privacy_compute_identity_commitment(...) { ... }
#[no_mangle]
pub extern "C" fn privacy_build_pay_open_calldata(...) { ... }
```

链接 `libinvisi_sdk.a`（静态库）或 `.dylib`（动态库）。

### Cargo 依赖 — 外部（其他 Rust 项目）

若为独立 Rust 项目，可依赖 core crate（无 alloy）：

```toml
[dependencies]
invisi-sdk-core = { git = "https://github.com/invisi-lab/invisi-sdk-rust", tag = "v0.1.0" }
```

或依赖完整 workspace：

```toml
[dependencies]
invisi-sdk-payer = { git = "https://github.com/invisi-lab/invisi-sdk-rust", tag = "v0.1.0" }
```

### 例子

```rust
use invisi_sdk::derive::{nullifier_key_raw, identity_commitment, payment_commitment};

let master_key: [u8; 32] = /* 从 OS 安全存储读取 */;
let invoice_id: [u8; 16] = /* 服务端分配 */;
let receiving_addr: [u8; 20] = /* EVM 地址 */;

let nk = nullifier_key_raw(&master_key, &invoice_id);
let identity = identity_commitment(&nk, &receiving_addr);

// 付款方扫码后用 (identity, token, amount, nonce) 算 paymentCommitment 上链
let token: [u8; 20] = /* USDT etc */;
let amount: [u8; 32] = /* big-endian raw wei */;
let nonce: [u8; 16] = /* 付款方随机 16 byte */;
let pc = payment_commitment(1u64, &identity, &token, &amount, &nonce);
```

## 测试

```bash
cargo test                          # 全部测试 (含 ignored protocol vectors)
cargo test --ignored                # 仅跑 ignored 测试
cargo test --release                # release 模式跑测试 (性能基准)
```

## 移动端集成

### invisi-pay-app 迁移指引

iOS / Android React Native 应用 [`invisi-pay-app`](https://github.com/invisi-lab/invisi-pay-app) 需从单 crate 依赖迁移到 workspace：

**Step 1: 更新 `apps/mobile/rust/Cargo.toml`**

```diff
[dependencies]
- invisi-sdk = { path = "../../../../invisi-sdk-rust" }
+ invisi-sdk-ffi = { package = "invisi-sdk-ffi", path = "../../../../invisi-sdk-rust/crates/invisi-sdk-ffi" }
```

**Step 2: 保持 Rust 代码不变**

所有 `use invisi_sdk::*` 导入继续工作（因 `invisi-sdk-ffi` 声明 `pub use invisi_sdk_core::*`）：

```rust
// 继续用（不改）
use invisi_sdk::derive::compute_identity_commitment;
use invisi_sdk::nonce::generate_nonce;
```

**Step 3: C/Swift 链接不变**

- iOS: `libinvisi_sdk.a` 链接方式同前
- Android: `libinvisi_sdk.so` 链接方式同前
- 所有 FFI 符号 `privacy_*` 继续导出

### 本 SDK 架构

- **invisi-sdk-core**：纯密码学，无 alloy，可独立编译 WASM、iOS、Android 库。
- **invisi-sdk-payer**：链上交互（calldata 构造），依赖 core + alloy。
- **invisi-sdk-ffi**：统一 FFI 入口，导出所有 C ABI，对 app 端透明。

其中 **子项目②（prover）**：`invisi-sdk-prover` 为独立 crate（尚未实现），未来在 workspace 引入。

## License

Apache-2.0
