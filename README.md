# invisi-sdk-rust

InvisiPay 协议层 Rust SDK — 隐私支付的密码学原语 + 派生函数 + AEAD 字段加密。

与同生态项目对称：
- `invisi-sdk-ts` (browser/node, @aztec/bb.js WASM) — Web 钱包、商户网页、Node 后端
- **`invisi-sdk-rust`（本仓库）** — iOS / Android RN / Desktop / CLI / 嵌入式

## 包含的能力

| 模块 | 功能 | 与协议层对齐 |
|---|---|---|
| `poseidon` | Aztec Barretenberg BN254 t=4 Poseidon2 sponge | ✅ 与 nexus/Noir 电路/@aztec/bb.js bit-perfect |
| `domain` | 域分离常量 D_NKEY/D_IDENT/D_PAY/D_NULL/D_DERIVE | ✅ protocol-docs 1.2-commitment.md |
| `derive` | nullifierKey / identityCommitment / paymentCommitment / paymentNullifier | ✅ SPEC-085 派生模型 |
| `pool` | ReceiverCommitment 批生成 (1..=500 nonces) | 待 nexus 对齐 pool 格式 |
| `cipher` | XChaCha20Poly1305 AEAD 字段加密 + dbEncKey 派生 | App 独立 (DB 字段保护) |
| `ffi` | C ABI exports — iOS Swift / Android JNI bridge 调用入口 | App-side bridge 用 |

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

### Cargo 依赖

```toml
[dependencies]
invisi-sdk = { git = "https://github.com/invisi-lab/invisi-sdk-rust", tag = "v0.1.0" }
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

iOS / Android React Native 应用通过 [`invisi-pay-app`](https://github.com/invisi-lab/invisi-pay-app) 的 RN bridge 调用 — 该仓库 `apps/mobile/rust/` 引用本 SDK 作为 `[dependencies]`，仅在 RN 这层做 JSI/JNI 包装（见 `ffi.rs`）。

## License

Apache-2.0
