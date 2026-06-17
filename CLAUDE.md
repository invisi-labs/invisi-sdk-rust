# CLAUDE.md

本仓库 = InvisiPay 协议层 Rust SDK。

## 仓库定位

| 仓库 | 角色 |
|---|---|
| `../invisi-protocol` | Noir 电路 + Solidity 合约 — 链上协议层 |
| `../invisi-nexus` | Go 后端服务（KMS / proof-service / payment-service / 等） |
| `../invisi-sdk-ts` | TS/JS SDK（@aztec/bb.js WASM）— 服务 Web / Node |
| **本仓库 `invisi-sdk-rust`** | Rust SDK — 服务 iOS / Android RN / Desktop / CLI / 嵌入式 |
| `../invisi-pay-app` | RN 客户端 — 消费本 SDK 通过 JSI/JNI bridge |
| `../invisi-pay-docs` | 产品 + 技术文档 + SPEC + PLAN |

## 关键设计

- **Poseidon2 实现**：Aztec Barretenberg BN254 t=4 (RF=8, RP=56, d=5)。与 `../invisi-nexus/pkg/kms/poseidon2.go` + `../invisi-protocol/circuits/*/src/main.nr` + `@aztec/bb.js poseidon2Hash` **bit-perfect**。3 个 alignment test vectors 是硬门。
- **域分离常量**：与 `../protocol-docs/01-protocol/1.2-commitment.md:12-21` 锁定（D_NKEY=1, D_IDENT=2, D_PAY=3, D_NULL=4, D_DERIVE=8）。
- **nullifier ≠ 0 不变式**：协议 1.3:17-23 — 零值是 batch 电路 padding 标记；产生零 → invoiceId 复用 → 必抛 `NullifierIsZero`。
- **non-custodial**：本 SDK 不读 Keychain 不持久化 masterKey；所有需要 masterKey 的函数都接受 `&[u8; 32]` 由调用方传入。
- **错误码稳定**：`Error::code()` 返回 `&'static str`（NULLIFIER_ZERO 等）是 FFI 跨语言契约，不可改。

## 工作流

| 阶段 | skill |
|---|---|
| 改 hash 实现 / 加 derive 函数 | `superpowers:test-driven-development` |
| 给 mobile / 服务端发布新版本 | `superpowers:requesting-code-review` 然后 cargo publish (TBD) |
| 升级协议常量 / 域分离 | 必须先在 protocol-docs SPEC 里改，本仓库跟进 |

## 构建 + 测试

```bash
cargo build              # debug
cargo test               # 全部测试
cargo test --release     # release 模式
cargo test --ignored     # 包括协议 vectors (升级后激活)
cargo doc --open         # 文档站
```

## 跨平台编译

```bash
# iOS (aarch64-apple-ios)
cargo build --target aarch64-apple-ios --release
# Android (aarch64-linux-android, 需要 NDK)
cargo build --target aarch64-linux-android --release
# WASM (wasm32-unknown-unknown)
cargo build --target wasm32-unknown-unknown --release
```

mobile app 通过 path / git 依赖引用本 SDK。

## 与 invisi-pay-app 的边界

- 本 SDK：**纯密码学 + 派生**。无 RN、无 JSI/JNI、无 platform-specific code（除 `ffi` 模块的 C ABI 给 RN bridge 用）。
- mobile app：JSI/JNI bridge 在 `apps/mobile/rust/` + `apps/mobile/ios/` + `apps/mobile/android/`。bridge 层负责从 Keychain 读 masterKey 后调本 SDK 函数。
