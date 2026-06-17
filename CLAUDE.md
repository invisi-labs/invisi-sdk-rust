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

## Workspace 结构

本仓库组织为 Cargo workspace（`Cargo.toml` 声明 `[workspace]`），包含三个 crate：

| Crate | 路径 | 类型 | 职责 |
|---|---|---|---|
| **invisi-sdk-core** | `crates/invisi-sdk-core/` | rlib | 密码学原语（poseidon2 / 派生函数 / nonce / cipher / pool）；**无 alloy**；可编译 WASM/iOS/Android |
| **invisi-sdk-payer** | `crates/invisi-sdk-payer/` | rlib | 链上交互（calldata 构造）；依赖 core + alloy-core/alloy-primitives |
| **invisi-sdk-ffi** | `crates/invisi-sdk-ffi/` | staticlib + cdylib | FFI C ABI 层；导出 `privacy_*` 符号；`pub use invisi_sdk_core::*` 重导出；链接端选用 `.a` 或 `.dylib` |

### 子项目②：Prover

- **invisi-sdk-prover**（未建）：独立 crate，选型 spike 中。未来将：
  - 本地 ZK proof 框架 = **Barretenberg (bb) UltraHonk** —— 本地生成的 proof 必须与链上 `../invisi-protocol/contracts/src/verifiers/shielded_payment_verifier.sol`（bb UltraHonk）**bit 兼容**；故**非** Halo2 / Circom（那些证明格式与已部署 verifier 不兼容）
  - spike：bb 经 FFI 绑定到 Rust 的可行性 + 与 verifier 的 bit 兼容验证 + 打包 `shielded_payment` 电路 artifact
  - 实现 witness 生成 + proof 构造 + FFI 导出给 app
  - 仓库内 workspace 集成
  
## 关键设计

- **Poseidon2 实现**：Aztec Barretenberg BN254 t=4 (RF=8, RP=56, d=5)。与 `../invisi-nexus/pkg/kms/poseidon2.go` + `../invisi-protocol/circuits/*/src/main.nr` + `@aztec/bb.js poseidon2Hash` **bit-perfect**。3 个 alignment test vectors 是硬门。
- **域分离常量**：与 `../protocol-docs/01-protocol/1.2-commitment.md:12-21` 锁定（D_NKEY=1, D_IDENT=2, D_PAY=3, D_NULL=4, D_DERIVE=8）。
- **nullifier ≠ 0 不变式**：协议 1.3:17-23 — 零值是 batch 电路 padding 标记；产生零 → invoiceId 复用 → 必抛 `NullifierIsZero`。
- **non-custodial**：本 SDK 不读 Keychain 不持久化 masterKey；所有需要 masterKey 的函数都接受 `&[u8; 32]` 由调用方传入。
- **错误码稳定**：`Error::code()` 返回 `&'static str`（NULLIFIER_ZERO 等）是 FFI 跨语言契约，不可改。
- **calldata 构造**：payer crate 的 `build_*_calldata` 与 Solidity 合约 ABI **字节级对齐**；foundry `cast` 验证通过。

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

### App 端迁移

app 的 `apps/mobile/rust/Cargo.toml` 改：
```diff
- invisi-sdk = { path = "../../../../invisi-sdk-rust" }
+ invisi-sdk-ffi = { package = "invisi-sdk-ffi", path = "../../../../invisi-sdk-rust/crates/invisi-sdk-ffi" }
```

所有 Rust 端 `use invisi_sdk::*` 继续有效（core 函数通过 FFI crate 重导出）；C/Swift/Kotlin 链接 `libinvisi_sdk.a` 不变。

### 职责边界

- **本 SDK**（三 crate）：
  - **core**：纯密码学 + 派生，无 alloy，可独立 WASM 编译
  - **payer**：链上 calldata 构造，依赖 alloy 类型
  - **ffi**：统一 C ABI 层，导出 `privacy_*` 符号
  - 无 RN、无 JSI/JNI、无 platform-specific code（除 ffi 的 C ABI）
- **mobile app**：JSI/JNI bridge 在 `apps/mobile/rust/` + `apps/mobile/ios/` + `apps/mobile/android/`。bridge 层负责从 Keychain/Keystore 读 masterKey 后调本 SDK 函数。
