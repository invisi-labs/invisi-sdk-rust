# Rust SDK calldata 模块 + workspace 重构 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把单 crate 仓库重构为镜像 `invisi-sdk-ts` 的 Cargo workspace，新增 payer crate 的本地 calldata 构建能力（payOpen / payBlind / approve），并对齐 TS 命名。

**Architecture:** 三 crate workspace —— `invisi-sdk-core`（纯 rlib：派生 + Poseidon + cipher + pool，轻量可 WASM、无 eth 依赖）、`invisi-sdk-payer`（rlib：alloy 做 ABI 编码的 calldata builder）、`invisi-sdk-ffi`（staticlib+cdylib，`[lib] name="invisi_sdk"`：依赖 core+payer，聚合所有 `privacy_*` C ABI 导出，是 app 链接的唯一产物）。FFI 单独成 crate 是为了让 core 不被 payer 的 alloy 依赖污染。

**Tech Stack:** Rust 2021 / ark-bn254 / alloy-primitives + alloy-sol-types / tiny-keccak（经 alloy 间接）/ Cargo workspace。

## Global Constraints

- `[lib] name = "invisi_sdk"` 仅存在于 `invisi-sdk-ffi` crate；保持此名不变（app 的 `libinvisi_sdk.a` 链接 + `use invisi_sdk::...` 稳定）。
- FFI 导出符号名（`privacy_*`）是稳定跨语言契约，**不可改**；错误码 `Error::code()` 的 `&'static str`（`INPUT_INVALID` / `BUFFER_TOO_SMALL` / `NULLIFIER_ZERO` 等）不可改。
- `invisi-sdk-core` **不得**依赖 alloy 或任何重型 eth 库，须保持可编 `wasm32-unknown-unknown`。
- nullifier ≠ 0 不变式（协议 1.3:17-23）保留。
- nonce 统一为 32 字节 field element（big-endian）；invoiceId 保持 16 字节。
- calldata 字节须与合约真实 ABI 编码一致（硬门，对账 foundry `cast`）。
- 合约签名（真相源 `../invisi-protocol/contracts/src/InvisiProtocol.sol`）：
  - `approve(address,uint256)` selector `0x095ea7b3`
  - `payOpen(bytes32,uint256,bytes32,uint256,bytes32)`
  - `payBlind(bytes,bytes32,bytes32,uint256,uint256,bytes32)`

---

### Task 1: workspace + core/ffi 双 crate 拆分

把现有单 crate 拆成 `invisi-sdk-core`（rlib，去掉 ffi）+ `invisi-sdk-ffi`（staticlib/cdylib，承接 ffi.rs）。结束时所有现有测试在新布局下全绿。

**Files:**
- Create: `Cargo.toml`（根，改为 `[workspace]`）
- Create: `crates/invisi-sdk-core/Cargo.toml`
- Create: `crates/invisi-sdk-ffi/Cargo.toml`
- Move: `src/{cipher,derive,domain,error,field,pool,poseidon,poseidon_constants}.rs` + `src/lib.rs` → `crates/invisi-sdk-core/src/`
- Move: `src/ffi.rs` → `crates/invisi-sdk-ffi/src/lib.rs`
- Move: `src/tests.rs` → 拆分：非 FFI 测试留 `crates/invisi-sdk-core/src/tests.rs`，FFI 烟雾测试（`ffi_*`）移到 `crates/invisi-sdk-ffi/src/lib.rs` 的 `#[cfg(test)] mod tests`

**Interfaces:**
- Produces: crate `invisi-sdk-core`（rlib，导出 `derive` / `poseidon` / `field` / `domain` / `error` / `cipher` / `pool` 模块）；crate `invisi-sdk-ffi`（`[lib] name="invisi_sdk"`，`privacy_*` 导出）。

- [ ] **Step 1: 建目录并移动 core 源文件**

```bash
cd /Users/walk/workspace/invisi/invisi-sdk-rust
mkdir -p crates/invisi-sdk-core/src crates/invisi-sdk-ffi/src
git mv src/cipher.rs src/derive.rs src/domain.rs src/error.rs src/field.rs \
       src/pool.rs src/poseidon.rs src/poseidon_constants.rs src/lib.rs \
       crates/invisi-sdk-core/src/
git mv src/ffi.rs crates/invisi-sdk-ffi/src/lib.rs
```

- [ ] **Step 2: 拆分 tests.rs**

把 `src/tests.rs` 中所有 `ffi_*` 开头的测试函数剪切出来；其余留在 core。

```bash
git mv src/tests.rs crates/invisi-sdk-core/src/tests.rs
rmdir src 2>/dev/null || true
```

然后手工把 `crates/invisi-sdk-core/src/tests.rs` 里 9 个 `ffi_*` 测试函数（`ffi_identity_commitment_smoke` / `ffi_identity_commitment_rejects_bad_hex` / `ffi_payment_commitment_smoke` / `ffi_payment_commitment_accepts_hex_chain_id` / `ffi_payment_nullifier_smoke` / `ffi_generate_receiver_pool_smoke` / `ffi_pool_rejects_oversized_count` / `ffi_encrypt_decrypt_roundtrip` / `ffi_decrypt_wrong_key_fails`）连同其用到的 helper 移入 `crates/invisi-sdk-ffi/src/lib.rs` 末尾的 `#[cfg(test)] mod tests { use super::*; ... }`。FFI 测试里对导出函数的调用改为 `super::privacy_...`。

- [ ] **Step 3: 从 core 的 lib.rs 移除 ffi 模块**

编辑 `crates/invisi-sdk-core/src/lib.rs`，删除 `pub mod ffi;` 行；更新模块文档列表去掉 `ffi`。

- [ ] **Step 4: 写根 workspace Cargo.toml**

```toml
[workspace]
resolver = "2"
members = ["crates/invisi-sdk-core", "crates/invisi-sdk-ffi"]

[profile.release]
opt-level = "z"
lto = true
strip = "debuginfo"
```

- [ ] **Step 5: 写 core Cargo.toml**

```toml
[package]
name = "invisi-sdk-core"
version = "0.1.0"
edition = "2021"
authors = ["InvisiPay team"]
license = "Apache-2.0"
description = "InvisiPay protocol core crypto — Poseidon2, commitment derivation, AEAD field encryption"
repository = "https://github.com/invisi-lab/invisi-sdk-rust"

# 注意：core 不设 [lib] name —— 默认 crate 名 invisi_sdk_core。
# 只有 invisi-sdk-ffi 用 name = "invisi_sdk"（见 Task 1 Step 6），避免双 crate 同名冲突。

[dependencies]
ark-bn254 = { version = "0.4", default-features = false, features = ["scalar_field"] }
ark-ff = { version = "0.4", default-features = false }
chacha20poly1305 = "0.10"
rand = "0.8"
sha2 = "0.10"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "1.0"
uuid = { version = "1", features = ["v4"] }
hex = "0.4"
```

- [ ] **Step 6: 写 ffi Cargo.toml**

```toml
[package]
name = "invisi-sdk-ffi"
version = "0.1.0"
edition = "2021"
license = "Apache-2.0"
description = "InvisiPay SDK C ABI exports for iOS/Android bridges"

[lib]
name = "invisi_sdk"
crate-type = ["staticlib", "cdylib"]

[dependencies]
invisi-sdk-core = { path = "../invisi-sdk-core" }
hex = "0.4"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

- [ ] **Step 7: 修 ffi crate 的 import + 重导出 core**

`crates/invisi-sdk-ffi/src/lib.rs`：
1. 顶部把原来的 `use super::cipher::...` / `use super::derive::...` / `use super::pool::...` 改为从 core crate 引用：
   ```rust
   use invisi_sdk_core::cipher::{decrypt_for_db_raw, encrypt_for_db_raw};
   use invisi_sdk_core::derive::{identity_commitment, nullifier_key_raw, payment_commitment, payment_nullifier};
   use invisi_sdk_core::pool::generate_receiver_pool_raw;
   ```
   （core 的 crate 名为 `invisi_sdk_core`，由 package 名 `invisi-sdk-core` 自动转换，无需别名。）
2. 紧接着加一行重导出，保证下游 `use invisi_sdk::derive::...` 等仍可用（app 兼容）：
   ```rust
   pub use invisi_sdk_core::{cipher, derive, domain, error, field, pool, poseidon, poseidon_constants};
   ```
   ffi crate 的 lib 名是 `invisi_sdk`（Step 6），所以消费者 `use invisi_sdk::derive::compute_payment_commitment` 走的就是这个重导出。

- [ ] **Step 8: 构建并跑全部测试**

Run:
```bash
cargo build --workspace
cargo test --workspace
```
Expected: 编译通过；core 的 ~47 个测试 + ffi 的 9 个测试全 PASS（共 56）。若报缺依赖（如 ffi 缺 `hex`）按提示在对应 Cargo.toml 补齐。

- [ ] **Step 9: 验证 staticlib 产物名不变**

Run:
```bash
cargo build -p invisi-sdk-ffi --release
ls target/release/ | grep invisi_sdk
```
Expected: 存在 `libinvisi_sdk.a`（和/或 `.dylib`/`.so`）。

- [ ] **Step 10: Commit**

```bash
git add -A
git commit -m "refactor: 拆分为 workspace — invisi-sdk-core(rlib) + invisi-sdk-ffi(staticlib)"
```

---

### Task 2: 派生函数改名对齐 TS

把 core 的派生函数改成 `@invisi-labs/core` 同名（snake_case）。FFI 导出符号名不变。

**Files:**
- Modify: `crates/invisi-sdk-core/src/derive.rs`
- Modify: `crates/invisi-sdk-core/src/lib.rs`（doc）
- Modify: `crates/invisi-sdk-core/src/tests.rs`（测试里的调用）
- Modify: `crates/invisi-sdk-ffi/src/lib.rs`（内部调用 + import）

**Interfaces:**
- Produces: `derive::derive_nullifier_key` / `derive::compute_identity_commitment` / `derive::compute_payment_commitment` / `derive::compute_payment_nullifier`（签名同原函数，仅改名）。

- [ ] **Step 1: 改 derive.rs 函数名**

在 `crates/invisi-sdk-core/src/derive.rs` 重命名：
- `nullifier_key_raw` → `derive_nullifier_key`
- `identity_commitment` → `compute_identity_commitment`
- `payment_commitment` → `compute_payment_commitment`
- `payment_nullifier` → `compute_payment_nullifier`

（函数体、参数不变。同步更新文件顶部注释与 `pub fn` 行。）

- [ ] **Step 2: 更新所有调用点**

`crates/invisi-sdk-ffi/src/lib.rs` 的 `use invisi_sdk_core::derive::{...}` 与函数体调用、`crates/invisi-sdk-core/src/tests.rs` 中所有调用、`lib.rs` 模块文档列表，全部替换为新名。

- [ ] **Step 3: 跑测试**

Run: `cargo test --workspace`
Expected: 全 PASS（仅改名，行为不变）。

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "refactor: 派生函数改名对齐 @invisi-labs/core (compute_*/derive_nullifier_key)"
```

---

### Task 3: nonce 统一为 [u8;32] + 新增 generate_nonce

把 payment 派生的 nonce 从 `[u8;16]` 拓宽到 `[u8;32]`（TS nonce 是完整 field element，16 字节装不下），并导出随机 nonce 生成。

**Files:**
- Modify: `crates/invisi-sdk-core/src/derive.rs`
- Create: `crates/invisi-sdk-core/src/nonce.rs`
- Modify: `crates/invisi-sdk-core/src/lib.rs`（加 `pub mod nonce;`）
- Modify: `crates/invisi-sdk-core/src/tests.rs`（nonce 测试数据 16→32 字节）
- Modify: `crates/invisi-sdk-ffi/src/lib.rs`（nonce 读 `read_hex_fixed::<32>`）

**Interfaces:**
- Consumes: `field::bytes_to_field`、`field::field_to_bytes_be`、`FIELD_MODULUS`（reduce 用 ark-bn254 `Fr` 直接随机更稳）。
- Produces: `nonce::generate_nonce() -> [u8; 32]`；`compute_payment_commitment(chain_id, identity_commitment, token, amount, nonce: &[u8;32])`；`compute_payment_nullifier(nullifier_key, chain_id, token, amount, nonce: &[u8;32])`。

- [ ] **Step 1: 写 generate_nonce 失败测试**

`crates/invisi-sdk-core/src/tests.rs` 加：

```rust
#[test]
fn generate_nonce_in_field_and_random() {
    use crate::nonce::generate_nonce;
    use crate::field::bytes_to_field;
    let a = generate_nonce();
    let b = generate_nonce();
    assert_ne!(a, b, "两次随机 nonce 不应相同");
    // 落在 field 内：解码再编码应等幂（已 < p）
    let round = crate::field::field_to_bytes_be(bytes_to_field(&a));
    assert_eq!(round, a, "nonce 应已是 field 内规范 32 字节");
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test -p invisi-sdk-core generate_nonce_in_field_and_random`
Expected: FAIL（`nonce` 模块不存在）。

- [ ] **Step 3: 写 nonce.rs**

```rust
//! 随机 nonce 生成 — BN254 标量域内 32 字节 field element。
//! 对齐 invisi-sdk-ts `@invisi-labs/core` generateNonce。

use ark_bn254::Fr;
use ark_ff::UniformRand;
use rand::rngs::OsRng;

use crate::field::field_to_bytes_be;

/// 生成一个落在 BN254 标量域内的随机 nonce，返回规范 32 字节大端编码。
pub fn generate_nonce() -> [u8; 32] {
    let fr = Fr::rand(&mut OsRng);
    field_to_bytes_be(fr)
}
```

- [ ] **Step 4: 注册模块**

`crates/invisi-sdk-core/src/lib.rs` 加 `pub mod nonce;`。

- [ ] **Step 5: 跑测试确认通过**

Run: `cargo test -p invisi-sdk-core generate_nonce_in_field_and_random`
Expected: PASS。

- [ ] **Step 6: 拓宽 derive.rs 的 nonce 参数**

在 `crates/invisi-sdk-core/src/derive.rs`：
- `compute_payment_commitment` 的 `nonce: &[u8; 16]` → `nonce: &[u8; 32]`；函数体把 `let n = pad_to_32(nonce);` 改为 `let n = *nonce;`。
- `compute_payment_nullifier` 同样：`nonce: &[u8; 32]`，`let n = *nonce;`。

（注：原 16 字节零扩展到 32 字节的 field 值与直接 32 字节相同，故对 UUID 形 nonce 行为不变，只是现在能承载完整 field element。）

- [ ] **Step 7: 更新 core 测试中的 nonce 数据**

`crates/invisi-sdk-core/src/tests.rs` 中所有传给 `compute_payment_commitment` / `compute_payment_nullifier` 的 `nonce` 由 `[u8;16]` 改为 `[u8;32]`（左侧补零即可，如 `[0u8;32]` 或具体值扩到 32 字节）。

- [ ] **Step 8: 更新 ffi 的 nonce 解析**

`crates/invisi-sdk-ffi/src/lib.rs` 中 `privacy_compute_payment_commitment` 与 `privacy_compute_payment_nullifier` 里读 nonce 的 `read_hex_fixed::<16>(nonce_hex)` 改为 `read_hex_fixed::<32>(nonce_hex)`。同步更新对应 FFI 测试里 nonce 的 hex 串（32 字节 = 64 hex 字符）。

- [ ] **Step 9: 跑全部测试**

Run: `cargo test --workspace`
Expected: 全 PASS。

- [ ] **Step 10: Commit**

```bash
git add -A
git commit -m "feat(core): nonce 统一为 [u8;32] field element + generate_nonce 导出"
```

---

### Task 4: compute_change_commitment

新增找零承诺派生，对齐电路 `shielded_payment/main.nr:71-72`。

**Files:**
- Modify: `crates/invisi-sdk-core/src/derive.rs`
- Modify: `crates/invisi-sdk-core/src/tests.rs`

**Interfaces:**
- Consumes: `compute_identity_commitment`、`compute_payment_commitment`。
- Produces: `derive::compute_change_commitment(chain_id: u64, change_nullifier_key: &[u8;32], change_receiving_address: &[u8;20], token: &[u8;20], change_amount: &[u8;32], change_nonce: &[u8;32]) -> [u8;32]`。

- [ ] **Step 1: 写失败测试**

`crates/invisi-sdk-core/src/tests.rs` 加：

```rust
#[test]
fn change_commitment_equals_identity_then_payment() {
    use crate::derive::{compute_change_commitment, compute_identity_commitment, compute_payment_commitment};
    let change_nk = [7u8; 32];
    let change_addr = [9u8; 20];
    let token = [3u8; 20];
    let amount = [0u8; 32];
    let nonce = [5u8; 32];
    let chain_id = 84532u64;

    let rcv = compute_identity_commitment(&change_nk, &change_addr);
    let expected = compute_payment_commitment(chain_id, &rcv, &token, &amount, &nonce);
    let got = compute_change_commitment(chain_id, &change_nk, &change_addr, &token, &amount, &nonce);
    assert_eq!(got, expected);
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test -p invisi-sdk-core change_commitment_equals_identity_then_payment`
Expected: FAIL（函数不存在）。

- [ ] **Step 3: 实现 compute_change_commitment**

`crates/invisi-sdk-core/src/derive.rs` 末尾加：

```rust
/// changeCommitment（隐藏支付找零）。对齐电路 shielded_payment/main.nr:71-72：
///   change_rcv        = Poseidon2(D_IDENT, change_nullifier_key, change_receiving_address)
///   change_commitment = Poseidon2(D_PAY, chain_id, change_rcv, token, change_amount, change_nonce)
pub fn compute_change_commitment(
    chain_id: u64,
    change_nullifier_key: &[u8; 32],
    change_receiving_address: &[u8; 20],
    token: &[u8; 20],
    change_amount: &[u8; 32],
    change_nonce: &[u8; 32],
) -> [u8; 32] {
    let rcv = compute_identity_commitment(change_nullifier_key, change_receiving_address);
    compute_payment_commitment(chain_id, &rcv, token, change_amount, change_nonce)
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `cargo test -p invisi-sdk-core change_commitment_equals_identity_then_payment`
Expected: PASS。

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(core): compute_change_commitment 派生 (对齐 shielded_payment 电路)"
```

---

### Task 5: invisi-sdk-payer crate 骨架 + alloy

新建 payer crate，引入 alloy，建立空 lib + 一个 sol! 定义，确保编译。

**Files:**
- Create: `crates/invisi-sdk-payer/Cargo.toml`
- Create: `crates/invisi-sdk-payer/src/lib.rs`
- Modify: `Cargo.toml`（workspace members 加 payer）

**Interfaces:**
- Produces: crate `invisi-sdk-payer`，内部 `sol!` 定义合约接口。

- [ ] **Step 1: 加入 workspace members**

根 `Cargo.toml` 的 members 改为：
```toml
members = ["crates/invisi-sdk-core", "crates/invisi-sdk-ffi", "crates/invisi-sdk-payer"]
```

- [ ] **Step 2: 写 payer Cargo.toml**

```toml
[package]
name = "invisi-sdk-payer"
version = "0.1.0"
edition = "2021"
license = "Apache-2.0"
description = "InvisiPay payer-side calldata builders (ABI encoding via alloy)"

[dependencies]
alloy-primitives = "0.8"
alloy-sol-types = "0.8"
```

- [ ] **Step 3: 写 lib.rs 骨架 + sol! 定义**

```rust
//! payer 侧 calldata 构建 — 对齐 @invisi-labs/payer build*Calldata。
//! ABI 编码用 alloy（Rust 版 viem）。

use alloy_sol_types::sol;

sol! {
    function approve(address spender, uint256 amount);
    function payOpen(bytes32 identityCommitment, uint256 amount, bytes32 nonce, uint256 treeId, bytes32 refundLink);
    function payBlind(bytes proof, bytes32 paymentCommitment, bytes32 changeCommitment, uint256 inputAmount, uint256 treeId, bytes32 refundLink);
}
```

- [ ] **Step 4: 构建**

Run: `cargo build -p invisi-sdk-payer`
Expected: 编译通过（alloy 拉取成功）。

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(payer): 新建 invisi-sdk-payer crate + alloy sol! 合约定义"
```

---

### Task 6: build_approve_calldata

**Files:**
- Modify: `crates/invisi-sdk-payer/src/lib.rs`

**Interfaces:**
- Produces: `build_approve_calldata(spender: &[u8;20], amount: &[u8;32]) -> Vec<u8>`。

- [ ] **Step 1: 写失败测试（完整具体 golden）**

`crates/invisi-sdk-payer/src/lib.rs` 末尾加：

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approve_calldata_matches_known_vector() {
        // spender = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8, amount = 1000 (0x3e8)
        let spender = hex_lit::<20>("70997970c51812dc3a010c7d01b50e0d17dc79c8");
        let mut amount = [0u8; 32];
        amount[30] = 0x03; amount[31] = 0xe8;
        let got = build_approve_calldata(&spender, &amount);
        let expected = concat_hex(&[
            "095ea7b3",
            "00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8",
            "00000000000000000000000000000000000000000000000000000000000003e8",
        ]);
        assert_eq!(got, expected);
    }

    // test helpers
    fn hex_lit<const N: usize>(s: &str) -> [u8; N] {
        let v = decode_hex(s);
        let mut o = [0u8; N];
        o.copy_from_slice(&v);
        o
    }
    fn concat_hex(parts: &[&str]) -> Vec<u8> {
        parts.iter().flat_map(|p| decode_hex(p)).collect()
    }
    fn decode_hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap()).collect()
    }
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test -p invisi-sdk-payer approve_calldata_matches_known_vector`
Expected: FAIL（`build_approve_calldata` 不存在）。

- [ ] **Step 3: 实现**

`crates/invisi-sdk-payer/src/lib.rs`（`sol!` 块之后）加：

```rust
use alloy_primitives::{Address, U256, FixedBytes};
use alloy_sol_types::SolCall;

pub fn build_approve_calldata(spender: &[u8; 20], amount: &[u8; 32]) -> Vec<u8> {
    approveCall {
        spender: Address::from(*spender),
        amount: U256::from_be_bytes(*amount),
    }
    .abi_encode()
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `cargo test -p invisi-sdk-payer approve_calldata_matches_known_vector`
Expected: PASS。

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(payer): build_approve_calldata (字节级对齐已知向量)"
```

---

### Task 7: build_pay_open_calldata

**Files:**
- Modify: `crates/invisi-sdk-payer/src/lib.rs`

**Interfaces:**
- Produces: `build_pay_open_calldata(identity_commitment: &[u8;32], amount: &[u8;32], nonce: &[u8;32], tree_id: u64, refund_link: &[u8;32]) -> Vec<u8>`。

- [ ] **Step 1: 用 cast 生成 golden（前置）**

Run（需 foundry，`../invisi-protocol` 有）：
```bash
cast calldata "payOpen(bytes32,uint256,bytes32,uint256,bytes32)" \
  0x1111111111111111111111111111111111111111111111111111111111111111 \
  1000 \
  0x2222222222222222222222222222222222222222222222222222222222222222 \
  1 \
  0x0000000000000000000000000000000000000000000000000000000000000000
```
记下输出（去掉 `0x`）作为下一步的 `GOLDEN`。

- [ ] **Step 2: 写失败测试**

`tests` mod 内加（把上一步 `cast` 输出去掉 `0x` 粘到 `GOLDEN`）：

```rust
#[test]
fn pay_open_calldata_matches_cast() {
    let identity = [0x11u8; 32];
    let mut amount = [0u8; 32]; amount[30] = 0x03; amount[31] = 0xe8; // 1000
    let nonce = [0x22u8; 32];
    let refund = [0u8; 32];
    let got = build_pay_open_calldata(&identity, &amount, &nonce, 1, &refund);
    // GOLDEN = 上一步 cast 的确定性输出（去掉 0x）。decode_hex 是本 mod 内已定义的 helper（Task 6）。
    const GOLDEN: &str = "<paste-cast-output-without-0x>";
    assert_eq!(got, decode_hex(GOLDEN));
}
```

- [ ] **Step 3: 跑测试确认失败**

Run: `cargo test -p invisi-sdk-payer pay_open_calldata_matches_cast`
Expected: FAIL（函数不存在）。

- [ ] **Step 4: 实现**

```rust
pub fn build_pay_open_calldata(
    identity_commitment: &[u8; 32],
    amount: &[u8; 32],
    nonce: &[u8; 32],
    tree_id: u64,
    refund_link: &[u8; 32],
) -> Vec<u8> {
    payOpenCall {
        identityCommitment: FixedBytes::from(*identity_commitment),
        amount: U256::from_be_bytes(*amount),
        nonce: FixedBytes::from(*nonce),
        treeId: U256::from(tree_id),
        refundLink: FixedBytes::from(*refund_link),
    }
    .abi_encode()
}
```

- [ ] **Step 5: 跑测试确认通过**

Run: `cargo test -p invisi-sdk-payer pay_open_calldata_matches_cast`
Expected: PASS。

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(payer): build_pay_open_calldata (对账 foundry cast)"
```

---

### Task 8: build_pay_blind_calldata

**Files:**
- Modify: `crates/invisi-sdk-payer/src/lib.rs`

**Interfaces:**
- Produces: `build_pay_blind_calldata(proof: &[u8], payment_commitment: &[u8;32], change_commitment: &[u8;32], input_amount: &[u8;32], tree_id: u64, refund_link: &[u8;32]) -> Vec<u8>`。

- [ ] **Step 1: 用 cast 生成 golden（含动态 bytes proof）**

Run：
```bash
cast calldata "payBlind(bytes,bytes32,bytes32,uint256,uint256,bytes32)" \
  0xdeadbeef \
  0x3333333333333333333333333333333333333333333333333333333333333333 \
  0x4444444444444444444444444444444444444444444444444444444444444444 \
  2000 \
  1 \
  0x0000000000000000000000000000000000000000000000000000000000000000
```
记下输出去掉 `0x`。

- [ ] **Step 2: 写失败测试**

```rust
#[test]
fn pay_blind_calldata_matches_cast() {
    let proof = vec![0xde, 0xad, 0xbe, 0xef];
    let pc = [0x33u8; 32];
    let cc = [0x44u8; 32];
    let mut input = [0u8; 32]; input[30] = 0x07; input[31] = 0xd0; // 2000
    let refund = [0u8; 32];
    let got = build_pay_blind_calldata(&proof, &pc, &cc, &input, 1, &refund);
    // GOLDEN = 上一步 cast 的确定性输出（去掉 0x）。decode_hex 是本 mod 内已定义的 helper（Task 6）。
    const GOLDEN: &str = "<paste-cast-output-without-0x>";
    assert_eq!(got, decode_hex(GOLDEN));
}
```

- [ ] **Step 3: 跑测试确认失败**

Run: `cargo test -p invisi-sdk-payer pay_blind_calldata_matches_cast`
Expected: FAIL。

- [ ] **Step 4: 实现**

```rust
use alloy_primitives::Bytes;

pub fn build_pay_blind_calldata(
    proof: &[u8],
    payment_commitment: &[u8; 32],
    change_commitment: &[u8; 32],
    input_amount: &[u8; 32],
    tree_id: u64,
    refund_link: &[u8; 32],
) -> Vec<u8> {
    payBlindCall {
        proof: Bytes::copy_from_slice(proof),
        paymentCommitment: FixedBytes::from(*payment_commitment),
        changeCommitment: FixedBytes::from(*change_commitment),
        inputAmount: U256::from_be_bytes(*input_amount),
        treeId: U256::from(tree_id),
        refundLink: FixedBytes::from(*refund_link),
    }
    .abi_encode()
}
```

- [ ] **Step 5: 跑测试确认通过**

Run: `cargo test -p invisi-sdk-payer pay_blind_calldata_matches_cast`
Expected: PASS。

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(payer): build_pay_blind_calldata (动态 bytes proof, 对账 cast)"
```

---

### Task 9: FFI 导出 privacy_build_* calldata

ffi crate 加 payer 依赖，导出三个 calldata 构建的 C ABI。

**Files:**
- Modify: `crates/invisi-sdk-ffi/Cargo.toml`（加 payer 依赖）
- Modify: `crates/invisi-sdk-ffi/src/lib.rs`（加导出 + 测试）

**Interfaces:**
- Consumes: `invisi_sdk_payer::{build_approve_calldata, build_pay_open_calldata, build_pay_blind_calldata}`；ffi 内已有 `read_hex_fixed` / `read_u64` / `read_bytes_len` / `write_str` / `write_err`。
- Produces: `privacy_build_approve_calldata` / `privacy_build_pay_open_calldata` / `privacy_build_pay_blind_calldata`（hex 入、hex 出）。

- [ ] **Step 1: ffi Cargo.toml 加 payer 依赖**

```toml
invisi-sdk-payer = { path = "../invisi-sdk-payer" }
```
（crate 名自动为 `invisi_sdk_payer`，import 直接 `use invisi_sdk_payer::...`，无需别名。）

- [ ] **Step 2: 写 FFI 烟雾失败测试**

`crates/invisi-sdk-ffi/src/lib.rs` 的 `#[cfg(test)] mod tests` 加：

```rust
#[test]
fn ffi_build_approve_calldata_smoke() {
    let spender = std::ffi::CString::new("70997970c51812dc3a010c7d01b50e0d17dc79c8").unwrap();
    let amount = std::ffi::CString::new(format!("{:064x}", 1000u64)).unwrap();
    let mut out = [0u8; 512];
    let mut err = [0u8; 64];
    let ok = unsafe {
        super::privacy_build_approve_calldata(
            spender.as_ptr(), amount.as_ptr(),
            out.as_mut_ptr(), out.len(), err.as_mut_ptr(), err.len())
    };
    assert!(ok);
    let s = unsafe { std::ffi::CStr::from_ptr(out.as_ptr() as *const i8) }.to_str().unwrap();
    assert!(s.starts_with("095ea7b3"));
    assert_eq!(s.len(), 8 + 64 + 64);
}
```

- [ ] **Step 3: 跑测试确认失败**

Run: `cargo test -p invisi-sdk-ffi ffi_build_approve_calldata_smoke`
Expected: FAIL（函数不存在）。

- [ ] **Step 4: 实现三个导出**

`crates/invisi-sdk-ffi/src/lib.rs` 加：

```rust
use invisi_sdk_payer::{build_approve_calldata, build_pay_open_calldata, build_pay_blind_calldata};

#[no_mangle]
pub unsafe extern "C" fn privacy_build_approve_calldata(
    spender_hex: *const c_char,
    amount_hex: *const c_char,
    out_buf: *mut u8, out_cap: usize,
    err_buf: *mut u8, err_cap: usize,
) -> bool {
    let spender = match read_hex_fixed::<20>(spender_hex) {
        Some(v) => v, None => { write_err(err_buf, err_cap, "INPUT_INVALID"); return false; }
    };
    let amount = match read_hex_fixed::<32>(amount_hex) {
        Some(v) => v, None => { write_err(err_buf, err_cap, "INPUT_INVALID"); return false; }
    };
    let data = build_approve_calldata(&spender, &amount);
    if !write_str(out_buf, out_cap, &hex::encode(data)) {
        write_err(err_buf, err_cap, "BUFFER_TOO_SMALL"); return false;
    }
    true
}

#[no_mangle]
pub unsafe extern "C" fn privacy_build_pay_open_calldata(
    identity_hex: *const c_char,
    amount_hex: *const c_char,
    nonce_hex: *const c_char,
    tree_id_str: *const c_char,
    refund_link_hex: *const c_char,
    out_buf: *mut u8, out_cap: usize,
    err_buf: *mut u8, err_cap: usize,
) -> bool {
    let identity = match read_hex_fixed::<32>(identity_hex) { Some(v)=>v, None=>{write_err(err_buf,err_cap,"INPUT_INVALID");return false;} };
    let amount = match read_hex_fixed::<32>(amount_hex) { Some(v)=>v, None=>{write_err(err_buf,err_cap,"INPUT_INVALID");return false;} };
    let nonce = match read_hex_fixed::<32>(nonce_hex) { Some(v)=>v, None=>{write_err(err_buf,err_cap,"INPUT_INVALID");return false;} };
    let tree_id = match read_u64(tree_id_str) { Some(v)=>v, None=>{write_err(err_buf,err_cap,"INPUT_INVALID");return false;} };
    let refund = match read_hex_fixed::<32>(refund_link_hex) { Some(v)=>v, None=>{write_err(err_buf,err_cap,"INPUT_INVALID");return false;} };
    let data = build_pay_open_calldata(&identity, &amount, &nonce, tree_id, &refund);
    if !write_str(out_buf, out_cap, &hex::encode(data)) { write_err(err_buf,err_cap,"BUFFER_TOO_SMALL"); return false; }
    true
}

#[no_mangle]
pub unsafe extern "C" fn privacy_build_pay_blind_calldata(
    proof_hex: *const c_char,
    payment_commitment_hex: *const c_char,
    change_commitment_hex: *const c_char,
    input_amount_hex: *const c_char,
    tree_id_str: *const c_char,
    refund_link_hex: *const c_char,
    out_buf: *mut u8, out_cap: usize,
    err_buf: *mut u8, err_cap: usize,
) -> bool {
    let proof_s = if proof_hex.is_null() { write_err(err_buf,err_cap,"INPUT_INVALID"); return false; }
                  else { match CStr::from_ptr(proof_hex).to_str() { Ok(s)=>s, Err(_)=>{write_err(err_buf,err_cap,"INPUT_INVALID");return false;} } };
    let proof = match hex::decode(proof_s) { Ok(v)=>v, Err(_)=>{write_err(err_buf,err_cap,"INPUT_INVALID");return false;} };
    let pc = match read_hex_fixed::<32>(payment_commitment_hex) { Some(v)=>v, None=>{write_err(err_buf,err_cap,"INPUT_INVALID");return false;} };
    let cc = match read_hex_fixed::<32>(change_commitment_hex) { Some(v)=>v, None=>{write_err(err_buf,err_cap,"INPUT_INVALID");return false;} };
    let input_amount = match read_hex_fixed::<32>(input_amount_hex) { Some(v)=>v, None=>{write_err(err_buf,err_cap,"INPUT_INVALID");return false;} };
    let tree_id = match read_u64(tree_id_str) { Some(v)=>v, None=>{write_err(err_buf,err_cap,"INPUT_INVALID");return false;} };
    let refund = match read_hex_fixed::<32>(refund_link_hex) { Some(v)=>v, None=>{write_err(err_buf,err_cap,"INPUT_INVALID");return false;} };
    let data = build_pay_blind_calldata(&proof, &pc, &cc, &input_amount, tree_id, &refund);
    if !write_str(out_buf, out_cap, &hex::encode(data)) { write_err(err_buf,err_cap,"BUFFER_TOO_SMALL"); return false; }
    true
}
```

- [ ] **Step 5: 跑全部测试**

Run: `cargo test --workspace`
Expected: 全 PASS（含新 FFI 烟雾）。

- [ ] **Step 6: 验证 staticlib 含新符号**

Run:
```bash
cargo build -p invisi-sdk-ffi --release
nm -g target/release/libinvisi_sdk.a 2>/dev/null | grep privacy_build_pay_open_calldata
```
Expected: 找到符号 `_privacy_build_pay_open_calldata`（或同名）。

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat(ffi): 导出 privacy_build_{approve,pay_open,pay_blind}_calldata"
```

---

### Task 10: README + 迁移说明

更新文档反映新结构 + app 迁移指引。

**Files:**
- Modify: `README.md`
- Modify: `CLAUDE.md`（仓库定位/结构段）

**Interfaces:** 无代码接口。

- [ ] **Step 1: 更新 README crate 结构 + app 迁移**

在 `README.md` 加一节「workspace 结构」列出三 crate 职责，并写明 app 迁移：
```
../invisi-pay-app/apps/mobile/rust/Cargo.toml 改：
- invisi-sdk = { path = "../../../../invisi-sdk-rust" }
+ invisi-sdk-ffi = { package = "invisi-sdk-ffi", path = "../../../../invisi-sdk-rust/crates/invisi-sdk-ffi" }
（use invisi_sdk::... 与 libinvisi_sdk.a 链接不变）
```

- [ ] **Step 2: 更新 CLAUDE.md 结构表**

把 CLAUDE.md「关键设计」附近补充 workspace 三 crate 说明（core/payer/ffi）与 prover 子项目②占位。

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "docs: README/CLAUDE 更新 workspace 结构 + app 迁移指引"
```

---

## 完成标准

- `cargo build --workspace` + `cargo test --workspace` 全绿（原 56 测试 + 新增派生/calldata/FFI 测试）。
- `cargo build -p invisi-sdk-core --target wasm32-unknown-unknown` 通过（core 无 alloy，保持可 WASM；若环境无 wasm target 则跳过并记录）。
- `libinvisi_sdk.a` 含 `privacy_build_*` 符号。
- calldata builder 字节级对齐 foundry `cast`（Task 6/7/8 硬门）。

## 后续（不在本 plan）

- **nonce vs 合约重算一致性测试**（spec §8.3）：验证本地 `compute_payment_commitment` 与合约用同 nonce 重算的 paymentCommitment 一致，需要协议团队的合约/电路 fixture。当前与既有的 `#[ignore]` 协议向量同一阻塞（无 fixture），故延后；fixture 到位后与那批向量一起激活。本 plan 的 calldata 字节对齐（Task 6/7/8 对账 `cast`）已覆盖「nonce 在 calldata 中按 bytes32 正确编码」这一半。
- app 仓库 `../invisi-pay-app` 的 Cargo 依赖迁移（改依赖 `invisi-sdk-ffi`）+ PrivacyBridge 增加 `privacyBuild*Calldata` 映射。
- 子项目②：`invisi-sdk-prover` 选型 spike（独立 spec/plan）。
