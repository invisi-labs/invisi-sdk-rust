//! # invisi-sdk
//!
//! InvisiPay 协议层 Rust SDK — 密码学原语 + 派生函数 + AEAD 字段加密。
//!
//! 与同生态项目对称：
//! - `invisi-sdk-ts` (browser/node, @aztec/bb.js WASM)
//! - **本 crate** — iOS / Android RN / Desktop / CLI
//!
//! ## 模块结构
//!
//! - [`domain`] — 域分离常量
//! - [`poseidon`] — Aztec BN254 t=4 Poseidon2 sponge
//! - [`derive`] — derive_nullifier_key / compute_identity_commitment / compute_payment_commitment / compute_payment_nullifier
//! - [`pool`] — ReceiverCommitment 批生成
//! - [`cipher`] — XChaCha20Poly1305 AEAD 字段加密
//! - [`error`] — 统一错误类型
//!
//! ## 与 nexus / Noir 兼容性
//!
//! Poseidon2 实现与 `invisi-nexus/pkg/kms/poseidon2.go` + Noir 电路 + `@aztec/bb.js`
//! bit-perfect. 3 个 alignment vectors (`hash2(1,2)` / `hash4(1,2,3,4)` /
//! `hash2(0,0)`) 是硬门。
//!
//! ## 设计原则
//!
//! 1. **non-custodial**: 不持久化 masterKey，由调用方从 OS 安全存储读取后传入。
//! 2. **稳定错误码**: `Error::code()` 返回的 `&'static str` 是跨语言 FFI 契约。
//! 3. **nullifier ≠ 0 不变式**: 协议 1.3:17-23 — 强制断言。

pub mod cipher;
pub mod derive;
pub mod domain;
pub mod error;
pub mod field;
pub mod nonce;
pub mod pool;
pub mod poseidon;
pub mod poseidon_constants;

#[cfg(test)]
mod tests;
