//! Poseidon2 哈希包装.
//!
//! ⚠️ 当前为 **stub 实现** — 用 sha256 + domain prefix 替代真实 Poseidon2.
//! protocol team 发布 invisi_protocol crate 后, 此文件整体替换为:
//!   `pub fn h(domain: u64, inputs: &[&[u8; 32]]) -> [u8; 32] {
//!       invisi_protocol::poseidon2::hash_with_domain(domain, inputs)
//!   }`
//!
//! Stub 阶段域分离测试可通过, 但与协议 test vectors 输出不一致 — 那些测试在
//! tests.rs 中标 #[ignore], 等 crate 就绪后再 unignore.

use sha2::{Digest, Sha256};

/// Domain-separated hash. domain 前缀防止跨场景的哈希碰撞.
///
/// 编码: domain.to_be_bytes() || inputs[0] || inputs[1] || ... → sha256.
pub fn h(domain: u64, inputs: &[&[u8; 32]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain.to_be_bytes());
    for input in inputs {
        hasher.update(*input);
    }
    let out = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&out);
    result
}
