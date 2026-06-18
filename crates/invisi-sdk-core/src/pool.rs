//! ReceiverCommitment 池批生成.
//!
//! 收款方为一个 invoice 生成一组随机 nonce + 同一 identity_commitment;
//! 付款方扫码时, 服务端从池子里分配一个 nonce, 付款方再用这个 nonce 算 paymentCommitment 上链.
//!
//! ⚠️ 池子数据格式 (nonce 列表 vs commitment 列表) 待与 protocol/nexus team 对齐.
//! 当前实现按 "nonce 列表 + 单 identity_commitment" 假设, 见 SPEC-009 §未决事项 #2.
//! 若协议要求池子里预算 paymentCommitment, 此模块需扩展.

use uuid::Uuid;

use super::derive::{derive_nullifier_key, compute_identity_commitment};
use super::error::{Error, Result};
use super::nonce::generate_nonce;

/// 同 invoice / 同 receivingAddress 下的承诺池.
#[derive(Debug, Clone)]
pub struct ReceiverPool {
    /// uuid v4, 本地用作池子主键 (DB.commitment_pools.pool_id).
    pub pool_id: String,
    /// identityCommitment = Poseidon2(D_IDENT, nullifierKey, receivingAddress).
    /// 同一 (mk, invoice_id, addr) 永远派生相同 identity_commitment.
    pub identity_commitment: [u8; 32],
    /// count 个 BN254 field-element nonce (规范 32-byte 大端编码), 每个分配给一个潜在付款人.
    /// 与 `derive::compute_payment_commitment` / payer `payOpen` 链上 bytes32 接口一致.
    pub nonces: Vec<[u8; 32]>,
}

/// 批生成 count 个 nonce, count ∈ [1, 500].
///
/// 使用 [`generate_nonce`] (OsRng + BN254 field 内均匀采样), 与单个付款方 nonce 生成
/// 用同一原语 — receiver pool 里抽出的 nonce 可直接喂给 `compute_payment_commitment`,
/// 不需要 pad / 截断 / 编码转换.
pub fn generate_receiver_pool_raw(
    master_key: &[u8; 32],
    invoice_id: &[u8; 16],
    receiving_address: &[u8; 20],
    count: u32,
) -> Result<ReceiverPool> {
    if count == 0 || count > 500 {
        return Err(Error::PoolSizeOutOfRange);
    }

    // 派生 identity_commitment (永远相同 per (mk, inv, addr)).
    let nk = derive_nullifier_key(master_key, invoice_id);
    let ident = compute_identity_commitment(&nk, receiving_address);

    // BN254 field-element nonce, OsRng-backed.
    let mut nonces = Vec::with_capacity(count as usize);
    for _ in 0..count {
        nonces.push(generate_nonce());
    }

    Ok(ReceiverPool {
        pool_id: Uuid::new_v4().to_string(),
        identity_commitment: ident,
        nonces,
    })
}
