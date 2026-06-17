//! ReceiverCommitment 池批生成.
//!
//! 收款方为一个 invoice 生成一组随机 nonce + 同一 identity_commitment;
//! 付款方扫码时, 服务端从池子里分配一个 nonce, 付款方再用这个 nonce 算 paymentCommitment 上链.
//!
//! ⚠️ 池子数据格式 (nonce 列表 vs commitment 列表) 待与 protocol/nexus team 对齐.
//! 当前实现按 "nonce 列表 + 单 identity_commitment" 假设, 见 SPEC-009 §未决事项 #2.
//! 若协议要求池子里预算 paymentCommitment, 此模块需扩展.

use rand::RngCore;
use uuid::Uuid;

use super::derive::{derive_nullifier_key, compute_identity_commitment};
use super::error::{Error, Result};

/// 同 invoice / 同 receivingAddress 下的承诺池.
#[derive(Debug, Clone)]
pub struct ReceiverPool {
    /// uuid v4, 本地用作池子主键 (DB.commitment_pools.pool_id).
    pub pool_id: String,
    /// identityCommitment = Poseidon2(D_IDENT, nullifierKey, receivingAddress).
    /// 同一 (mk, invoice_id, addr) 永远派生相同 identity_commitment.
    pub identity_commitment: [u8; 32],
    /// count 个随机 16-byte nonce, 每个分配给一个潜在付款人.
    pub nonces: Vec<[u8; 16]>,
}

/// 批生成 count 个 nonce, count ∈ [1, 500].
///
/// SPEC-009a Task 7: 与 Keychain 解耦, master_key 由 bridge 层传入.
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

    // CSPRNG 生成 count 个独立 16-byte nonce.
    let mut nonces = Vec::with_capacity(count as usize);
    let mut rng = rand::thread_rng();
    for _ in 0..count {
        let mut n = [0u8; 16];
        rng.fill_bytes(&mut n);
        nonces.push(n);
    }

    Ok(ReceiverPool {
        pool_id: Uuid::new_v4().to_string(),
        identity_commitment: ident,
        nonces,
    })
}
