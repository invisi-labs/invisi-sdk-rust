//! 派生函数: derive_nullifier_key / compute_identity_commitment / compute_payment_commitment / compute_payment_nullifier
//!
//! 所有函数都是 "raw" 形式 — 输入 master_key 等明文字节, 不与 Keychain 交互.
//! iOS/Android bridge 层负责从 Keychain/Keystore 读 masterKey 后传入.
//!
//! Tasks 5: derive_nullifier_key + compute_identity_commitment
//! Task 6: compute_payment_commitment + compute_payment_nullifier (含 ≠0 不变式)

use super::domain::{D_NKEY, D_IDENT, D_PAY, D_NULL};
use super::error::{Error, Result};
use super::poseidon::h;

/// 把 ≤32 字节的输入右对齐 (zero-pad) 成 32 字节 field element.
/// 例: [u8; 16] → [0; 16] ++ [u8; 16]
fn pad_to_32(input: &[u8]) -> [u8; 32] {
    assert!(input.len() <= 32, "pad_to_32 input must be ≤ 32 bytes");
    let mut out = [0u8; 32];
    out[32 - input.len()..].copy_from_slice(input);
    out
}

/// nullifierKey = Poseidon2(D_NKEY, masterKey, invoiceId_field).
///
/// 与 protocol-docs/01-protocol/1.2-commitment.md:26-46 的哈希链对齐.
/// 入参 master_key 由 bridge 层从 Keychain 读取后传入.
pub fn derive_nullifier_key(master_key: &[u8; 32], invoice_id: &[u8; 16]) -> [u8; 32] {
    let inv = pad_to_32(invoice_id);
    h(D_NKEY, &[master_key, &inv])
}

/// identityCommitment = Poseidon2(D_IDENT, nullifierKey, receivingAddress_field).
pub fn compute_identity_commitment(nullifier_key: &[u8; 32], receiving_address: &[u8; 20]) -> [u8; 32] {
    let addr = pad_to_32(receiving_address);
    h(D_IDENT, &[nullifier_key, &addr])
}

/// 把 u64 chain_id 编码成 32 字节 field (右对齐 big-endian).
fn chain_id_to_field(chain_id: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&chain_id.to_be_bytes());
    out
}

/// paymentCommitment = Poseidon2(D_PAY, chainId, identityCommitment, token, amount, nonce).
///
/// 协议 1.2-commitment.md:42 定义. 付款方算并写入链上事件; 收款方从事件里取 nonce 反推.
pub fn compute_payment_commitment(
    chain_id: u64,
    identity_commitment: &[u8; 32],
    token: &[u8; 20],
    amount: &[u8; 32],
    nonce: &[u8; 32],
) -> [u8; 32] {
    let chain = chain_id_to_field(chain_id);
    let tok = pad_to_32(token);
    let n = *nonce;
    h(D_PAY, &[&chain, identity_commitment, &tok, amount, &n])
}

/// paymentNullifier = Poseidon2(D_NULL, chainId, nullifierKey, token, amount, nonce).
///
/// 协议 1.3-nullifier.md:8-30. **不变式 (1.3:17-23): 输出 ≠ 0** — 零值是 batch_settle 电路
/// 里的 padding 槽位标记. 一旦碰撞出零, 协议视为 invoiceId 复用攻击, 必须立即报错.
pub fn compute_payment_nullifier(
    nullifier_key: &[u8; 32],
    chain_id: u64,
    token: &[u8; 20],
    amount: &[u8; 32],
    nonce: &[u8; 32],
) -> Result<[u8; 32]> {
    let chain = chain_id_to_field(chain_id);
    let tok = pad_to_32(token);
    let n = *nonce;
    let out = h(D_NULL, &[&chain, nullifier_key, &tok, amount, &n]);
    if out == [0u8; 32] {
        return Err(Error::NullifierIsZero);
    }
    Ok(out)
}

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
