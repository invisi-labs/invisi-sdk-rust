//! Shared raw commitment and nullifier derivation primitives.
//!
//! Callers supply raw key material; these functions do not access secure storage.
//! Native bridges obtain master keys from platform secure storage.
//!
//! Hash ordering follows the protocol commitment definitions.

use super::domain::{D_CHANGE_NKEY, D_IDENT, D_NKEY, D_NULL, D_PAY};
use super::error::{Error, Result};
use super::poseidon::h;

/// Right-align at most 32 bytes in a zero-padded field word.
/// A 16-byte input receives 16 leading zero bytes.
fn pad_to_32(input: &[u8]) -> [u8; 32] {
    assert!(input.len() <= 32, "pad_to_32 input must be ≤ 32 bytes");
    let mut out = [0u8; 32];
    out[32 - input.len()..].copy_from_slice(input);
    out
}

/// nullifierKey = Poseidon2(D_NKEY, masterKey, invoiceId_field).
///
/// The invoice identifier is encoded as a field word.
/// The caller supplies the master key from secure storage.
pub fn derive_nullifier_key(master_key: &[u8; 32], invoice_id: &[u8; 16]) -> [u8; 32] {
    let inv = pad_to_32(invoice_id);
    h(D_NKEY, &[master_key, &inv])
}

/// identityCommitment = Poseidon2(D_IDENT, nullifierKey, receivingAddress_field).
pub fn compute_identity_commitment(
    nullifier_key: &[u8; 32],
    receiving_address: &[u8; 20],
) -> [u8; 32] {
    let addr = pad_to_32(receiving_address);
    h(D_IDENT, &[nullifier_key, &addr])
}

/// Encode the chain ID as a right-aligned big-endian field word.
fn chain_id_to_field(chain_id: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&chain_id.to_be_bytes());
    out
}

/// paymentCommitment = Poseidon2(D_PAY, chainId, identityCommitment, token, amount, nonce).
///
/// Payers publish the nonce in the on-chain event so recipients can recompute it.
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
/// Zero is reserved for padding slots in settlement circuits.
/// A zero nullifier must therefore be rejected.
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

/// Shielded payment change commitment, matching the circuit hash ordering:
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

/// changeNullifierKey = Poseidon2(D_CHANGE_NKEY, masterKey, paymentCommitment).
///
/// Use the payment commitment as the change-key salt.
/// This permits deterministic reconstruction and reconciliation.
/// The change domain separates this key from invoice-derived keys.
/// The commitment is already a field word and needs no padding.
pub fn derive_change_nullifier_key(
    master_key: &[u8; 32],
    payment_commitment: &[u8; 32],
) -> [u8; 32] {
    h(D_CHANGE_NKEY, &[master_key, payment_commitment])
}
