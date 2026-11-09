//! Invoice receiver pools with canonical BN254 field nonces.

use uuid::Uuid;

use super::derive::{compute_identity_commitment, derive_nullifier_key};
use super::error::{Error, Result};
use super::nonce::generate_nonce;

/// Nonce pool bound to one invoice and receiving address.
#[derive(Debug, Clone)]
pub struct ReceiverPool {
    /// Local UUIDv4 pool identifier.
    pub pool_id: String,
    /// identityCommitment = Poseidon2(D_IDENT, nullifierKey, receivingAddress).
    /// Deterministic for the same master key, invoice and recipient.
    pub identity_commitment: [u8; 32],
    /// Canonical 32-byte BN254 scalar-field nonces, one per prospective payer.
    /// Compatible with compute_payment_commitment and on-chain bytes32 inputs.
    pub nonces: Vec<[u8; 32]>,
}

/// Generate between 1 and 500 nonces.
///
/// Uses the same uniform OsRng-backed scalar sampling as individual payment nonces.
/// Pool nonces can be passed directly to compute_payment_commitment.
/// No padding, truncation or encoding conversion is required.
pub fn generate_receiver_pool_raw(
    master_key: &[u8; 32],
    invoice_id: &[u8; 16],
    receiving_address: &[u8; 20],
    count: u32,
) -> Result<ReceiverPool> {
    if count == 0 || count > 500 {
        return Err(Error::PoolSizeOutOfRange);
    }

    // The identity is shared by every nonce in this pool.
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
