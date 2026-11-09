//! Local database encryption: nonce(24) || XChaCha20Poly1305 ciphertext || tag(16).
//! This storage format is independent of protocol delivery envelopes.

use chacha20poly1305::{
    aead::{Aead, OsRng},
    AeadCore, KeyInit, XChaCha20Poly1305,
};

use super::domain::D_DERIVE;
use super::error::{Error, Result};
use super::poseidon::h;

const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const MIN_CT_LEN: usize = NONCE_LEN + TAG_LEN;

/// Derive the database key using the fixed database domain and label.
///
pub fn db_enc_key_from_master(master_key: &[u8; 32]) -> [u8; 32] {
    let mut label = [0u8; 32];
    let l = b"db-enc";
    label[..l.len()].copy_from_slice(l);
    h(D_DERIVE, &[master_key, &label])
}

/// Encrypt with a fresh 24-byte nonce prepended to the authenticated ciphertext.
pub fn encrypt_with_key(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let mut ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| Error::EncryptFailed)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.append(&mut ct);
    Ok(out)
}

/// Authenticate and decrypt a nonce-prefixed ciphertext.
pub fn decrypt_with_key(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < MIN_CT_LEN {
        return Err(Error::CiphertextMalformed);
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(nonce.into(), ct)
        .map_err(|_| Error::DecryptFailed)
}

/// Derive the database key and encrypt a record.
pub fn encrypt_for_db_raw(master_key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let key = db_enc_key_from_master(master_key);
    encrypt_with_key(&key, plaintext)
}

/// Derive the database key and decrypt a record.
pub fn decrypt_for_db_raw(master_key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>> {
    let key = db_enc_key_from_master(master_key);
    decrypt_with_key(&key, blob)
}
