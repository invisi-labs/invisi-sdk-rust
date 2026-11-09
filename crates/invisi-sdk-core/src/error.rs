//! Stable error codes for the existing primitive and database APIs.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("masterkey not found for mnemonic {0}")]
    MasterKeyMissing(String),

    #[error("nullifier collision (zero); invoiceId reuse detected")]
    NullifierIsZero,

    #[error("pool size out of range (1..=500)")]
    PoolSizeOutOfRange,

    #[error("encryption failed")]
    EncryptFailed,

    #[error("decryption failed (tampered or wrong key)")]
    DecryptFailed,

    #[error("ciphertext malformed")]
    CiphertextMalformed,
}

impl Error {
    /// Stable machine-readable error code shared with native bridges.
    pub fn code(&self) -> &'static str {
        match self {
            Self::MasterKeyMissing(_) => "MASTERKEY_MISSING",
            Self::NullifierIsZero => "NULLIFIER_ZERO",
            Self::PoolSizeOutOfRange => "POOL_SIZE_OUT_OF_RANGE",
            Self::EncryptFailed => "ENCRYPT_FAILED",
            Self::DecryptFailed => "DECRYPT_FAILED",
            Self::CiphertextMalformed => "CIPHERTEXT_MALFORMED",
        }
    }
}

/// Result type for primitive operations.
pub type Result<T> = std::result::Result<T, Error>;
