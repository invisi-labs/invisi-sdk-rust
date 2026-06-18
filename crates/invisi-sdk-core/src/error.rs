//! 统一错误类型 + 稳定字符串错误码.
//!
//! 错误码 (Error::code()) 是 Bridge 层透传给 JS/iOS/Android 的稳定字符串契约.
//! 修改任何 code() 返回值都是 breaking change.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// NOTE: SDK 内部从不直接产生此变体 — masterKey 由 bridge 层从 Keychain/Keystore
    /// 读取后传入, 缺失时 bridge 层直接 reject Promise with code MASTERKEY_MISSING.
    /// 此变体保留为跨平台错误码契约的一部分 (`code()` 返回 "MASTERKEY_MISSING"),
    /// 让 SDK / Rust bridge / Swift / Kotlin 共享同一字符串.
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
    /// 稳定错误码, 透传给上层 (JS/iOS/Android). 不可改.
    pub fn code(&self) -> &'static str {
        match self {
            Self::MasterKeyMissing(_)   => "MASTERKEY_MISSING",
            Self::NullifierIsZero       => "NULLIFIER_ZERO",
            Self::PoolSizeOutOfRange    => "POOL_SIZE_OUT_OF_RANGE",
            Self::EncryptFailed         => "ENCRYPT_FAILED",
            Self::DecryptFailed         => "DECRYPT_FAILED",
            Self::CiphertextMalformed   => "CIPHERTEXT_MALFORMED",
        }
    }
}

/// 隐私支付模块统一的 Result 别名.
pub type Result<T> = std::result::Result<T, Error>;
