//! 字段级 AEAD 加密.
//!
//! 用途:
//!   1. SQLite 行的敏感字段 (_enc 后缀) 在落库前加密, 解密在读取时 — 防止 root 设备
//!      或越狱后直接读 DB 拿明文.
//!   2. 与 SPEC-007 云备份加密用同一 XChaCha20Poly1305 原语, 但 key 派生不同
//!      (db: D_DERIVE+"db-enc"; cloud: 用户云备份密码经 Argon2 派生).
//!
//! 加密格式 (40 字节起步):
//!   ciphertext = nonce(24) || encrypted_payload || tag(16)
//!
//! Stub 阶段 Poseidon2 用 sha256, 因此 db_enc_key 输出位级不与协议未来值一致,
//! 但语义 (域分离 + 确定性 + 与 nullifier_key 隔离) 完全正确.

use chacha20poly1305::{XChaCha20Poly1305, KeyInit, AeadCore, aead::{Aead, OsRng}};

use super::domain::D_DERIVE;
use super::poseidon::h;
use super::error::{Error, Result};

const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const MIN_CT_LEN: usize = NONCE_LEN + TAG_LEN;

/// 用 D_DERIVE 域 + 固定 label "db-enc" 派生 SQLite 字段加密密钥.
///
/// 域分离常量 D_DERIVE=8 让 db_enc_key 与 nullifier_key (D_NKEY=1) 等支付域完全
/// 隔离 — 即使 masterKey 被泄漏, 攻击者无法从 db_enc_key 反推出 nullifier_key.
pub fn db_enc_key_from_master(master_key: &[u8; 32]) -> [u8; 32] {
    let mut label = [0u8; 32];
    let l = b"db-enc";
    label[..l.len()].copy_from_slice(l);
    h(D_DERIVE, &[master_key, &label])
}

/// XChaCha20Poly1305 AEAD 加密. 随机生成 24-byte nonce, prepend 到 ciphertext.
pub fn encrypt_with_key(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let mut ct = cipher.encrypt(&nonce, plaintext).map_err(|_| Error::EncryptFailed)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.append(&mut ct);
    Ok(out)
}

/// 验证 AEAD tag + 解密. 输入必须包含 nonce + ciphertext + tag.
pub fn decrypt_with_key(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < MIN_CT_LEN {
        return Err(Error::CiphertextMalformed);
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher.decrypt(nonce.into(), ct).map_err(|_| Error::DecryptFailed)
}

/// 一站式: masterKey → db_enc_key → encrypt. Bridge 层使用.
pub fn encrypt_for_db_raw(master_key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let key = db_enc_key_from_master(master_key);
    encrypt_with_key(&key, plaintext)
}

/// 一站式: masterKey → db_enc_key → decrypt. Bridge 层使用.
pub fn decrypt_for_db_raw(master_key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>> {
    let key = db_enc_key_from_master(master_key);
    decrypt_with_key(&key, blob)
}
