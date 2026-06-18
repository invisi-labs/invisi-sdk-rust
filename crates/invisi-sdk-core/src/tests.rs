#[test]
fn module_compiles() {
    // Sanity: privacy_payment module is reachable. Subsequent tasks add real tests.
    assert!(true);
}

use super::domain::*;

#[test]
fn domain_constants_match_protocol() {
    assert_eq!(D_NKEY,   1);
    assert_eq!(D_IDENT,  2);
    assert_eq!(D_PAY,    3);
    assert_eq!(D_NULL,   4);
    assert_eq!(D_DERIVE, 8);
}

use super::poseidon::*;

#[test]
fn poseidon_deterministic() {
    let a: [u8; 32] = [1; 32];
    let b: [u8; 32] = [2; 32];
    assert_eq!(h(D_NKEY, &[&a, &b]), h(D_NKEY, &[&a, &b]));
}

#[test]
fn poseidon_domain_separation() {
    let a: [u8; 32] = [1; 32];
    let b: [u8; 32] = [2; 32];
    assert_ne!(h(D_NKEY, &[&a, &b]), h(D_IDENT, &[&a, &b]));
}

#[test]
fn poseidon_input_order_matters() {
    let a: [u8; 32] = [1; 32];
    let b: [u8; 32] = [2; 32];
    assert_ne!(h(D_NKEY, &[&a, &b]), h(D_NKEY, &[&b, &a]));
}

#[test]
fn poseidon_output_size_32() {
    let h_out = h(D_NKEY, &[&[1u8; 32]]);
    assert_eq!(h_out.len(), 32);
}

#[test]
fn poseidon_empty_inputs_ok() {
    // Edge case: empty inputs should still produce a deterministic 32-byte output
    let h1 = h(D_NKEY, &[]);
    let h2 = h(D_NKEY, &[]);
    assert_eq!(h1, h2);
    assert_eq!(h1.len(), 32);
}

use super::derive::*;

#[test]
fn nullifier_key_deterministic() {
    let mk = [42u8; 32];
    let inv = [7u8; 16];
    assert_eq!(derive_nullifier_key(&mk, &inv), derive_nullifier_key(&mk, &inv));
}

#[test]
fn nullifier_key_varies_with_master() {
    let inv = [7u8; 16];
    let nk1 = derive_nullifier_key(&[1u8; 32], &inv);
    let nk2 = derive_nullifier_key(&[2u8; 32], &inv);
    assert_ne!(nk1, nk2);
}

#[test]
fn nullifier_key_varies_with_invoice() {
    let mk = [42u8; 32];
    let nk1 = derive_nullifier_key(&mk, &[1u8; 16]);
    let nk2 = derive_nullifier_key(&mk, &[2u8; 16]);
    assert_ne!(nk1, nk2);
}

#[test]
fn identity_commitment_deterministic() {
    let nk = [1u8; 32];
    let addr = [2u8; 20];
    assert_eq!(compute_identity_commitment(&nk, &addr), compute_identity_commitment(&nk, &addr));
}

#[test]
fn identity_commitment_varies_with_address() {
    let nk = [1u8; 32];
    let a1 = [1u8; 20];
    let a2 = [2u8; 20];
    assert_ne!(compute_identity_commitment(&nk, &a1), compute_identity_commitment(&nk, &a2));
}

#[test]
fn identity_commitment_varies_with_nk() {
    let addr = [1u8; 20];
    let i1 = compute_identity_commitment(&[1u8; 32], &addr);
    let i2 = compute_identity_commitment(&[2u8; 32], &addr);
    assert_ne!(i1, i2);
}

#[test]
fn payment_commitment_deterministic() {
    let id = [1u8; 32];
    let tok = [2u8; 20];
    let amt = [3u8; 32];
    let n = [4u8; 32];
    assert_eq!(
        compute_payment_commitment(1, &id, &tok, &amt, &n),
        compute_payment_commitment(1, &id, &tok, &amt, &n),
    );
}

#[test]
fn payment_commitment_varies_with_nonce() {
    let id = [1u8; 32];
    let tok = [2u8; 20];
    let amt = [3u8; 32];
    assert_ne!(
        compute_payment_commitment(1, &id, &tok, &amt, &[4u8; 32]),
        compute_payment_commitment(1, &id, &tok, &amt, &[5u8; 32]),
    );
}

#[test]
fn payment_commitment_varies_with_chain() {
    let id = [1u8; 32];
    let tok = [2u8; 20];
    let amt = [3u8; 32];
    let n = [4u8; 32];
    assert_ne!(
        compute_payment_commitment(1, &id, &tok, &amt, &n),
        compute_payment_commitment(2, &id, &tok, &amt, &n),
    );
}

#[test]
fn payment_nullifier_normal_input_nonzero() {
    let nk = [1u8; 32];
    let tok = [2u8; 20];
    let amt = [3u8; 32];
    let n = [4u8; 32];
    let r = compute_payment_nullifier(&nk, 1, &tok, &amt, &n).expect("non-zero");
    assert_ne!(r, [0u8; 32]);
}

#[test]
fn payment_nullifier_deterministic() {
    let nk = [1u8; 32];
    let tok = [2u8; 20];
    let amt = [3u8; 32];
    let n = [4u8; 32];
    let r1 = compute_payment_nullifier(&nk, 1, &tok, &amt, &n).unwrap();
    let r2 = compute_payment_nullifier(&nk, 1, &tok, &amt, &n).unwrap();
    assert_eq!(r1, r2);
}

#[test]
fn payment_nullifier_varies_with_nk() {
    let tok = [2u8; 20];
    let amt = [3u8; 32];
    let n = [4u8; 32];
    let r1 = compute_payment_nullifier(&[1u8; 32], 1, &tok, &amt, &n).unwrap();
    let r2 = compute_payment_nullifier(&[2u8; 32], 1, &tok, &amt, &n).unwrap();
    assert_ne!(r1, r2);
}

#[test]
fn change_commitment_equals_identity_then_payment() {
    use crate::derive::{compute_change_commitment, compute_identity_commitment, compute_payment_commitment};
    let change_nk = [7u8; 32];
    let change_addr = [9u8; 20];
    let token = [3u8; 20];
    let amount = [0u8; 32];
    let nonce = [5u8; 32];
    let chain_id = 84532u64;

    let rcv = compute_identity_commitment(&change_nk, &change_addr);
    let expected = compute_payment_commitment(chain_id, &rcv, &token, &amount, &nonce);
    let got = compute_change_commitment(chain_id, &change_nk, &change_addr, &token, &amount, &nonce);
    assert_eq!(got, expected);
}

use super::error::Error;

#[test]
fn error_codes_stable() {
    assert_eq!(Error::MasterKeyMissing("m1".into()).code(), "MASTERKEY_MISSING");
    assert_eq!(Error::NullifierIsZero.code(), "NULLIFIER_ZERO");
    assert_eq!(Error::PoolSizeOutOfRange.code(), "POOL_SIZE_OUT_OF_RANGE");
    assert_eq!(Error::EncryptFailed.code(), "ENCRYPT_FAILED");
    assert_eq!(Error::DecryptFailed.code(), "DECRYPT_FAILED");
    assert_eq!(Error::CiphertextMalformed.code(), "CIPHERTEXT_MALFORMED");
}

#[test]
fn error_display_includes_context() {
    let e = Error::MasterKeyMissing("mnemonic-id-1".into());
    assert!(format!("{}", e).contains("mnemonic-id-1"));
}

#[test]
fn generate_nonce_in_field_and_random() {
    use crate::nonce::generate_nonce;
    use crate::field::bytes_to_field;
    let a = generate_nonce();
    let b = generate_nonce();
    assert_ne!(a, b, "两次随机 nonce 不应相同");
    // 落在 field 内：解码再编码应等幂（已 < p）
    let round = crate::field::field_to_bytes_be(bytes_to_field(&a));
    assert_eq!(round, a, "nonce 应已是 field 内规范 32 字节");
}

use super::pool::*;

#[test]
fn pool_generate_basic() {
    let mk = [3u8; 32];
    let inv = [1u8; 16];
    let addr = [2u8; 20];
    let pool = generate_receiver_pool_raw(&mk, &inv, &addr, 5).unwrap();
    assert_eq!(pool.nonces.len(), 5);
    assert_eq!(pool.pool_id.len(), 36, "uuid v4 string is 36 chars");
    assert_eq!(pool.identity_commitment.len(), 32);
}

#[test]
fn pool_identity_commitment_deterministic_per_invoice() {
    let mk = [3u8; 32];
    let inv = [1u8; 16];
    let addr = [2u8; 20];
    let p1 = generate_receiver_pool_raw(&mk, &inv, &addr, 3).unwrap();
    let p2 = generate_receiver_pool_raw(&mk, &inv, &addr, 3).unwrap();
    // Identity commitment is fully derived from (mk, invoice_id, addr) — same across pools
    assert_eq!(p1.identity_commitment, p2.identity_commitment);
    // Nonces are random — should differ between pools
    assert_ne!(p1.nonces, p2.nonces);
    // pool_id is uuid v4 — should differ
    assert_ne!(p1.pool_id, p2.pool_id);
}

#[test]
fn pool_rejects_zero_count() {
    let r = generate_receiver_pool_raw(&[3u8; 32], &[1u8; 16], &[2u8; 20], 0);
    assert!(matches!(r, Err(Error::PoolSizeOutOfRange)));
}

#[test]
fn pool_rejects_oversized() {
    let r = generate_receiver_pool_raw(&[3u8; 32], &[1u8; 16], &[2u8; 20], 501);
    assert!(matches!(r, Err(Error::PoolSizeOutOfRange)));
}

#[test]
fn pool_accepts_max_size() {
    let r = generate_receiver_pool_raw(&[3u8; 32], &[1u8; 16], &[2u8; 20], 500).unwrap();
    assert_eq!(r.nonces.len(), 500);
}

#[test]
fn pool_nonces_unique() {
    let pool = generate_receiver_pool_raw(&[3u8; 32], &[1u8; 16], &[2u8; 20], 100).unwrap();
    let set: std::collections::HashSet<_> = pool.nonces.iter().collect();
    assert_eq!(set.len(), 100, "all 100 nonces should be unique");
}

use super::cipher::*;

#[test]
fn cipher_roundtrip_basic() {
    let key = [1u8; 32];
    let pt = b"hello, privacy world";
    let ct = encrypt_with_key(&key, pt).unwrap();
    let recovered = decrypt_with_key(&key, &ct).unwrap();
    assert_eq!(recovered, pt);
}

#[test]
fn cipher_roundtrip_empty() {
    let key = [1u8; 32];
    let ct = encrypt_with_key(&key, b"").unwrap();
    assert_eq!(decrypt_with_key(&key, &ct).unwrap(), b"");
}

#[test]
fn cipher_roundtrip_1kb() {
    let key = [1u8; 32];
    let pt = vec![0x42u8; 1024];
    let ct = encrypt_with_key(&key, &pt).unwrap();
    assert_eq!(decrypt_with_key(&key, &ct).unwrap(), pt);
}

#[test]
fn cipher_wrong_key_fails() {
    let ct = encrypt_with_key(&[1u8; 32], b"secret").unwrap();
    let r = decrypt_with_key(&[2u8; 32], &ct);
    assert!(matches!(r, Err(Error::DecryptFailed)));
}

#[test]
fn cipher_tampered_tag_fails() {
    let key = [1u8; 32];
    let mut ct = encrypt_with_key(&key, b"secret").unwrap();
    let last = ct.len() - 1;
    ct[last] ^= 0xff;
    assert!(matches!(decrypt_with_key(&key, &ct), Err(Error::DecryptFailed)));
}

#[test]
fn cipher_short_input_rejected() {
    let key = [1u8; 32];
    // 39 bytes < 24 (nonce) + 16 (tag) — malformed
    let too_short = vec![0u8; 39];
    assert!(matches!(decrypt_with_key(&key, &too_short), Err(Error::CiphertextMalformed)));
}

#[test]
fn cipher_nonce_randomized() {
    // Two encryptions of same plaintext should yield different ciphertexts
    let key = [1u8; 32];
    let c1 = encrypt_with_key(&key, b"same").unwrap();
    let c2 = encrypt_with_key(&key, b"same").unwrap();
    assert_ne!(c1, c2, "AEAD nonce must be fresh per call");
}

#[test]
fn db_enc_key_deterministic_per_master() {
    let mk = [42u8; 32];
    assert_eq!(db_enc_key_from_master(&mk), db_enc_key_from_master(&mk));
}

#[test]
fn db_enc_key_isolated_from_payment_keys() {
    // Sanity: D_DERIVE key for db != D_NKEY for nullifier
    use super::derive::derive_nullifier_key;
    let mk = [42u8; 32];
    let inv = [1u8; 16];
    let db_key = db_enc_key_from_master(&mk);
    let nk = derive_nullifier_key(&mk, &inv);
    assert_ne!(db_key, nk, "domain separation must isolate D_DERIVE from D_NKEY");
}

#[test]
fn for_db_raw_roundtrip() {
    let mk = [7u8; 32];
    let ct = encrypt_for_db_raw(&mk, b"sensitive").unwrap();
    let pt = decrypt_for_db_raw(&mk, &ct).unwrap();
    assert_eq!(pt, b"sensitive");
}

#[test]
fn for_db_raw_isolation_across_masters() {
    let ct = encrypt_for_db_raw(&[1u8; 32], b"alice secret").unwrap();
    // Bob (different masterKey) cannot decrypt Alice's data
    let r = decrypt_for_db_raw(&[2u8; 32], &ct);
    assert!(matches!(r, Err(Error::DecryptFailed)));
}

// ==================== Protocol Test Vectors ====================
//
// These tests verify our hash derivations match the canonical values published by
// the protocol team (see ../protocol-docs/01-protocol/1.2-commitment.md). All four
// are #[ignore]'d until the protocol team publishes a fixture file (TBD path,
// likely the invisi-protocol crate's `tests/` directory or a separate
// "vectors" repo). Poseidon2 itself is already real (Aztec BN254 t=4) and
// passes the 3 inline alignment vectors at the top of this file.
//
// To activate:
//   - Replace the `unimplemented!()` calls with `hex!("...")` literals from the
//     fixture file (add `hex-literal = "0.4"` to dev-dependencies).
//   - Remove `#[ignore]` from each test.
//   - Run `cargo test protocol_vector_` to verify.
//
// If any vector fails, the bug is either (a) wrong byte ordering in our derive
// helpers, (b) wrong field encoding (we use right-aligned zero-pad), or (c) Poseidon2
// parameter mismatch. Bisect by re-running each individually.

#[test]
#[ignore = "awaiting real Poseidon2 + protocol vectors fixture"]
fn protocol_vector_nullifier_key() {
    let master_key: [u8; 32] = unimplemented!("vector: master_key");
    let invoice_id: [u8; 16] = unimplemented!("vector: invoice_id");
    let expected: [u8; 32] = unimplemented!("vector: expected nullifier_key");
    assert_eq!(super::derive::derive_nullifier_key(&master_key, &invoice_id), expected);
}

#[test]
#[ignore = "awaiting real Poseidon2 + protocol vectors fixture"]
fn protocol_vector_identity_commitment() {
    let nullifier_key: [u8; 32] = unimplemented!("vector: nullifier_key");
    let receiving_address: [u8; 20] = unimplemented!("vector: receiving_address");
    let expected: [u8; 32] = unimplemented!("vector: expected identity_commitment");
    assert_eq!(super::derive::compute_identity_commitment(&nullifier_key, &receiving_address), expected);
}

#[test]
#[ignore = "awaiting real Poseidon2 + protocol vectors fixture"]
fn protocol_vector_payment_commitment() {
    let chain_id: u64 = unimplemented!("vector: chain_id");
    let identity_commitment: [u8; 32] = unimplemented!("vector: identity_commitment");
    let token: [u8; 20] = unimplemented!("vector: token");
    let amount: [u8; 32] = unimplemented!("vector: amount");
    let nonce: [u8; 32] = unimplemented!("vector: nonce");
    let expected: [u8; 32] = unimplemented!("vector: expected payment_commitment");
    assert_eq!(
        super::derive::compute_payment_commitment(chain_id, &identity_commitment, &token, &amount, &nonce),
        expected
    );
}

#[test]
#[ignore = "awaiting real Poseidon2 + protocol vectors fixture"]
fn protocol_vector_payment_nullifier() {
    let nullifier_key: [u8; 32] = unimplemented!("vector: nullifier_key");
    let chain_id: u64 = unimplemented!("vector: chain_id");
    let token: [u8; 20] = unimplemented!("vector: token");
    let amount: [u8; 32] = unimplemented!("vector: amount");
    let nonce: [u8; 32] = unimplemented!("vector: nonce");
    let expected: [u8; 32] = unimplemented!("vector: expected payment_nullifier");
    assert_eq!(
        super::derive::compute_payment_nullifier(&nullifier_key, chain_id, &token, &amount, &nonce).unwrap(),
        expected
    );
}

// ==================== Nexus alignment vectors (HARD GATE) ====================
//
// 取自 invisi-nexus/pkg/kms/poseidon2_test.go (lines 11-37).
// 三个 vector 与 Noir 电路 + @aztec/bb.js 对账过 — 任何一个不通过都意味本仓
// Poseidon2 实现与协议不兼容, 必须立即修. 不要在没改 poseidon.rs 的情况下
// 修改这些 expected 值.

use ark_bn254::Fr;
use super::poseidon::hash as raw_hash;

fn fr_from_hex(s: &str) -> Fr {
    use ark_ff::PrimeField;
    let bytes = hex::decode(s).expect("hex");
    Fr::from_be_bytes_mod_order(&bytes)
}

#[test]
fn nexus_vector_hash2_one_two() {
    let inputs = [Fr::from(1u64), Fr::from(2u64)];
    let got = raw_hash(&inputs);
    let want = fr_from_hex("038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383");
    assert_eq!(got, want, "hash(1,2) MUST match Aztec Poseidon2 / Noir circuit / bb.js");
}

#[test]
fn nexus_vector_hash4_one_two_three_four() {
    let inputs = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
    let got = raw_hash(&inputs);
    let want = fr_from_hex("130bf204a32cac1f0ace56c78b731aa3809f06df2731ebcf6b3464a15788b1b9");
    assert_eq!(got, want, "hash(1,2,3,4) MUST match Aztec Poseidon2");
}

#[test]
fn nexus_vector_hash2_zero_zero() {
    let inputs = [Fr::from(0u64), Fr::from(0u64)];
    let got = raw_hash(&inputs);
    let want = fr_from_hex("0b63a53787021a4a962a452c2921b3663aff1ffd8d5510540f8e659e782956f1");
    assert_eq!(got, want, "hash(0,0) MUST match Aztec Poseidon2 (zero-zero edge case)");
}
