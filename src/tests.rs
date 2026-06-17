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
    assert_eq!(nullifier_key_raw(&mk, &inv), nullifier_key_raw(&mk, &inv));
}

#[test]
fn nullifier_key_varies_with_master() {
    let inv = [7u8; 16];
    let nk1 = nullifier_key_raw(&[1u8; 32], &inv);
    let nk2 = nullifier_key_raw(&[2u8; 32], &inv);
    assert_ne!(nk1, nk2);
}

#[test]
fn nullifier_key_varies_with_invoice() {
    let mk = [42u8; 32];
    let nk1 = nullifier_key_raw(&mk, &[1u8; 16]);
    let nk2 = nullifier_key_raw(&mk, &[2u8; 16]);
    assert_ne!(nk1, nk2);
}

#[test]
fn identity_commitment_deterministic() {
    let nk = [1u8; 32];
    let addr = [2u8; 20];
    assert_eq!(identity_commitment(&nk, &addr), identity_commitment(&nk, &addr));
}

#[test]
fn identity_commitment_varies_with_address() {
    let nk = [1u8; 32];
    let a1 = [1u8; 20];
    let a2 = [2u8; 20];
    assert_ne!(identity_commitment(&nk, &a1), identity_commitment(&nk, &a2));
}

#[test]
fn identity_commitment_varies_with_nk() {
    let addr = [1u8; 20];
    let i1 = identity_commitment(&[1u8; 32], &addr);
    let i2 = identity_commitment(&[2u8; 32], &addr);
    assert_ne!(i1, i2);
}

#[test]
fn payment_commitment_deterministic() {
    let id = [1u8; 32];
    let tok = [2u8; 20];
    let amt = [3u8; 32];
    let n = [4u8; 16];
    assert_eq!(
        payment_commitment(1, &id, &tok, &amt, &n),
        payment_commitment(1, &id, &tok, &amt, &n),
    );
}

#[test]
fn payment_commitment_varies_with_nonce() {
    let id = [1u8; 32];
    let tok = [2u8; 20];
    let amt = [3u8; 32];
    assert_ne!(
        payment_commitment(1, &id, &tok, &amt, &[4u8; 16]),
        payment_commitment(1, &id, &tok, &amt, &[5u8; 16]),
    );
}

#[test]
fn payment_commitment_varies_with_chain() {
    let id = [1u8; 32];
    let tok = [2u8; 20];
    let amt = [3u8; 32];
    let n = [4u8; 16];
    assert_ne!(
        payment_commitment(1, &id, &tok, &amt, &n),
        payment_commitment(2, &id, &tok, &amt, &n),
    );
}

#[test]
fn payment_nullifier_normal_input_nonzero() {
    let nk = [1u8; 32];
    let tok = [2u8; 20];
    let amt = [3u8; 32];
    let n = [4u8; 16];
    let r = payment_nullifier(&nk, 1, &tok, &amt, &n).expect("non-zero");
    assert_ne!(r, [0u8; 32]);
}

#[test]
fn payment_nullifier_deterministic() {
    let nk = [1u8; 32];
    let tok = [2u8; 20];
    let amt = [3u8; 32];
    let n = [4u8; 16];
    let r1 = payment_nullifier(&nk, 1, &tok, &amt, &n).unwrap();
    let r2 = payment_nullifier(&nk, 1, &tok, &amt, &n).unwrap();
    assert_eq!(r1, r2);
}

#[test]
fn payment_nullifier_varies_with_nk() {
    let tok = [2u8; 20];
    let amt = [3u8; 32];
    let n = [4u8; 16];
    let r1 = payment_nullifier(&[1u8; 32], 1, &tok, &amt, &n).unwrap();
    let r2 = payment_nullifier(&[2u8; 32], 1, &tok, &amt, &n).unwrap();
    assert_ne!(r1, r2);
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
    use super::derive::nullifier_key_raw;
    let mk = [42u8; 32];
    let inv = [1u8; 16];
    let db_key = db_enc_key_from_master(&mk);
    let nk = nullifier_key_raw(&mk, &inv);
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
// are #[ignore]'d until both prerequisites are met:
//
//   1. apps/mobile/rust/src/privacy_payment/poseidon.rs replaces the sha256 stub
//      with the real invisi_protocol::poseidon2 implementation.
//   2. Protocol team publishes a fixture file (TBD path, likely in invisi_protocol
//      crate's tests/ directory or a separate "vectors" repo).
//
// To activate:
//   - Replace the `unimplemented!()` calls with `hex!("...")` literals from the
//     fixture file (add `hex-literal = "0.4"` to dev-dependencies).
//   - Remove `#[ignore]` from each test.
//   - Run `cargo test --lib privacy_payment::tests::protocol_vector_` to verify.
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
    assert_eq!(super::derive::nullifier_key_raw(&master_key, &invoice_id), expected);
}

#[test]
#[ignore = "awaiting real Poseidon2 + protocol vectors fixture"]
fn protocol_vector_identity_commitment() {
    let nullifier_key: [u8; 32] = unimplemented!("vector: nullifier_key");
    let receiving_address: [u8; 20] = unimplemented!("vector: receiving_address");
    let expected: [u8; 32] = unimplemented!("vector: expected identity_commitment");
    assert_eq!(super::derive::identity_commitment(&nullifier_key, &receiving_address), expected);
}

#[test]
#[ignore = "awaiting real Poseidon2 + protocol vectors fixture"]
fn protocol_vector_payment_commitment() {
    let chain_id: u64 = unimplemented!("vector: chain_id");
    let identity_commitment: [u8; 32] = unimplemented!("vector: identity_commitment");
    let token: [u8; 20] = unimplemented!("vector: token");
    let amount: [u8; 32] = unimplemented!("vector: amount");
    let nonce: [u8; 16] = unimplemented!("vector: nonce");
    let expected: [u8; 32] = unimplemented!("vector: expected payment_commitment");
    assert_eq!(
        super::derive::payment_commitment(chain_id, &identity_commitment, &token, &amount, &nonce),
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
    let nonce: [u8; 16] = unimplemented!("vector: nonce");
    let expected: [u8; 32] = unimplemented!("vector: expected payment_nullifier");
    assert_eq!(
        super::derive::payment_nullifier(&nullifier_key, chain_id, &token, &amount, &nonce).unwrap(),
        expected
    );
}

// ==================== FFI smoke tests ====================
//
// Verify the C ABI exports work end-to-end when called from Rust with hex-encoded
// inputs. These don't validate cross-platform behavior (iOS Swift / Android JNI
// integration belongs to Tasks 10b/11), only that the boundary code (hex parse,
// buffer writing, error mapping) is correct.

use super::ffi::*;
use std::ffi::CString;

fn cstr(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn read_cstr_until_nul(buf: &[u8]) -> &str {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    std::str::from_utf8(&buf[..end]).unwrap()
}

#[test]
fn ffi_identity_commitment_smoke() {
    let mk = cstr(&hex::encode([1u8; 32]));
    let inv = cstr(&hex::encode([2u8; 16]));
    let addr = cstr(&hex::encode([3u8; 20]));
    let mut out = vec![0u8; 128];
    let mut err = vec![0u8; 64];
    let ok = unsafe {
        privacy_compute_identity_commitment(
            mk.as_ptr(),
            inv.as_ptr(),
            addr.as_ptr(),
            out.as_mut_ptr(),
            out.len(),
            err.as_mut_ptr(),
            err.len(),
        )
    };
    assert!(ok, "FFI call should succeed");
    let hex_str = read_cstr_until_nul(&out);
    assert_eq!(hex_str.len(), 64, "32-byte hash → 64 hex chars");
    assert!(hex_str.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn ffi_identity_commitment_rejects_bad_hex() {
    let bad = cstr("not-hex");
    let mut out = vec![0u8; 128];
    let mut err = vec![0u8; 64];
    let ok = unsafe {
        privacy_compute_identity_commitment(
            bad.as_ptr(),
            bad.as_ptr(),
            bad.as_ptr(),
            out.as_mut_ptr(),
            out.len(),
            err.as_mut_ptr(),
            err.len(),
        )
    };
    assert!(!ok);
    assert_eq!(read_cstr_until_nul(&err), "INPUT_INVALID");
}

#[test]
fn ffi_payment_commitment_smoke() {
    let chain = cstr("1");
    let ident = cstr(&hex::encode([1u8; 32]));
    let tok = cstr(&hex::encode([2u8; 20]));
    let amt = cstr(&hex::encode([3u8; 32]));
    let nonce = cstr(&hex::encode([4u8; 16]));
    let mut out = vec![0u8; 128];
    let mut err = vec![0u8; 64];
    let ok = unsafe {
        privacy_compute_payment_commitment(
            chain.as_ptr(),
            ident.as_ptr(),
            tok.as_ptr(),
            amt.as_ptr(),
            nonce.as_ptr(),
            out.as_mut_ptr(),
            out.len(),
            err.as_mut_ptr(),
            err.len(),
        )
    };
    assert!(ok, "got err: {}", read_cstr_until_nul(&err));
    assert_eq!(read_cstr_until_nul(&out).len(), 64);
}

#[test]
fn ffi_payment_commitment_accepts_hex_chain_id() {
    let chain = cstr("0x1");
    let ident = cstr(&hex::encode([1u8; 32]));
    let tok = cstr(&hex::encode([2u8; 20]));
    let amt = cstr(&hex::encode([3u8; 32]));
    let nonce = cstr(&hex::encode([4u8; 16]));
    let mut out = vec![0u8; 128];
    let mut err = vec![0u8; 64];
    let ok = unsafe {
        privacy_compute_payment_commitment(
            chain.as_ptr(),
            ident.as_ptr(),
            tok.as_ptr(),
            amt.as_ptr(),
            nonce.as_ptr(),
            out.as_mut_ptr(),
            out.len(),
            err.as_mut_ptr(),
            err.len(),
        )
    };
    assert!(ok);
}

#[test]
fn ffi_payment_nullifier_smoke() {
    let mk = cstr(&hex::encode([1u8; 32]));
    let inv = cstr(&hex::encode([2u8; 16]));
    let chain = cstr("1");
    let tok = cstr(&hex::encode([3u8; 20]));
    let amt = cstr(&hex::encode([4u8; 32]));
    let nonce = cstr(&hex::encode([5u8; 16]));
    let mut out = vec![0u8; 128];
    let mut err = vec![0u8; 64];
    let ok = unsafe {
        privacy_compute_payment_nullifier(
            mk.as_ptr(),
            inv.as_ptr(),
            chain.as_ptr(),
            tok.as_ptr(),
            amt.as_ptr(),
            nonce.as_ptr(),
            out.as_mut_ptr(),
            out.len(),
            err.as_mut_ptr(),
            err.len(),
        )
    };
    assert!(ok);
    let hex_str = read_cstr_until_nul(&out);
    assert_eq!(hex_str.len(), 64);
    assert_ne!(hex_str, "0".repeat(64), "nullifier must be non-zero");
}

#[test]
fn ffi_generate_receiver_pool_smoke() {
    let mk = cstr(&hex::encode([4u8; 32]));
    let inv = cstr(&hex::encode([5u8; 16]));
    let addr = cstr(&hex::encode([6u8; 20]));
    let mut out = vec![0u8; 4096];
    let mut err = vec![0u8; 64];
    let ok = unsafe {
        privacy_generate_receiver_pool(
            mk.as_ptr(),
            inv.as_ptr(),
            addr.as_ptr(),
            10,
            out.as_mut_ptr(),
            out.len(),
            err.as_mut_ptr(),
            err.len(),
        )
    };
    assert!(ok);
    let json = read_cstr_until_nul(&out);
    assert!(json.contains("\"poolId\""));
    assert!(json.contains("\"identityCommitment\""));
    assert!(json.contains("\"nonces\""));
}

#[test]
fn ffi_pool_rejects_oversized_count() {
    let mk = cstr(&hex::encode([4u8; 32]));
    let inv = cstr(&hex::encode([5u8; 16]));
    let addr = cstr(&hex::encode([6u8; 20]));
    let mut out = vec![0u8; 4096];
    let mut err = vec![0u8; 64];
    let ok = unsafe {
        privacy_generate_receiver_pool(
            mk.as_ptr(),
            inv.as_ptr(),
            addr.as_ptr(),
            501,
            out.as_mut_ptr(),
            out.len(),
            err.as_mut_ptr(),
            err.len(),
        )
    };
    assert!(!ok);
    assert_eq!(read_cstr_until_nul(&err), "POOL_SIZE_OUT_OF_RANGE");
}

#[test]
fn ffi_encrypt_decrypt_roundtrip() {
    let mk = cstr(&hex::encode([7u8; 32]));
    let plaintext = b"ffi roundtrip test";

    // Encrypt
    let mut ct_buf = vec![0u8; 1024];
    let mut err = vec![0u8; 64];
    let ok = unsafe {
        privacy_encrypt_for_db(
            mk.as_ptr(),
            plaintext.as_ptr(),
            plaintext.len(),
            ct_buf.as_mut_ptr(),
            ct_buf.len(),
            err.as_mut_ptr(),
            err.len(),
        )
    };
    assert!(ok, "encrypt failed: {}", read_cstr_until_nul(&err));
    let ct_hex = read_cstr_until_nul(&ct_buf).to_string();

    // Decrypt
    let ct_cstr = cstr(&ct_hex);
    let mut pt_buf = vec![0u8; 1024];
    let ok2 = unsafe {
        privacy_decrypt_from_db(
            mk.as_ptr(),
            ct_cstr.as_ptr(),
            pt_buf.as_mut_ptr(),
            pt_buf.len(),
            err.as_mut_ptr(),
            err.len(),
        )
    };
    assert!(ok2, "decrypt failed: {}", read_cstr_until_nul(&err));
    let pt_hex = read_cstr_until_nul(&pt_buf);
    let recovered = hex::decode(pt_hex).unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
fn ffi_decrypt_wrong_key_fails() {
    let mk_alice = cstr(&hex::encode([1u8; 32]));
    let mk_bob = cstr(&hex::encode([2u8; 32]));
    let pt = b"alice secret";

    let mut ct_buf = vec![0u8; 1024];
    let mut err = vec![0u8; 64];
    let ok = unsafe {
        privacy_encrypt_for_db(
            mk_alice.as_ptr(),
            pt.as_ptr(),
            pt.len(),
            ct_buf.as_mut_ptr(),
            ct_buf.len(),
            err.as_mut_ptr(),
            err.len(),
        )
    };
    assert!(ok);
    let ct_cstr = cstr(read_cstr_until_nul(&ct_buf));

    let mut pt_buf = vec![0u8; 1024];
    let ok2 = unsafe {
        privacy_decrypt_from_db(
            mk_bob.as_ptr(),
            ct_cstr.as_ptr(),
            pt_buf.as_mut_ptr(),
            pt_buf.len(),
            err.as_mut_ptr(),
            err.len(),
        )
    };
    assert!(!ok2);
    assert_eq!(read_cstr_until_nul(&err), "DECRYPT_FAILED");
}
