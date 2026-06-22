//! C ABI exports for iOS Swift / Android JNI bridges.
//!
//! Naming convention: `privacy_<function_name>` — matches existing keyring exports.
//! All hex I/O is null-terminated ASCII (no 0x prefix).
//! Errors are written to err_buf as a null-terminated stable code string
//! (see error::Error::code()).
//!
//! Returns `true` on success; on failure, err_buf contains the code and the
//! function returns `false`. Output buffers are populated only on success.

use std::ffi::{c_char, CStr};
use std::slice;

use serde::Serialize;

use invisi_sdk_payer::{build_approve_calldata, build_pay_blind_calldata, build_pay_open_calldata};

use invisi_sdk_core::cipher::{decrypt_for_db_raw, encrypt_for_db_raw};
use invisi_sdk_core::derive::{
    compute_identity_commitment, compute_payment_commitment, compute_payment_nullifier,
    derive_nullifier_key,
};
use invisi_sdk_core::pool::generate_receiver_pool_raw;

pub use invisi_sdk_core::{cipher, derive, domain, error, field, pool, poseidon, poseidon_constants};

// ===== helpers =====

unsafe fn write_err(err_buf: *mut u8, err_cap: usize, code: &str) {
    if err_buf.is_null() || err_cap == 0 {
        return;
    }
    let bytes = code.as_bytes();
    let n = bytes.len().min(err_cap.saturating_sub(1));
    let dst = slice::from_raw_parts_mut(err_buf, n);
    dst.copy_from_slice(&bytes[..n]);
    *err_buf.add(n) = 0;
}

unsafe fn write_str(out_buf: *mut u8, out_cap: usize, s: &str) -> bool {
    if out_buf.is_null() {
        return false;
    }
    let needed = s.len() + 1; // +1 for null terminator
    if needed > out_cap {
        return false;
    }
    let dst = slice::from_raw_parts_mut(out_buf, s.len());
    dst.copy_from_slice(s.as_bytes());
    *out_buf.add(s.len()) = 0;
    true
}

unsafe fn read_hex_fixed<const N: usize>(hex_ptr: *const c_char) -> Option<[u8; N]> {
    if hex_ptr.is_null() {
        return None;
    }
    let s = CStr::from_ptr(hex_ptr).to_str().ok()?;
    let v = hex::decode(s).ok()?;
    if v.len() != N {
        return None;
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&v);
    Some(out)
}

/// 接受十进制 (e.g. "1") 或 0x-prefixed 十六进制 (e.g. "0x1") chain_id.
unsafe fn read_u64(hex_ptr: *const c_char) -> Option<u64> {
    if hex_ptr.is_null() {
        return None;
    }
    let s = CStr::from_ptr(hex_ptr).to_str().ok()?;
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(rest, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

unsafe fn read_bytes_len(ptr: *const u8, len: usize) -> Option<Vec<u8>> {
    if ptr.is_null() && len > 0 {
        return None;
    }
    if len == 0 {
        return Some(Vec::new());
    }
    Some(slice::from_raw_parts(ptr, len).to_vec())
}

// ===== exports =====

/// Expose nullifier_key = Poseidon2(D_NKEY, master_key, invoice_id) as raw hex.
/// Mobile B-side withdraw flow needs to inject this into each settlement
/// witness leaf (`leaf.NullifierKey`) before calling GenerateSettlementProof.
/// Computing it once here saves a round trip vs. exposing the FFI fields of
/// privacy_compute_payment_nullifier (which already derives nk internally but
/// only returns the final nullifier).
#[no_mangle]
pub unsafe extern "C" fn privacy_compute_nullifier_key(
    master_key_hex: *const c_char,
    invoice_id_hex: *const c_char,
    out_buf: *mut u8,
    out_cap: usize,
    err_buf: *mut u8,
    err_cap: usize,
) -> bool {
    let mk = match read_hex_fixed::<32>(master_key_hex) {
        Some(v) => v,
        None => {
            write_err(err_buf, err_cap, "INPUT_INVALID");
            return false;
        }
    };
    let inv = match read_hex_fixed::<16>(invoice_id_hex) {
        Some(v) => v,
        None => {
            write_err(err_buf, err_cap, "INPUT_INVALID");
            return false;
        }
    };
    let nk = derive_nullifier_key(&mk, &inv);
    let hex_out = hex::encode(nk);
    if !write_str(out_buf, out_cap, &hex_out) {
        write_err(err_buf, err_cap, "BUFFER_TOO_SMALL");
        return false;
    }
    true
}

#[no_mangle]
pub unsafe extern "C" fn privacy_compute_identity_commitment(
    master_key_hex: *const c_char,
    invoice_id_hex: *const c_char,
    recv_addr_hex: *const c_char,
    out_buf: *mut u8,
    out_cap: usize,
    err_buf: *mut u8,
    err_cap: usize,
) -> bool {
    let mk = match read_hex_fixed::<32>(master_key_hex) {
        Some(v) => v,
        None => {
            write_err(err_buf, err_cap, "INPUT_INVALID");
            return false;
        }
    };
    let inv = match read_hex_fixed::<16>(invoice_id_hex) {
        Some(v) => v,
        None => {
            write_err(err_buf, err_cap, "INPUT_INVALID");
            return false;
        }
    };
    let addr = match read_hex_fixed::<20>(recv_addr_hex) {
        Some(v) => v,
        None => {
            write_err(err_buf, err_cap, "INPUT_INVALID");
            return false;
        }
    };
    let nk = derive_nullifier_key(&mk, &inv);
    let ident = compute_identity_commitment(&nk, &addr);
    let hex_out = hex::encode(ident);
    if !write_str(out_buf, out_cap, &hex_out) {
        write_err(err_buf, err_cap, "BUFFER_TOO_SMALL");
        return false;
    }
    true
}

#[no_mangle]
pub unsafe extern "C" fn privacy_compute_payment_commitment(
    chain_id_str: *const c_char,
    identity_commitment_hex: *const c_char,
    token_hex: *const c_char,
    amount_hex: *const c_char,
    nonce_hex: *const c_char,
    out_buf: *mut u8,
    out_cap: usize,
    err_buf: *mut u8,
    err_cap: usize,
) -> bool {
    let chain = match read_u64(chain_id_str) {
        Some(v) => v,
        None => {
            write_err(err_buf, err_cap, "INPUT_INVALID");
            return false;
        }
    };
    let ident = match read_hex_fixed::<32>(identity_commitment_hex) {
        Some(v) => v,
        None => {
            write_err(err_buf, err_cap, "INPUT_INVALID");
            return false;
        }
    };
    let token = match read_hex_fixed::<20>(token_hex) {
        Some(v) => v,
        None => {
            write_err(err_buf, err_cap, "INPUT_INVALID");
            return false;
        }
    };
    let amount = match read_hex_fixed::<32>(amount_hex) {
        Some(v) => v,
        None => {
            write_err(err_buf, err_cap, "INPUT_INVALID");
            return false;
        }
    };
    let nonce = match read_hex_fixed::<32>(nonce_hex) {
        Some(v) => v,
        None => {
            write_err(err_buf, err_cap, "INPUT_INVALID");
            return false;
        }
    };
    let pc = compute_payment_commitment(chain, &ident, &token, &amount, &nonce);
    let hex_out = hex::encode(pc);
    if !write_str(out_buf, out_cap, &hex_out) {
        write_err(err_buf, err_cap, "BUFFER_TOO_SMALL");
        return false;
    }
    true
}

#[no_mangle]
pub unsafe extern "C" fn privacy_compute_payment_nullifier(
    master_key_hex: *const c_char,
    invoice_id_hex: *const c_char,
    chain_id_str: *const c_char,
    token_hex: *const c_char,
    amount_hex: *const c_char,
    nonce_hex: *const c_char,
    out_buf: *mut u8,
    out_cap: usize,
    err_buf: *mut u8,
    err_cap: usize,
) -> bool {
    let mk = match read_hex_fixed::<32>(master_key_hex) {
        Some(v) => v,
        None => {
            write_err(err_buf, err_cap, "INPUT_INVALID");
            return false;
        }
    };
    let inv = match read_hex_fixed::<16>(invoice_id_hex) {
        Some(v) => v,
        None => {
            write_err(err_buf, err_cap, "INPUT_INVALID");
            return false;
        }
    };
    let chain = match read_u64(chain_id_str) {
        Some(v) => v,
        None => {
            write_err(err_buf, err_cap, "INPUT_INVALID");
            return false;
        }
    };
    let token = match read_hex_fixed::<20>(token_hex) {
        Some(v) => v,
        None => {
            write_err(err_buf, err_cap, "INPUT_INVALID");
            return false;
        }
    };
    let amount = match read_hex_fixed::<32>(amount_hex) {
        Some(v) => v,
        None => {
            write_err(err_buf, err_cap, "INPUT_INVALID");
            return false;
        }
    };
    let nonce = match read_hex_fixed::<32>(nonce_hex) {
        Some(v) => v,
        None => {
            write_err(err_buf, err_cap, "INPUT_INVALID");
            return false;
        }
    };
    let nk = derive_nullifier_key(&mk, &inv);
    match compute_payment_nullifier(&nk, chain, &token, &amount, &nonce) {
        Ok(pn) => {
            let hex_out = hex::encode(pn);
            if !write_str(out_buf, out_cap, &hex_out) {
                write_err(err_buf, err_cap, "BUFFER_TOO_SMALL");
                return false;
            }
            true
        }
        Err(e) => {
            write_err(err_buf, err_cap, e.code());
            false
        }
    }
}

#[derive(Serialize)]
struct PoolJson<'a> {
    #[serde(rename = "poolId")]
    pool_id: &'a str,
    #[serde(rename = "identityCommitment")]
    identity_commitment: String,
    nonces: Vec<String>,
}

#[no_mangle]
pub unsafe extern "C" fn privacy_generate_receiver_pool(
    master_key_hex: *const c_char,
    invoice_id_hex: *const c_char,
    recv_addr_hex: *const c_char,
    count: u32,
    out_buf: *mut u8,
    out_cap: usize,
    err_buf: *mut u8,
    err_cap: usize,
) -> bool {
    let mk = match read_hex_fixed::<32>(master_key_hex) {
        Some(v) => v,
        None => {
            write_err(err_buf, err_cap, "INPUT_INVALID");
            return false;
        }
    };
    let inv = match read_hex_fixed::<16>(invoice_id_hex) {
        Some(v) => v,
        None => {
            write_err(err_buf, err_cap, "INPUT_INVALID");
            return false;
        }
    };
    let addr = match read_hex_fixed::<20>(recv_addr_hex) {
        Some(v) => v,
        None => {
            write_err(err_buf, err_cap, "INPUT_INVALID");
            return false;
        }
    };
    let pool = match generate_receiver_pool_raw(&mk, &inv, &addr, count) {
        Ok(p) => p,
        Err(e) => {
            write_err(err_buf, err_cap, e.code());
            return false;
        }
    };
    let json_obj = PoolJson {
        pool_id: &pool.pool_id,
        identity_commitment: hex::encode(pool.identity_commitment),
        nonces: pool.nonces.iter().map(hex::encode).collect(),
    };
    let json = match serde_json::to_string(&json_obj) {
        Ok(s) => s,
        Err(_) => {
            write_err(err_buf, err_cap, "SERIALIZE_FAILED");
            return false;
        }
    };
    if !write_str(out_buf, out_cap, &json) {
        write_err(err_buf, err_cap, "BUFFER_TOO_SMALL");
        return false;
    }
    true
}

#[no_mangle]
pub unsafe extern "C" fn privacy_encrypt_for_db(
    master_key_hex: *const c_char,
    plaintext_ptr: *const u8,
    plaintext_len: usize,
    out_buf: *mut u8,
    out_cap: usize,
    err_buf: *mut u8,
    err_cap: usize,
) -> bool {
    let mk = match read_hex_fixed::<32>(master_key_hex) {
        Some(v) => v,
        None => {
            write_err(err_buf, err_cap, "INPUT_INVALID");
            return false;
        }
    };
    let pt = match read_bytes_len(plaintext_ptr, plaintext_len) {
        Some(v) => v,
        None => {
            write_err(err_buf, err_cap, "INPUT_INVALID");
            return false;
        }
    };
    let ct = match encrypt_for_db_raw(&mk, &pt) {
        Ok(v) => v,
        Err(e) => {
            write_err(err_buf, err_cap, e.code());
            return false;
        }
    };
    let hex_out = hex::encode(ct);
    if !write_str(out_buf, out_cap, &hex_out) {
        write_err(err_buf, err_cap, "BUFFER_TOO_SMALL");
        return false;
    }
    true
}

#[no_mangle]
pub unsafe extern "C" fn privacy_decrypt_from_db(
    master_key_hex: *const c_char,
    ciphertext_hex: *const c_char,
    out_buf: *mut u8,
    out_cap: usize,
    err_buf: *mut u8,
    err_cap: usize,
) -> bool {
    let mk = match read_hex_fixed::<32>(master_key_hex) {
        Some(v) => v,
        None => {
            write_err(err_buf, err_cap, "INPUT_INVALID");
            return false;
        }
    };
    if ciphertext_hex.is_null() {
        write_err(err_buf, err_cap, "INPUT_INVALID");
        return false;
    }
    let ct_str = match CStr::from_ptr(ciphertext_hex).to_str() {
        Ok(s) => s,
        Err(_) => {
            write_err(err_buf, err_cap, "INPUT_INVALID");
            return false;
        }
    };
    let ct = match hex::decode(ct_str) {
        Ok(v) => v,
        Err(_) => {
            write_err(err_buf, err_cap, "CIPHERTEXT_MALFORMED");
            return false;
        }
    };
    let pt = match decrypt_for_db_raw(&mk, &ct) {
        Ok(v) => v,
        Err(e) => {
            write_err(err_buf, err_cap, e.code());
            return false;
        }
    };
    let hex_out = hex::encode(pt);
    if !write_str(out_buf, out_cap, &hex_out) {
        write_err(err_buf, err_cap, "BUFFER_TOO_SMALL");
        return false;
    }
    true
}

// ===== calldata builders =====

#[no_mangle]
pub unsafe extern "C" fn privacy_build_approve_calldata(
    spender_hex: *const c_char,
    amount_hex: *const c_char,
    out_buf: *mut u8, out_cap: usize,
    err_buf: *mut u8, err_cap: usize,
) -> bool {
    let spender = match read_hex_fixed::<20>(spender_hex) {
        Some(v) => v, None => { write_err(err_buf, err_cap, "INPUT_INVALID"); return false; }
    };
    let amount = match read_hex_fixed::<32>(amount_hex) {
        Some(v) => v, None => { write_err(err_buf, err_cap, "INPUT_INVALID"); return false; }
    };
    let data = build_approve_calldata(&spender, &amount);
    if !write_str(out_buf, out_cap, &hex::encode(data)) {
        write_err(err_buf, err_cap, "BUFFER_TOO_SMALL"); return false;
    }
    true
}

#[no_mangle]
pub unsafe extern "C" fn privacy_build_pay_open_calldata(
    identity_hex: *const c_char,
    amount_hex: *const c_char,
    nonce_hex: *const c_char,
    tree_id_str: *const c_char,
    refund_link_hex: *const c_char,
    out_buf: *mut u8, out_cap: usize,
    err_buf: *mut u8, err_cap: usize,
) -> bool {
    let identity = match read_hex_fixed::<32>(identity_hex) { Some(v)=>v, None=>{write_err(err_buf,err_cap,"INPUT_INVALID");return false;} };
    let amount = match read_hex_fixed::<32>(amount_hex) { Some(v)=>v, None=>{write_err(err_buf,err_cap,"INPUT_INVALID");return false;} };
    let nonce = match read_hex_fixed::<32>(nonce_hex) { Some(v)=>v, None=>{write_err(err_buf,err_cap,"INPUT_INVALID");return false;} };
    let tree_id = match read_u64(tree_id_str) { Some(v)=>v, None=>{write_err(err_buf,err_cap,"INPUT_INVALID");return false;} };
    let refund = match read_hex_fixed::<32>(refund_link_hex) { Some(v)=>v, None=>{write_err(err_buf,err_cap,"INPUT_INVALID");return false;} };
    let data = build_pay_open_calldata(&identity, &amount, &nonce, tree_id, &refund);
    if !write_str(out_buf, out_cap, &hex::encode(data)) { write_err(err_buf,err_cap,"BUFFER_TOO_SMALL"); return false; }
    true
}

#[no_mangle]
pub unsafe extern "C" fn privacy_build_pay_blind_calldata(
    proof_hex: *const c_char,
    payment_commitment_hex: *const c_char,
    change_commitment_hex: *const c_char,
    input_amount_hex: *const c_char,
    tree_id_str: *const c_char,
    refund_link_hex: *const c_char,
    out_buf: *mut u8, out_cap: usize,
    err_buf: *mut u8, err_cap: usize,
) -> bool {
    let proof_s = if proof_hex.is_null() { write_err(err_buf,err_cap,"INPUT_INVALID"); return false; }
                  else { match CStr::from_ptr(proof_hex).to_str() { Ok(s)=>s, Err(_)=>{write_err(err_buf,err_cap,"INPUT_INVALID");return false;} } };
    let proof = match hex::decode(proof_s) { Ok(v)=>v, Err(_)=>{write_err(err_buf,err_cap,"INPUT_INVALID");return false;} };
    let pc = match read_hex_fixed::<32>(payment_commitment_hex) { Some(v)=>v, None=>{write_err(err_buf,err_cap,"INPUT_INVALID");return false;} };
    let cc = match read_hex_fixed::<32>(change_commitment_hex) { Some(v)=>v, None=>{write_err(err_buf,err_cap,"INPUT_INVALID");return false;} };
    let input_amount = match read_hex_fixed::<32>(input_amount_hex) { Some(v)=>v, None=>{write_err(err_buf,err_cap,"INPUT_INVALID");return false;} };
    let tree_id = match read_u64(tree_id_str) { Some(v)=>v, None=>{write_err(err_buf,err_cap,"INPUT_INVALID");return false;} };
    let refund = match read_hex_fixed::<32>(refund_link_hex) { Some(v)=>v, None=>{write_err(err_buf,err_cap,"INPUT_INVALID");return false;} };
    let data = build_pay_blind_calldata(&proof, &pc, &cc, &input_amount, tree_id, &refund);
    if !write_str(out_buf, out_cap, &hex::encode(data)) { write_err(err_buf,err_cap,"BUFFER_TOO_SMALL"); return false; }
    true
}

// ==================== FFI smoke tests ====================
//
// Verify the C ABI exports work end-to-end when called from Rust with hex-encoded
// inputs. These don't validate cross-platform behavior (iOS Swift / Android JNI
// integration belongs to Tasks 10b/11), only that the boundary code (hex parse,
// buffer writing, error mapping) is correct.

#[cfg(test)]
mod tests {
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
            super::privacy_compute_identity_commitment(
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
            super::privacy_compute_identity_commitment(
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
        let nonce = cstr(&hex::encode([4u8; 32]));
        let mut out = vec![0u8; 128];
        let mut err = vec![0u8; 64];
        let ok = unsafe {
            super::privacy_compute_payment_commitment(
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
        let nonce = cstr(&hex::encode([4u8; 32]));
        let mut out = vec![0u8; 128];
        let mut err = vec![0u8; 64];
        let ok = unsafe {
            super::privacy_compute_payment_commitment(
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
        let nonce = cstr(&hex::encode([5u8; 32]));
        let mut out = vec![0u8; 128];
        let mut err = vec![0u8; 64];
        let ok = unsafe {
            super::privacy_compute_payment_nullifier(
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
            super::privacy_generate_receiver_pool(
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
            super::privacy_generate_receiver_pool(
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
            super::privacy_encrypt_for_db(
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
            super::privacy_decrypt_from_db(
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
    fn ffi_build_approve_calldata_smoke() {
        let spender = std::ffi::CString::new("70997970c51812dc3a010c7d01b50e0d17dc79c8").unwrap();
        let amount = std::ffi::CString::new(format!("{:064x}", 1000u64)).unwrap();
        let mut out = [0u8; 512];
        let mut err = [0u8; 64];
        let ok = unsafe {
            super::privacy_build_approve_calldata(
                spender.as_ptr(), amount.as_ptr(),
                out.as_mut_ptr(), out.len(), err.as_mut_ptr(), err.len())
        };
        assert!(ok);
        let s = unsafe { std::ffi::CStr::from_ptr(out.as_ptr() as *const i8) }.to_str().unwrap();
        assert!(s.starts_with("095ea7b3"));
        assert_eq!(s.len(), 8 + 64 + 64);
    }

    #[test]
    fn ffi_decrypt_wrong_key_fails() {
        let mk_alice = cstr(&hex::encode([1u8; 32]));
        let mk_bob = cstr(&hex::encode([2u8; 32]));
        let pt = b"alice secret";

        let mut ct_buf = vec![0u8; 1024];
        let mut err = vec![0u8; 64];
        let ok = unsafe {
            super::privacy_encrypt_for_db(
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
            super::privacy_decrypt_from_db(
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

    #[test]
    fn ffi_build_pay_open_calldata_smoke() {
        let identity = CString::new(format!("{:064x}", 0xAAu64)).unwrap();
        let amount = CString::new(format!("{:064x}", 1000u64)).unwrap();
        let nonce = CString::new(format!("{:064x}", 0xBBu64)).unwrap();
        let tree_id = CString::new("1").unwrap();
        let refund = CString::new("0".repeat(64)).unwrap();
        let mut out = [0u8; 2048];
        let mut err = [0u8; 64];
        let ok = unsafe {
            super::privacy_build_pay_open_calldata(
                identity.as_ptr(), amount.as_ptr(), nonce.as_ptr(),
                tree_id.as_ptr(), refund.as_ptr(),
                out.as_mut_ptr(), out.len(), err.as_mut_ptr(), err.len())
        };
        assert!(ok, "payOpen failed: {}", read_cstr_until_nul(&err));
        let s = unsafe { std::ffi::CStr::from_ptr(out.as_ptr() as *const i8) }.to_str().unwrap();
        assert!(s.starts_with("8cf55984"), "payOpen selector mismatch");
        assert!(!s.is_empty(), "output hex should be non-empty");
    }

    #[test]
    fn ffi_build_pay_blind_calldata_smoke() {
        // Normal path: valid proof
        let proof = CString::new("deadbeef").unwrap();
        let pc = CString::new(format!("{:064x}", 0xCCu64)).unwrap();
        let cc = CString::new(format!("{:064x}", 0xDDu64)).unwrap();
        let input_amt = CString::new(format!("{:064x}", 2000u64)).unwrap();
        let tree_id = CString::new("1").unwrap();
        let refund = CString::new("0".repeat(64)).unwrap();
        let mut out = [0u8; 2048];
        let mut err = [0u8; 64];
        let ok = unsafe {
            super::privacy_build_pay_blind_calldata(
                proof.as_ptr(), pc.as_ptr(), cc.as_ptr(),
                input_amt.as_ptr(), tree_id.as_ptr(), refund.as_ptr(),
                out.as_mut_ptr(), out.len(), err.as_mut_ptr(), err.len())
        };
        assert!(ok, "payBlind normal failed: {}", read_cstr_until_nul(&err));
        let s = unsafe { std::ffi::CStr::from_ptr(out.as_ptr() as *const i8) }.to_str().unwrap();
        assert!(s.starts_with("82d33b9b"), "payBlind selector mismatch");
        assert!(!s.is_empty(), "output hex should be non-empty");

        // Failure path: null proof pointer
        let mut out_fail = [0u8; 2048];
        let mut err_fail = [0u8; 64];
        let ok_fail = unsafe {
            super::privacy_build_pay_blind_calldata(
                std::ptr::null(), pc.as_ptr(), cc.as_ptr(),
                input_amt.as_ptr(), tree_id.as_ptr(), refund.as_ptr(),
                out_fail.as_mut_ptr(), out_fail.len(), err_fail.as_mut_ptr(), err_fail.len())
        };
        assert!(!ok_fail, "payBlind with null proof should fail");
        assert_eq!(read_cstr_until_nul(&err_fail), "INPUT_INVALID");
    }
}
