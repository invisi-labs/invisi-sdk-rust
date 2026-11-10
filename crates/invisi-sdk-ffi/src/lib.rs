//! Native wallet custody boundary shared with the current SDK wallet protocol.
use std::ffi::{c_char, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use zeroize::{Zeroize, Zeroizing};

use invisi_sdk_primitives::wallet;

const MAX_REQUEST_BYTES: usize = wallet::MAX_WALLET_BATCH_JSON_BYTES;

fn response(key: &[u8], request: &[u8]) -> Result<serde_json::Value, String> {
    let input: serde_json::Value =
        serde_json::from_slice(request).map_err(|_| "WALLET_INVALID_JSON".to_owned())?;
    let requests = input.as_array().ok_or("WALLET_BATCH_ARRAY_REQUIRED")?;
    serde_json::to_value(wallet::execute_batch(key, requests)?)
        .map_err(|_| "WALLET_INVALID_JSON".into())
}

/// Execute a JSON request array; free the returned UTF-8 JSON with `invisi_wallet_free`.
/// Errors are returned as `{"error":{"code":"..."}}`; success is the wire response array.
///
/// # Safety
/// Non-null input pointers must reference readable buffers of the given lengths.
/// The host retains ownership of inputs and must clear its own key buffers.
#[no_mangle]
pub unsafe extern "C" fn invisi_wallet_execute_batch(
    key: *const u8,
    key_len: usize,
    request: *const u8,
    request_len: usize,
) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if key.is_null()
            || key_len != 32
            || request.is_null()
            || request_len == 0
            || request_len > MAX_REQUEST_BYTES
        {
            return Err("WALLET_INVALID_INPUT".to_owned());
        }
        let key = Zeroizing::new(std::slice::from_raw_parts(key, key_len).to_vec());
        response(&key, std::slice::from_raw_parts(request, request_len))
    }))
    .unwrap_or_else(|_| Err("WALLET_NATIVE_FAILURE".to_owned()));
    let value = match result {
        Ok(value) => value,
        Err(code) => serde_json::json!({"error":{"code":code}}),
    };
    // JSON escaping removes embedded NUL bytes from the returned C string.
    CString::new(value.to_string())
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// Release one result allocated by `invisi_wallet_execute_batch`; null is accepted.
///
/// # Safety
/// The pointer must be null or an unfreed result returned by this library.
#[no_mangle]
pub unsafe extern "C" fn invisi_wallet_free(result: *mut c_char) {
    if !result.is_null() {
        let mut bytes = CString::from_raw(result).into_bytes_with_nul();
        bytes.zeroize();
    }
}
