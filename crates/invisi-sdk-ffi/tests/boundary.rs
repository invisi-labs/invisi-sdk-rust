use invisi_sdk_ffi::{invisi_wallet_execute_batch, invisi_wallet_free};
use serde_json::Value;
use std::ffi::CStr;
#[test]
fn ffi_validates_pointers_and_owns_its_result() {
    unsafe {
        let out = invisi_wallet_execute_batch(std::ptr::null(), 0, std::ptr::null(), 0);
        assert!(!out.is_null());
        let result: Value = serde_json::from_str(CStr::from_ptr(out).to_str().unwrap()).unwrap();
        assert!(result["error"]["code"].is_string());
        invisi_wallet_free(out);
        invisi_wallet_free(std::ptr::null_mut());
    }
}
#[test]
fn ffi_executes_wire_request() {
    let mut key = [0; 32];
    key[31] = 1;
    let request=br#"[{"version":1,"id":"ffi-test","ownerAddress":"0x7e5f4552091a69125d5dfcb7b8c2659029395bdf","method":"wallet.public","params":{}}]"#;
    unsafe {
        let out =
            invisi_wallet_execute_batch(key.as_ptr(), key.len(), request.as_ptr(), request.len());
        assert!(!out.is_null());
        let result: Value = serde_json::from_str(CStr::from_ptr(out).to_str().unwrap()).unwrap();
        assert_eq!(result[0]["id"], "ffi-test");
        assert!(result[0]["result"]["clueKey"].is_string());
        invisi_wallet_free(out);
    }
}

#[test]
fn ffi_accepts_empty_arrays_and_rejects_scalar_or_duplicate_batches() {
    let mut key = [0; 32];
    key[31] = 1;
    for (request, success) in [
        ("[]".to_owned(), true),
        ("{}".to_owned(), false),
        (
            {
                let request = serde_json::json!({"version":1,"id":"duplicate","ownerAddress":"0x7e5f4552091a69125d5dfcb7b8c2659029395bdf","method":"wallet.public","params":{}});
                serde_json::json!([request, request]).to_string()
            },
            false,
        ),
    ] {
        unsafe {
            let output =
                invisi_wallet_execute_batch(key.as_ptr(), 32, request.as_ptr(), request.len());
            let value: Value =
                serde_json::from_str(CStr::from_ptr(output).to_str().unwrap()).unwrap();
            invisi_wallet_free(output);
            if success {
                assert_eq!(value, serde_json::json!([]));
            } else {
                assert!(value["error"]["code"].is_string());
            }
        }
    }
}
