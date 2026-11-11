use invisi_sdk::{
    sdk::{Wallet, WalletRequest, WalletResponse},
    wallet,
};
use serde_json::{json, Value};
fn key() -> [u8; 32] {
    let mut key = [0; 32];
    key[31] = 1;
    key
}
fn public(id: &str) -> Value {
    json!({"version":1,"id":id,"ownerAddress":"0x7e5f4552091a69125d5dfcb7b8c2659029395bdf","method":"wallet.public","params":{}})
}
#[test]
fn native_batch_validates_every_item_and_keeps_errors_bound_to_ids() {
    assert_eq!(
        wallet::execute_batch(&key(), &[]).unwrap(),
        Vec::<Value>::new()
    );
    assert!(wallet::execute_batch(&key(), &[public("same"), public("same")]).is_err());
    let mut wrong_owner = public("other");
    wrong_owner["ownerAddress"] = json!("0x2b5ad5c4795c026514f8317c7a215e218dccd6cf");
    assert!(wallet::execute_batch(&key(), &[public("first"), wrong_owner]).is_err());
    let mut malformed = public("bad");
    malformed["params"] = json!({"privateKey":"forbidden"});
    assert!(wallet::execute_batch(&key(), &[public("first"), malformed]).is_err());
    let mut too_many = Vec::new();
    for n in 0..1025 {
        too_many.push(public(&format!("request-{n}")));
    }
    assert!(wallet::execute_batch(&key(), &too_many).is_err());
}
#[test]
fn wallet_correlates_reordered_batches_and_rejects_missing_duplicate_unknown_and_errors() {
    let wallet = Wallet::from_owner(
        "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
            .parse()
            .unwrap(),
    )
    .unwrap();
    let requests = vec![
        wallet
            .prepare_request("public", "wallet.public", json!({}))
            .unwrap(),
        wallet
            .prepare_request("detect", "wallet.detect", json!({"clues":[]}))
            .unwrap(),
    ];
    let values: Vec<Value> = requests.iter().map(WalletRequest::as_value).collect();
    let mut responses: Vec<WalletResponse> = wallet::execute_batch(&key(), &values)
        .unwrap()
        .into_iter()
        .map(|v| serde_json::from_value(v).unwrap())
        .collect();
    responses.reverse();
    assert_eq!(wallet.accept_batch(&requests, &responses).unwrap().len(), 2);
    assert!(wallet.accept_batch(&requests, &responses[..1]).is_err());
    let mut duplicated = responses.clone();
    duplicated[1] = duplicated[0].clone();
    assert!(wallet.accept_batch(&requests, &duplicated).is_err());
    let mut unknown = responses.clone();
    unknown[0].id = "unknown".into();
    assert!(wallet.accept_batch(&requests, &unknown).is_err());
    let mut wrong_method = responses.clone();
    wrong_method[0].method = "wallet.public".into();
    assert!(wallet.accept_batch(&requests, &wrong_method).is_err());
    let mut wrong_owner = responses.clone();
    wrong_owner[0].owner_address = "0x2b5ad5c4795c026514f8317c7a215e218dccd6cf".into();
    assert!(wallet.accept_batch(&requests, &wrong_owner).is_err());
    let error:WalletResponse=serde_json::from_value(json!({"version":1,"id":"public","ownerAddress":requests[0].owner_address,"method":"wallet.public","error":{"code":"WALLET_LOCKED"}})).unwrap();
    assert!(wallet.accept_response(&requests[0], &error).is_err());
    assert!(wallet
        .accept_batch(&requests, &[error, responses[0].clone()])
        .unwrap()[0]
        .is_err());
}

#[test]
fn native_batch_returns_ambiguous_authentication_and_preserves_other_members() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/wallet-wire-vectors.json")).unwrap();
    let mut request = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["request"]["method"] == "wallet.decryptNote")
        .unwrap()["request"]
        .clone();
    let mut envelope = request["params"]["envelope"].as_str().unwrap().to_owned();
    let last = envelope.pop().unwrap();
    envelope.push(if last == '0' { '1' } else { '0' });
    request["params"]["envelope"] = json!(envelope);
    let responses = wallet::execute_batch(&key(), &[public("public"), request.clone()]).unwrap();
    assert!(responses[0]["result"].is_object());
    assert_eq!(
        responses[1]["error"]["code"],
        "WALLET_AUTHENTICATION_FAILED"
    );
    assert_eq!(responses[1]["id"], request["id"]);
    assert!(responses[1].get("result").is_none());
    let mut oversized = public("large");
    oversized["params"] = json!({"padding":"x".repeat(16*1024*1024)});
    assert!(wallet::execute_batch(&key(), &[oversized]).is_err());
}

#[test]
fn response_envelopes_require_exactly_one_bound_result_or_error() {
    let mut response = json!({"version":1,"id":"a","ownerAddress":public("a")["ownerAddress"],"method":"wallet.public","error":{"code":"WALLET_CANCELLED"}});
    assert!(serde_json::from_value::<WalletResponse>(response.clone()).is_ok());
    response["result"] = json!({});
    assert!(serde_json::from_value::<WalletResponse>(response.clone()).is_err());
    response.as_object_mut().unwrap().remove("result");
    response["error"]["message"] = json!("unexpected");
    assert!(serde_json::from_value::<WalletResponse>(response.clone()).is_err());
    response["error"] = Value::Null;
    assert!(serde_json::from_value::<WalletResponse>(response).is_err());
}

#[test]
fn private_key_execution_stays_in_native_test_and_resolves_only_a_public_profile() {
    let wallet = Wallet::from_owner(
        "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
            .parse()
            .unwrap(),
    )
    .unwrap();
    let request = wallet
        .prepare_request("profile", "wallet.public", json!({}))
        .unwrap();
    let values = wallet::execute_batch(&key(), &[request.as_value()]).unwrap();
    assert!(values[0]["result"].get("viewingPrivateKey").is_none());
    assert!(values[0]["result"].get("detectionKey").is_none());
    let response: WalletResponse = serde_json::from_value(values[0].clone()).unwrap();
    let resolved = Wallet::from_response(&request, &response).unwrap();
    assert_eq!(resolved.owner_address(), wallet.owner_address());
    assert!(resolved.address().unwrap().starts_with("0i"));
}

#[test]
fn response_error_codes_start_with_an_uppercase_letter() {
    for code in ["1BAD", "_BAD", "lowercase", ""] {
        let value = json!({"version":1,"id":"error-code","ownerAddress":public("a")["ownerAddress"],"method":"wallet.public","error":{"code":code}});
        assert!(
            serde_json::from_value::<WalletResponse>(value).is_err(),
            "{code}"
        );
    }
}
