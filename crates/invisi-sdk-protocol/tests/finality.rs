use invisi_sdk_protocol::finality::*;
use serde_json::json;
#[test]
fn rejects_impossible_native_claims() {
    let unavailable = json!({"status":"unavailable","block":null});
    assert!(ChainFinality::parse(
        &json!({"latest":unavailable,"safe":unavailable,"finalized":unavailable})
    )
    .is_ok());
    assert!(FinalityHead::parse(&json!({"status":"available","block":null})).is_err());
    assert!(FinalityHead::parse(&json!({"status":"guessed","block":null})).is_err());
    assert!(FinalityHead::parse(&json!({"status":"unavailable","block":{"number":1}})).is_err());
}
