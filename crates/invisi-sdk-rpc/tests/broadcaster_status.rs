use invisi_sdk_rpc::broadcaster::Status;
use serde_json::json;

#[test]
fn scheduled_period_rejection_preserves_reason_and_window() {
    let value = json!({
        "id": format!("0x{}", "11".repeat(32)),
        "state": "rejected",
        "reasonCode": "CREDIT_PERIOD_CHANGED",
        "publishAfter": "1796040060",
        "executeBefore": "1796040360"
    });
    let decoded = serde_json::from_value::<Status>(value.clone());
    assert!(decoded.is_ok(), "valid scheduled rejection: {decoded:?}");
    assert_eq!(serde_json::to_value(decoded.unwrap()).unwrap(), value);
}

#[test]
fn ordinary_status_omits_optional_scheduling_fields() {
    let value = json!({"id": "known", "state": "pending"});
    let decoded: Status = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), value);
}

#[test]
fn malformed_status_reason_or_schedule_is_rejected() {
    for (key, invalid) in [
        ("reasonCode", json!(42)),
        ("reasonCode", json!("")),
        ("reasonCode", json!("x".repeat(257))),
        ("publishAfter", json!(1796040060u64)),
        ("publishAfter", json!("01796040060")),
        ("executeBefore", json!("-1")),
        ("executeBefore", json!("9007199254740992")),
    ] {
        let mut value = json!({"id":"known","state":"rejected"});
        value[key] = invalid;
        assert!(
            serde_json::from_value::<Status>(value).is_err(),
            "accepted {key}"
        );
    }
}
