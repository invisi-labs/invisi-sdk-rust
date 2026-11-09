use invisi_sdk::payment_request::*;
#[test]
fn portable_payment_links_match_independent_ts_go_vectors() {
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/current-payment-requests.json")).unwrap();
    for row in fixtures["vectors"].as_array().unwrap() {
        let request: PaymentRequest = serde_json::from_value(row["request"].clone()).unwrap();
        assert_eq!(encode_payment_request(&request).unwrap(), row["encoded"]);
        let decoded = decode_payment_request(row["encoded"].as_str().unwrap()).unwrap();
        assert_eq!(encode_payment_request(&decoded).unwrap(), row["encoded"]);
    }
}
#[test]
fn rejects_noncanonical_links_and_conflicting_local_options() {
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/current-payment-requests.json")).unwrap();
    let row = &fixtures["vectors"][0];
    let encoded = row["encoded"].as_str().unwrap();
    assert!(decode_payment_request(&(encoded.to_owned() + "=")).is_err());
    assert!(decode_payment_request(&(encoded.to_owned() + "A")).is_err());
    assert!(decode_payment_request("ipr:").is_err());
    let request: PaymentRequest = serde_json::from_value(row["request"].clone()).unwrap();
    let local = apply_execution_options(
        &request,
        &ExecutionOptions {
            nonce: Some(alloy_primitives::U256::from(5)),
            address_lookup: None,
        },
    )
    .unwrap();
    assert_ne!(encode_payment_request(&local).unwrap(), encoded);
    assert!(apply_execution_options(
        &local,
        &ExecutionOptions {
            nonce: Some(alloy_primitives::U256::from(6)),
            address_lookup: None
        }
    )
    .is_err());
    assert!(apply_execution_options(
        &request,
        &ExecutionOptions {
            nonce: None,
            address_lookup: Some(AddressLookup::Chain)
        }
    )
    .is_err());
}
