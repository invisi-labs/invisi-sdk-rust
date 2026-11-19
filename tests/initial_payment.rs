use invisi_sdk::wallet::authorization_digest;
use serde_json::{json, Value};
#[test]
fn initial_payment_authorization_accepts_combined_statement() {
    let f: Value =
        serde_json::from_str(include_str!("../testdata/initial-payment-fixture.json")).unwrap();
    let words = &f["publicInputs"].as_array().unwrap()[..16];
    let request = json!({"operation":"create-credit-initial-payment", "capacity":1,"context":f["context"],"words":words});
    assert!(authorization_digest(&request).is_ok());
}
#[test]
fn initial_payment_gas_preview_uses_measured_combined_receipt() {
    let q = json!({"kind":"create-credit-initial-payment","feeEnabled":true});
    let estimate = invisi_sdk::gas::estimate_gas(q.as_object().unwrap()).unwrap();
    assert_eq!(
        estimate.gas_units(),
        Some(alloy_primitives::U256::from(1_701_560))
    );
}

#[test]
#[ignore = "requires authenticated Core resource set via INVISI_INITIAL_PAYMENT_ASSETS"]
fn combined_resources_load_from_local_flat_directory_offline() {
    use invisi_sdk::prover::{Assets, ResourceOptions, ResourceProvider};
    let f: Value =
        serde_json::from_str(include_str!("../testdata/initial-payment-fixture.json")).unwrap();
    let statement = invisi_sdk::prover::statement(
        "create_credit_initial_payment",
        "evm",
        serde_json::from_value(f["publicInputs"].clone()).unwrap(),
    )
    .unwrap();
    let directory =
        std::env::var_os("INVISI_INITIAL_PAYMENT_ASSETS").expect("local Core resources required");
    let provider = ResourceProvider {
        options: ResourceOptions {
            directory: Some(directory.into()),
            offline: true,
            cache: std::env::temp_dir().join("invisi-rust-combined-resource-test"),
            ..Default::default()
        },
    };
    let (artifact, key) = provider.load(&statement).unwrap();
    assert!(!artifact.is_empty());
    assert!(!key.is_empty());
}
