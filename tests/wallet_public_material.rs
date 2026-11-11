use invisi_sdk::{
    address::ReceivingAddress,
    sdk::{Wallet, WalletRequest, WalletResponse},
};
use serde_json::Value;

#[test]
fn owner_only_input_is_rejected_but_standalone_short_addresses_remain_valid() {
    let owner = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf";
    assert!(Wallet::from_address(owner).is_err());
    assert!(ReceivingAddress::parse(owner)
        .unwrap()
        .encode()
        .unwrap()
        .starts_with("0x"));
    let q = invisi_sdk::sdk::prepare_wallet_request(
        owner.parse().unwrap(),
        "public",
        "wallet.public",
        serde_json::json!({}),
    )
    .unwrap();
    assert_eq!(q.owner_address, owner);
}

#[test]
fn fixed_public_material_roundtrips_and_is_owned() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/current-address.json")).unwrap();
    let address = fixture["longAddress"].as_str().unwrap();
    let wallet = Wallet::from_address(address).unwrap();
    assert_eq!(wallet.address().unwrap(), address);
    let mut keys = wallet.receiving_keys().clone();
    let rebuilt = Wallet::from_keys(wallet.owner_address(), keys.clone()).unwrap();
    keys.clue_key = [0; 32];
    assert!(Wallet::from_keys(wallet.owner_address(), keys).is_err());
    assert_eq!(rebuilt.address().unwrap(), address);
    let mut missing_viewing = wallet.receiving_keys().clone();
    missing_viewing.viewing_public_key = [0; 33];
    assert!(Wallet::from_keys(wallet.owner_address(), missing_viewing).is_err());
    let short = fixture["shortAddress"].as_str().unwrap();
    assert!(Wallet::from_address(short).is_err());
    let mut bad_checksum = short.to_owned();
    bad_checksum.replace_range(3..4, "e");
    assert!(Wallet::from_address(&bad_checksum).is_err());
}

#[test]
fn native_public_material_is_bound_to_owner_and_contains_no_secrets() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/wallet-wire-vectors.json")).unwrap();
    let case = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["request"]["method"] == "wallet.public")
        .unwrap();
    let request: WalletRequest = serde_json::from_value(case["request"].clone()).unwrap();
    let response: WalletResponse = serde_json::from_value(case["response"].clone()).unwrap();
    let wallet = Wallet::from_response(&request, &response).unwrap();
    assert_eq!(
        Wallet::from_address(&wallet.address().unwrap()).unwrap(),
        wallet
    );
    let debug = format!("{wallet:?}");
    for secret in ["private", "detection_key", "executor"] {
        assert!(!debug.contains(secret));
    }
    let mut mismatched = case["response"].clone();
    mismatched["result"]["spendingPublicKey"] = serde_json::json!("0x0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
    let mut wrong_request = request.clone();
    wrong_request.owner_address = "0x2b5ad5c4795c026514f8317c7a215e218dccd6cf".into();
    mismatched["ownerAddress"] = serde_json::json!(wrong_request.owner_address);
    assert!(
        Wallet::from_response(&wrong_request, &serde_json::from_value(mismatched).unwrap())
            .is_err()
    );
}

#[test]
fn independent_owner_helpers_keep_authorization_and_credit_receiving_key_pins() {
    use invisi_sdk::sdk::{accept_wallet_response, prepare_wallet_request, WalletResult};
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/wallet-wire-vectors.json")).unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let q: WalletRequest = serde_json::from_value(case["request"].clone()).unwrap();
        let r: WalletResponse = serde_json::from_value(case["response"].clone()).unwrap();
        let owner = q.owner_address.parse().unwrap();
        assert_eq!(
            prepare_wallet_request(owner, q.id.clone(), &q.method, q.params.clone())
                .unwrap()
                .as_value(),
            q.as_value()
        );
        match q.method.as_str() {
            "wallet.authorize" => assert!(matches!(
                accept_wallet_response(owner, None, &q, &r).unwrap(),
                WalletResult::Authorized(_)
            )),
            "wallet.decryptNote" => assert!(matches!(
                accept_wallet_response(owner, None, &q, &r).unwrap(),
                WalletResult::Note(_)
            )),
            "wallet.decryptCredit" => {
                assert!(matches!(
                    accept_wallet_response(owner, None, &q, &r).unwrap(),
                    WalletResult::Credit(_)
                ));
                let other = "0x0000000000000000000000000000000000000001";
                let mut wrong_owner_q = q.clone();
                wrong_owner_q.owner_address = other.into();
                let mut wrong_owner_r = r.clone();
                wrong_owner_r.owner_address = other.into();
                assert!(accept_wallet_response(
                    other.parse().unwrap(),
                    None,
                    &wrong_owner_q,
                    &wrong_owner_r
                )
                .is_err());
                for field in [
                    "chainId",
                    "protocolAddress",
                    "tokenAddress",
                    "outputCommitment",
                ] {
                    let mut wrong_context = q.clone();
                    wrong_context.params["context"][field] = if field == "outputCommitment" {
                        serde_json::json!(format!("0x{}", "01".repeat(32)))
                    } else {
                        serde_json::json!("2")
                    };
                    assert!(accept_wallet_response(owner, None, &wrong_context, &r).is_err());
                }
                let mut corrupt = case["response"].clone();
                let plain = corrupt["result"]["plaintext"].as_str().unwrap();
                let mut bytes = hex::decode(plain.strip_prefix("0x").unwrap()).unwrap();
                bytes[47] ^= 1;
                corrupt["result"]["plaintext"] =
                    serde_json::json!(format!("0x{}", hex::encode(bytes)));
                let corrupt: WalletResponse = serde_json::from_value(corrupt).unwrap();
                assert!(accept_wallet_response(owner, None, &q, &corrupt).is_err());
                let public_case = &fixture["cases"][0];
                let public_q = serde_json::from_value(public_case["request"].clone()).unwrap();
                let public_r = serde_json::from_value(public_case["response"].clone()).unwrap();
                let wallet = Wallet::from_response(&public_q, &public_r).unwrap();
                assert!(
                    accept_wallet_response(owner, Some(wallet.receiving_keys()), &q, &r).is_ok()
                );
                let mut wrong = wallet.receiving_keys().clone();
                let key = k256::SecretKey::from_slice(&[2; 32]).unwrap().public_key();
                use k256::elliptic_curve::sec1::ToEncodedPoint;
                wrong
                    .viewing_public_key
                    .copy_from_slice(key.to_encoded_point(true).as_bytes());
                assert!(accept_wallet_response(owner, Some(&wrong), &q, &r).is_err());
                let mismatched_wallet = Wallet::from_keys(owner, wrong).unwrap();
                assert!(mismatched_wallet.accept_response(&q, &r).is_err());
                assert!(wallet.accept_response(&q, &r).is_ok());
            }
            _ => {}
        }
    }
}
