use alloy_primitives::U256;
use invisi_sdk::{delivery::*, disclosure::*};
use serde_json::Value;
#[test]
fn disclosure_openings_and_payload_keys_are_scoped() {
    let f: Value = serde_json::from_str(include_str!("fixtures/wallet-wire-vectors.json")).unwrap();
    for case in f["cases"].as_array().unwrap() {
        let method = case["request"]["method"].as_str().unwrap();
        if method != "wallet.decryptNote" && method != "wallet.decryptCredit" {
            continue;
        }
        let c = &case["request"]["params"]["context"];
        let mut scoped = c.clone();
        scoped.as_object_mut().unwrap().remove("role");
        let context: DeliveryContext = serde_json::from_value(scoped).unwrap();
        let plain = hex::decode(
            case["response"]["result"]["plaintext"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
        )
        .unwrap();
        let role = if method == "wallet.decryptNote" {
            DisclosureRole::Funds
        } else {
            DisclosureRole::Owner
        };
        let disclosure = if role == DisclosureRole::Funds {
            Disclosure::from_note(&decode_note(&plain, &context).unwrap()).unwrap()
        } else {
            Disclosure::from_credit(&decode_credit(&plain, &context).unwrap().note).unwrap()
        };
        let output = DisclosureOutput {
            context: context.clone(),
            role,
            ciphertext: None,
        };
        let exported = disclosure.export();
        assert!(!serde_json::to_string(&exported)
            .unwrap()
            .contains("creditSharedKey\""));
        let imported = Disclosure::from_export(exported).unwrap();
        assert!(imported.verify(&output).is_ok());
        let mut wrong = output.clone();
        wrong.context.token_address = U256::from(1);
        assert!(imported.verify(&wrong).is_err());
        assert!(!format!("{:?}", disclosure).contains("payloadKey"));
    }
}
#[test]
fn payload_key_disclosure_checks_independent_ciphertext_and_role() {
    let f: Value = serde_json::from_str(include_str!("fixtures/wallet-wire-vectors.json")).unwrap();
    let mut account = [0; 32];
    account[31] = 1;
    let view = invisi_sdk::wallet::viewing_key(&account).unwrap();
    let owner = U256::from_str_radix("7e5f4552091a69125d5dfcb7b8c2659029395bdf", 16).unwrap();
    for case in f["cases"].as_array().unwrap() {
        let method = case["request"]["method"].as_str().unwrap();
        if method != "wallet.decryptNote" && method != "wallet.decryptCredit" {
            continue;
        }
        let mut c = case["request"]["params"]["context"].clone();
        c.as_object_mut().unwrap().remove("role");
        let context: DeliveryContext = serde_json::from_value(c).unwrap();
        let role = if method == "wallet.decryptNote" {
            DisclosureRole::Funds
        } else {
            DisclosureRole::Owner
        };
        let envelope = hex::decode(
            case["request"]["params"]["envelope"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
        )
        .unwrap();
        let disclosure =
            Disclosure::from_encrypted(&*view, &envelope, &context, role, owner).unwrap();
        let exported = disclosure.export();
        assert_eq!(exported.method, DisclosureMethod::PayloadKey);
        let imported = Disclosure::from_export(exported).unwrap();
        let mut output = DisclosureOutput {
            context,
            role,
            ciphertext: Some(envelope),
        };
        assert!(imported.verify(&output).is_ok());
        let bytes = output.ciphertext.as_mut().unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert!(imported.verify(&output).is_err());
    }
}

#[test]
fn disclosures_require_nonzero_deployment_and_token() {
    use invisi_sdk::note::{Note, ProtocolContext};
    let mut note = Note {
        context: ProtocolContext {
            chain_id: 1,
            protocol_address: U256::ZERO,
        },
        owner_address: U256::from(1),
        token_address: U256::from(2),
        amount: U256::from(3),
        nonce: U256::from(4),
        payload: vec![],
    };
    assert!(Disclosure::from_note(&note).is_err());
    note.context.protocol_address = U256::from(1);
    note.token_address = U256::ZERO;
    assert!(Disclosure::from_note(&note).is_err());
}
