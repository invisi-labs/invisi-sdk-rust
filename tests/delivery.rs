use alloy_primitives::U256;
use invisi_sdk::delivery::*;
use invisi_sdk::note::ProtocolContext;
use serde_json::Value;
#[test]
fn current_delivery_vectors_and_roundtrip() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/wallet-note-vectors.json")).unwrap();
    let n = |s: &str| {
        if let Some(x) = s.strip_prefix("0x") {
            U256::from_str_radix(x, 16).unwrap()
        } else {
            U256::from_str_radix(s, 10).unwrap()
        }
    };
    let mut context = DeliveryContext {
        context: ProtocolContext {
            chain_id: 31337,
            protocol_address: U256::from(4660),
        },
        token_address: U256::from(22136),
        output_commitment: n(fixture["note"]["commitment"].as_str().unwrap()),
    };
    let key = hex::decode(
        fixture["owner"]["viewingPrivateKey"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
    )
    .unwrap();
    let public = hex::decode(
        fixture["owner"]["viewingPublicKey"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
    )
    .unwrap();
    let owner = n(fixture["owner"]["ownerAddress"].as_str().unwrap());
    let envelope = hex::decode(
        fixture["note"]["ciphertext"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
    )
    .unwrap();
    let note = decrypt_note(&key, &envelope, &context, owner).unwrap();
    assert_eq!(note.amount, U256::from(70));
    let sealed = encrypt_note(&public, &note, &context).unwrap();
    assert_ne!(sealed, envelope);
    assert_eq!(decrypt_note(&key, &sealed, &context, owner).unwrap(), note);
    context.output_commitment = n(fixture["credit"]["commitment"].as_str().unwrap());
    let envelope = hex::decode(
        fixture["credit"]["ownerCiphertext"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
    )
    .unwrap();
    let state = decrypt_credit(&key, &envelope, &context, CreditRole::Owner, owner).unwrap();
    let sealed = encrypt_credit(&public, &state, &context, CreditRole::Owner).unwrap();
    assert_eq!(
        decrypt_credit(&key, &sealed, &context, CreditRole::Owner, owner).unwrap(),
        state
    );
    let mut bad = context.clone();
    bad.output_commitment = U256::from(1);
    assert!(decrypt_credit(&key, &sealed, &bad, CreditRole::Owner, owner).is_err());
    assert!(decrypt_credit(&key, &sealed, &context, CreditRole::Spender, owner).is_err());
}

#[test]
fn viewing_key_encoding_is_exactly_32_bytes() {
    let f: Value = serde_json::from_str(include_str!("fixtures/wallet-note-vectors.json")).unwrap();
    let envelope = hex::decode(
        f["note"]["ciphertext"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
    )
    .unwrap();
    assert!(payload_key(&[1u8; 31], &envelope, false).is_err());
}
