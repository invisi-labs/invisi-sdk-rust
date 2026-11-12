use alloy_primitives::{Address, U256};
use invisi_sdk::{
    note::{Note, ProtocolContext},
    sdk::PaymentNote,
};
#[test]
fn portable_ipn_is_fixed_canonical_and_binds_opening() {
    let note = Note {
        context: ProtocolContext {
            chain_id: 97,
            protocol_address: U256::from_be_slice(Address::repeat_byte(0x11).as_slice()),
        },
        owner_address: U256::from_be_slice(Address::repeat_byte(0x11).as_slice()),
        token_address: U256::from_be_slice(Address::repeat_byte(0x11).as_slice()),
        amount: U256::from(70),
        nonce: U256::ZERO,
        payload: vec![9],
    };
    let payment = PaymentNote::from_note(&note).unwrap();
    let ipn = payment.encode();
    assert_eq!(ipn.len(), 203);
    let decoded = PaymentNote::decode(&ipn).unwrap();
    assert_eq!(decoded.note().amount, note.amount);
    assert!(decoded.note().payload.is_empty());
    assert_eq!(decoded.encode(), ipn);
    assert!(PaymentNote::decode(&(ipn.clone() + "=")).is_err());
    let mut bytes =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &ipn[4..])
            .unwrap();
    bytes[64] ^= 1;
    let tampered = format!(
        "ipn:{}",
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
    );
    assert!(PaymentNote::decode(&tampered).is_err());
}

#[test]
fn shared_typescript_go_payment_note_bytes_match_all_fixtures() {
    use base64::Engine;
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/payment-notes.json")).unwrap();
    for fixture in fixtures.as_array().unwrap() {
        let encoded = fixture["encoded"].as_str().unwrap();
        let note = PaymentNote::decode(encoded).unwrap();
        assert_eq!(note.encode(), encoded, "{}", fixture["name"]);
        assert_eq!(
            format!("{:#x}", note.commitment()),
            fixture["note"]["commitment"].as_str().unwrap()
        );
        assert_eq!(
            note.note().context.chain_id.to_string(),
            fixture["note"]["chainId"].as_str().unwrap()
        );
        assert_eq!(
            note.note().amount.to_string(),
            fixture["note"]["amount"].as_str().unwrap()
        );
        assert_eq!(
            note.note().nonce.to_string(),
            fixture["note"]["nonce"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(&encoded[4..])
                    .unwrap()
            ),
            fixture["binaryHex"].as_str().unwrap()
        );
    }
}
