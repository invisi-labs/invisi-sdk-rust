use alloy_primitives::{keccak256, Address, B256};
use invisi_sdk::broadcaster::{
    quote_digest, request_hash, verify_quote, Quote, SignedQuote, Trust,
};
use invisi_sdk::broadcaster::{verify_quote_for_provenance, REQUEST_HASH_FORMAT};
#[test]
fn provenance_quote_binds_source_format_and_required_metadata() {
    let rows: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/broadcaster-vectors.json")).unwrap();
    let row = &rows[0];
    let data = hex::decode(row["data"].as_str().unwrap().trim_start_matches("0x")).unwrap();
    let key = k256::ecdsa::SigningKey::from_slice(&[0x11; 32]).unwrap();
    let public = key.verifying_key().to_encoded_point(false);
    let trust = Trust {
        chain_id: row["trust"]["chainId"].as_str().unwrap().parse().unwrap(),
        protocol: row["trust"]["protocol"].as_str().unwrap().parse().unwrap(),
        signer: Address::from_slice(&keccak256(&public.as_bytes()[1..])[12..]),
    };

    let mut quote: Quote = serde_json::from_value(row["quote"].clone()).unwrap();
    quote.request_hash = B256::from(invisi_sdk::provenance::provenance_intent_hash(
        request_hash(&data).unwrap().0,
    ));
    let (signature, recovery) = key
        .sign_prehash_recoverable(quote_digest(&quote, &trust).unwrap().as_slice())
        .unwrap();
    let mut bytes = signature.to_bytes().to_vec();
    bytes.push(recovery.to_byte());
    let s = SignedQuote {
        quote: quote.clone(),
        signature: format!("0x{}", hex::encode(bytes)),

        request_hash_format: Some(REQUEST_HASH_FORMAT.into()),
        provenance_required: Some(true),
    };
    verify_quote_for_provenance(&s, &trust, &data, 0, Some(())).unwrap();
    assert!(verify_quote(
        &SignedQuote {
            quote,
            signature: s.signature.clone(),

            request_hash_format: None,
            provenance_required: None,
        },
        &trust,
        &data,
        0
    )
    .is_err());
    assert!(serde_json::from_value::<SignedQuote>(serde_json::to_value(&s).unwrap()).is_ok());
    assert!(verify_quote(&s, &trust, &data, 0).is_ok());
}

#[test]
fn broadcaster_status_lookup_only_treats_current_unknown_request_code_as_missing() {
    struct ErrorTransport(i64);
    impl invisi_sdk::rpc::RpcTransport for ErrorTransport {
        fn send(&self, request: &serde_json::Value) -> invisi_sdk::rpc::Result<serde_json::Value> {
            assert_eq!(request["method"], "broadcaster_getTransactionStatus");
            Ok(
                serde_json::json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":self.0,"message":"Unknown request"}}),
            )
        }
    }
    for code in [-32001, -32000] {
        let client = invisi_sdk::broadcaster::BroadcasterClient::new(
            invisi_sdk::broadcaster::Configuration {
                endpoint: "https://relay.example".into(),
                quote_signer: Address::repeat_byte(1),
                fee_recipient: Address::repeat_byte(2),
            },
            ErrorTransport(code),
        )
        .unwrap();
        let result = client.lookup_status("stable-id");
        if code == -32001 {
            assert!(result.unwrap().is_none());
        } else {
            assert!(result.is_err());
        }
    }
}
