use alloy_primitives::{Address, B256};
use invisi_sdk::broadcaster::{quote_digest, request_hash, verify_quote, SignedQuote, Trust};
#[test]
fn six_current_quote_and_request_hash_vectors_match_independent_typescript_reference() {
    let rows: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/broadcaster-vectors.json")).unwrap();
    for row in rows.as_array().unwrap() {
        let data = hex::decode(row["data"].as_str().unwrap().trim_start_matches("0x")).unwrap();
        let unsigned = hex::decode(
            row["unsignedVariant"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
        )
        .unwrap();
        let expected: B256 = row["requestHash"].as_str().unwrap().parse().unwrap();
        assert_eq!(request_hash(&data).unwrap(), expected);
        assert_eq!(request_hash(&unsigned).unwrap(), expected);
        let trust = Trust {
            chain_id: row["trust"]["chainId"].as_str().unwrap().parse().unwrap(),
            protocol: row["trust"]["protocol"]
                .as_str()
                .unwrap()
                .parse::<Address>()
                .unwrap(),
            signer: row["trust"]["signer"].as_str().unwrap().parse().unwrap(),
        };
        let signed: SignedQuote = serde_json::from_value(
            serde_json::json!({"quote":row["quote"],"signature":row["signature"]}),
        )
        .unwrap();
        assert_eq!(
            quote_digest(&signed.quote, &trust).unwrap(),
            row["quoteDigest"]
                .as_str()
                .unwrap()
                .parse::<B256>()
                .unwrap()
        );
        verify_quote(&signed, &trust, &data, 0).unwrap();
        let mut changed = signed.clone();
        changed.quote.fee_amount = "999".into();
        assert!(verify_quote(&changed, &trust, &data, 0).is_err());
    }
}

#[test]
fn quotes_reject_different_context_expiry_and_noncanonical_calldata() {
    let rows: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/broadcaster-vectors.json")).unwrap();
    let row = &rows[0];
    let mut data = hex::decode(row["data"].as_str().unwrap().trim_start_matches("0x")).unwrap();
    let trust = Trust {
        chain_id: 56,
        protocol: row["trust"]["protocol"].as_str().unwrap().parse().unwrap(),
        signer: row["trust"]["signer"].as_str().unwrap().parse().unwrap(),
    };
    let signed: SignedQuote = serde_json::from_value(
        serde_json::json!({"quote":row["quote"],"signature":row["signature"]}),
    )
    .unwrap();
    let mut changed = trust.clone();
    changed.chain_id += 1;
    assert!(verify_quote(&signed, &changed, &data, 0).is_err());
    changed = trust.clone();
    changed.protocol = Address::repeat_byte(9);
    assert!(verify_quote(&signed, &changed, &data, 0).is_err());
    changed = trust.clone();
    changed.signer = Address::repeat_byte(9);
    assert!(verify_quote(&signed, &changed, &data, 0).is_err());
    assert!(verify_quote(&signed, &trust, &data, u64::MAX).is_err());
    data.extend([0; 32]);
    assert!(request_hash(&data).is_err());
}
#[test]
fn client_verifies_registered_quote_and_submit_status_correlation() {
    use invisi_sdk::{
        broadcaster::{BroadcasterClient, Configuration},
        rpc::{Result, RpcTransport},
    };
    use serde_json::{json, Value};
    struct Transport {
        signed: Value,
    }
    impl RpcTransport for Transport {
        fn send(&self, r: &Value) -> Result<Value> {
            let result = match r["method"].as_str().unwrap() {
                "broadcaster_getQuote" => self.signed.clone(),
                "broadcaster_getFee" => {
                    json!({"feeRecipient":self.signed["quote"]["feeRecipient"],"feeAmount":"1","maxGas":"21000"})
                }
                "broadcaster_submitTransaction" => {
                    json!({"id":r["params"][0]["idempotencyKey"],"state":"pending"})
                }
                "broadcaster_getTransactionStatus" => {
                    json!({"id":"substituted","state":"confirmed"})
                }
                _ => panic!("unexpected broadcaster method"),
            };
            Ok(json!({"jsonrpc":"2.0","id":r["id"],"result":result}))
        }
    }
    let rows: Value =
        serde_json::from_str(include_str!("fixtures/broadcaster-vectors.json")).unwrap();
    let row = &rows[0];
    let data = hex::decode(row["data"].as_str().unwrap().trim_start_matches("0x")).unwrap();
    let configuration = Configuration {
        endpoint: "https://relay.example/rpc".into(),
        quote_signer: row["trust"]["signer"].as_str().unwrap().parse().unwrap(),
        fee_recipient: row["quote"]["feeRecipient"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap(),
    };
    let client = BroadcasterClient::new(
        configuration,
        Transport {
            signed: json!({"quote":row["quote"],"signature":row["signature"]}),
        },
    )
    .unwrap();
    let protocol = row["trust"]["protocol"].as_str().unwrap().parse().unwrap();
    let verified = client.quote(&data, 56, protocol, 0).unwrap();
    assert_eq!(
        client
            .fee(verified.signed().quote.token, None)
            .unwrap()
            .fee_amount,
        "1"
    );
    assert_eq!(
        client.submit(&data, &verified, "operation-1").unwrap().id,
        "operation-1"
    );
    assert!(client.status("operation-1").is_err());
    assert!(client.submit(&data, &verified, "").is_err());
}
