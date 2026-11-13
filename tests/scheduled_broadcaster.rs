use alloy_primitives::{keccak256, Address, B256};
use invisi_sdk_rpc::broadcaster::{quote_digest, Quote, Schedule, Trust};
#[test]
fn scheduled_quote_matches_go_vector_and_binds_every_field() {
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/scheduled-quote.json")).unwrap();
    let quote: Quote = serde_json::from_value(vector["quote"].clone()).unwrap();
    let trust = Trust {
        chain_id: 31337,
        protocol: Address::repeat_byte(0x11),
        signer: Address::repeat_byte(1),
    };
    assert_eq!(
        quote_digest(&quote, &trust).unwrap().to_string(),
        vector["digest"].as_str().unwrap()
    );
    assert_eq!(
        quote.schedule.as_ref().unwrap().cancel_token_hash,
        keccak256([0x55; 32])
    );
    let mut changed = quote.clone();
    changed.schedule.as_mut().unwrap().execute_before = "2000000401".into();
    assert_ne!(
        quote_digest(&quote, &trust).unwrap(),
        quote_digest(&changed, &trust).unwrap()
    );
    changed.schedule = None;
    assert_ne!(
        quote_digest(&quote, &trust).unwrap(),
        quote_digest(&changed, &trust).unwrap()
    );
}
#[test]
fn schedule_rejects_unsafe_noncanonical_or_unordered_times() {
    for after in ["0", "01", "+1", "9007199254740992", "18446744073709551616"] {
        assert!(Schedule {
            publish_after: after.into(),
            execute_before: "2000000400".into(),
            cancel_token_hash: B256::repeat_byte(1)
        }
        .validate()
        .is_err());
    }
    assert!(Schedule {
        publish_after: "2".into(),
        execute_before: "2".into(),
        cancel_token_hash: B256::repeat_byte(1)
    }
    .validate()
    .is_err());
}
#[test]
fn cancellation_debug_is_redacted() {
    let token = invisi_sdk::sdk::CancellationToken::generate();
    assert_eq!(format!("{token:?}"), "CancellationToken([REDACTED])");
    assert_ne!(token.commitment(), B256::ZERO);
}

#[test]
fn advertised_limits_are_configurable_and_deadline_covers_execution() {
    use alloy_primitives::U256;
    use invisi_sdk_rpc::broadcaster::SchedulingCapability;
    let capability = SchedulingCapability {
        enabled: true,
        max_delay_seconds: "1209600".into(),
        default_execution_window_seconds: "300".into(),
        max_execution_window_seconds: "3600".into(),
        min_deadline_slack_seconds: "120".into(),
    };
    let schedule = Schedule {
        publish_after: "900000".into(),
        execute_before: "900300".into(),
        cancel_token_hash: B256::repeat_byte(1),
    };
    capability
        .validate_schedule(&schedule, 1, U256::from(900420))
        .unwrap();
    assert!(capability
        .validate_schedule(&schedule, 1, U256::from(900419))
        .is_err());
    let mut disabled = capability.clone();
    disabled.enabled = false;
    assert!(disabled
        .validate_schedule(&schedule, 1, U256::from(900420))
        .is_err());
}

#[test]
fn schedule_wire_rejects_noncanonical_hash_and_accepts_new_statuses() {
    let valid = serde_json::json!({"publishAfter":"1","executeBefore":"2","cancelTokenHash":format!("{}", B256::repeat_byte(0xab))});
    let _: Schedule = serde_json::from_value(valid.clone()).unwrap();
    let mut invalid = valid;
    invalid["cancelTokenHash"] = serde_json::json!(format!("0x{}", "AB".repeat(32)));
    assert!(serde_json::from_value::<Schedule>(invalid).is_err());
    for state in ["scheduled", "preparing", "cancelled"] {
        serde_json::from_value::<invisi_sdk_rpc::broadcaster::Status>(
            serde_json::json!({"id":"id","state":state}),
        )
        .unwrap();
    }
}

#[test]
fn cancellation_rpc_uses_only_scoped_id_and_preimage() {
    use invisi_sdk_rpc::{
        broadcaster::{BroadcasterClient, Configuration},
        rpc::{Result, RpcTransport},
    };
    struct Transport;
    impl RpcTransport for Transport {
        fn send(&self, request: &serde_json::Value) -> Result<serde_json::Value> {
            assert_eq!(request["method"], "broadcaster_cancelTransaction");
            assert_eq!(
                request["params"],
                serde_json::json!([{"id":"scheduled-id","cancelToken":B256::repeat_byte(0x55)}])
            );
            Ok(
                serde_json::json!({"jsonrpc":"2.0","id":request["id"],"result":{"id":"scheduled-id","state":"cancelled"}}),
            )
        }
    }
    let relay = BroadcasterClient::new(
        Configuration {
            endpoint: "https://relay.example".into(),
            quote_signer: Address::repeat_byte(1),
            fee_recipient: Address::repeat_byte(2),
        },
        Transport,
    )
    .unwrap();
    assert_eq!(
        relay
            .cancel("scheduled-id", B256::repeat_byte(0x55))
            .unwrap()
            .state,
        invisi_sdk_rpc::broadcaster::StatusState::Cancelled
    );
}

#[test]
fn scheduled_submit_accepts_opaque_server_id_and_replays_identical_frozen_payload() {
    use invisi_sdk_rpc::{
        broadcaster::{BroadcasterClient, Configuration, Execution, SignedQuote, VerifiedQuote},
        rpc::{Error, Result, RpcTransport},
    };
    use std::sync::{Arc, Mutex};
    #[derive(Clone)]
    struct Transport(Arc<Mutex<Vec<serde_json::Value>>>);
    impl RpcTransport for Transport {
        fn send(&self, request: &serde_json::Value) -> Result<serde_json::Value> {
            assert_eq!(request["method"], "broadcaster_submitTransaction");
            let mut requests = self.0.lock().unwrap();
            if let Some(first) = requests.first() {
                assert_eq!(first, &request["params"]);
            }
            requests.push(request["params"].clone());
            if requests.len() == 1 {
                return Err(Error::Transport("accepted but response lost".into()));
            }
            Ok(
                serde_json::json!({"jsonrpc":"2.0","id":request["id"],"result":{"id":"server-assigned/opaque-job-93","state":"scheduled"}}),
            )
        }
    }
    let rows: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/broadcaster-vectors.json")).unwrap();
    let row = &rows[0];
    let data = hex::decode(row["data"].as_str().unwrap().trim_start_matches("0x")).unwrap();
    let mut quote: Quote = serde_json::from_value(row["quote"].clone()).unwrap();
    quote.execution = Execution::Direct;
    quote.schedule = Some(Schedule {
        publish_after: "2000000100".into(),
        execute_before: "2000000400".into(),
        cancel_token_hash: keccak256([0x55; 32]),
    });
    let trust = Trust {
        chain_id: row["trust"]["chainId"].as_str().unwrap().parse().unwrap(),
        protocol: row["trust"]["protocol"].as_str().unwrap().parse().unwrap(),
        signer: row["trust"]["signer"].as_str().unwrap().parse().unwrap(),
    };
    let private =
        hex::decode(row["privateKey"].as_str().unwrap().trim_start_matches("0x")).unwrap();
    let signing = k256::ecdsa::SigningKey::from_slice(&private).unwrap();
    let (signature, recovery) = signing
        .sign_prehash_recoverable(quote_digest(&quote, &trust).unwrap().as_slice())
        .unwrap();
    let mut signature = signature.to_bytes().to_vec();
    signature.push(recovery.to_byte());
    let signed = SignedQuote {
        quote,
        signature: format!("0x{}", hex::encode(signature)),
        request_hash_format: None,
        provenance_required: None,
    };
    let verified = VerifiedQuote::authenticate(signed, trust.clone(), &data, 0, None).unwrap();
    let transport = Transport(Arc::new(Mutex::new(Vec::new())));
    let relay = BroadcasterClient::new(
        Configuration {
            endpoint: "https://relay.example".into(),
            quote_signer: trust.signer,
            fee_recipient: verified.signed().quote.fee_recipient,
        },
        transport.clone(),
    )
    .unwrap();
    assert!(relay.submit(&data, &verified).is_err());
    let accepted = relay.submit(&data, &verified).unwrap();
    assert_eq!(accepted.id, "server-assigned/opaque-job-93");
    assert_eq!(transport.0.lock().unwrap().len(), 2);
}
