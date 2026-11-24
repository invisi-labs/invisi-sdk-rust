use alloy_primitives::Address;
use invisi_sdk_rpc::broadcaster::{
    fee_lock_digest, verify_fee_lock, FeeLock, SignedFeeLock, Trust,
};
#[test]
fn frozen_tariff_golden_and_rejection() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/fee-lock-vector.json")).unwrap();
    let trust = Trust {
        chain_id: 31337,
        protocol: v["trust"]["protocol"].as_str().unwrap().parse().unwrap(),
        signer: v["trust"]["signer"].as_str().unwrap().parse().unwrap(),
    };
    let lock: FeeLock = serde_json::from_value(v["lock"].clone()).unwrap();
    let mut ticket = SignedFeeLock {
        lock,
        signature: v["signature"].as_str().unwrap().to_owned(),
    };
    assert_eq!(
        format!("{}", fee_lock_digest(&ticket.lock, &trust).unwrap()),
        v["digest"].as_str().unwrap()
    );
    let token: Address = ticket.lock.token;
    let recipient = ticket.lock.fee_recipient;
    verify_fee_lock(&ticket, &trust, token, recipient, 1900000000).unwrap();
    assert!(verify_fee_lock(&ticket, &trust, token, recipient, 2000000000).is_err());
    ticket.lock.gas_price = "1".into();
    assert!(verify_fee_lock(&ticket, &trust, token, recipient, 1900000000).is_err());
}

#[test]
fn client_negotiates_and_carries_same_tariff_without_changing_legacy_requests() {
    use invisi_sdk_rpc::{
        broadcaster::{BroadcasterClient, Configuration},
        rpc::{Result, RpcTransport},
    };
    use serde_json::{json, Value};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };
    #[derive(Clone)]
    struct Transport {
        v: Value,
        seen: Arc<Mutex<Vec<Value>>>,
        advertised: Arc<AtomicBool>,
    }
    impl RpcTransport for Transport {
        fn send(&self, request: &Value) -> Result<Value> {
            self.seen.lock().unwrap().push(request.clone());
            let v = &self.v;
            let result = match request["method"].as_str().unwrap() {
                "broadcaster_getStatus" => {
                    let mut status = json!({"apiVersion":"v1","protocolVersion":"1","chainId":v["trust"]["chainId"],"protocol":v["trust"]["protocol"],"sender":v["trust"]["signer"],"feeRecipient":v["lock"]["feeRecipient"],"submissionHalted":false});
                    if self.advertised.load(Ordering::SeqCst) {
                        status["feeLock"] = json!({"version":"1","model":"core-gas-v1.3.4","core":true,"router":false});
                    }
                    status
                }
                "broadcaster_lockFee" => json!({"lock":v["lock"],"signature":v["signature"]}),
                "broadcaster_estimateQuote" => {
                    json!({"feeRecipient":v["lock"]["feeRecipient"],"feeAmount":"2","maxGas":"100000"})
                }
                "broadcaster_getQuote" => v["quote"].clone(),
                other => panic!("unexpected method {other}"),
            };
            Ok(json!({"jsonrpc":"2.0","id":request["id"],"result":result}))
        }
    }
    let v: Value = serde_json::from_str(include_str!("fixtures/fee-lock-vector.json")).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let advertised = Arc::new(AtomicBool::new(true));
    let config = Configuration {
        endpoint: "https://relay.test".into(),
        quote_signer: v["trust"]["signer"].as_str().unwrap().parse().unwrap(),
        fee_recipient: v["lock"]["feeRecipient"].as_str().unwrap().parse().unwrap(),
    };
    let token = v["lock"]["token"].as_str().unwrap().parse().unwrap();
    let protocol = v["trust"]["protocol"].as_str().unwrap().parse().unwrap();
    let data = hex::decode(v["data"].as_str().unwrap().trim_start_matches("0x")).unwrap();
    let client = BroadcasterClient::new(
        config.clone(),
        Transport {
            v: v.clone(),
            seen: seen.clone(),
            advertised: advertised.clone(),
        },
    )
    .unwrap();
    assert!(client.initialize_fee_lock(31337, protocol).unwrap());
    assert!(client.initialize_fee_lock(31337, protocol).unwrap());
    let lock = client
        .lock_fee(&data, 31337, protocol, 1900000000)
        .unwrap()
        .unwrap();
    client
        .fee_with_schedule_and_lock(token, Some(&data), None, Some(&lock))
        .unwrap();
    client
        .quote_with_schedule_and_lock(&data, 31337, protocol, 1900000000, &[], None, Some(&lock))
        .unwrap();
    client.estimate_quote(&data).unwrap();
    advertised.store(false, Ordering::SeqCst);
    // Stable capabilities and an authenticated unexpired tariff belong to this client.
    assert_eq!(
        client
            .lock_fee(&data, 31337, protocol, 1900000001)
            .unwrap()
            .unwrap()
            .signed(),
        lock.signed()
    );
    let legacy_seen = Arc::new(Mutex::new(Vec::new()));
    let legacy = BroadcasterClient::new(
        config,
        Transport {
            v: v.clone(),
            seen: legacy_seen.clone(),
            advertised: advertised.clone(),
        },
    )
    .unwrap();
    assert!(!legacy.initialize_fee_lock(31337, protocol).unwrap());
    assert!(legacy
        .lock_fee(&data, 31337, protocol, 1900000000)
        .unwrap()
        .is_none());
    assert_eq!(legacy_seen.lock().unwrap().len(), 1);
    let requests = seen.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|r| r["method"] == "broadcaster_getStatus")
            .count(),
        1
    );
    let pricing: Vec<_> = requests
        .iter()
        .filter(|r| {
            r["method"] == "broadcaster_estimateQuote" || r["method"] == "broadcaster_getQuote"
        })
        .collect();
    assert_eq!(
        pricing[0]["params"][0]["feeLock"]["signature"],
        v["signature"]
    );
    assert_eq!(
        pricing[1]["params"][0]["feeLock"]["signature"],
        v["signature"]
    );
    assert!(pricing[2]["params"][0].get("feeLock").is_none());
    assert_eq!(
        requests
            .iter()
            .filter(|r| r["method"] == "broadcaster_lockFee")
            .count(),
        1
    );
}

#[test]
fn expired_cached_tariff_is_refetched_and_invalid_response_never_downgrades() {
    use invisi_sdk_rpc::{
        broadcaster::{BroadcasterClient, Configuration},
        rpc::{Result, RpcTransport},
    };
    use serde_json::{json, Value};
    use std::sync::{Arc, Mutex};
    struct Transport {
        v: Value,
        locks: Arc<Mutex<usize>>,
    }
    impl RpcTransport for Transport {
        fn send(&self, request: &Value) -> Result<Value> {
            let result = if request["method"] == "broadcaster_getStatus" {
                json!({"apiVersion":"v1","protocolVersion":"1","chainId":"31337","protocol":self.v["trust"]["protocol"],"sender":self.v["trust"]["signer"],"feeRecipient":self.v["lock"]["feeRecipient"],"submissionHalted":false,"feeLock":{"version":"1","model":"core-gas-v1.3.4","core":true,"router":false}})
            } else {
                assert_eq!(request["method"], "broadcaster_lockFee");
                *self.locks.lock().unwrap() += 1;
                json!({"lock":self.v["lock"],"signature":self.v["signature"]})
            };
            Ok(json!({"jsonrpc":"2.0","id":request["id"],"result":result}))
        }
    }
    let v: Value = serde_json::from_str(include_str!("fixtures/fee-lock-vector.json")).unwrap();
    let locks = Arc::new(Mutex::new(0));
    let protocol = v["trust"]["protocol"].as_str().unwrap().parse().unwrap();
    let data = hex::decode(v["data"].as_str().unwrap().trim_start_matches("0x")).unwrap();
    let client = BroadcasterClient::new(
        Configuration {
            endpoint: "https://relay.test".into(),
            quote_signer: v["trust"]["signer"].as_str().unwrap().parse().unwrap(),
            fee_recipient: v["lock"]["feeRecipient"].as_str().unwrap().parse().unwrap(),
        },
        Transport {
            v,
            locks: locks.clone(),
        },
    )
    .unwrap();
    assert!(client
        .lock_fee(&data, 31337, protocol, 1900000000)
        .unwrap()
        .is_some());
    assert!(client.lock_fee(&data, 31338, protocol, 1900000000).is_err());
    assert!(client
        .lock_fee(&data, 31337, Address::repeat_byte(9), 1900000000)
        .is_err());
    assert!(client.lock_fee(&data, 31337, protocol, 2000000000).is_err());
    assert!(client.lock_fee(&data, 31337, protocol, 2000000000).is_err());
    assert_eq!(*locks.lock().unwrap(), 3);
}

mod cache_races {
    use super::*;
    use invisi_sdk_rpc::{
        broadcaster::{BroadcasterClient, Configuration},
        rpc::{Result, RpcTransport},
    };
    use serde_json::{json, Value};
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    };
    type Hook = Arc<dyn Fn(&Value) + Send + Sync>;
    struct State {
        v: Value,
        hook: Mutex<Option<Hook>>,
        calls: Mutex<Vec<String>>,
        locks: AtomicUsize,
        reject_estimate: AtomicBool,
        legacy_status: AtomicBool,
    }
    struct Transport(Arc<State>);
    impl RpcTransport for Transport {
        fn send(&self, request: &Value) -> Result<Value> {
            let method = request["method"].as_str().unwrap();
            self.0.calls.lock().unwrap().push(method.into());
            let hook = self.0.hook.lock().unwrap().clone();
            if let Some(hook) = hook {
                hook(request)
            }
            let v = &self.0.v;
            let result = match method {
                "broadcaster_getStatus" | "broadcaster_getTokenSupport" => {
                    let mut result = json!({"apiVersion":"v1","protocolVersion":"1","chainId":"31337","protocol":v["trust"]["protocol"],"sender":v["trust"]["signer"],"feeRecipient":v["lock"]["feeRecipient"],"submissionHalted":false,"provenance":{"enabled":false},"supported":true,"tokenAddress":request["params"][0]["tokenAddress"]});
                    if method != "broadcaster_getStatus"
                        || !self.0.legacy_status.load(Ordering::SeqCst)
                    {
                        result["feeLock"] = json!({"version":"1","model":"core-gas-v1.3.4","core":true,"router":false});
                    }
                    result
                }
                "broadcaster_lockFee" => {
                    let n = self.0.locks.fetch_add(1, Ordering::SeqCst) + 1;
                    let mut ticket: SignedFeeLock = serde_json::from_value(
                        json!({"lock":v["lock"],"signature":v["signature"]}),
                    )
                    .unwrap();
                    ticket.lock.gas_price = n.to_string();
                    let trust: Trust = Trust {
                        chain_id: 31337,
                        protocol: v["trust"]["protocol"].as_str().unwrap().parse().unwrap(),
                        signer: v["trust"]["signer"].as_str().unwrap().parse().unwrap(),
                    };
                    let (sig, id) = k256::ecdsa::SigningKey::from_slice(&[0x11; 32])
                        .unwrap()
                        .sign_prehash_recoverable(
                            fee_lock_digest(&ticket.lock, &trust).unwrap().as_slice(),
                        )
                        .unwrap();
                    let mut bytes = sig.to_bytes().to_vec();
                    bytes.push(id.to_byte());
                    ticket.signature = format!("0x{}", hex::encode(bytes));
                    json!(ticket)
                }
                "broadcaster_getQuote" => {
                    return Ok(
                        json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":-32042,"message":"FEE_LOCK_GAS_EXCEEDED"}}),
                    )
                }
                "broadcaster_estimateQuote" if self.0.reject_estimate.load(Ordering::SeqCst) => {
                    return Ok(
                        json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":-32042,"message":"FEE_LOCK_GAS_EXCEEDED"}}),
                    )
                }
                "broadcaster_estimateQuote" => {
                    json!({"feeRecipient":v["lock"]["feeRecipient"],"feeAmount":"2","maxGas":"100000"})
                }
                _ => panic!("unexpected method {method}"),
            };
            Ok(json!({"jsonrpc":"2.0","id":request["id"],"result":result}))
        }
    }
    fn fixture() -> (
        Arc<BroadcasterClient<Transport>>,
        Arc<State>,
        Vec<u8>,
        Address,
        Address,
    ) {
        let v: Value = serde_json::from_str(include_str!("fixtures/fee-lock-vector.json")).unwrap();
        let protocol = v["trust"]["protocol"].as_str().unwrap().parse().unwrap();
        let token = v["lock"]["token"].as_str().unwrap().parse().unwrap();
        let data = hex::decode(v["data"].as_str().unwrap().trim_start_matches("0x")).unwrap();
        let config = Configuration {
            endpoint: "https://relay.test".into(),
            quote_signer: v["trust"]["signer"].as_str().unwrap().parse().unwrap(),
            fee_recipient: v["lock"]["feeRecipient"].as_str().unwrap().parse().unwrap(),
        };
        let state = Arc::new(State {
            v,
            hook: Default::default(),
            calls: Default::default(),
            locks: 0.into(),
            reject_estimate: false.into(),
            legacy_status: false.into(),
        });
        (
            Arc::new(BroadcasterClient::new(config, Transport(state.clone())).unwrap()),
            state,
            data,
            protocol,
            token,
        )
    }
    #[test]
    fn validated_support_primes_capabilities_without_duplicate_status_or_cross_client_ticket_use() {
        let (client, state, data, protocol, token) = fixture();
        assert!(client.supports_token(token, 31337, protocol).unwrap());
        let ticket = client
            .lock_fee(&data, 31337, protocol, 1900000000)
            .unwrap()
            .unwrap();
        assert!(client.initialize_fee_lock(31337, protocol).unwrap());
        assert_eq!(
            *state.calls.lock().unwrap(),
            vec!["broadcaster_getTokenSupport", "broadcaster_lockFee"]
        );
        let (foreign, _, _, _, _) = fixture();
        assert!(foreign
            .fee_with_schedule_and_lock(token, Some(&data), None, Some(&ticket))
            .is_err());
    }
    #[test]
    fn reentrant_transport_reinitialization_fences_old_acquisition_and_late_legacy_probe() {
        let (client, state, data, protocol, token) = fixture();
        client.initialize_fee_lock(31337, protocol).unwrap();
        let weak = Arc::downgrade(&client);
        let once = Arc::new(AtomicBool::new(false));
        *state.hook.lock().unwrap() = Some(Arc::new(move |request| {
            if request["method"] == "broadcaster_lockFee" && !once.swap(true, Ordering::SeqCst) {
                assert!(weak
                    .upgrade()
                    .unwrap()
                    .supports_token(token, 31337, protocol)
                    .unwrap());
            }
        }));
        assert!(client
            .lock_fee(&data, 31337, protocol, 1900000000)
            .unwrap_err()
            .to_string()
            .contains("superseded"));
        *state.hook.lock().unwrap() = None;
        assert!(client
            .lock_fee(&data, 31337, protocol, 1900000000)
            .unwrap()
            .is_some());
        assert_eq!(state.locks.load(Ordering::SeqCst), 2);
        let ticket = client
            .lock_fee(&data, 31337, protocol, 1900000000)
            .unwrap()
            .unwrap();
        let weak = Arc::downgrade(&client);
        *state.hook.lock().unwrap() = Some(Arc::new(move |request| {
            if request["method"] == "broadcaster_estimateQuote" {
                assert!(weak
                    .upgrade()
                    .unwrap()
                    .supports_token(token, 31337, protocol)
                    .unwrap());
            }
        }));
        assert!(client
            .fee_with_schedule_and_lock(token, Some(&data), None, Some(&ticket))
            .unwrap_err()
            .to_string()
            .contains("lifetime"));
        *state.hook.lock().unwrap() = None;

        let (client, state, data, protocol, token) = fixture();
        state.legacy_status.store(true, Ordering::SeqCst);
        let weak = Arc::downgrade(&client);
        *state.hook.lock().unwrap() = Some(Arc::new(move |request| {
            if request["method"] == "broadcaster_getStatus" {
                assert!(weak
                    .upgrade()
                    .unwrap()
                    .supports_token(token, 31337, protocol)
                    .unwrap());
            }
        }));
        assert!(client.lock_fee(&data, 31337, protocol, 1900000000).is_err());
        *state.hook.lock().unwrap() = None;
        assert!(client
            .lock_fee(&data, 31337, protocol, 1900000000)
            .unwrap()
            .is_some());
        assert_eq!(state.locks.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn delayed_old_gas_refusal_cannot_evict_a_newer_ticket() {
        let (client, state, data, protocol, token) = fixture();
        let old = client
            .lock_fee(&data, 31337, protocol, 1900000000)
            .unwrap()
            .unwrap();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let release_rx = Mutex::new(release_rx);
        *state.hook.lock().unwrap() = Some(Arc::new(move |request| {
            if request["method"] == "broadcaster_getQuote" {
                entered_tx.send(()).unwrap();
                release_rx.lock().unwrap().recv().unwrap();
            }
        }));
        let task_client = client.clone();
        let task_data = data.clone();
        let task_old = old.clone();
        let task = std::thread::spawn(move || {
            task_client
                .quote_with_schedule_and_lock(
                    &task_data,
                    31337,
                    protocol,
                    1900000000,
                    &[],
                    None,
                    Some(&task_old),
                )
                .unwrap_err()
        });
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        state.reject_estimate.store(true, Ordering::SeqCst);
        assert!(client
            .fee_with_schedule_and_lock(token, Some(&data), None, Some(&old))
            .is_err());
        let new = client
            .lock_fee(&data, 31337, protocol, 1900000000)
            .unwrap()
            .unwrap();
        assert_ne!(old.signed(), new.signed());
        release_tx.send(()).unwrap();
        task.join().unwrap();
        assert_eq!(
            client
                .lock_fee(&data, 31337, protocol, 1900000000)
                .unwrap()
                .unwrap()
                .signed(),
            new.signed()
        );
        assert_eq!(state.locks.load(Ordering::SeqCst), 2);
    }
    #[test]
    fn provenance_policy_transition_retires_tickets_but_noop_preserves_lifetime() {
        let (client, state, data, protocol, token) = fixture();
        let client = Arc::try_unwrap(client).ok().unwrap();
        let old = client
            .lock_fee(&data, 31337, protocol, 1900000000)
            .unwrap()
            .unwrap();
        let client = client.with_provenance_mode();
        assert!(
            client
                .fee_with_schedule_and_lock(token, Some(&data), None, Some(&old))
                .is_err(),
            "policy change retained old fee-lock authority"
        );
        let new = client
            .lock_fee(&data, 31337, protocol, 1900000000)
            .unwrap()
            .unwrap();
        assert_eq!(state.locks.load(Ordering::SeqCst), 2);
        let calls = state.calls.lock().unwrap().len();
        let client = client.with_provenance_mode();
        assert_eq!(
            client
                .lock_fee(&data, 31337, protocol, 1900000000)
                .unwrap()
                .unwrap()
                .signed(),
            new.signed()
        );
        assert_eq!(state.calls.lock().unwrap().len(), calls);
        client
            .fee_with_schedule_and_lock(token, Some(&data), None, Some(&new))
            .unwrap();
    }
}
