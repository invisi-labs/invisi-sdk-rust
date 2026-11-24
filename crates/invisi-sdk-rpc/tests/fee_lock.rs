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
        config,
        Transport {
            v: v.clone(),
            seen: seen.clone(),
            advertised: advertised.clone(),
        },
    )
    .unwrap();
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
    assert!(client
        .lock_fee(&data, 31337, protocol, 1900000000)
        .unwrap()
        .is_none());
    let requests = seen.lock().unwrap();
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
