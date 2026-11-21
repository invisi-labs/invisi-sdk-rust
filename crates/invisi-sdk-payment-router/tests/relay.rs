use alloy_primitives::{keccak256, Address, Bytes, U256};
use alloy_sol_types::SolCall;
use invisi_sdk::broadcaster::{quote_digest, Execution, Quote, SignedQuote, Trust};
use invisi_sdk::rpc::RpcTransport;
use invisi_sdk_payment_router::{canonical::*, *};
use invisi_sdk_protocol::protocol::TransactionCall;
use k256::ecdsa::SigningKey;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
fn fixture() -> (Payment, RouterEnvelope) {
    let v: Value = serde_json::from_str(include_str!("fixtures/intent.json")).unwrap();
    let c = &v["cases"][2];
    let data = hex::decode(c["call"]["data"].as_str().unwrap().trim_start_matches("0x")).unwrap();
    let call = PaymentRouter::payTokenForCall::abi_decode_validate(&data).unwrap();
    let d = PaymentRouterDeployment {
        chain_id: 31337,
        core_address: Address::repeat_byte(0x11),
        router_address: Address::repeat_byte(0x33),
        weth_address: Address::repeat_byte(0x44),
        uniswap_router_address: Address::repeat_byte(0x55),
        runtime_code_hash: None,
        zero_ex: None,
    };
    let p = Payment::prepare(
        &d,
        TransactionCall {
            to: d.core_address,
            data: hex::decode(c["coreCalldata"].as_str().unwrap().trim_start_matches("0x"))
                .unwrap(),
            value: U256::ZERO,
        },
        call.i,
        call.route,
        1000,
        None,
    )
    .unwrap();
    let e = p.relay_envelope(call.permit, call.signature).unwrap();
    (p, e)
}
struct Transport {
    requests: Arc<Mutex<Vec<Value>>>,
    signed: SignedQuote,
}
impl RpcTransport for Transport {
    fn send(&self, r: &Value) -> invisi_sdk::rpc::Result<Value> {
        self.requests.lock().unwrap().push(r.clone());
        let result = match r["method"].as_str().unwrap() {
            "broadcaster_estimateQuote" => {
                json!({"feeRecipient":Address::repeat_byte(0xbb),"feeAmount":"200000","maxGas":"1000000"})
            }
            "broadcaster_getQuote" => json!(self.signed),
            "broadcaster_submitTransaction" => json!({"id":"test-submission"}),
            _ => panic!("unexpected method"),
        };
        Ok(json!({"jsonrpc":"2.0","id":r["id"],"result":result}))
    }
}
#[test]
fn relay_wire_quote_validation_and_tampering() {
    let (p, e) = fixture();
    let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
    let signer = Address::from_slice(
        &keccak256(&key.verifying_key().to_encoded_point(false).as_bytes()[1..])[12..],
    );
    let trust = Trust {
        chain_id: 31337,
        protocol: p.core().to,
        signer,
    };
    let q = Quote {
        schedule: None,
        execution: Execution::Direct,
        token: p.request().params.token,
        fee_recipient: p.request().params.feeRecipient,
        fee_amount: p.request().params.feeAmount.to_string(),
        deadline: "1800000000".into(),
        max_gas: "1000000".into(),
        request_hash: envelope_hash(31337, trust.protocol, &e).unwrap(),
    };
    let (sig, id) = key
        .sign_prehash_recoverable(quote_digest(&q, &trust).unwrap().as_slice())
        .unwrap();
    let mut raw = sig.to_bytes().to_vec();
    raw.push(id.to_byte() + 27);
    let signed = SignedQuote {
        quote: q,
        signature: format!("0x{}", hex::encode(raw)),
        request_hash_format: Some(ENVELOPE_HASH_FORMAT.into()),
        provenance_required: Some(true),
    };
    let requests = Arc::new(Mutex::new(vec![]));
    let client = RouterRelayClient::new(
        Transport {
            requests: requests.clone(),
            signed: signed.clone(),
        },
        trust,
        Address::repeat_byte(0xbb),
    )
    .unwrap();
    client.estimate_quote(&p, &e).unwrap();
    let q = client.get_quote(&p, &e, 1000).unwrap();
    client.submit_transaction(&p, &e, &q, 1000, &[]).unwrap();
    let req = requests.lock().unwrap();
    for r in req.iter() {
        assert_eq!(
            r["params"][0]["data"],
            format!("0x{}", hex::encode(&p.core().data))
        );
        assert_eq!(r["params"][0]["router"], json!(e));
    }
    assert_eq!(req[2]["params"][0]["quote"], json!(q.quote));
    assert_eq!(req[2]["params"][0]["signature"], q.signature);
    drop(req);
    for provenance in [Some(true), Some(false), None] {
        let mut advertised = q.clone();
        advertised.provenance_required = provenance;
        client.verify_quote(&p, &e, &advertised, 1000).unwrap();
    }
    let mut bad = q.clone();
    bad.request_hash_format = None;
    assert!(client.verify_quote(&p, &e, &bad, 1000).is_err());
    bad = q.clone();
    bad.quote.execution = Execution::Aggregate;
    assert!(client.verify_quote(&p, &e, &bad, 1000).is_err());
    bad = q.clone();
    bad.quote.fee_amount = "200001".into();
    assert!(client.verify_quote(&p, &e, &bad, 1000).is_err());
    bad = q.clone();
    bad.quote.deadline = "999".into();
    assert!(client.verify_quote(&p, &e, &bad, 1000).is_err());
    let mut changed = e.clone();
    changed.to = Address::repeat_byte(0xff);
    assert!(client.verify_quote(&p, &changed, &q, 1000).is_err());
    changed = e.clone();
    changed.data = Bytes::from(vec![1, 2, 3, 4]);
    assert!(client.verify_quote(&p, &changed, &q, 1000).is_err());
    changed = e.clone();
    changed.value = "1".into();
    assert!(client.verify_quote(&p, &changed, &q, 1000).is_err());
}
