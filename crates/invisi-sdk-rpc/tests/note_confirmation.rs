use alloy_primitives::{Address, B256};
use invisi_sdk_rpc::rpc::*;
use serde_json::{json, Value};
struct Transport(Value);
impl RpcTransport for Transport {
    fn send(&self, request: &Value) -> Result<Value> {
        assert_eq!(request["method"], "invisi_getNote");
        assert!(
            [json!({"finality":"finalized"}), json!({"finality":"safe"})]
                .contains(&request["params"][1])
        );
        Ok(json!({"jsonrpc":"2.0", "id":request["id"], "result": self.0}))
    }
}
fn deployment() -> ProtocolDeployment {
    ProtocolDeployment {
        chain_id: "1".into(),
        protocol: ContractDeployment {
            address: Address::repeat_byte(1),
            runtime_code_hash: B256::repeat_byte(2),
            from_block: 1,
        },
        registry: None,
        broadcaster_registry: None,
    }
}
fn pending() -> Value {
    json!({"apiVersion":"v1","protocolVersion":"1","deployment":deployment(),
        "indexedHead":null,"status":"pending","reason":"not_observed",
        "output":null,"membership":null,"confirmation":null})
}
fn get(v: Value) -> Result<TrustedNoteLookup> {
    TrustedProtocolRpcClient::new(Transport(v), deployment())?
        .get_note(B256::with_last_byte(1), FinalityTag::Finalized)
}
#[test]
fn trusted_pending_uses_only_transport_without_chain() {
    assert!(matches!(
        get(pending()).unwrap(),
        TrustedNoteLookup::Pending { .. }
    ));
}
#[test]
fn rejects_invalid_pending_envelopes_and_deployments() {
    for (key, value) in [
        ("apiVersion", json!("v2")),
        ("reason", json!("unknown")),
        ("output", json!({})),
        ("confirmation", json!({})),
        ("membership", json!({})),
        ("deployment", json!(null)),
        ("status", json!("confirmed")),
    ] {
        let mut v = pending();
        v[key] = value;
        assert!(get(v).is_err(), "{key}");
    }
    let mut v = pending();
    v.as_object_mut().unwrap().remove("output");
    assert!(get(v).is_err());
    assert!(get(Value::Null).is_err());
}
fn block(n: u64) -> Value {
    json!({"number":n,"hash":B256::repeat_byte(n as u8),"parentHash":B256::repeat_byte((n-1) as u8),"timestamp":n*10})
}
fn confirmed() -> Value {
    let commitment = B256::with_last_byte(1);
    let mut root = invisi_sdk_rpc::field::bytes_to_field(commitment.as_slice());
    let zero = invisi_sdk_rpc::field::bytes_to_field(B256::ZERO.as_slice());
    for _ in 0..TREE_DEPTH {
        root = invisi_sdk_rpc::poseidon::hash(&[root, zero]);
    }
    let root = B256::from_slice(&invisi_sdk_rpc::field::field_to_bytes_be(root));
    json!({"apiVersion":"v1","protocolVersion":"1","deployment":deployment(),
        "indexedHead":block(5),"status":"confirmed","reason":null,
        "output":{"block":block(2),"treeId":1,"leafIndex":0,"commitment":commitment,
            "token":Address::repeat_byte(3),"transactionHash":B256::repeat_byte(9),"logIndex":0,
            "kind":"Shield","ciphertext":"0x","clue":"0x"},
        "membership":{"anchor":{"treeId":1,"root":root,"leafCount":1,"block":block(3)},
            "leafIndex":0,"commitment":commitment,"siblings":vec![B256::ZERO;TREE_DEPTH]},
        "confirmation":{"finality":"finalized","verifiedAt":block(5),"finalityHead":block(6)}})
}
#[test]
fn trusted_confirmed_checks_proof_without_chain() {
    let TrustedNoteLookup::Confirmed {
        membership,
        confirmation,
        ..
    } = get(confirmed()).unwrap()
    else {
        panic!()
    };
    assert_eq!(membership.block, confirmation.verified_at);
    assert_eq!(confirmation.finality, FinalityTag::Finalized);
}
#[test]
fn rejects_forged_proofs_finality_and_block_bindings() {
    let changes = [
        ("/membership/siblings/0", json!(B256::with_last_byte(2))),
        ("/membership/anchor/treeId", json!(2)),
        ("/membership/anchor/leafCount", json!(0)),
        ("/membership/commitment", json!(B256::with_last_byte(2))),
        ("/output/commitment", json!(B256::with_last_byte(2))),
        ("/confirmation/finality", json!("safe")),
        ("/confirmation/verifiedAt/hash", json!(B256::repeat_byte(8))),
        (
            "/confirmation/finalityHead/parentHash",
            json!(B256::repeat_byte(8)),
        ),
        ("/confirmation/verifiedAt", block(4)),
        ("/membership/anchor/block", block(1)),
        ("/output/block/timestamp", json!(1000)),
        ("/indexedHead/number", json!(9007199254740992_u64)),
        ("/deployment/chainId", json!("2")),
        ("/reason", json!("not_observed")),
    ];
    for (path, value) in changes {
        let mut v = confirmed();
        *v.pointer_mut(path).unwrap() = value;
        assert!(get(v).is_err(), "accepted {path}");
    }
}
#[test]
fn rejects_latest_before_transport() {
    let c = TrustedProtocolRpcClient::new(Transport(Value::Null), deployment()).unwrap();
    assert!(c
        .get_note(B256::with_last_byte(1), FinalityTag::Latest)
        .is_err());
    assert!(c.get_note(B256::ZERO, FinalityTag::Safe).is_err());
}

#[test]
fn trusted_safe_and_native_head_behind_index() {
    let mut v = confirmed();
    v["confirmation"]["finality"] = json!("safe");
    v["confirmation"]["verifiedAt"] = block(3);
    v["confirmation"]["finalityHead"] = block(3);
    let client = TrustedProtocolRpcClient::new(Transport(v), deployment()).unwrap();
    assert!(matches!(
        client
            .get_note(B256::with_last_byte(1), FinalityTag::Safe)
            .unwrap(),
        TrustedNoteLookup::Confirmed { .. }
    ));
}
#[test]
fn all_pending_reasons_are_explicit_and_empty() {
    for reason in [
        "not_observed",
        "pending_index",
        "confirmation_pending",
        "finality_unsupported",
        "finality_unavailable",
        "finality_inconsistent",
    ] {
        let mut v = pending();
        v["reason"] = json!(reason);
        assert!(get(v).is_ok());
    }
}
#[test]
fn independent_note_lookup_keeps_historic_selector_and_chain_verification() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    struct Chain(Arc<AtomicUsize>);
    impl CanonicalChain for Chain {
        fn chain_id(&self) -> Result<u64> {
            Ok(1)
        }
        fn block(&self, n: u64) -> Result<CanonicalBlock> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(CanonicalBlock::parse(&block(n))?)
        }
        fn code_at(&self, _: Address, _: Option<u64>) -> Result<Vec<u8>> {
            panic!("unexpected code read")
        }
        fn call(&self, _: Address, _: &[u8], _: u64) -> Result<Vec<u8>> {
            panic!("unexpected contract read")
        }
    }
    struct HistoricTransport;
    impl RpcTransport for HistoricTransport {
        fn send(&self, request: &Value) -> Result<Value> {
            let result = match request["method"].as_str().unwrap() {
                "invisi_getStatus" => {
                    json!({"apiVersion":"v1","protocolVersion":"1", "deployment":deployment(), "indexedHead":block(5)})
                }
                "invisi_getNote" => {
                    assert_eq!(request["params"][1], json!(5));
                    Value::Null
                }
                _ => panic!("unexpected RPC method"),
            };
            Ok(json!({"jsonrpc":"2.0","id":request["id"],"result":result}))
        }
    }
    let reads = Arc::new(AtomicUsize::new(0));
    let client =
        ProtocolRpcClient::new(HistoricTransport, Chain(reads.clone()), deployment()).unwrap();
    assert!(client
        .get_note(
            B256::with_last_byte(1),
            &CanonicalBlock::parse(&block(5)).unwrap()
        )
        .unwrap()
        .is_none());
    assert!(reads.load(Ordering::Relaxed) > 0);
}

#[test]
fn rpc_server_shared_fixture_is_compatible_without_chain() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/note-confirmation.json")).unwrap();
    // Pins are provided by the application, independently of the response.
    let pins = ProtocolDeployment {
        chain_id: "31337".into(),
        protocol: ContractDeployment {
            address: "0x0000000000000000000000000000000000001234"
                .parse()
                .unwrap(),
            runtime_code_hash: "0x000000000000000000000000000000000000000000000000000000000000abcd"
                .parse()
                .unwrap(),
            from_block: 8,
        },
        registry: None,
        broadcaster_registry: None,
    };
    let client = TrustedProtocolRpcClient::new(Transport(fixture), pins).unwrap();
    let TrustedNoteLookup::Confirmed {
        output,
        membership,
        confirmation,
        ..
    } = client
        .get_note(B256::with_last_byte(1), FinalityTag::Finalized)
        .unwrap()
    else {
        panic!("expected server confirmation")
    };
    assert_eq!(output.leaf.tree_id, 1);
    assert_eq!(membership.path.len(), TREE_DEPTH);
    assert_eq!(confirmation.verified_at.number, 10);
}

#[test]
fn rejects_zero_transaction_hash_and_repeated_hash_at_distinct_heights() {
    let mut v = confirmed();
    v["output"]["transactionHash"] = json!(B256::ZERO);
    assert!(get(v).is_err());
    let mut v = confirmed();
    // Keep timestamps and nonadjacent heights valid so only hash reuse contradicts the evidence.
    v["output"]["block"]["hash"] = v["indexedHead"]["hash"].clone();
    v["membership"]["anchor"]["block"]["parentHash"] = v["indexedHead"]["hash"].clone();
    assert!(get(v).is_err());
}
