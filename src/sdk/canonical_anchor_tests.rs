use super::*;
use crate::rpc::{ContractDeployment, EthereumChain, RpcTransport};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct Transport(Arc<Mutex<CanonicalBlock>>);
impl RpcTransport for Transport {
    fn send(&self, request: &Value) -> crate::rpc::Result<Value> {
        assert_eq!(request["method"], "eth_getBlockByNumber");
        assert_eq!(request["params"][0], "0xa");
        let block = self.0.lock().unwrap();
        Ok(
            serde_json::json!({"jsonrpc":"2.0","id":request["id"],"result":{
                "number":format!("0x{:x}",block.number),
                "hash":block.hash,
                "parentHash":block.parent_hash,
                "timestamp":format!("0x{:x}",block.timestamp)
            }}),
        )
    }
}
fn fixture() -> (
    RpcChainState<EthereumChain<Transport>>,
    Arc<Mutex<CanonicalBlock>>,
) {
    let block = Arc::new(Mutex::new(CanonicalBlock {
        number: 10,
        hash: B256::repeat_byte(10),
        parent_hash: B256::repeat_byte(9),
        timestamp: 1_800_000_000,
    }));
    let chain = RpcChainState {
        chain: EthereumChain::new(Transport(block.clone())),
        deployment: ProtocolDeployment {
            chain_id: "97".into(),
            protocol: ContractDeployment {
                address: Address::repeat_byte(1),
                runtime_code_hash: B256::repeat_byte(2),
                from_block: 1,
            },
            registry: None,
            broadcaster_registry: None,
        },
    };
    (chain, block)
}
#[test]
fn certificate_anchor_accepts_real_header_metadata_without_zero_padding() {
    let (chain, block) = fixture();
    let actual = block.lock().unwrap().clone();
    chain.canonical_anchor(actual.number, actual.hash).unwrap();
    chain.canonical(&actual).unwrap();
    let padded = CanonicalBlock {
        parent_hash: B256::ZERO,
        timestamp: 0,
        ..actual
    };
    assert!(chain.canonical(&padded).is_err());
}
#[test]
fn certificate_anchor_rechecks_detect_a_changed_canonical_hash() {
    let (chain, block) = fixture();
    let hash = block.lock().unwrap().hash;
    chain.canonical_anchor(10, hash).unwrap();
    block.lock().unwrap().hash = B256::repeat_byte(11);
    assert_eq!(
        chain.canonical_anchor(10, hash).unwrap_err(),
        "chain reorganization"
    );
}
#[test]
fn certificate_anchor_rejects_rpc_wrong_height_even_with_matching_hash() {
    let (chain, block) = fixture();
    let hash = block.lock().unwrap().hash;
    block.lock().unwrap().number = 11;
    assert!(chain.canonical_anchor(10, hash).is_err());
}
