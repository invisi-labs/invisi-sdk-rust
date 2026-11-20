use alloy_primitives::{Address, B256};
use invisi_sdk_rpc::rpc::*;
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
fn deployment() -> ProtocolDeployment {
    ProtocolDeployment {
        chain_id: "97".into(),
        protocol: ContractDeployment {
            address: Address::with_last_byte(1),
            runtime_code_hash: B256::with_last_byte(2),
            from_block: 1,
        },
        registry: None,
        broadcaster_registry: None,
    }
}
fn block(n: u64) -> CanonicalBlock {
    CanonicalBlock {
        number: n,
        hash: B256::with_last_byte(n as u8),
        parent_hash: B256::with_last_byte((n - 1) as u8),
        timestamp: n,
    }
}
struct Chain;
impl CanonicalChain for Chain {
    fn chain_id(&self) -> Result<u64> {
        Ok(97)
    }
    fn block(&self, n: u64) -> Result<CanonicalBlock> {
        Ok(block(n))
    }
    fn code_at(&self, _: Address, _: Option<u64>) -> Result<Vec<u8>> {
        unreachable!()
    }
    fn call(&self, _: Address, _: &[u8], _: u64) -> Result<Vec<u8>> {
        unreachable!()
    }
}
struct Transport {
    reads: Arc<AtomicUsize>,
    wrong_anchor: bool,
}
impl RpcTransport for Transport {
    fn send(&self, q: &Value) -> Result<Value> {
        let value = match q["method"].as_str().unwrap() {
            "invisi_getStatus" => {
                self.reads.fetch_add(1, Ordering::SeqCst);
                json!({"apiVersion":"v1","protocolVersion":"1","deployment":deployment(),"indexedHead":block(10)})
            }
            "invisi_getNoteUpdates" => {
                json!({"notes":[],"blockHash":if self.wrong_anchor {B256::ZERO}else{block(10).hash}})
            }
            "invisi_getCreditTransitions" => json!([]),
            _ => unreachable!(),
        };
        Ok(json!({"jsonrpc":"2.0","id":q["id"],"result":value}))
    }
}
#[test]
fn combined_history_reuses_one_authenticated_status_and_keeps_anchor_checks() {
    for wrong_anchor in [false, true] {
        let reads = Arc::new(AtomicUsize::new(0));
        let c = ProtocolRpcClient::new(
            Transport {
                reads: reads.clone(),
                wrong_anchor,
            },
            Chain,
            deployment(),
        )
        .unwrap();
        let result = c.get_history_updates(1, 10);
        if wrong_anchor {
            assert!(result.is_err());
        } else {
            let (notes, credits) = result.unwrap();
            assert_eq!(notes.block, credits.block);
            assert!(notes.items.is_empty() && credits.items.is_empty());
        }
        assert_eq!(reads.load(Ordering::SeqCst), 1);
    }
}
