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

struct GrantTransport {
    token: Address,
    status: Value,
    wrong_block: bool,
}
impl RpcTransport for GrantTransport {
    fn send(&self, q: &Value) -> Result<Value> {
        let value = match q["method"].as_str().unwrap() {
            "invisi_getStatus" => {
                json!({"apiVersion":"v1","protocolVersion":"1","deployment":deployment(),"indexedHead":block(10)})
            }
            "invisi_getCreditStatus" => {
                assert_eq!(
                    q["params"],
                    json!([
                        Address::with_last_byte(2),
                        self.token,
                        u128::MAX.to_string(),
                        10
                    ])
                );
                json!({"block":block(if self.wrong_block {9}else{10}),"status":self.status})
            }
            _ => unreachable!(),
        };
        Ok(json!({"jsonrpc":"2.0","id":q["id"],"result":value}))
    }
}
#[test]
fn credit_status_pins_the_scope_full_id_and_exact_canonical_block() {
    for status in [0, 1, 2] {
        let client = ProtocolRpcClient::new(
            GrantTransport {
                token: Address::with_last_byte(3),
                status: json!(status),
                wrong_block: false,
            },
            Chain,
            deployment(),
        )
        .unwrap();
        let observation = client
            .get_credit_status(
                Address::with_last_byte(2),
                Address::with_last_byte(3),
                u128::MAX,
                &block(10),
            )
            .unwrap();
        assert_eq!(observation.status, status);
        assert_eq!(observation.block, block(10));
    }
    for (status, wrong_block) in [
        (json!(3), false),
        (json!(-1), false),
        (json!("1"), false),
        (json!(1), true),
    ] {
        let client = ProtocolRpcClient::new(
            GrantTransport {
                token: Address::with_last_byte(3),
                status,
                wrong_block,
            },
            Chain,
            deployment(),
        )
        .unwrap();
        assert!(client
            .get_credit_status(
                Address::with_last_byte(2),
                Address::with_last_byte(3),
                u128::MAX,
                &block(10)
            )
            .is_err());
    }
    let client = ProtocolRpcClient::new(
        GrantTransport {
            token: Address::with_last_byte(3),
            status: json!(0),
            wrong_block: false,
        },
        Chain,
        deployment(),
    )
    .unwrap();
    assert!(client
        .get_credit_status(
            Address::with_last_byte(2),
            Address::with_last_byte(3),
            0,
            &block(10)
        )
        .is_err());
}

#[test]
fn native_credit_status_accepts_zero_token_and_keeps_scope_guards() {
    let client = ProtocolRpcClient::new(
        GrantTransport {
            token: Address::ZERO,
            status: json!(1),
            wrong_block: false,
        },
        Chain,
        deployment(),
    )
    .unwrap();
    let status = client
        .get_credit_status(
            Address::with_last_byte(2),
            Address::ZERO,
            u128::MAX,
            &block(10),
        )
        .unwrap();
    assert_eq!(status.status, 1);
    assert_eq!(status.block, block(10));
    assert!(client
        .get_credit_status(Address::ZERO, Address::ZERO, u128::MAX, &block(10))
        .is_err());
    assert!(client
        .get_credit_status(Address::with_last_byte(2), Address::ZERO, 0, &block(10))
        .is_err());
    let wrong_block = ProtocolRpcClient::new(
        GrantTransport {
            token: Address::ZERO,
            status: json!(1),
            wrong_block: true,
        },
        Chain,
        deployment(),
    )
    .unwrap();
    assert!(wrong_block
        .get_credit_status(
            Address::with_last_byte(2),
            Address::ZERO,
            u128::MAX,
            &block(10)
        )
        .is_err());
}
