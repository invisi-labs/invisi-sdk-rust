use alloy_primitives::{Address, B256};
use invisi_sdk_rpc::rpc::*;
struct Chain;
fn block(n: u64) -> CanonicalBlock {
    CanonicalBlock {
        number: n,
        hash: B256::repeat_byte(n as u8),
        parent_hash: B256::ZERO,
        timestamp: n,
    }
}
impl CanonicalChain for Chain {
    fn chain_id(&self) -> Result<u64> {
        Ok(1)
    }
    fn block(&self, n: u64) -> Result<CanonicalBlock> {
        Ok(block(n))
    }
    fn code_at(&self, _: Address, _: Option<u64>) -> Result<Vec<u8>> {
        Ok(vec![])
    }
    fn call(&self, _: Address, _: &[u8], _: u64) -> Result<Vec<u8>> {
        Ok(vec![])
    }
}
#[test]
fn custom_chain_native_capability_defaults_unsupported() {
    let got = read_chain_finality(&Chain);
    assert_eq!(got.finalized.status, FinalityStatus::Unsupported);
    assert!(got.finalized.block.is_none());
}
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
struct Native {
    lag: bool,
    unsupported: bool,
    reorg: AtomicBool,
    reads: AtomicUsize,
}
impl CanonicalChain for Native {
    fn chain_id(&self) -> Result<u64> {
        Ok(1)
    }
    fn block(&self, n: u64) -> Result<CanonicalBlock> {
        let mut b = block(n);
        if n == 4
            && self.reorg.load(Ordering::Relaxed)
            && self.reads.fetch_add(1, Ordering::Relaxed) > 0
        {
            b.hash = B256::repeat_byte(99)
        }
        Ok(b)
    }
    fn code_at(&self, _: Address, _: Option<u64>) -> Result<Vec<u8>> {
        Ok(vec![])
    }
    fn call(&self, _: Address, _: &[u8], _: u64) -> Result<Vec<u8>> {
        Ok(vec![])
    }
    fn block_by_tag(&self, tag: FinalityTag) -> Result<Option<CanonicalBlock>> {
        if self.unsupported {
            return Err(Error::FinalityUnsupported);
        }
        Ok(Some(block(match tag {
            FinalityTag::Latest => 10,
            FinalityTag::Safe => 8,
            FinalityTag::Finalized => {
                if self.lag {
                    3
                } else {
                    5
                }
            }
        })))
    }
    fn confirmation_receipt(&self, hash: B256) -> Result<Option<CanonicalReceipt>> {
        Ok(Some(CanonicalReceipt {
            transaction_hash: hash,
            block: block(4),
            success: true,
            logs: vec![],
        }))
    }
}
fn native() -> Native {
    Native {
        lag: false,
        unsupported: false,
        reorg: AtomicBool::new(false),
        reads: AtomicUsize::new(0),
    }
}
#[test]
fn native_finality_and_receipt_reorg_are_independent() {
    let chain = native();
    assert_eq!(
        read_chain_finality(&chain).finalized.block.unwrap().number,
        5
    );
    let got = read_transaction_confirmation(&chain, B256::repeat_byte(1)).unwrap();
    assert_eq!(got.level, ConfirmationLevel::Finalized);
    assert_eq!(got.status, FinalityStatus::Available);
    chain.reorg.store(true, Ordering::Relaxed);
    chain.reads.store(0, Ordering::Relaxed);
    let got = read_transaction_confirmation(&chain, B256::repeat_byte(1)).unwrap();
    assert_eq!(got.level, ConfirmationLevel::Pending);
    assert_eq!(got.status, FinalityStatus::Inconsistent);
}
#[test]
fn stalled_native_finality_does_not_upgrade() {
    let mut chain = native();
    chain.lag = true;
    let got = read_transaction_confirmation(&chain, B256::repeat_byte(1)).unwrap();
    assert_eq!(got.level, ConfirmationLevel::Safe);
    assert_eq!(got.status, FinalityStatus::Available);
}
use serde_json::{json, Value};
struct Source(Value);
impl RpcTransport for Source {
    fn send(&self, req: &Value) -> Result<Value> {
        Ok(json!({"jsonrpc":"2.0","id":req["id"],"result":self.0}))
    }
}
#[test]
fn service_finality_ahead_of_primary_is_unavailable_not_discovery_failure() {
    let deployment = ProtocolDeployment {
        chain_id: "1".into(),
        protocol: ContractDeployment {
            address: Address::repeat_byte(1),
            runtime_code_hash: B256::repeat_byte(2),
            from_block: 0,
        },
        registry: None,
        broadcaster_registry: None,
    };
    let head = |n| json!({"status":"available","block":block(n)});
    let source = Source(
        json!({"apiVersion":"v1","protocolVersion":"1","deployment":deployment,"indexedHead":block(2),"finality":{"latest":head(10),"safe":head(8),"finalized":head(8)}}),
    );
    let client = ProtocolRpcClient::new(source, native(), deployment).unwrap();
    let got = client.get_status().unwrap();
    assert_eq!(got.indexed_head.unwrap().number, 2);
    assert_eq!(
        got.finality.unwrap().finalized.status,
        FinalityStatus::Unavailable
    );
}
#[test]
fn broadcaster_confirmation_strictly_checks_wire_shape() {
    use invisi_sdk_rpc::broadcaster::Confirmation;
    let good = json!({"level":"finalized","status":"available","block":{"number":"10","hash":B256::repeat_byte(1),"timestamp":123}});
    assert!(serde_json::from_value::<Confirmation>(good.clone()).is_ok());
    for bad in [
        json!({"level":"finalized","status":"available","block":null}),
        json!({"level":"pending","status":"available","block":good["block"]}),
        json!({"level":"finalized","status":"guessed","block":good["block"]}),
        json!({"level":"included","status":"available","block":{"number":"01","hash":B256::repeat_byte(1),"timestamp":123}}),
    ] {
        assert!(serde_json::from_value::<Confirmation>(bad).is_err())
    }
}
struct RetryChain {
    calls: AtomicUsize,
    permanent: bool,
}
impl CanonicalChain for RetryChain {
    fn chain_id(&self) -> Result<u64> {
        Ok(1)
    }
    fn block(&self, n: u64) -> Result<CanonicalBlock> {
        Ok(block(n))
    }
    fn code_at(&self, _: Address, _: Option<u64>) -> Result<Vec<u8>> {
        Ok(vec![])
    }
    fn call(&self, _: Address, _: &[u8], _: u64) -> Result<Vec<u8>> {
        Ok(vec![])
    }
    fn block_by_tag(&self, tag: FinalityTag) -> Result<Option<CanonicalBlock>> {
        let mut b = block(match tag {
            FinalityTag::Latest => 10,
            FinalityTag::Safe => 8,
            FinalityTag::Finalized => 5,
        });
        if tag == FinalityTag::Safe
            && (self.calls.fetch_add(1, Ordering::Relaxed) == 0 || self.permanent)
        {
            b.hash = B256::repeat_byte(77)
        }
        Ok(Some(b))
    }
}
#[test]
fn incoherent_native_samples_retry_once_without_depth_fallback() {
    let chain = RetryChain {
        calls: AtomicUsize::new(0),
        permanent: false,
    };
    assert_eq!(
        read_chain_finality(&chain).safe.status,
        FinalityStatus::Available
    );
    assert_eq!(chain.calls.load(Ordering::Relaxed), 2);
    let chain = RetryChain {
        calls: AtomicUsize::new(0),
        permanent: true,
    };
    assert_eq!(
        read_chain_finality(&chain).safe.status,
        FinalityStatus::Inconsistent
    );
    assert_eq!(chain.calls.load(Ordering::Relaxed), 2);
}
