use alloy_primitives::{Address, B256};
use invisi_sdk_rpc::rpc::*;
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
fn block() -> CanonicalBlock {
    CanonicalBlock {
        number: 10,
        hash: B256::with_last_byte(10),
        parent_hash: B256::with_last_byte(9),
        timestamp: 10,
    }
}
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
#[derive(Default)]
struct Counts {
    status: AtomicUsize,
    roots: AtomicUsize,
    known: AtomicUsize,
    paths: AtomicUsize,
    headers: AtomicUsize,
    chain_ids: AtomicUsize,
    reorg: AtomicBool,
}
struct Chain(Arc<Counts>);
impl CanonicalChain for Chain {
    fn chain_id(&self) -> Result<u64> {
        self.0.chain_ids.fetch_add(1, Ordering::SeqCst);
        Ok(97)
    }
    fn block(&self, number: u64) -> Result<CanonicalBlock> {
        self.0.headers.fetch_add(1, Ordering::SeqCst);
        let mut b = block();
        b.number = number;
        b.hash = B256::with_last_byte(number as u8);
        b.parent_hash = B256::with_last_byte(number.saturating_sub(1) as u8);
        b.timestamp = number;
        if self.0.reorg.load(Ordering::SeqCst) {
            b.hash = B256::ZERO;
        }
        Ok(b)
    }
    fn code_at(&self, _: Address, _: Option<u64>) -> Result<Vec<u8>> {
        unreachable!()
    }
    fn call(&self, _: Address, _: &[u8], n: u64) -> Result<Vec<u8>> {
        assert_eq!(n, 10);
        self.0.known.fetch_add(1, Ordering::SeqCst);
        let mut out = vec![0; 32];
        out[31] = 1;
        Ok(out)
    }
}
struct Transport {
    counts: Arc<Counts>,
    tamper: bool,
    reorg: bool,
    bad_status: bool,
}
fn root() -> B256 {
    static ROOT: std::sync::OnceLock<B256> = std::sync::OnceLock::new();
    *ROOT.get_or_init(|| {
        let mut value = invisi_sdk_rpc::field::bytes_to_field(B256::with_last_byte(1).as_slice());
        let zero = invisi_sdk_rpc::field::bytes_to_field(B256::ZERO.as_slice());
        for _ in 0..TREE_DEPTH {
            value = invisi_sdk_rpc::poseidon::hash(&[value, zero]);
        }
        B256::from_slice(&invisi_sdk_rpc::field::field_to_bytes_be(value))
    })
}
fn anchor() -> Value {
    json!({"treeId":1,"root":root(),"leafCount":1,"block":block()})
}
impl RpcTransport for Transport {
    fn send(&self, q: &Value) -> Result<Value> {
        let value = match q["method"].as_str().unwrap() {
            "invisi_getStatus" => {
                self.counts.status.fetch_add(1, Ordering::SeqCst);
                json!({"apiVersion":if self.bad_status {"v2"}else{"v1"},"protocolVersion":"1","deployment":deployment(),"indexedHead":block()})
            }
            "invisi_getRoots" => {
                self.counts.roots.fetch_add(1, Ordering::SeqCst);
                json!([anchor()])
            }
            "invisi_getMembership" => {
                let n = self.counts.paths.fetch_add(1, Ordering::SeqCst);
                let mut siblings = vec![B256::ZERO; TREE_DEPTH];
                if self.tamper && n == 1 {
                    siblings[0] = B256::with_last_byte(2);
                }
                if self.reorg && n == 1 {
                    self.counts.reorg.store(true, Ordering::SeqCst);
                }
                json!({"anchor":anchor(),"leafIndex":0,"commitment":B256::with_last_byte(1),"siblings":siblings})
            }
            _ => unreachable!(),
        };
        Ok(json!({"jsonrpc":"2.0","id":q["id"],"result":value}))
    }
}
fn input() -> MembershipInput {
    MembershipInput {
        tree_id: 1,
        leaf_index: 0,
        commitment: B256::with_last_byte(1),
        root: None,
    }
}
#[test]
fn batch_shares_evidence_but_checks_every_path_and_fences_reorgs() {
    for (tamper, reorg, bad_status) in [
        (false, false, false),
        (true, false, false),
        (false, true, false),
        (false, false, true),
    ] {
        let counts = Arc::new(Counts::default());
        let client = ProtocolRpcClient::new(
            Transport {
                counts: counts.clone(),
                tamper,
                reorg,
                bad_status,
            },
            Chain(counts.clone()),
            deployment(),
        )
        .unwrap();
        let result = client.get_memberships(&[input(), input()], &block());
        if tamper || reorg || bad_status {
            assert!(result.is_err());
        } else {
            let proofs = result.unwrap();
            assert_eq!(proofs.len(), 2);
            assert_eq!(proofs[0].root, root());
            assert_eq!(counts.roots.load(Ordering::SeqCst), 1);
            assert_eq!(counts.known.load(Ordering::SeqCst), 1);
            assert_eq!(counts.paths.load(Ordering::SeqCst), 2);
        }
        assert_eq!(counts.status.load(Ordering::SeqCst), 1);
    }
}
#[test]
fn batch_cap_rejects_before_io() {
    let counts = Arc::new(Counts::default());
    let client = ProtocolRpcClient::new(
        Transport {
            counts: counts.clone(),
            tamper: false,
            reorg: false,
            bad_status: false,
        },
        Chain(counts.clone()),
        deployment(),
    )
    .unwrap();
    assert!(client
        .get_memberships(&vec![input(); 257], &block())
        .is_err());
    assert_eq!(counts.status.load(Ordering::SeqCst), 0);
}

#[test]
#[ignore = "request-count and local wall-time benchmark; run with --ignored --nocapture"]
fn benchmark_membership_evidence() {
    for size in [1, 8, 32, 128, 256] {
        for batch in [false, true] {
            let counts = Arc::new(Counts::default());
            let client = ProtocolRpcClient::new(
                Transport {
                    counts: counts.clone(),
                    tamper: false,
                    reorg: false,
                    bad_status: false,
                },
                Chain(counts.clone()),
                deployment(),
            )
            .unwrap();
            let start = std::time::Instant::now();
            if batch {
                assert_eq!(
                    client
                        .get_memberships(&vec![input(); size], &block())
                        .unwrap()
                        .len(),
                    size
                );
            } else {
                for _ in 0..size {
                    client.get_membership(&input(), &block()).unwrap();
                }
            }
            let elapsed = start.elapsed();
            let status = counts.status.load(Ordering::SeqCst);
            let roots = counts.roots.load(Ordering::SeqCst);
            let known = counts.known.load(Ordering::SeqCst);
            let paths = counts.paths.load(Ordering::SeqCst);
            assert_eq!(status, if batch { 1 } else { size });
            assert_eq!(roots, status);
            assert_eq!(known, status);
            assert_eq!(paths, size);
            println!("memberships={size} batch={batch} status={status} roots={roots} known_root={known} paths={paths} indexed_and_contract_requests={} canonical_headers={} chain_ids={} local_us={}",status+roots+known+paths,counts.headers.load(Ordering::SeqCst),counts.chain_ids.load(Ordering::SeqCst),elapsed.as_micros());
        }
    }
}

#[test]
fn conflicting_explicit_roots_fail_before_io() {
    let counts = Arc::new(Counts::default());
    let client = ProtocolRpcClient::new(
        Transport {
            counts: counts.clone(),
            tamper: false,
            reorg: false,
            bad_status: false,
        },
        Chain(counts.clone()),
        deployment(),
    )
    .unwrap();
    let mut a = input();
    a.root = Some(B256::with_last_byte(1));
    let mut b = input();
    b.root = Some(B256::with_last_byte(2));
    assert!(client.get_memberships(&[a, b], &block()).is_err());
    assert_eq!(counts.status.load(Ordering::SeqCst), 0);
}

struct TwoLeaves;
fn two_leaf_proof(index: u32) -> (B256, Vec<B256>) {
    let leaf = B256::with_last_byte(index as u8 + 1);
    let mut path = vec![B256::ZERO; TREE_DEPTH];
    path[0] = B256::with_last_byte(2 - index as u8);
    let mut value = invisi_sdk_rpc::field::bytes_to_field(leaf.as_slice());
    for (level, sibling) in path.iter().enumerate() {
        let sibling = invisi_sdk_rpc::field::bytes_to_field(sibling.as_slice());
        value = if index >> level & 1 == 0 {
            invisi_sdk_rpc::poseidon::hash(&[value, sibling])
        } else {
            invisi_sdk_rpc::poseidon::hash(&[sibling, value])
        };
    }
    (
        B256::from_slice(&invisi_sdk_rpc::field::field_to_bytes_be(value)),
        path,
    )
}
impl RpcTransport for TwoLeaves {
    fn send(&self, q: &Value) -> Result<Value> {
        let (root, path) = two_leaf_proof(q["params"][1].as_u64().unwrap_or(0) as u32);
        let mut older = block();
        older.number = 9;
        older.hash = B256::with_last_byte(9);
        older.parent_hash = B256::with_last_byte(8);
        older.timestamp = 9;
        let anchor = json!({"treeId":1,"root":root,"leafCount":2,"block":older});
        let value = match q["method"].as_str().unwrap() {
            "invisi_getStatus" => {
                json!({"apiVersion":"v1","protocolVersion":"1","deployment":deployment(),"indexedHead":block()})
            }
            "invisi_getRoots" => {
                json!([anchor,{"treeId":1,"root":B256::with_last_byte(3),"leafCount":1,"block":block()}])
            }
            "invisi_getMembership" => {
                assert_eq!(
                    q["params"][2],
                    json!(root),
                    "every path must use a root covering highest leaf"
                );
                let index = q["params"][1].as_u64().unwrap();
                json!({"anchor":anchor,"leafIndex":index,"commitment":B256::with_last_byte(index as u8+1),"siblings":path})
            }
            _ => unreachable!(),
        };
        Ok(json!({"jsonrpc":"2.0","id":q["id"],"result":value}))
    }
}
#[test]
fn highest_leaf_sets_common_root_and_preserves_caller_order() {
    for indices in [[0, 1], [1, 0]] {
        let client =
            ProtocolRpcClient::new(TwoLeaves, Chain(Arc::new(Counts::default())), deployment())
                .unwrap();
        let inputs = indices.map(|index| MembershipInput {
            tree_id: 1,
            leaf_index: index,
            commitment: B256::with_last_byte(index as u8 + 1),
            root: None,
        });
        let proofs = client.get_memberships(&inputs, &block()).unwrap();
        assert_eq!(
            proofs.iter().map(|p| p.leaf_index).collect::<Vec<_>>(),
            indices
        );
        assert_eq!(proofs[0].root, proofs[1].root);
    }
}
