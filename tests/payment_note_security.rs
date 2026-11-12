use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_sol_types::SolCall;
use invisi_sdk::{
    note::{Note, ProtocolContext},
    protocol::InvisiProtocol,
    rpc::{
        CanonicalBlock, CanonicalChain, ContractDeployment, Error, FinalityTag, ProtocolDeployment,
        ProtocolRpcClient, Result, RpcTransport,
    },
    sdk::{PaymentNote, Wallet},
};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
fn block(number: u64) -> CanonicalBlock {
    CanonicalBlock {
        number,
        hash: B256::with_last_byte(number as u8),
        parent_hash: B256::with_last_byte(number.saturating_sub(1) as u8),
        timestamp: 100 + number,
    }
}
fn deployment() -> ProtocolDeployment {
    ProtocolDeployment {
        chain_id: "97".into(),
        protocol: ContractDeployment {
            address: Address::with_last_byte(1),
            runtime_code_hash: keccak256([0x60, 0]),
            from_block: 1,
        },
        registry: None,
        broadcaster_registry: None,
    }
}
struct Index {
    commitment: B256,
    root: B256,
    spent_queries: Arc<AtomicUsize>,
}
impl RpcTransport for Index {
    fn send(&self, r: &Value) -> Result<Value> {
        let anchor = json!({"treeId":1,"root":self.root,"leafCount":1,"block":block(10)});
        let membership = json!({"anchor":anchor,"leafIndex":0,"commitment":self.commitment,"siblings":vec![B256::ZERO;16]});
        let result = match r["method"].as_str().unwrap() {
            "invisi_getStatus" => {
                json!({"apiVersion":"v1","protocolVersion":"1","deployment":deployment(),"indexedHead":block(10)})
            }
            "invisi_getNote" => {
                json!({"output":{"block":block(10),"treeId":"1","leafIndex":0,"commitment":self.commitment,"token":Address::with_last_byte(2),"transactionHash":B256::with_last_byte(4),"logIndex":1,"kind":"Shield","ciphertext":"0x","clue":"0x"},"membership":membership})
            }
            "invisi_getRoots" => json!([anchor]),
            "invisi_getMembership" => membership,
            "invisi_isNoteSpent" => {
                self.spent_queries.fetch_add(1, Ordering::SeqCst);
                json!(false)
            }
            other => panic!("unexpected indexed method {other}"),
        };
        Ok(json!({"jsonrpc":"2.0","id":r["id"],"result":result}))
    }
}
struct Chain {
    spent: AtomicBool,
    current_root_known: AtomicBool,
    unsupported: AtomicBool,
    native_spent_reads: AtomicUsize,
    indexed_spent_queries: Arc<AtomicUsize>,
}
impl CanonicalChain for Chain {
    fn chain_id(&self) -> Result<u64> {
        Ok(97)
    }
    fn block(&self, n: u64) -> Result<CanonicalBlock> {
        Ok(block(n))
    }
    fn code_at(&self, _: Address, _: Option<u64>) -> Result<Vec<u8>> {
        Ok(vec![0x60, 0])
    }
    fn block_by_tag(&self, t: FinalityTag) -> Result<Option<CanonicalBlock>> {
        if self.unsupported.load(Ordering::SeqCst) {
            return Err(Error::FinalityUnsupported);
        };
        Ok(Some(block(match t {
            FinalityTag::Latest => 12,
            FinalityTag::Safe => 11,
            FinalityTag::Finalized => 10,
        })))
    }
    fn call(&self, address: Address, data: &[u8], number: u64) -> Result<Vec<u8>> {
        assert_eq!(address, Address::with_last_byte(1));
        let yes = if data.starts_with(&InvisiProtocol::isNullifierSpentCall::SELECTOR) {
            assert_eq!(number, 12);
            self.native_spent_reads.fetch_add(1, Ordering::SeqCst);
            self.spent.load(Ordering::SeqCst)
        } else if data.starts_with(&InvisiProtocol::rootHistoryCall::SELECTOR) {
            number != 12 || self.current_root_known.load(Ordering::SeqCst)
        } else {
            panic!("unexpected contract read")
        };
        let mut word = vec![0; 32];
        word[31] = u8::from(yes);
        Ok(word)
    }
}
fn fixture() -> (ProtocolRpcClient<Index, Chain>, PaymentNote, Wallet) {
    let public: Value =
        serde_json::from_str(include_str!("fixtures/current-address.json")).unwrap();
    let wallet = Wallet::from_address(public["longAddress"].as_str().unwrap()).unwrap();
    let note = Note {
        context: ProtocolContext {
            chain_id: 97,
            protocol_address: U256::from(1),
        },
        owner_address: U256::from_be_slice(wallet.owner_address().as_slice()),
        token_address: U256::from(2),
        amount: U256::from(70),
        nonce: U256::from(9),
        payload: vec![1, 2, 3],
    };
    let payment = PaymentNote::from_note(&note).unwrap();
    let mut root = invisi_sdk::field::bytes_to_field(payment.commitment().as_slice());
    for _ in 0..16 {
        root = invisi_sdk::poseidon::hash(&[
            root,
            invisi_sdk::field::bytes_to_field(B256::ZERO.as_slice()),
        ]);
    }
    let indexed_spent_queries = Arc::new(AtomicUsize::new(0));
    let rpc = ProtocolRpcClient::new(
        Index {
            commitment: payment.commitment(),
            root: B256::from(invisi_sdk::field::field_to_bytes_be(root)),
            spent_queries: indexed_spent_queries.clone(),
        },
        Chain {
            spent: AtomicBool::new(false),
            current_root_known: AtomicBool::new(true),
            unsupported: AtomicBool::new(false),
            native_spent_reads: AtomicUsize::new(0),
            indexed_spent_queries,
        },
        deployment(),
    )
    .unwrap();
    (rpc, payment, wallet)
}
#[test]
fn spendability_uses_native_spent_state_even_when_indexer_claims_unspent() {
    let (rpc, payment, wallet) = fixture();
    let spendable = payment
        .verify_spendable_with_finality(&rpc, &wallet, FinalityTag::Finalized)
        .unwrap();
    let mut detached = spendable.to_input();
    detached.note.amount = U256::from(999);
    detached.path[0] = U256::from(7);
    assert_eq!(spendable.to_input().note.amount, U256::from(70));
    assert_eq!(spendable.to_input().path[0], U256::ZERO);
    assert_eq!(rpc.chain.native_spent_reads.load(Ordering::SeqCst), 1);
    assert_eq!(rpc.chain.indexed_spent_queries.load(Ordering::SeqCst), 0);
    rpc.chain.spent.store(true, Ordering::SeqCst);
    let error = payment
        .verify_spendable_with_finality(&rpc, &wallet, FinalityTag::Finalized)
        .err()
        .expect("spent note accepted");
    assert!(error.contains("spent"), "{error}");
}
#[test]
fn historical_inclusion_is_separate_from_current_spendability() {
    let (rpc, payment, wallet) = fixture();
    rpc.chain.current_root_known.store(false, Ordering::SeqCst);
    assert!(payment
        .verify_with_finality(&rpc, FinalityTag::Finalized)
        .is_ok());
    assert!(payment
        .verify_spendable_with_finality(&rpc, &wallet, FinalityTag::Finalized)
        .is_err());
    rpc.chain.unsupported.store(true, Ordering::SeqCst);
    assert!(payment
        .verify_with_finality(&rpc, FinalityTag::Finalized)
        .is_err());
}
#[test]
fn private_opening_is_cloned_and_ipn_rejects_zero_deployment_fields() {
    let (_, payment, _) = fixture();
    assert!(payment.note().payload.is_empty());
    let detached = payment.clone();
    assert_eq!(detached.encode(), payment.encode());
    for zero in ["chain", "protocol"] {
        let mut note = payment.note().clone();
        if zero == "chain" {
            note.context.chain_id = 0
        } else {
            note.context.protocol_address = U256::ZERO
        };
        assert!(
            PaymentNote::from_note(&note).is_err(),
            "accepted zero {zero}"
        );
        let mut raw = vec![1u8];
        raw.extend(note.context.chain_id.to_be_bytes());
        raw.extend(&note.context.protocol_address.to_be_bytes::<32>()[12..]);
        raw.extend(&note.token_address.to_be_bytes::<32>()[12..]);
        raw.extend(&note.amount.to_be_bytes::<32>()[16..]);
        raw.extend(&note.owner_address.to_be_bytes::<32>()[12..]);
        raw.extend(note.nonce.to_be_bytes::<32>());
        raw.extend(
            note.commitment()
                .unwrap_or(U256::from_be_slice(payment.commitment().as_slice()))
                .to_be_bytes::<32>(),
        );
        let ipn = format!(
            "ipn:{}",
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, raw)
        );
        assert!(PaymentNote::decode(&ipn).is_err(), "decoded zero {zero}");
    }
    assert_eq!(payment.encode().len(), 203);
}
