use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_sol_types::SolEvent;
use invisi_sdk::{
    disclosure::{Disclosure, DisclosureRole},
    note::{Note, ProtocolContext},
    protocol::{IInvisiCore::Delivery, InvisiCore},
    rpc::{
        CanonicalBlock, CanonicalChain, CanonicalLog, CanonicalReceipt, ChainReceipts,
        ContractDeployment, Error, FinalityTag, ProtocolDeployment, ProtocolRpcClient, Result,
        RpcTransport,
    },
    sdk::{DisclosureReference, DisclosureVerifier},
};
use serde_json::Value;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    Mutex,
};

struct NoIndex;
impl RpcTransport for NoIndex {
    fn send(&self, _: &Value) -> Result<Value> {
        panic!("disclosure must not query indexed services")
    }
}
struct Chain {
    receipt: Mutex<CanonicalReceipt>,
    finality: AtomicU64,
    unsupported: AtomicBool,
    block_calls: AtomicUsize,
    reorg_after: AtomicUsize,
    code: Mutex<Vec<u8>>,
}
fn block(number: u64) -> CanonicalBlock {
    CanonicalBlock {
        number,
        hash: B256::with_last_byte(number as u8),
        parent_hash: B256::with_last_byte(number.saturating_sub(1) as u8),
        timestamp: 100 + number,
    }
}
impl CanonicalChain for Chain {
    fn chain_id(&self) -> Result<u64> {
        Ok(97)
    }
    fn block(&self, number: u64) -> Result<CanonicalBlock> {
        let calls = self.block_calls.fetch_add(1, Ordering::SeqCst) + 1;
        let mut b = block(number);
        if calls >= self.reorg_after.load(Ordering::SeqCst) {
            b.hash = B256::repeat_byte(0xff)
        }
        Ok(b)
    }
    fn code_at(&self, _: Address, _: Option<u64>) -> Result<Vec<u8>> {
        Ok(self.code.lock().unwrap().clone())
    }
    fn call(&self, _: Address, _: &[u8], _: u64) -> Result<Vec<u8>> {
        Err(Error::Invalid("unexpected contract call"))
    }
    fn block_by_tag(&self, _: FinalityTag) -> Result<Option<CanonicalBlock>> {
        if self.unsupported.load(Ordering::SeqCst) {
            return Err(Error::FinalityUnsupported);
        }
        Ok(Some(block(self.finality.load(Ordering::SeqCst))))
    }
}
impl ChainReceipts for Chain {
    fn receipt(&self, _: B256) -> Result<Option<CanonicalReceipt>> {
        Ok(Some(self.receipt.lock().unwrap().clone()))
    }
}
fn log<E: SolEvent>(event: &E, index: u32) -> CanonicalLog {
    let data = event.encode_log_data();
    CanonicalLog {
        address: Address::with_last_byte(1),
        topics: data.topics().to_vec(),
        data: data.data.to_vec(),
        log_index: index,
    }
}
fn fixture() -> (
    ProtocolRpcClient<NoIndex, Chain>,
    Disclosure,
    DisclosureReference,
) {
    let note = Note {
        context: ProtocolContext {
            chain_id: 97,
            protocol_address: U256::from(1),
        },
        token_address: U256::from(2),
        owner_address: U256::from(3),
        amount: U256::from(7),
        nonce: U256::from(9),
        payload: vec![],
    };
    let commitment = B256::from(note.commitment().unwrap().to_be_bytes::<32>());
    let insertion = InvisiCore::CommitmentsInserted {
        treeId: U256::from(1),
        startLeafIndex: 7,
        commitments: vec![commitment],
    };
    let params = invisi_sdk::protocol::IInvisiCore::CrossTreeTransactParams {
        token: Address::with_last_byte(2),
        sources: vec![],
        nullifiers: vec![],
        noteCommitments: vec![commitment],
        withdrawalAddress: Address::ZERO,
        withdrawalAmount: U256::ZERO,
        deadline: U256::from(900),
        feeRecipient: Address::ZERO,
        feeAmount: U256::ZERO,
    };
    let id = invisi_sdk::protocol::note_operation_id(
        97,
        Address::with_last_byte(1),
        0,
        &params,
        Address::with_last_byte(3),
        U256::from(7),
        &[Delivery {
            ciphertext: vec![].into(),
            clue: vec![].into(),
        }],
    )
    .unwrap();
    let operation = InvisiCore::NoteOperation {
        operationId: id,
        token: params.token,
        kind: 0,
        outputCount: U256::from(1),
        deadline: params.deadline,
        feeRecipient: Address::ZERO,
        feeAmount: U256::ZERO,
    };
    let deposit = InvisiCore::PublicDeposit {
        operationId: id,
        token: params.token,
        payer: Address::with_last_byte(3),
        amount: U256::from(7),
    };
    let shield = InvisiCore::NoteOutputs {
        operationId: id,
        treeId: U256::from(1),
        startLeafIndex: 7,
        packedDeliveries: vec![0, 0].into(),
    };
    let receipt = CanonicalReceipt {
        transaction_hash: B256::repeat_byte(7),
        block: block(10),
        success: true,
        logs: vec![
            log(&operation, 0),
            log(&insertion, 1),
            log(&shield, 2),
            log(&deposit, 3),
        ],
    };
    let reference = DisclosureReference {
        transaction_hash: receipt.transaction_hash,
        tree_id: 1,
        leaf_index: 7,
        role: DisclosureRole::Funds,
    };
    let chain = Chain {
        receipt: Mutex::new(receipt),
        finality: AtomicU64::new(10),
        unsupported: AtomicBool::new(false),
        block_calls: AtomicUsize::new(0),
        reorg_after: AtomicUsize::new(usize::MAX),
        code: Mutex::new(vec![0x60, 0]),
    };
    let deployment = ProtocolDeployment {
        chain_id: "97".into(),
        protocol: ContractDeployment {
            address: Address::with_last_byte(1),
            runtime_code_hash: keccak256([0x60, 0]),
            from_block: 1,
        },
        registry: None,
        broadcaster_registry: None,
    };
    (
        ProtocolRpcClient::new(NoIndex, chain, deployment).unwrap(),
        Disclosure::from_note(&note).unwrap(),
        reference,
    )
}
#[test]
fn default_finalized_disclosure_uses_only_independent_receipt_and_chain() {
    let (rpc, disclosure, reference) = fixture();
    let verifier = DisclosureVerifier::new(&rpc, Address::with_last_byte(2)).unwrap();
    let result = verifier.verify(&disclosure, reference).unwrap();
    assert_eq!(result.finality, FinalityTag::Finalized);
    assert_eq!(result.block, block(10));
    assert!(DisclosureVerifier::new(&rpc, Address::ZERO).is_err());
}
#[test]
fn disclosure_rejects_unconfirmed_reorged_and_changed_deployment() {
    for condition in [
        "finality",
        "unsupported",
        "reorg",
        "runtime",
        "reverted",
        "transaction",
        "insertion",
        "token",
        "role",
    ] {
        let (rpc, disclosure, mut reference) = fixture();
        let token = if condition == "token" {
            Address::with_last_byte(4)
        } else {
            Address::with_last_byte(2)
        };
        match condition {
            "finality" => rpc.chain.finality.store(9, Ordering::SeqCst),
            "unsupported" => rpc.chain.unsupported.store(true, Ordering::SeqCst),
            "reorg" => rpc.chain.reorg_after.store(1, Ordering::SeqCst),
            "runtime" => *rpc.chain.code.lock().unwrap() = vec![0x60, 1],
            "reverted" => rpc.chain.receipt.lock().unwrap().success = false,
            "transaction" => reference.transaction_hash = B256::repeat_byte(8),
            "insertion" => {
                rpc.chain.receipt.lock().unwrap().logs.remove(0);
            }
            "role" => reference.role = DisclosureRole::Owner,
            _ => {}
        }
        assert!(
            DisclosureVerifier::new(&rpc, token)
                .unwrap()
                .verify(&disclosure, reference)
                .is_err(),
            "accepted {condition}"
        );
    }
}
#[test]
fn disclosure_rechecks_original_block_after_opening_verification() {
    let (rpc, disclosure, reference) = fixture();
    rpc.chain.reorg_after.store(6, Ordering::SeqCst);
    assert!(DisclosureVerifier::new(&rpc, Address::with_last_byte(2))
        .unwrap()
        .verify(&disclosure, reference)
        .is_err());
    assert!(rpc.chain.block_calls.load(Ordering::SeqCst) >= 6);
}
#[test]
fn explicit_latest_finality_and_opening_commitment_are_enforced() {
    let (rpc, disclosure, reference) = fixture();
    let verifier =
        DisclosureVerifier::with_finality(&rpc, Address::with_last_byte(2), FinalityTag::Latest)
            .unwrap();
    let result = verifier.verify(&disclosure, reference.clone()).unwrap();
    assert_eq!(result.finality, FinalityTag::Latest);
    let invisi_sdk::disclosure::DisclosureResult::Note(mut note) = result.result else {
        panic!("expected a funds Note")
    };
    note.amount += U256::from(1);
    let wrong = Disclosure::from_note(&note).unwrap();
    assert!(verifier.verify(&wrong, reference).is_err());
}
