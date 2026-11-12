use super::*;
use crate::{
    protocol::{IInvisiProtocol as abi, InvisiProtocol as P},
    prover::{ProofBundle, ProofStatement, Prover, ProvingRequest},
    rpc::{CanonicalLog, CanonicalReceipt, CanonicalTransaction, Membership, MembershipInput},
    sdk::{ChainState, TransferPreparation, WalletResponse},
};
use alloy_sol_types::SolEvent;
use std::collections::BTreeSet;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};
fn block(n: u64) -> CanonicalBlock {
    CanonicalBlock {
        number: n,
        hash: B256::with_last_byte(n as u8),
        parent_hash: B256::with_last_byte(n.saturating_sub(1) as u8),
        timestamp: 2_000_000_000 + n,
    }
}
fn context() -> ProtocolContext {
    ProtocolContext {
        chain_id: 31337,
        protocol_address: U256::from(4660),
    }
}
fn key(n: u8) -> [u8; 32] {
    let mut key = [0; 32];
    key[31] = n;
    key
}
fn wallet(n: u8) -> Wallet {
    let owner = if n == 1 {
        "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
    } else {
        "0x2b5ad5c4795c026514f8317c7a215e218dccd6cf"
    };
    let q = sdk::prepare_wallet_request(
        owner.parse().unwrap(),
        "public",
        "wallet.public",
        serde_json::json!({}),
    )
    .unwrap();
    let r: WalletResponse =
        serde_json::from_value(crate::wallet::execute(&key(n), &q.as_value()).unwrap()).unwrap();
    Wallet::from_response(&q, &r).unwrap()
}
#[derive(Default)]
struct Chain {
    changed_context: AtomicBool,
    gas_forbidden: AtomicBool,
    height: std::sync::atomic::AtomicU64,
    reorg: AtomicBool,
    source_anchors: AtomicBool,
    spent: Mutex<BTreeSet<B256>>,
    roots: Mutex<BTreeSet<B256>>,
}
impl ChainState for Chain {
    fn context(&self) -> ProtocolContext {
        assert!(
            !self.gas_forbidden.load(Ordering::SeqCst),
            "estimator read chain context"
        );
        let mut value = context();
        if self.changed_context.load(Ordering::SeqCst) {
            value.chain_id += 1
        }
        value
    }
    fn snapshot(&self) -> Result<CanonicalBlock> {
        assert!(
            !self.gas_forbidden.load(Ordering::SeqCst),
            "estimator read chain"
        );
        Ok(block(self.height.load(Ordering::SeqCst).max(10)))
    }
    fn canonical(&self, b: &CanonicalBlock) -> Result<()> {
        let expected = block(b.number);
        let source_anchor = self.source_anchors.load(Ordering::SeqCst)
            && b.parent_hash == B256::ZERO
            && b.timestamp == 0
            && b.number == expected.number
            && b.hash == expected.hash;
        if self.reorg.load(Ordering::SeqCst) || (*b != expected && !source_anchor) {
            return Err("chain reorg".into());
        }
        Ok(())
    }
    fn known_root(&self, _: u64, root: B256, _: &CanonicalBlock) -> Result<bool> {
        Ok(self.roots.lock().unwrap().contains(&root))
    }
    fn nullifier_spent(&self, n: B256, _: &CanonicalBlock) -> Result<bool> {
        Ok(self.spent.lock().unwrap().contains(&n))
    }
    fn credit_revoked(
        &self,
        _: Address,
        _: Address,
        _: u64,
        _: u16,
        _: &CanonicalBlock,
    ) -> Result<bool> {
        Ok(false)
    }
    fn token_balance_allowance(
        &self,
        _: Address,
        _: Address,
        _: &CanonicalBlock,
    ) -> Result<(U256, U256)> {
        Ok((U256::MAX, U256::MAX))
    }
    fn credit_allocation(&self, _: Address, _: Address, _: &CanonicalBlock) -> Result<(u64, u16)> {
        Ok((1, 0))
    }
}
struct Source {
    fork: AtomicBool,
    runtime_hash: Mutex<Option<B256>>,
    extra_receipts: Mutex<Vec<CanonicalReceipt>>,
    indexed_height: std::sync::atomic::AtomicU64,
    receipt_reads: std::sync::atomic::AtomicUsize,
    discovery_reads: std::sync::atomic::AtomicUsize,
    chain: Arc<Chain>,
    receipt: Mutex<CanonicalReceipt>,
    transaction: Mutex<Option<CanonicalTransaction>>,
    proofs: Mutex<BTreeMap<B256, (u64, u16, [U256; 16], U256)>>,
}
impl SessionSource for Source {
    fn context(&self) -> ProtocolContext {
        context()
    }
    fn deployment_start(&self) -> u64 {
        0
    }
    fn runtime_code_hash(&self) -> Option<B256> {
        *self.runtime_hash.lock().unwrap()
    }
    fn indexed_head(&self) -> Result<CanonicalBlock> {
        self.block(self.indexed_height.load(Ordering::SeqCst))
    }
    fn block(&self, n: u64) -> Result<CanonicalBlock> {
        if self.fork.load(Ordering::SeqCst) {
            let mut b = block(n);
            b.hash = B256::with_last_byte(n as u8 + 70);
            return Ok(b);
        }
        let b = block(n);
        self.chain.canonical(&b)?;
        Ok(b)
    }
    fn discover(&self, from: u64, to: u64) -> Result<Vec<B256>> {
        self.discovery_reads.fetch_add(1, Ordering::SeqCst);
        let r = self.receipt.lock().unwrap();
        let mut hashes = if (from..=to).contains(&r.block.number) {
            vec![r.transaction_hash]
        } else {
            vec![]
        };
        hashes.extend(
            self.extra_receipts
                .lock()
                .unwrap()
                .iter()
                .filter(|r| (from..=to).contains(&r.block.number))
                .map(|r| r.transaction_hash),
        );
        Ok(hashes)
    }
    fn receipt(&self, hash: B256) -> Result<Option<CanonicalReceipt>> {
        self.receipt_reads.fetch_add(1, Ordering::SeqCst);
        let r = self.receipt.lock().unwrap();
        Ok(if r.transaction_hash == hash {
            Some(r.clone())
        } else {
            self.extra_receipts
                .lock()
                .unwrap()
                .iter()
                .find(|r| r.transaction_hash == hash)
                .cloned()
        })
    }
    fn transaction(&self, _: B256) -> Result<Option<CanonicalTransaction>> {
        Ok(self.transaction.lock().unwrap().clone())
    }
    fn known_root(&self, tree: u64, root: B256, block: &CanonicalBlock) -> Result<bool> {
        self.chain.known_root(tree, root, block)
    }
    fn membership(&self, i: &MembershipInput, b: &CanonicalBlock) -> Result<Membership> {
        let p = self.proofs.lock().unwrap();
        let (tree, index, path, root) = p.get(&i.commitment).ok_or("proof unavailable")?;
        Ok(Membership {
            tree_id: *tree,
            leaf_index: *index as u32,
            leaf: i.commitment,
            root: sdk::field_word(*root),
            path: path.iter().map(|n| sdk::field_word(*n)).collect(),
            block: b.clone(),
        })
    }
}
fn log<E: SolEvent>(event: &E, index: u32) -> CanonicalLog {
    let e = event.encode_log_data();
    CanonicalLog {
        address: sdk::word_address(context().protocol_address).unwrap(),
        topics: e.topics().to_vec(),
        data: e.data.to_vec(),
        log_index: index,
    }
}
#[derive(Default)]
struct GasGuardStore {
    inner: MemoryWalletStore,
    forbidden: AtomicBool,
}
impl WalletStore for GasGuardStore {
    fn snapshot(&self, scope: &str) -> Result<WalletState> {
        assert!(
            !self.forbidden.load(Ordering::SeqCst),
            "estimator accessed wallet store"
        );
        self.inner.snapshot(scope)
    }
    fn compare_and_swap(&self, scope: &str, revision: u64, next: WalletState) -> Result<()> {
        assert!(
            !self.forbidden.load(Ordering::SeqCst),
            "estimator wrote wallet store"
        );
        self.inner.compare_and_swap(scope, revision, next)
    }
    fn persistent(&self) -> bool {
        false
    }
}
struct Harness {
    session: WalletSession,
    store: Arc<GasGuardStore>,
    chain: Arc<Chain>,
    source: Arc<Source>,
    note: crate::note::Note,
    commitment: B256,
}
fn harness() -> Harness {
    let wallet = wallet(1);
    let note = crate::note::Note {
        context: context(),
        owner_address: sdk::address_word(wallet.owner_address()),
        token_address: U256::from(22136),
        amount: U256::from(70),
        nonce: U256::from(123),
        payload: vec![1, 2],
    };
    let commitment = sdk::field_word(note.commitment().unwrap());
    let delivery = crate::delivery::DeliveryContext {
        context: context(),
        token_address: note.token_address,
        output_commitment: U256::from_be_slice(commitment.as_slice()),
    };
    let keys = wallet.receiving_keys();
    let ciphertext =
        crate::delivery::encrypt_note(&keys.viewing_public_key, &note, &delivery).unwrap();
    let clue = crate::fmd::create_clue(&keys.clue_key).unwrap();
    let path = [U256::ZERO; 16];
    let root = sdk::merkle_root(U256::from_be_slice(commitment.as_slice()), 0, &path).unwrap();
    let chain = Arc::new(Chain::default());
    chain.roots.lock().unwrap().insert(sdk::field_word(root));
    let insert = P::CommitmentsInserted {
        treeId: U256::from(1),
        startLeafIndex: 0,
        commitments: vec![commitment],
    };
    let shield = P::Shield {
        token: sdk::word_address(note.token_address).unwrap(),
        payer: wallet.owner_address(),
        amount: note.amount,
        treeId: U256::from(1),
        startLeafIndex: 0,
        deliveries: vec![abi::Delivery {
            ciphertext: ciphertext.into(),
            clue: clue.into(),
        }],
        deadline: U256::from(2_000_000_100u64),
    };
    let receipt = CanonicalReceipt {
        transaction_hash: B256::with_last_byte(9),
        block: block(10),
        success: true,
        logs: vec![log(&insert, 0), log(&shield, 1)],
    };
    let mut proofs = BTreeMap::new();
    proofs.insert(commitment, (1, 0, path, root));
    let source = Arc::new(Source {
        fork: Default::default(),
        runtime_hash: Default::default(),
        extra_receipts: Default::default(),
        indexed_height: std::sync::atomic::AtomicU64::new(10),
        receipt_reads: Default::default(),
        discovery_reads: Default::default(),
        chain: chain.clone(),
        receipt: Mutex::new(receipt),
        transaction: Mutex::new(None),
        proofs: Mutex::new(proofs),
    });
    let store = Arc::new(GasGuardStore::default());
    let session = WalletSession::connect(
        Invisi::new(chain.clone()),
        wallet,
        store.clone(),
        source.clone(),
        "test",
    )
    .unwrap();
    Harness {
        session,
        store,
        chain,
        source,
        note,
        commitment,
    }
}
#[derive(Default)]
struct AppDecryptor {
    fail: bool,
    forge: bool,
    nonrecipient: bool,
}
impl crate::delivery::DeliveryDecryptor for AppDecryptor {
    fn decrypt_note(
        &self,
        envelope: &[u8],
        context: &crate::delivery::DeliveryContext,
        owner: U256,
    ) -> Result<Option<Vec<u8>>> {
        if self.fail {
            return Err("App wallet locked".into());
        }
        if self.nonrecipient {
            return Ok(None);
        }
        let viewing = crate::wallet::viewing_key(&key(1))?;
        let Ok(note) = crate::delivery::decrypt_note(&*viewing, envelope, context, owner) else {
            return Ok(None);
        };
        let mut plain = crate::delivery::encode_note(&note).map_err(|e| e.to_string())?;
        if self.forge {
            plain[47] ^= 1;
        }
        Ok(Some(plain.to_vec()))
    }
    fn decrypt_credit(
        &self,
        envelope: &[u8],
        context: &crate::delivery::DeliveryContext,
        role: CreditRole,
        owner: U256,
    ) -> Result<Option<Vec<u8>>> {
        if self.fail {
            return Err("App wallet locked".into());
        }
        if self.nonrecipient {
            return Ok(None);
        }
        let viewing = crate::wallet::viewing_key(&key(1))?;
        let Ok(credit) = crate::delivery::decrypt_credit(&*viewing, envelope, context, role, owner)
        else {
            return Ok(None);
        };
        Ok(Some(
            crate::delivery::encode_credit(&credit)
                .map_err(|e| e.to_string())?
                .to_vec(),
        ))
    }
}
#[test]
fn app_errors_do_not_commit_and_retries_succeed() {
    let h = harness();
    let pending = h.session.refresh(RefreshOptions::from_block(0)).unwrap();
    assert!(pending
        .decrypt(&AppDecryptor {
            fail: true,
            ..Default::default()
        })
        .is_err());
    assert_eq!(h.session.snapshot().unwrap().revision, 0);
    assert!(h.session.snapshot().unwrap().notes.is_empty());
    pending.decrypt(&AppDecryptor::default()).unwrap();
    assert_eq!(h.session.snapshot().unwrap().notes.len(), 1);
}

fn synced() -> Harness {
    let h = harness();
    let pending = h.session.refresh(RefreshOptions::from_block(0)).unwrap();
    pending.decrypt(&AppDecryptor::default()).unwrap();
    h
}
fn transfer(h: &Harness) -> TransferPreparation {
    TransferPreparation {
        token: sdk::word_address(h.note.token_address).unwrap(),
        inputs: Vec::new(),
        outputs: Vec::new(),
        withdrawal: Some((h.session.wallet.owner_address(), h.note.amount)),
        funding: sdk::empty_funding(),
        fee: sdk::Fee::default(),
        deadline: 2_000_000_100,
        automatic_change: false,
    }
}
#[test]
fn stages_without_state_writes_and_retries_app_failures() {
    let h = harness();
    let pending = h.session.refresh(RefreshOptions::from_block(0)).unwrap();
    assert_eq!(h.session.snapshot().unwrap().revision, 0);
    assert!(pending
        .decrypt(&AppDecryptor {
            fail: true,
            ..Default::default()
        })
        .is_err());
    assert_eq!(h.session.snapshot().unwrap().revision, 0);
    pending.decrypt(&AppDecryptor::default()).unwrap();
    assert_eq!(
        h.session
            .balance(sdk::word_address(h.note.token_address).unwrap())
            .unwrap()
            .available,
        Some(U256::from(70))
    );
    assert!(pending.decrypt(&AppDecryptor::default()).is_err());
}

#[test]
fn refresh_rejects_forged_plaintext_wrong_membership_reorg_and_stale_revision() {
    let h = harness();
    let pending = h.session.refresh(RefreshOptions::from_block(0)).unwrap();
    assert!(pending
        .decrypt(&AppDecryptor {
            forge: true,
            ..Default::default()
        })
        .is_err());
    assert_eq!(h.session.snapshot().unwrap().revision, 0);
    h.chain.reorg.store(true, Ordering::SeqCst);
    assert!(pending.decrypt(&AppDecryptor::default()).is_err());
    h.chain.reorg.store(false, Ordering::SeqCst);
    let mut state = h.session.snapshot().unwrap();
    state.scope = Some(h.session.scope.clone());
    h.store
        .compare_and_swap(&h.session.scope.key(), 0, state)
        .unwrap();
    assert!(pending.decrypt(&AppDecryptor::default()).is_err());
}
#[test]
fn reservations_are_atomic_and_resume_invalidates_prior_handles() {
    let h = synced();
    let first = h.session.prepare_transfer(transfer(&h)).unwrap();
    let id = first.id().to_owned();
    assert!(h.session.prepare_transfer(transfer(&h)).is_err());
    let resumed = h.session.resume(&id, None).unwrap();
    assert!(first.cancel().is_err());
    resumed.cancel().unwrap();
    assert!(h.session.snapshot().unwrap().notes[&h.commitment]
        .reserved_by
        .is_none());
    assert!(h.session.prepare_transfer(transfer(&h)).is_ok());
}
#[test]
fn storage_encrypts_and_binds_scope_revision_and_ciphertext() {
    let records = Arc::new(MemoryAtomicRecords::default());
    let store = EncryptedWalletStore::new(records.clone(), [7; 32]).unwrap();
    store
        .compare_and_swap("scope-a", 0, WalletState::default())
        .unwrap();
    let record = records.read("scope-a").unwrap().unwrap();
    assert!(!String::from_utf8_lossy(&record.data).contains("notes"));
    assert_eq!(store.snapshot("scope-a").unwrap().revision, 1);
    records.compare_and_swap("scope-b", 0, &record).unwrap();
    assert!(store.snapshot("scope-b").is_err());
    let mut corrupt = record.clone();
    corrupt.revision = 2;
    corrupt.data[13] ^= 1;
    records.compare_and_swap("scope-a", 1, &corrupt).unwrap();
    assert!(store.snapshot("scope-a").is_err());
    assert!(!store.persistent());
}
#[test]
fn explicit_not_recipient_is_a_no_match_and_scope_isolation_is_enforced() {
    let h = harness();
    let pending = h.session.refresh(RefreshOptions::from_block(0)).unwrap();
    pending
        .decrypt(&AppDecryptor {
            nonrecipient: true,
            ..Default::default()
        })
        .unwrap();
    assert!(h.session.snapshot().unwrap().notes.is_empty());
    let other = WalletSession::connect(
        h.session.invisi.clone(),
        wallet(2),
        h.store.clone(),
        h.source.clone(),
        "test",
    )
    .unwrap();
    assert!(other.snapshot().unwrap().notes.is_empty());
    assert_eq!(other.snapshot().unwrap().revision, 0);
}

struct Backend;
impl Prover for Backend {
    fn prove(&self, r: &ProvingRequest) -> Result<ProofBundle> {
        let s = &r.statement;
        let proof = vec![
            0;
            if r.statement.target == "noir-recursive" {
                458 * 32
            } else {
                32
            }
        ];
        Ok(ProofBundle {
            format_version: 1,
            circuit_name: s.circuit_name.clone(),
            target: s.target.clone(),
            bb_version: "6.0.0".into(),
            artifact_sha256: s.artifact_sha256.clone(),
            vk_sha256: s.vk_sha256.clone(),
            proof_sha256: crate::prover::sha256(&proof),
            proof,
            public_inputs: s.expected_public_inputs.clone(),
        })
    }
    fn verify(&self, _: &ProofBundle, _: &ProofStatement) -> Result<bool> {
        Ok(true)
    }
}
#[test]
fn durable_journal_omits_wallet_authorization_and_requires_reverification_on_resume() {
    let h = synced();
    let bob = wallet(2);
    let mut options = transfer(&h);
    options.withdrawal = None;
    options.outputs = vec![sdk::NoteOutput::for_recipient(
        context(),
        options.token,
        &bob,
        U256::from(30),
        vec![],
    )
    .unwrap()];
    options.automatic_change = true;
    let mut operation = h.session.prepare_transfer(options).unwrap();
    let request = operation.export_wallet_request("authorize-1").unwrap();
    let response: WalletResponse =
        serde_json::from_value(crate::wallet::execute(&key(1), &request.as_value()).unwrap())
            .unwrap();
    let signature = response.result().unwrap()["signature"]
        .as_str()
        .unwrap()
        .to_owned();
    let operation = operation.with_wallet_response(&response).unwrap();
    assert_eq!(operation.phase(), sdk::Phase::Authorized);
    let encoded = serde_json::to_string(&h.session.snapshot().unwrap()).unwrap();
    assert!(!encoded.contains(&signature));
    assert!(!encoded.contains("public_key_x"));
    assert!(!encoded.contains("spending_public_key"));
    let operation = operation.prove(&Backend, false).unwrap();
    let id = operation.id().to_owned();
    assert_eq!(operation.phase(), sdk::Phase::Proved);
    let resumed = h.session.resume(&id, Some(&Backend)).unwrap();
    assert_eq!(resumed.phase(), sdk::Phase::Proved);
    assert!(operation.cancel().is_err());
    let reset = h.session.resume(&id, None).unwrap();
    assert_eq!(reset.phase(), sdk::Phase::Prepared);
    assert!(resumed.cancel().is_err());
    reset.cancel().unwrap();
}
fn tracked_sweep(h: &Harness) -> Operation {
    let operation = h
        .session
        .prepare_transfer(transfer(h))
        .unwrap()
        .prove(&Backend, false)
        .unwrap();
    let mut operation = operation;
    let call = operation
        .calldata(h.session.wallet.owner_address())
        .unwrap();
    operation
        .track_transaction(B256::with_last_byte(8))
        .unwrap();
    *h.source.transaction.lock().unwrap() = Some(CanonicalTransaction {
        hash: B256::with_last_byte(8),
        to: Some(call.to),
        input: call.data,
        value: call.value,
        chain_id: context().chain_id,
        block: Some(block(10)),
    });
    operation
}
#[test]
fn exported_operations_cannot_cancel_and_reconciliation_checks_exact_transaction() {
    let h = synced();
    let operation = tracked_sweep(&h);
    let id = operation.id().to_owned();
    assert!(operation.cancel().is_err());
    assert!(h.session.snapshot().unwrap().notes[&h.commitment]
        .reserved_by
        .is_some());
    {
        let mut receipt = h.source.receipt.lock().unwrap();
        receipt.transaction_hash = B256::with_last_byte(8);
        receipt.success = false;
        receipt.logs.clear();
    }
    h.source
        .transaction
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .input
        .push(1);
    assert!(h.session.reconcile(&id).is_err());
    h.source
        .transaction
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .input
        .pop();
    let pending = match h.session.reconcile(&id).unwrap() {
        Reconciliation::Ready(v) => v,
        _ => panic!("expected canonical reconciliation"),
    };
    pending.decrypt(&AppDecryptor::default()).unwrap();
    let state = h.session.snapshot().unwrap();
    assert_eq!(state.operations[&id].status, OperationStatus::Reverted);
    assert!(state.notes[&h.commitment].reserved_by.is_none());
    assert!(state.discovery_through.is_some());
}
#[test]
fn successful_canonical_shield_reconciliation_commits_only_after_injected_app_decryption() {
    use alloy_sol_types::SolCall;
    let h = harness();
    let output =
        sdk::NoteOutput::from_note(h.note.clone(), Some(h.session.wallet.receiving_keys()))
            .unwrap();
    let mut funding = sdk::empty_funding();
    funding.payer = h.session.wallet.owner_address();
    funding.amount = h.note.amount;
    let options = sdk::ShieldPreparation {
        token: sdk::word_address(h.note.token_address).unwrap(),
        outputs: vec![output],
        funding,
        fee: sdk::Fee::default(),
        deadline: 2_000_000_100,
    };
    let mut operation = h.session.prepare_shield(options).unwrap().ready().unwrap();
    let call = operation
        .calldata(h.session.wallet.owner_address())
        .unwrap();
    operation
        .track_transaction(B256::with_last_byte(9))
        .unwrap();
    *h.source.transaction.lock().unwrap() = Some(CanonicalTransaction {
        hash: B256::with_last_byte(9),
        to: Some(call.to),
        input: call.data.clone(),
        value: call.value,
        chain_id: context().chain_id,
        block: Some(block(10)),
    });
    let parsed = P::shieldCall::abi_decode(&call.data, true).unwrap();
    let event = P::Shield {
        token: parsed.p.token,
        payer: h.session.wallet.owner_address(),
        amount: h.note.amount,
        treeId: U256::from(1),
        startLeafIndex: 0,
        deliveries: parsed._2,
        deadline: parsed.p.deadline,
    };
    h.source.receipt.lock().unwrap().logs[1] = log(&event, 1);
    let pending = match h.session.reconcile(operation.id()).unwrap() {
        Reconciliation::Ready(v) => v,
        _ => panic!("expected reconciliation"),
    };
    assert!(h.session.snapshot().unwrap().notes.is_empty());
    assert!(pending
        .decrypt(&AppDecryptor {
            fail: true,
            ..Default::default()
        })
        .is_err());
    assert!(h.session.snapshot().unwrap().notes.is_empty());
    pending.decrypt(&AppDecryptor::default()).unwrap();
    let state = h.session.snapshot().unwrap();
    assert_eq!(
        state.operations[operation.id()].status,
        OperationStatus::Confirmed
    );
    assert_eq!(state.notes.len(), 1);
    assert!(state.discovery_through.is_none());
}

#[test]
fn durable_snapshot_rejects_corrupted_capacity_sources_and_authorization_flags() {
    let h = synced();
    let operation = h.session.prepare_transfer(transfer(&h)).unwrap();
    let snapshot = h.session.snapshot().unwrap().operations[operation.id()]
        .snapshot
        .clone();
    let value = serde_json::to_value(snapshot).unwrap();
    for (field, patch) in [
        ("capacity", serde_json::json!(0)),
        ("needsAuthorization", serde_json::json!(true)),
        ("token", serde_json::json!(Address::repeat_byte(9))),
    ] {
        let mut bad = value.clone();
        bad[field] = patch;
        let snapshot: PreparedSnapshot = serde_json::from_value(bad).unwrap();
        assert!(
            snapshot.restore(h.session.wallet(), None).is_err(),
            "{field}"
        );
    }
}
#[test]
fn credit_inventory_is_separate_and_canonical_draw_recovers_owned_successor_without_decrypting_new_envelopes(
) {
    use crate::credit::{CreditPolicy, CreditState, CreditUsage};
    let h = harness();
    let alice = wallet(1);
    let bob = wallet(2);
    let state = CreditDeliveryState {
        note: CreditState {
            context: context(),
            token_address: h.note.token_address,
            spender_wallet_identity: sdk::address_word(bob.owner_address()),
            owner_wallet_identity: sdk::address_word(alice.owner_address()),
            revocation_shard: 1,
            revocation_slot: 0,
            nonce: U256::from(74),
            expiry: 2_100_000_000,
            credit_shared_key: U256::from(75),
            policy: CreditPolicy::default(),
            usage: CreditUsage::default(),
            available_credit: U256::from(400),
            unlimited: false,
            payload: Vec::new(),
        },
        owner_receiving_keys: alice.receiving_keys().clone(),
        spender_receiving_keys: bob.receiving_keys().clone(),
    };
    let delivery_for = |state: &CreditDeliveryState, role: CreditRole| {
        let keys = if role == CreditRole::Owner {
            &state.owner_receiving_keys
        } else {
            &state.spender_receiving_keys
        };
        let context = crate::delivery::DeliveryContext {
            context: context(),
            token_address: state.note.token_address,
            output_commitment: state.note.commitment().unwrap(),
        };
        abi::Delivery {
            ciphertext: crate::delivery::encrypt_credit(
                &keys.viewing_public_key,
                state,
                &context,
                role,
            )
            .unwrap()
            .into(),
            clue: crate::fmd::create_clue(&keys.clue_key).unwrap().into(),
        }
    };
    let commitment = sdk::field_word(state.note.commitment().unwrap());
    let path = [U256::ZERO; 16];
    let root = sdk::merkle_root(U256::from_be_slice(commitment.as_slice()), 0, &path).unwrap();
    h.chain.roots.lock().unwrap().insert(sdk::field_word(root));
    h.source
        .proofs
        .lock()
        .unwrap()
        .insert(commitment, (2, 0, path, root));
    let created = P::CreditCreated {
        token: sdk::word_address(h.note.token_address).unwrap(),
        owner: alice.owner_address(),
        outputTreeId: U256::from(2),
        revocationShard: 1,
        revocationSlot: 0,
        creditCommitment: commitment,
        leafIndex: 0,
        deliveries: vec![
            delivery_for(&state, CreditRole::Owner),
            delivery_for(&state, CreditRole::Spender),
        ],
        deadline: U256::from(2_000_000_100u64),
        feeRecipient: Address::ZERO,
        feeAmount: U256::ZERO,
    };
    let insertion = P::CommitmentsInserted {
        treeId: U256::from(2),
        startLeafIndex: 0,
        commitments: vec![commitment],
    };
    h.source.receipt.lock().unwrap().logs = vec![log(&insertion, 0), log(&created, 1)];
    let pending = h.session.refresh(RefreshOptions::from_block(0)).unwrap();
    pending.decrypt(&AppDecryptor::default()).unwrap();
    let initial = h.session.snapshot().unwrap();
    assert_eq!(initial.credits.len(), 1);
    assert!(initial.notes.is_empty());
    assert_eq!(
        initial.credits.values().next().unwrap().role,
        CreditRole::Owner
    );
    let transition =
        crate::credit::derive_credit_state(&state.note, U256::from(30), block(10).timestamp)
            .unwrap();
    let successor = CreditDeliveryState {
        note: transition.state.clone(),
        owner_receiving_keys: state.owner_receiving_keys.clone(),
        spender_receiving_keys: state.spender_receiving_keys.clone(),
    };
    let output = sdk::NoteOutput::for_recipient(
        context(),
        sdk::word_address(h.note.token_address).unwrap(),
        &bob,
        U256::from(30),
        Vec::new(),
    )
    .unwrap();
    let credit_commitment = sdk::field_word(transition.state_commitment);
    let note_commitment = output.commitment();
    let mut credit_path = [U256::ZERO; 16];
    credit_path[0] = U256::from_be_slice(note_commitment.as_slice());
    let mut note_path = [U256::ZERO; 16];
    note_path[0] = U256::from_be_slice(credit_commitment.as_slice());
    let next_root = sdk::merkle_root(transition.state_commitment, 0, &credit_path).unwrap();
    assert_eq!(
        sdk::merkle_root(
            U256::from_be_slice(note_commitment.as_slice()),
            1,
            &note_path
        )
        .unwrap(),
        next_root
    );
    h.chain
        .roots
        .lock()
        .unwrap()
        .insert(sdk::field_word(next_root));
    h.source
        .proofs
        .lock()
        .unwrap()
        .insert(credit_commitment, (3, 0, credit_path, next_root));
    h.source
        .proofs
        .lock()
        .unwrap()
        .insert(note_commitment, (3, 1, note_path, next_root));
    h.chain
        .spent
        .lock()
        .unwrap()
        .insert(sdk::field_word(transition.nullifier));
    let params = abi::CreditDrawParams {
        token: sdk::word_address(h.note.token_address).unwrap(),
        sources: vec![abi::InputSource {
            treeId: U256::from(2),
            merkleRoot: sdk::field_word(root),
        }],
        payers: vec![abi::CreditPayer {
            payer: alice.owner_address(),
            amount: U256::from(30),
        }],
        grantRefs: vec![abi::CreditGrantRef {
            payerIndex: U256::ZERO,
            shard: 1,
            slot: 0,
        }],
        nullifiers: vec![sdk::field_word(transition.nullifier)],
        creditCommitments: vec![credit_commitment],
        recoveryAmounts: vec![sdk::field_word(transition.recovery_amount)],
        noteCommitment: note_commitment,
        totalAmount: U256::from(30),
        deadline: U256::from(2_000_000_100u64),
        feeRecipient: Address::ZERO,
        feeAmount: U256::ZERO,
    };
    let draw = P::CreditDraw {
        outputTreeId: U256::from(3),
        params,
        leafIndices: vec![0, 1],
        deliveries: vec![
            delivery_for(&successor, CreditRole::Owner),
            delivery_for(&successor, CreditRole::Spender),
            output.delivery().clone(),
        ],
    };
    let insertion = P::CommitmentsInserted {
        treeId: U256::from(3),
        startLeafIndex: 0,
        commitments: vec![credit_commitment, note_commitment],
    };
    {
        let mut receipt = h.source.receipt.lock().unwrap();
        receipt.transaction_hash = B256::with_last_byte(8);
        receipt.logs = vec![log(&insertion, 2), log(&draw, 3)];
    }
    let pending = h.session.refresh(RefreshOptions::from_block(0)).unwrap();
    pending
        .decrypt(&AppDecryptor {
            nonrecipient: true,
            ..Default::default()
        })
        .unwrap();
    let after = h.session.snapshot().unwrap();
    assert_eq!(after.credits.len(), 2);
    assert!(after.credits[&credit_key(commitment, CreditRole::Owner)].consumed);
    assert_eq!(
        after.credits[&credit_key(credit_commitment, CreditRole::Owner)]
            .delivery
            .note
            .available_credit,
        U256::from(370)
    );
    assert!(after.notes.is_empty());
    assert_eq!(
        h.session
            .balance(sdk::word_address(h.note.token_address).unwrap())
            .unwrap()
            .known,
        U256::ZERO
    );
    let id = credit_key(credit_commitment, CreditRole::Owner);
    let operation = h
        .session
        .prepare_update_credit(
            &id,
            crate::credit::CreditUpdateChanges::default(),
            2_000_000_100,
            sdk::Fee::default(),
        )
        .unwrap();
    assert!(h
        .session
        .prepare_update_credit(
            &id,
            crate::credit::CreditUpdateChanges::default(),
            2_000_000_100,
            sdk::Fee::default()
        )
        .is_err());
    let resumed = h.session.resume(operation.id(), None).unwrap();
    assert!(operation.cancel().is_err());
    resumed.cancel().unwrap();
}

#[test]
fn concurrent_apply_has_one_winner_and_expiry_requires_canonical_unspent_inputs() {
    let h = harness();
    let pending = h.session.refresh(RefreshOptions::from_block(0)).unwrap();
    let barrier = std::sync::Barrier::new(2);
    let results = std::thread::scope(|scope| {
        let a = scope.spawn(|| {
            barrier.wait();
            pending.decrypt(&AppDecryptor::default())
        });
        let b = scope.spawn(|| {
            barrier.wait();
            pending.decrypt(&AppDecryptor::default())
        });
        [a.join().unwrap().is_ok(), b.join().unwrap().is_ok()]
    });
    assert_eq!(results.iter().filter(|success| **success).count(), 1);
    assert_eq!(h.session.snapshot().unwrap().revision, 1);
    let mut options = transfer(&h);
    options.deadline = 2_000_000_015;
    let mut operation = h
        .session
        .prepare_transfer(options)
        .unwrap()
        .prove(&Backend, false)
        .unwrap();
    let id = operation.id().to_owned();
    operation
        .calldata(h.session.wallet.owner_address())
        .unwrap();
    h.chain.height.store(20, Ordering::SeqCst);
    assert!(h.session.expire_operation(&id).is_err());
    operation
        .track_transaction(B256::with_last_byte(8))
        .unwrap();
    h.session.expire_operation(&id).unwrap();
    let state = h.session.snapshot().unwrap();
    assert_eq!(state.operations[&id].status, OperationStatus::Expired);
    assert!(state.notes[&h.commitment].reserved_by.is_none());
}
#[test]
fn same_wallet_aggregate_externalizes_tracks_and_reconciles_member_journals_atomically() {
    let h = synced();
    let mut state = h.session.snapshot().unwrap();
    let mut extra = state.notes[&h.commitment].clone();
    extra.input.note.nonce += U256::from(1);
    extra.commitment = sdk::field_word(extra.input.note.commitment().unwrap());
    extra.nullifier = sdk::field_word(extra.input.note.nullifier().unwrap());
    extra.input.root = sdk::merkle_root(
        U256::from_be_slice(extra.commitment.as_slice()),
        extra.input.leaf_index,
        &extra.input.path,
    )
    .unwrap();
    h.chain
        .roots
        .lock()
        .unwrap()
        .insert(sdk::field_word(extra.input.root));
    state.notes.insert(extra.commitment, extra);
    h.session.commit(state).unwrap();
    let first = h
        .session
        .prepare_transfer(transfer(&h))
        .unwrap()
        .prove(&Backend, true)
        .unwrap();
    let second = h
        .session
        .prepare_transfer(transfer(&h))
        .unwrap()
        .prove(&Backend, true)
        .unwrap();
    let mut operations = vec![first, second];
    let call = h
        .session
        .aggregate(&Backend, &mut operations, h.session.wallet.owner_address())
        .unwrap();
    let snapshot = h.session.snapshot().unwrap();
    assert!(operations
        .iter()
        .all(|operation| snapshot.operations[operation.id()].externalized));
    let hash = B256::with_last_byte(8);
    h.session.track_aggregate(&mut operations, hash).unwrap();
    let state = h.session.snapshot().unwrap();
    assert!(operations
        .iter()
        .all(|operation| state.operations[operation.id()].transaction_hash == Some(hash)));
    *h.source.transaction.lock().unwrap() = Some(CanonicalTransaction {
        hash,
        to: Some(call.to),
        input: call.data,
        value: call.value,
        chain_id: context().chain_id,
        block: Some(block(10)),
    });
    {
        let mut receipt = h.source.receipt.lock().unwrap();
        receipt.transaction_hash = hash;
        receipt.success = false;
        receipt.logs.clear();
    }
    let pending = match h.session.reconcile(operations[0].id()).unwrap() {
        Reconciliation::Ready(v) => v,
        _ => panic!("expected group reconciliation"),
    };
    pending.decrypt(&AppDecryptor::default()).unwrap();
    let state = h.session.snapshot().unwrap();
    assert!(operations
        .iter()
        .all(|operation| state.operations[operation.id()].status == OperationStatus::Reverted));
    assert!(state.notes.values().all(|note| note.reserved_by.is_none()));
}
#[test]
fn canonical_reset_keeps_uncertain_operation_inputs_reserved() {
    let h = synced();
    let operation = h.session.prepare_transfer(transfer(&h)).unwrap();
    h.session.invalidate_reorg().unwrap();
    assert!(h.session.prepare_transfer(transfer(&h)).is_err());
    let mut options = RefreshOptions::from_block(0);
    options.reset = true;
    let pending = h.session.refresh(options).unwrap();
    pending.decrypt(&AppDecryptor::default()).unwrap();
    let state = h.session.snapshot().unwrap();
    assert!(!state.invalidated);
    assert_eq!(
        state.operations[operation.id()].status,
        OperationStatus::Reorged
    );
    assert_eq!(
        state.notes[&h.commitment].reserved_by.as_deref(),
        Some(operation.id())
    );
}

#[test]
fn healthy_reset_preserves_canonical_terminal_history_and_does_not_resurrect_reservations() {
    let h = synced();
    let original = h.source.receipt.lock().unwrap().clone();
    let operation = tracked_sweep(&h);
    let id = operation.id().to_owned();
    {
        let mut receipt = h.source.receipt.lock().unwrap();
        receipt.transaction_hash = B256::with_last_byte(8);
        receipt.success = false;
        receipt.logs.clear();
    }
    let pending = match h.session.reconcile(&id).unwrap() {
        Reconciliation::Ready(v) => v,
        _ => panic!("expected mined outcome"),
    };
    pending.decrypt(&AppDecryptor::default()).unwrap();
    *h.source.receipt.lock().unwrap() = original;
    let mut options = RefreshOptions::from_block(0);
    options.reset = true;
    let pending = h.session.refresh(options).unwrap();
    pending.decrypt(&AppDecryptor::default()).unwrap();
    let state = h.session.snapshot().unwrap();
    assert_eq!(state.operations[&id].status, OperationStatus::Reverted);
    assert!(state.operations[&id].resolved_at.is_some());
    assert!(state.notes[&h.commitment].reserved_by.is_none());
    assert_eq!(
        h.session
            .balance(sdk::word_address(h.note.token_address).unwrap())
            .unwrap()
            .available,
        Some(h.note.amount)
    );
}

#[test]
fn credit_relay_context_survives_encrypted_restart_and_fences_uncertain_submission() {
    let h = harness();
    let alice = wallet(1);
    let bob = wallet(2);
    let records = Arc::new(MemoryAtomicRecords::default());
    let store = Arc::new(EncryptedWalletStore::new(records.clone(), [9; 32]).unwrap());
    let connect = || {
        WalletSession::connect(
            h.session.invisi.clone(),
            alice.clone(),
            store.clone(),
            h.source.clone(),
            "relay-credit",
        )
        .unwrap()
    };
    let session = connect();
    let state = CreditDeliveryState {
        note: crate::credit::CreditState {
            context: context(),
            token_address: h.note.token_address,
            spender_wallet_identity: sdk::address_word(bob.owner_address()),
            owner_wallet_identity: sdk::address_word(alice.owner_address()),
            revocation_shard: 1,
            revocation_slot: 0,
            nonce: U256::from(74),
            expiry: 2100000000,
            credit_shared_key: U256::from(75),
            policy: crate::credit::CreditPolicy::default(),
            usage: crate::credit::CreditUsage::default(),
            available_credit: U256::from(400),
            unlimited: false,
            payload: Vec::new(),
        },
        owner_receiving_keys: alice.receiving_keys().clone(),
        spender_receiving_keys: bob.receiving_keys().clone(),
    };
    let operation = session
        .prepare_create_credit(state, 2000000100, sdk::Fee::default())
        .unwrap();
    let id = operation.id().to_string();
    drop(operation);
    let restarted = connect();
    let mut operation = restarted.resume(&id, None).unwrap();
    let relay = Arc::new(SessionCreditRelay {
        lookup_mode: std::sync::atomic::AtomicUsize::new(0),
        attempts: std::sync::atomic::AtomicUsize::new(0),
    });
    operation
        .with_broadcaster(
            relay.clone(),
            &sdk::BroadcasterOptions {
                max_fee_amount: Some(U256::from(100)),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(operation.broadcaster_state().is_some());
    let encrypted = records.read(&restarted.scope.key()).unwrap().unwrap();
    assert!(!encrypted
        .data
        .windows(b"broadcaster".len())
        .any(|v| v == b"broadcaster"));
    let request = operation.export_wallet_request("credit-consent").unwrap();
    let response: sdk::WalletResponse =
        serde_json::from_value(crate::wallet::execute(&key(1), &request.as_value()).unwrap())
            .unwrap();
    // This backend intentionally exercises journal/state transitions with synthetic main proof bytes.
    let operation = operation
        .with_wallet_response(&response)
        .unwrap()
        .prove(&Backend, false)
        .unwrap();
    drop(operation);
    let restarted = connect();
    let mut operation = restarted.resume(&id, Some(&Backend)).unwrap();
    assert!(operation.broadcaster_state().is_some());
    assert!(operation
        .submit_broadcaster(relay.as_ref())
        .unwrap_err()
        .contains("uncertain"));
    assert_eq!(relay.attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(restarted.snapshot().unwrap().operations[&id].externalized);
    assert!(restarted.cancel_operation(&id, None).is_err());
    assert_eq!(
        restarted.snapshot().unwrap().operations[&id]
            .broadcaster_id
            .as_deref(),
        Some(id.as_str())
    );
    h.chain
        .height
        .store(200, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        operation.submit_broadcaster(relay.as_ref()).unwrap().id,
        "server-owned"
    );
    relay
        .lookup_mode
        .store(1, std::sync::atomic::Ordering::SeqCst);
    assert!(operation
        .submit_broadcaster(relay.as_ref())
        .unwrap_err()
        .contains("offline"));
    relay
        .lookup_mode
        .store(2, std::sync::atomic::Ordering::SeqCst);
    assert!(operation
        .submit_broadcaster(relay.as_ref())
        .unwrap_err()
        .contains("not found"));
    assert_eq!(relay.attempts.load(std::sync::atomic::Ordering::SeqCst), 2);
}
struct SessionCreditRelay {
    lookup_mode: std::sync::atomic::AtomicUsize,
    attempts: std::sync::atomic::AtomicUsize,
}
impl sdk::PreparedBroadcaster for SessionCreditRelay {
    fn lookup_status(&self, id: &str) -> Result<Option<crate::broadcaster::Status>> {
        match self.lookup_mode.load(std::sync::atomic::Ordering::SeqCst) {
            0 => Ok(Some(crate::broadcaster::Status {
                confirmation: None,
                id: id.into(),
                state: crate::broadcaster::StatusState::Pending,
                transaction_hash: None,
            })),
            1 => Err("provider offline".into()),
            _ => Ok(None),
        }
    }
    fn configuration(&self) -> crate::broadcaster::Configuration {
        let signing = k256::ecdsa::SigningKey::from_slice(&key(1)).unwrap();
        let public = signing.verifying_key().to_encoded_point(false);
        crate::broadcaster::Configuration {
            endpoint: "https://relay.example".into(),
            quote_signer: Address::from_slice(
                &alloy_primitives::keccak256(&public.as_bytes()[1..])[12..],
            ),
            fee_recipient: Address::repeat_byte(4),
        }
    }
    fn submission_requirements(
        &self,
        q: &invisi_sdk_rpc::broadcaster::VerifiedQuote,
    ) -> Result<bool> {
        Ok(q.signed().provenance_required == Some(true))
    }
    fn provenance_mode(&self) -> Option<()> {
        None
    }
    fn fee(&self, _: Address, _: Option<&[u8]>) -> Result<crate::broadcaster::Fee> {
        Ok(crate::broadcaster::Fee {
            fee_recipient: self.configuration().fee_recipient,
            fee_amount: "1".into(),
            max_gas: "100000".into(),
        })
    }
    fn quote(
        &self,
        data: &[u8],
        chain_id: u64,
        protocol: Address,
        now: u64,
        sidecars: &[crate::provenance::ProofSidecar],
    ) -> Result<crate::broadcaster::VerifiedQuote> {
        use crate::broadcaster::*;
        assert!(sidecars.is_empty());
        let intent = decode_intent(data).unwrap();
        let trust = Trust {
            chain_id,
            protocol,
            signer: self.configuration().quote_signer,
        };
        let quote = Quote {
            execution: invisi_sdk_rpc::broadcaster::Execution::Direct,
            token: intent.token,
            fee_recipient: intent.fee_recipient,
            fee_amount: intent.fee_amount.to_string(),
            deadline: intent.deadline.to_string(),
            max_gas: "100000".into(),
            request_hash: request_hash(data).unwrap(),
        };
        let (signature, recovery) = k256::ecdsa::SigningKey::from_slice(&key(1))
            .unwrap()
            .sign_prehash_recoverable(quote_digest(&quote, &trust).unwrap().as_slice())
            .unwrap();
        let mut bytes = signature.to_bytes().to_vec();
        bytes.push(recovery.to_byte());
        VerifiedQuote::authenticate(
            SignedQuote {
                quote,
                signature: format!("0x{}", hex::encode(bytes)),

                request_hash_format: None,
                provenance_required: None,
            },
            trust,
            data,
            now,
            None,
        )
        .map_err(|e| e.to_string())
    }
    fn submit(
        &self,
        data: &[u8],
        quote: &crate::broadcaster::VerifiedQuote,
        sidecars: &[crate::provenance::ProofSidecar],
    ) -> Result<crate::broadcaster::Status> {
        assert!(sidecars.is_empty());
        crate::broadcaster::verify_quote(quote.signed(), quote.trust(), data, 0)
            .map_err(|e| e.to_string())?;
        let attempt = self
            .attempts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if attempt == 0 {
            return Err("uncertain relay response".into());
        }
        Ok(crate::broadcaster::Status {
            confirmation: None,
            id: "server-owned".into(),
            state: crate::broadcaster::StatusState::Pending,
            transaction_hash: None,
        })
    }
}

#[test]
fn funds_relay_retry_reads_known_journal_even_when_inputs_are_spent() {
    let h = synced();
    let token = sdk::word_address(h.note.token_address).unwrap();
    let output =
        sdk::NoteOutput::for_recipient(context(), token, &wallet(2), U256::from(30), Vec::new())
            .unwrap();
    let mut op = h
        .session
        .prepare_transfer(sdk::TransferPreparation {
            token,
            inputs: Vec::new(),
            outputs: vec![output],
            withdrawal: None,
            funding: sdk::empty_funding(),
            fee: sdk::Fee::default(),
            deadline: 2000000100,
            automatic_change: true,
        })
        .unwrap();
    let relay = Arc::new(SessionCreditRelay {
        lookup_mode: std::sync::atomic::AtomicUsize::new(0),
        attempts: std::sync::atomic::AtomicUsize::new(0),
    });
    op.with_broadcaster(
        relay.clone(),
        &sdk::BroadcasterOptions {
            max_fee_amount: Some(U256::from(100)),
            ..Default::default()
        },
    )
    .unwrap();
    let request = op.export_wallet_request("funds-relay").unwrap();
    let response: sdk::WalletResponse =
        serde_json::from_value(crate::wallet::execute(&key(1), &request.as_value()).unwrap())
            .unwrap();
    let mut op = op
        .with_wallet_response(&response)
        .unwrap()
        .prove(&Backend, false)
        .unwrap();
    let id = op.id().to_string();
    assert!(op.submit_broadcaster(relay.as_ref()).is_err());
    drop(op);
    h.chain
        .spent
        .lock()
        .unwrap()
        .insert(sdk::field_word(h.note.nullifier().unwrap()));
    h.chain
        .height
        .store(200, std::sync::atomic::Ordering::SeqCst);
    let mut op = h.session.resume(&id, Some(&Backend)).unwrap();
    assert_eq!(
        op.submit_broadcaster(relay.as_ref()).unwrap().id,
        "server-owned"
    );
    relay
        .lookup_mode
        .store(1, std::sync::atomic::Ordering::SeqCst);
    assert!(op
        .submit_broadcaster(relay.as_ref())
        .unwrap_err()
        .contains("offline"));
    relay
        .lookup_mode
        .store(2, std::sync::atomic::Ordering::SeqCst);
    assert!(op
        .submit_broadcaster(relay.as_ref())
        .unwrap_err()
        .contains("not found"));
    assert_eq!(relay.attempts.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[test]
fn managed_note_and_credit_estimate_without_externalizing() {
    for credit in [false, true] {
        let h = synced();
        let caller = h.session.wallet.owner_address();
        let mut operation = if credit {
            let state = CreditDeliveryState {
                note: crate::credit::CreditState {
                    context: context(),
                    token_address: h.note.token_address,
                    spender_wallet_identity: sdk::address_word(wallet(2).owner_address()),
                    owner_wallet_identity: sdk::address_word(caller),
                    revocation_shard: 1,
                    revocation_slot: 0,
                    nonce: U256::from(74),
                    expiry: 2100000000,
                    credit_shared_key: U256::from(75),
                    policy: Default::default(),
                    usage: Default::default(),
                    available_credit: U256::from(400),
                    unlimited: false,
                    payload: Vec::new(),
                },
                owner_receiving_keys: h.session.wallet.receiving_keys().clone(),
                spender_receiving_keys: wallet(2).receiving_keys().clone(),
            };
            h.session
                .prepare_create_credit(state, 2000000100, sdk::Fee::default())
                .unwrap()
        } else {
            h.session.prepare_transfer(transfer(&h)).unwrap()
        };
        let before = serde_json::to_value(h.session.snapshot().unwrap()).unwrap();
        h.store.forbidden.store(true, Ordering::SeqCst);
        h.chain.gas_forbidden.store(true, Ordering::SeqCst);
        let estimate = operation.estimate_gas().unwrap();
        h.store.forbidden.store(false, Ordering::SeqCst);
        h.chain.gas_forbidden.store(false, Ordering::SeqCst);
        assert_eq!(
            serde_json::to_value(&estimate).unwrap()["source"],
            "benchmark"
        );
        assert_eq!(
            before,
            serde_json::to_value(h.session.snapshot().unwrap()).unwrap()
        );
        assert_eq!(estimate, operation.estimate_gas().unwrap());
        assert!(!h.session.snapshot().unwrap().operations[operation.id()].externalized);
        if credit {
            let request = operation.export_wallet_request("gas-consent").unwrap();
            let response: WalletResponse = serde_json::from_value(
                crate::wallet::execute(&key(1), &request.as_value()).unwrap(),
            )
            .unwrap();
            operation = operation.with_wallet_response(&response).unwrap();
        }
        let operation = operation.prove(&Backend, false).unwrap();
        h.store.forbidden.store(true, Ordering::SeqCst);
        assert_eq!(estimate, operation.estimate_gas().unwrap());
        h.store.forbidden.store(false, Ordering::SeqCst);
        assert!(!h.session.snapshot().unwrap().operations[operation.id()].externalized);
    }
}

#[path = "source_reproof_tests.rs"]
mod source_reproof_tests;

#[test]
fn private_reverse_ranges_preserve_maximum_and_fill_actual_gaps() {
    let h = harness();
    h.session
        .refresh(RefreshOptions {
            from_block: 8,
            to_block: Some(10),
            page_size: 3,
            reset: false,
        })
        .unwrap()
        .decrypt(&AppDecryptor::default())
        .unwrap();
    let state = h.session.snapshot().unwrap();
    assert!(state.discovery_through.is_none());
    assert_eq!(state.discovery_ranges[0].from_block, 8);
    h.session
        .refresh(RefreshOptions {
            from_block: 0,
            to_block: Some(7),
            page_size: 8,
            reset: false,
        })
        .unwrap()
        .decrypt(&AppDecryptor::default())
        .unwrap();
    let state = h.session.snapshot().unwrap();
    assert_eq!(state.discovery_through.unwrap().number, 10);
    assert_eq!(state.observed_through.unwrap().number, 10);
}

#[test]
fn ambiguous_authentication_persists_unresolved_and_operational_failure_aborts() {
    struct Ambiguous;
    impl crate::delivery::DeliveryDecryptor for Ambiguous {
        fn decrypt_note(
            &self,
            _: &[u8],
            _: &crate::delivery::DeliveryContext,
            _: U256,
        ) -> Result<Option<Vec<u8>>> {
            panic!("outcome override must be used")
        }
        fn decrypt_credit(
            &self,
            _: &[u8],
            _: &crate::delivery::DeliveryContext,
            _: CreditRole,
            _: U256,
        ) -> Result<Option<Vec<u8>>> {
            Ok(None)
        }
        fn decrypt_note_outcome(
            &self,
            _: &[u8],
            _: &crate::delivery::DeliveryContext,
            _: U256,
        ) -> Result<crate::delivery::DecryptionOutcome> {
            Ok(crate::delivery::DecryptionOutcome::AuthenticationFailed)
        }
    }
    let h = harness();
    h.session
        .refresh(RefreshOptions::from_block(0))
        .unwrap()
        .decrypt(&Ambiguous)
        .unwrap();
    assert_eq!(h.session.snapshot().unwrap().unresolved_deliveries.len(), 1);
    h.session
        .retry_unresolved(&AppDecryptor::default())
        .unwrap();
    assert!(h
        .session
        .snapshot()
        .unwrap()
        .unresolved_deliveries
        .is_empty());
    assert!(h
        .session
        .snapshot()
        .unwrap()
        .notes
        .contains_key(&h.commitment));
}

#[test]
fn priority_scan_commits_new_assets_before_descending_old_gaps_and_resumes() {
    let h = harness();
    let options = ScanOptions {
        page_size: 3,
        ..Default::default()
    };
    let cancel = crate::public_history::CancellationToken::default();
    let mut ranges = vec![];
    h.session
        .scan_with_progress(
            &AppDecryptor::default(),
            options.clone(),
            &cancel,
            |result| {
                ranges.push(result.block.number);
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(ranges, vec![10, 7, 4, 1]);
    let state = h.session.snapshot().unwrap();
    assert_eq!(state.discovery_through.unwrap().number, 10);
    assert!(state.notes.contains_key(&h.commitment));
    let mut called = false;
    h.session
        .scan_with_progress(&AppDecryptor::default(), options, &cancel, |_| {
            called = true;
            Ok(())
        })
        .unwrap();
    assert!(!called);
}

#[test]
fn shared_public_history_second_account_reuses_receipts_and_private_coverage_is_independent() {
    use crate::public_history::*;
    let h = harness();
    let history = Arc::new(
        PublicHistory::new(
            Arc::new(
                PublicHistoryStore::new(
                    Arc::new(MemoryAtomicRecords::default()),
                    Retention::default(),
                )
                .unwrap(),
            ),
            PublicHistoryScope {
                chain_id: context().chain_id,
                protocol_address: sdk::word_address(context().protocol_address).unwrap(),
                runtime_code_hash: B256::with_last_byte(42),
                deployment_block: 0,
            },
            h.source.clone(),
        )
        .unwrap(),
    );
    let a = h
        .session
        .clone()
        .with_public_history(history.clone())
        .unwrap();
    a.scan(&AppDecryptor::default(), ScanOptions::default())
        .unwrap();
    assert_eq!(h.source.receipt_reads.load(Ordering::SeqCst), 1);
    let updates = h.source.discovery_reads.load(Ordering::SeqCst);
    let b = WalletSession::connect(
        Invisi::new(h.chain.clone()),
        wallet(2),
        Arc::new(MemoryWalletStore::default()),
        h.source.clone(),
        "b",
    )
    .unwrap()
    .with_public_history(history)
    .unwrap();
    assert!(b.snapshot().unwrap().discovery_ranges.is_empty());
    b.scan(
        &AppDecryptor {
            nonrecipient: true,
            ..Default::default()
        },
        ScanOptions::default(),
    )
    .unwrap();
    assert_eq!(h.source.receipt_reads.load(Ordering::SeqCst), 1);
    assert_eq!(h.source.discovery_reads.load(Ordering::SeqCst), updates);
    assert!(b.snapshot().unwrap().notes.is_empty());
    assert_eq!(b.scan_status().unwrap().fully_scanned_height, Some(10));
    assert!(a.snapshot().unwrap().notes.contains_key(&h.commitment));
}
#[test]
fn native_detection_receives_complete_context_and_false_skips_decrypt() {
    struct Detect;
    impl crate::delivery::DeliveryDecryptor for Detect {
        fn decrypt_note(
            &self,
            _: &[u8],
            _: &crate::delivery::DeliveryContext,
            _: U256,
        ) -> Result<Option<Vec<u8>>> {
            panic!("false detection must skip decrypt")
        }
        fn decrypt_credit(
            &self,
            _: &[u8],
            _: &crate::delivery::DeliveryContext,
            _: CreditRole,
            _: U256,
        ) -> Result<Option<Vec<u8>>> {
            panic!("no Credit candidate")
        }
        fn detect(&self, c: &[crate::delivery::DetectionCandidate]) -> Result<Vec<bool>> {
            assert_eq!(c.len(), 1);
            assert_eq!(c[0].clue.len(), 68);
            assert_eq!(c[0].context.context, context());
            assert_eq!(c[0].context.token_address, U256::from(22136));
            assert_ne!(c[0].context.output_commitment, U256::ZERO);
            assert_eq!(c[0].owner, sdk::address_word(wallet(1).owner_address()));
            assert_eq!(c[0].role, crate::delivery::DeliveryRole::Funds);
            Ok(vec![false])
        }
    }
    let h = harness();
    h.session.scan(&Detect, ScanOptions::default()).unwrap();
    assert!(h.session.snapshot().unwrap().notes.is_empty());
    assert_eq!(
        h.session
            .snapshot()
            .unwrap()
            .discovery_through
            .unwrap()
            .number,
        10
    );
}
#[test]
fn cancelled_priority_scan_resumes_only_actual_gaps() {
    let h = harness();
    let token = crate::public_history::CancellationToken::default();
    let result = h.session.scan_with_progress(
        &AppDecryptor::default(),
        ScanOptions {
            page_size: 3,
            ..Default::default()
        },
        &token,
        |_| {
            token.cancel();
            Ok(())
        },
    );
    assert!(result.is_err());
    assert_eq!(
        h.session.snapshot().unwrap().discovery_ranges[0].from_block,
        8
    );
    assert!(h
        .session
        .snapshot()
        .unwrap()
        .notes
        .contains_key(&h.commitment));
    let mut ranges = vec![];
    h.session
        .scan_with_progress(
            &AppDecryptor::default(),
            ScanOptions {
                page_size: 3,
                ..Default::default()
            },
            &crate::public_history::CancellationToken::default(),
            |r| {
                ranges.push(r.block.number);
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(ranges, vec![7, 4, 1]);
}

#[test]
fn reverse_discovery_replays_credit_successor_after_late_parent() {
    use crate::credit::{CreditPolicy, CreditState, CreditUsage};
    let h = harness();
    let alice = wallet(1);
    let bob = wallet(2);
    let state = CreditDeliveryState {
        note: CreditState {
            context: context(),
            token_address: h.note.token_address,
            spender_wallet_identity: sdk::address_word(bob.owner_address()),
            owner_wallet_identity: sdk::address_word(alice.owner_address()),
            revocation_shard: 1,
            revocation_slot: 0,
            nonce: U256::from(74),
            expiry: 2_100_000_000,
            credit_shared_key: U256::from(75),
            policy: CreditPolicy::default(),
            usage: CreditUsage::default(),
            available_credit: U256::from(400),
            unlimited: false,
            payload: Vec::new(),
        },
        owner_receiving_keys: alice.receiving_keys().clone(),
        spender_receiving_keys: bob.receiving_keys().clone(),
    };
    let delivery_for = |state: &CreditDeliveryState, role: CreditRole| {
        let keys = if role == CreditRole::Owner {
            &state.owner_receiving_keys
        } else {
            &state.spender_receiving_keys
        };
        let context = crate::delivery::DeliveryContext {
            context: context(),
            token_address: state.note.token_address,
            output_commitment: state.note.commitment().unwrap(),
        };
        abi::Delivery {
            ciphertext: crate::delivery::encrypt_credit(
                &keys.viewing_public_key,
                state,
                &context,
                role,
            )
            .unwrap()
            .into(),
            clue: crate::fmd::create_clue(&keys.clue_key).unwrap().into(),
        }
    };
    let commitment = sdk::field_word(state.note.commitment().unwrap());
    let path = [U256::ZERO; 16];
    let root = sdk::merkle_root(U256::from_be_slice(commitment.as_slice()), 0, &path).unwrap();
    h.chain.roots.lock().unwrap().insert(sdk::field_word(root));
    h.source
        .proofs
        .lock()
        .unwrap()
        .insert(commitment, (2, 0, path, root));
    let created = P::CreditCreated {
        token: sdk::word_address(h.note.token_address).unwrap(),
        owner: alice.owner_address(),
        outputTreeId: U256::from(2),
        revocationShard: 1,
        revocationSlot: 0,
        creditCommitment: commitment,
        leafIndex: 0,
        deliveries: vec![
            delivery_for(&state, CreditRole::Owner),
            delivery_for(&state, CreditRole::Spender),
        ],
        deadline: U256::from(2_000_000_100u64),
        feeRecipient: Address::ZERO,
        feeAmount: U256::ZERO,
    };
    let insertion = P::CommitmentsInserted {
        treeId: U256::from(2),
        startLeafIndex: 0,
        commitments: vec![commitment],
    };
    h.source.receipt.lock().unwrap().logs = vec![log(&insertion, 0), log(&created, 1)];
    let mut parent_receipt = h.source.receipt.lock().unwrap().clone();
    parent_receipt.block = block(4);
    h.source.extra_receipts.lock().unwrap().push(parent_receipt);
    let parent_cipher = created.deliveries[0].ciphertext.to_vec();
    let transition =
        crate::credit::derive_credit_state(&state.note, U256::from(30), block(10).timestamp)
            .unwrap();
    let successor = CreditDeliveryState {
        note: transition.state.clone(),
        owner_receiving_keys: state.owner_receiving_keys.clone(),
        spender_receiving_keys: state.spender_receiving_keys.clone(),
    };
    let output = sdk::NoteOutput::for_recipient(
        context(),
        sdk::word_address(h.note.token_address).unwrap(),
        &bob,
        U256::from(30),
        Vec::new(),
    )
    .unwrap();
    let credit_commitment = sdk::field_word(transition.state_commitment);
    let note_commitment = output.commitment();
    let mut credit_path = [U256::ZERO; 16];
    credit_path[0] = U256::from_be_slice(note_commitment.as_slice());
    let mut note_path = [U256::ZERO; 16];
    note_path[0] = U256::from_be_slice(credit_commitment.as_slice());
    let next_root = sdk::merkle_root(transition.state_commitment, 0, &credit_path).unwrap();
    assert_eq!(
        sdk::merkle_root(
            U256::from_be_slice(note_commitment.as_slice()),
            1,
            &note_path
        )
        .unwrap(),
        next_root
    );
    h.chain
        .roots
        .lock()
        .unwrap()
        .insert(sdk::field_word(next_root));
    h.source
        .proofs
        .lock()
        .unwrap()
        .insert(credit_commitment, (3, 0, credit_path, next_root));
    h.source
        .proofs
        .lock()
        .unwrap()
        .insert(note_commitment, (3, 1, note_path, next_root));
    h.chain
        .spent
        .lock()
        .unwrap()
        .insert(sdk::field_word(transition.nullifier));
    let params = abi::CreditDrawParams {
        token: sdk::word_address(h.note.token_address).unwrap(),
        sources: vec![abi::InputSource {
            treeId: U256::from(2),
            merkleRoot: sdk::field_word(root),
        }],
        payers: vec![abi::CreditPayer {
            payer: alice.owner_address(),
            amount: U256::from(30),
        }],
        grantRefs: vec![abi::CreditGrantRef {
            payerIndex: U256::ZERO,
            shard: 1,
            slot: 0,
        }],
        nullifiers: vec![sdk::field_word(transition.nullifier)],
        creditCommitments: vec![credit_commitment],
        recoveryAmounts: vec![sdk::field_word(transition.recovery_amount)],
        noteCommitment: note_commitment,
        totalAmount: U256::from(30),
        deadline: U256::from(2_000_000_100u64),
        feeRecipient: Address::ZERO,
        feeAmount: U256::ZERO,
    };
    let draw = P::CreditDraw {
        outputTreeId: U256::from(3),
        params,
        leafIndices: vec![0, 1],
        deliveries: vec![
            delivery_for(&successor, CreditRole::Owner),
            delivery_for(&successor, CreditRole::Spender),
            output.delivery().clone(),
        ],
    };
    let insertion = P::CommitmentsInserted {
        treeId: U256::from(3),
        startLeafIndex: 0,
        commitments: vec![credit_commitment, note_commitment],
    };
    {
        let mut receipt = h.source.receipt.lock().unwrap();
        receipt.transaction_hash = B256::with_last_byte(8);
        receipt.logs = vec![log(&insertion, 2), log(&draw, 3)];
    }
    struct ParentOnly(Vec<u8>);
    impl crate::delivery::DeliveryDecryptor for ParentOnly {
        fn decrypt_note(
            &self,
            _: &[u8],
            _: &crate::delivery::DeliveryContext,
            _: U256,
        ) -> Result<Option<Vec<u8>>> {
            Ok(None)
        }
        fn decrypt_credit(
            &self,
            e: &[u8],
            c: &crate::delivery::DeliveryContext,
            r: CreditRole,
            o: U256,
        ) -> Result<Option<Vec<u8>>> {
            if e == self.0 {
                AppDecryptor::default().decrypt_credit(e, c, r, o)
            } else {
                Ok(None)
            }
        }
    }
    let decryptor = ParentOnly(parent_cipher);
    let result = h
        .session
        .scan(
            &decryptor,
            ScanOptions {
                page_size: 3,
                ..Default::default()
            },
        )
        .unwrap();
    let after = h.session.snapshot().unwrap();
    assert!(after
        .credits
        .contains_key(&credit_key(commitment, CreditRole::Owner)));
    assert!(after
        .credits
        .contains_key(&credit_key(credit_commitment, CreditRole::Owner)));
    assert!(result.credits >= 2);
    assert!(after.credit_replay_from.is_none());
}

#[test]
fn history_generation_change_invalidates_before_status_or_funds_can_reuse_inventory() {
    use crate::public_history::*;
    let h = synced();
    let history = Arc::new(
        PublicHistory::new(
            Arc::new(
                PublicHistoryStore::new(
                    Arc::new(MemoryAtomicRecords::default()),
                    Retention::default(),
                )
                .unwrap(),
            ),
            PublicHistoryScope {
                chain_id: context().chain_id,
                protocol_address: sdk::word_address(context().protocol_address).unwrap(),
                runtime_code_hash: B256::with_last_byte(42),
                deployment_block: 0,
            },
            h.source.clone(),
        )
        .unwrap(),
    );
    let session = h
        .session
        .clone()
        .with_public_history(history.clone())
        .unwrap();
    history.store.rewind(&history.scope, None).unwrap();
    assert!(session.scan_status().unwrap().invalidated);
    assert!(
        !session
            .funds_status(sdk::word_address(h.note.token_address).unwrap())
            .unwrap()
            .are_funds_spendable
    );
    assert!(session
        .scan(&AppDecryptor::default(), ScanOptions::default())
        .is_err());
}
#[test]
fn paginated_history_includes_active_records_and_rejects_revision_changes() {
    let h = synced();
    let page = h.session.history_page(None, 1).unwrap();
    assert_eq!(page.entries.len(), 1);
    assert!(matches!(page.entries[0].record, WalletRecord::Note(_)));
    let mut state = h.session.snapshot().unwrap();
    state.recovery_boundary = Some(10);
    h.session.commit(state).unwrap();
    if let Some(cursor) = page.next_cursor {
        assert!(h.session.history_page(Some(&cursor), 1).is_err())
    }
}
#[test]
fn archived_externalized_journal_restores_its_input_lock_before_rebuild() {
    let h = synced();
    let operation = tracked_sweep(&h);
    let id = operation.id().to_owned();
    let mut state = h.session.snapshot().unwrap();
    let op = state.operations.get_mut(&id).unwrap();
    op.status = OperationStatus::Confirmed;
    op.resolved_at = Some(block(10));
    let note = state.notes.get_mut(&h.commitment).unwrap();
    note.block = block(4);
    note.spent = true;
    note.reserved_by = None;
    let records = Arc::new(MemoryAtomicRecords::default());
    let store = Arc::new(RecordWalletStore::with_recent_records(records, [8; 32], 0).unwrap());
    state.revision = 0;
    store
        .compare_and_swap(&h.session.scope.key(), 0, state)
        .unwrap();
    let session = WalletSession::connect(
        Invisi::new(h.chain.clone()),
        wallet(1),
        store.clone(),
        h.source.clone(),
        "test",
    )
    .unwrap();
    assert!(session.snapshot().unwrap().operations.is_empty());
    assert!(session.snapshot().unwrap().notes.is_empty());
    session.invalidate_reorg_from(8).unwrap();
    let state = session.snapshot().unwrap();
    assert!(state.invalidated);
    assert_eq!(state.operations[&id].status, OperationStatus::Reorged);
    assert_eq!(
        state.notes[&h.commitment].reserved_by.as_deref(),
        Some(id.as_str())
    );
    assert!(session.prepare_transfer(transfer(&h)).is_err());
    let mut options = RefreshOptions::from_block(0);
    options.reset = true;
    session
        .refresh(options)
        .unwrap()
        .decrypt(&AppDecryptor::default())
        .unwrap();
    let after = session.snapshot().unwrap();
    assert_eq!(
        after.notes[&h.commitment].reserved_by.as_deref(),
        Some(id.as_str())
    );
}
#[test]
fn replaying_earlier_snapshot_cannot_clear_later_credit_obligation() {
    let h = synced();
    h.source.indexed_height.store(16, Ordering::SeqCst);
    let mut state = h.session.snapshot().unwrap();
    state.credit_replay_from = Some(0);
    state.credit_replay_target = Some(16);
    state.credit_replay_revision = 1;
    h.session.commit(state).unwrap();
    h.session
        .replay_credits(
            &AppDecryptor::default(),
            14,
            7,
            &crate::public_history::CancellationToken::default(),
        )
        .unwrap();
    let state = h.session.snapshot().unwrap();
    assert_eq!(state.credit_replay_target, Some(16));
    assert_eq!(state.credit_replay_from, Some(0));
    assert_eq!(state.credit_replay_through, Some(14));
    h.session
        .replay_credits(
            &AppDecryptor::default(),
            16,
            7,
            &crate::public_history::CancellationToken::default(),
        )
        .unwrap();
    assert!(h.session.snapshot().unwrap().credit_replay_from.is_none());
}
#[test]
fn empty_pages_do_not_decrypt_and_refresh_known_funds_at_primary_head_despite_indexer_lag() {
    struct Empty;
    impl crate::delivery::DeliveryDecryptor for Empty {
        fn detect(&self, _: &[crate::delivery::DetectionCandidate]) -> Result<Vec<bool>> {
            panic!("empty batch must not invoke detect")
        }
        fn decrypt_note(
            &self,
            _: &[u8],
            _: &crate::delivery::DeliveryContext,
            _: U256,
        ) -> Result<Option<Vec<u8>>> {
            panic!("empty batch must not decrypt")
        }
        fn decrypt_credit(
            &self,
            _: &[u8],
            _: &crate::delivery::DeliveryContext,
            _: CreditRole,
            _: U256,
        ) -> Result<Option<Vec<u8>>> {
            panic!("empty batch must not decrypt")
        }
    }
    let h = synced();
    h.chain.height.store(16, Ordering::SeqCst);
    let nullifier = h.session.snapshot().unwrap().notes[&h.commitment].nullifier;
    h.chain.spent.lock().unwrap().insert(nullifier);
    h.session
        .scan(
            &Empty,
            ScanOptions {
                to_block: Some(7),
                ..Default::default()
            },
        )
        .unwrap();
    let state = h.session.snapshot().unwrap();
    assert_eq!(state.observed_through.unwrap().number, 16);
    assert!(state.notes[&h.commitment].spent);
    assert!(
        !h.session
            .funds_status(sdk::word_address(h.note.token_address).unwrap())
            .unwrap()
            .are_funds_spendable
    );
}
#[test]
fn cancelled_shared_download_does_not_cancel_another_subscriber_or_duplicate_receipts() {
    use crate::public_history::*;
    struct Slow {
        source: Arc<Source>,
        started: Mutex<Option<std::sync::mpsc::Sender<()>>>,
    }
    impl SessionSource for Slow {
        fn context(&self) -> ProtocolContext {
            self.source.context()
        }
        fn deployment_start(&self) -> u64 {
            0
        }
        fn indexed_head(&self) -> Result<CanonicalBlock> {
            self.source.indexed_head()
        }
        fn block(&self, n: u64) -> Result<CanonicalBlock> {
            self.source.block(n)
        }
        fn discover(&self, f: u64, t: u64) -> Result<Vec<B256>> {
            self.source.discover(f, t)
        }
        fn receipt(&self, h: B256) -> Result<Option<CanonicalReceipt>> {
            if let Some(s) = self.started.lock().unwrap().take() {
                s.send(()).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            self.source.receipt(h)
        }
        fn transaction(&self, h: B256) -> Result<Option<CanonicalTransaction>> {
            self.source.transaction(h)
        }
        fn known_root(&self, tree: u64, root: B256, block: &CanonicalBlock) -> Result<bool> {
            self.source.known_root(tree, root, block)
        }
        fn membership(&self, i: &MembershipInput, b: &CanonicalBlock) -> Result<Membership> {
            self.source.membership(i, b)
        }
    }
    let h = harness();
    let (tx, rx) = std::sync::mpsc::channel();
    let source = Arc::new(Slow {
        source: h.source.clone(),
        started: Mutex::new(Some(tx)),
    });
    let history = Arc::new(
        PublicHistory::new(
            Arc::new(
                PublicHistoryStore::new(
                    Arc::new(MemoryAtomicRecords::default()),
                    Retention::default(),
                )
                .unwrap(),
            ),
            PublicHistoryScope {
                chain_id: context().chain_id,
                protocol_address: sdk::word_address(context().protocol_address).unwrap(),
                runtime_code_hash: B256::with_last_byte(42),
                deployment_block: 0,
            },
            source,
        )
        .unwrap(),
    );
    let token = CancellationToken::default();
    let worker = {
        let history = history.clone();
        let token = token.clone();
        std::thread::spawn(move || history.acquire(0, 10, &token))
    };
    rx.recv().unwrap();
    token.cancel();
    let other = {
        let history = history.clone();
        std::thread::spawn(move || history.acquire(0, 10, &CancellationToken::default()))
    };
    assert!(worker.join().unwrap().is_err());
    assert_eq!(other.join().unwrap().unwrap().0.receipts.len(), 1);
    assert_eq!(h.source.receipt_reads.load(Ordering::SeqCst), 1);
}
#[test]
fn offline_account_recovers_from_retained_public_proofs_without_rpc_or_spendable_claim() {
    use crate::public_history::*;
    let h = harness();
    let store = Arc::new(
        PublicHistoryStore::new(
            Arc::new(MemoryAtomicRecords::default()),
            Retention::default(),
        )
        .unwrap(),
    );
    let history = Arc::new(
        PublicHistory::new(
            store,
            PublicHistoryScope {
                chain_id: context().chain_id,
                protocol_address: sdk::word_address(context().protocol_address).unwrap(),
                runtime_code_hash: B256::with_last_byte(42),
                deployment_block: 0,
            },
            h.source.clone(),
        )
        .unwrap(),
    );
    history
        .sync(PublicSyncOptions::default(), &CancellationToken::default())
        .unwrap();
    let session = h.session.clone().with_public_history(history).unwrap();
    h.chain.reorg.store(true, Ordering::SeqCst);
    session
        .scan(
            &AppDecryptor::default(),
            ScanOptions {
                offline: true,
                ..Default::default()
            },
        )
        .unwrap();
    let state = session.snapshot().unwrap();
    assert!(state.notes.contains_key(&h.commitment));
    assert!(state.observed_through.is_none());
    assert_eq!(state.discovery_through.unwrap().number, 10);
    assert!(session
        .balance(sdk::word_address(h.note.token_address).unwrap())
        .unwrap()
        .available
        .is_none());
    assert!(
        !session
            .funds_status(sdk::word_address(h.note.token_address).unwrap())
            .unwrap()
            .are_funds_spendable
    );
}
#[test]
fn empty_scan_reconciles_reverted_inflight_at_primary_head_ahead_of_indexer() {
    let h = synced();
    let operation = tracked_sweep(&h);
    let id = operation.id().to_owned();
    h.chain.height.store(16, Ordering::SeqCst);
    {
        let mut r = h.source.receipt.lock().unwrap();
        r.transaction_hash = B256::with_last_byte(8);
        r.block = block(16);
        r.success = false;
        r.logs.clear();
    }
    h.source.transaction.lock().unwrap().as_mut().unwrap().block = Some(block(16));
    h.session
        .scan(&AppDecryptor::default(), ScanOptions::default())
        .unwrap();
    let state = h.session.snapshot().unwrap();
    assert_eq!(state.operations[&id].status, OperationStatus::Reverted);
    assert!(state.notes[&h.commitment].reserved_by.is_none());
    assert_eq!(state.observed_through.unwrap().number, 16);
}
#[test]
fn reorg_reset_discards_orphan_unresolved_deliveries_when_new_chain_has_no_output() {
    let h = harness();
    let mut state = h.session.snapshot().unwrap();
    state.unresolved_deliveries.insert(
        "orphan".into(),
        UnresolvedDelivery {
            receipt: h.source.receipt.lock().unwrap().clone(),
            key: "orphan".into(),
        },
    );
    h.session.commit(state).unwrap();
    h.session.invalidate_reorg_from(8).unwrap();
    h.source.receipt.lock().unwrap().logs.clear();
    let mut options = RefreshOptions::from_block(0);
    options.reset = true;
    h.session
        .refresh(options)
        .unwrap()
        .decrypt(&AppDecryptor::default())
        .unwrap();
    assert!(h
        .session
        .snapshot()
        .unwrap()
        .unresolved_deliveries
        .is_empty());
    assert_eq!(
        h.session.snapshot().unwrap().unresolved_delivery_count,
        Some(0)
    );
}

#[test]
fn complete_same_height_fork_invalidates_before_empty_scan_and_sync_can_reuse_old_assets() {
    use crate::public_history::*;
    let h = harness();
    let scope = PublicHistoryScope {
        chain_id: context().chain_id,
        protocol_address: sdk::word_address(context().protocol_address).unwrap(),
        runtime_code_hash: B256::with_last_byte(42),
        deployment_block: 0,
    };
    let history = Arc::new(
        PublicHistory::new(
            Arc::new(
                PublicHistoryStore::new(
                    Arc::new(MemoryAtomicRecords::default()),
                    Retention::default(),
                )
                .unwrap(),
            ),
            scope,
            h.source.clone(),
        )
        .unwrap(),
    );
    let session = h
        .session
        .clone()
        .with_public_history(history.clone())
        .unwrap();
    session
        .scan(&AppDecryptor::default(), ScanOptions::default())
        .unwrap();
    assert!(
        session
            .funds_status(sdk::word_address(h.note.token_address).unwrap())
            .unwrap()
            .are_funds_spendable
    );
    h.source.fork.store(true, Ordering::SeqCst);
    assert!(session
        .scan(&AppDecryptor::default(), ScanOptions::default())
        .is_err());
    assert_eq!(history.snapshot().unwrap().generation, 2);
    assert!(session.snapshot().unwrap().invalidated);
    assert!(
        !session
            .funds_status(sdk::word_address(h.note.token_address).unwrap())
            .unwrap()
            .are_funds_spendable
    );
}
#[test]
fn runtime_code_hash_is_bound_when_source_exposes_it() {
    use crate::public_history::*;
    let h = harness();
    let scope = PublicHistoryScope {
        chain_id: context().chain_id,
        protocol_address: sdk::word_address(context().protocol_address).unwrap(),
        runtime_code_hash: B256::with_last_byte(42),
        deployment_block: 0,
    };
    let store = Arc::new(
        PublicHistoryStore::new(
            Arc::new(MemoryAtomicRecords::default()),
            Retention::default(),
        )
        .unwrap(),
    );
    let history =
        Arc::new(PublicHistory::new(store.clone(), scope.clone(), h.source.clone()).unwrap());
    *h.source.runtime_hash.lock().unwrap() = Some(B256::with_last_byte(43));
    assert!(PublicHistory::new(store, scope, h.source.clone()).is_err());
    assert!(h.session.with_public_history(history).is_err());
}
#[cfg(feature = "sqlite")]
#[test]
fn sqlite_public_cache_reopen_reuses_receipts_across_accounts() {
    use crate::public_history::*;
    let h = harness();
    let path = std::env::temp_dir().join(format!(
        "invisi-public-history-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    let scope = PublicHistoryScope {
        chain_id: context().chain_id,
        protocol_address: sdk::word_address(context().protocol_address).unwrap(),
        runtime_code_hash: B256::with_last_byte(42),
        deployment_block: 0,
    };
    {
        let history = Arc::new(
            PublicHistory::new(
                Arc::new(
                    PublicHistoryStore::new(
                        Arc::new(sqlite::SQLiteRecords::open_public(&path).unwrap()),
                        Retention::default(),
                    )
                    .unwrap(),
                ),
                scope.clone(),
                h.source.clone(),
            )
            .unwrap(),
        );
        let a = h.session.clone().with_public_history(history).unwrap();
        a.scan(&AppDecryptor::default(), ScanOptions::default())
            .unwrap();
    }
    let reads = h.source.receipt_reads.load(Ordering::SeqCst);
    {
        let history = Arc::new(
            PublicHistory::new(
                Arc::new(
                    PublicHistoryStore::new(
                        Arc::new(sqlite::SQLiteRecords::open_public(&path).unwrap()),
                        Retention::default(),
                    )
                    .unwrap(),
                ),
                scope,
                h.source.clone(),
            )
            .unwrap(),
        );
        let b = WalletSession::connect(
            Invisi::new(h.chain.clone()),
            wallet(2),
            Arc::new(MemoryWalletStore::default()),
            h.source.clone(),
            "persisted-b",
        )
        .unwrap()
        .with_public_history(history)
        .unwrap();
        b.scan(
            &AppDecryptor {
                nonrecipient: true,
                ..Default::default()
            },
            ScanOptions::default(),
        )
        .unwrap();
        assert_eq!(h.source.receipt_reads.load(Ordering::SeqCst), reads);
        assert_eq!(b.scan_status().unwrap().fully_scanned_height, Some(10));
    }
    let _ = std::fs::remove_file(path);
}
#[test]
fn public_sync_validates_canonical_coverage_even_when_fully_downloaded() {
    use crate::public_history::*;
    let h = harness();
    let history = PublicHistory::new(
        Arc::new(
            PublicHistoryStore::new(
                Arc::new(MemoryAtomicRecords::default()),
                Retention::default(),
            )
            .unwrap(),
        ),
        PublicHistoryScope {
            chain_id: context().chain_id,
            protocol_address: sdk::word_address(context().protocol_address).unwrap(),
            runtime_code_hash: B256::with_last_byte(42),
            deployment_block: 0,
        },
        h.source.clone(),
    )
    .unwrap();
    history
        .sync(PublicSyncOptions::default(), &CancellationToken::default())
        .unwrap();
    h.source.fork.store(true, Ordering::SeqCst);
    assert!(history
        .sync(PublicSyncOptions::default(), &CancellationToken::default())
        .is_err());
    assert_eq!(history.snapshot().unwrap().generation, 2);
    assert!(history.snapshot().unwrap().coverage.is_empty());
}

#[test]
fn public_cache_rejects_self_consistent_merkle_path_with_unknown_canonical_root() {
    use crate::public_history::*;
    let h = harness();
    h.chain.roots.lock().unwrap().clear();
    let history = PublicHistory::new(
        Arc::new(
            PublicHistoryStore::new(
                Arc::new(MemoryAtomicRecords::default()),
                Retention::default(),
            )
            .unwrap(),
        ),
        PublicHistoryScope {
            chain_id: context().chain_id,
            protocol_address: sdk::word_address(context().protocol_address).unwrap(),
            runtime_code_hash: B256::with_last_byte(42),
            deployment_block: 0,
        },
        h.source.clone(),
    )
    .unwrap();
    assert!(history
        .sync(PublicSyncOptions::default(), &CancellationToken::default())
        .unwrap_err()
        .contains("not canonical"));
    assert!(history.snapshot().unwrap().coverage.is_empty());
    assert!(history.snapshot().unwrap().pages.is_empty());
}
#[test]
fn offline_partial_page_rejects_membership_from_later_snapshot() {
    use crate::public_history::*;
    let h = harness();
    h.source.receipt.lock().unwrap().block = block(4);
    let history = Arc::new(
        PublicHistory::new(
            Arc::new(
                PublicHistoryStore::new(
                    Arc::new(MemoryAtomicRecords::default()),
                    Retention::default(),
                )
                .unwrap(),
            ),
            PublicHistoryScope {
                chain_id: context().chain_id,
                protocol_address: sdk::word_address(context().protocol_address).unwrap(),
                runtime_code_hash: B256::with_last_byte(42),
                deployment_block: 0,
            },
            h.source.clone(),
        )
        .unwrap(),
    );
    history
        .sync(PublicSyncOptions::default(), &CancellationToken::default())
        .unwrap();
    let session = h.session.with_public_history(history).unwrap();
    let error = session
        .scan(
            &AppDecryptor::default(),
            ScanOptions {
                offline: true,
                to_block: Some(7),
                ..Default::default()
            },
        )
        .unwrap_err();
    assert!(error.contains("proof snapshot"));
    assert!(session.snapshot().unwrap().notes.is_empty());
    assert!(session.snapshot().unwrap().discovery_ranges.is_empty());
}
#[test]
fn acquired_page_generation_cannot_be_relabelled_after_rewind_during_handoff() {
    use crate::public_history::*;
    let h = harness();
    let history = Arc::new(
        PublicHistory::new(
            Arc::new(
                PublicHistoryStore::new(
                    Arc::new(MemoryAtomicRecords::default()),
                    Retention::default(),
                )
                .unwrap(),
            ),
            PublicHistoryScope {
                chain_id: context().chain_id,
                protocol_address: sdk::word_address(context().protocol_address).unwrap(),
                runtime_code_hash: B256::with_last_byte(42),
                deployment_block: 0,
            },
            h.source.clone(),
        )
        .unwrap(),
    );
    let session = h.session.with_public_history(history.clone()).unwrap();
    let (page, generation) = history
        .acquire(0, 10, &CancellationToken::default())
        .unwrap();
    history.store.rewind(&history.scope, None).unwrap();
    for offline in [false, true] {
        let mut pending = session
            .stage_refresh(
                session.snapshot().unwrap(),
                page.block.clone(),
                page.receipts.clone(),
                RefreshOptions::from_block(0),
                None,
            )
            .unwrap();
        pending.offline = offline;
        assert!(pending.bind_acquired_generation(generation).is_err());
        assert_eq!(pending.public_generation, Some(generation));
        assert!(pending.decrypt(&AppDecryptor::default()).is_err());
    }
    assert!(session.snapshot().unwrap().notes.is_empty());
}

#[test]
fn signed_direct_quote_rejects_manual_recursive_proving() {
    let h = synced();
    let mut preparation = transfer(&h);
    preparation.withdrawal.as_mut().unwrap().1 -= U256::from(10);
    preparation.automatic_change = true;
    let mut operation = h.session.prepare_transfer(preparation).unwrap();
    let relay = Arc::new(SessionCreditRelay {
        lookup_mode: std::sync::atomic::AtomicUsize::new(0),
        attempts: std::sync::atomic::AtomicUsize::new(0),
    });
    operation
        .with_broadcaster(
            relay,
            &sdk::BroadcasterOptions {
                max_fee_amount: Some(U256::from(100)),
                ..Default::default()
            },
        )
        .unwrap();
    let request = operation.export_wallet_request("quoted-direct").unwrap();
    let response: sdk::WalletResponse =
        serde_json::from_value(crate::wallet::execute(&key(1), &request.as_value()).unwrap())
            .unwrap();
    assert!(operation
        .with_wallet_response(&response)
        .unwrap()
        .prove(&Backend, true)
        .is_err());
}

struct SessionAggregateRelay {
    base: SessionCreditRelay,
    request: std::sync::Mutex<Option<serde_json::Value>>,
}
impl sdk::PreparedBroadcaster for SessionAggregateRelay {
    fn configuration(&self) -> crate::broadcaster::Configuration {
        self.base.configuration()
    }
    fn provenance_mode(&self) -> Option<()> {
        None
    }
    fn fee(&self, token: Address, data: Option<&[u8]>) -> Result<crate::broadcaster::Fee> {
        self.base.fee(token, data)
    }
    fn submission_requirements(&self, _: &crate::broadcaster::VerifiedQuote) -> Result<bool> {
        Ok(false)
    }
    fn quote(
        &self,
        data: &[u8],
        chain: u64,
        protocol: Address,
        now: u64,
        sidecars: &[crate::provenance::ProofSidecar],
    ) -> Result<crate::broadcaster::VerifiedQuote> {
        use crate::broadcaster::*;
        let base = self.base.quote(data, chain, protocol, now, sidecars)?;
        let mut signed = base.signed().clone();
        signed.quote.execution = Execution::Aggregate;
        let (signature, recovery) = k256::ecdsa::SigningKey::from_slice(&key(1))
            .unwrap()
            .sign_prehash_recoverable(
                quote_digest(&signed.quote, base.trust())
                    .unwrap()
                    .as_slice(),
            )
            .unwrap();
        let mut bytes = signature.to_bytes().to_vec();
        bytes.push(recovery.to_byte());
        signed.signature = format!("0x{}", hex::encode(bytes));
        VerifiedQuote::authenticate(signed, base.trust().clone(), data, now, None)
            .map_err(|e| e.to_string())
    }
    fn submit(
        &self,
        _: &[u8],
        _: &crate::broadcaster::VerifiedQuote,
        _: &[crate::provenance::ProofSidecar],
    ) -> Result<crate::broadcaster::Status> {
        panic!("recursive submission must carry memberProof")
    }
    fn submit_member(
        &self,
        data: &[u8],
        quote: &crate::broadcaster::VerifiedQuote,
        sidecars: &[crate::provenance::ProofSidecar],
        member: Option<&crate::broadcaster::MemberProof>,
    ) -> Result<crate::broadcaster::Status> {
        let member = member.ok_or("member required")?;
        crate::broadcaster::validate_member_proof(data, member).map_err(|e| e.to_string())?;
        let request = serde_json::json!({"data":hex::encode(data),"quote":quote.signed(),"proofSidecars":sidecars,"memberProof":member});
        let mut saved = self.request.lock().unwrap();
        if let Some(previous) = &*saved {
            assert_eq!(previous, &request);
        } else {
            *saved = Some(request);
        }
        let attempt = self
            .base
            .attempts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if attempt == 0 {
            return Err("response lost".into());
        }
        self.lookup_status("aggregate-owned")?
            .ok_or("status missing".into())
    }
    fn lookup_status(&self, id: &str) -> Result<Option<crate::broadcaster::Status>> {
        use crate::broadcaster::StatusState::*;
        let state = match self
            .base
            .lookup_mode
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            0 => Queued,
            1 => Proving,
            2 => Rejected,
            3 => Expired,
            _ => return Ok(None),
        };
        Ok(Some(crate::broadcaster::Status {
            confirmation: None,
            id: id.into(),
            state,
            transaction_hash: None,
        }))
    }
}

#[test]
fn signed_aggregate_defaults_recursive_and_restores_exact_request_without_reproving() {
    let h = synced();
    let mut preparation = transfer(&h);
    preparation.withdrawal.as_mut().unwrap().1 -= U256::from(10);
    preparation.automatic_change = true;
    let mut operation = h.session.prepare_transfer(preparation).unwrap();
    let relay = Arc::new(SessionAggregateRelay {
        base: SessionCreditRelay {
            lookup_mode: std::sync::atomic::AtomicUsize::new(0),
            attempts: std::sync::atomic::AtomicUsize::new(0),
        },
        request: std::sync::Mutex::new(None),
    });
    operation
        .with_broadcaster(
            relay.clone(),
            &sdk::BroadcasterOptions {
                max_fee_amount: Some(U256::from(100)),
                ..Default::default()
            },
        )
        .unwrap();
    let request = operation
        .export_wallet_request("aggregate-consent")
        .unwrap();
    let response: sdk::WalletResponse =
        serde_json::from_value(crate::wallet::execute(&key(1), &request.as_value()).unwrap())
            .unwrap();
    let mut operation = operation
        .with_wallet_response(&response)
        .unwrap()
        .prove(&Backend, None)
        .unwrap();
    assert!(operation.calldata(Address::ZERO).is_err());
    let id = operation.id().to_string();
    assert!(operation
        .submit_broadcaster(relay.as_ref())
        .unwrap_err()
        .contains("response lost"));
    let snapshot = h.session.snapshot().unwrap();
    let saved = serde_json::to_value(&snapshot.operations[&id].snapshot).unwrap();
    assert_eq!(
        saved["broadcaster"]["memberProof"]["target"],
        "noir-recursive"
    );
    let mut forged = saved.clone();
    forged["proof"]["publicInputs"][6] = serde_json::json!(format!("0x{}", "00".repeat(32)));
    forged["broadcaster"]["memberProof"]["publicInputs"][6] =
        forged["proof"]["publicInputs"][6].clone();
    let forged: sdk::journal::PreparedSnapshot = serde_json::from_value(forged).unwrap();
    assert!(forged.export_broadcaster_submission().is_err());
    drop(operation);
    h.chain
        .spent
        .lock()
        .unwrap()
        .insert(sdk::field_word(h.note.nullifier().unwrap()));
    h.chain
        .height
        .store(200, std::sync::atomic::Ordering::SeqCst);
    let mut operation = h.session.resume(&id, None).unwrap();
    assert_eq!(
        operation.submit_broadcaster(relay.as_ref()).unwrap().id,
        "aggregate-owned"
    );
    for mode in 0..4 {
        relay
            .base
            .lookup_mode
            .store(mode, std::sync::atomic::Ordering::SeqCst);
        operation.submit_broadcaster(relay.as_ref()).unwrap();
        let state = h.session.snapshot().unwrap();
        assert!(!state.operations[&id].status.terminal());
        assert!(state
            .notes
            .values()
            .any(|n| n.reserved_by.as_deref() == Some(&id)));
    }
    relay
        .base
        .lookup_mode
        .store(4, std::sync::atomic::Ordering::SeqCst);
    assert!(operation
        .submit_broadcaster(relay.as_ref())
        .unwrap_err()
        .contains("not found"));
    assert_eq!(
        relay
            .base
            .attempts
            .load(std::sync::atomic::Ordering::SeqCst),
        2
    );
    use alloy_sol_types::SolCall;
    let state = h.session.snapshot().unwrap();
    let call = state.operations[&id].call.as_ref().unwrap();
    let member = P::transact_0Call::abi_decode(&call.data, true).unwrap();
    let mut outer = P::transact_1Call {
        _0: vec![1; 32].into(),
        requests: vec![member.r.clone(), member.r.clone()],
    };
    let hash = B256::with_last_byte(8);
    operation.track_transaction(hash).unwrap();
    *h.source.transaction.lock().unwrap() = Some(CanonicalTransaction {
        hash,
        to: Some(call.to),
        input: outer.abi_encode(),
        value: U256::ZERO,
        chain_id: context().chain_id,
        block: Some(block(10)),
    });
    {
        let mut receipt = h.source.receipt.lock().unwrap();
        receipt.transaction_hash = hash;
        receipt.success = true;
        receipt.logs.clear();
    }
    assert!(h.session.reconcile(&id).is_err());
    assert!(h
        .session
        .snapshot()
        .unwrap()
        .notes
        .values()
        .any(|n| n.reserved_by.as_deref() == Some(&id)));
    outer.requests.pop();
    h.source.transaction.lock().unwrap().as_mut().unwrap().input = outer.abi_encode();
    let pending = match h.session.reconcile(&id).unwrap() {
        Reconciliation::Ready(v) => v,
        _ => panic!("canonical aggregate reconciliation expected"),
    };
    pending.decrypt(&AppDecryptor::default()).unwrap();
    let state = h.session.snapshot().unwrap();
    assert_eq!(state.operations[&id].status, OperationStatus::Confirmed);
    assert!(state
        .notes
        .values()
        .all(|n| n.reserved_by.as_deref() != Some(&id)));
}

#[test]
fn confirmation_observation_does_not_change_operation_or_reservations() {
    let h = synced();
    let operation = h.session.prepare_transfer(transfer(&h)).unwrap();
    let before = serde_json::to_value(h.session.snapshot().unwrap()).unwrap();
    let confirmation = operation.confirmation().unwrap();
    assert_eq!(confirmation.level, crate::rpc::ConfirmationLevel::Pending);
    assert_eq!(confirmation.status, crate::rpc::FinalityStatus::Available);
    let mut state = h.session.snapshot().unwrap();
    state
        .operations
        .get_mut(operation.id())
        .unwrap()
        .transaction_hash = Some(B256::repeat_byte(1));
    h.session.commit(state).unwrap();
    let submitted = serde_json::to_value(h.session.snapshot().unwrap()).unwrap();
    assert_eq!(
        operation.confirmation().unwrap().status,
        crate::rpc::FinalityStatus::Unsupported
    );
    assert_eq!(
        serde_json::to_value(h.session.snapshot().unwrap()).unwrap(),
        submitted
    );
    assert_ne!(before, submitted);
    h.chain.changed_context.store(true, Ordering::SeqCst);
    assert!(operation.confirmation().is_err());
    assert_eq!(
        serde_json::to_value(h.session.snapshot().unwrap()).unwrap(),
        submitted
    );
    h.chain.changed_context.store(false, Ordering::SeqCst);
    assert!(h.session.prepare_transfer(transfer(&h)).is_err());
}

#[test]
fn repeated_snapshot_validation_is_bound_to_the_entire_detached_state() {
    let h = synced();
    let mut first = h.session.snapshot().unwrap();
    let fingerprint = *h.session.validated_snapshot.lock().unwrap();
    assert!(fingerprint.is_some());
    first
        .notes
        .get_mut(&h.commitment)
        .unwrap()
        .input
        .note
        .amount = U256::ZERO;
    assert_eq!(
        h.session.snapshot().unwrap().notes[&h.commitment]
            .input
            .note
            .amount,
        h.note.amount
    );
    assert_eq!(*h.session.validated_snapshot.lock().unwrap(), fingerprint);
    let mut changed = h.session.snapshot().unwrap();
    changed
        .notes
        .get_mut(&h.commitment)
        .unwrap()
        .input
        .note
        .amount = U256::ZERO;
    let revision = changed.revision;
    h.store
        .compare_and_swap(&h.session.scope.key(), revision, changed)
        .unwrap();
    assert!(h.session.snapshot().is_err());
}
