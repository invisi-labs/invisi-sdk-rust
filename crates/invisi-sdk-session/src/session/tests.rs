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
    let base = Wallet::from_owner(owner.parse().unwrap()).unwrap();
    let q = base
        .prepare_request("public", "wallet.public", serde_json::json!({}))
        .unwrap();
    let r: WalletResponse =
        serde_json::from_value(crate::wallet::execute(&key(n), &q.as_value()).unwrap()).unwrap();
    Wallet::from_response(&q, &r).unwrap()
}
#[derive(Default)]
struct Chain {
    height: std::sync::atomic::AtomicU64,
    reorg: AtomicBool,
    spent: Mutex<BTreeSet<B256>>,
    roots: Mutex<BTreeSet<B256>>,
}
impl ChainState for Chain {
    fn context(&self) -> ProtocolContext {
        context()
    }
    fn snapshot(&self) -> Result<CanonicalBlock> {
        Ok(block(self.height.load(Ordering::SeqCst).max(10)))
    }
    fn canonical(&self, b: &CanonicalBlock) -> Result<()> {
        if self.reorg.load(Ordering::SeqCst) || *b != block(b.number) {
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
    fn indexed_head(&self) -> Result<CanonicalBlock> {
        Ok(block(10))
    }
    fn block(&self, n: u64) -> Result<CanonicalBlock> {
        let b = block(n);
        self.chain.canonical(&b)?;
        Ok(b)
    }
    fn discover(&self, from: u64, to: u64) -> Result<Vec<B256>> {
        let r = self.receipt.lock().unwrap();
        Ok(if (from..=to).contains(&r.block.number) {
            vec![r.transaction_hash]
        } else {
            vec![]
        })
    }
    fn receipt(&self, hash: B256) -> Result<Option<CanonicalReceipt>> {
        let r = self.receipt.lock().unwrap();
        Ok(if r.transaction_hash == hash {
            Some(r.clone())
        } else {
            None
        })
    }
    fn transaction(&self, _: B256) -> Result<Option<CanonicalTransaction>> {
        Ok(self.transaction.lock().unwrap().clone())
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
struct Harness {
    session: WalletSession,
    store: Arc<MemoryWalletStore>,
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
    let keys = wallet.receiving_keys().unwrap();
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
        chain: chain.clone(),
        receipt: Mutex::new(receipt),
        transaction: Mutex::new(None),
        proofs: Mutex::new(proofs),
    });
    let store = Arc::new(MemoryWalletStore::default());
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
        sdk::NoteOutput::from_note(h.note.clone(), h.session.wallet.receiving_keys()).unwrap();
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
        owner_receiving_keys: alice.receiving_keys().unwrap().clone(),
        spender_receiving_keys: bob.receiving_keys().unwrap().clone(),
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
        owner_receiving_keys: alice.receiving_keys().unwrap().clone(),
        spender_receiving_keys: bob.receiving_keys().unwrap().clone(),
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
    assert_eq!(
        operation.submit_broadcaster(relay.as_ref()).unwrap().id,
        "server-owned"
    );
    assert_eq!(relay.attempts.load(std::sync::atomic::Ordering::SeqCst), 3);
}
struct SessionCreditRelay {
    lookup_mode: std::sync::atomic::AtomicUsize,
    attempts: std::sync::atomic::AtomicUsize,
}
impl sdk::PreparedBroadcaster for SessionCreditRelay {
    fn lookup_status(&self, id: &str) -> Result<Option<crate::broadcaster::Status>> {
        match self.lookup_mode.load(std::sync::atomic::Ordering::SeqCst) {
            0 => Ok(Some(crate::broadcaster::Status {
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
    assert_eq!(
        op.submit_broadcaster(relay.as_ref()).unwrap().id,
        "server-owned"
    );
    assert_eq!(relay.attempts.load(std::sync::atomic::Ordering::SeqCst), 3);
}
