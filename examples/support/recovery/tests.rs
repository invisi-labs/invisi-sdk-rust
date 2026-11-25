use super::*;
use alloy_primitives::{Address, B256, U256};
use invisi_sdk::{
    note::ProtocolContext,
    rpc::{CanonicalReceipt, CanonicalTransaction, Membership, MembershipInput},
    sdk::{Fee, Invisi, Wallet},
};
use invisi_sdk_session::session::{MemoryWalletStore, OperationStatus};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

fn block() -> CanonicalBlock {
    CanonicalBlock {
        number: 10,
        hash: B256::with_last_byte(10),
        parent_hash: B256::with_last_byte(9),
        timestamp: 2_000_000_000,
    }
}
fn context() -> ProtocolContext {
    ProtocolContext {
        chain_id: 31337,
        protocol_address: U256::from(4660),
    }
}
#[derive(Default)]
struct Evidence {
    reorg: AtomicBool,
    receipt: Mutex<Option<CanonicalReceipt>>,
    transaction: Mutex<Option<CanonicalTransaction>>,
}
impl ChainState for Evidence {
    fn context(&self) -> ProtocolContext {
        context()
    }
    fn snapshot(&self) -> Result<CanonicalBlock, String> {
        Ok(block())
    }
    fn canonical(&self, b: &CanonicalBlock) -> Result<(), String> {
        if self.reorg.load(Ordering::SeqCst) || *b != block() {
            Err("canonical block changed".into())
        } else {
            Ok(())
        }
    }
    fn known_root(&self, _: u64, _: B256, _: &CanonicalBlock) -> Result<bool, String> {
        Ok(true)
    }
    fn nullifier_spent(&self, _: B256, _: &CanonicalBlock) -> Result<bool, String> {
        Ok(false)
    }
    fn credit_status(
        &self,
        _: Address,
        _: Address,
        _: u128,
        _: &CanonicalBlock,
    ) -> Result<u8, String> {
        Ok(1)
    }
    fn token_balance_allowance(
        &self,
        _: Address,
        _: Address,
        _: &CanonicalBlock,
    ) -> Result<(U256, U256), String> {
        Ok((U256::MAX, U256::MAX))
    }
}
impl SessionSource for Evidence {
    fn context(&self) -> ProtocolContext {
        context()
    }
    fn deployment_start(&self) -> u64 {
        10
    }
    fn indexed_head(&self) -> Result<CanonicalBlock, String> {
        Ok(block())
    }
    fn block(&self, _: u64) -> Result<CanonicalBlock, String> {
        Ok(block())
    }
    fn discover(&self, _: u64, _: u64) -> Result<Vec<B256>, String> {
        Ok(vec![])
    }
    fn receipt(&self, _: B256) -> Result<Option<CanonicalReceipt>, String> {
        Ok(self.receipt.lock().unwrap().clone())
    }
    fn transaction(&self, _: B256) -> Result<Option<CanonicalTransaction>, String> {
        Ok(self.transaction.lock().unwrap().clone())
    }
    fn membership(&self, _: &MembershipInput, _: &CanonicalBlock) -> Result<Membership, String> {
        Err("no inputs expected".into())
    }
}
fn submitted() -> (WalletSession, Arc<Evidence>, String, B256) {
    let evidence = Arc::new(Evidence::default());
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/wallet-wire-vectors.json"
    ))
    .unwrap();
    let wallet = Wallet::from_response(
        &serde_json::from_value(fixture["cases"][0]["request"].clone()).unwrap(),
        &serde_json::from_value(fixture["cases"][0]["response"].clone()).unwrap(),
    )
    .unwrap();
    let session = WalletSession::connect(
        Invisi::new(evidence.clone()),
        wallet,
        Arc::new(MemoryWalletStore::default()),
        evidence.clone(),
        "recovery-test",
    )
    .unwrap();
    let mut operation = session
        .prepare_revoke_credit_explicit(
            Address::with_last_byte(2),
            1,
            block().timestamp + 1000,
            Fee::default(),
        )
        .unwrap();
    let id = operation.id().to_owned();
    let call = operation
        .calldata(session.wallet().owner_address())
        .unwrap();
    let hash = B256::with_last_byte(20);
    operation.track_transaction(hash).unwrap();
    *evidence.transaction.lock().unwrap() = Some(CanonicalTransaction {
        hash,
        to: Some(call.to),
        input: call.data,
        value: call.value,
        chain_id: context().chain_id,
        block: Some(block()),
    });
    (session, evidence, id, hash)
}
fn confirm(session: &WalletSession, evidence: &Evidence, id: &str, hash: B256) {
    *evidence.receipt.lock().unwrap() = Some(CanonicalReceipt {
        transaction_hash: hash,
        block: block(),
        success: true,
        logs: vec![],
    });
    match session.reconcile(id).unwrap() {
        Reconciliation::Ready(pending) => {
            pending.decrypt(&crate::AppDecryptor).unwrap();
        }
        _ => panic!("receipt must reconcile"),
    }
    assert_eq!(
        session.snapshot().unwrap().operations[id].status,
        OperationStatus::Confirmed
    );
}
#[test]
fn submitted_hash_without_host_override_reconciles_instead_of_exporting() {
    let (session, evidence, id, hash) = submitted();
    *evidence.receipt.lock().unwrap() = Some(CanonicalReceipt {
        transaction_hash: hash,
        block: block(),
        success: true,
        logs: vec![],
    });
    assert_eq!(
        recover_sent_operation(
            &session,
            evidence.as_ref(),
            evidence.as_ref(),
            &id,
            Some("revoke-credit"),
            None
        )
        .unwrap(),
        Some(Recovery::Confirmed(block()))
    );
}
#[test]
fn repeated_confirmed_recovery_is_read_only_and_checks_the_frozen_transaction() {
    let (session, evidence, id, hash) = submitted();
    confirm(&session, &evidence, &id, hash);
    let before = serde_json::to_value(session.snapshot().unwrap()).unwrap();
    assert_eq!(
        recover_sent_operation(
            &session,
            evidence.as_ref(),
            evidence.as_ref(),
            &id,
            Some("revoke-credit"),
            Some(&hash.to_string())
        )
        .unwrap(),
        Some(Recovery::Confirmed(block()))
    );
    assert_eq!(
        serde_json::to_value(session.snapshot().unwrap()).unwrap(),
        before
    );
    evidence
        .transaction
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .input
        .push(0);
    assert!(recover_sent_operation(
        &session,
        evidence.as_ref(),
        evidence.as_ref(),
        &id,
        None,
        None
    )
    .is_err());
}
#[test]
fn pending_recovery_retains_the_original_record_and_rejects_hash_or_kind_changes() {
    let (session, evidence, id, hash) = submitted();
    let before = serde_json::to_value(session.snapshot().unwrap()).unwrap();
    assert_eq!(
        recover_sent_operation(
            &session,
            evidence.as_ref(),
            evidence.as_ref(),
            &id,
            None,
            None
        )
        .unwrap(),
        Some(Recovery::Pending)
    );
    for supplied in [
        "garbage".to_owned(),
        B256::ZERO.to_string(),
        B256::with_last_byte(21).to_string(),
        hex::encode(hash),
    ] {
        assert!(recover_sent_operation(
            &session,
            evidence.as_ref(),
            evidence.as_ref(),
            &id,
            None,
            Some(&supplied)
        )
        .is_err());
    }
    assert!(recover_sent_operation(
        &session,
        evidence.as_ref(),
        evidence.as_ref(),
        &id,
        Some("transfer"),
        None
    )
    .is_err());
    assert_eq!(
        serde_json::to_value(session.snapshot().unwrap()).unwrap(),
        before
    );
}
#[test]
fn confirmed_recovery_rejects_changed_receipt_missing_receipt_reorg_and_host_hash() {
    let (session, evidence, id, hash) = submitted();
    confirm(&session, &evidence, &id, hash);
    assert!(recover_sent_operation(
        &session,
        evidence.as_ref(),
        evidence.as_ref(),
        &id,
        None,
        Some(&B256::with_last_byte(21).to_string())
    )
    .is_err());
    evidence.reorg.store(true, Ordering::SeqCst);
    assert!(recover_sent_operation(
        &session,
        evidence.as_ref(),
        evidence.as_ref(),
        &id,
        None,
        None
    )
    .is_err());
    evidence.reorg.store(false, Ordering::SeqCst);
    evidence.receipt.lock().unwrap().as_mut().unwrap().success = false;
    assert!(recover_sent_operation(
        &session,
        evidence.as_ref(),
        evidence.as_ref(),
        &id,
        None,
        None
    )
    .is_err());
    *evidence.receipt.lock().unwrap() = None;
    assert!(recover_sent_operation(
        &session,
        evidence.as_ref(),
        evidence.as_ref(),
        &id,
        None,
        None
    )
    .is_err());
}

struct OfflineRelay;
impl invisi_sdk::rpc::RpcTransport for OfflineRelay {
    fn send(&self, _: &serde_json::Value) -> invisi_sdk::rpc::Result<serde_json::Value> {
        Err(invisi_sdk::rpc::Error::Transport(
            "relay unavailable; no status preflight permitted".into(),
        ))
    }
}
fn saved_cancellation(
    known_id: bool,
    acknowledged: bool,
    attempted: bool,
) -> (
    WalletSession,
    Arc<Evidence>,
    String,
    invisi_sdk::broadcaster::BroadcasterClient<OfflineRelay>,
) {
    use invisi_sdk::broadcaster::*;
    use invisi_sdk_session::session::WalletStore;
    let (original, evidence, id, _) = submitted();
    let config = Configuration {
        endpoint: "https://relay.example".into(),
        quote_signer: Address::repeat_byte(8),
        fee_recipient: Address::repeat_byte(9),
    };
    let token = invisi_sdk::sdk::CancellationToken::generate();
    let saved = invisi_sdk::sdk::PreparedBroadcasterState {
        cancellation_token: Some(token.clone()),
        endpoint: config.endpoint.clone(),
        signer: config.quote_signer,
        fee_recipient: config.fee_recipient,
        quote: SignedQuote {
            quote: Quote {
                schedule: Some(Schedule {
                    publish_after: "1".into(),
                    execute_before: "2".into(),
                    cancel_token_hash: token.commitment(),
                }),
                execution: Execution::Direct,
                token: Address::repeat_byte(1),
                fee_recipient: config.fee_recipient,
                fee_amount: "1".into(),
                deadline: "3".into(),
                max_gas: "100000".into(),
                request_hash: B256::repeat_byte(3),
            },
            signature: "unused cancellation signature".into(),
            request_hash_format: None,
            provenance_required: None,
        },
        intent_hash: B256::repeat_byte(3),
        sidecars: vec![],
        pre_send_refusal: None,
        attempted,
        submission_id: known_id.then(|| "server-id".into()),
        submitted_data: vec![],
        member_proof: None,
    };
    let mut state = original.snapshot().unwrap();
    state.revision = 0;
    let record = state.operations.get_mut(&id).unwrap();
    record.transaction_hash = None;
    record.broadcaster_id = attempted.then(|| id.clone());
    if !attempted {
        record.externalized = false;
        record.call = None;
        record.status = OperationStatus::Prepared;
    }
    record.broadcaster_submission_id = known_id.then(|| "server-id".into());
    record.broadcaster_cancelled = acknowledged;
    let mut snapshot = serde_json::to_value(&record.snapshot).unwrap();
    snapshot["broadcaster"] = serde_json::to_value(saved).unwrap();
    record.snapshot = serde_json::from_value(snapshot).unwrap();
    let store = Arc::new(MemoryWalletStore::default());
    store
        .compare_and_swap(&original.scope().key(), 0, state)
        .unwrap();
    let session = WalletSession::connect(
        Invisi::new(evidence.clone()),
        original.wallet().clone(),
        store,
        evidence.clone(),
        "recovery-test",
    )
    .unwrap();
    let relay = BroadcasterClient::new(config, OfflineRelay).unwrap();
    (session, evidence, id, relay)
}
#[test]
fn saved_cancellation_ack_restarts_keylessly_while_relay_is_offline() {
    let (session, evidence, id, relay) = saved_cancellation(true, true, true);
    evidence.reorg.store(true, Ordering::SeqCst);
    let error =
        cancel_saved_operation(&session, evidence.as_ref(), &relay, &id, false).unwrap_err();
    assert!(error.contains("canonical block changed"), "{error}");
    assert!(session.snapshot().unwrap().operations[&id].broadcaster_cancelled);
    assert!(!session.snapshot().unwrap().operations[&id]
        .status
        .terminal());
    evidence.reorg.store(false, Ordering::SeqCst);
    cancel_saved_operation(&session, evidence.as_ref(), &relay, &id, false).unwrap();
    assert_eq!(
        session.snapshot().unwrap().operations[&id].status,
        OperationStatus::Failed
    );
    cancel_saved_operation(&session, evidence.as_ref(), &relay, &id, false).unwrap();
    evidence.reorg.store(true, Ordering::SeqCst);
    assert!(cancel_saved_operation(&session, evidence.as_ref(), &relay, &id, false).is_err());
}

#[test]
fn exported_intent_requires_the_original_host_hash_and_attaches_it_without_signing() {
    use invisi_sdk_session::session::WalletStore;
    let (original, evidence, id, hash) = submitted();
    let mut state = original.snapshot().unwrap();
    state.revision = 0;
    let record = state.operations.get_mut(&id).unwrap();
    record.transaction_hash = None;
    record.status = OperationStatus::Exported;
    let store = Arc::new(MemoryWalletStore::default());
    store
        .compare_and_swap(&original.scope().key(), 0, state)
        .unwrap();
    let session = WalletSession::connect(
        Invisi::new(evidence.clone()),
        original.wallet().clone(),
        store,
        evidence.clone(),
        "recovery-test",
    )
    .unwrap();
    let before = serde_json::to_value(session.snapshot().unwrap()).unwrap();
    assert!(recover_sent_operation(
        &session,
        evidence.as_ref(),
        evidence.as_ref(),
        &id,
        None,
        None
    )
    .unwrap_err()
    .contains("do not export or resend"));
    assert_eq!(
        serde_json::to_value(session.snapshot().unwrap()).unwrap(),
        before
    );
    *evidence.receipt.lock().unwrap() = Some(CanonicalReceipt {
        transaction_hash: hash,
        block: block(),
        success: true,
        logs: vec![],
    });
    assert_eq!(
        recover_sent_operation(
            &session,
            evidence.as_ref(),
            evidence.as_ref(),
            &id,
            None,
            Some(&hash.to_string())
        )
        .unwrap(),
        Some(Recovery::Confirmed(block()))
    );
}

#[test]
fn cancellation_without_remote_id_stops_without_replaying_or_changing_the_journal() {
    let (session, evidence, id, relay) = saved_cancellation(false, false, true);
    let before = serde_json::to_value(session.snapshot().unwrap()).unwrap();
    let error =
        cancel_saved_operation(&session, evidence.as_ref(), &relay, &id, false).unwrap_err();
    assert!(error.contains("--recover-submit-id"), "{error}");
    assert_eq!(
        serde_json::to_value(session.snapshot().unwrap()).unwrap(),
        before
    );
}

#[test]
fn invalidated_wallet_cannot_report_repeated_confirmed_recovery() {
    use invisi_sdk_session::session::WalletStore;
    let (original, evidence, id, hash) = submitted();
    confirm(&original, &evidence, &id, hash);
    let mut state = original.snapshot().unwrap();
    state.revision = 0;
    state.invalidated = true;
    let store = Arc::new(MemoryWalletStore::default());
    store
        .compare_and_swap(&original.scope().key(), 0, state)
        .unwrap();
    let session = WalletSession::connect(
        Invisi::new(evidence.clone()),
        original.wallet().clone(),
        store,
        evidence.clone(),
        "recovery-test",
    )
    .unwrap();
    assert!(recover_sent_operation(
        &session,
        evidence.as_ref(),
        evidence.as_ref(),
        &id,
        None,
        None
    )
    .unwrap_err()
    .contains("canonical resync"));
}

#[test]
fn quote_only_journal_cannot_be_submitted_by_cancellation_recovery() {
    let (session, evidence, id, relay) = saved_cancellation(false, false, false);
    let before = serde_json::to_value(session.snapshot().unwrap()).unwrap();
    let error = cancel_saved_operation(&session, evidence.as_ref(), &relay, &id, true).unwrap_err();
    assert!(
        error.contains("saved Broadcaster attempt required"),
        "{error}"
    );
    assert_eq!(
        serde_json::to_value(session.snapshot().unwrap()).unwrap(),
        before
    );
}

#[test]
fn invalidated_wallet_cannot_report_completed_cancellation() {
    use invisi_sdk_session::session::WalletStore;
    let (original, evidence, id, relay) = saved_cancellation(true, true, true);
    cancel_saved_operation(&original, evidence.as_ref(), &relay, &id, false).unwrap();
    let mut state = original.snapshot().unwrap();
    state.revision = 0;
    state.invalidated = true;
    let store = Arc::new(MemoryWalletStore::default());
    store
        .compare_and_swap(&original.scope().key(), 0, state)
        .unwrap();
    let session = WalletSession::connect(
        Invisi::new(evidence.clone()),
        original.wallet().clone(),
        store,
        evidence.clone(),
        "recovery-test",
    )
    .unwrap();
    assert!(
        cancel_saved_operation(&session, evidence.as_ref(), &relay, &id, false)
            .unwrap_err()
            .contains("canonical resync")
    );
}

#[test]
fn scheduled_restart_reads_the_original_relay_configuration_without_changing_the_journal() {
    let (session, _, id, _) = saved_cancellation(true, true, true);
    let before = serde_json::to_value(session.snapshot().unwrap()).unwrap();
    let config = saved_broadcaster_configuration(&session, &id).unwrap();
    assert_eq!(config.endpoint, "https://relay.example");
    assert_eq!(config.quote_signer, Address::repeat_byte(8));
    assert_eq!(config.fee_recipient, Address::repeat_byte(9));
    assert_eq!(
        serde_json::to_value(session.snapshot().unwrap()).unwrap(),
        before
    );
}
