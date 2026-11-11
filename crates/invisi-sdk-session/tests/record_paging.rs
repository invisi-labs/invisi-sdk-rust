use invisi_sdk_session::session::{AtomicRecords, EncryptedRecord, MemoryAtomicRecords};
#[test]
fn guarded_batch_is_atomic_and_physically_deletes_rows() {
    let records = MemoryAtomicRecords::default();
    let root = EncryptedRecord {
        revision: 1,
        data: vec![1],
    };
    let row = EncryptedRecord {
        revision: 1,
        data: vec![2],
    };
    assert!(records.supports_batches());
    assert!(records
        .compare_and_swap_batch(
            "wallet",
            0,
            &root,
            &[
                ("wallet/row/a".into(), Some(row.clone())),
                ("wallet/row/b".into(), Some(row))
            ]
        )
        .unwrap());
    assert_eq!(records.list("wallet/row/", None, 1).unwrap().len(), 1);
    assert_eq!(
        records
            .list("wallet/row/", Some("wallet/row/a"), 1)
            .unwrap()[0]
            .0,
        "wallet/row/b"
    );
    let next = EncryptedRecord {
        revision: 2,
        data: vec![3],
    };
    assert!(!records
        .compare_and_swap_batch("wallet", 0, &root, &[("wallet/row/a".into(), None)])
        .unwrap());
    assert!(records.read("wallet/row/a").unwrap().is_some());
    assert!(records
        .compare_and_swap_batch("wallet", 1, &next, &[("wallet/row/a".into(), None)])
        .unwrap());
    assert_eq!(records.list("wallet/row/", None, 10).unwrap().len(), 1);
    assert!(records.list("wallet/row/", None, 0).is_err());
}
use alloy_primitives::{B256, U256};
use invisi_sdk_session::session::{
    EncryptedWalletStore, RecordWalletStore, StoredNote, WalletState, WalletStore,
};
use invisi_sdk_session::{
    note::{Note, ProtocolContext},
    rpc::CanonicalBlock,
    sdk::NoteInput,
};
use std::sync::Arc;
fn stored(n: u64) -> StoredNote {
    let context = ProtocolContext {
        chain_id: 97,
        protocol_address: U256::from(1),
    };
    StoredNote {
        input: NoteInput {
            note: Note {
                context,
                owner_address: U256::from(2),
                token_address: U256::from(3),
                amount: U256::from(1),
                nonce: U256::from(n),
                payload: vec![],
            },
            tree_id: 1,
            leaf_index: 0,
            path: [U256::ZERO; 16],
            root: U256::ZERO,
        },
        commitment: B256::from(U256::from(n).to_be_bytes()),
        nullifier: B256::ZERO,
        block: CanonicalBlock {
            number: n,
            hash: B256::with_last_byte(1),
            parent_hash: B256::ZERO,
            timestamp: 0,
        },
        transaction_hash: B256::ZERO,
        spent: true,
        reserved_by: None,
    }
}
#[test]
fn encrypted_records_bound_active_history_and_reopen_archives() {
    let records = Arc::new(MemoryAtomicRecords::default());
    let store = RecordWalletStore::with_recent_records(records.clone(), [7; 32], 2).unwrap();
    let mut state = WalletState::default();
    for n in 1..=300 {
        let note = stored(n);
        state.notes.insert(note.commitment, note);
    }
    store.compare_and_swap("alice", 0, state).unwrap();
    let active = store.snapshot("alice").unwrap();
    assert_eq!(active.notes.len(), 2);
    assert_eq!(active.revision, 1);
    assert!(active.notes.contains_key(&stored(300).commitment));
    assert!(store.read_summary("alice").unwrap().notes.is_empty());
    let first = store.history_page("alice", None, 7).unwrap();
    assert_eq!(first.entries.len(), 7);
    let second = store
        .history_page("alice", first.next_cursor.as_deref(), 7)
        .unwrap();
    assert_ne!(first.entries[0].cursor, second.entries[0].cursor);
    let reopened = RecordWalletStore::new(records.clone(), [7; 32]).unwrap();
    assert_eq!(reopened.full_snapshot("alice").unwrap().notes.len(), 300);
    assert!(RecordWalletStore::new(records.clone(), [8; 32])
        .unwrap()
        .snapshot("alice")
        .is_err());
    let mut next = active;
    next.recovery_boundary = Some(200);
    next.credit_replay_from = Some(50);
    store.compare_and_swap("alice", 1, next).unwrap();
    assert_eq!(
        store.snapshot("alice").unwrap().recovery_boundary,
        Some(200)
    );
    assert_eq!(store.full_snapshot("alice").unwrap().notes.len(), 300);
}
#[test]
fn legacy_blob_migrates_atomically_to_records() {
    let records = Arc::new(MemoryAtomicRecords::default());
    let legacy = EncryptedWalletStore::new(records.clone(), [7; 32]).unwrap();
    let mut s = WalletState::default();
    let n = stored(1);
    s.notes.insert(n.commitment, n);
    legacy.compare_and_swap("alice", 0, s).unwrap();
    let records_store = RecordWalletStore::with_recent_records(records, [7; 32], 0).unwrap();
    let s = records_store.snapshot("alice").unwrap();
    assert_eq!(s.notes.len(), 1);
    records_store.compare_and_swap("alice", 1, s).unwrap();
    assert_eq!(records_store.snapshot("alice").unwrap().notes.len(), 0);
    assert_eq!(records_store.full_snapshot("alice").unwrap().notes.len(), 1);
}
#[cfg(feature = "sqlite")]
#[test]
fn sqlite_batch_rolls_back_invalid_write_and_separates_public_table() {
    use invisi_sdk_session::session::sqlite::SQLiteRecords;
    let path = std::env::temp_dir().join(format!("invisi-record-page-{}.db", uuid::Uuid::new_v4()));
    let store = SQLiteRecords::open(&path).unwrap();
    let public = SQLiteRecords::open_public(&path).unwrap();
    let root = EncryptedRecord {
        revision: 1,
        data: vec![1],
    };
    assert!(store
        .compare_and_swap_batch(
            "scope",
            0,
            &root,
            &[("scope/row/1".into(), Some(root.clone()))]
        )
        .unwrap());
    assert!(public.read("scope").unwrap().is_none());
    let bad = EncryptedRecord {
        revision: u64::MAX,
        data: vec![2],
    };
    assert!(store
        .compare_and_swap_batch(
            "scope",
            1,
            &EncryptedRecord {
                revision: 2,
                data: vec![2]
            },
            &[
                ("scope/row/1".into(), None),
                ("scope/row/2".into(), Some(bad))
            ]
        )
        .is_err());
    assert!(store.read("scope/row/1").unwrap().is_some());
    assert_eq!(store.read("scope").unwrap().unwrap().revision, 1);
    drop(store);
    let reopened = SQLiteRecords::open(&path).unwrap();
    assert_eq!(reopened.list("scope/row/", None, 10).unwrap().len(), 1);
    drop(reopened);
    drop(public);
    let _ = std::fs::remove_file(path);
}
#[test]
fn reorg_prunes_orphan_archives_but_preserves_older_history() {
    let records = Arc::new(MemoryAtomicRecords::default());
    let store = RecordWalletStore::with_recent_records(records, [7; 32], 0).unwrap();
    let mut s = WalletState::default();
    for n in 1..=10 {
        let note = stored(n);
        s.notes.insert(note.commitment, note);
    }
    store.compare_and_swap("alice", 0, s).unwrap();
    store.recover_reorg("alice", 8).unwrap();
    let full = store.full_snapshot("alice").unwrap();
    assert_eq!(full.notes.len(), 7);
    assert!(!full.notes.contains_key(&stored(8).commitment));
}
#[test]
fn missing_active_and_archive_rows_never_silently_hide_assets() {
    for recent in [0, 1] {
        let records = Arc::new(MemoryAtomicRecords::default());
        let store =
            RecordWalletStore::with_recent_records(records.clone(), [7; 32], recent).unwrap();
        let mut s = WalletState::default();
        let n = stored(1);
        s.notes.insert(n.commitment, n);
        store.compare_and_swap("alice", 0, s).unwrap();
        let rows = records.list("wallet-records/", None, 100).unwrap();
        let victim = rows
            .iter()
            .find(|(k, _)| {
                if recent == 0 {
                    k.contains("/archive/")
                } else {
                    k.contains("/row/")
                }
            })
            .unwrap()
            .0
            .clone();
        assert!(records
            .compare_and_swap_batch(
                "corruption",
                0,
                &EncryptedRecord {
                    revision: 1,
                    data: vec![1]
                },
                &[(victim, None)]
            )
            .unwrap());
        if recent == 0 {
            assert!(store.history_page("alice", None, 10).is_err())
        } else {
            assert!(store.snapshot("alice").is_err())
        }
    }
}
#[test]
fn missing_manifest_with_remaining_rows_is_not_an_empty_wallet() {
    let records = Arc::new(MemoryAtomicRecords::default());
    let store = RecordWalletStore::with_recent_records(records.clone(), [7; 32], 0).unwrap();
    let mut s = WalletState::default();
    let n = stored(1);
    s.notes.insert(n.commitment, n);
    store.compare_and_swap("alice", 0, s).unwrap();
    records
        .compare_and_swap_batch(
            "corruption",
            0,
            &EncryptedRecord {
                revision: 1,
                data: vec![1],
            },
            &[("alice".into(), None)],
        )
        .unwrap();
    assert!(store.snapshot("alice").is_err());
    assert!(store.history_page("alice", None, 10).is_err());
}
#[test]
fn unresolved_payloads_are_independent_rows_with_small_summary() {
    use invisi_sdk_session::session::UnresolvedDelivery;
    let records = Arc::new(MemoryAtomicRecords::default());
    let store = RecordWalletStore::new(records.clone(), [7; 32]).unwrap();
    let mut s = WalletState::default();
    let receipt = invisi_sdk_session::rpc::CanonicalReceipt {
        transaction_hash: B256::with_last_byte(1),
        block: stored(1).block,
        success: true,
        logs: vec![],
    };
    for i in 0..200 {
        s.unresolved_deliveries.insert(
            i.to_string(),
            UnresolvedDelivery {
                receipt: receipt.clone(),
                key: i.to_string(),
            },
        );
    }
    store.compare_and_swap("alice", 0, s).unwrap();
    let summary = store.read_summary("alice").unwrap();
    assert!(summary.unresolved_deliveries.is_empty());
    assert_eq!(summary.unresolved_delivery_count, Some(200));
    let mut full = store.snapshot("alice").unwrap();
    assert_eq!(full.unresolved_deliveries.len(), 200);
    full.unresolved_deliveries.clear();
    store.compare_and_swap("alice", 1, full).unwrap();
    assert_eq!(
        store
            .read_summary("alice")
            .unwrap()
            .unresolved_delivery_count,
        Some(0)
    );
}
#[test]
fn reorg_removes_unresolved_candidates_from_orphan_blocks() {
    use invisi_sdk_session::session::UnresolvedDelivery;
    let records = Arc::new(MemoryAtomicRecords::default());
    let store = RecordWalletStore::new(records, [7; 32]).unwrap();
    let mut s = WalletState::default();
    for n in [1, 9] {
        let receipt = invisi_sdk_session::rpc::CanonicalReceipt {
            transaction_hash: B256::with_last_byte(n),
            block: stored(n as u64).block,
            success: true,
            logs: vec![],
        };
        s.unresolved_deliveries.insert(
            n.to_string(),
            UnresolvedDelivery {
                receipt,
                key: n.to_string(),
            },
        );
    }
    store.compare_and_swap("alice", 0, s).unwrap();
    store.recover_reorg("alice", 8).unwrap();
    let s = store.snapshot("alice").unwrap();
    assert_eq!(s.unresolved_deliveries.len(), 1);
    assert!(s.unresolved_deliveries.contains_key("1"));
    assert_eq!(s.unresolved_delivery_count, Some(1));
}
