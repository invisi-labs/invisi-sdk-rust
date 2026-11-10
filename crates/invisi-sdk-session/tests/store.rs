use invisi_sdk_session::session::{
    AtomicRecords, EncryptedWalletStore, MemoryAtomicRecords, WalletState, WalletStore,
};
use std::sync::Arc;
#[test]
fn encrypted_records_authenticate_scope_revision_and_key() {
    let records = Arc::new(MemoryAtomicRecords::default());
    let store = EncryptedWalletStore::new(records.clone(), [1; 32]).unwrap();
    store
        .compare_and_swap("alice", 0, WalletState::default())
        .unwrap();
    let record = records.read("alice").unwrap().unwrap();
    assert!(!record
        .data
        .windows(b"formatVersion".len())
        .any(|w| w == b"formatVersion"));
    assert_eq!(store.snapshot("alice").unwrap().revision, 1);
    assert!(records.compare_and_swap("bob", 0, &record).unwrap());
    assert!(store.snapshot("bob").is_err());
    assert!(EncryptedWalletStore::new(records.clone(), [2; 32])
        .unwrap()
        .snapshot("alice")
        .is_err());
    let mut stale = record.clone();
    stale.revision = 2;
    assert!(records.compare_and_swap("alice", 1, &stale).unwrap());
    assert!(store.snapshot("alice").is_err());
    assert!(store
        .compare_and_swap("bob", 0, WalletState::default())
        .is_err());
}
