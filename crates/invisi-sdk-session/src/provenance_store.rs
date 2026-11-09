//! Explicit ciphertext adapter for independently scoped provenance recovery records.
use crate::session::{AtomicRecords, EncryptedRecord};
use invisi_sdk_rpc::provenance_recovery::{AtomicRecoveryRecords, RecoveryCiphertext};
use std::sync::Arc;
pub struct SessionRecoveryRecords {
    records: Arc<dyn AtomicRecords>,
}
impl SessionRecoveryRecords {
    pub fn new(records: Arc<dyn AtomicRecords>) -> Self {
        Self { records }
    }
}
impl AtomicRecoveryRecords for SessionRecoveryRecords {
    fn read(&self, key: &str) -> Result<Option<RecoveryCiphertext>, String> {
        Ok(self.records.read(key)?.map(|r| RecoveryCiphertext {
            revision: r.revision,
            data: r.data,
        }))
    }
    fn compare_and_swap(
        &self,
        key: &str,
        old: u64,
        next: &RecoveryCiphertext,
    ) -> Result<bool, String> {
        self.records.compare_and_swap(
            key,
            old,
            &EncryptedRecord {
                revision: next.revision,
                data: next.data.clone(),
            },
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::MemoryAtomicRecords;
    #[test]
    fn existing_ciphertext_store_is_reused_without_wallet_snapshot_changes() {
        let records = Arc::new(MemoryAtomicRecords::default());
        let adapter = SessionRecoveryRecords::new(records.clone());
        let key = "Invisi.Provenance.Recovery.v1:one";
        let cipher = RecoveryCiphertext {
            revision: 1,
            data: vec![1, 2, 3],
        };
        assert!(adapter.compare_and_swap(key, 0, &cipher).unwrap());
        assert_eq!(records.read(key).unwrap().unwrap().data, vec![1, 2, 3]);
        assert!(!adapter.compare_and_swap(key, 0, &cipher).unwrap());
        assert!(records.read("wallet-scope").unwrap().is_none());
    }
}

#[cfg(test)]
mod encrypted_adapter_tests {
    use super::*;
    use crate::session::MemoryAtomicRecords;
    use invisi_sdk_rpc::provenance_recovery::{
        EncryptedRecoveryStore, RecoveryAtomicStore, RecoveryRecord,
    };
    use serde_json::{json, Value};
    fn record() -> RecoveryRecord {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../invisi-sdk-rpc/testdata/provenance-recovery.json"
        ))
        .unwrap();
        serde_json::from_value(json!({"format":"invisi-provenance-recovery-v1","revision":1,"id":"one","intent":fixture["intent"],"manifestSha256":fixture["manifestSha256"],"chainGeneration":"1","sidecar":fixture["sidecars"][0],"idempotencyKey":"stable","state":"broadcast_possible"})).unwrap()
    }
    #[test]
    fn existing_records_hold_only_authenticated_recovery_ciphertext() {
        let records = Arc::new(MemoryAtomicRecords::default());
        let adapter = Arc::new(SessionRecoveryRecords::new(records.clone()));
        let store = EncryptedRecoveryStore::new(adapter.clone(), [7; 32]);
        assert!(store.compare_and_swap("one", 0, &record()).unwrap());
        let encrypted = records
            .read("Invisi.Provenance.Recovery.v1:one")
            .unwrap()
            .unwrap();
        assert!(!encrypted.data.windows(6).any(|w| w == b"0x1234"));
        let restarted = EncryptedRecoveryStore::new(adapter.clone(), [7; 32]);
        assert_eq!(
            restarted.load("one").unwrap().unwrap().state,
            "broadcast_possible"
        );
        let wrong = EncryptedRecoveryStore::new(adapter, [8; 32]);
        assert!(wrong.load("one").is_err());
        assert!(records.read("wallet-scope").unwrap().is_none());
    }
    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_records_reopen_with_independent_recovery_namespace() {
        use crate::session::sqlite::SQLiteRecords;
        let path = std::env::temp_dir().join(format!(
            "invisi-provenance-recovery-{}.sqlite",
            uuid::Uuid::new_v4()
        ));
        {
            let records = Arc::new(SQLiteRecords::open(&path).unwrap());
            let adapter = Arc::new(SessionRecoveryRecords::new(records));
            let store = EncryptedRecoveryStore::new(adapter, [7; 32]);
            assert!(store.compare_and_swap("one", 0, &record()).unwrap());
        }
        {
            let records = Arc::new(SQLiteRecords::open(&path).unwrap());
            let adapter = Arc::new(SessionRecoveryRecords::new(records));
            let store = EncryptedRecoveryStore::new(adapter, [7; 32]);
            assert_eq!(
                store.load("one").unwrap().unwrap().intent.calldata,
                "0x1234"
            );
            assert!(!store.compare_and_swap("one", 0, &record()).unwrap());
        }
        std::fs::remove_file(path).unwrap();
    }
}
