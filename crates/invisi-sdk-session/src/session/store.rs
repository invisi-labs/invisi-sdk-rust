use super::{Result, WalletState};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use alloy_primitives::keccak256;
use rand::RngCore;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use zeroize::Zeroizing;

// Share local observations across independently connected sessions and store adapters.
#[derive(Default)]
struct WriteActivity {
    epoch: u64,
    active: usize,
}
#[derive(Default)]
pub(crate) struct WalletWrites {
    activity: Mutex<WriteActivity>,
}
impl WalletWrites {
    pub(crate) fn shared(identity: usize, scope: &str) -> Arc<Self> {
        type Registry = BTreeMap<(usize, String), std::sync::Weak<WalletWrites>>;
        static WRITES: std::sync::OnceLock<Mutex<Registry>> = std::sync::OnceLock::new();
        let mut registry = WRITES.get_or_init(Default::default).lock().unwrap();
        let key = (identity, scope.to_owned());
        if let Some(clock) = registry.get(&key).and_then(std::sync::Weak::upgrade) {
            return clock;
        }
        registry.retain(|_, value| value.strong_count() > 0);
        let clock = Arc::new(Self::default());
        registry.insert(key, Arc::downgrade(&clock));
        clock
    }
    pub(crate) fn idle_epoch(&self) -> Result<u64> {
        let activity = self.activity.lock().unwrap();
        if activity.active > 0 {
            return Err("wallet write in progress before submission".into());
        }
        Ok(activity.epoch)
    }
}
/// Marks an SDK wallet write until the backing store finishes its compare-and-swap.
#[must_use = "keep the mutation guard until the backing write returns"]
pub struct WalletStoreMutation(Arc<WalletWrites>);
impl Drop for WalletStoreMutation {
    fn drop(&mut self) {
        self.0.activity.lock().unwrap().active -= 1;
    }
}
/// Implementations must atomically compare the revision and replace the complete detached snapshot.
pub trait WalletStore: Send + Sync {
    /// In-process identity of the backing store shared by wallet handles.
    fn mutation_identity(&self) -> usize {
        self as *const Self as *const () as usize
    }
    /// Custom adapters use this for direct writes made outside a WalletSession.
    fn begin_mutation(&self, scope: &str) -> Result<WalletStoreMutation> {
        let clock = WalletWrites::shared(self.mutation_identity(), scope);
        {
            let mut activity = clock.activity.lock().unwrap();
            activity.epoch = activity
                .epoch
                .checked_add(1)
                .ok_or("wallet write generation exhausted")?;
            activity.active += 1;
        }
        Ok(WalletStoreMutation(clock))
    }

    fn snapshot(&self, scope: &str) -> Result<WalletState>;
    fn compare_and_swap(
        &self,
        scope: &str,
        expected_revision: u64,
        next: WalletState,
    ) -> Result<()>;
    fn persistent(&self) -> bool;
    fn supports_history_paging(&self) -> bool {
        false
    }
    fn read_summary(&self, scope: &str) -> Result<WalletState> {
        self.snapshot(scope)
    }
    fn full_snapshot(&self, scope: &str) -> Result<WalletState> {
        self.snapshot(scope)
    }
    fn history_page(
        &self,
        _scope: &str,
        _after: Option<&str>,
        _limit: usize,
    ) -> Result<WalletRecordPage> {
        Err("wallet store does not support record paging".into())
    }
    fn recover_reorg(&self, _scope: &str, _from_block: u64) -> Result<()> {
        Ok(())
    }
}
#[derive(Default)]
pub struct MemoryWalletStore {
    states: Mutex<BTreeMap<String, WalletState>>,
}
impl WalletStore for MemoryWalletStore {
    fn snapshot(&self, scope: &str) -> Result<WalletState> {
        Ok(self
            .states
            .lock()
            .map_err(|_| "wallet store lock poisoned")?
            .get(scope)
            .cloned()
            .unwrap_or_default())
    }
    fn compare_and_swap(
        &self,
        scope: &str,
        expected_revision: u64,
        mut next: WalletState,
    ) -> Result<()> {
        let _write = self.begin_mutation(scope)?;
        if next.revision != expected_revision {
            return Err("invalid next snapshot revision".into());
        }
        let mut states = self
            .states
            .lock()
            .map_err(|_| "wallet store lock poisoned")?;
        if states.get(scope).map_or(0, |s| s.revision) != expected_revision {
            return Err("wallet inventory revision changed".into());
        }
        next.revision = expected_revision
            .checked_add(1)
            .ok_or("wallet revision exhausted")?;
        states.insert(scope.into(), next);
        Ok(())
    }
    fn persistent(&self) -> bool {
        false
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedRecord {
    pub revision: u64,
    pub data: Vec<u8>,
}
/// Host adapters store opaque bytes. Private wallet values are authenticated ciphertext;
/// public history uses a separate namespace/table. Missing records have revision zero.
pub trait AtomicRecords: Send + Sync {
    /// Shared identity for adapters addressing the same records in this process.
    fn mutation_identity(&self) -> usize {
        self as *const Self as *const () as usize
    }
    fn read(&self, scope: &str) -> Result<Option<EncryptedRecord>>;
    fn compare_and_swap(
        &self,
        scope: &str,
        expected_revision: u64,
        next: &EncryptedRecord,
    ) -> Result<bool>;
    fn persistent(&self) -> bool;
    fn supports_batches(&self) -> bool {
        false
    }
    fn compare_and_swap_batch(
        &self,
        _scope: &str,
        _expected: u64,
        _next: &EncryptedRecord,
        _writes: &[(String, Option<EncryptedRecord>)],
    ) -> Result<bool> {
        Err("record store requires atomic batch support".into())
    }
    fn count(&self, prefix: &str) -> Result<u64> {
        let mut count = 0u64;
        let mut after = None;
        loop {
            let rows = self.list(prefix, after.as_deref(), 1000)?;
            count = count
                .checked_add(rows.len() as u64)
                .ok_or("record count overflow")?;
            if rows.len() < 1000 {
                return Ok(count);
            }
            after = rows.last().map(|r| r.0.clone());
        }
    }
    fn list(
        &self,
        _prefix: &str,
        _after: Option<&str>,
        _limit: usize,
    ) -> Result<Vec<(String, EncryptedRecord)>> {
        Err("record store requires bounded paging".into())
    }
}
#[derive(Default)]
pub struct MemoryAtomicRecords {
    records: Mutex<BTreeMap<String, EncryptedRecord>>,
}
impl AtomicRecords for MemoryAtomicRecords {
    fn read(&self, scope: &str) -> Result<Option<EncryptedRecord>> {
        Ok(self
            .records
            .lock()
            .map_err(|_| "record store lock poisoned")?
            .get(scope)
            .cloned())
    }
    fn compare_and_swap(&self, scope: &str, expected: u64, next: &EncryptedRecord) -> Result<bool> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| "record store lock poisoned")?;
        if records.get(scope).map_or(0, |v| v.revision) != expected {
            return Ok(false);
        }
        if next.revision != expected.checked_add(1).ok_or("record revision exhausted")? {
            return Err("invalid encrypted record revision".into());
        }
        records.insert(scope.into(), next.clone());
        Ok(true)
    }
    fn supports_batches(&self) -> bool {
        true
    }
    fn compare_and_swap_batch(
        &self,
        scope: &str,
        expected: u64,
        next: &EncryptedRecord,
        writes: &[(String, Option<EncryptedRecord>)],
    ) -> Result<bool> {
        validate_batch(scope, expected, next, writes)?;
        let mut records = self
            .records
            .lock()
            .map_err(|_| "record store lock poisoned")?;
        if records.get(scope).map_or(0, |r| r.revision) != expected {
            return Ok(false);
        }
        for (key, value) in writes {
            if let Some(value) = value {
                records.insert(key.clone(), value.clone());
            } else {
                records.remove(key);
            }
        }
        records.insert(scope.into(), next.clone());
        Ok(true)
    }
    fn list(
        &self,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<(String, EncryptedRecord)>> {
        validate_page(prefix, after, limit)?;
        let records = self
            .records
            .lock()
            .map_err(|_| "record store lock poisoned")?;
        Ok(records
            .range(prefix.to_owned()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .filter(|(k, _)| after.is_none_or(|a| k.as_str() > a))
            .take(limit)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }
    fn persistent(&self) -> bool {
        false
    }
}
pub struct EncryptedWalletStore {
    decoded: DecodedRecords,
    records: Arc<dyn AtomicRecords>,
    key: Zeroizing<[u8; 32]>,
}
impl std::fmt::Debug for EncryptedWalletStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedWalletStore")
            .field("persistent", &self.records.persistent())
            .finish_non_exhaustive()
    }
}
impl EncryptedWalletStore {
    pub fn new(records: Arc<dyn AtomicRecords>, key: [u8; 32]) -> Result<Self> {
        Ok(Self {
            records,
            key: Zeroizing::new(key),
            decoded: DecodedRecords::default(),
        })
    }
    fn aad(scope: &str, revision: u64) -> Vec<u8> {
        let mut aad = b"Invisi.WalletRecord.v1\0".to_vec();
        aad.extend_from_slice(keccak256(scope.as_bytes()).as_slice());
        aad.extend_from_slice(&revision.to_be_bytes());
        aad
    }
}
impl WalletStore for EncryptedWalletStore {
    fn mutation_identity(&self) -> usize {
        self.records.mutation_identity()
    }
    fn snapshot(&self, scope: &str) -> Result<WalletState> {
        let Some(record) = self.records.read(scope)? else {
            return Ok(WalletState::default());
        };
        if record.revision == 0
            || record.data.len() < 29
            || record.data.len() > 64 << 20
            || record.data[0] != 1
        {
            return Err("invalid encrypted wallet record".into());
        }
        let cipher =
            Aes256Gcm::new_from_slice(&*self.key).map_err(|_| "invalid store encryption key")?;
        let plain = self.decoded.open(scope, &record, || {
            Ok(Zeroizing::new(
                cipher
                    .decrypt(
                        Nonce::from_slice(&record.data[1..13]),
                        Payload {
                            msg: &record.data[13..],
                            aad: &Self::aad(scope, record.revision),
                        },
                    )
                    .map_err(|_| "wallet record authentication failed")?,
            ))
        })?;
        let state: WalletState =
            serde_json::from_slice(&plain).map_err(|_| "invalid wallet state encoding")?;
        if state.revision != record.revision || state.format_version != 2 {
            return Err("wallet record schema or revision mismatch".into());
        }
        Ok(state)
    }
    fn compare_and_swap(&self, scope: &str, expected: u64, mut next: WalletState) -> Result<()> {
        let _write = self.begin_mutation(scope)?;
        if next.revision != expected || next.format_version != 2 {
            return Err("invalid next wallet state".into());
        }
        next.revision = expected.checked_add(1).ok_or("wallet revision exhausted")?;
        let plain =
            Zeroizing::new(serde_json::to_vec(&next).map_err(|_| "wallet state encoding failed")?);
        if plain.len() > 64 << 20 {
            return Err("wallet state exceeds storage bound".into());
        }
        let mut nonce = [0; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let cipher = Aes256Gcm::new_from_slice(&*self.key).map_err(|_| "invalid encryption key")?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: &Self::aad(scope, next.revision),
                },
            )
            .map_err(|_| "wallet record encryption failed")?;
        let mut data = vec![1];
        data.extend_from_slice(&nonce);
        data.extend(ciphertext);
        if !self.records.compare_and_swap(
            scope,
            expected,
            &EncryptedRecord {
                revision: next.revision,
                data,
            },
        )? {
            return Err("wallet inventory revision changed".into());
        }
        Ok(())
    }
    fn persistent(&self) -> bool {
        self.records.persistent()
    }
}

pub(crate) fn validate_page(prefix: &str, after: Option<&str>, limit: usize) -> Result<()> {
    if prefix.is_empty()
        || !(1..=1000).contains(&limit)
        || after.is_some_and(|a| !a.starts_with(prefix))
    {
        return Err("invalid record page range".into());
    }
    Ok(())
}
pub(crate) fn validate_batch(
    scope: &str,
    expected: u64,
    next: &EncryptedRecord,
    writes: &[(String, Option<EncryptedRecord>)],
) -> Result<()> {
    if scope.is_empty()
        || next.revision != expected.checked_add(1).ok_or("record revision overflow")?
    {
        return Err("invalid batch revision".into());
    }
    let mut keys = std::collections::BTreeSet::new();
    for (key, value) in writes {
        if key == scope
            || key.is_empty()
            || !keys.insert(key)
            || value.as_ref().is_some_and(|v| v.revision == 0)
        {
            return Err("invalid batch record key or revision".into());
        }
    }
    Ok(())
}
mod record_wallet;
pub use record_wallet::*;

mod decoded;
use decoded::DecodedRecords;
