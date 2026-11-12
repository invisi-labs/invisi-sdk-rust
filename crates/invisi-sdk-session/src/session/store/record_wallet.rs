use super::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[derive(Clone, Serialize, Deserialize)]
pub enum WalletRecord {
    Note(super::super::StoredNote),
    Credit(super::super::StoredCredit),
    Operation(super::super::OperationRecord),
}
pub struct WalletRecordEntry {
    pub cursor: String,
    pub record: WalletRecord,
}
pub struct WalletRecordPage {
    pub entries: Vec<WalletRecordEntry>,
    pub next_cursor: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
struct Pointer {
    key: String,
    digest: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
struct Manifest {
    magic: String,
    state: WalletState,
    salt: [u8; 32],
    active: BTreeMap<String, Pointer>,
    #[serde(default)]
    unresolved: BTreeMap<String, Pointer>,
    archive_count: u64,
    sequence: u64,
}
#[derive(Serialize, Deserialize)]
struct Row {
    id: String,
    record: WalletRecord,
    archive: Option<u64>,
}
#[derive(Serialize, Deserialize)]
struct Locator {
    pointer: Pointer,
    id: String,
}
/// Private records use opaque keys; only the authenticated manifest routes active assets.
pub struct RecordWalletStore {
    decoded: DecodedRecords,
    records: Arc<dyn AtomicRecords>,
    key: Zeroizing<[u8; 32]>,
    recent: usize,
}
impl RecordWalletStore {
    pub fn new(records: Arc<dyn AtomicRecords>, key: [u8; 32]) -> Result<Self> {
        Self::with_recent_records(records, key, 128)
    }
    pub fn with_recent_records(
        records: Arc<dyn AtomicRecords>,
        key: [u8; 32],
        recent: usize,
    ) -> Result<Self> {
        if !records.supports_batches() {
            return Err("record wallet requires atomic batch storage".into());
        }
        if recent > 4096 {
            return Err("recent record limit exceeds bound".into());
        }
        Ok(Self {
            records,
            key: Zeroizing::new(key),
            decoded: DecodedRecords::default(),
            recent,
        })
    }
    fn encode<T: Serialize>(&self, key: &str, revision: u64, value: &T) -> Result<EncryptedRecord> {
        let plain =
            Zeroizing::new(serde_json::to_vec(value).map_err(|_| "wallet record encoding failed")?);
        if plain.len() > 64 << 20 {
            return Err("wallet record exceeds storage bound".into());
        }
        let mut nonce = [0; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let cipher =
            Aes256Gcm::new_from_slice(&*self.key).map_err(|_| "invalid store encryption key")?;
        let cipher = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: &EncryptedWalletStore::aad(key, revision),
                },
            )
            .map_err(|_| "wallet record encryption failed")?;
        let mut data = vec![1];
        data.extend_from_slice(&nonce);
        data.extend(cipher);
        Ok(EncryptedRecord { revision, data })
    }
    fn decode<T: serde::de::DeserializeOwned>(
        &self,
        key: &str,
        record: &EncryptedRecord,
    ) -> Result<T> {
        if record.revision == 0
            || record.data.len() < 29
            || record.data.len() > 64 << 20
            || record.data[0] != 1
        {
            return Err("invalid encrypted wallet record".into());
        }
        let cipher =
            Aes256Gcm::new_from_slice(&*self.key).map_err(|_| "invalid store encryption key")?;
        let plain = self.decoded.open(key, record, || {
            Ok(Zeroizing::new(
                cipher
                    .decrypt(
                        Nonce::from_slice(&record.data[1..13]),
                        Payload {
                            msg: &record.data[13..],
                            aad: &EncryptedWalletStore::aad(key, record.revision),
                        },
                    )
                    .map_err(|_| "wallet record authentication failed")?,
            ))
        })?;
        serde_json::from_slice(&plain).map_err(|_| "invalid private record encoding".into())
    }
    fn layout(&self, scope: &str) -> Result<Option<Manifest>> {
        let Some(record) = self.records.read(scope)? else {
            if self.records.count(&self.base(scope))? > 0 {
                return Err("wallet manifest missing while records remain".into());
            }
            return Ok(None);
        };
        let value: serde_json::Value = self.decode(scope, &record)?;
        if value.get("magic").and_then(|v| v.as_str()) != Some("invisi.wallet.records.v1") {
            if self.records.count(&self.base(scope))? > 0 {
                return Err("wallet manifest format omitted".into());
            }
            return Ok(None);
        }
        let m: Manifest =
            serde_json::from_value(value).map_err(|_| "invalid private record manifest")?;
        if m.state.revision != record.revision
            || m.state.format_version != 2
            || !m.state.notes.is_empty()
            || !m.state.credits.is_empty()
            || !m.state.operations.is_empty()
            || !m.state.unresolved_deliveries.is_empty()
        {
            return Err("wallet record manifest mismatch".into());
        }
        let base = self.base(scope);
        let expected_rows = ((m.active.len() + m.unresolved.len()) as u64)
            .checked_add(m.archive_count)
            .ok_or("wallet record count overflow")?;
        if self.records.count(&format!("{base}row/"))? != expected_rows
            || self.records.count(&format!("{base}archive/"))? != m.archive_count
        {
            return Err("wallet record inventory count mismatch".into());
        }
        Ok(Some(m))
    }
    fn base(&self, scope: &str) -> String {
        format!(
            "wallet-records/{}/",
            hex::encode(Sha256::digest(scope.as_bytes()))
        )
    }
    fn row_key(&self, scope: &str, salt: &[u8; 32], id: &str) -> String {
        let mut h = Sha256::new();
        h.update(salt);
        h.update(id.as_bytes());
        format!("{}row/{}", self.base(scope), hex::encode(h.finalize()))
    }
    fn archive_key(&self, scope: &str, seq: u64) -> String {
        format!("{}archive/{:020}", self.base(scope), u64::MAX - seq)
    }
    fn load_row(&self, scope: &str, p: &Pointer) -> Result<Row> {
        if !p.key.starts_with(&format!("{}row/", self.base(scope))) {
            return Err("wallet record routing mismatch".into());
        }
        let r = self.records.read(&p.key)?.ok_or("wallet record missing")?;
        if Sha256::digest(&r.data).as_slice() != p.digest {
            return Err("wallet record digest mismatch".into());
        }
        self.decode(&p.key, &r)
    }
    fn insert(state: &mut WalletState, id: &str, r: WalletRecord) -> Result<()> {
        match r {
            WalletRecord::Note(n) => {
                let key = id
                    .strip_prefix("note:")
                    .ok_or("invalid note routing")?
                    .parse()
                    .map_err(|_| "invalid note id")?;
                if key != n.commitment {
                    return Err("note identity mismatch".into());
                }
                state.notes.insert(key, n);
            }
            WalletRecord::Credit(c) => {
                let key = id.strip_prefix("credit:").ok_or("invalid credit routing")?;
                if key != super::super::credit_key(c.commitment, c.role) {
                    return Err("credit identity mismatch".into());
                }
                state.credits.insert(key.into(), c);
            }
            WalletRecord::Operation(o) => {
                if id != format!("operation:{}", o.id) {
                    return Err("operation identity mismatch".into());
                }
                state.operations.insert(o.id.clone(), o);
            }
        }
        Ok(())
    }
    fn entries(state: &WalletState) -> BTreeMap<String, WalletRecord> {
        state
            .notes
            .iter()
            .map(|(id, v)| (format!("note:{id}"), WalletRecord::Note(v.clone())))
            .chain(
                state
                    .credits
                    .iter()
                    .map(|(id, v)| (format!("credit:{id}"), WalletRecord::Credit(v.clone()))),
            )
            .chain(state.operations.iter().map(|(id, v)| {
                (
                    format!("operation:{id}"),
                    WalletRecord::Operation(v.clone()),
                )
            }))
            .collect()
    }
    fn cold(record: &WalletRecord, state: &WalletState) -> bool {
        match record {
            WalletRecord::Note(n) => n.spent && n.reserved_by.is_none(),
            WalletRecord::Credit(c) => {
                (c.consumed || c.revoked)
                    && c.reserved_by.is_none()
                    && state.credit_replay_from.is_none()
                    && state
                        .discovery_through
                        .as_ref()
                        .zip(state.observed_through.as_ref())
                        .is_some_and(|(a, b)| a.number >= b.number)
            }
            WalletRecord::Operation(o) => o.status.terminal(),
        }
    }
    fn height(r: &WalletRecord) -> u64 {
        match r {
            WalletRecord::Note(n) => n.block.number,
            WalletRecord::Credit(c) => c.block.number,
            WalletRecord::Operation(o) => o.resolved_at.as_ref().map_or(0, |b| b.number),
        }
    }
    fn kind(r: &WalletRecord) -> u8 {
        match r {
            WalletRecord::Note(_) => 0,
            WalletRecord::Credit(_) => 1,
            WalletRecord::Operation(_) => 2,
        }
    }
}
impl WalletStore for RecordWalletStore {
    fn supports_history_paging(&self) -> bool {
        true
    }
    fn snapshot(&self, scope: &str) -> Result<WalletState> {
        let Some(m) = self.layout(scope)? else {
            return EncryptedWalletStore::new(self.records.clone(), *self.key)?.snapshot(scope);
        };
        let mut state = m.state;
        for (id, p) in m.unresolved {
            let value = self
                .records
                .read(&p.key)?
                .ok_or("unresolved record missing")?;
            if p.key != self.row_key(scope, &m.salt, &format!("unresolved:{id}"))
                || Sha256::digest(&value.data).as_slice() != p.digest
            {
                return Err("unresolved record binding mismatch".into());
            }
            state
                .unresolved_deliveries
                .insert(id, self.decode(&p.key, &value)?);
        }
        for (id, p) in m.active {
            let r = self.load_row(scope, &p)?;
            if r.id != id || r.archive.is_some() {
                return Err("active record binding mismatch".into());
            }
            Self::insert(&mut state, &id, r.record)?;
        }
        Ok(state)
    }
    fn read_summary(&self, scope: &str) -> Result<WalletState> {
        match self.layout(scope)? {
            Some(m) => Ok(m.state),
            None => self.snapshot(scope),
        }
    }
    fn full_snapshot(&self, scope: &str) -> Result<WalletState> {
        let mut state = self.snapshot(scope)?;
        let mut after = None;
        loop {
            let page = self.history_page(scope, after.as_deref(), 100)?;
            for e in page.entries {
                let id = match &e.record {
                    WalletRecord::Note(n) => format!("note:{}", n.commitment),
                    WalletRecord::Credit(c) => {
                        format!("credit:{}", super::super::credit_key(c.commitment, c.role))
                    }
                    WalletRecord::Operation(o) => format!("operation:{}", o.id),
                };
                Self::insert(&mut state, &id, e.record)?;
            }
            match page.next_cursor {
                Some(c) => after = Some(c),
                None => break,
            }
        }
        if self.read_summary(scope)?.revision != state.revision {
            return Err("wallet changed during history read".into());
        }
        Ok(state)
    }
    fn history_page(
        &self,
        scope: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<WalletRecordPage> {
        let prefix = format!("{}archive/", self.base(scope));
        super::validate_page(&prefix, after, limit)?;
        if let Some(m) = self.layout(scope)? {
            if self.records.count(&prefix)? != m.archive_count {
                return Err("wallet archive count mismatch".into());
            }
        }

        let rows = self
            .records
            .list(&prefix, after, limit + usize::from(limit < 1000))?;
        let has_more = rows.len() > limit || limit == 1000 && rows.len() == 1000;
        let mut entries = vec![];
        for (key, value) in rows.into_iter().take(limit) {
            let loc: Locator = self.decode(&key, &value)?;
            let row = self.load_row(scope, &loc.pointer)?;
            if row.id != loc.id
                || row.archive.map(|s| self.archive_key(scope, s)).as_deref() != Some(key.as_str())
            {
                return Err("archive locator binding mismatch".into());
            }
            entries.push(WalletRecordEntry {
                cursor: key,
                record: row.record,
            });
        }
        let next_cursor = if has_more {
            entries.last().map(|e| e.cursor.clone())
        } else {
            None
        };
        Ok(WalletRecordPage {
            entries,
            next_cursor,
        })
    }
    fn compare_and_swap(&self, scope: &str, expected: u64, mut next: WalletState) -> Result<()> {
        if next.revision != expected || next.format_version != 2 {
            return Err("invalid next wallet state".into());
        }
        let old = self.layout(scope)?;
        if old.as_ref().is_some_and(|m| m.state.revision != expected) {
            return Err("wallet inventory revision changed".into());
        }
        let mut salt = old.as_ref().map(|m| m.salt).unwrap_or([0; 32]);
        if old.is_none() {
            rand::rngs::OsRng.fill_bytes(&mut salt)
        }
        let revision = expected.checked_add(1).ok_or("wallet revision exhausted")?;
        let entries = Self::entries(&next);
        let mut cold: Vec<_> = entries
            .iter()
            .filter(|(_, r)| Self::cold(r, &next))
            .map(|(id, r)| (id.clone(), Self::kind(r), Self::height(r)))
            .collect();
        cold.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| b.0.cmp(&a.0)));
        let mut counts = [0usize; 3];
        let mut archive = std::collections::BTreeSet::new();
        for (id, kind, _) in cold {
            counts[kind as usize] += 1;
            if counts[kind as usize] > self.recent {
                archive.insert(id);
            }
        }
        let mut sequence = old.as_ref().map_or(0, |m| m.sequence);
        let mut archive_count = old.as_ref().map_or(0, |m| m.archive_count);
        let mut active = BTreeMap::new();
        let mut writes = BTreeMap::<String, Option<EncryptedRecord>>::new();
        if let Some(old) = &old {
            for (id, p) in &old.active {
                if !entries.contains_key(id) {
                    writes.insert(p.key.clone(), None);
                }
            }
        }
        for (id, record) in entries {
            let key = self.row_key(scope, &salt, &id);
            if let Some(previous) = self.records.read(&key)? {
                let row: Row = self.decode(&key, &previous)?;
                if row.id != id {
                    return Err("private record identity mismatch".into());
                }
                if let Some(seq) = row.archive {
                    writes.insert(self.archive_key(scope, seq), None);
                    archive_count = archive_count
                        .checked_sub(1)
                        .ok_or("archive count mismatch")?;
                }
            }
            let archived = if archive.contains(&id) {
                sequence = sequence
                    .checked_add(1)
                    .ok_or("archive sequence exhausted")?;
                archive_count = archive_count
                    .checked_add(1)
                    .ok_or("archive count overflow")?;
                Some(sequence)
            } else {
                None
            };
            let row = Row {
                id: id.clone(),
                record,
                archive: archived,
            };
            let value = self.encode(&key, revision, &row)?;
            let pointer = Pointer {
                key: key.clone(),
                digest: Sha256::digest(&value.data).to_vec(),
            };
            writes.insert(key, Some(value));
            if let Some(seq) = archived {
                let key = self.archive_key(scope, seq);
                writes.insert(
                    key.clone(),
                    Some(self.encode(&key, revision, &Locator { pointer, id })?),
                );
            } else {
                active.insert(id, pointer);
            }
        }
        let mut unresolved = BTreeMap::new();
        if let Some(old) = &old {
            for (id, p) in &old.unresolved {
                if !next.unresolved_deliveries.contains_key(id) {
                    writes.insert(p.key.clone(), None);
                }
            }
        }
        for (id, value) in &next.unresolved_deliveries {
            let key = self.row_key(scope, &salt, &format!("unresolved:{id}"));
            let record = self.encode(&key, revision, value)?;
            unresolved.insert(
                id.clone(),
                Pointer {
                    key: key.clone(),
                    digest: Sha256::digest(&record.data).to_vec(),
                },
            );
            writes.insert(key, Some(record));
        }
        next.unresolved_delivery_count = Some(next.unresolved_deliveries.len());
        next.unresolved_deliveries.clear();
        next.revision = revision;
        next.notes.clear();
        next.credits.clear();
        next.operations.clear();
        let manifest = Manifest {
            magic: "invisi.wallet.records.v1".into(),
            state: next,
            salt,
            active,
            unresolved,
            archive_count,
            sequence,
        };
        let metadata = self.encode(scope, revision, &manifest)?;
        if !self.records.compare_and_swap_batch(
            scope,
            expected,
            &metadata,
            &writes.into_iter().collect::<Vec<_>>(),
        )? {
            return Err("wallet inventory revision changed".into());
        }
        Ok(())
    }
    fn recover_reorg(&self, scope: &str, from_block: u64) -> Result<()> {
        let mut state = self.snapshot(scope)?;
        let previous = state.unresolved_deliveries.len();
        state
            .unresolved_deliveries
            .retain(|_, candidate| candidate.receipt.block.number < from_block);
        if state.unresolved_deliveries.len() != previous {
            state.unresolved_delivery_count = Some(state.unresolved_deliveries.len());
            let revision = state.revision;
            self.compare_and_swap(scope, revision, state)?;
        }
        // Restore externalized locks before deleting any cold inputs from the affected range.
        let mut after = None;
        loop {
            let page = self.history_page(scope, after.as_deref(), 100)?;
            for entry in page.entries {
                if let WalletRecord::Operation(mut op) = entry.record {
                    if op.externalized
                        && op
                            .resolved_at
                            .as_ref()
                            .is_some_and(|b| b.number >= from_block)
                    {
                        let mut state = self.snapshot(scope)?;
                        op.status = super::super::OperationStatus::Reorged;
                        op.resolved_at = None;
                        op.generation = op
                            .generation
                            .checked_add(1)
                            .ok_or("operation generation exhausted")?;
                        let id = op.id.clone();
                        for input in &op.inputs {
                            for rid in if input.starts_with("credit:") {
                                vec![format!("{input}:Owner"), format!("{input}:Spender")]
                            } else {
                                vec![input.clone()]
                            } {
                                if let Some(m) = self.layout(scope)? {
                                    let key = self.row_key(scope, &m.salt, &rid);
                                    if let Some(value) = self.records.read(&key)? {
                                        let mut row: Row = self.decode(&key, &value)?;
                                        match &mut row.record {
                                            WalletRecord::Note(n) => {
                                                n.reserved_by = Some(id.clone())
                                            }
                                            WalletRecord::Credit(c) => {
                                                c.reserved_by = Some(id.clone())
                                            }
                                            _ => {}
                                        }
                                        Self::insert(&mut state, &rid, row.record)?;
                                    }
                                }
                            }
                        }
                        state.operations.insert(id, op);
                        let revision = state.revision;
                        self.compare_and_swap(scope, revision, state)?;
                    }
                }
            }
            match page.next_cursor {
                Some(c) => after = Some(c),
                None => break,
            }
        }
        let mut after = None;
        loop {
            let page = self.history_page(scope, after.as_deref(), 100)?;
            for entry in page.entries {
                let orphan = match &entry.record {
                    WalletRecord::Note(n) => n.block.number >= from_block,
                    WalletRecord::Credit(c) => c.block.number >= from_block,
                    WalletRecord::Operation(o) => {
                        !o.externalized
                            && o.resolved_at
                                .as_ref()
                                .is_some_and(|b| b.number >= from_block)
                    }
                };
                if orphan {
                    let mut m = self.layout(scope)?.ok_or("archive manifest missing")?;
                    let value = self
                        .records
                        .read(&entry.cursor)?
                        .ok_or("archive locator missing")?;
                    let loc: Locator = self.decode(&entry.cursor, &value)?;
                    let expected = m.state.revision;
                    let revision = expected.checked_add(1).ok_or("wallet revision overflow")?;
                    m.state.revision = revision;
                    m.archive_count = m
                        .archive_count
                        .checked_sub(1)
                        .ok_or("archive count mismatch")?;
                    let root = self.encode(scope, revision, &m)?;
                    if !self.records.compare_and_swap_batch(
                        scope,
                        expected,
                        &root,
                        &[(entry.cursor, None), (loc.pointer.key, None)],
                    )? {
                        return Err("wallet inventory revision changed".into());
                    }
                    continue;
                }
            }
            match page.next_cursor {
                Some(c) => after = Some(c),
                None => break,
            }
        }
        Ok(())
    }
    fn persistent(&self) -> bool {
        self.records.persistent()
    }
}
