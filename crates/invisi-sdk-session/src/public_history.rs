//! Deployment-wide public canonical history. Account secrets never enter this store.
use crate::{
    rpc::{CanonicalBlock, CanonicalReceipt},
    session::{AtomicRecords, EncryptedRecord, Result},
};
use alloy_primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoverageRange {
    pub from_block: u64,
    pub block: CanonicalBlock,
}
pub fn merge_coverage(
    ranges: &[CoverageRange],
    input: CoverageRange,
) -> Result<Vec<CoverageRange>> {
    let mut sorted = ranges.to_vec();
    sorted.push(input);
    sorted.sort_by_key(|r| r.from_block);
    let mut out: Vec<CoverageRange> = vec![];
    for range in sorted {
        if range.from_block > range.block.number || range.block.hash == B256::ZERO {
            return Err("invalid history coverage".into());
        }
        if let Some(last) = out.last_mut() {
            if range.from_block <= last.block.number.saturating_add(1) {
                if range.block.number == last.block.number && range.block.hash != last.block.hash {
                    return Err("conflicting history anchor".into());
                }
                if range.block.number > last.block.number {
                    last.block = range.block
                }
                continue;
            }
        }
        out.push(range)
    }
    if out.len() > 4096 {
        return Err("history coverage too fragmented".into());
    }
    Ok(out)
}
pub fn highest_gap(ranges: &[CoverageRange], from: u64, to: u64) -> Option<(u64, u64)> {
    if to < from {
        return None;
    }
    let mut cursor = to;
    let mut sorted = ranges.to_vec();
    sorted.sort_by_key(|r| std::cmp::Reverse(r.from_block));
    for r in sorted {
        if r.from_block > cursor {
            continue;
        }
        if r.block.number < cursor {
            return Some((r.block.number.saturating_add(1).max(from), cursor));
        }
        if r.from_block <= from {
            return None;
        }
        cursor = r.from_block - 1
    }
    Some((from, cursor))
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicHistoryScope {
    pub chain_id: u64,
    pub protocol_address: Address,
    pub runtime_code_hash: B256,
    pub deployment_block: u64,
}
impl PublicHistoryScope {
    pub fn key(&self) -> Result<String> {
        if self.chain_id == 0 || self.protocol_address == Address::ZERO {
            return Err("invalid public deployment".into());
        }
        Ok(format!(
            "public-history/v1/{}",
            hex::encode(Sha256::digest(
                serde_json::to_vec(self).map_err(|e| e.to_string())?
            ))
        ))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CachedMembership {
    pub tree_id: u64,
    pub leaf_index: u32,
    pub commitment: B256,
    pub block: CanonicalBlock,
    pub root: U256,
    pub path: [U256; 16],
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicHistoryPage {
    pub from_block: u64,
    pub block: CanonicalBlock,
    pub headers: Vec<CanonicalBlock>,
    pub receipts: Vec<CanonicalReceipt>,
    pub verified_positions: Vec<String>,
    #[serde(default)]
    pub memberships: Vec<CachedMembership>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PageReference {
    pub from_block: u64,
    pub block: CanonicalBlock,
    pub parent_hash: B256,
    pub key: String,
    pub digest: Vec<u8>,
    pub bytes: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicHistorySnapshot {
    pub revision: u64,
    pub generation: u64,
    pub scope_key: String,
    pub coverage: Vec<CoverageRange>,
    pub pages: Vec<PageReference>,
    pub through: Option<CanonicalBlock>,
    pub indexed_head: Option<CanonicalBlock>,
    pub known_head: Option<CanonicalBlock>,
    pub reorg_from: Option<u64>,
}
#[derive(Clone, Copy, Debug)]
pub struct Retention {
    pub max_bytes: usize,
    pub max_pages: usize,
    pub max_page_bytes: usize,
}
impl Default for Retention {
    fn default() -> Self {
        Self {
            max_bytes: 128 << 20,
            max_pages: 4096,
            max_page_bytes: 8 << 20,
        }
    }
}
pub struct PublicHistoryStore {
    records: Arc<dyn AtomicRecords>,
    pub retention: Retention,
    pub(crate) tasks: Mutex<()>,
}
impl PublicHistoryStore {
    pub fn new(records: Arc<dyn AtomicRecords>, retention: Retention) -> Result<Self> {
        if !records.supports_batches() {
            return Err("public history requires atomic batch storage".into());
        }
        if retention.max_bytes == 0
            || retention.max_pages == 0
            || retention.max_pages > 4096
            || retention.max_page_bytes == 0
            || retention.max_page_bytes > retention.max_bytes
        {
            return Err("invalid public retention".into());
        }
        Ok(Self {
            records,
            retention,
            tasks: Mutex::new(()),
        })
    }
    pub fn persistent(&self) -> bool {
        self.records.persistent()
    }
    pub fn snapshot(&self, scope: &PublicHistoryScope) -> Result<PublicHistorySnapshot> {
        let key = scope.key()?;
        let Some(record) = self.records.read(&key)? else {
            return Ok(PublicHistorySnapshot {
                revision: 0,
                generation: 1,
                scope_key: key,
                coverage: vec![],
                pages: vec![],
                through: None,
                indexed_head: None,
                known_head: None,
                reorg_from: None,
            });
        };
        let state: PublicHistorySnapshot =
            serde_json::from_slice(&record.data).map_err(|_| "invalid public metadata")?;
        if state.scope_key != key || state.revision != record.revision || state.generation == 0 {
            return Err("public metadata binding mismatch".into());
        }
        if state.pages.len() > 4096 || state.coverage.len() > 4096 {
            return Err("public metadata exceeds bound".into());
        }
        let mut previous = None;
        let mut bytes = 0usize;
        for p in &state.pages {
            if p.from_block < scope.deployment_block
                || p.from_block > p.block.number
                || p.block.number - p.from_block >= 256
                || previous.is_some_and(|n| p.from_block <= n)
                || !p.key.starts_with(&(key.clone() + "/page/"))
                || p.digest.len() != 32
                || p.bytes == 0
                || p.bytes > self.retention.max_page_bytes
            {
                return Err("invalid public page reference".into());
            }
            bytes = bytes.checked_add(p.bytes).ok_or("public size overflow")?;
            previous = Some(p.block.number);
        }
        if state.pages.len() > self.retention.max_pages || bytes > self.retention.max_bytes {
            return Err("public cache exceeds configured retention".into());
        }
        let mut merged = vec![];
        for r in &state.coverage {
            if r.from_block < scope.deployment_block {
                return Err("invalid public coverage scope".into());
            }
            merged = merge_coverage(&merged, r.clone())?;
        }
        if merged != state.coverage
            || state.through
                != state
                    .coverage
                    .iter()
                    .find(|r| r.from_block == scope.deployment_block)
                    .map(|r| r.block.clone())
        {
            return Err("invalid public coverage metadata".into());
        }
        Ok(state)
    }
    fn update(
        &self,
        scope: &PublicHistoryScope,
        mut action: impl FnMut(&mut PublicHistorySnapshot) -> Result<()>,
    ) -> Result<PublicHistorySnapshot> {
        self.update_batch(scope, |state| {
            action(state)?;
            Ok(vec![])
        })
    }
    fn update_batch(
        &self,
        scope: &PublicHistoryScope,
        mut action: impl FnMut(
            &mut PublicHistorySnapshot,
        ) -> Result<Vec<(String, Option<EncryptedRecord>)>>,
    ) -> Result<PublicHistorySnapshot> {
        for _ in 0..32 {
            let mut state = self.snapshot(scope)?;
            let previous = state.revision;
            let writes = action(&mut state)?;
            state.revision = previous.checked_add(1).ok_or("public revision overflow")?;
            let next = EncryptedRecord {
                revision: state.revision,
                data: serde_json::to_vec(&state).map_err(|e| e.to_string())?,
            };
            if self
                .records
                .compare_and_swap_batch(&state.scope_key, previous, &next, &writes)?
            {
                return Ok(state);
            }
        }
        Err("public cache contention".into())
    }
    pub fn read(&self, reference: &PageReference) -> Result<PublicHistoryPage> {
        let record = self
            .records
            .read(&reference.key)?
            .ok_or("public page missing")?;
        if Sha256::digest(&record.data).as_slice() != reference.digest {
            return Err("public page corrupt".into());
        }
        let page: PublicHistoryPage =
            serde_json::from_slice(&record.data).map_err(|_| "invalid public page")?;
        if record.data.len() != reference.bytes {
            return Err("public page size mismatch".into());
        }
        if page.from_block != reference.from_block || page.block != reference.block {
            return Err("public page binding mismatch".into());
        }
        Ok(page)
    }
    pub fn page_at(
        &self,
        scope: &PublicHistoryScope,
        number: u64,
    ) -> Result<Option<PublicHistoryPage>> {
        let state = self.snapshot(scope)?;
        state
            .pages
            .iter()
            .find(|p| p.from_block <= number && p.block.number >= number)
            .map(|p| self.read(p))
            .transpose()
    }
    pub fn note_head(
        &self,
        scope: &PublicHistoryScope,
        indexed: CanonicalBlock,
        known: CanonicalBlock,
    ) -> Result<PublicHistorySnapshot> {
        self.update(scope, |s| {
            s.indexed_head = Some(indexed.clone());
            s.known_head = Some(known.clone());
            Ok(())
        })
    }
    pub fn append(
        &self,
        scope: &PublicHistoryScope,
        page: PublicHistoryPage,
        generation: u64,
    ) -> Result<PublicHistorySnapshot> {
        if page.from_block < scope.deployment_block
            || page.block.number < page.from_block
            || page.block.number - page.from_block >= 256
            || page.headers.len() as u64 != page.block.number - page.from_block + 1
        {
            return Err("invalid public page range".into());
        }
        for (i, h) in page.headers.iter().enumerate() {
            if h.number != page.from_block + i as u64
                || i > 0 && h.parent_hash != page.headers[i - 1].hash
            {
                return Err("noncontiguous public headers".into());
            }
        }
        if page.headers.last() != Some(&page.block) {
            return Err("public anchor mismatch".into());
        }
        for r in &page.receipts {
            if !r.success || !page.headers.contains(&r.block) || r.transaction_hash == B256::ZERO {
                return Err("invalid public receipt binding".into());
            }
        }
        let data = serde_json::to_vec(&page).map_err(|e| e.to_string())?;
        if data.len() > self.retention.max_page_bytes {
            return Err("public page exceeds cache budget; reduce page size".into());
        }
        let key = format!(
            "{}/page/{generation}/{}/{}/{}",
            scope.key()?,
            page.from_block,
            page.block.number,
            page.block.hash
        );
        let digest = Sha256::digest(&data).to_vec();
        self.update_batch(scope, |state| {
            let mut removed = vec![];
            if state.generation != generation {
                return Err("public generation changed".into());
            }
            if state
                .pages
                .iter()
                .any(|p| p.key == key && p.digest == digest)
            {
                return Ok(vec![]);
            }
            if state
                .pages
                .iter()
                .any(|p| p.from_block <= page.block.number && p.block.number >= page.from_block)
            {
                return Err("overlapping public pages".into());
            }
            state.pages.push(PageReference {
                from_block: page.from_block,
                block: page.block.clone(),
                parent_hash: page.headers[0].parent_hash,
                key: key.clone(),
                digest: digest.clone(),
                bytes: data.len(),
            });
            state.pages.sort_by_key(|p| p.from_block);
            for pair in state.pages.windows(2) {
                if pair[0].block.number.checked_add(1) == Some(pair[1].from_block)
                    && pair[0].block.hash != pair[1].parent_hash
                {
                    return Err("public parent conflict".into());
                }
            }
            state.coverage = merge_coverage(
                &state.coverage,
                CoverageRange {
                    from_block: page.from_block,
                    block: page.block.clone(),
                },
            )?;
            state.through = state
                .coverage
                .iter()
                .find(|r| r.from_block == scope.deployment_block)
                .map(|r| r.block.clone());
            while state.pages.len() > self.retention.max_pages
                || state.pages.iter().map(|p| p.bytes).sum::<usize>() > self.retention.max_bytes
            {
                removed.push(state.pages.remove(0))
            }
            let retained = state.pages.iter().any(|p| p.key == key);
            let mut writes = removed
                .into_iter()
                .filter(|p| p.key != key)
                .map(|p| (p.key, None))
                .collect::<Vec<_>>();
            if retained {
                let old = self.records.read(&key)?;
                if old.as_ref().is_some_and(|r| r.data != data) {
                    return Err("conflicting public page".into());
                }
                writes.push((
                    key.clone(),
                    Some(EncryptedRecord {
                        revision: old.map_or(1, |r| r.revision + 1),
                        data: data.clone(),
                    }),
                ));
            }
            Ok(writes)
        })
    }
    pub fn rewind(
        &self,
        scope: &PublicHistoryScope,
        ancestor: Option<CanonicalBlock>,
    ) -> Result<PublicHistorySnapshot> {
        self.update_batch(scope, |s| {
            let mut removed = vec![];
            s.generation = s
                .generation
                .checked_add(1)
                .ok_or("public generation overflow")?;
            let from = ancestor
                .as_ref()
                .map_or(scope.deployment_block, |a| a.number.saturating_add(1));
            s.reorg_from = Some(s.reorg_from.map_or(from, |old| old.min(from)));
            s.pages.retain(|p| {
                if p.block.number >= from {
                    removed.push(p.clone());
                    false
                } else {
                    true
                }
            });
            s.coverage = s
                .coverage
                .iter()
                .filter_map(|r| {
                    if r.from_block >= from {
                        None
                    } else if r.block.number >= from {
                        ancestor.as_ref().map(|a| CoverageRange {
                            from_block: r.from_block,
                            block: a.clone(),
                        })
                    } else {
                        Some(r.clone())
                    }
                })
                .collect();
            s.through = s
                .coverage
                .iter()
                .find(|r| r.from_block == scope.deployment_block)
                .map(|r| r.block.clone());
            Ok(removed.into_iter().map(|p| (p.key, None)).collect())
        })
    }
}

#[derive(Clone, Default)]
pub struct CancellationToken(Arc<std::sync::atomic::AtomicBool>);
impl CancellationToken {
    pub fn cancel(&self) {
        self.0.store(true, std::sync::atomic::Ordering::Release)
    }
    pub fn check(&self) -> Result<()> {
        if self.0.load(std::sync::atomic::Ordering::Acquire) {
            Err("history request cancelled".into())
        } else {
            Ok(())
        }
    }
}
/// Share one instance per deployment to coalesce overlapping downloads across accounts.
#[derive(Clone)]
pub struct PublicHistory {
    pub store: Arc<PublicHistoryStore>,
    pub scope: PublicHistoryScope,
    source: Arc<dyn crate::session::SessionSource>,
}
impl PublicHistory {
    pub fn new(
        store: Arc<PublicHistoryStore>,
        scope: PublicHistoryScope,
        source: Arc<dyn crate::session::SessionSource>,
    ) -> Result<Self> {
        scope.key()?;
        if scope.chain_id != source.context().chain_id
            || scope.protocol_address
                != crate::sdk::word_address(source.context().protocol_address)?
            || scope.deployment_block != source.deployment_start()
            || source
                .runtime_code_hash()
                .is_some_and(|h| h != scope.runtime_code_hash)
        {
            return Err("public source deployment mismatch".into());
        }
        Ok(Self {
            store,
            scope,
            source,
        })
    }
    pub fn validate_canonical(&self) -> Result<()> {
        let state = self.snapshot()?;
        for range in &state.coverage {
            if self.source.block(range.block.number)? != range.block {
                self.store.rewind(&self.scope, None)?;
                return Err("public canonical history changed; rebuild required".into());
            }
        }
        Ok(())
    }
    pub fn snapshot(&self) -> Result<PublicHistorySnapshot> {
        self.store.snapshot(&self.scope)
    }
    fn read_headers(
        &self,
        from: u64,
        to: u64,
        cancel: &CancellationToken,
    ) -> Result<Vec<CanonicalBlock>> {
        let numbers = (from..=to).collect::<Vec<_>>();
        let mut bulk = Vec::with_capacity(numbers.len());
        for chunk in numbers.chunks(256) {
            cancel.check()?;
            match self.source.blocks(chunk) {
                Some(result) => {
                    let headers = result?;
                    cancel.check()?;
                    if headers.len() != chunk.len()
                        || headers.iter().zip(chunk).any(|(h, n)| h.number != *n)
                    {
                        return Err("invalid public bulk headers".into());
                    }
                    bulk.extend(headers);
                }
                None if bulk.is_empty() => break,
                None => return Err("public bulk header capability changed".into()),
            }
        }
        if !bulk.is_empty() {
            if bulk.windows(2).any(|p| p[1].parent_hash != p[0].hash) {
                return Err("noncontiguous public bulk headers".into());
            }
            return Ok(bulk);
        }
        let count = (to - from + 1) as usize;
        let workers = count.min(8);
        // Reuse bounded workers across the page, rather than spawning per block.
        let batches = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..workers)
                .map(|worker| {
                    scope.spawn(move || -> Result<Vec<CanonicalBlock>> {
                        let mut headers = Vec::new();
                        for index in (worker..count).step_by(workers) {
                            cancel.check()?;
                            let number = from + index as u64;
                            let header = self.source.block(number)?;
                            if header.number != number {
                                return Err("invalid public header height".into());
                            }
                            headers.push(header);
                        }
                        Ok(headers)
                    })
                })
                .collect();
            // Join every reader before returning errors or permitting a retry.
            handles.into_iter().map(|h| h.join()).collect::<Vec<_>>()
        });
        let mut headers = Vec::with_capacity(count);
        for batch in batches {
            headers.extend(batch.map_err(|_| "public header reader panicked")??);
        }
        cancel.check()?;
        headers.sort_by_key(|h| h.number);
        if headers
            .windows(2)
            .any(|pair| pair[1].parent_hash != pair[0].hash)
        {
            return Err("noncontiguous public headers".into());
        }
        Ok(headers)
    }
    pub fn acquire(
        &self,
        from: u64,
        to: u64,
        cancel: &CancellationToken,
    ) -> Result<(PublicHistoryPage, u64)> {
        cancel.check()?;
        if from < self.scope.deployment_block || to < from || to - from >= 256 {
            return Err("invalid public download range".into());
        }
        let _guard = loop {
            match self.store.tasks.try_lock() {
                Ok(g) => break g,
                Err(std::sync::TryLockError::WouldBlock) => {
                    cancel.check()?;
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(_) => return Err("public history lock poisoned".into()),
            }
        };
        cancel.check()?;
        let before = self.snapshot()?;
        for r in &before.coverage {
            if self.source.block(r.block.number)? != r.block {
                self.store.rewind(&self.scope, None)?;
                return Err("public canonical history changed; rebuild required".into());
            }
        }
        let mut receipts = std::collections::BTreeMap::new();
        let mut headers = vec![];
        let mut memberships = vec![];
        let mut cursor = from;
        while cursor <= to {
            if let Some(reference) = before
                .pages
                .iter()
                .find(|p| p.from_block <= cursor && p.block.number >= cursor)
            {
                let page = self.store.read(reference)?;
                for h in page
                    .headers
                    .iter()
                    .filter(|h| h.number >= cursor && h.number <= to)
                {
                    headers.push(h.clone())
                }
                memberships.extend(page.memberships.clone());
                for r in page
                    .receipts
                    .into_iter()
                    .filter(|r| r.block.number >= from && r.block.number <= to)
                {
                    receipts.insert(r.transaction_hash, r);
                }
                if page.block.number >= to {
                    break;
                }
                cursor = page.block.number + 1;
                continue;
            }
            let end = before
                .pages
                .iter()
                .filter(|p| p.from_block > cursor)
                .map(|p| p.from_block - 1)
                .min()
                .unwrap_or(to)
                .min(to);
            let downloaded_headers = self.read_headers(cursor, end, cancel)?;
            let mut page = PublicHistoryPage {
                from_block: cursor,
                block: downloaded_headers
                    .last()
                    .cloned()
                    .ok_or("empty public headers")?,
                headers: downloaded_headers,
                receipts: vec![],
                verified_positions: vec![],
                memberships: vec![],
            };
            let hashes = self
                .source
                .discover(cursor, end)?
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>();
            for hash in hashes {
                let receipt = self
                    .source
                    .receipt(hash)?
                    .ok_or("missing canonical public receipt")?;
                if receipt.transaction_hash != hash
                    || !receipt.success
                    || receipt.block.number < cursor
                    || receipt.block.number > end
                    || !page.headers.contains(&receipt.block)
                {
                    return Err("public receipt canonical binding mismatch".into());
                }
                let outputs = crate::protocol::decode_receipt_outputs_with_context(
                    crate::note::ProtocolContext {
                        chain_id: self.scope.chain_id,
                        protocol_address: crate::sdk::address_word(self.scope.protocol_address),
                    },
                    &receipt,
                )?;
                for leaf in outputs
                    .notes
                    .iter()
                    .map(|v| &v.leaf)
                    .chain(outputs.credits.iter().map(|v| &v.leaf))
                {
                    page.verified_positions.push(format!(
                        "{}:{}:{}",
                        leaf.tree_id, leaf.leaf_index, leaf.commitment
                    ));
                    let proof = self.source.membership(
                        &crate::rpc::MembershipInput {
                            tree_id: leaf.tree_id,
                            leaf_index: leaf.leaf_index,
                            commitment: leaf.commitment,
                            root: None,
                        },
                        &page.block,
                    )?;
                    if proof.block != page.block
                        || proof.tree_id != leaf.tree_id
                        || proof.leaf_index != leaf.leaf_index
                        || proof.leaf != leaf.commitment
                        || proof.path.len() != 16
                    {
                        return Err("public membership binding mismatch".into());
                    }
                    let path: [U256; 16] = proof
                        .path
                        .iter()
                        .map(|p| U256::from_be_slice(p.as_slice()))
                        .collect::<Vec<_>>()
                        .try_into()
                        .map_err(|_| "public membership depth mismatch")?;
                    let root = U256::from_be_slice(proof.root.as_slice());
                    if crate::sdk::merkle_root(
                        U256::from_be_slice(leaf.commitment.as_slice()),
                        u16::try_from(leaf.leaf_index).map_err(|_| "public leaf index overflow")?,
                        &path,
                    )? != root
                    {
                        return Err("public membership proof mismatch".into());
                    }
                    if !self
                        .source
                        .known_root(leaf.tree_id, proof.root, &page.block)?
                    {
                        return Err("public membership root is not canonical".into());
                    }
                    page.memberships.push(CachedMembership {
                        tree_id: leaf.tree_id,
                        leaf_index: leaf.leaf_index,
                        commitment: leaf.commitment,
                        block: page.block.clone(),
                        root,
                        path,
                    })
                }
                page.receipts.push(receipt)
            }
            page.receipts
                .sort_by_key(|r| (r.block.number, r.logs.first().map_or(0, |l| l.log_index)));
            if self.source.block(end)? != page.block {
                return Err("public download anchor changed".into());
            }
            self.store
                .append(&self.scope, page.clone(), before.generation)?;
            headers.extend(page.headers);
            memberships.extend(page.memberships);
            for r in page.receipts {
                receipts.insert(r.transaction_hash, r);
            }
            if end == to {
                break;
            }
            cursor = end + 1;
        }
        cancel.check()?;
        headers.sort_by_key(|h| h.number);
        headers.dedup_by_key(|h| h.number);
        let block = headers.last().cloned().ok_or("empty public page")?;
        if self.source.block(to)? != block {
            return Err("public anchor changed".into());
        }
        if self.snapshot()?.generation != before.generation {
            return Err("public history generation changed during acquisition".into());
        }
        let mut receipts = receipts.into_values().collect::<Vec<_>>();
        receipts.sort_by_key(|r| (r.block.number, r.logs.first().map_or(0, |l| l.log_index)));
        Ok((
            PublicHistoryPage {
                from_block: from,
                block,
                headers,
                receipts,
                verified_positions: vec![],
                memberships,
            },
            before.generation,
        ))
    }
}

/// Ephemeral cache identity includes the validated chain instance; no process-global account material.
pub(crate) fn ephemeral_store(
    chain: usize,
    scope: &PublicHistoryScope,
) -> Result<Arc<PublicHistoryStore>> {
    type Cache = std::collections::BTreeMap<String, std::sync::Weak<PublicHistoryStore>>;
    static STORES: std::sync::OnceLock<Mutex<Cache>> = std::sync::OnceLock::new();
    let key = format!("{chain}/{}", scope.key()?);
    let mut stores = STORES
        .get_or_init(|| Mutex::new(Cache::new()))
        .lock()
        .map_err(|_| "shared history cache lock poisoned")?;
    stores.retain(|_, s| s.strong_count() > 0);
    if let Some(store) = stores.get(&key).and_then(|s| s.upgrade()) {
        return Ok(store);
    }
    let store = Arc::new(PublicHistoryStore::new(
        Arc::new(crate::session::MemoryAtomicRecords::default()),
        Retention::default(),
    )?);
    stores.insert(key, Arc::downgrade(&store));
    Ok(store)
}

#[derive(Clone, Debug)]
pub struct PublicSyncOptions {
    pub from_block: Option<u64>,
    pub to_block: Option<u64>,
    pub page_size: u64,
}
impl Default for PublicSyncOptions {
    fn default() -> Self {
        Self {
            from_block: None,
            to_block: None,
            page_size: 100,
        }
    }
}
impl PublicHistory {
    pub fn sync(
        &self,
        options: PublicSyncOptions,
        cancel: &CancellationToken,
    ) -> Result<PublicHistorySnapshot> {
        self.sync_with_progress(options, cancel, |_| Ok(()))
    }
    pub fn sync_with_progress(
        &self,
        options: PublicSyncOptions,
        cancel: &CancellationToken,
        mut progress: impl FnMut(&PublicHistorySnapshot) -> Result<()>,
    ) -> Result<PublicHistorySnapshot> {
        if options.page_size == 0 || options.page_size > 256 {
            return Err("public page size must be 1..256".into());
        }
        cancel.check()?;
        self.validate_canonical()?;
        let indexed = self.source.indexed_head()?;
        let known = self.source.known_head()?;
        if self.source.block(indexed.number)? != indexed
            || self.source.block(known.number)? != known
        {
            return Err("public head canonical binding mismatch".into());
        }
        self.store.note_head(&self.scope, indexed.clone(), known)?;
        let lower = options.from_block.unwrap_or(self.scope.deployment_block);
        let target = options.to_block.unwrap_or(indexed.number);
        if lower < self.scope.deployment_block || target > indexed.number || lower > target {
            return Err("public synchronization outside indexed history".into());
        }
        loop {
            cancel.check()?;
            let state = self.snapshot()?;
            let max = state.coverage.last().map(|r| r.block.number);
            let range = if max.is_none_or(|n| n < target) {
                let start = max
                    .map_or(target.saturating_sub(options.page_size - 1), |n| {
                        n.saturating_add(1)
                    })
                    .max(lower);
                Some((
                    start,
                    start.saturating_add(options.page_size - 1).min(target),
                ))
            } else {
                highest_gap(&state.coverage, lower, target)
                    .map(|(f, t)| (f.max(t.saturating_sub(options.page_size - 1)), t))
            };
            let Some((from, to)) = range else {
                return Ok(state);
            };
            self.acquire(from, to, cancel)?;
            progress(&self.snapshot()?)?;
        }
    }
}

impl PublicHistory {
    pub fn acquire_offline(&self, from: u64, to: u64) -> Result<(PublicHistoryPage, u64)> {
        if from < self.scope.deployment_block || to < from || to - from >= 256 {
            return Err("invalid offline history range".into());
        }
        let state = self.snapshot()?;
        let mut headers = vec![];
        let mut receipts = std::collections::BTreeMap::new();
        let mut memberships = vec![];
        let mut positions = vec![];
        let mut cursor = from;
        loop {
            let page = self
                .store
                .page_at(&self.scope, cursor)?
                .ok_or("offline public payload unavailable; synchronize missing range")?;
            headers.extend(
                page.headers
                    .into_iter()
                    .filter(|h| h.number >= from && h.number <= to),
            );
            for r in page
                .receipts
                .into_iter()
                .filter(|r| r.block.number >= from && r.block.number <= to)
            {
                receipts.insert(r.transaction_hash, r);
            }
            memberships.extend(page.memberships);
            positions.extend(page.verified_positions);
            if page.block.number >= to {
                break;
            }
            cursor = page.block.number + 1;
        }
        headers.sort_by_key(|h| h.number);
        headers.dedup_by_key(|h| h.number);
        if headers.len() as u64 != to - from + 1 {
            return Err("offline public headers incomplete".into());
        }
        let block = headers
            .last()
            .cloned()
            .ok_or("offline anchor unavailable")?;
        let mut receipts = receipts.into_values().collect::<Vec<_>>();
        receipts.sort_by_key(|r| (r.block.number, r.logs.first().map_or(0, |l| l.log_index)));
        if self.snapshot()?.generation != state.generation {
            return Err("offline public generation changed".into());
        }
        Ok((
            PublicHistoryPage {
                from_block: from,
                block,
                headers,
                receipts,
                verified_positions: positions,
                memberships,
            },
            state.generation,
        ))
    }
}

#[cfg(test)]
mod parallel_header_tests {
    use super::*;
    use crate::note::ProtocolContext;
    use crate::rpc::{CanonicalTransaction, Membership, MembershipInput};
    use crate::session::{MemoryAtomicRecords, SessionSource};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Source {
        active: AtomicUsize,
        peak: AtomicUsize,
        broken: bool,
        failed: bool,
        batch: bool,
        batch_cancel: Option<CancellationToken>,
        batch_calls: AtomicUsize,
    }
    impl SessionSource for Source {
        fn context(&self) -> ProtocolContext {
            ProtocolContext {
                chain_id: 97,
                protocol_address: crate::sdk::address_word(Address::with_last_byte(1)),
            }
        }
        fn deployment_start(&self) -> u64 {
            100
        }
        fn indexed_head(&self) -> Result<CanonicalBlock> {
            self.block(115)
        }
        fn block(&self, n: u64) -> Result<CanonicalBlock> {
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(active, Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(5));
            self.active.fetch_sub(1, Ordering::SeqCst);
            if self.failed && n == 108 {
                return Err("header unavailable".into());
            }
            Ok(CanonicalBlock {
                number: n,
                hash: B256::with_last_byte(n as u8),
                parent_hash: B256::with_last_byte(if self.broken && n == 108 {
                    99
                } else {
                    (n - 1) as u8
                }),
                timestamp: n,
            })
        }
        fn blocks(&self, numbers: &[u64]) -> Option<Result<Vec<CanonicalBlock>>> {
            self.batch.then(|| {
                assert!(numbers.len() <= 256);
                self.batch_calls.fetch_add(1, Ordering::SeqCst);
                let result = numbers.iter().map(|n| self.block(*n)).collect();
                if let Some(cancel) = &self.batch_cancel {
                    cancel.cancel();
                }
                result
            })
        }
        fn discover(&self, _: u64, _: u64) -> Result<Vec<B256>> {
            Ok(vec![])
        }
        fn receipt(&self, _: B256) -> Result<Option<CanonicalReceipt>> {
            unreachable!()
        }
        fn transaction(&self, _: B256) -> Result<Option<CanonicalTransaction>> {
            unreachable!()
        }
        fn membership(&self, _: &MembershipInput, _: &CanonicalBlock) -> Result<Membership> {
            unreachable!()
        }
    }

    #[test]
    fn parallel_headers_are_bounded_ordered_and_never_commit_failed_pages() {
        for mode in [
            "ordered",
            "broken",
            "failed",
            "batch",
            "batch-broken",
            "batch-failed",
        ] {
            let source = Arc::new(Source {
                active: AtomicUsize::new(0),
                peak: AtomicUsize::new(0),
                broken: mode.ends_with("broken"),
                failed: mode.ends_with("failed"),
                batch: mode.starts_with("batch"),
                batch_cancel: None,
                batch_calls: AtomicUsize::new(0),
            });
            let history = PublicHistory::new(
                Arc::new(
                    PublicHistoryStore::new(
                        Arc::new(MemoryAtomicRecords::default()),
                        Retention::default(),
                    )
                    .unwrap(),
                ),
                PublicHistoryScope {
                    chain_id: 97,
                    protocol_address: Address::with_last_byte(1),
                    runtime_code_hash: B256::with_last_byte(42),
                    deployment_block: 100,
                },
                source.clone(),
            )
            .unwrap();
            let result = history.acquire(100, 115, &CancellationToken::default());
            if mode == "ordered" || mode == "batch" {
                let (page, _) = result.unwrap();
                let peak = source.peak.load(Ordering::SeqCst);
                if mode == "ordered" {
                    assert!((2..=8).contains(&peak), "parallel reads: {peak}");
                }
                assert_eq!(
                    page.headers.iter().map(|h| h.number).collect::<Vec<_>>(),
                    (100..=115).collect::<Vec<_>>()
                );
            } else {
                assert!(result.is_err(), "{mode} page accepted");
                let state = history.snapshot().unwrap();
                assert!(state.pages.is_empty() && state.coverage.is_empty());
            }
            assert_eq!(source.active.load(Ordering::SeqCst), 0);
        }
    }
    #[test]
    fn full_history_page_uses_one_bulk_range_request() {
        let source = Arc::new(Source {
            active: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            broken: false,
            failed: false,
            batch: true,
            batch_cancel: None,
            batch_calls: AtomicUsize::new(0),
        });
        let history = PublicHistory::new(
            Arc::new(
                PublicHistoryStore::new(
                    Arc::new(MemoryAtomicRecords::default()),
                    Retention::default(),
                )
                .unwrap(),
            ),
            PublicHistoryScope {
                chain_id: 97,
                protocol_address: Address::with_last_byte(1),
                runtime_code_hash: B256::with_last_byte(42),
                deployment_block: 100,
            },
            source.clone(),
        )
        .unwrap();
        let headers = history
            .read_headers(100, 355, &CancellationToken::default())
            .unwrap();
        assert_eq!(headers.len(), 256);
        assert_eq!(headers[0].number, 100);
        assert_eq!(headers[255].number, 355);
        assert_eq!(source.batch_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cancelled_bulk_headers_stop_after_one_chunk_and_never_commit_partial_page() {
        let token = CancellationToken::default();
        let source = Arc::new(Source {
            active: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            broken: false,
            failed: false,
            batch: true,
            batch_cancel: Some(token.clone()),
            batch_calls: AtomicUsize::new(0),
        });
        let history = PublicHistory::new(
            Arc::new(
                PublicHistoryStore::new(
                    Arc::new(MemoryAtomicRecords::default()),
                    Retention::default(),
                )
                .unwrap(),
            ),
            PublicHistoryScope {
                chain_id: 97,
                protocol_address: Address::with_last_byte(1),
                runtime_code_hash: B256::with_last_byte(42),
                deployment_block: 100,
            },
            source.clone(),
        )
        .unwrap();
        assert!(history.acquire(100, 147, &token).is_err());
        assert_eq!(source.batch_calls.load(Ordering::SeqCst), 1);
        let state = history.snapshot().unwrap();
        assert!(state.pages.is_empty() && state.coverage.is_empty());
    }
}
