use super::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};
use std::time::{Duration, Instant};

pub(super) fn map_preparation<T: Send, F: Fn(usize) -> Result<T> + Sync>(
    count: usize,
    work: F,
) -> Result<Vec<T>> {
    if count <= 1 {
        return (0..count).map(work).collect();
    }
    let next = AtomicUsize::new(0);
    let mut indexed = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for _ in 0..count.min(4) {
            let next = &next;
            let work = &work;
            handles.push(scope.spawn(move || {
                let mut values = Vec::new();
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= count {
                        break;
                    }
                    values.push((i, work(i)));
                }
                values
            }));
        }
        let mut values = Vec::new();
        let mut panicked = false;
        for handle in handles {
            match handle.join() {
                Ok(v) => values.extend(v),
                Err(_) => panicked = true,
            }
        }
        if panicked {
            Err("preparation worker panicked".to_owned())
        } else {
            Ok(values)
        }
    })?;
    indexed.sort_by_key(|(i, _)| *i);
    indexed.into_iter().map(|(_, v)| v).collect()
}
#[derive(Clone)]
enum ReadValue {
    Boolean(bool),
    Amounts(U256, U256),
    Allocation(u64, u16),
}
pub(crate) struct PreparationChain {
    upstream: Arc<dyn ChainState>,
    born: Instant,
    entries: Mutex<BTreeMap<String, Arc<Mutex<Option<ReadValue>>>>>,
}
impl PreparationChain {
    pub(super) fn new(upstream: Arc<dyn ChainState>) -> Self {
        Self {
            upstream,
            born: Instant::now(),
            entries: Mutex::new(BTreeMap::new()),
        }
    }
    pub(super) fn for_quote(self: &Arc<Self>, chain: Arc<dyn ChainState>) -> Arc<dyn ChainState> {
        if self.matches(&chain) {
            self.clone()
        } else {
            chain
        }
    }
    pub(super) fn matches(&self, chain: &Arc<dyn ChainState>) -> bool {
        Arc::ptr_eq(&self.upstream, chain) && self.born.elapsed() < Duration::from_secs(30)
    }
    fn read(&self, key: String, load: impl FnOnce() -> Result<ReadValue>) -> Result<ReadValue> {
        if self.born.elapsed() >= Duration::from_secs(30) {
            self.entries
                .lock()
                .map_err(|_| "preparation read lock poisoned")?
                .clear();
            return load();
        }
        let key = format!("{:?}:{key}", self.upstream.context());
        let entry = {
            let mut entries = self
                .entries
                .lock()
                .map_err(|_| "preparation read lock poisoned")?;
            if let Some(entry) = entries.get(&key) {
                Some(entry.clone())
            } else if entries.len() < 1024 {
                let entry = Arc::new(Mutex::new(None));
                entries.insert(key.clone(), entry.clone());
                Some(entry)
            } else {
                None
            }
        };
        let Some(entry) = entry else {
            return load();
        };
        let mut value = entry.lock().map_err(|_| "preparation read lock poisoned")?;
        if let Some(value) = value.as_ref() {
            return Ok(value.clone());
        }
        match load() {
            Ok(result) => {
                *value = Some(result.clone());
                Ok(result)
            }
            Err(err) => {
                let mut entries = self
                    .entries
                    .lock()
                    .map_err(|_| "preparation read lock poisoned")?;
                if entries.get(&key).is_some_and(|e| Arc::ptr_eq(e, &entry)) {
                    entries.remove(&key);
                }
                Err(err)
            }
        }
    }
    fn boolean(&self, key: String, load: impl FnOnce() -> Result<bool>) -> Result<bool> {
        match self.read(key, || load().map(ReadValue::Boolean))? {
            ReadValue::Boolean(v) => Ok(v),
            _ => Err("preparation read type mismatch".into()),
        }
    }
}
impl ChainState for PreparationChain {
    fn context(&self) -> ProtocolContext {
        self.upstream.context()
    }
    fn snapshot(&self) -> Result<CanonicalBlock> {
        self.upstream.snapshot()
    }
    fn canonical(&self, b: &CanonicalBlock) -> Result<()> {
        self.upstream.canonical(b)
    }
    fn finality(&self) -> crate::rpc::ChainFinality {
        self.upstream.finality()
    }
    fn transaction_confirmation(&self, h: B256) -> Result<crate::rpc::TransactionConfirmation> {
        self.upstream.transaction_confirmation(h)
    }
    fn known_root(&self, t: u64, r: B256, b: &CanonicalBlock) -> Result<bool> {
        self.boolean(format!("root:{t}:{r}:{b:?}"), || {
            self.upstream.known_root(t, r, b)
        })
    }
    fn nullifier_spent(&self, n: B256, b: &CanonicalBlock) -> Result<bool> {
        self.boolean(format!("spent:{n}:{b:?}"), || {
            self.upstream.nullifier_spent(n, b)
        })
    }
    fn credit_revoked(
        &self,
        o: Address,
        t: Address,
        s: u64,
        l: u16,
        b: &CanonicalBlock,
    ) -> Result<bool> {
        self.boolean(format!("revoked:{o}:{t}:{s}:{l}:{b:?}"), || {
            self.upstream.credit_revoked(o, t, s, l, b)
        })
    }
    fn token_balance_allowance(
        &self,
        o: Address,
        t: Address,
        b: &CanonicalBlock,
    ) -> Result<(U256, U256)> {
        match self.read(format!("token:{o}:{t}:{b:?}"), || {
            self.upstream
                .token_balance_allowance(o, t, b)
                .map(|(a, b)| ReadValue::Amounts(a, b))
        })? {
            ReadValue::Amounts(a, b) => Ok((a, b)),
            _ => Err("preparation read type mismatch".into()),
        }
    }
    fn credit_allocation(&self, o: Address, t: Address, b: &CanonicalBlock) -> Result<(u64, u16)> {
        match self.read(format!("allocation:{o}:{t}:{b:?}"), || {
            self.upstream
                .credit_allocation(o, t, b)
                .map(|(a, b)| ReadValue::Allocation(a, b))
        })? {
            ReadValue::Allocation(a, b) => Ok((a, b)),
            _ => Err("preparation read type mismatch".into()),
        }
    }
    fn funding_nonce(&self, o: Address, b: &CanonicalBlock) -> Result<U256> {
        self.upstream.funding_nonce(o, b)
    }
    fn public_signature_valid(
        &self,
        o: Address,
        d: B256,
        s: &[u8],
        b: &CanonicalBlock,
    ) -> Result<bool> {
        self.upstream.public_signature_valid(o, d, s, b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk::test_support::note_fixture;
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[test]
    fn workers_are_bounded_and_keep_statement_order() {
        let active = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let values = map_preparation(10, |i| {
            let n = active.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(n, Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis((10 - i) as u64));
            active.fetch_sub(1, Ordering::SeqCst);
            Ok(i * 2)
        })
        .unwrap();
        assert_eq!(values, (0..10).map(|i| i * 2).collect::<Vec<_>>());
        assert!((2..=4).contains(&peak.load(Ordering::SeqCst)));
    }
    #[test]
    fn reads_reuse_success_but_not_errors_or_new_blocks() {
        let (chain, _, _, _) = note_fixture();
        let reads = PreparationChain::new(chain);
        let calls = AtomicUsize::new(0);
        for _ in 0..2 {
            assert!(matches!(
                reads
                    .read("root".into(), || {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Ok(ReadValue::Boolean(true))
                    })
                    .unwrap(),
                ReadValue::Boolean(true)
            ));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(reads
            .read("failed".into(), || Err("offline".into()))
            .is_err());
        assert!(reads
            .read("failed".into(), || Ok(ReadValue::Boolean(true)))
            .is_ok());
        for i in 0..1100 {
            reads
                .read(format!("key:{i}"), || Ok(ReadValue::Boolean(true)))
                .unwrap();
        }
        assert!(reads.entries.lock().unwrap().len() <= 1024);
    }
    #[test]
    fn independent_public_reads_overlap() {
        let (chain, _, _, _) = note_fixture();
        let reads = PreparationChain::new(chain);
        let active = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        map_preparation(10, |i| {
            reads.read(i.to_string(), || {
                let n = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(n, Ordering::SeqCst);
                std::thread::sleep(std::time::Duration::from_millis(5));
                active.fetch_sub(1, Ordering::SeqCst);
                Ok(ReadValue::Boolean(true))
            })
        })
        .unwrap();
        assert!((2..=4).contains(&peak.load(Ordering::SeqCst)));
    }
    #[test]
    fn block_identity_expiry_and_live_checks_fence_reused_reads() {
        let (chain, _, _, _) = note_fixture();
        let mut reads = PreparationChain::new(chain.clone());
        let original = chain.snapshot().unwrap();
        let n = B256::repeat_byte(23);
        assert!(!reads.nullifier_spent(n, &original).unwrap());
        chain.spent.lock().unwrap().insert(n);
        assert!(!reads.nullifier_spent(n, &original).unwrap());
        let mut next = original.clone();
        next.hash = B256::repeat_byte(24);
        assert!(reads.nullifier_spent(n, &next).unwrap());
        reads.born = Instant::now() - Duration::from_secs(31);
        assert!(reads.nullifier_spent(n, &original).unwrap());
        *chain.block.lock().unwrap() = next.clone();
        assert!(reads.canonical(&original).is_err());
        assert_eq!(reads.snapshot().unwrap(), next);
        let reads = Arc::new(PreparationChain::new(chain));
        let (foreign, _, _, _) = note_fixture();
        let foreign: Arc<dyn ChainState> = foreign;
        assert!(Arc::ptr_eq(&reads.for_quote(foreign.clone()), &foreign));
    }
    #[test]
    fn concurrent_identical_public_reads_are_deduplicated() {
        let (chain, _, _, _) = note_fixture();
        let reads = PreparationChain::new(chain);
        let calls = AtomicUsize::new(0);
        map_preparation(10, |_| {
            reads.read("one".into(), || {
                calls.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(5));
                Ok(ReadValue::Boolean(true))
            })
        })
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
