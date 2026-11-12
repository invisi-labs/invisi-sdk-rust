use super::*;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
struct Entry {
    digest: [u8; 32],
    revision: u64,
    plain: Zeroizing<Vec<u8>>,
    weight: usize,
}
#[derive(Default)]
struct Cache {
    entries: BTreeMap<String, Entry>,
    order: VecDeque<String>,
    bytes: usize,
}
#[derive(Default)]
pub(super) struct DecodedRecords(Mutex<Cache>);
impl DecodedRecords {
    pub(super) fn open(
        &self,
        key: &str,
        record: &EncryptedRecord,
        decode: impl FnOnce() -> Result<Zeroizing<Vec<u8>>>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let digest: [u8; 32] = Sha256::digest(&record.data).into();
        let mut cache = self.0.lock().map_err(|_| "decoded record cache poisoned")?;
        if let Some(entry) = cache.entries.get(key) {
            if entry.revision == record.revision && entry.digest == digest {
                let result = Zeroizing::new(entry.plain.to_vec());
                if let Some(i) = cache.order.iter().position(|k| k == key) {
                    cache.order.remove(i);
                }
                cache.order.push_back(key.into());
                return Ok(result);
            }
        }
        if let Some(old) = cache.entries.remove(key) {
            cache.bytes -= old.weight;
            if let Some(i) = cache.order.iter().position(|k| k == key) {
                cache.order.remove(i);
            }
        }
        let plain = decode()?;
        let weight = record.data.len().max(plain.len());
        if weight > 8 << 20 {
            return Ok(plain);
        }
        while cache.entries.len() >= 512 || cache.bytes + weight > 8 << 20 {
            let oldest = cache
                .order
                .pop_front()
                .ok_or("decoded record cache accounting failed")?;
            if let Some(old) = cache.entries.remove(&oldest) {
                cache.bytes -= old.weight;
            }
        }
        cache.entries.insert(
            key.into(),
            Entry {
                digest,
                revision: record.revision,
                plain: Zeroizing::new(plain.to_vec()),
                weight,
            },
        );
        cache.order.push_back(key.into());
        cache.bytes += weight;
        Ok(plain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[test]
    fn cached_plaintext_is_detached_bounded_and_bound_to_all_authenticated_bytes() {
        let cache = DecodedRecords::default();
        let calls = AtomicUsize::new(0);
        let record = EncryptedRecord {
            revision: 1,
            data: vec![1; 40],
        };
        let load = || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(Zeroizing::new(vec![7; 20]))
        };
        let mut first = cache.open("scope/row", &record, load).unwrap();
        first[0] = 99;
        assert_eq!(cache.open("scope/row", &record, load).unwrap()[0], 7);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let mut changed = record.clone();
        changed.data[12] ^= 1;
        assert!(cache
            .open(
                "scope/row",
                &changed,
                || Err("authentication failed".into())
            )
            .is_err());
        cache.open("other-scope/row", &record, load).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        changed = record.clone();
        changed.revision = 2;
        cache.open("scope/row", &changed, load).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        for i in 0..600 {
            cache.open(&i.to_string(), &record, load).unwrap();
        }
        let data = cache.0.lock().unwrap();
        assert!(data.entries.len() <= 512);
        assert!(data.bytes <= 8 << 20);
    }
}
