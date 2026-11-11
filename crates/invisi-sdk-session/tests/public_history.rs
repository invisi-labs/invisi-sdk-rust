use alloy_primitives::{Address, B256};
use invisi_sdk_session::rpc::CanonicalBlock;
use invisi_sdk_session::{public_history::*, session::MemoryAtomicRecords};
use std::sync::Arc;
fn block(n: u64) -> CanonicalBlock {
    CanonicalBlock {
        number: n,
        hash: B256::with_last_byte((n + 1) as u8),
        parent_hash: B256::with_last_byte(n as u8),
        timestamp: n,
    }
}
fn scope() -> PublicHistoryScope {
    PublicHistoryScope {
        chain_id: 1,
        protocol_address: Address::with_last_byte(1),
        runtime_code_hash: B256::with_last_byte(2),
        deployment_block: 0,
    }
}
fn page(n: u64) -> PublicHistoryPage {
    PublicHistoryPage {
        from_block: n,
        block: block(n),
        headers: vec![block(n)],
        receipts: vec![],
        verified_positions: vec![],
        memberships: vec![],
    }
}
#[test]
fn coverage_survives_eviction_and_reverse_backfill_retains_head() {
    let store = PublicHistoryStore::new(
        Arc::new(MemoryAtomicRecords::default()),
        Retention {
            max_pages: 1,
            ..Default::default()
        },
    )
    .unwrap();
    store.append(&scope(), page(2), 1).unwrap();
    store.append(&scope(), page(0), 1).unwrap();
    store.append(&scope(), page(1), 1).unwrap();
    let state = store.snapshot(&scope()).unwrap();
    assert_eq!(state.pages.len(), 1);
    assert_eq!(state.pages[0].from_block, 2);
    assert_eq!(state.coverage.len(), 1);
    assert_eq!(state.through.unwrap().number, 2);
    assert!(store.page_at(&scope(), 0).unwrap().is_none());
}
#[test]
fn rewind_fences_stale_downloads_and_truncates_coverage() {
    let store = PublicHistoryStore::new(
        Arc::new(MemoryAtomicRecords::default()),
        Retention::default(),
    )
    .unwrap();
    store.append(&scope(), page(0), 1).unwrap();
    store.append(&scope(), page(1), 1).unwrap();
    store.rewind(&scope(), Some(block(0))).unwrap();
    assert!(store.append(&scope(), page(2), 1).is_err());
    let state = store.snapshot(&scope()).unwrap();
    assert_eq!(state.generation, 2);
    assert_eq!(state.through.unwrap().number, 0);
}
#[test]
fn highest_gap_does_not_confuse_maximum_with_prefix() {
    let ranges = merge_coverage(
        &[],
        CoverageRange {
            from_block: 8,
            block: block(10),
        },
    )
    .unwrap();
    assert_eq!(highest_gap(&ranges, 0, 10), Some((0, 7)));
    let ranges = merge_coverage(
        &ranges,
        CoverageRange {
            from_block: 0,
            block: block(2),
        },
    )
    .unwrap();
    assert_eq!(highest_gap(&ranges, 0, 10), Some((3, 7)));
}
#[test]
fn eviction_physically_deletes_rows_and_generation_failure_cannot_orphan_payload() {
    use invisi_sdk_session::session::AtomicRecords;
    let records = Arc::new(MemoryAtomicRecords::default());
    let store = PublicHistoryStore::new(
        records.clone(),
        Retention {
            max_pages: 1,
            ..Default::default()
        },
    )
    .unwrap();
    store.append(&scope(), page(2), 1).unwrap();
    store.append(&scope(), page(0), 1).unwrap();
    assert_eq!(
        records
            .list(&scope().key().unwrap(), None, 100)
            .unwrap()
            .len(),
        2
    );
    assert!(store.append(&scope(), page(1), 3).is_err());
    assert_eq!(
        records
            .list(&scope().key().unwrap(), None, 100)
            .unwrap()
            .len(),
        2
    );
}
