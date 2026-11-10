#![cfg(feature = "sqlite")]
use invisi_sdk_session::session::{sqlite::SQLiteRecords, AtomicRecords, EncryptedRecord};
use std::sync::{Arc, Barrier};
#[test]
fn sqlite_competing_instances_compare_and_swap_atomically() {
    let path =
        std::env::temp_dir().join(format!("invisi-sdk-store-{}.sqlite", uuid::Uuid::new_v4()));
    let a = Arc::new(SQLiteRecords::open(&path).unwrap());
    let b = Arc::new(SQLiteRecords::open(&path).unwrap());
    assert!(a.read("alice").unwrap().is_none());
    let barrier = Arc::new(Barrier::new(2));
    let jobs: [_; 2] = [a.clone(), b.clone()].map(|store| {
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            store
                .compare_and_swap(
                    "alice",
                    0,
                    &EncryptedRecord {
                        revision: 1,
                        data: vec![1, 2, 3],
                    },
                )
                .unwrap()
        })
    });
    let successes = jobs
        .into_iter()
        .map(|j| usize::from(j.join().unwrap()))
        .sum::<usize>();
    assert_eq!(successes, 1);
    assert_eq!(a.read("alice").unwrap().unwrap().revision, 1);
    assert!(a.read("bob").unwrap().is_none());
    assert!(!b
        .compare_and_swap(
            "alice",
            0,
            &EncryptedRecord {
                revision: 1,
                data: vec![9]
            }
        )
        .unwrap());
    assert!(b
        .compare_and_swap(
            "alice",
            1,
            &EncryptedRecord {
                revision: 2,
                data: vec![4]
            }
        )
        .unwrap());
    assert!(a
        .compare_and_swap(
            "alice",
            2,
            &EncryptedRecord {
                revision: 4,
                data: vec![8]
            }
        )
        .is_err());
    drop(a);
    drop(b);
    let reopened = SQLiteRecords::open(&path).unwrap();
    assert_eq!(reopened.read("alice").unwrap().unwrap().data, vec![4]);
    drop(reopened);
    let _ = std::fs::remove_file(path);
}
