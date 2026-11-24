//! In-process пины: seqlock-слоты, `MP`/`RV`, `EpochGuard` RAII, freeze,
//! overflow и деградация.

use std::sync::atomic::{AtomicU32, Ordering};

use pulse_zonefile::parallel::{
    EpochGuard, ParallelError, ParallelStore, RootEntry, RootState, StoreConfig,
};

fn create() -> (tempfile::TempDir, ParallelStore) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pins.v2");
    let store = ParallelStore::create(&path, StoreConfig::small(8, 4096)).unwrap();
    (dir, store)
}

fn publish(store: &ParallelStore, zone: u32, version: u64) {
    let entry = RootEntry {
        owner_zone: zone,
        version,
        root_page: 0,
        state: RootState::Serving,
        soa_serial: u32::try_from(version).unwrap(),
        ..RootEntry::default()
    };
    for _ in 0..32 {
        match store.publish_root(entry) {
            Ok(_) => return,
            Err(ParallelError::ReaderContended) => {}
            Err(error) => panic!("publish failed: {error:?}"),
        }
    }
    panic!("publish retry limit");
}

#[test]
fn snapshot_pin_updates_mp_and_rv() {
    let (_dir, store) = create();
    for version in 2..=5 {
        publish(&store, 1, version);
    }
    let reader = store.reader().unwrap();
    let snapshot = store.zone_snapshot(&reader, 1).unwrap();
    assert_eq!(snapshot.version(), 5);
    assert_eq!(store.min_pinned(1), 5);
    assert_eq!(snapshot.pinned_version(), 5);
    assert_eq!(store.reclaim_version(1), 4);

    // Публикация не блокируется пином и не понижает RV.
    publish(&store, 1, 6);
    assert_eq!(store.reclaim_version(1), 5);
    drop(snapshot);

    assert!(store.gc_pass().unwrap() >= 1);
    assert_eq!(store.min_pinned(1), u64::MAX);
    assert_eq!(store.reclaim_version(1), 5);
}

#[test]
fn oldest_reader_is_min_over_slots() {
    let (_dir, store) = create();
    for version in 2..=6 {
        publish(&store, 1, version);
    }
    let reader_a = store.reader().unwrap();
    let reader_b = store.reader().unwrap();
    let snapshot_a = store.zone_snapshot(&reader_a, 1).unwrap();
    let snapshot_b = store.zone_snapshot(&reader_b, 1).unwrap();
    assert_eq!(snapshot_a.version(), 6);
    assert_eq!(snapshot_b.version(), 6);
    assert_eq!(snapshot_a.pinned_version(), 6);
    assert!(!snapshot_a.is_overflow_pin());
    assert!(reader_a.slot() < 1024);
    drop(snapshot_a);
    drop(snapshot_b);
    assert_eq!(store.gc_pass().unwrap(), 1);
}

#[test]
fn six_pins_then_epoch_overflow() {
    let (_dir, store) = create();
    publish(&store, 1, 2);
    let reader = store.reader().unwrap();
    let mut snapshots = Vec::new();
    for _ in 0..6 {
        snapshots.push(store.zone_snapshot(&reader, 1).unwrap());
    }
    assert_eq!(store.stats().reader_pin_overflow, 0);
    let overflow = store.zone_snapshot(&reader, 1).unwrap();
    assert!(overflow.is_overflow_pin());
    assert!(store.stats().reader_pin_overflow >= 1);
    // EPOCH-пин удерживает всё ≤ version.
    assert_eq!(store.min_pinned(1), 2);
    drop(overflow);
    drop(snapshots);
    assert!(store.gc_pass().unwrap() >= 1);
    assert_eq!(store.min_pinned(1), u64::MAX);
}

#[test]
fn epoch_guard_restores_parity_on_panic() {
    let guard = AtomicU32::new(0);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _epoch = EpochGuard::enter(&guard);
        assert_eq!(guard.load(Ordering::Acquire), 1);
        panic!("writer abort");
    }));
    assert!(result.is_err());
    assert_eq!(guard.load(Ordering::Acquire), 2);
    assert!(guard.load(Ordering::Acquire).is_multiple_of(2));

    {
        let _epoch = EpochGuard::enter(&guard);
        assert_eq!(guard.load(Ordering::Acquire), 3);
    }
    assert_eq!(guard.load(Ordering::Acquire), 4);
}

#[test]
fn freeze_holds_retention_without_blocking_writes() {
    let (_dir, store) = create();
    for version in 2..=6 {
        publish(&store, 1, version);
    }
    let freeze = store.freeze().unwrap();
    assert_eq!(freeze.epoch(), 6);
    assert_eq!(store.freeze_epoch(), 6);
    assert_eq!(store.reclaim_version(1), 5);
    publish(&store, 1, 7);
    publish(&store, 1, 8);
    assert_eq!(store.reclaim_version(1), 6);
    assert!(matches!(store.freeze(), Err(ParallelError::Busy)));
    drop(freeze);
    assert_eq!(store.freeze_epoch(), 0);
    assert_eq!(store.reclaim_version(1), 7);
}

#[test]
fn snapshot_drop_unpins_even_with_nested_snapshots() {
    let (_dir, store) = create();
    for version in 2..=5 {
        publish(&store, 1, version);
    }
    let reader = store.reader().unwrap();
    let outer = store.zone_snapshot(&reader, 1).unwrap();
    let inner = store.zone_snapshot(&reader, 1).unwrap();
    drop(inner);
    assert_eq!(store.gc_pass().unwrap(), 1);
    assert_eq!(store.min_pinned(1), 5);
    drop(outer);
    assert_eq!(store.gc_pass().unwrap(), 1);
    assert_eq!(store.min_pinned(1), u64::MAX);
}
