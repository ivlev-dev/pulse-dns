//! Root ring, torn-копии, chain-вытеснение и чтение истории.

use std::os::unix::fs::FileExt;
use std::sync::Arc;

use pulse_zonefile::parallel::{
    OpenConfigV2, ParallelError, ParallelStore, PublishOutcome, RootEntry, RootState, StoreConfig,
};

fn config(chain: u32) -> StoreConfig {
    let mut config = StoreConfig::small(8, 8192);
    config.max_root_chain_pages = chain;
    config
}

fn create(dir: &tempfile::TempDir, config: StoreConfig) -> (std::path::PathBuf, ParallelStore) {
    let path = dir.path().join("ring.v2");
    let store = ParallelStore::create(&path, config).unwrap();
    (path, store)
}

fn publish(store: &ParallelStore, zone: u32, version: u64) -> PublishOutcome {
    let ticket = store.reserve_pages(1).unwrap();
    store
        .write_raw_page(ticket.first_page, b"root payload")
        .unwrap();
    let entry = RootEntry {
        owner_zone: zone,
        version,
        root_page: ticket.first_page,
        state: RootState::Serving,
        soa_serial: u32::try_from(version).unwrap(),
        rrset_count: 1,
        ..RootEntry::default()
    };
    for _ in 0..64 {
        match store.publish_root(entry) {
            Ok(outcome) => return outcome,
            Err(ParallelError::ReaderContended) => {}
            Err(error) => panic!("publish failed: {error:?}"),
        }
    }
    panic!("publish retry limit");
}

#[test]
fn publishes_and_selects_versions() {
    let dir = tempfile::tempdir().unwrap();
    let (_, store) = create(&dir, config(64));
    for version in 2..=9 {
        let outcome = publish(&store, 1, version);
        assert_eq!(outcome.zone, 1);
        assert_eq!(outcome.version, version);
        let selected = store.select_root(1, u64::MAX).unwrap();
        assert_eq!(selected.version, version);
    }
    assert_eq!(store.select_root(1, 6).unwrap().version, 6);
    assert_eq!(store.select_root(1, 7).unwrap().version, 7);
    assert!(matches!(
        store.select_root(2, u64::MAX),
        Err(ParallelError::NoZoneVersion { zone: 2 })
    ));
    assert!(store.fsck_lite().unwrap().ok);
}

#[test]
fn concurrent_publish_per_zone_and_reader_sees_valid_versions() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(create(&dir, config(64)).1);
    let zones: Vec<u32> = (1..=6).collect();
    let per_zone = 40_u64;
    let reader_store = Arc::clone(&store);
    let reader = std::thread::spawn(move || {
        let reader = reader_store.reader().unwrap();
        let mut seen = 0_u32;
        for iteration in 0..2_000_u32 {
            let zone = (iteration % 6) + 1;
            match reader_store.zone_snapshot(&reader, zone) {
                Ok(snapshot) => {
                    assert!(snapshot.version() >= 2);
                    assert_eq!(snapshot.zone(), zone);
                    seen += 1;
                }
                Err(ParallelError::ReaderContended | ParallelError::NoZoneVersion { .. }) => {}
                Err(error) => panic!("snapshot failed: {error:?}"),
            }
        }
        assert!(seen > 0, "читатель не получил ни одного снапшота");
    });

    std::thread::scope(|scope| {
        for zone in zones {
            let store = Arc::clone(&store);
            scope.spawn(move || {
                for version in 2..=per_zone + 1 {
                    publish(&store, zone, version);
                }
            });
        }
    });
    reader.join().unwrap();

    for zone in 1..=6 {
        assert_eq!(
            store.select_root(zone, u64::MAX).unwrap().version,
            per_zone + 1
        );
    }
    let report = store.fsck_lite().unwrap();
    assert!(report.ok, "fsck issues: {:?}", report.issues);
    assert_eq!(report.zones, 6);
}

#[test]
fn torn_copy_falls_back_to_healthy_copy() {
    let dir = tempfile::tempdir().unwrap();
    let (path, store) = create(&dir, config(64));
    publish(&store, 1, 2);
    publish(&store, 1, 3);
    let geometry = store.geometry();
    let slot = geometry.zone_slot(1).unwrap();
    drop(store);

    let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    let cell = slot.cell_offset(3);
    let offset = u64::from(slot.page_a) * u64::from(geometry.page_size()) + cell as u64;
    file.write_all_at(&[0xAA_u8; 64], offset).unwrap();
    file.sync_all().unwrap();
    drop(file);

    let reopened = ParallelStore::open(&path, OpenConfigV2::default()).unwrap();
    assert_eq!(reopened.select_root(1, u64::MAX).unwrap().version, 3);
    assert!(
        reopened.recovery_report().torn_root_copies > 0,
        "torn-копия должна быть обнаружена"
    );
}

#[test]
fn both_copies_torn_roll_back_at_most_one_version() {
    let dir = tempfile::tempdir().unwrap();
    let (path, store) = create(&dir, config(64));
    publish(&store, 1, 2);
    publish(&store, 1, 3);
    let geometry = store.geometry();
    let slot = geometry.zone_slot(1).unwrap();
    drop(store);

    let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    let cell = slot.cell_offset(3);
    for page in [slot.page_a, slot.page_b] {
        let offset = u64::from(page) * u64::from(geometry.page_size()) + cell as u64;
        file.write_all_at(&[0x5A_u8; 64], offset).unwrap();
    }
    file.sync_all().unwrap();
    drop(file);

    let reopened = ParallelStore::open(&path, OpenConfigV2::default()).unwrap();
    assert_eq!(reopened.select_root(1, u64::MAX).unwrap().version, 2);
    assert!(reopened.fsck_lite().unwrap().ok);
}

#[test]
fn pinned_version_is_evicted_to_chain_and_history_is_readable() {
    let dir = tempfile::tempdir().unwrap();
    let (_, store) = create(&dir, config(64));
    publish(&store, 1, 2);
    let reader = store.reader().unwrap();
    let snapshot = store.zone_snapshot(&reader, 1).unwrap();
    assert_eq!(snapshot.version(), 2);

    publish(&store, 1, 3);
    publish(&store, 1, 4);
    publish(&store, 1, 5);
    let outcome = publish(&store, 1, 6);
    assert!(outcome.evicted_page.is_some(), "v2 должен уйти в chain");
    assert_eq!(store.stats().chain_evictions, 1);

    assert_eq!(store.select_root(1, 2).unwrap().version, 2);
    assert_eq!(store.select_root(1, 4).unwrap().version, 4);
    assert_eq!(store.select_root(1, 5).unwrap().version, 5);
    assert_eq!(store.select_root(1, 6).unwrap().version, 6);
    let report = store.fsck_lite().unwrap();
    assert!(report.ok, "{:?}", report.issues);
    assert!(report.chain_pages >= 1);
    assert_eq!(report.chain_max_depth, 1);
}

#[test]
fn unpinned_ring_slot_is_overwritten_without_chain() {
    let dir = tempfile::tempdir().unwrap();
    let (_, store) = create(&dir, config(64));
    publish(&store, 1, 2);
    let reader = store.reader().unwrap();
    {
        let snapshot = store.zone_snapshot(&reader, 1).unwrap();
        assert_eq!(snapshot.version(), 2);
        publish(&store, 1, 6);
        assert_eq!(store.stats().chain_evictions, 1);
    }
    assert_eq!(store.gc_pass().unwrap(), 1);
    assert_eq!(store.min_pinned(1), u64::MAX);
    let outcome = publish(&store, 1, 10);
    assert!(outcome.evicted_page.is_none(), "пин снят — chain не нужен");
    assert_eq!(store.stats().chain_evictions, 1);
}

#[test]
fn chain_limit_stalls_only_that_zone() {
    let dir = tempfile::tempdir().unwrap();
    let (_, store) = create(&dir, config(4));
    publish(&store, 1, 2);
    let reader = store.reader().unwrap();
    let snapshot = store.zone_snapshot(&reader, 1).unwrap();
    assert_eq!(snapshot.version(), 2);

    for version in 3..=9 {
        publish(&store, 1, version);
    }
    let error = {
        let ticket = store.reserve_pages(1).unwrap();
        store.write_raw_page(ticket.first_page, b"x").unwrap();
        store
            .publish_root(RootEntry {
                owner_zone: 1,
                version: 10,
                root_page: ticket.first_page,
                state: RootState::Serving,
                ..RootEntry::default()
            })
            .unwrap_err()
    };
    assert!(matches!(
        error,
        ParallelError::ZoneWriterStalled { zone: 1 }
    ));
    // Другая зона продолжает писаться.
    publish(&store, 2, 2);
    assert_eq!(store.select_root(2, u64::MAX).unwrap().version, 2);
    drop(snapshot);
}

#[test]
fn torn_chain_page_yields_stale_root_without_panic() {
    let dir = tempfile::tempdir().unwrap();
    let (path, store) = create(&dir, config(64));
    publish(&store, 1, 2);
    let reader = store.reader().unwrap();
    let snapshot = store.zone_snapshot(&reader, 1).unwrap();
    publish(&store, 1, 3);
    publish(&store, 1, 4);
    publish(&store, 1, 5);
    let outcome = publish(&store, 1, 6);
    let chain_page = outcome.evicted_page.unwrap();
    let geometry = store.geometry();
    assert_eq!(store.select_root(1, 2).unwrap().version, 2);
    drop(snapshot);
    drop(reader);
    drop(store);

    let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    let offset = u64::from(chain_page) * u64::from(geometry.page_size());
    file.write_all_at(&[0xFF_u8; 4096], offset).unwrap();
    file.sync_all().unwrap();
    drop(file);

    let reopened = ParallelStore::open(&path, OpenConfigV2::default()).unwrap();
    assert_eq!(reopened.select_root(1, 6).unwrap().version, 6);
    assert!(matches!(
        reopened.select_root(1, 2),
        Err(ParallelError::StaleRoot { zone: 1, .. })
    ));
}

#[test]
fn tombstone_maps_to_no_zone_version() {
    let dir = tempfile::tempdir().unwrap();
    let (_, store) = create(&dir, config(64));
    publish(&store, 1, 2);
    let ticket = store.reserve_pages(1).unwrap();
    store.write_raw_page(ticket.first_page, b"x").unwrap();
    store
        .publish_root(RootEntry {
            owner_zone: 1,
            version: 3,
            root_page: 0,
            state: RootState::Tombstone,
            deleted_txn: 3,
            ..RootEntry::default()
        })
        .unwrap();
    let selected = store.select_root(1, u64::MAX).unwrap();
    assert!(selected.is_tombstone());
    let reader = store.reader().unwrap();
    assert!(matches!(
        store.zone_snapshot(&reader, 1),
        Err(ParallelError::NoZoneVersion { zone: 1 })
    ));
}

#[test]
fn version_regression_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (_, store) = create(&dir, config(64));
    publish(&store, 1, 5);
    let ticket = store.reserve_pages(1).unwrap();
    store.write_raw_page(ticket.first_page, b"x").unwrap();
    let error = store
        .publish_root(RootEntry {
            owner_zone: 1,
            version: 5,
            root_page: ticket.first_page,
            state: RootState::Serving,
            ..RootEntry::default()
        })
        .unwrap_err();
    assert!(matches!(
        error,
        ParallelError::InvalidArgument { field: "version" }
    ));
    assert_eq!(store.select_root(1, u64::MAX).unwrap().version, 5);
}
