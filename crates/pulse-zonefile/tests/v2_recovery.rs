//! Recovery/fsck-lite: torn-копии, DP/DT, регрессии, file-fatal и read-only.

use std::os::unix::fs::FileExt;

use pulse_zonefile::parallel::{
    AllocRecord, FatalKind, Geometry, OpenConfigV2, ParallelError, ParallelStore, RootEntry,
    RootState, StoreConfig, open_read_only,
};

fn create(dir: &tempfile::TempDir) -> (std::path::PathBuf, ParallelStore) {
    let path = dir.path().join("recovery.v2");
    let store = ParallelStore::create(&path, StoreConfig::small(8, 8192)).unwrap();
    (path, store)
}

fn publish(store: &ParallelStore, zone: u32, version: u64) -> u32 {
    let ticket = store.reserve_pages(1).unwrap();
    store
        .write_raw_page(ticket.first_page, b"recovery payload")
        .unwrap();
    let entry = RootEntry {
        owner_zone: zone,
        version,
        root_page: ticket.first_page,
        state: RootState::Serving,
        soa_serial: u32::try_from(version).unwrap(),
        ..RootEntry::default()
    };
    for _ in 0..64 {
        match store.publish_root(entry) {
            Ok(_) => {
                return store
                    .select_root(zone, u64::MAX)
                    .unwrap()
                    .page_limit_at_commit;
            }
            Err(ParallelError::ReaderContended) => {}
            Err(error) => panic!("publish failed: {error:?}"),
        }
    }
    panic!("publish retry limit");
}

fn write_bytes(path: &std::path::Path, offset: u64, data: &[u8]) {
    let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    file.write_all_at(data, offset).unwrap();
    file.sync_all().unwrap();
}

fn slot_offset(geometry: Geometry, zone: u32, version: u64, page_a: bool) -> u64 {
    let slot = geometry.zone_slot(zone).unwrap();
    let page = if page_a { slot.page_a } else { slot.page_b };
    u64::from(page) * u64::from(geometry.page_size()) + slot.cell_offset(version) as u64
}

#[test]
fn reopen_restores_watermarks_and_heads() {
    let dir = tempfile::tempdir().unwrap();
    let (path, store) = create(&dir);
    for version in 2..=5 {
        publish(&store, 1, version);
    }
    publish(&store, 2, 2);
    publish(&store, 2, 3);
    let dp = store.sync().unwrap().0;
    let previous_cursor = store.allocator().cursor();
    drop(store);

    let reopened = ParallelStore::open(&path, OpenConfigV2::default()).unwrap();
    assert_eq!(reopened.durable_page_limit(), dp);
    assert_eq!(reopened.allocator().cursor(), dp);
    assert!(reopened.allocator().cursor() >= previous_cursor);
    assert_eq!(reopened.select_root(1, u64::MAX).unwrap().version, 5);
    assert_eq!(reopened.select_root(2, u64::MAX).unwrap().version, 3);
    assert!(reopened.durable_txn_limit() >= 5);
    assert!(reopened.published_txn() >= 5);
    let report = reopened.recovery_report();
    assert!(!report.torn_layout);
    assert!(!report.torn_alloc);
    assert_eq!(report.zones_with_roots, 2);
    assert!(report.fatal.is_none());
    assert!(reopened.fsck_lite().unwrap().ok);

    // Стор снова пишется и водяные знаки не убывают.
    publish(&reopened, 1, 6);
    let dp_after = reopened.sync().unwrap().0;
    assert!(dp_after >= dp);
}

#[test]
fn torn_alloc_record_copy_uses_other_copy() {
    let dir = tempfile::tempdir().unwrap();
    let (path, store) = create(&dir);
    for version in 2..=4 {
        publish(&store, 1, version);
    }
    let dp = store.sync().unwrap().0;
    let geometry = store.geometry();
    drop(store);

    let offset_a = u64::from(geometry.page_alloc_record_a()) * u64::from(geometry.page_size());
    write_bytes(&path, offset_a, &[0xEE_u8; 256]);

    let reopened = ParallelStore::open(&path, OpenConfigV2::default()).unwrap();
    assert!(reopened.recovery_report().torn_alloc);
    assert_eq!(reopened.durable_page_limit(), dp);
    assert_eq!(reopened.select_root(1, u64::MAX).unwrap().version, 4);
    publish(&reopened, 1, 5);
    assert_eq!(reopened.select_root(1, u64::MAX).unwrap().version, 5);
}

#[test]
fn both_alloc_copies_invalid_are_file_fatal_but_readable() {
    let dir = tempfile::tempdir().unwrap();
    let (path, store) = create(&dir);
    for version in 2..=4 {
        publish(&store, 1, version);
    }
    let geometry = store.geometry();
    drop(store);

    for page in [
        geometry.page_alloc_record_a(),
        geometry.page_alloc_record_b(),
    ] {
        let offset = u64::from(page) * u64::from(geometry.page_size());
        write_bytes(&path, offset, &[0x77_u8; 256]);
    }

    let reopened = ParallelStore::open(&path, OpenConfigV2::default()).unwrap();
    assert_eq!(reopened.fatal(), Some(FatalKind::AllocRecord));
    assert_eq!(reopened.select_root(1, u64::MAX).unwrap().version, 4);
    let entry = RootEntry {
        owner_zone: 1,
        version: 5,
        root_page: 0,
        state: RootState::Serving,
        ..RootEntry::default()
    };
    assert!(matches!(
        reopened.publish_root(entry),
        Err(ParallelError::ReadOnly {
            reason: FatalKind::AllocRecord
        })
    ));
    let report = reopened.fsck_lite().unwrap();
    assert!(!report.ok);
    assert_eq!(report.fatal, Some(FatalKind::AllocRecord));
}

#[test]
fn alloc_watermark_regression_is_file_fatal() {
    let dir = tempfile::tempdir().unwrap();
    let (path, store) = create(&dir);
    publish(&store, 1, 2);
    let geometry = store.geometry();
    drop(store);

    let lower = u64::from(geometry.page_data_first());
    for page in [
        geometry.page_alloc_record_a(),
        geometry.page_alloc_record_b(),
    ] {
        let record = AllocRecord::new(page, 900, lower, 1);
        let offset = u64::from(page) * u64::from(geometry.page_size());
        write_bytes(&path, offset, &record.encode());
    }

    let reopened = ParallelStore::open(&path, OpenConfigV2::default()).unwrap();
    assert_eq!(reopened.fatal(), Some(FatalKind::AllocWatermarkRegression));
    assert_eq!(reopened.select_root(1, u64::MAX).unwrap().version, 2);
    let entry = RootEntry {
        owner_zone: 1,
        version: 3,
        root_page: 0,
        state: RootState::Serving,
        ..RootEntry::default()
    };
    assert!(matches!(
        reopened.publish_root(entry),
        Err(ParallelError::ReadOnly { .. })
    ));
}

#[test]
fn foreign_owner_record_is_file_fatal() {
    let dir = tempfile::tempdir().unwrap();
    let (path, store) = create(&dir);
    publish(&store, 1, 2);
    let geometry = store.geometry();
    drop(store);

    let foreign = RootEntry {
        owner_zone: 2,
        version: 2,
        root_page: 0,
        state: RootState::Serving,
        page_limit_at_commit: geometry.page_data_first(),
        ..RootEntry::default()
    };
    let raw = foreign.encode();
    // Пишем запись зоны 2 в слот зоны 1.
    write_bytes(&path, slot_offset(geometry, 1, 2, true), &raw);

    let reopened = ParallelStore::open(&path, OpenConfigV2::default()).unwrap();
    assert_eq!(reopened.fatal(), Some(FatalKind::ForeignOwner));
    let entry = RootEntry {
        owner_zone: 2,
        version: 3,
        root_page: 0,
        state: RootState::Serving,
        ..RootEntry::default()
    };
    assert!(matches!(
        reopened.publish_root(entry),
        Err(ParallelError::ReadOnly {
            reason: FatalKind::ForeignOwner
        })
    ));
}

#[test]
fn semantic_zone_issue_degrades_only_that_zone() {
    let dir = tempfile::tempdir().unwrap();
    let (path, store) = create(&dir);
    publish(&store, 1, 2);
    publish(&store, 2, 2);
    let geometry = store.geometry();
    let dp = store.sync().unwrap().0;
    drop(store);

    // Валидный ALLOC_RECORD с DT = 3, чтобы «сломанная» запись v3 давала
    // только zone-fatal, а не регрессию txn.
    for page in [
        geometry.page_alloc_record_a(),
        geometry.page_alloc_record_b(),
    ] {
        let record = AllocRecord::new(page, 901, dp, 3);
        let offset = u64::from(page) * u64::from(geometry.page_size());
        write_bytes(&path, offset, &record.encode());
    }

    let broken = RootEntry {
        owner_zone: 1,
        version: 3,
        root_page: geometry.page_data_first() + 10,
        state: RootState::Serving,
        page_limit_at_commit: geometry.page_data_first(),
        ..RootEntry::default()
    };
    let raw = broken.encode();
    write_bytes(&path, slot_offset(geometry, 1, 3, true), &raw);
    write_bytes(&path, slot_offset(geometry, 1, 3, false), &raw);

    let reopened = ParallelStore::open(&path, OpenConfigV2::default()).unwrap();
    assert!(reopened.recovery_report().zone_issues >= 1);
    assert!(matches!(
        reopened.select_root(1, u64::MAX),
        Err(ParallelError::ZoneDegraded { zone: 1, .. })
    ));
    assert!(matches!(
        reopened.select_root(1, 2),
        Err(ParallelError::ZoneDegraded { zone: 1, .. })
    ));
    let reader = reopened.reader().unwrap();
    assert!(matches!(
        reopened.zone_snapshot(&reader, 1),
        Err(ParallelError::ZoneDegraded { zone: 1, .. })
    ));
    // Другая зона не затронута.
    assert_eq!(reopened.select_root(2, u64::MAX).unwrap().version, 2);
    publish(&reopened, 2, 3);
    assert_eq!(reopened.select_root(2, u64::MAX).unwrap().version, 3);
}

#[test]
fn torn_layout_copy_survives_and_double_torn_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let (path, store) = create(&dir);
    publish(&store, 1, 2);
    let geometry = store.geometry();
    drop(store);

    let offset_b = u64::from(geometry.page_layout_head_b()) * u64::from(geometry.page_size());
    write_bytes(&path, offset_b, &[0xDD_u8; 512]);
    let reopened = ParallelStore::open(&path, OpenConfigV2::default()).unwrap();
    assert!(reopened.recovery_report().torn_layout);
    assert_eq!(reopened.select_root(1, u64::MAX).unwrap().version, 2);
    drop(reopened);

    let offset_a = u64::from(geometry.page_layout_head_a()) * u64::from(geometry.page_size());
    write_bytes(&path, offset_a, &[0xCC_u8; 512]);
    let error = ParallelStore::open(&path, OpenConfigV2::default()).unwrap_err();
    assert!(matches!(
        error,
        ParallelError::Corrupt {
            kind: pulse_zonefile::parallel::V2CorruptKind::LayoutHead,
            ..
        }
    ));
}

#[test]
fn second_writer_is_busy_and_read_only_open_works() {
    let dir = tempfile::tempdir().unwrap();
    let (path, store) = create(&dir);
    publish(&store, 1, 2);

    assert!(matches!(
        ParallelStore::open(&path, OpenConfigV2::default()),
        Err(ParallelError::Busy)
    ));
    let reader_store = open_read_only(&path).unwrap();
    assert_eq!(reader_store.select_root(1, u64::MAX).unwrap().version, 2);
    let entry = RootEntry {
        owner_zone: 1,
        version: 3,
        root_page: 0,
        state: RootState::Serving,
        ..RootEntry::default()
    };
    assert!(matches!(
        reader_store.publish_root(entry),
        Err(ParallelError::ReadOnly {
            reason: FatalKind::ReadOnlyOpen
        })
    ));
    drop(reader_store);
    drop(store);
    // После освобождения lock файл открывается writer'ом.
    let reopened = ParallelStore::open(&path, OpenConfigV2::default()).unwrap();
    assert_eq!(reopened.select_root(1, u64::MAX).unwrap().version, 2);
}
