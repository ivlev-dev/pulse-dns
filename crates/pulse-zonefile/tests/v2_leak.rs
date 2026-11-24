//! B2b: sweep утечек (`[DP, cursor)`/aborted/bucket-orphans), `MAX_LEAK_RATIO`,
//! offline `fsck --repair` (возврат в free-пул + проверка дизъюнктности).

use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    OpenConfigV2, ParallelError, ParallelStore, ParallelZones, RootEntry, RootState, RrsetData,
    StoreConfig, V2CorruptKind, ZoneCreateMeta, fsck_repair,
};

fn config() -> StoreConfig {
    StoreConfig::small(8, 2048)
}

fn origin(index: u32) -> NameRle {
    NameRle::from_ascii(&format!("leak{index}.example")).unwrap()
}

fn name(index: u32) -> NameRle {
    NameRle::from_ascii(&format!("r{index}.leak{index}.example")).unwrap()
}

fn rr() -> RrsetData {
    RrsetData::from_slices(60, 0, &[&[192, 0, 2, 1]]).unwrap()
}

fn seed_zone(store: &ParallelStore, index: u32) -> u32 {
    let mut zones = ParallelZones::open(store).unwrap();
    let seq = zones
        .create_zone(&origin(index), ZoneCreateMeta { soa_serial: 1 })
        .unwrap();
    let mut writer = zones.writer(&origin(index)).unwrap();
    writer.upsert_rrset(&name(index), 1, 0, &rr()).unwrap();
    writer.commit().unwrap();
    seq
}

fn make_leak(store: &ParallelStore, pages: u32) {
    let ticket = store.reserve_pages(pages).unwrap();
    for page in ticket.first_page..=ticket.last_page() {
        store
            .write_raw_page(page, b"unreferenced aborted page")
            .unwrap();
    }
    // `sync()` двигает DP до курсора: страницы становятся `[data, DP)`-утечкой.
    store.sync().unwrap();
}

#[test]
fn leak_report_detects_and_aborted_pages_are_separate() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("leak.v2");
    let store = ParallelStore::create(&path, config()).unwrap();
    seed_zone(&store, 0);
    let clean = store.leak_report().unwrap();
    // Батч-слэк аллокатора — штатная «утечка»-оценка `fsck` (не порча);
    // она ограничена размером батча на зону.
    assert!(clean.leaked_pages <= 256, "{clean:?}");
    assert_eq!(clean.max_ratio, 0.01);

    // Aborted: выделено, но DP ещё не двигался — это `[DP, cursor)`, не утечка
    // в `[data, DP)`.
    let before = store.leak_report().unwrap();
    let ticket = store.reserve_pages(4).unwrap();
    for page in ticket.first_page..=ticket.last_page() {
        store.write_raw_page(page, b"aborted").unwrap();
    }
    let aborted = store.leak_report().unwrap();
    assert_eq!(aborted.leaked_pages, before.leaked_pages);
    assert!(aborted.aborted_pages >= 4);
    assert!(store.stats().aborted_pages_estimate >= 4);
    let _ = ticket;
}

#[test]
fn fsck_repair_returns_leaks_to_free_pool_and_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("repair.v2");
    let store = ParallelStore::create(&path, config()).unwrap();
    seed_zone(&store, 0);
    make_leak(&store, 8);
    let report = store.leak_report().unwrap();
    assert!(report.leaked_pages >= 8, "{report:?}");
    assert!(report.exceeds_max_ratio, "порог MAX_LEAK_RATIO не сработал");
    assert!(
        (report.ratio - report.max_ratio).is_sign_positive() || report.ratio > report.max_ratio
    );

    let high_water = store.high_water();
    let repaired = store.repair_leaks().unwrap();
    assert!(repaired.repaired_pages >= 8, "{repaired:?}");
    assert!(repaired.ok, "{repaired:?}");
    assert_eq!(repaired.remaining_leaks, 0);
    assert!(
        store.high_water() <= high_water + 2,
        "repair не должен заметно растить файл"
    );
    assert_eq!(store.leak_report().unwrap().leaked_pages, 0);
    assert!(store.fsck_graph().unwrap().ok);
    // Утёкшие страницы теперь durable-free в bucket-цепочке каталога.
    let graph = store.fsck_graph().unwrap();
    assert!(graph.free_pages >= 8, "{graph:?}");
    // Повторный repair без новой нагрузки — 0 (идемпотентность).
    let again = store.repair_leaks().unwrap();
    assert_eq!(again.repaired_pages, 0);
    assert!(again.ok);
    // Новая зона не пересекается с возвращённым пулом.
    seed_zone(&store, 1);
    assert!(store.fsck_graph().unwrap().ok);
    drop(store);

    // Offline `fsck --repair` на новом файле с утечкой.
    let offline_path = dir.path().join("offline.v2");
    let store = ParallelStore::create(&offline_path, config()).unwrap();
    seed_zone(&store, 2);
    make_leak(&store, 4);
    drop(store);
    let repaired = fsck_repair(&offline_path).unwrap();
    assert!(repaired.repaired_pages >= 4);
    assert!(repaired.ok);
    let reopened = ParallelStore::open(&offline_path, OpenConfigV2::default()).unwrap();
    assert_eq!(reopened.leak_report().unwrap().leaked_pages, 0);
    assert!(reopened.fsck_graph().unwrap().ok);
    drop(reopened);
    assert_eq!(fsck_repair(&offline_path).unwrap().repaired_pages, 0);
}

#[test]
fn repair_refuses_cross_zone_overlap() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("overlap.v2");
    let store = ParallelStore::create(&path, config()).unwrap();
    let first = seed_zone(&store, 0);
    let second = seed_zone(&store, 1);
    let head_first = store.select_root(first, u64::MAX).unwrap();
    let head_second = store.select_root(second, u64::MAX).unwrap();
    assert_ne!(head_second.root_page, 0);

    // Чужая страница под видом корня первой зоны: `owner_zone` не совпадёт —
    // `fsck` обязан отказать (file-fatal класс), repair не «чинит» это.
    let forged = RootEntry {
        owner_zone: first,
        version: head_first.version + 100,
        root_page: head_second.root_page,
        tree_level: head_second.tree_level,
        state: RootState::Serving,
        ..RootEntry::default()
    };
    store.publish_root(forged).unwrap();
    let error = store.fsck_graph().expect_err("пересечение не поймано");
    assert!(
        matches!(
            error,
            ParallelError::Corrupt {
                kind: V2CorruptKind::ForeignOwner | V2CorruptKind::PageOverlap,
                ..
            }
        ),
        "unexpected: {error:?}"
    );
    assert!(matches!(
        store.repair_leaks(),
        Err(ParallelError::Corrupt { .. })
    ));
}

#[test]
fn leak_ratio_metric_tracks_threshold() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ratio.v2");
    let store = ParallelStore::create(&path, config()).unwrap();
    seed_zone(&store, 0);
    let before = store.leak_report().unwrap();
    assert_eq!(before.max_ratio, 0.01);
    make_leak(&store, 16);
    let report = store.leak_report().unwrap();
    assert!(report.leaked_pages >= before.leaked_pages + 16);
    assert!(report.ratio > 0.01);
    assert!(report.exceeds_max_ratio);
}
