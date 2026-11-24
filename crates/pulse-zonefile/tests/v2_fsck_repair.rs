//! Полный `fsck --verify` / `fsck --repair` v2: битый `txn`, чужой владелец,
//! карантин повреждённой зоны и сохранность валидных зон.

use std::os::unix::fs::FileExt;

use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    OpenConfigV2, ParallelError, ParallelStore, ParallelZones, RootFlags, RrsetData, StoreConfig,
    V2CorruptKind, ZoneCreateMeta, fsck_repair, open_read_only,
};

const PAGE_OFF_TXN: usize = 16;
const PAGE_BYTES: usize = 4096;

fn page_offset(page: u32) -> u64 {
    u64::from(page) * u64::try_from(PAGE_BYTES).unwrap()
}

fn config() -> StoreConfig {
    StoreConfig::small(8, 2048)
}

fn apex(index: u32) -> NameRle {
    NameRle::from_ascii(&format!("zone{index}.example")).unwrap()
}

fn name(index: u32) -> NameRle {
    NameRle::from_ascii(&format!("www.zone{index}.example")).unwrap()
}

fn rr(value: u8) -> RrsetData {
    RrsetData::from_slices(60, 0, &[&[192, 0, 2, value]]).unwrap()
}

fn seed(store: &ParallelStore, index: u32) -> u32 {
    let mut zones = ParallelZones::open(store).unwrap();
    let seq = zones
        .create_zone(&apex(index), ZoneCreateMeta { soa_serial: 1 })
        .unwrap();
    let mut writer = zones.writer(&apex(index)).unwrap();
    writer
        .upsert_rrset(&name(index), 1, 0, &rr(u8::try_from(index).unwrap_or(1)))
        .unwrap();
    writer.commit().unwrap();
    seq
}

fn read_zone(store: &ParallelStore, index: u32) -> Option<Vec<u8>> {
    let zones = ParallelZones::open(store).unwrap();
    let reader = store.reader().unwrap();
    let view = zones.read(&reader, &apex(index)).unwrap();
    view.lookup(&name(index), 1, 0)
        .unwrap()
        .map(|record| record.rdata.concat())
}

#[test]
fn repair_quarantines_damaged_zone_and_keeps_valid_zone() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("quarantine.v2");
    let store = ParallelStore::create(&path, config()).unwrap();
    let good = seed(&store, 0);
    let bad = seed(&store, 1);
    let bad_head = store.select_root(bad, u64::MAX).unwrap();
    assert_ne!(bad_head.root_page, 0);
    assert!(!bad_head.flags.contains(RootFlags::NEEDS_FSCK));
    drop(store);

    // Битая страница дерева зоны `bad`: CRC перестаёт сходиться, но заголовок
    // и `txn` целы — это zone-fatal, а не file-fatal.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let offset = page_offset(bad_head.root_page);
    let mut page_before = [0_u8; PAGE_BYTES];
    file.read_exact_at(&mut page_before, offset).unwrap();
    file.write_all_at(&[page_before[0] ^ 0xFF], offset).unwrap();
    drop(file);

    let report = fsck_repair(&path).expect("repair");
    assert!(report.ok, "{report:?}");
    assert_eq!(report.quarantined_zones, vec![bad], "{report:?}");

    // `--repair` не трогает страницы данных повреждённой зоны.
    let file = std::fs::File::open(&path).unwrap();
    let mut page_after = [0_u8; PAGE_BYTES];
    file.read_exact_at(&mut page_after, offset).unwrap();
    drop(file);
    assert_eq!(page_after[0], !page_before[0]);
    assert_eq!(page_before[1..], page_after[1..]);

    let store = ParallelStore::open(&path, OpenConfigV2::default()).unwrap();
    // Валидная зона продолжает читаться, изолированная — нет на запись.
    assert_eq!(read_zone(&store, 0).as_deref(), Some(&[192, 0, 2, 0][..]));
    let zones = ParallelZones::open(&store).unwrap();
    let reader = store.reader().unwrap();
    assert!(
        zones.read(&reader, &apex(1)).is_err(),
        "изолированная зона должна быть read-only"
    );
    drop(reader);
    let _ = good;
    drop(store);

    // Повторный repair — no-op по reclaimed-страницам; карантин уже стоит.
    let again = fsck_repair(&path).expect("second repair");
    assert_eq!(again.repaired_pages, 0, "{again:?}");
    assert!(again.quarantined_zones.contains(&bad), "{again:?}");
    assert!(again.ok, "{again:?}");
}

#[test]
fn verify_rejects_page_txn_newer_than_head_as_file_fatal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("txn.v2");
    let store = ParallelStore::create(&path, config()).unwrap();
    let zone = seed(&store, 0);
    let head = store.select_root(zone, u64::MAX).unwrap();
    assert_ne!(head.root_page, 0);
    drop(store);

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    file.write_all_at(
        &(head.version + 1).to_le_bytes(),
        page_offset(head.root_page) + u64::try_from(PAGE_OFF_TXN).unwrap(),
    )
    .unwrap();
    drop(file);

    let store = ParallelStore::open(&path, OpenConfigV2::default()).unwrap();
    let error = store
        .fsck_graph()
        .expect_err("page.txn > version не поймано");
    assert!(
        matches!(
            error,
            ParallelError::Corrupt {
                kind: V2CorruptKind::PageTxn | V2CorruptKind::Bounds,
                ..
            }
        ),
        "unexpected: {error:?}"
    );
    drop(store);
    assert!(fsck_repair(&path).is_err());
}

#[test]
fn repair_defers_leaks_inside_damaged_zone_range() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("deferred.v2");
    let store = ParallelStore::create(&path, config()).unwrap();
    let _good = seed(&store, 0);

    // Утечка ниже будущего `page_limit_at_commit` повреждённой зоны: отдать её
    // пулу нельзя, пока дерево зоны недоступно.
    let ticket = store.reserve_pages(4).unwrap();
    for page in ticket.first_page..=ticket.last_page() {
        store.write_raw_page(page, b"aborted").unwrap();
    }
    store.sync().unwrap();

    let bad = seed(&store, 1);
    let bad_head = store.select_root(bad, u64::MAX).unwrap();
    drop(store);

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let offset = page_offset(bad_head.root_page) + 200;
    let mut byte = [0_u8; 1];
    file.read_exact_at(&mut byte, offset).unwrap();
    byte[0] ^= 0xFF;
    file.write_all_at(&byte, offset).unwrap();
    drop(file);

    let report = fsck_repair(&path).unwrap();
    assert!(report.ok, "{report:?}");
    assert_eq!(report.repaired_pages, 0, "{report:?}");
    assert!(report.deferred_leaks >= 4, "{report:?}");
    assert_eq!(report.remaining_leaks, report.deferred_leaks, "{report:?}");

    let store = open_read_only(&path).unwrap();
    assert_eq!(read_zone(&store, 0).as_deref(), Some(&[192, 0, 2, 0][..]));
    let zones = ParallelZones::open(&store).unwrap();
    let reader = store.reader().unwrap();
    assert!(zones.read(&reader, &apex(1)).is_err());
}
