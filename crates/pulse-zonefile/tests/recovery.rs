//! Матрица краха и политика recovery: два meta-слота (valid/torn/not persisted),
//! torn-диагностика, Memory-фолбэк/opt-in, липкий режим и граница переиспользования.

use std::fs::OpenOptions;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use pulse_zonefile::consts as c;
use pulse_zonefile::{
    CreateConfig, InvariantId, Meta, OpenConfig, SyncMode, ZoneFile, ZoneFileError, checksum,
    is_reclaimable,
};

const PAGE_SIZE: u32 = 4096;

fn config(sync_mode: SyncMode) -> CreateConfig {
    CreateConfig {
        page_size: PAGE_SIZE,
        map_size: 64 * 1024 * 1024,
        sync_mode,
        ..CreateConfig::default()
    }
}

fn write_at(path: &Path, offset: u64, bytes: &[u8]) {
    let file = OpenOptions::new().write(true).open(path).unwrap();
    file.write_all_at(bytes, offset).unwrap();
}

fn meta(page_no: u32, txnid: u64, durable_txn: u64) -> Meta {
    let mut meta = Meta::initial(page_no, PAGE_SIZE, 13, 16_384, 36_864, 0);
    meta.txnid = txnid;
    meta.durable_txn = durable_txn;
    meta
}

/// Состояние записанного слота meta на диске.
#[derive(Debug, Clone, Copy)]
enum Slot {
    /// Полностью записанная валидная meta.
    Valid(Meta),
    /// Оборванная запись: `txnid` читается, CRC — нет.
    Torn(Meta),
    /// Невалидная страница без читаемого `txnid`.
    Unreadable,
    /// Слот не записан (нулевая страница).
    NotPersisted,
}

fn encoded_torn(meta: &Meta) -> Vec<u8> {
    let mut page = meta.encode();
    // Портим байт вне поля txnid: CRC перестаёт сходиться, txnid читается.
    page[40] ^= 0xFF;
    page
}

fn write_slot(path: &Path, page_no: u32, slot: Slot) {
    let offset = u64::from(page_no) * u64::from(PAGE_SIZE);
    match slot {
        Slot::Valid(meta) => write_at(path, offset, &meta.encode()),
        Slot::Torn(meta) => write_at(path, offset, &encoded_torn(&meta)),
        Slot::Unreadable => {
            let mut page = vec![0_u8; PAGE_SIZE as usize];
            page[100] = 0xAA;
            write_at(path, offset, &page);
        }
        Slot::NotPersisted => write_at(path, offset, &[0_u8; PAGE_SIZE as usize]),
    }
}

fn build(sync_mode: SyncMode, slot_a: Slot, slot_b: Slot) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    {
        let zonefile = ZoneFile::create(&path, config(sync_mode)).unwrap();
        drop(zonefile);
    }
    write_slot(&path, c::PAGE_META_A, slot_a);
    write_slot(&path, c::PAGE_META_B, slot_b);
    (dir, path)
}

fn reader_cfg() -> OpenConfig {
    OpenConfig::default()
}

/// Открывает файл и проверяет инварианты матрицы краха.
///
/// Пока B+tree/freelist не реализованы, проверяются только `meta/high_water`:
/// выбранная meta внутренне согласована, freelist пуст и его корни в границах.
fn open_checked(path: &Path, cfg: OpenConfig) -> ZoneFile {
    let zonefile = ZoneFile::open(path, cfg).unwrap();
    let meta = zonefile.meta();
    assert!(meta.txnid >= 1);
    assert!(meta.durable_txn >= 1 && meta.durable_txn <= meta.txnid);
    assert_eq!(meta.free_page_count, meta.freelist_entries);
    assert!(meta.page_count_high_water >= zonefile.superblock().page_data_first);
    assert!(meta.page_count_high_water <= zonefile.superblock().page_count_max);
    assert!(meta.freelist_head == 0 || meta.freelist_head < meta.page_count_high_water);
    assert!(meta.freelist_tail == 0 || meta.freelist_tail < meta.page_count_high_water);
    zonefile
}

#[test]
fn newest_valid_meta_wins_cleanly() {
    let (_dir, path) = build(
        SyncMode::Sync,
        Slot::Valid(meta(c::PAGE_META_A, 3, 3)),
        Slot::Valid(meta(c::PAGE_META_B, 4, 4)),
    );
    let zonefile = open_checked(&path, reader_cfg());
    assert_eq!(zonefile.meta().txnid, 4);
    assert_eq!(zonefile.meta().page_no, c::PAGE_META_B);
    assert!(!zonefile.torn_meta());
    assert!(!zonefile.meta().needs_fsck());
    assert!(!zonefile.recovered_unsynced());
}

#[test]
fn torn_slot_at_valid_peer_is_normal_crash() {
    let (_dir, path) = build(
        SyncMode::Sync,
        Slot::Valid(meta(c::PAGE_META_A, 5, 5)),
        Slot::Torn(meta(c::PAGE_META_B, 4, 4)),
    );
    let zonefile = open_checked(&path, reader_cfg());
    assert_eq!(zonefile.meta().txnid, 5);
    assert!(zonefile.torn_meta());
    assert!(!zonefile.meta().needs_fsck());
}

#[test]
fn unreadable_torn_slot_does_not_force_fsck() {
    let (_dir, path) = build(
        SyncMode::Sync,
        Slot::Unreadable,
        Slot::Valid(meta(c::PAGE_META_B, 5, 5)),
    );
    let zonefile = open_checked(&path, reader_cfg());
    assert_eq!(zonefile.meta().txnid, 5);
    assert!(zonefile.torn_meta());
    assert!(!zonefile.meta().needs_fsck());
}

#[test]
fn torn_slot_newer_than_active_forces_fsck() {
    let (_dir, path) = build(
        SyncMode::Sync,
        Slot::Valid(meta(c::PAGE_META_A, 5, 5)),
        Slot::Torn(meta(c::PAGE_META_B, 6, 6)),
    );
    let zonefile = open_checked(&path, reader_cfg());
    assert_eq!(zonefile.meta().txnid, 5);
    assert!(zonefile.torn_meta());
    assert!(zonefile.meta().needs_fsck());
}

#[test]
fn both_slots_invalid_is_corrupt() {
    let (_dir, path) = build(SyncMode::Sync, Slot::Unreadable, Slot::NotPersisted);
    assert!(matches!(
        ZoneFile::open(&path, reader_cfg()),
        Err(ZoneFileError::CorruptNoValidMeta)
    ));
}

#[test]
fn empty_slot_after_initial_is_anomaly() {
    // active.txnid = 2, второй слот пуст: так не бывает при штатном коммите
    // (неактивный слот пишется первым) → NEEDS_FSCK (§13.7 шаг 5).
    let (_dir, path) = build(
        SyncMode::Sync,
        Slot::Valid(meta(c::PAGE_META_A, 2, 2)),
        Slot::NotPersisted,
    );
    let zonefile = open_checked(&path, reader_cfg());
    assert_eq!(zonefile.meta().txnid, 2);
    assert!(!zonefile.torn_meta());
    assert!(zonefile.meta().needs_fsck());
}

#[test]
fn stored_reclaim_txn_is_recomputed_on_open() {
    // В файле — устаревший advisory reclaim_txn = 0; при открытии он
    // пересчитывается: min(durable − 1, oldest_reader=active) = 2.
    let (_dir, path) = build(
        SyncMode::Sync,
        Slot::Valid(meta(c::PAGE_META_A, 3, 3)),
        Slot::NotPersisted,
    );
    let zonefile = open_checked(&path, reader_cfg());
    assert_eq!(zonefile.meta().durable_txn, 3);
    assert_eq!(zonefile.meta().reclaim_txn, 2);
}

#[test]
fn not_persisted_second_slot_is_normal_initial_state() {
    let (_dir, path) = build(
        SyncMode::Sync,
        Slot::Valid(meta(c::PAGE_META_A, 1, 1)),
        Slot::NotPersisted,
    );
    let zonefile = open_checked(&path, reader_cfg());
    assert_eq!(zonefile.meta().txnid, 1);
    assert!(!zonefile.torn_meta());
    assert!(!zonefile.meta().needs_fsck());
}

#[test]
fn memory_falls_back_to_durable_meta() {
    // durable_txn = 1: sticky-водораздела ещё нет, работает Memory-политика.
    let (_dir, path) = build(
        SyncMode::NoSync,
        Slot::Valid(meta(c::PAGE_META_A, 1, 1)),
        Slot::Valid(meta(c::PAGE_META_B, 9, 1)),
    );
    let zonefile = open_checked(&path, reader_cfg());
    // Максимальная валидная (9) отвергнута: подтверждена только initial meta.
    assert_eq!(zonefile.meta().txnid, 1);
    assert_eq!(zonefile.meta().page_no, c::PAGE_META_A);
    assert!(!zonefile.recovered_unsynced());
    assert!(zonefile.memory_tail_discarded());
    assert!(!zonefile.meta().needs_fsck());
    assert!(!zonefile.is_write_locked());
    assert!(zonefile.check_commit_mode(SyncMode::Sync).is_ok());
}

#[test]
fn sticky_sync_rolls_forward_memory_tail() {
    // Memory-файл уже прошёл sync() (durable_txn = 4 > 1): по §4.1 п.6 режим
    // липко Sync. Max-valid meta новее durable принимается roll-forward, без
    // Memory-фолбэка/write-locked/fsck.
    let (_dir, path) = build(
        SyncMode::NoSync,
        Slot::Valid(meta(c::PAGE_META_A, 4, 4)),
        Slot::Valid(meta(c::PAGE_META_B, 9, 4)),
    );
    let zonefile = open_checked(&path, reader_cfg());
    assert_eq!(zonefile.meta().txnid, 9);
    assert_eq!(zonefile.meta().page_no, c::PAGE_META_B);
    assert!(zonefile.recovered_unsynced());
    assert!(!zonefile.memory_tail_discarded());
    assert!(!zonefile.meta().needs_fsck());
    assert!(!zonefile.is_write_locked());
    assert_eq!(zonefile.durable_watermark(), 4);
    assert_eq!(zonefile.effective_mode(), SyncMode::Sync);
}

#[test]
fn durable_regression_forces_fsck_and_write_lock() {
    // W-10: watermark по валидным метам = 6, выбранная B (txn 9) — durable 1.
    // Это порча, а не повод тихо принять meta: NEEDS_FSCK + read-only.
    let (_dir, path) = build(
        SyncMode::NoSync,
        Slot::Valid(meta(c::PAGE_META_A, 7, 6)),
        Slot::Valid(meta(c::PAGE_META_B, 9, 1)),
    );
    let zonefile = open_checked(&path, reader_cfg());
    assert_eq!(zonefile.meta().txnid, 9);
    assert_eq!(zonefile.meta().durable_txn, 1);
    assert_eq!(zonefile.durable_watermark(), 6);
    assert!(zonefile.recovered_unsynced());
    assert!(zonefile.meta().needs_fsck());
    assert!(zonefile.is_write_locked());
    assert_eq!(zonefile.effective_mode(), SyncMode::Sync);
    assert!(matches!(
        zonefile.check_commit_mode(SyncMode::NoSync),
        Err(ZoneFileError::ReadOnly)
    ));
}

#[test]
fn reclaim_uses_durable_watermark() {
    // watermark = 6; читателей нет → oldest = active txnid 9;
    // reclaim = min(6 − 1, 9) = 5 (а не min(durable_selected − 1) = 5 при B тоже 6).
    let (_dir, path) = build(
        SyncMode::Sync,
        Slot::Valid(meta(c::PAGE_META_A, 7, 6)),
        Slot::Valid(meta(c::PAGE_META_B, 9, 6)),
    );
    let zonefile = open_checked(&path, reader_cfg());
    assert_eq!(zonefile.durable_watermark(), 6);
    assert_eq!(zonefile.meta().reclaim_txn, 5);
}

#[test]
fn memory_without_flag_refuses_unsynced_meta() {
    let (_dir, path) = build(
        SyncMode::NoSync,
        Slot::Torn(meta(c::PAGE_META_A, 1, 1)),
        Slot::Valid(meta(c::PAGE_META_B, 9, 1)),
    );
    assert!(matches!(
        ZoneFile::open(&path, reader_cfg()),
        Err(ZoneFileError::UnsyncedMemoryRecovery {
            txnid: 9,
            durable_txn: 1
        })
    ));
}

#[test]
fn memory_with_flag_accepts_but_locks_writes() {
    let (_dir, path) = build(
        SyncMode::NoSync,
        Slot::Torn(meta(c::PAGE_META_A, 1, 1)),
        Slot::Valid(meta(c::PAGE_META_B, 9, 1)),
    );
    let zonefile = open_checked(
        &path,
        OpenConfig {
            allow_unsynced_memory_recovery: true,
            ..reader_cfg()
        },
    );
    assert_eq!(zonefile.meta().txnid, 9);
    assert!(zonefile.recovered_unsynced());
    assert!(zonefile.meta().needs_fsck());
    assert!(zonefile.is_write_locked());
    assert!(matches!(
        zonefile.check_commit_mode(SyncMode::Sync),
        Err(ZoneFileError::ReadOnly)
    ));
}

#[test]
fn sync_and_flush_accept_unsynced_meta_without_fsck() {
    for mode in [SyncMode::Sync, SyncMode::MetaNoSync] {
        let (_dir, path) = build(
            mode,
            Slot::Valid(meta(c::PAGE_META_A, 1, 1)),
            Slot::Valid(meta(c::PAGE_META_B, 2, 1)),
        );
        let zonefile = open_checked(&path, reader_cfg());
        assert_eq!(zonefile.meta().txnid, 2);
        // Durable не повышается принятием unsynced meta.
        assert_eq!(zonefile.meta().durable_txn, 1);
        assert_eq!(zonefile.durable_watermark(), 1);
        assert!(zonefile.recovered_unsynced());
        assert!(!zonefile.meta().needs_fsck());
        assert!(!zonefile.is_write_locked());
    }
}

#[test]
fn effective_mode_is_sticky_after_durable_watermark() {
    // durable_txn = 1: режим файла действует как есть.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fresh.zonefile");
    let zonefile = ZoneFile::create(&path, config(SyncMode::MetaNoSync)).unwrap();
    assert_eq!(zonefile.effective_mode(), SyncMode::MetaNoSync);
    assert!(zonefile.check_commit_mode(SyncMode::MetaNoSync).is_ok());
    assert!(matches!(
        zonefile.check_commit_mode(SyncMode::NoSync),
        Err(ZoneFileError::InvariantViolation(
            InvariantId::DurabilityBelowFileMode
        ))
    ));
    drop(zonefile);

    // durable_txn = 2: липко Sync, Flush-коммит уже запрещён.
    write_slot(
        &path,
        c::PAGE_META_B,
        Slot::Valid(meta(c::PAGE_META_B, 2, 2)),
    );
    let zonefile = open_checked(&path, reader_cfg());
    assert_eq!(zonefile.effective_mode(), SyncMode::Sync);
    assert!(matches!(
        zonefile.check_commit_mode(SyncMode::MetaNoSync),
        Err(ZoneFileError::InvariantViolation(
            InvariantId::DurabilityBelowFileMode
        ))
    ));
    assert!(zonefile.check_commit_mode(SyncMode::Sync).is_ok());
}

#[test]
fn memory_file_without_watermark_allows_memory_commit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("memory.zonefile");
    let zonefile = ZoneFile::create(&path, config(SyncMode::NoSync)).unwrap();
    assert_eq!(zonefile.effective_mode(), SyncMode::NoSync);
    assert!(zonefile.check_commit_mode(SyncMode::NoSync).is_ok());
    assert!(zonefile.check_commit_mode(SyncMode::Sync).is_ok());
}

fn leaf_page(page_no: u32, txn: u64) -> Vec<u8> {
    let mut page = vec![0_u8; PAGE_SIZE as usize];
    page[0..4].copy_from_slice(&c::PAGE_TYPE_LEAF.to_le_bytes());
    page[8..12].copy_from_slice(&page_no.to_le_bytes());
    page[16..24].copy_from_slice(&txn.to_le_bytes());
    page[36..40].copy_from_slice(&PAGE_SIZE.to_le_bytes());
    let crc = checksum::page_crc32c(&page, 32).unwrap();
    page[32..36].copy_from_slice(&crc.to_le_bytes());
    page
}

#[test]
fn lazy_page_checks_respect_snapshot_and_high_water() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pages.zonefile");
    {
        let zonefile = ZoneFile::create(&path, config(SyncMode::Sync)).unwrap();
        drop(zonefile);
    }
    let mut selected = meta(c::PAGE_META_A, 4, 4);
    selected.page_count_high_water = 15;
    write_slot(&path, c::PAGE_META_A, Slot::Valid(selected));
    write_at(
        &path,
        u64::from(selected.page_count_high_water - 2) * u64::from(PAGE_SIZE),
        &leaf_page(13, 3),
    );
    // Страница «из будущего»: txn 5 > snapshot.txnid 4.
    write_at(
        &path,
        u64::from(selected.page_count_high_water - 1) * u64::from(PAGE_SIZE),
        &leaf_page(14, 5),
    );

    let zonefile = open_checked(&path, reader_cfg());
    // Выбранная meta = max-valid; high_water — из неё же.
    assert_eq!(zonefile.meta().txnid, 4);
    assert_eq!(zonefile.meta().page_count_high_water, 15);

    let reader = zonefile.reader();
    let snapshot = reader.snapshot().unwrap();
    let header = zonefile.page_header(&snapshot, 13).unwrap();
    assert_eq!(header.txn, 3);
    assert_eq!(header.page_no, 13);
    // page.txn <= snapshot.txnid.
    assert!(zonefile.page_header(&snapshot, 14).is_err());
    // Границы: вне [page_data_first, high_water).
    assert!(zonefile.page_header(&snapshot, 15).is_err());
    assert!(zonefile.page_header(&snapshot, 12).is_err());
}

#[test]
fn reclaim_regression_durable_boundary_is_strict() {
    // F == durable -> не переиспользуется.
    assert!(!is_reclaimable(5, 5, 100));
    // F < durable и F <= oldest_reader.
    assert!(is_reclaimable(4, 5, 4));
    assert!(is_reclaimable(4, 5, 100));
    assert!(!is_reclaimable(5, 6, 4));
    // durable == 1 -> ничего не переиспользуется.
    assert!(!is_reclaimable(0, 1, 1));
    assert!(!is_reclaimable(1, 1, 1));
}
