//! Интеграционные тесты фазы 1: создание, открытие, reader table, восстановление.

use std::fs::{self, OpenOptions};
use std::os::unix::fs::{FileExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use pulse_zonefile::consts::{self as c, ReaderGeometry};
use pulse_zonefile::{
    CorruptDetail, CorruptKind, CreateConfig, LockMode, Meta, OpenConfig, Superblock, ZoneFile,
    ZoneFileError,
};

fn create_config(page_size: u32, mib: u64) -> CreateConfig {
    CreateConfig {
        page_size,
        map_size: mib * 1024 * 1024,
        ..CreateConfig::default()
    }
}

fn create(path: &Path, page_size: u32, mib: u64) -> ZoneFile {
    ZoneFile::create(path, create_config(page_size, mib)).expect("create zone file")
}

fn reader_cfg() -> OpenConfig {
    OpenConfig::default()
}

fn writer_cfg() -> OpenConfig {
    OpenConfig {
        lock_mode: LockMode::Writer,
        ..OpenConfig::default()
    }
}

fn lock_path(path: &Path) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(c::LOCK_FILE_SUFFIX);
    PathBuf::from(os)
}

fn write_at(path: &Path, offset: u64, bytes: &[u8]) {
    let file = OpenOptions::new().write(true).open(path).unwrap();
    file.write_all_at(bytes, offset).unwrap();
}

fn read_at(path: &Path, offset: u64, len: usize) -> Vec<u8> {
    let file = OpenOptions::new().read(true).open(path).unwrap();
    let mut buffer = vec![0_u8; len];
    file.read_exact_at(&mut buffer, offset).unwrap();
    buffer
}

fn now_ns() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    )
    .unwrap()
}

#[test]
fn create_open_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 4096, 64);

    assert_eq!(zonefile.superblock().page_size, 4096);
    assert_eq!(zonefile.superblock().page_count_max, 16_384);
    assert_eq!(zonefile.superblock().page_data_first, 13);
    assert_eq!(zonefile.superblock().page_reader_table_count, 9);
    assert_eq!(zonefile.superblock().reader_region_off, 16_384);
    assert_eq!(zonefile.superblock().reader_region_len, 36_864);

    let meta = *zonefile.meta();
    assert_eq!(meta.txnid, 1);
    assert_eq!(meta.durable_txn, 1);
    assert_eq!(meta.page_no, c::PAGE_META_A);
    assert_eq!(meta.page_count_high_water, 13);
    assert_eq!(meta.free_page_count, 0);
    assert_eq!(meta.next_zone_seq, 1);
    assert_eq!(meta.zone_dir_root, 0);
    assert_eq!(meta.zone_dir_level, 0);
    assert_eq!(meta.freelist_head, 0);
    assert_eq!(meta.freelist_entries, 0);
    assert_eq!(meta.reader_region_off, 16_384);
    assert_eq!(meta.reader_region_len, 36_864);
    assert!(!meta.needs_fsck());
    assert_eq!(zonefile.txnid(), 1);
    assert!(zonefile.is_writer());

    let map_size = zonefile.superblock().map_size();
    drop(zonefile);
    assert_eq!(fs::metadata(&path).unwrap().len(), map_size);

    let reopened = ZoneFile::open(&path, reader_cfg()).unwrap();
    assert_eq!(*reopened.meta(), meta);
    assert!(!reopened.is_writer());
    assert_eq!(reopened.lock_mode(), LockMode::Reader);
}

#[test]
fn file_layout_has_copies_and_zero_meta_b() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 4096, 64);
    let superblock = *zonefile.superblock();
    assert_eq!(
        fs::metadata(&path).unwrap().len(),
        u64::from(superblock.page_count_max) * u64::from(superblock.page_size)
    );

    let record_a = read_at(&path, 0, 4096);
    let record_b = read_at(&path, u64::from(superblock.page_size), 4096);
    assert_eq!(Superblock::decode(&record_a).unwrap(), superblock);
    let copy_b = Superblock::decode(&record_b).unwrap();
    assert_eq!(copy_b.superblock_copy, 1);
    assert_eq!(copy_b.page_size, superblock.page_size);
    assert_eq!(copy_b.page_count_max, superblock.page_count_max);
    assert_eq!(copy_b.instance_uuid, superblock.instance_uuid);

    assert!(read_at(&path, 3 * 4096, 4096).iter().all(|&byte| byte == 0));
}

#[test]
fn reader_table_pages_match_spec() {
    let cases = [
        (4096_u32, 9_u32, 16_384_u64, 36_864_u64, 13_u32),
        (8192, 5, 32_768, 40_960, 9),
        (16_384, 3, 65_536, 49_152, 7),
    ];
    for (page_size, pages, region_off, region_len, data_first) in cases {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(format!("zones-{page_size}.bin"));
        let zonefile = create(&path, page_size, 64);
        let superblock = *zonefile.superblock();
        let geometry = ReaderGeometry::for_page_size(page_size).unwrap();
        assert_eq!(superblock.page_reader_table_count, pages);
        assert_eq!(superblock.reader_region_off, region_off);
        assert_eq!(superblock.reader_region_len, region_len);
        assert_eq!(superblock.page_data_first, data_first);
        assert_eq!(superblock.reader_region_align, page_size);
        assert_eq!(geometry.region_off % 64, 0);
        assert_eq!(geometry.region_len % 64, 0);
        assert_eq!(zonefile.meta().page_count_high_water, data_first);

        for index in 0..pages {
            let page_no = c::PAGE_READER_TABLE + index;
            let page = read_at(
                &path,
                u64::from(page_no) * u64::from(page_size),
                page_size as usize,
            );
            assert_eq!(
                u32::from_le_bytes(page[0..4].try_into().unwrap()),
                c::PAGE_TYPE_READER_TABLE
            );
            assert_eq!(u16::from_le_bytes(page[4..6].try_into().unwrap()), 1);
            assert_eq!(u16::from_le_bytes(page[6..8].try_into().unwrap()), 0);
            assert_eq!(u32::from_le_bytes(page[8..12].try_into().unwrap()), page_no);
            assert_eq!(u32::from_le_bytes(page[12..16].try_into().unwrap()), 0);
            assert_eq!(u32::from_le_bytes(page[16..20].try_into().unwrap()), 0);
        }
        drop(zonefile);
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            u64::from(superblock.page_count_max) * u64::from(page_size)
        );
    }
}

#[test]
fn second_create_reports_already_exists() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 4096, 64);
    drop(zonefile);
    let error = ZoneFile::create(&path, create_config(4096, 64)).unwrap_err();
    assert!(matches!(error, ZoneFileError::AlreadyExists));
}

#[test]
fn truncated_file_is_rejected_for_writer_and_reader() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 4096, 64);
    let map_size = zonefile.superblock().map_size();
    drop(zonefile);
    let file = OpenOptions::new().write(true).open(&path).unwrap();
    file.set_len(map_size - 4096).unwrap();
    drop(file);

    assert!(matches!(
        ZoneFile::open(&path, reader_cfg()),
        Err(ZoneFileError::TruncatedFile)
    ));
    assert!(matches!(
        ZoneFile::open(&path, writer_cfg()),
        Err(ZoneFileError::TruncatedFile)
    ));

    let file = OpenOptions::new().write(true).open(&path).unwrap();
    file.set_len(100).unwrap();
    drop(file);
    assert!(matches!(
        ZoneFile::open(&path, reader_cfg()),
        Err(ZoneFileError::TruncatedFile)
    ));
}

#[test]
fn corrupt_meta_a_falls_back_to_meta_b() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 4096, 64);
    let base_meta = *zonefile.meta();
    let page_size = zonefile.superblock().page_size;
    drop(zonefile);

    let mut meta_b = base_meta;
    meta_b.page_no = c::PAGE_META_B;
    meta_b.txnid = 2;
    meta_b.durable_txn = 2;
    meta_b.commit_unix_ns = now_ns();
    let encoded_b = meta_b.encode();
    write_at(
        &path,
        u64::from(c::PAGE_META_B) * u64::from(page_size),
        &encoded_b,
    );

    // Torn-запись meta A: портим high_water (CRC перестаёт сходиться), а txnid
    // (+16) оставляем читаемым и не новее выбранной meta B. Это штатный крах,
    // а не повод для NEEDS_FSCK.
    write_at(
        &path,
        u64::from(c::PAGE_META_A) * u64::from(page_size) + 40,
        &[0xFF, 0xFF, 0xFF, 0xFF],
    );
    let reopened = ZoneFile::open(&path, reader_cfg()).unwrap();
    assert_eq!(reopened.meta().txnid, 2);
    assert_eq!(reopened.meta().page_no, c::PAGE_META_B);
    assert_eq!(reopened.txnid(), 2);
    assert!(reopened.torn_meta());
    assert!(!reopened.meta().needs_fsck());
    drop(reopened);

    // Портим и meta B.
    write_at(
        &path,
        u64::from(c::PAGE_META_B) * u64::from(page_size) + 16,
        &[0xEE, 0xEE, 0xEE, 0xEE],
    );
    assert!(matches!(
        ZoneFile::open(&path, reader_cfg()),
        Err(ZoneFileError::CorruptNoValidMeta)
    ));
}

#[test]
fn two_writers_get_busy_but_reader_opens() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let writer = create(&path, 4096, 64);

    let reader = ZoneFile::open(&path, reader_cfg()).unwrap();
    assert!(!reader.is_writer());
    drop(reader);

    assert!(matches!(
        ZoneFile::open(&path, writer_cfg()),
        Err(ZoneFileError::Busy)
    ));
    drop(writer);
    let second = ZoneFile::open(&path, writer_cfg()).unwrap();
    assert!(second.is_writer());
    assert_eq!(second.lock_mode(), LockMode::Writer);
}

#[test]
fn rollback_to_initial_requires_opt_in() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 4096, 64);
    let mut superblock = *zonefile.superblock();
    let instance_uuid = superblock.instance_uuid;
    drop(zonefile);

    let old_created = now_ns() - 120_000_000_000;
    superblock.created_unix_ns = old_created;
    write_superblock_copies(&path, &superblock);

    let error = ZoneFile::open(&path, reader_cfg()).unwrap_err();
    match error {
        ZoneFileError::RolledBackToInitial {
            instance_uuid: uuid,
            created_unix_ns,
        } => {
            assert_eq!(uuid, instance_uuid);
            assert_eq!(created_unix_ns, old_created);
        }
        other => panic!("unexpected error: {other}"),
    }

    let allowed = ZoneFile::open(
        &path,
        OpenConfig {
            allow_rollback_to_initial: true,
            ..reader_cfg()
        },
    )
    .unwrap();
    assert!(allowed.meta().needs_fsck());
    assert_eq!(allowed.meta().txnid, 1);
}

#[test]
fn created_file_and_lock_have_private_permissions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 4096, 64);
    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let lock = lock_path(&path);
    let lock_mode = fs::metadata(&lock).unwrap().permissions().mode() & 0o777;
    assert_eq!(lock_mode, 0o600);
    drop(zonefile);
}

#[test]
fn snapshots_are_reflected_in_reader_table() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 4096, 64);
    let txnid = zonefile.txnid();
    let table = zonefile.reader_table();

    assert_eq!(table.oldest_reader_txn(txnid), txnid);
    let reader = zonefile.reader();
    let snapshot = reader.snapshot().unwrap();
    assert_eq!(snapshot.txnid(), txnid);
    assert_eq!(table.registered_slots(), 1);
    assert_eq!(table.oldest_reader_txn(99), txnid);

    let cloned = snapshot.clone();
    drop(snapshot);
    assert_eq!(table.registered_slots(), 1);
    assert_eq!(table.oldest_reader_txn(99), txnid);

    drop(cloned);
    assert_eq!(table.registered_slots(), 0);
    assert_eq!(table.oldest_reader_txn(99), 99);
}

#[test]
fn per_thread_snapshot_limit_is_enforced() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 4096, 64);
    let reader = zonefile.reader();
    let snapshots: Vec<_> = (0..c::READER_SLOTS_PER_THREAD)
        .map(|_| reader.snapshot().unwrap())
        .collect();
    assert!(matches!(
        reader.snapshot(),
        Err(ZoneFileError::ReaderContended)
    ));
    drop(snapshots);
    let _snapshot = reader.snapshot().unwrap();
}

#[test]
fn corrupt_reader_descriptor_rejects_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 4096, 64);
    drop(zonefile);
    write_at(&path, u64::from(c::PAGE_READER_TABLE) * 4096, &[0_u8; 4]);
    match ZoneFile::open(&path, reader_cfg()) {
        Err(ZoneFileError::Corrupt { kind, detail, .. }) => {
            assert_eq!(kind, CorruptKind::Bounds);
            assert_eq!(detail, CorruptDetail::BadReaderRegion);
        }
        other => panic!("unexpected result: {other:?}"),
    }
}

#[test]
fn corrupt_superblock_a_falls_back_to_valid_b() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 4096, 64);
    drop(zonefile);
    write_at(&path, 0, &[0_u8; 8]);
    let reopened = ZoneFile::open(&path, reader_cfg()).unwrap();
    assert_eq!(reopened.superblock().page_size, 4096);
    assert_eq!(reopened.txnid(), 1);
}

#[test]
fn corrupt_superblock_copies_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 4096, 64);
    let page_size = zonefile.superblock().page_size;
    drop(zonefile);
    write_at(&path, 0, &[0_u8; 8]);
    write_at(&path, u64::from(page_size), &[0_u8; 8]);
    match ZoneFile::open(&path, reader_cfg()) {
        Err(ZoneFileError::Corrupt { kind, detail, .. }) => {
            assert_eq!(kind, CorruptKind::NoValidMeta);
            assert_eq!(detail, CorruptDetail::BadMagic);
        }
        other => panic!("unexpected result: {other:?}"),
    }
}

#[test]
fn reader_region_alignment_is_validated() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 4096, 64);
    let mut superblock = *zonefile.superblock();
    drop(zonefile);
    superblock.reader_region_off += 64;
    write_superblock_copies(&path, &superblock);
    assert!(matches!(
        ZoneFile::open(&path, reader_cfg()),
        Err(ZoneFileError::Corrupt {
            kind: CorruptKind::Bounds,
            ..
        })
    ));
}

#[test]
fn meta_getter_and_page_access_are_consistent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 8192, 64);
    let meta_page = read_at(&path, u64::from(c::PAGE_META_A) * 8192, 8192);
    let decoded = Meta::decode(
        &meta_page,
        c::PAGE_META_A,
        zonefile.superblock().page_size,
        zonefile.superblock().page_count_max,
    )
    .unwrap();
    assert_eq!(decoded, *zonefile.meta());
    assert_eq!(zonefile.superblock().page_size, 8192);
    assert_eq!(zonefile.superblock().reader_region_off, 32_768);
    assert_eq!(zonefile.superblock().reader_region_len, 40_960);
}

#[test]
fn zonefile_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ZoneFile>();
    assert_send_sync::<pulse_zonefile::ReaderTable>();
    assert_send_sync::<pulse_zonefile::Snapshot>();
}

fn write_slot(path: &Path, page_size: u32, slot: u32, owner: u64, active: u64, flags: u64) {
    let slots_per_page = (page_size - 32) / 32;
    let page_no = c::PAGE_READER_TABLE + slot / slots_per_page;
    let base =
        u64::from(page_no) * u64::from(page_size) + 32 + u64::from(slot % slots_per_page) * 32;
    write_at(path, base, &owner.to_le_bytes());
    write_at(path, base + 8, &active.to_le_bytes());
    write_at(path, base + 24, &flags.to_le_bytes());
}

fn current_owner_token() -> u64 {
    let stat = fs::read_to_string("/proc/self/stat").unwrap();
    let tail = stat.rsplit_once(')').unwrap().1;
    let starttime = tail
        .split_whitespace()
        .nth(19)
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let incarnation = u32::try_from(starttime & u64::from(u32::MAX)).unwrap();
    (u64::from(std::process::id()) << 32) | u64::from(incarnation)
}

fn current_incarnation() -> u32 {
    let stat = fs::read_to_string("/proc/self/stat").unwrap();
    let tail = stat.rsplit_once(')').unwrap().1;
    let starttime = tail
        .split_whitespace()
        .nth(19)
        .unwrap()
        .parse::<u64>()
        .unwrap();
    u32::try_from(starttime & u64::from(u32::MAX)).unwrap()
}

fn slot_bytes(path: &Path, page_size: u32, slot: u32) -> Vec<u8> {
    let slots_per_page = (page_size - 32) / 32;
    let page_no = c::PAGE_READER_TABLE + slot / slots_per_page;
    let offset =
        u64::from(page_no) * u64::from(page_size) + 32 + u64::from(slot % slots_per_page) * 32;
    read_at(path, offset, 32)
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

#[test]
fn unsupported_version_in_superblock_copy_is_not_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 4096, 64);
    let superblock = *zonefile.superblock();
    drop(zonefile);

    let mut version_two = superblock;
    version_two.version_major = 2;
    let record = version_two.encode();
    write_at(&path, 0, &record);
    match ZoneFile::open(&path, reader_cfg()) {
        Err(ZoneFileError::UnsupportedVersion { found, .. }) => {
            assert_eq!(found.major, 2);
        }
        other => panic!("unexpected result: {other:?}"),
    }

    // B с неподдерживаемой версией при валидной A.
    write_at(&path, 0, &superblock.encode());
    write_at(
        &path,
        u64::from(superblock.page_size),
        &version_two.as_copy_b().encode(),
    );
    assert!(matches!(
        ZoneFile::open(&path, reader_cfg()),
        Err(ZoneFileError::UnsupportedVersion { found, .. }) if found.major == 2
    ));
}

#[test]
fn superblock_b_nonzero_section_pad_is_corrupt_not_absent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 4096, 64);
    let page_size = zonefile.superblock().page_size;
    drop(zonefile);
    let mut record = read_at(&path, u64::from(page_size), 4096);
    record[112 + 12] = 0xAA;
    let crc = pulse_zonefile::checksum::page_crc32c(&record, 40).unwrap();
    record[40..44].copy_from_slice(&crc.to_le_bytes());
    write_at(&path, u64::from(page_size), &record);
    assert!(matches!(
        ZoneFile::open(&path, reader_cfg()),
        Err(ZoneFileError::Corrupt {
            kind: CorruptKind::Bounds,
            ..
        })
    ));
}

#[test]
fn superblock_b_valid_crc_but_wrong_copy_flag_is_corrupt() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 4096, 64);
    let superblock = *zonefile.superblock();
    drop(zonefile);
    // Страница 1: валидный CRC, но superblock_copy=0 (не B).
    write_at(&path, u64::from(superblock.page_size), &superblock.encode());
    assert!(matches!(
        ZoneFile::open(&path, reader_cfg()),
        Err(ZoneFileError::Corrupt {
            kind: CorruptKind::Bounds,
            ..
        })
    ));
}

#[test]
fn sync_mode_version_mismatch_between_copies_is_corrupt() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 4096, 64);
    let superblock = *zonefile.superblock();
    drop(zonefile);

    // A — новый формат (version 1), B — legacy (version 0, mode Sync допустим).
    let mut legacy_b = superblock.as_copy_b();
    legacy_b.sync_mode_version = 0;
    write_at(&path, 0, &superblock.encode());
    write_at(&path, u64::from(superblock.page_size), &legacy_b.encode());
    assert!(matches!(
        ZoneFile::open(&path, reader_cfg()),
        Err(ZoneFileError::Corrupt {
            kind: CorruptKind::Bounds,
            ..
        })
    ));

    // Обе копии legacy — валидный старый файл.
    let mut legacy_a = superblock;
    legacy_a.sync_mode_version = 0;
    write_superblock_copies(&path, &legacy_a);
    let reopened = ZoneFile::open(&path, reader_cfg()).unwrap();
    assert_eq!(
        reopened.superblock().sync_mode,
        pulse_zonefile::SyncMode::Sync
    );
    assert_eq!(reopened.superblock().sync_mode_version, 0);
}

#[test]
fn superblock_copy_layout_mismatch_is_corrupt() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 4096, 64);
    let superblock = *zonefile.superblock();
    drop(zonefile);
    let mut copy_b = superblock.as_copy_b();
    copy_b.feature_flags_optional = 1;
    write_at(&path, u64::from(superblock.page_size), &copy_b.encode());
    assert!(matches!(
        ZoneFile::open(&path, reader_cfg()),
        Err(ZoneFileError::Corrupt {
            kind: CorruptKind::Bounds,
            ..
        })
    ));
}

#[test]
fn unsupported_meta_version_is_not_fallen_back() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 4096, 64);
    let mut meta_a = *zonefile.meta();
    let mut meta_b = meta_a;
    let page_size = zonefile.superblock().page_size;
    drop(zonefile);

    meta_a.version_major = 2;
    write_at(
        &path,
        u64::from(c::PAGE_META_A) * u64::from(page_size),
        &meta_a.encode(),
    );
    meta_b.page_no = c::PAGE_META_B;
    meta_b.txnid = 2;
    meta_b.durable_txn = 2;
    write_at(
        &path,
        u64::from(c::PAGE_META_B) * u64::from(page_size),
        &meta_b.encode(),
    );

    assert!(matches!(
        ZoneFile::open(&path, reader_cfg()),
        Err(ZoneFileError::UnsupportedVersion { found, .. }) if found.major == 2
    ));
}

#[test]
fn reader_table_sanitizes_dead_and_stale_slots() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 4096, 64);
    drop(zonefile);

    let dead = (0xFFFF_FFFE_u64 << 32) | 7;
    write_slot(&path, 4096, 0, dead, 0, c::READER_FLAG_IN_PROCESS);
    let mismatched =
        (u64::from(std::process::id()) << 32) | u64::from(current_incarnation().wrapping_add(1));
    write_slot(&path, 4096, 1, mismatched, 0, c::READER_FLAG_IN_PROCESS);

    let zonefile = ZoneFile::open(&path, reader_cfg()).unwrap();
    for slot in [0, 1] {
        let bytes = slot_bytes(&path, 4096, slot);
        assert_eq!(u64_at(&bytes, 0), 0);
        assert_eq!(u64_at(&bytes, 8), 0);
        assert_eq!(u64_at(&bytes, 24), 0);
    }
    let page = read_at(&path, u64::from(c::PAGE_READER_TABLE) * 4096, 4096);
    assert_eq!(u32::from_le_bytes(page[12..16].try_into().unwrap()), 0);
    assert!(zonefile.meta().needs_fsck());
}

#[test]
fn reader_table_keeps_live_reader() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 4096, 64);
    drop(zonefile);

    let token = current_owner_token();
    write_slot(&path, 4096, 0, token, 1, c::READER_FLAG_IN_PROCESS);
    write_at(
        &path,
        u64::from(c::PAGE_READER_TABLE) * 4096 + 12,
        &1_u32.to_le_bytes(),
    );
    let zonefile = ZoneFile::open(&path, reader_cfg()).unwrap();
    let bytes = slot_bytes(&path, 4096, 0);
    assert_eq!(u64_at(&bytes, 0), token);
    assert_eq!(u64_at(&bytes, 8), 1);
    assert_eq!(u64_at(&bytes, 24), c::READER_FLAG_IN_PROCESS);
    assert_eq!(zonefile.reader_table().oldest_reader_txn(1), 1);
    let page = read_at(&path, u64::from(c::PAGE_READER_TABLE) * 4096, 4096);
    assert_eq!(u32::from_le_bytes(page[12..16].try_into().unwrap()), 1);
}

#[test]
fn live_reader_with_invalid_active_txn_is_corrupt() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 4096, 64);
    drop(zonefile);
    write_slot(
        &path,
        4096,
        0,
        current_owner_token(),
        2,
        c::READER_FLAG_IN_PROCESS,
    );
    assert!(matches!(
        ZoneFile::open(&path, reader_cfg()),
        Err(ZoneFileError::Corrupt {
            kind: CorruptKind::Bounds,
            detail: CorruptDetail::BadReaderRegion,
            ..
        })
    ));
}

#[test]
fn live_reader_with_reserved_flags_is_corrupt() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 4096, 64);
    drop(zonefile);
    write_slot(
        &path,
        4096,
        0,
        current_owner_token(),
        1,
        c::READER_FLAG_IN_PROCESS | (1 << 9),
    );
    assert!(matches!(
        ZoneFile::open(&path, reader_cfg()),
        Err(ZoneFileError::Corrupt { .. })
    ));
}

#[test]
fn dead_reader_with_bad_state_is_cleared_and_marks_fsck() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 4096, 64);
    drop(zonefile);
    let dead = (0xFFFF_FFFE_u64 << 32) | 7;
    write_slot(
        &path,
        4096,
        0,
        dead,
        2,
        c::READER_FLAG_IN_PROCESS | (1 << 9),
    );
    let zonefile = ZoneFile::open(&path, reader_cfg()).unwrap();
    assert!(zonefile.meta().needs_fsck());
    let bytes = slot_bytes(&path, 4096, 0);
    assert_eq!(u64_at(&bytes, 0), 0);
}

#[test]
fn longer_file_is_corrupt_bounds() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 4096, 64);
    let map_size = zonefile.superblock().map_size();
    drop(zonefile);
    let file = OpenOptions::new().write(true).open(&path).unwrap();
    file.set_len(map_size + 4096).unwrap();
    drop(file);
    assert!(matches!(
        ZoneFile::open(&path, reader_cfg()),
        Err(ZoneFileError::Corrupt {
            kind: CorruptKind::Bounds,
            ..
        })
    ));
}

#[test]
fn strict_mode_cannot_be_disabled_in_production() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 4096, 64);
    drop(zonefile);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        ZoneFile::open(&path, reader_cfg()),
        Err(ZoneFileError::Io(_))
    ));
    // Намеренная попытка ослабить проверки через публичный API не работает
    // в production-сборке (library скомпилирована без cfg(test)).
    assert!(matches!(
        ZoneFile::open(
            &path,
            OpenConfig {
                strict: false,
                ..reader_cfg()
            }
        ),
        Err(ZoneFileError::Io(_))
    ));
}

#[test]
fn symlink_is_rejected_as_not_regular_file() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real.zonefile");
    let link = dir.path().join("link.zonefile");
    let zonefile = create(&real, 4096, 64);
    drop(zonefile);
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert!(matches!(
        ZoneFile::open(&link, reader_cfg()),
        Err(ZoneFileError::NotRegularFile)
    ));
}

#[test]
fn directory_zone_file_is_not_regular_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    fs::create_dir(&path).unwrap();
    assert!(matches!(
        ZoneFile::open(&path, reader_cfg()),
        Err(ZoneFileError::NotRegularFile)
    ));
}

#[test]
fn fifo_zone_file_is_not_regular_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &path,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .unwrap();
    assert!(matches!(
        ZoneFile::open(&path, reader_cfg()),
        Err(ZoneFileError::NotRegularFile)
    ));
}

#[test]
fn reader_region_formula_mismatch_is_corrupt() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 4096, 64);
    let mut superblock = *zonefile.superblock();
    drop(zonefile);
    superblock.reader_region_len += 4096;
    write_superblock_copies(&path, &superblock);
    assert!(matches!(
        ZoneFile::open(&path, reader_cfg()),
        Err(ZoneFileError::Corrupt {
            kind: CorruptKind::Bounds,
            detail: CorruptDetail::BadReaderRegion,
            ..
        })
    ));
}

#[test]
fn reader_table_slots_used_overflow_is_corrupt() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 4096, 64);
    drop(zonefile);
    write_at(
        &path,
        u64::from(c::PAGE_READER_TABLE) * 4096 + 12,
        &9999_u32.to_le_bytes(),
    );
    assert!(matches!(
        ZoneFile::open(&path, reader_cfg()),
        Err(ZoneFileError::Corrupt {
            kind: CorruptKind::Bounds,
            detail: CorruptDetail::BadReaderRegion,
            ..
        })
    ));
}

#[test]
fn page_header_is_data_only_and_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 4096, 64);
    let data_first = zonefile.superblock().page_data_first;
    let high_water = zonefile.meta().page_count_high_water;
    assert_eq!(data_first, high_water);
    let reader = zonefile.reader();
    let snapshot = reader.snapshot().unwrap();
    for page_no in [
        c::PAGE_SUPERBLOCK_A,
        c::PAGE_META_A,
        c::PAGE_READER_TABLE,
        data_first - 1,
        data_first,
        high_water,
    ] {
        assert!(matches!(
            zonefile.page_header(&snapshot, page_no),
            Err(ZoneFileError::Corrupt { .. })
        ));
    }
    drop(snapshot);
    drop(reader);

    // high_water = data_first + 1: диапазон расширен, но нулевая страница —
    // невалидный PageHeader; за high_water — по-прежнему отказ.
    let mut meta = *zonefile.meta();
    meta.txnid = 2;
    meta.durable_txn = 2;
    meta.page_count_high_water = data_first + 1;
    drop(zonefile);
    write_at(&path, u64::from(c::PAGE_META_A) * 4096, &meta.encode());
    let zonefile = ZoneFile::open(&path, reader_cfg()).unwrap();
    assert_eq!(zonefile.meta().page_count_high_water, data_first + 1);
    let reader = zonefile.reader();
    let snapshot = reader.snapshot().unwrap();
    assert!(matches!(
        zonefile.page_header(&snapshot, data_first),
        Err(ZoneFileError::Corrupt { .. })
    ));
    assert!(matches!(
        zonefile.page_header(&snapshot, data_first + 1),
        Err(ZoneFileError::Corrupt { .. })
    ));
    assert!(matches!(
        zonefile.page_header(&snapshot, c::PAGE_READER_TABLE),
        Err(ZoneFileError::Corrupt { .. })
    ));
}

#[test]
fn snapshot_is_bound_to_its_zonefile() {
    let dir = tempfile::tempdir().unwrap();
    let path_a = dir.path().join("a.zonefile");
    let path_b = dir.path().join("b.zonefile");
    let a = create(&path_a, 4096, 64);
    {
        let b = create(&path_b, 4096, 64);
        let mut meta_b = *b.meta();
        drop(b);
        // B уходит на txn 2: снапшот A (txn 1) младше, но принадлежит другому
        // файлу — его пин не защищает страницы B.
        meta_b.page_no = c::PAGE_META_B;
        meta_b.txnid = 2;
        meta_b.durable_txn = 2;
        write_meta_slot(&path_b, &meta_b, 4096);
    }
    let b = ZoneFile::open(&path_b, reader_cfg()).unwrap();
    assert_eq!(b.txnid(), 2);
    let snapshot_a = a.reader().snapshot().unwrap();
    assert_eq!(snapshot_a.txnid(), 1);
    let data_first = b.superblock().page_data_first;
    assert!(matches!(
        b.page_header(&snapshot_a, data_first),
        Err(ZoneFileError::SnapshotFromDifferentFile)
    ));
    // Свой снапшот того же файла проходит проверку принадлежности: ошибка —
    // уже про диапазон/невалидную страницу, не про владельца.
    let snapshot_b = b.reader().snapshot().unwrap();
    assert!(matches!(
        b.page_header(&snapshot_b, data_first),
        Err(ZoneFileError::Corrupt { .. })
    ));
}

#[test]
fn minimal_sixteen_pages_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let config = CreateConfig {
        page_size: 4096,
        map_size: 16 * 4096,
        ..CreateConfig::default()
    };
    let zonefile = ZoneFile::create(&path, config).unwrap();
    assert_eq!(zonefile.superblock().page_count_max, 16);
    assert_eq!(zonefile.meta().page_count_high_water, 13);
    let reader = zonefile.reader();
    let snapshot = reader.snapshot().unwrap();
    assert!(zonefile.page_header(&snapshot, 0).is_err());
    assert!(zonefile.page_header(&snapshot, 12).is_err());
    assert!(zonefile.page_header(&snapshot, 13).is_err());
    drop(zonefile);
    let reopened = ZoneFile::open(&path, reader_cfg()).unwrap();
    assert_eq!(reopened.superblock().page_count_max, 16);
}

#[test]
fn reopen_works_for_8192_and_16384_pages() {
    for page_size in [8192_u32, 16_384] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(format!("zones-{page_size}.bin"));
        let zonefile = create(&path, page_size, 64);
        let meta = *zonefile.meta();
        assert_eq!(zonefile.superblock().page_size, page_size);
        drop(zonefile);
        let reopened = ZoneFile::open(&path, reader_cfg()).unwrap();
        assert_eq!(*reopened.meta(), meta);
        assert_eq!(
            reopened.superblock().reader_region_off,
            4 * u64::from(page_size)
        );
    }
}

#[test]
fn read_only_config_forbids_writer_lock_only() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 4096, 64);
    drop(zonefile);
    let reader = ZoneFile::open(
        &path,
        OpenConfig {
            read_only: true,
            ..reader_cfg()
        },
    )
    .unwrap();
    assert!(!reader.is_writer());
    drop(reader);
    assert!(matches!(
        ZoneFile::open(
            &path,
            OpenConfig {
                read_only: true,
                lock_mode: LockMode::Writer,
                ..reader_cfg()
            }
        ),
        Err(ZoneFileError::ReadOnly)
    ));
}

fn write_superblock_copies(path: &Path, superblock: &Superblock) {
    write_at(path, 0, &superblock.encode());
    write_at(
        path,
        u64::from(superblock.page_size),
        &superblock.as_copy_b().encode(),
    );
}

fn write_meta_slot(path: &Path, meta: &Meta, page_size: u32) {
    write_at(
        path,
        u64::from(meta.page_no) * u64::from(page_size),
        &meta.encode(),
    );
}

fn zonefile_with_unsynced_b(sync_mode: pulse_zonefile::SyncMode) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 4096, 64);
    let mut meta_b = *zonefile.meta();
    let mut superblock = *zonefile.superblock();
    drop(zonefile);

    meta_b.page_no = c::PAGE_META_B;
    meta_b.txnid = 2;
    meta_b.durable_txn = 1;
    write_meta_slot(&path, &meta_b, 4096);
    superblock.sync_mode = sync_mode;
    write_superblock_copies(&path, &superblock);
    (dir, path)
}

#[test]
fn flush_recovery_keeps_unsynced_commit_with_diagnostic() {
    let (_dir, path) = zonefile_with_unsynced_b(pulse_zonefile::SyncMode::MetaNoSync);
    let zonefile = ZoneFile::open(&path, reader_cfg()).unwrap();
    assert_eq!(zonefile.meta().txnid, 2);
    assert!(zonefile.recovered_unsynced());
    assert!(!zonefile.meta().needs_fsck());
}

#[test]
fn sync_recovery_keeps_unsynced_commit_with_diagnostic() {
    let (_dir, path) = zonefile_with_unsynced_b(pulse_zonefile::SyncMode::Sync);
    let zonefile = ZoneFile::open(&path, reader_cfg()).unwrap();
    assert_eq!(zonefile.meta().txnid, 2);
    assert!(zonefile.recovered_unsynced());
    assert!(!zonefile.meta().needs_fsck());
}

#[test]
fn memory_unsynced_recovery_falls_back_to_durable_meta() {
    let (_dir, path) = zonefile_with_unsynced_b(pulse_zonefile::SyncMode::NoSync);
    // Второй слот (txn 2, durable 1) отвергнут; durable-фолбэк — initial meta
    // txn 1. Это чистое открытие: данные txn 1 подтверждены, fsck не нужен.
    let zonefile = ZoneFile::open(&path, reader_cfg()).unwrap();
    assert_eq!(zonefile.meta().txnid, 1);
    assert_eq!(zonefile.meta().page_no, c::PAGE_META_A);
    assert!(!zonefile.recovered_unsynced());
    assert!(zonefile.memory_tail_discarded());
    assert!(!zonefile.meta().needs_fsck());
    assert!(!zonefile.is_write_locked());
}

#[test]
fn create_persists_sync_mode() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let config = CreateConfig {
        sync_mode: pulse_zonefile::SyncMode::MetaNoSync,
        map_size: 64 * 1024 * 1024,
        ..CreateConfig::default()
    };
    let zonefile = ZoneFile::create(&path, config).unwrap();
    assert_eq!(
        zonefile.superblock().sync_mode,
        pulse_zonefile::SyncMode::MetaNoSync
    );
    drop(zonefile);
    let zonefile = ZoneFile::open(&path, reader_cfg()).unwrap();
    assert_eq!(
        zonefile.superblock().sync_mode,
        pulse_zonefile::SyncMode::MetaNoSync
    );
}

#[test]
fn both_valid_metas_pick_newest() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 4096, 64);
    let mut meta_a = *zonefile.meta();
    let mut meta_b = meta_a;
    drop(zonefile);
    meta_a.txnid = 2;
    meta_a.durable_txn = 2;
    meta_b.page_no = c::PAGE_META_B;
    meta_b.txnid = 3;
    meta_b.durable_txn = 3;
    write_meta_slot(&path, &meta_a, 4096);
    write_meta_slot(&path, &meta_b, 4096);
    let zonefile = ZoneFile::open(&path, reader_cfg()).unwrap();
    assert_eq!(zonefile.meta().txnid, 3);
    assert_eq!(zonefile.meta().page_no, c::PAGE_META_B);
    assert!(!zonefile.meta().needs_fsck());
    assert!(!zonefile.recovered_unsynced());
}

#[test]
fn synced_commit_is_clean() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 4096, 64);
    let mut meta_b = *zonefile.meta();
    drop(zonefile);
    meta_b.page_no = c::PAGE_META_B;
    meta_b.txnid = 2;
    meta_b.durable_txn = 2;
    write_meta_slot(&path, &meta_b, 4096);
    let zonefile = ZoneFile::open(&path, reader_cfg()).unwrap();
    assert_eq!(zonefile.meta().txnid, 2);
    assert!(!zonefile.recovered_unsynced());
    assert!(!zonefile.meta().needs_fsck());
}

#[test]
fn empty_a_valid_b_selects_b_with_diagnostic() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 4096, 64);
    let mut meta_b = *zonefile.meta();
    drop(zonefile);
    write_at(&path, u64::from(c::PAGE_META_A) * 4096, &[0_u8; 4096]);
    meta_b.page_no = c::PAGE_META_B;
    meta_b.txnid = 3;
    meta_b.durable_txn = 3;
    write_meta_slot(&path, &meta_b, 4096);
    let zonefile = ZoneFile::open(&path, reader_cfg()).unwrap();
    assert_eq!(zonefile.meta().txnid, 3);
    assert_eq!(zonefile.meta().page_no, c::PAGE_META_B);
    assert!(zonefile.meta().needs_fsck());
}

#[test]
fn valid_a_empty_or_invalid_b_selects_a_with_diagnostic() {
    // A=Valid(txn2), B=Empty.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 4096, 64);
    let mut meta_a = *zonefile.meta();
    drop(zonefile);
    meta_a.txnid = 2;
    meta_a.durable_txn = 2;
    write_meta_slot(&path, &meta_a, 4096);
    let zonefile = ZoneFile::open(&path, reader_cfg()).unwrap();
    assert_eq!(zonefile.meta().txnid, 2);
    assert!(zonefile.meta().needs_fsck());
    drop(zonefile);

    // A=Valid(txn2), B=Invalid (непустая битая страница).
    write_at(&path, u64::from(c::PAGE_META_B) * 4096, &[0xAA_u8; 4096]);
    let zonefile = ZoneFile::open(&path, reader_cfg()).unwrap();
    assert_eq!(zonefile.meta().txnid, 2);
    assert_eq!(zonefile.meta().page_no, c::PAGE_META_A);
    assert!(zonefile.meta().needs_fsck());
}

#[test]
fn initial_empty_second_meta_is_not_fsck() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let zonefile = create(&path, 4096, 64);
    drop(zonefile);
    let zonefile = ZoneFile::open(&path, reader_cfg()).unwrap();
    assert!(!zonefile.meta().needs_fsck());
    assert!(!zonefile.recovered_unsynced());
}
