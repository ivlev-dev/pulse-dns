//! Раскладка формата v2.0: golden-смещения, CRC, размеры, отказ на мусоре.

use static_assertions::const_assert_eq;
use std::mem::size_of;

use pulse_zonefile::parallel::consts::{
    ALLOC_RECORD_SIZE, LAYOUT_HEAD_RECORD_SIZE, PAGE_ALLOC_RECORD_A, PAGE_ALLOC_RECORD_B,
    PAGE_LAYOUT_HEAD_B, PAGE_SIZE_V2, PAGE_WRITER_REG, READER_SLOT_SIZE_V2, ROOT_ENTRY_SIZE,
};
use pulse_zonefile::parallel::{
    AllocRecord, ChainPage, FilePin, FileReaderSlot, Geometry, LayoutHead, RootEntry, RootFlags,
    RootState, SuperblockV2, SyncModeV2, WriterRegistry,
};

const_assert_eq!(size_of::<RootEntry>(), 64);
const_assert_eq!(ROOT_ENTRY_SIZE, 64);
const_assert_eq!(LAYOUT_HEAD_RECORD_SIZE, 512);
const_assert_eq!(ALLOC_RECORD_SIZE, 256);
const_assert_eq!(READER_SLOT_SIZE_V2, 128);

fn sample_root() -> RootEntry {
    RootEntry {
        crc32c: 0,
        owner_zone: 7,
        version: 42,
        root_page: 100,
        page_limit_at_commit: 120,
        prev_record: 90,
        meta_root: 101,
        ixfr_root: 0,
        deleted_txn: 0,
        rrset_count: 17,
        soa_serial: 20_260_101,
        free_head: 102,
        tree_level: 1,
        state: RootState::Serving,
        flags: RootFlags::empty().union(RootFlags::COMPACTION),
    }
}

#[test]
fn store_types_are_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<pulse_zonefile::parallel::ParallelStore>();
    assert_send_sync::<pulse_zonefile::parallel::Allocator>();
    assert_send_sync::<pulse_zonefile::parallel::PinTable>();
}

#[test]
fn root_entry_golden_offsets() {
    let raw = sample_root().encode();
    assert_eq!(raw.len(), 64);
    assert_eq!(u32::from_le_bytes(raw[4..8].try_into().unwrap()), 7);
    assert_eq!(u64::from_le_bytes(raw[8..16].try_into().unwrap()), 42);
    assert_eq!(u32::from_le_bytes(raw[16..20].try_into().unwrap()), 100);
    assert_eq!(u32::from_le_bytes(raw[20..24].try_into().unwrap()), 120);
    assert_eq!(u32::from_le_bytes(raw[24..28].try_into().unwrap()), 90);
    assert_eq!(u32::from_le_bytes(raw[32..36].try_into().unwrap()), 101);
    assert_eq!(u32::from_le_bytes(raw[36..40].try_into().unwrap()), 0);
    assert_eq!(u64::from_le_bytes(raw[40..48].try_into().unwrap()), 0);
    assert_eq!(u32::from_le_bytes(raw[48..52].try_into().unwrap()), 17);
    assert_eq!(
        u32::from_le_bytes(raw[52..56].try_into().unwrap()),
        20_260_101
    );
    assert_eq!(u32::from_le_bytes(raw[56..60].try_into().unwrap()), 102);
    assert_eq!(u16::from_le_bytes(raw[60..62].try_into().unwrap()), 1);
    assert_eq!(raw[62], 1);
    assert_eq!(raw[63], RootFlags::COMPACTION.bits());
    // CRC покрывает [4, 64) и не зависит от собственного поля.
    let crc = u32::from_le_bytes(raw[..4].try_into().unwrap());
    assert_eq!(crc, pulse_zonefile::checksum::crc32c(&raw[4..]));
}

#[test]
fn root_entry_roundtrip_and_torn_detection() {
    let entry = sample_root();
    let raw = entry.encode();
    let decoded = RootEntry::decode(&raw).unwrap();
    assert_eq!(decoded.owner_zone, entry.owner_zone);
    assert_eq!(decoded.version, entry.version);
    assert_eq!(decoded.state, RootState::Serving);
    assert!(decoded.flags.contains(RootFlags::COMPACTION));

    let mut torn = raw;
    torn[30] ^= 0x40;
    assert!(RootEntry::decode(&torn).is_none());

    let mut short = [0_u8; 63];
    short.copy_from_slice(&raw[..63]);
    assert!(RootEntry::decode(&short).is_none());
}

#[test]
fn root_entry_semantic_validation() {
    let mut entry = sample_root();
    assert!(entry.check_fields(1024).is_ok());

    entry.version = 1;
    assert!(entry.check_fields(1024).is_err());
    entry.version = 42;

    entry.state = RootState::Tombstone;
    assert!(entry.check_fields(1024).is_err());
    entry.deleted_txn = 42;
    assert!(entry.check_fields(1024).is_ok());
    entry.deleted_txn = 0;
    entry.state = RootState::Serving;

    entry.tree_level = 9;
    assert!(entry.check_fields(1024).is_err());
    entry.tree_level = 0;

    entry.root_page = entry.page_limit_at_commit;
    assert!(entry.check_fields(1024).is_err());
    entry.root_page = 100;

    entry.soa_serial = 0x8000_0000;
    assert!(entry.check_fields(1024).is_err());
    entry.soa_serial = 1;

    entry.ixfr_root = 5;
    assert!(entry.check_fields(1024).is_err());
    entry.ixfr_root = 0;

    entry.page_limit_at_commit = 0;
    assert!(entry.check_fields(1024).is_err());
}

#[test]
fn flags_reject_reserved_bits() {
    assert!(RootFlags::from_bits(0b111).is_some());
    assert!(RootFlags::from_bits(0b1000).is_none());
    let mut raw = sample_root().encode();
    raw[63] = 0x80;
    // Пересчитываем CRC, чтобы проверить именно отказ по флагам.
    let crc = pulse_zonefile::checksum::crc32c(&raw[4..]);
    raw[..4].copy_from_slice(&crc.to_le_bytes());
    assert!(RootEntry::decode(&raw).is_none());
}

#[test]
fn layout_head_roundtrip_and_page_identity() {
    let geometry = Geometry::new(64, 4096, 4096, 1024).unwrap();
    let head = LayoutHead::for_geometry(geometry, PAGE_LAYOUT_HEAD_B, 9, 3, 0);
    let raw = head.encode();
    assert_eq!(raw.len(), 512);
    let decoded = LayoutHead::decode(&raw).unwrap();
    assert_eq!(decoded.page_no, PAGE_LAYOUT_HEAD_B);
    assert_eq!(decoded.layout_seq, 9);
    assert_eq!(decoded.geometry, geometry);

    let mut wrong_page = raw;
    wrong_page[8..12].copy_from_slice(&PAGE_WRITER_REG.to_le_bytes());
    let crc = pulse_zonefile::checksum::page_crc32c(&wrong_page, 12).unwrap();
    wrong_page[12..16].copy_from_slice(&crc.to_le_bytes());
    assert!(LayoutHead::decode(&wrong_page).is_none());

    let mut dirty_reserved = raw;
    dirty_reserved[200] = 1;
    let crc = pulse_zonefile::checksum::page_crc32c(&dirty_reserved, 12).unwrap();
    dirty_reserved[12..16].copy_from_slice(&crc.to_le_bytes());
    assert!(LayoutHead::decode(&dirty_reserved).is_none());
}

#[test]
fn layout_geometry_is_fixed_and_ab_split() {
    let geometry = Geometry::new(65_536, 1 << 20, 4096, 1024).unwrap();
    assert_eq!(geometry.page_size(), 4096);
    assert_eq!(geometry.reader_pages(), 33);
    assert_eq!(geometry.root_dir_pages(), 4096);
    assert_eq!(geometry.page_root_dir_a_first(), 40);
    assert_eq!(geometry.page_root_dir_b_first(), 4136);
    assert_eq!(geometry.page_data_first(), 8232);
    assert_ne!(geometry.page_layout_head_a(), geometry.page_layout_head_b());
    assert_ne!(
        geometry.page_alloc_record_a(),
        geometry.page_alloc_record_b()
    );
    assert!(
        geometry.page_layout_head_b() - geometry.page_layout_head_a() >= 1,
        "A/B LayoutHead обязаны быть в разных 4 КиБ страницах"
    );
    assert!(
        geometry.page_alloc_record_b() - geometry.page_alloc_record_a() >= 1,
        "A/B ALLOC_RECORD обязаны быть в разных 4 КиБ страницах"
    );

    let small = Geometry::new(16, 4096, 8, 1024).unwrap();
    assert_eq!(small.root_dir_pages(), 1);
    assert_eq!(small.page_data_first(), 42);

    let slot = geometry.zone_slot(17).unwrap();
    assert_eq!(slot.page_a, 40 + 1);
    assert_eq!(slot.page_b, 4136 + 1);
    assert_eq!(slot.block_offset, 256);
    assert_eq!(slot.cell_offset(18), 256 + 2 * 64);
}

#[test]
fn alloc_record_roundtrip_and_two_copies() {
    let record = AllocRecord::new(PAGE_ALLOC_RECORD_A, 7, 42, 9);
    let raw = record.encode();
    assert_eq!(raw.len(), 256);
    let decoded = AllocRecord::decode(&raw, 4096).unwrap();
    assert_eq!(decoded, record);

    assert_ne!(PAGE_ALLOC_RECORD_A, PAGE_ALLOC_RECORD_B);
    let other = AllocRecord::new(PAGE_ALLOC_RECORD_B, 7, 42, 9);
    assert_eq!(
        AllocRecord::decode(&other.encode(), 4096).unwrap().page_no,
        PAGE_ALLOC_RECORD_B
    );

    let mut torn = raw;
    torn[100] ^= 1;
    assert!(AllocRecord::decode(&torn, 4096).is_none());

    let mut over = raw;
    over[24..32].copy_from_slice(&4097_u64.to_le_bytes());
    let crc = pulse_zonefile::checksum::page_crc32c(&over, 12).unwrap();
    over[12..16].copy_from_slice(&crc.to_le_bytes());
    assert!(AllocRecord::decode(&over, 4096).is_none());
}

#[test]
fn superblock_and_registry_roundtrip() {
    let geometry = Geometry::new(64, 4096, 4096, 1024).unwrap();
    let uuid = [7_u8; 16];
    let superblock = SuperblockV2::for_geometry(geometry, 0, uuid, SyncModeV2::Sync);
    let raw = superblock.encode();
    assert_eq!(raw.len(), 4096);
    let decoded = SuperblockV2::decode(&raw).unwrap();
    assert_eq!(decoded.magic, *b"PULSEZF2");
    assert_eq!(decoded.version_major, 2);
    assert_eq!(decoded.instance_uuid, uuid);
    decoded.verify(&geometry, geometry.file_size()).unwrap();

    let registry = WriterRegistry::default();
    let page = registry.encode();
    let decoded = WriterRegistry::decode(&page).unwrap();
    assert_eq!(decoded.leader_term, 1);
    assert_eq!(decoded.writer_count, 0);
}

#[test]
fn chain_page_roundtrip_and_ordering() {
    let mut entry = sample_root();
    entry.owner_zone = 3;
    entry.version = 10;
    entry.page_limit_at_commit = 200;
    entry.prev_record = 50;
    let chain = ChainPage {
        page_no: 100,
        owner_zone: 3,
        evicted_txn: 14,
        entry,
    };
    let raw = chain.encode();
    assert_eq!(raw.len(), 4096);
    assert_eq!(u32::from_le_bytes(raw[0..4].try_into().unwrap()), 11);
    assert_eq!(u32::from_le_bytes(raw[12..16].try_into().unwrap()), 0);
    let decoded = ChainPage::decode(&raw, 100).unwrap();
    assert_eq!(decoded.entry, entry);
    assert_eq!(decoded.evicted_txn, 14);

    assert!(ChainPage::decode(&raw, 101).is_none());

    let mut forward = entry;
    forward.prev_record = 150;
    let bad = ChainPage {
        page_no: 100,
        owner_zone: 3,
        evicted_txn: 14,
        entry: forward,
    };
    assert!(ChainPage::decode(&bad.encode(), 100).is_none());

    let mut torn = raw;
    torn[40] ^= 1;
    assert!(ChainPage::decode(&torn, 100).is_none());
}

#[test]
fn file_reader_slot_roundtrip() {
    let slot = FileReaderSlot {
        owner_token: 0xDEAD_BEEF_0000_0001,
        epoch: 99,
        n_pins: 2,
        kind: 1,
        flags: 0,
        heartbeat_unix_ns: 123,
        pins: [
            FilePin {
                zone_seq: 5,
                version: 10,
            },
            FilePin {
                zone_seq: 6,
                version: 11,
            },
            FilePin::default(),
            FilePin::default(),
            FilePin::default(),
            FilePin::default(),
        ],
    };
    let raw = slot.encode();
    assert_eq!(raw.len(), 128);
    let decoded = FileReaderSlot::decode(&raw).unwrap();
    assert_eq!(decoded, slot);

    let mut bad = raw;
    bad[20] = 1;
    assert!(FileReaderSlot::decode(&bad).is_none());
}

#[test]
fn geometry_rejects_out_of_contract_values() {
    assert!(Geometry::new(0, 4096, 4096, 1024).is_err());
    assert!(Geometry::new(64, 42, 4096, 1024).is_err());
    assert!(Geometry::new(64, 4096, 0, 1024).is_err());
    assert!(Geometry::new(64, 4096, 4097, 1024).is_err());
    assert!(Geometry::new(64, 4096, 4096, 0).is_err());
    assert!(Geometry::new(64, 4096, 4096, 4097).is_err());
    assert!(
        Geometry::new(64, 4096, 4096, 1024)
            .unwrap()
            .zone_slot(0)
            .is_err()
    );
    assert!(
        Geometry::new(64, 4096, 4096, 1024)
            .unwrap()
            .zone_slot(64)
            .is_err()
    );
}

#[test]
fn garbage_never_panics_decoders() {
    let mut state = 0x1234_5678_9ABC_DEF0_u64;
    for len in 0..=600_usize {
        let mut raw = vec![0_u8; len];
        for byte in &mut raw {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = (state & 0xFF) as u8;
        }
        let _ = RootEntry::decode(&raw);
        let _ = AllocRecord::decode(&raw, PAGE_SIZE_V2 * 1000);
        let _ = LayoutHead::decode(&raw);
        let _ = ChainPage::decode(&raw, 10);
        let _ = FileReaderSlot::decode(&raw);
        let _ = SuperblockV2::decode(&raw);
        let _ = WriterRegistry::decode(&raw);
    }
}
