//! Property-тесты: encode/decode, мусор без паник, аллокатор, ring select.

use std::collections::HashSet;

use proptest::prelude::*;

use pulse_zonefile::parallel::{
    AllocRecord, Allocator, ChainPage, Geometry, LayoutHead, ParallelStore, RootEntry, RootFlags,
    RootState, StoreConfig,
};

fn root_strategy() -> impl Strategy<Value = RootEntry> {
    (
        1_u32..1_000,
        2_u64..1_000_000,
        0_u32..64,
        1_u32..64,
        0_u32..64,
        0_u32..64,
        0_u32..64,
        0_u32..0x8000_0000,
        0_u16..=8,
        0_u8..3,
        0_u8..8,
    )
        .prop_map(
            |(
                owner,
                version,
                root_delta,
                meta_delta,
                free_delta,
                prev_delta,
                gap,
                serial,
                level,
                state,
                flags,
            )| {
                let limit = 200_u32;
                let state = match state {
                    0 => RootState::Init,
                    1 => RootState::Serving,
                    _ => RootState::Tombstone,
                };
                let flags = RootFlags::from_bits(flags & RootFlags::KNOWN).unwrap_or_default();
                RootEntry {
                    owner_zone: owner,
                    version,
                    page_limit_at_commit: limit,
                    root_page: 1 + root_delta % (limit - 1),
                    meta_root: 1 + meta_delta % (limit - 1),
                    free_head: 1 + free_delta % (limit - 1),
                    prev_record: 1 + prev_delta % (limit - 1),
                    deleted_txn: if state == RootState::Tombstone {
                        u64::from(1 + gap)
                    } else {
                        0
                    },
                    rrset_count: gap,
                    soa_serial: serial,
                    tree_level: level,
                    ixfr_root: 0,
                    state,
                    flags,
                    crc32c: 0,
                }
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn root_entry_roundtrip(entry in root_strategy()) {
        let raw = entry.encode();
        let decoded = RootEntry::decode(&raw).expect("CRC верной записи");
        prop_assert_eq!(decoded, entry);
        prop_assert_eq!(decoded.encode(), raw);
        prop_assert!(decoded.check_fields(1024).is_ok());
    }

    #[test]
    fn any_single_bit_flip_invalidates_root_crc(entry in root_strategy(), offset in 0_usize..64, bit in 0_u8..8) {
        let mut raw = entry.encode();
        raw[offset] ^= 1 << bit;
        prop_assert!(RootEntry::decode(&raw).is_none());
    }

    #[test]
    fn alloc_record_roundtrip(seq in 1_u64..u64::MAX, limit in 1_u64..100_000, txn in 1_u64..100_000, page in 0_u8..2) {
        let page_no = if page == 0 { 5 } else { 6 };
        let record = AllocRecord::new(page_no, seq, limit, txn);
        let raw = record.encode();
        let decoded = AllocRecord::decode(&raw, 100_000).expect("валидная запись");
        prop_assert_eq!(decoded, record);
    }

    #[test]
    fn layout_head_roundtrip(seq in 0_u64..u64::MAX, generation in 0_u64..u64::MAX) {
        let geometry = Geometry::new(64, 4096, 4096, 1024).unwrap();
        let head = LayoutHead::for_geometry(geometry, 2, seq, generation, 0);
        let raw = head.encode();
        let decoded = LayoutHead::decode(&raw).expect("валидная запись");
        prop_assert_eq!(decoded.layout_seq, seq);
        prop_assert_eq!(decoded.generation, generation);
        prop_assert_eq!(decoded.geometry, geometry);
    }

    #[test]
    fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        let _ = RootEntry::decode(&bytes);
        let _ = AllocRecord::decode(&bytes, 4096);
        let _ = LayoutHead::decode(&bytes);
        let _ = ChainPage::decode(&bytes, 7);
        let _ = pulse_zonefile::parallel::FileReaderSlot::decode(&bytes);
        let _ = pulse_zonefile::parallel::SuperblockV2::decode(&bytes);
        let _ = pulse_zonefile::parallel::WriterRegistry::decode(&bytes);
    }

    #[test]
    fn allocator_ranges_are_disjoint(sizes in prop::collection::vec(1_u32..=32, 1..200)) {
        let allocator = Allocator::new(100, 2, 100_000).unwrap();
        let mut seen = HashSet::new();
        let mut last_end = 100_u64;
        for size in sizes {
            let ticket = allocator.reserve_exact(size).unwrap();
            prop_assert_eq!(u64::from(ticket.first_page), last_end);
            last_end += u64::from(size);
            for page in ticket.first_page..=ticket.last_page() {
                prop_assert!(seen.insert(page));
            }
        }
        prop_assert_eq!(allocator.cursor(), last_end);
    }
}

fn publish(store: &ParallelStore, zone: u32, version: u64) -> Result<(), String> {
    let ticket = store.reserve_pages(1).map_err(|e| format!("{e:?}"))?;
    store
        .write_raw_page(ticket.first_page, b"prop")
        .map_err(|e| format!("{e:?}"))?;
    let entry = RootEntry {
        owner_zone: zone,
        version,
        root_page: ticket.first_page,
        state: RootState::Serving,
        ..RootEntry::default()
    };
    for _ in 0..32 {
        match store.publish_root(entry) {
            Ok(_) => return Ok(()),
            Err(pulse_zonefile::parallel::ParallelError::ReaderContended) => {}
            Err(error) => return Err(format!("{error:?}")),
        }
    }
    Err("retry limit".into())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn publish_and_select_never_returns_future_version(versions in prop::collection::vec(2_u64..40, 1..40)) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prop.v2");
        let store = ParallelStore::create(&path, StoreConfig::small(4, 4096)).unwrap();
        let mut sorted: Vec<u64> = versions;
        sorted.sort_unstable();
        sorted.dedup();
        for version in &sorted {
            publish(&store, 1, *version).unwrap();
            let head = store.select_root(1, u64::MAX).unwrap();
            prop_assert!(head.version >= *version);
        }
        let head = store.select_root(1, u64::MAX).unwrap();
        for ceiling in 0..head.version + 2 {
            match store.select_root(1, ceiling) {
                Ok(entry) => prop_assert!(entry.version <= ceiling),
                Err(pulse_zonefile::parallel::ParallelError::StaleRoot { .. }) => {}
                Err(error) => prop_assert!(false, "unexpected error: {error:?}"),
            }
        }
        let report = store.fsck_lite().unwrap();
        prop_assert!(report.ok, "fsck issues: {:?}", report.issues);
    }
}
