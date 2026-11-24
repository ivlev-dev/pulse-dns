//! B1: зоны поверх `ParallelStore` — writer, per-zone commit, read snapshots,
//! каталог, конкурентность, reopen и негативы владельца/`txn`.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;

use pulse_zonefile::checksum;
use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    OpenConfigV2, ParallelError, ParallelStore, ParallelZones, PublishOutcome, RrsetData,
    StoreConfig, SyncModeV2, V2CorruptKind, ZoneCreateMeta,
};

const PAGE_OFF_TXN: usize = 16;
const PAGE_OFF_CRC32C: usize = 32;

fn config() -> StoreConfig {
    StoreConfig::small(32, 65_536)
}

fn origin(index: u32) -> NameRle {
    NameRle::from_ascii(&format!("z{index}.example")).unwrap()
}

/// Гасит флаг готовности при любом выходе (включая panic), чтобы поток-читатель
/// не завис в ожидании.
struct SignalOnDrop<'a>(&'a AtomicBool);

impl Drop for SignalOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

fn rr(ttl: u32, octets: &[u8]) -> RrsetData {
    RrsetData::from_slices(ttl, 0, &[octets]).unwrap()
}

#[test]
fn create_upsert_commit_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.v2");
    let store = ParallelStore::create(&path, config()).unwrap();
    let apex = NameRle::from_ascii("example.com").unwrap();
    let mut zones = ParallelZones::open(&store).unwrap();
    let seq = zones
        .create_zone(&apex, ZoneCreateMeta { soa_serial: 7 })
        .unwrap();
    assert_eq!(zones.zone_seq(&apex), Some(seq));
    assert_eq!(zones.origin(seq), Some(apex));
    {
        let mut writer = zones.writer(&apex).unwrap();
        let www = NameRle::from_ascii("www.example.com").unwrap();
        writer
            .upsert_rrset(&www, 1, 0, &rr(300, &[192, 0, 2, 1]))
            .unwrap();
        let outcome = writer.commit().unwrap();
        assert!(outcome.changed);
        assert_eq!(outcome.rrset_count, 1);
        assert!(!writer.commit().unwrap().changed);
    }
    let reader = store.reader().unwrap();
    let view = zones.read(&reader, &apex).unwrap();
    let www = NameRle::from_ascii("www.example.com").unwrap();
    let record = view.lookup(&www, 1, 0).unwrap().expect("rrset");
    assert_eq!(record.rdata, vec![vec![192, 0, 2, 1]]);
    assert_eq!(record.ttl, 300);
    drop(view);
    drop(reader);
    drop(zones);
    drop(store);

    let reopened = ParallelStore::open(&path, OpenConfigV2::default()).unwrap();
    let zones = ParallelZones::open(&reopened).unwrap();
    assert_eq!(zones.zone_seq(&apex), Some(seq));
    let info = zones.zones();
    assert_eq!(info.len(), 1);
    assert_eq!(info[0].rrset_count, 1);
    assert_eq!(info[0].soa_serial, 7);
    let reader = reopened.reader().unwrap();
    let view = zones.read(&reader, &apex).unwrap();
    assert!(view.lookup(&www, 1, 0).unwrap().is_some());
    assert!(reopened.fsck_lite().unwrap().ok);
}

#[test]
fn eight_zones_four_threads_no_loss() {
    const ZONES: u32 = 8;
    const THREADS: usize = 4;
    const COMMITS: usize = 12;
    const PER_COMMIT: usize = 4;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.v2");
    let store = ParallelStore::create(&path, config()).unwrap();
    let mut zones = ParallelZones::open(&store).unwrap();
    for index in 0..ZONES {
        zones
            .create_zone(
                &origin(index),
                ZoneCreateMeta {
                    soa_serial: index + 1,
                },
            )
            .unwrap();
    }
    thread::scope(|scope| {
        for thread_index in 0..THREADS {
            let zones = &zones;
            scope.spawn(move || {
                let mut handled = 0;
                for index in (u32::try_from(thread_index).unwrap()..ZONES).step_by(THREADS) {
                    let apex = origin(index);
                    let mut writer = zones.writer(&apex).unwrap();
                    for commit in 0..COMMITS {
                        for slot in 0..PER_COMMIT {
                            let name =
                                NameRle::from_ascii(&format!("r{commit}-{slot}.z{index}.example"))
                                    .unwrap();
                            let octets = [10, 0, 0, u8::try_from(commit).unwrap()];
                            writer.upsert_rrset(&name, 1, 0, &rr(60, &octets)).unwrap();
                        }
                        writer.commit().unwrap();
                        handled += 1;
                    }
                }
                handled
            });
        }
    });
    // Проверяем, что каждая зона содержит ровно свои 48 записей.
    for index in 0..ZONES {
        let apex = origin(index);
        let reader = store.reader().unwrap();
        let view = zones.read(&reader, &apex).unwrap();
        let records = view.records().unwrap();
        assert_eq!(records.len(), COMMITS * PER_COMMIT, "zone {index}");
        for commit in 0..COMMITS {
            for slot in 0..PER_COMMIT {
                let name =
                    NameRle::from_ascii(&format!("r{commit}-{slot}.z{index}.example")).unwrap();
                assert!(view.lookup(&name, 1, 0).unwrap().is_some(), "zone {index}");
            }
        }
        assert_eq!(u32::try_from(records.len()).unwrap(), 48);
    }
    drop(zones);
    drop(store);

    // Reopen: все зоны, каталог и heads на месте.
    let reopened = ParallelStore::open(&path, OpenConfigV2::default()).unwrap();
    let zones = ParallelZones::open(&reopened).unwrap();
    assert_eq!(zones.zones().len(), ZONES as usize);
    for index in 0..ZONES {
        let apex = origin(index);
        let seq = zones.zone_seq(&apex).unwrap();
        let head = reopened.select_root(seq, u64::MAX).unwrap();
        assert_eq!(head.rrset_count, 48);
        let reader = reopened.reader().unwrap();
        let view = zones.read(&reader, &apex).unwrap();
        assert_eq!(view.records().unwrap().len(), 48);
    }
    assert!(reopened.fsck_lite().unwrap().ok);
    assert!(reopened.durable_page_limit() > reopened.geometry().page_data_first().into());
}

#[test]
fn reader_sees_consistent_versions_during_commits() {
    const COMMITS: usize = 40;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.v2");
    let store = ParallelStore::create(&path, config()).unwrap();
    let apex = origin(0);
    let mut zones = ParallelZones::open(&store).unwrap();
    zones
        .create_zone(&apex, ZoneCreateMeta { soa_serial: 1 })
        .unwrap();

    // Первый коммит фиксирует базовую версию зоны (каталог уже не пишется).
    {
        let mut writer = zones.writer(&apex).unwrap();
        let name = NameRle::from_ascii("r0.z0.example").unwrap();
        writer.upsert_rrset(&name, 1, 0, &rr(60, &[0])).unwrap();
        writer.commit().unwrap();
    }

    let done = AtomicBool::new(false);
    let seen = AtomicU64::new(0);
    thread::scope(|scope| {
        let signal = SignalOnDrop(&done);
        let zones = &zones;
        let done = &done;
        let seen = &seen;
        let apex_ref = &apex;
        let store_ref = &store;
        let reader_thread = scope.spawn(move || {
            let reader = store_ref.reader().unwrap();
            let mut previous = 0_u64;
            while !done.load(Ordering::Acquire) {
                let view = match zones.read(&reader, apex_ref) {
                    Ok(view) => view,
                    Err(ParallelError::ReaderContended | ParallelError::ZoneDegraded { .. }) => {
                        continue;
                    }
                    Err(error) => panic!("reader failed: {error:?}"),
                };
                assert!(view.version() >= previous, "версия откатилась");
                previous = view.version();
                let records = view.records().unwrap();
                assert!(records.len() <= COMMITS);
                // Снапшот обязан быть префиксом r0..rN: ни дыр, ни полу-дерева.
                for index in 0..records.len() {
                    let name = NameRle::from_ascii(&format!("r{index}.z0.example")).unwrap();
                    assert!(
                        view.lookup(&name, 1, 0).unwrap().is_some(),
                        "version {} misses r{index}",
                        view.version()
                    );
                }
                if records.len() < COMMITS {
                    let missing =
                        NameRle::from_ascii(&format!("r{}.z0.example", records.len())).unwrap();
                    assert!(
                        view.lookup(&missing, 1, 0).unwrap().is_none(),
                        "version {} contains r{} too early",
                        view.version(),
                        records.len()
                    );
                }
                seen.fetch_max(view.version(), Ordering::AcqRel);
            }
        });
        {
            let mut writer = zones.writer(&apex).unwrap();
            for index in 1..COMMITS {
                let name = NameRle::from_ascii(&format!("r{index}.z0.example")).unwrap();
                writer
                    .upsert_rrset(&name, 1, 0, &rr(60, &[u8::try_from(index).unwrap()]))
                    .unwrap();
                writer.commit().unwrap();
            }
        }
        drop(signal);
        reader_thread.join().unwrap();
    });
    assert!(seen.load(Ordering::Acquire) > 0);
}

#[test]
fn same_zone_writers_serialize_without_loss() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.v2");
    let store = ParallelStore::create(&path, config()).unwrap();
    let apex = origin(0);
    let mut zones = ParallelZones::open(&store).unwrap();
    zones
        .create_zone(&apex, ZoneCreateMeta { soa_serial: 1 })
        .unwrap();
    thread::scope(|scope| {
        let zones = &zones;
        let apex_ref = &apex;
        let mut handles = Vec::new();
        for thread_index in 0..2_u32 {
            handles.push(scope.spawn(move || {
                let mut writer = zones.writer(apex_ref).unwrap();
                let name = NameRle::from_ascii(&format!("t{thread_index}.z0.example")).unwrap();
                writer
                    .upsert_rrset(&name, 1, 0, &rr(60, &[u8::try_from(thread_index).unwrap()]))
                    .unwrap();
                writer.commit().unwrap()
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
    });
    let reader = store.reader().unwrap();
    let view = zones.read(&reader, &apex).unwrap();
    assert_eq!(view.records().unwrap().len(), 2);
    for thread_index in 0..2_u32 {
        let name = NameRle::from_ascii(&format!("t{thread_index}.z0.example")).unwrap();
        assert!(view.lookup(&name, 1, 0).unwrap().is_some());
    }
}

#[test]
fn wildcard_ent_overflow_and_iterate() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.v2");
    let store = ParallelStore::create(&path, config()).unwrap();
    let apex = NameRle::from_ascii("example.com").unwrap();
    let mut zones = ParallelZones::open(&store).unwrap();
    zones
        .create_zone(&apex, ZoneCreateMeta { soa_serial: 9 })
        .unwrap();
    let apex_rr = NameRle::from_ascii("example.com").unwrap();
    let www = NameRle::from_ascii("www.example.com").unwrap();
    let wildcard = NameRle::from_ascii("*.example.com").unwrap();
    let deep = NameRle::from_ascii("a.b.example.com").unwrap();
    let big_name = NameRle::from_ascii("big.example.com").unwrap();
    let big_payload: Vec<Vec<u8>> = (0..4)
        .map(|index| vec![u8::try_from(index).unwrap(); 200])
        .collect();
    {
        let mut writer = zones.writer(&apex).unwrap();
        writer
            .upsert_rrset(&apex_rr, 1, 0, &rr(300, &[192, 0, 2, 1]))
            .unwrap();
        writer
            .upsert_rrset(&www, 1, 0, &rr(300, &[192, 0, 2, 2]))
            .unwrap();
        writer
            .upsert_rrset(&wildcard, 1, 0, &rr(120, &[192, 0, 2, 3]))
            .unwrap();
        writer
            .upsert_rrset(&deep, 1, 0, &rr(300, &[192, 0, 2, 4]))
            .unwrap();
        writer
            .upsert_rrset(
                &big_name,
                16,
                0,
                &RrsetData::new(60, 0, big_payload.clone()).unwrap(),
            )
            .unwrap();
        writer.commit().unwrap();
    }
    let reader = store.reader().unwrap();
    let view = zones.read(&reader, &apex).unwrap();
    let records = view.records().unwrap();
    assert_eq!(records.len(), 5);
    let node = view
        .node(&NameRle::from_ascii("b.example.com").unwrap())
        .unwrap();
    assert!(node.is_empty_non_terminal);
    assert!(node.has_children);
    assert!(node.exists, "ENT существует как T_NODE");
    assert!(view.node(&apex).unwrap().is_apex);
    assert!(view.node(&www).unwrap().exists);
    let wildcard_record = view.lookup(&wildcard, 1, 0).unwrap().unwrap();
    assert_eq!(wildcard_record.ttl, 120);
    assert!(wildcard_record.name.is_wildcard());
    let big = view.lookup(&big_name, 16, 0).unwrap().unwrap();
    assert_eq!(big.rdata.len(), 4);
    assert_eq!(big.rdata, big_payload);
    // next_name: канонический порядок без пропусков.
    let mut names = Vec::new();
    let mut after = None;
    while let Some(name) = view.next_name(after.as_ref()).unwrap() {
        names.push(name);
        after = Some(name);
    }
    assert!(names.contains(&www));
    assert!(names.contains(&wildcard));
    // Zero-alloc повторный lookup_ref: новые страницы не читаются.
    let warm = view.cached_pages();
    let first = view.lookup_ref(&www, 1, 0).unwrap().unwrap();
    let after_first = view.cached_pages();
    let second = view.lookup_ref(&www, 1, 0).unwrap().unwrap();
    assert_eq!(view.cached_pages(), after_first);
    assert_eq!(first.payload, second.payload);
    assert!(after_first >= warm);
}

#[test]
fn foreign_owner_and_page_txn_are_corrupt() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.v2");
    let store = ParallelStore::create(&path, config()).unwrap();
    let mut zones = ParallelZones::open(&store).unwrap();
    let apex_a = NameRle::from_ascii("a.example").unwrap();
    let apex_b = NameRle::from_ascii("b.example").unwrap();
    let apex_c = NameRle::from_ascii("c.example").unwrap();
    let _seq_a = zones
        .create_zone(&apex_a, ZoneCreateMeta { soa_serial: 1 })
        .unwrap();
    let seq_b = zones
        .create_zone(&apex_b, ZoneCreateMeta { soa_serial: 1 })
        .unwrap();
    let seq_c = zones
        .create_zone(&apex_c, ZoneCreateMeta { soa_serial: 1 })
        .unwrap();
    let name_a = NameRle::from_ascii("x.a.example").unwrap();
    let leaf_page = {
        let mut writer = zones.writer(&apex_a).unwrap();
        writer
            .upsert_rrset(&name_a, 1, 0, &rr(60, &[1, 2, 3, 4]))
            .unwrap();
        writer.commit().unwrap().root_page
    };
    assert_ne!(leaf_page, 0);

    // Зона B ссылается на страницу зоны A: чужой owner_zone.
    let head_b = store.select_root(seq_b, u64::MAX).unwrap();
    let foreign: PublishOutcome = store
        .publish_root(pulse_zonefile::parallel::RootEntry {
            owner_zone: seq_b,
            version: head_b.version + 1,
            root_page: leaf_page,
            tree_level: 1,
            state: pulse_zonefile::parallel::RootState::Serving,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(foreign.zone, seq_b);
    let reader = store.reader().unwrap();
    let view_b = zones.read(&reader, &apex_b).unwrap();
    let error = view_b.lookup(&name_a, 1, 0).unwrap_err();
    assert!(
        matches!(
            error,
            ParallelError::Corrupt {
                kind: V2CorruptKind::ForeignOwner,
                ..
            }
        ),
        "unexpected: {error:?}"
    );
    drop(view_b);

    // txn страницы больше версии головы: зона C получает чужую страницу с
    // валидным CRC по reserved1=0 и огромным txn.
    let head_c = store.select_root(seq_c, u64::MAX).unwrap();
    let ticket = store.reserve_pages(1).unwrap();
    let mut raw = store.read_raw_page(leaf_page).unwrap();
    raw[12..16].copy_from_slice(&[0, 0, 0, 0]);
    raw[PAGE_OFF_TXN..PAGE_OFF_TXN + 8]
        .copy_from_slice(&(head_c.version + 1_000_000).to_le_bytes());
    raw[PAGE_OFF_CRC32C..PAGE_OFF_CRC32C + 4].copy_from_slice(&[0, 0, 0, 0]);
    let crc = checksum::page_crc32c(&raw, PAGE_OFF_CRC32C).unwrap();
    raw[PAGE_OFF_CRC32C..PAGE_OFF_CRC32C + 4].copy_from_slice(&crc.to_le_bytes());
    // `owner_zone` живёт в reserved1 и не входит в CRC v2-страницы.
    raw[12..16].copy_from_slice(&seq_c.to_le_bytes());
    store.write_raw_page(ticket.first_page, &raw).unwrap();
    store
        .publish_root(pulse_zonefile::parallel::RootEntry {
            owner_zone: seq_c,
            version: head_c.version + 1,
            root_page: ticket.first_page,
            tree_level: 1,
            state: pulse_zonefile::parallel::RootState::Serving,
            ..Default::default()
        })
        .unwrap();
    let view_c = zones.read(&reader, &apex_c).unwrap();
    let error = view_c.lookup(&name_a, 1, 0).unwrap_err();
    assert!(
        matches!(
            error,
            ParallelError::Corrupt {
                kind: V2CorruptKind::PageTxn,
                ..
            }
        ),
        "unexpected: {error:?}"
    );
}

#[test]
fn delete_and_tombstone() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.v2");
    let store = ParallelStore::create(&path, config()).unwrap();
    let apex = origin(0);
    let mut zones = ParallelZones::open(&store).unwrap();
    zones
        .create_zone(&apex, ZoneCreateMeta { soa_serial: 1 })
        .unwrap();
    let one = NameRle::from_ascii("one.z0.example").unwrap();
    let two = NameRle::from_ascii("two.z0.example").unwrap();
    let three = NameRle::from_ascii("three.z0.example").unwrap();
    {
        let mut writer = zones.writer(&apex).unwrap();
        writer.upsert_rrset(&one, 1, 0, &rr(60, &[1])).unwrap();
        writer.upsert_rrset(&one, 28, 0, &rr(60, &[2])).unwrap();
        writer.upsert_rrset(&two, 1, 0, &rr(60, &[3])).unwrap();
        writer.upsert_rrset(&three, 1, 0, &rr(60, &[4])).unwrap();
        assert_eq!(writer.rrset_count(), 4);
        assert!(writer.delete_rrset(&one, 28, 0).unwrap());
        assert!(writer.delete_name(&three).unwrap());
        assert_eq!(writer.rrset_count(), 2);
        writer.commit().unwrap();
    }
    let reader = store.reader().unwrap();
    {
        let view = zones.read(&reader, &apex).unwrap();
        assert_eq!(view.records().unwrap().len(), 2);
        assert!(view.lookup(&one, 28, 0).unwrap().is_none());
        assert!(view.lookup(&three, 1, 0).unwrap().is_none());
    }
    let outcome = zones.delete_zone(&apex).unwrap();
    assert!(outcome.changed);
    assert_eq!(zones.zones(), vec![]);
    assert!(matches!(
        zones.read(&reader, &apex),
        Err(ParallelError::NoZoneVersion { .. })
    ));
    assert!(
        store
            .select_root(zones.zone_seq(&apex).unwrap(), u64::MAX)
            .unwrap()
            .is_tombstone()
    );
}

#[test]
fn durability_flush_and_memory_require_file_mode() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.v2");
    let store = ParallelStore::create(&path, config()).unwrap();
    let apex = origin(0);
    let mut zones = ParallelZones::open(&store).unwrap();
    zones
        .create_zone(&apex, ZoneCreateMeta { soa_serial: 1 })
        .unwrap();
    let mut writer = zones.writer(&apex).unwrap();
    let name = NameRle::from_ascii("one.z0.example").unwrap();
    writer.upsert_rrset(&name, 1, 0, &rr(60, &[1])).unwrap();
    // Файл создан в `Sync`: слабее липкого режима нельзя (§7.2).
    assert!(matches!(
        writer.commit_with(SyncModeV2::Flush),
        Err(ParallelError::DurabilityBelowFileMode { .. })
    ));
    assert!(matches!(
        writer.commit_with(SyncModeV2::Memory),
        Err(ParallelError::DurabilityBelowFileMode { .. })
    ));
    // `Sync` разрешён и публикует данные.
    let outcome = writer.commit().unwrap();
    assert!(outcome.changed);
    let view = {
        let reader = store.reader().unwrap();
        let view = zones.read(&reader, &apex).unwrap();
        assert!(view.lookup(&name, 1, 0).unwrap().is_some());
        view.version()
    };
    assert_eq!(view, outcome.version);
}

#[test]
fn empty_zone_iterates_and_commits() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.v2");
    let store = ParallelStore::create(&path, config()).unwrap();
    let apex = origin(0);
    let mut zones = ParallelZones::open(&store).unwrap();
    zones
        .create_zone(&apex, ZoneCreateMeta { soa_serial: 1 })
        .unwrap();
    let reader = store.reader().unwrap();
    {
        let view = zones.read(&reader, &apex).unwrap();
        assert_eq!(view.records().unwrap(), vec![]);
        assert!(view.next_name(None).unwrap().is_none());
    }
    {
        let mut writer = zones.writer(&apex).unwrap();
        assert_eq!(writer.records().unwrap().len(), 0);
        writer.commit().unwrap();
    }
}

#[test]
fn many_keys_split_and_reopen() {
    const KEYS: usize = 400;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.v2");
    let store = ParallelStore::create(&path, config()).unwrap();
    let apex = origin(0);
    let mut zones = ParallelZones::open(&store).unwrap();
    zones
        .create_zone(&apex, ZoneCreateMeta { soa_serial: 1 })
        .unwrap();
    {
        let mut writer = zones.writer(&apex).unwrap();
        for index in 0..KEYS {
            let name = NameRle::from_ascii(&format!("k{index:03}.z0.example")).unwrap();
            writer
                .upsert_rrset(
                    &name,
                    1,
                    0,
                    &rr(60, &[10, 0, u8::try_from(index % 250).unwrap(), 7]),
                )
                .unwrap();
            if index % 50 == 49 {
                writer.commit().unwrap();
            }
        }
        writer.commit().unwrap();
    }
    let reader = store.reader().unwrap();
    {
        let view = zones.read(&reader, &apex).unwrap();
        assert!(view.root().tree_level >= 1);
        let records = view.records().unwrap();
        assert_eq!(records.len(), KEYS);
        for index in 0..KEYS {
            let name = NameRle::from_ascii(&format!("k{index:03}.z0.example")).unwrap();
            assert!(view.lookup(&name, 1, 0).unwrap().is_some(), "k{index}");
        }
        // Удаление с перебалансировкой половины ключей + commit.
        drop(view);
        let mut writer = zones.writer(&apex).unwrap();
        for index in 0..KEYS / 2 {
            let name = NameRle::from_ascii(&format!("k{index:03}.z0.example")).unwrap();
            assert!(writer.delete_rrset(&name, 1, 0).unwrap());
        }
        writer.commit().unwrap();
    }
    drop(reader);
    drop(zones);
    drop(store);

    let reopened = ParallelStore::open(&path, OpenConfigV2::default()).unwrap();
    let zones = ParallelZones::open(&reopened).unwrap();
    let reader = reopened.reader().unwrap();
    let view = zones.read(&reader, &apex).unwrap();
    assert_eq!(view.records().unwrap().len(), KEYS / 2);
    for index in KEYS / 2..KEYS {
        let name = NameRle::from_ascii(&format!("k{index:03}.z0.example")).unwrap();
        assert!(view.lookup(&name, 1, 0).unwrap().is_some(), "k{index}");
    }
    assert!(reopened.fsck_lite().unwrap().ok);
}

#[test]
fn create_skips_orphan_zone_head() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.v2");
    let store = ParallelStore::create(&path, config()).unwrap();
    // Имитация краха между коммитом зоны и каталогом: голова слота 1 есть,
    // каталог пуст.
    store
        .publish_root(pulse_zonefile::parallel::RootEntry {
            owner_zone: 1,
            version: 2,
            root_page: 0,
            tree_level: 0,
            state: pulse_zonefile::parallel::RootState::Serving,
            ..Default::default()
        })
        .unwrap();
    let apex = origin(0);
    let mut zones = ParallelZones::open(&store).unwrap();
    assert_eq!(zones.zone_seq(&apex), None);
    let seq = zones
        .create_zone(&apex, ZoneCreateMeta { soa_serial: 1 })
        .unwrap();
    assert_eq!(
        seq, 2,
        "слот осиротевшей зоны 1 не должен переиспользоваться"
    );
    assert_eq!(zones.zone_seq(&apex), Some(2));
    assert_eq!(zones.zones().len(), 1);
}
