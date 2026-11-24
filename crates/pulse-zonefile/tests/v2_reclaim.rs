//! B2a: рекламация страниц — bucket/`free_head`, `is_reclaimable`, chain-GC,
//! tombstone/overflow, donation, property 10k insert/delete, пины читателей.
//!
//! Инварианты: страница, освобождённая в `V`, не выдаётся до durable `V+1`;
//! читатель с пином `V` не видит переиспользованных страниц; нет double-free
//! (`fsck_graph`); `high_water` на стабильной нагрузке не растёт.

use std::thread;

use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    OpenConfigV2, ParallelStore, ParallelZones, RrsetData, StoreConfig, ZoneCreateMeta,
    is_reclaimable,
};

fn rr(value: u8) -> RrsetData {
    RrsetData::from_slices(60, 0, &[&[192, 0, 2, value]]).unwrap()
}

fn name(prefix: &str, index: u32) -> NameRle {
    NameRle::from_ascii(&format!("{prefix}{index}.reclaim.example")).unwrap()
}

fn donor_name(index: u32) -> NameRle {
    NameRle::from_ascii(&format!("d{index}.donor.reclaim.example")).unwrap()
}

fn config(pages: u32) -> StoreConfig {
    StoreConfig::small(16, pages)
}

fn setup(pages: u32) -> (tempfile::TempDir, ParallelStore, NameRle) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("reclaim.v2");
    let store = ParallelStore::create(&path, config(pages)).unwrap();
    let apex = NameRle::from_ascii("reclaim.example").unwrap();
    {
        let mut zones = ParallelZones::open(&store).unwrap();
        zones
            .create_zone(&apex, ZoneCreateMeta { soa_serial: 1 })
            .unwrap();
    }
    (dir, store, apex)
}

#[test]
fn reclaim_rule_matches_spec() {
    assert!(!is_reclaimable(1, 10, 10, 10));
    assert!(!is_reclaimable(5, 5, 10, 10));
    assert!(is_reclaimable(5, 6, 5, 10));
    assert!(!is_reclaimable(6, 6, 10, 10));
    assert!(!is_reclaimable(5, 6, 4, 10));
    assert!(!is_reclaimable(5, 6, 10, 5));
    assert!(is_reclaimable(5, 6, 10, 6));
}

#[test]
fn steady_updates_reuse_pages_and_keep_high_water() {
    let (_dir, store, apex) = setup(4096);
    let zones = ParallelZones::open(&store).unwrap();
    let mut writer = zones.writer(&apex).unwrap();
    let key = name("k", 0);
    writer.upsert_rrset(&key, 1, 0, &rr(1)).unwrap();
    writer.commit().unwrap();
    let mut stable = 0_u64;
    for cycle in 0..300_u32 {
        writer
            .upsert_rrset(&key, 1, 0, &rr(u8::try_from(cycle % 250).unwrap_or(0)))
            .unwrap();
        writer.commit().unwrap();
        if cycle == 20 {
            stable = store.high_water();
        }
    }
    assert!(store.stats().reclaimed_pages > 0, "{:?}", store.stats());
    assert!(
        store.high_water() <= stable + 8,
        "high_water вырос: {stable} → {}",
        store.high_water()
    );
    assert!(store.free_pool_pages() > 0);
    assert!(store.fsck_lite().unwrap().ok);
    let graph = store.fsck_graph().unwrap();
    assert!(graph.ok, "{:?}", graph.issues);
}

#[test]
fn reader_pin_holds_version_and_blocks_reuse() {
    let (_dir, store, apex) = setup(4096);
    let zones = ParallelZones::open(&store).unwrap();
    let key = name("pin", 0);
    {
        let mut writer = zones.writer(&apex).unwrap();
        writer.upsert_rrset(&key, 1, 0, &rr(1)).unwrap();
        writer.commit().unwrap();
    }
    let reader = store.reader().unwrap();
    let pinned = zones.read(&reader, &apex).unwrap();
    let pinned_version = pinned.version();
    {
        let mut writer = zones.writer(&apex).unwrap();
        for value in 2..=4 {
            writer.upsert_rrset(&key, 1, 0, &rr(value)).unwrap();
            writer.commit().unwrap();
        }
    }
    // Пока пин жив, старая версия читается и её страницы не переиспользованы.
    assert_eq!(
        pinned.lookup(&key, 1, 0).unwrap().unwrap().rdata,
        vec![vec![192, 0, 2, 1]]
    );
    assert!(store.min_pinned(pinned.zone()) <= pinned_version);
    drop(pinned);
    assert_eq!(store.gc_pass().unwrap(), 1);
    let before = store.stats().reclaimed_pages;
    {
        let mut writer = zones.writer(&apex).unwrap();
        for value in 5..=7 {
            writer.upsert_rrset(&key, 1, 0, &rr(value)).unwrap();
            writer.commit().unwrap();
        }
    }
    assert!(
        store.stats().reclaimed_pages > before,
        "после снятия пина страницы не вернулись"
    );
    let fresh = zones.read(&reader, &apex).unwrap();
    assert_eq!(
        fresh.lookup(&key, 1, 0).unwrap().unwrap().rdata,
        vec![vec![192, 0, 2, 7]]
    );
    assert!(store.fsck_lite().unwrap().ok);
    assert!(store.fsck_graph().unwrap().ok);
}

#[test]
fn bounded_insert_delete_keeps_high_water() {
    run_insert_delete(1_000, 50);
}

/// Полный property-тест приёмки (10k + 10k). Тяжёлый в debug-профиле:
/// `cargo test -p pulse-zonefile --test v2_reclaim -- --ignored --nocapture`.
#[test]
#[ignore = "heavy: 10k insert + 10k delete; run with --ignored"]
fn ten_thousand_insert_delete_keeps_high_water_bounded() {
    run_insert_delete(10_000, 250);
}

fn run_insert_delete(keys: u32, per_commit: u32) {
    let keys_per_commit = per_commit.min(keys);
    let chunks = keys.div_ceil(keys_per_commit);
    let checkpoint = (chunks / 2).max(1);
    let (dir, store, apex) = setup(8192);
    let zones = ParallelZones::open(&store).unwrap();
    let mut writer = zones.writer(&apex).unwrap();
    let mut insert_mid = 0_u64;
    for chunk in 0..chunks {
        for offset in 0..keys_per_commit {
            let index = chunk * keys_per_commit + offset;
            if index >= keys {
                break;
            }
            writer
                .upsert_rrset(
                    &name("i", index),
                    1,
                    0,
                    &rr(u8::try_from(index % 250).unwrap_or(0)),
                )
                .unwrap();
        }
        writer.commit().unwrap();
        if chunk == checkpoint {
            insert_mid = store.high_water();
        }
    }
    let after_insert = store.high_water();
    assert!(
        after_insert <= insert_mid + 256,
        "high_water растёт на вставках: {insert_mid} → {after_insert}"
    );
    let mut delete_mid = 0_u64;
    for chunk in 0..chunks {
        for offset in 0..keys_per_commit {
            let index = chunk * keys_per_commit + offset;
            if index >= keys {
                break;
            }
            assert!(writer.delete_rrset(&name("i", index), 1, 0).unwrap());
        }
        writer.commit().unwrap();
        if chunk == checkpoint {
            delete_mid = store.high_water();
        }
    }
    let after_delete = store.high_water();
    assert!(
        after_delete <= delete_mid + 256,
        "high_water растёт на удалении: {delete_mid} → {after_delete}"
    );
    assert_eq!(writer.rrset_count(), 0);
    assert!(store.stats().reclaimed_pages > 0);
    drop(writer);
    let reader = store.reader().unwrap();
    let view = zones.read(&reader, &apex).unwrap();
    assert_eq!(view.records().unwrap().len(), 0);
    drop(view);
    assert!(
        store.fsck_lite().unwrap().ok,
        "{:?}",
        store.fsck_lite().unwrap().issues
    );
    let graph = store.fsck_graph().unwrap();
    assert!(graph.ok, "{:?}", graph.issues);
    assert!(graph.leaked_pages > 0 || graph.free_pages > 0);
    drop(reader);
    drop(zones);
    drop(store);
    let reopened =
        ParallelStore::open(&dir.path().join("reclaim.v2"), OpenConfigV2::default()).unwrap();
    assert!(reopened.fsck_lite().unwrap().ok);
    assert!(reopened.fsck_graph().unwrap().ok);
}

#[test]
fn overflow_chain_is_freed_on_replace() {
    let (_dir, store, apex) = setup(4096);
    let zones = ParallelZones::open(&store).unwrap();
    let key = name("of", 0);
    let large = vec![7_u8; 5000];
    {
        let mut writer = zones.writer(&apex).unwrap();
        writer
            .upsert_rrset(
                &key,
                16,
                0,
                &RrsetData::from_slices(60, 0, &[&large]).unwrap(),
            )
            .unwrap();
        writer.commit().unwrap();
        writer.upsert_rrset(&key, 16, 0, &rr(1)).unwrap();
        writer.commit().unwrap();
    }
    assert!(store.free_pool_pages() > 0);
    // Ещё один коммит, чтобы освобождённая цепочка стала выдаваемой, и
    // несколько апдейтов, которые её переиспользуют.
    {
        let mut writer = zones.writer(&apex).unwrap();
        for value in 2..=10 {
            writer.upsert_rrset(&key, 16, 0, &rr(value)).unwrap();
            writer.commit().unwrap();
        }
    }
    assert!(store.stats().reclaimed_pages > 0);
    assert!(store.fsck_lite().unwrap().ok);
    assert!(store.fsck_graph().unwrap().ok);
}

#[test]
fn tombstone_frees_zone_pages() {
    let (dir, store, apex) = setup(4096);
    let mut zones = ParallelZones::open(&store).unwrap();
    {
        let mut writer = zones.writer(&apex).unwrap();
        for index in 0..50 {
            writer
                .upsert_rrset(&name("t", index), 1, 0, &rr(1))
                .unwrap();
        }
        writer.commit().unwrap();
    }
    let before = store.free_pool_pages();
    zones.delete_zone(&apex).unwrap();
    assert!(
        store.free_pool_pages() > before,
        "tombstone не освободил страницы"
    );
    let reader = store.reader().unwrap();
    assert!(zones.read(&reader, &apex).is_err());
    drop(reader);
    assert!(store.fsck_lite().unwrap().ok);
    assert!(store.fsck_graph().unwrap().ok);
    drop(zones);
    drop(store);
    let reopened =
        ParallelStore::open(&dir.path().join("reclaim.v2"), OpenConfigV2::default()).unwrap();
    assert!(reopened.fsck_lite().unwrap().ok);
    assert!(reopened.fsck_graph().unwrap().ok);
}

#[test]
fn chain_gc_frees_evicted_root_pages() {
    let (_dir, store, apex) = setup(4096);
    let zones = ParallelZones::open(&store).unwrap();
    let key = name("c", 0);
    {
        let mut writer = zones.writer(&apex).unwrap();
        writer.upsert_rrset(&key, 1, 0, &rr(1)).unwrap();
        writer.commit().unwrap();
    }
    let reader = store.reader().unwrap();
    let pinned = zones.read(&reader, &apex).unwrap();
    {
        let mut writer = zones.writer(&apex).unwrap();
        for value in 2..=12 {
            writer.upsert_rrset(&key, 1, 0, &rr(value)).unwrap();
            writer.commit().unwrap();
        }
    }
    assert!(store.stats().chain_evictions > 0);
    drop(pinned);
    assert_eq!(store.gc_pass().unwrap(), 1);
    assert!(store.stats().chain_freed_pages > 0);
    {
        let mut writer = zones.writer(&apex).unwrap();
        for value in 13..=16 {
            writer.upsert_rrset(&key, 1, 0, &rr(value)).unwrap();
            writer.commit().unwrap();
        }
    }
    assert!(store.fsck_lite().unwrap().ok);
    assert!(store.fsck_graph().unwrap().ok);
    assert_eq!(
        zones
            .read(&reader, &apex)
            .unwrap()
            .lookup(&key, 1, 0)
            .unwrap()
            .unwrap()
            .rdata,
        vec![vec![192, 0, 2, 16]]
    );
}

#[test]
fn donation_moves_pages_between_zones() {
    let (_dir, store, apex_a) = setup(4096);
    let apex_b = NameRle::from_ascii("donor.reclaim.example").unwrap();
    let mut zones = ParallelZones::open(&store).unwrap();
    zones
        .create_zone(&apex_b, ZoneCreateMeta { soa_serial: 2 })
        .unwrap();
    {
        let mut writer = zones.writer(&apex_b).unwrap();
        for index in 0..400 {
            writer
                .upsert_rrset(&donor_name(index), 1, 0, &rr(1))
                .unwrap();
        }
        writer.commit().unwrap();
        for chunk in 0..4 {
            for offset in 0..100 {
                writer
                    .delete_rrset(&donor_name(chunk * 100 + offset), 1, 0)
                    .unwrap();
            }
            writer.commit().unwrap();
        }
        // Ещё один коммит, чтобы освобождённые страницы стали выдаваемыми.
        writer.upsert_rrset(&donor_name(999), 1, 0, &rr(2)).unwrap();
        writer.commit().unwrap();
        let donated = writer.donate(64).unwrap();
        assert!(donated > 0, "donation не забрала страницы");
        assert_eq!(store.donation_pages(), u64::from(donated));
    }
    drop(zones);
    let zones = ParallelZones::open(&store).unwrap();
    let high_before = store.high_water();
    let mut mid = 0_u64;
    {
        let mut writer = zones.writer(&apex_a).unwrap();
        for index in 0..24 {
            writer
                .upsert_rrset(&name("b", index), 1, 0, &rr(3))
                .unwrap();
            writer.commit().unwrap();
            if index == 8 {
                mid = store.high_water();
            }
        }
    }
    // Зона A не имела своего пула: страницы пришли из donation.
    assert!(store.stats().reclaimed_pages > 0);
    assert!(
        store.high_water() <= mid + 16,
        "donation не сдержала high_water: {mid} → {}",
        store.high_water()
    );
    assert!(store.high_water() <= high_before + 200);
    assert!(store.donation_pages() < store.stats().donated_pages);
    assert!(store.fsck_lite().unwrap().ok);
    assert!(store.fsck_graph().unwrap().ok);
}

#[test]
fn concurrent_writers_and_gc_keep_reads_valid() {
    const ZONES: u32 = 4;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("concurrent.v2");
    let store = ParallelStore::create(&path, config(32_768)).unwrap();
    let mut zones = ParallelZones::open(&store).unwrap();
    let mut origins = Vec::new();
    for index in 0..ZONES {
        let origin = NameRle::from_ascii(&format!("z{index}.reclaim.example")).unwrap();
        zones
            .create_zone(
                &origin,
                ZoneCreateMeta {
                    soa_serial: index + 1,
                },
            )
            .unwrap();
        origins.push(origin);
    }
    let keys: Vec<Vec<NameRle>> = origins
        .iter()
        .enumerate()
        .map(|(zone_index, _)| {
            (0..40)
                .map(|index| named(zone_index, index))
                .collect::<Vec<_>>()
        })
        .collect();
    let zones = &zones;
    let keys = &keys;
    let store_ref = &store;
    thread::scope(|scope| {
        for (zone_index, origin) in origins.iter().enumerate() {
            scope.spawn(move || {
                let mut writer = zones.writer(origin).unwrap();
                for cycle in 0..60_u32 {
                    let key = named(zone_index, cycle);
                    writer.upsert_rrset(&key, 1, 0, &rr(1)).unwrap();
                    writer.commit().unwrap();
                    if cycle % 7 == 0 {
                        let _ = writer.delete_rrset(&named(zone_index, cycle / 2), 1, 0);
                    }
                }
            });
        }
        scope.spawn(move || {
            for _ in 0..100 {
                let _ = store_ref.gc_pass();
            }
        });
        for (zone_index, origin) in origins.iter().enumerate() {
            scope.spawn(move || {
                let reader = store_ref.reader().unwrap();
                for cycle in 0..100_u32 {
                    let view = retry_read(zones, &reader, origin);
                    if let Some(record) = view
                        .lookup(
                            &keys[zone_index][usize::try_from(cycle % 40).unwrap()],
                            1,
                            0,
                        )
                        .unwrap()
                    {
                        assert_ne!(record.rdata.len(), 0);
                    }
                }
            });
        }
    });
    assert!(store.fsck_lite().unwrap().ok);
    assert!(store.fsck_graph().unwrap().ok);
}

fn named(zone: usize, index: u32) -> NameRle {
    NameRle::from_ascii(&format!("r{index}.z{zone}.reclaim.example")).unwrap()
}

fn retry_read<'a>(
    zones: &'a ParallelZones<'a>,
    reader: &'a pulse_zonefile::parallel::Reader<'a>,
    origin: &NameRle,
) -> pulse_zonefile::parallel::ZoneReader<'a> {
    for _ in 0..64 {
        match zones.read(reader, origin) {
            Ok(view) => return view,
            Err(pulse_zonefile::parallel::ParallelError::ReaderContended) => {
                std::thread::sleep(std::time::Duration::from_micros(50));
            }
            Err(error) => panic!("snapshot failed: {error:?}"),
        }
    }
    panic!("snapshot retry limit");
}
