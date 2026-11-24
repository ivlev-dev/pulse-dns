//! B2a: кеш валидированных страниц v2 — общий для снапшотов, COW-ключи,
//! лимит/вытеснение, отключение кеша, конкурентные читатели.

use std::sync::Arc;
use std::thread;

use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    OpenConfigV2, ParallelStore, ParallelZones, RrsetData, StoreConfig, ZoneCreateMeta,
};

fn rr(value: u8) -> RrsetData {
    RrsetData::from_slices(60, 0, &[&[192, 0, 2, value]]).unwrap()
}

fn zone_config(entries: usize) -> StoreConfig {
    let mut config = StoreConfig::small(16, 65_536);
    config.page_cache_entries = entries;
    config
}

fn setup(entries: usize) -> (tempfile::TempDir, ParallelStore, NameRle, NameRle) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.v2");
    let store = ParallelStore::create(&path, zone_config(entries)).unwrap();
    let apex = NameRle::from_ascii("cache.example").unwrap();
    let name = NameRle::from_ascii("www.cache.example").unwrap();
    {
        let mut zones = ParallelZones::open(&store).unwrap();
        zones
            .create_zone(&apex, ZoneCreateMeta { soa_serial: 1 })
            .unwrap();
        let mut writer = zones.writer(&apex).unwrap();
        writer.upsert_rrset(&name, 1, 0, &rr(1)).unwrap();
        writer.commit().unwrap();
    }
    (dir, store, apex, name)
}

#[test]
fn shared_cache_avoids_revalidation_across_snapshots() {
    let (_dir, store, apex, name) = setup(1024);
    let zones = ParallelZones::open(&store).unwrap();
    // Первый снапшот: страницы читаются с диска и валидируются.
    {
        let reader = store.reader().unwrap();
        let view = zones.read(&reader, &apex).unwrap();
        assert_eq!(view.lookup_ref(&name, 1, 0).unwrap().unwrap().ttl, 60);
    }
    let after_first = store.page_cache_stats();
    assert!(after_first.misses > 0, "{after_first:?}");
    assert!(after_first.entries > 0);
    // Второй снапшот другой читатель: страницы уже валидированы.
    {
        let reader = store.reader().unwrap();
        let view = zones.read(&reader, &apex).unwrap();
        let hits_before = store.page_cache_stats().hits;
        assert_eq!(view.lookup_ref(&name, 1, 0).unwrap().unwrap().ttl, 60);
        assert!(
            store.page_cache_stats().hits > hits_before,
            "общий кеш не использован: {:?}",
            store.page_cache_stats()
        );
    }
    assert!(store.node_cache_stats().hits > 0);
    assert!(store.node_cache_stats().entries <= 1024, "лимит кеша узлов");
    assert!(store.fsck_lite().unwrap().ok);
    assert!(store.fsck_graph().unwrap().ok);
}

#[test]
fn cow_versions_are_not_confused() {
    let (_dir, store, apex, name) = setup(1024);
    let zones = ParallelZones::open(&store).unwrap();
    let reader = store.reader().unwrap();
    let old = zones.read(&reader, &apex).unwrap();
    assert_eq!(
        old.lookup(&name, 1, 0).unwrap().unwrap().rdata,
        vec![vec![192, 0, 2, 1]]
    );
    let old_version = old.version();
    {
        let mut writer = zones.writer(&apex).unwrap();
        writer.upsert_rrset(&name, 1, 0, &rr(2)).unwrap();
        writer.commit().unwrap();
    }
    // Старый пин видит старую версию, новый снапшот — новую.
    assert_eq!(
        old.lookup(&name, 1, 0).unwrap().unwrap().rdata,
        vec![vec![192, 0, 2, 1]]
    );
    {
        let reader2 = store.reader().unwrap();
        let new = zones.read(&reader2, &apex).unwrap();
        assert!(new.version() > old_version);
        assert_eq!(
            new.lookup(&name, 1, 0).unwrap().unwrap().rdata,
            vec![vec![192, 0, 2, 2]]
        );
    }
}

#[test]
fn disabled_cache_is_correct_and_uses_no_pages() {
    let (_dir, store, apex, name) = setup(0);
    let zones = ParallelZones::open(&store).unwrap();
    for _ in 0..3 {
        let reader = store.reader().unwrap();
        let view = zones.read(&reader, &apex).unwrap();
        assert_eq!(
            view.lookup(&name, 1, 0).unwrap().unwrap().rdata,
            vec![vec![192, 0, 2, 1]]
        );
    }
    let stats = store.page_cache_stats();
    assert_eq!(stats.entries, 0);
    assert_eq!(stats.capacity, 0);
    assert_eq!(store.node_cache_stats().capacity, 0);
}

#[test]
fn tiny_cache_evicts_and_stays_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tiny.v2");
    let store = ParallelStore::create(&path, zone_config(8)).unwrap();
    let apex = NameRle::from_ascii("tiny.example").unwrap();
    let mut zones = ParallelZones::open(&store).unwrap();
    zones
        .create_zone(&apex, ZoneCreateMeta { soa_serial: 1 })
        .unwrap();
    let mut writer = zones.writer(&apex).unwrap();
    for index in 0..300_u32 {
        let name = NameRle::from_ascii(&format!("n{index}.tiny.example")).unwrap();
        writer
            .upsert_rrset(&name, 1, 0, &rr(u8::try_from(index % 250).unwrap_or(0)))
            .unwrap();
        if index % 50 == 49 {
            writer.commit().unwrap();
        }
    }
    drop(writer);
    for _ in 0..20 {
        let reader = store.reader().unwrap();
        let view = zones.read(&reader, &apex).unwrap();
        let name = NameRle::from_ascii("n299.tiny.example").unwrap();
        assert!(view.lookup(&name, 1, 0).unwrap().is_some());
    }
    let stats = store.page_cache_stats();
    assert_eq!(stats.capacity, 8);
    assert!(stats.entries <= 8, "{stats:?}");
    assert!(stats.evictions > 0, "{stats:?}");
}

#[test]
fn concurrent_readers_share_cache_without_errors() {
    let (_dir, store, apex, _name) = setup(1024);
    let store = Arc::new(store);
    let zones = Arc::new(ParallelZones::open(&store).unwrap());
    thread::scope(|scope| {
        for thread_index in 0..8_u32 {
            let store = Arc::clone(&store);
            let zones = Arc::clone(&zones);
            scope.spawn(move || {
                let reader = store.reader().unwrap();
                for index in 0..200_u32 {
                    let name =
                        NameRle::from_ascii(&format!("t{thread_index}-{index}.cache.example"))
                            .unwrap();
                    let view = zones.read(&reader, &apex).unwrap();
                    // Ключа нет — проверяется корректность пути без паники.
                    assert!(view.lookup(&name, 1, 0).unwrap().is_none());
                }
            });
        }
    });
    assert!(store.page_cache_stats().hits > 0);
    assert!(store.fsck_lite().unwrap().ok);
    assert!(store.fsck_graph().unwrap().ok);
}

#[test]
fn reopen_keeps_cache_config_and_reads() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("reopen.v2");
    let apex = NameRle::from_ascii("cache.example").unwrap();
    let name = NameRle::from_ascii("www.cache.example").unwrap();
    {
        let store = ParallelStore::create(&path, zone_config(64)).unwrap();
        let mut zones = ParallelZones::open(&store).unwrap();
        zones
            .create_zone(&apex, ZoneCreateMeta { soa_serial: 1 })
            .unwrap();
        let mut writer = zones.writer(&apex).unwrap();
        writer.upsert_rrset(&name, 1, 0, &rr(9)).unwrap();
        writer.commit().unwrap();
    }
    let store = ParallelStore::open(
        &path,
        OpenConfigV2 {
            page_cache_entries: 64,
            ..OpenConfigV2::default()
        },
    )
    .unwrap();
    let zones = ParallelZones::open(&store).unwrap();
    let reader = store.reader().unwrap();
    let view = zones.read(&reader, &apex).unwrap();
    assert_eq!(
        view.lookup(&name, 1, 0).unwrap().unwrap().rdata,
        vec![vec![192, 0, 2, 9]]
    );
    assert_eq!(store.page_cache_stats().capacity, 64);
    assert!(store.fsck_lite().unwrap().ok);
    assert!(store.fsck_graph().unwrap().ok);
}
