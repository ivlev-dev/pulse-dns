#![allow(missing_docs)]
//! B2a: кеш страниц, commit с рекламацией и `high_water` на 100k циклов.
//!
//! Запуск:
//!
//! ```text
//! cargo bench -p pulse-zonefile --bench v2_cache
//! ```

use std::hint::black_box;
use std::thread;

use criterion::Criterion;

use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    ParallelStore, ParallelZones, RrsetData, StoreConfig, ZoneCreateMeta,
};

fn data(value: u8) -> RrsetData {
    RrsetData::from_slices(60, 0, &[&[192, 0, 2, value]]).unwrap()
}

fn key(zone: usize, index: u32) -> NameRle {
    NameRle::from_ascii(&format!("k{index}.b{zone}.example")).unwrap()
}

fn origin(index: u32) -> NameRle {
    NameRle::from_ascii(&format!("b{index}.example")).unwrap()
}

struct Fixture {
    _dir: tempfile::TempDir,
    store: &'static ParallelStore,
    zones: &'static ParallelZones<'static>,
    origins: Vec<NameRle>,
}

fn setup(zones_count: u32, keys: u32, cache_entries: usize, pages: u32) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bench.v2");
    let mut config = StoreConfig::small(zones_count.saturating_add(2), pages);
    config.page_cache_entries = cache_entries;
    let store: &'static ParallelStore =
        Box::leak(Box::new(ParallelStore::create(&path, config).unwrap()));
    let mut zones = ParallelZones::open(store).unwrap();
    let mut origins = Vec::new();
    for index in 0..zones_count {
        let origin = origin(index);
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
    for (zone_index, origin) in origins.iter().enumerate() {
        let mut writer = zones.writer(origin).unwrap();
        for index in 0..keys {
            writer
                .upsert_rrset(&key(zone_index, index), 1, 0, &data(1))
                .unwrap();
        }
        writer.commit().unwrap();
    }
    let zones: &'static ParallelZones<'static> = Box::leak(Box::new(zones));
    Fixture {
        _dir: dir,
        store,
        zones,
        origins,
    }
}

fn bench_lookup(c: &mut Criterion) {
    let small = setup(1, 1, 1024, 1 << 20);
    let small_origin = small.origins[0];
    let cached = setup(1, 1000, 1024, 1 << 20);
    let uncached = setup(1, 1000, 0, 1 << 20);
    let origin = cached.origins[0];
    let origin_uncached = uncached.origins[0];
    let mut group = c.benchmark_group("pw_v2_read_cache");
    group.bench_function("per_request_shared_cache", |b| {
        let mut index = 0_u32;
        b.iter(|| {
            let reader = cached.store.reader().unwrap();
            let view = cached.zones.read(&reader, &origin).unwrap();
            let target = key(0, index % 1000);
            index = index.wrapping_add(1);
            black_box(view.lookup_ref(&target, 1, 0).unwrap().is_some())
        });
    });
    group.bench_function("per_request_no_cache", |b| {
        let mut index = 0_u32;
        b.iter(|| {
            let reader = uncached.store.reader().unwrap();
            let view = uncached.zones.read(&reader, &origin_uncached).unwrap();
            let target = key(0, index % 1000);
            index = index.wrapping_add(1);
            black_box(view.lookup_ref(&target, 1, 0).unwrap().is_some())
        });
    });
    group.bench_function("one_key_warm", |b| {
        let reader = small.store.reader().unwrap();
        let view = small.zones.read(&reader, &small_origin).unwrap();
        let target = key(0, 0);
        b.iter(|| black_box(view.lookup_ref(&target, 1, 0).unwrap().is_some()));
    });
    group.bench_function("zone_snapshot_only", |b| {
        let reader = small.store.reader().unwrap();
        b.iter(|| {
            let snapshot = small.store.zone_snapshot(&reader, 1).unwrap();
            black_box(snapshot.version())
        });
    });
    group.bench_function("warm_reused_snapshot", |b| {
        let reader = cached.store.reader().unwrap();
        let view = cached.zones.read(&reader, &origin).unwrap();
        let mut index = 0_u32;
        b.iter(|| {
            let target = key(0, index % 1000);
            index = index.wrapping_add(1);
            black_box(view.lookup_ref(&target, 1, 0).unwrap().is_some())
        });
    });
    group.finish();
    eprintln!(
        "cache stats: {:?}; node cache: {:?}",
        cached.store.page_cache_stats(),
        cached.store.node_cache_stats()
    );
}

fn bench_commit_reclaim(c: &mut Criterion) {
    let fixture = setup(8, 64, 1024, 1 << 20);
    let mut group = c.benchmark_group("pw_v2_commit_reclaim");
    group.sample_size(10);
    let fixture = &fixture;
    let origins = &fixture.origins;
    for threads in [1_usize, 4, 8] {
        group.bench_function(format!("{threads}_threads_x8_zones"), |b| {
            let round = std::sync::atomic::AtomicU8::new(0);
            b.iter(|| {
                let salt = round.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                thread::scope(|scope| {
                    for thread_index in 0..threads {
                        scope.spawn(move || {
                            for (zone_index, apex) in origins.iter().enumerate() {
                                if zone_index % threads != thread_index {
                                    continue;
                                }
                                let mut writer = fixture.zones.writer(apex).unwrap();
                                for cycle in 0..8_u32 {
                                    writer
                                        .upsert_rrset(
                                            &key(zone_index, cycle),
                                            1,
                                            0,
                                            &data(
                                                salt.wrapping_add(u8::try_from(cycle).unwrap_or(0)),
                                            ),
                                        )
                                        .unwrap();
                                    writer.commit().unwrap();
                                }
                                black_box(fixture.store.durable_page_limit());
                            }
                        });
                    }
                });
            });
        });
    }
    group.finish();
    eprintln!(
        "commit/reclaim stats: {:?}, free pool {} pages",
        fixture.store.stats(),
        fixture.store.free_pool_pages()
    );
}

/// 100k операций вставки/удаления: печатает `high_water` до/после.
/// 100k циклов обновления фиксированного набора: `high_water` до/после.
fn report_high_water() {
    const KEYS: u32 = 10_000;
    const CYCLES: u32 = 100_000;
    const BATCH: u32 = 1000;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hw.v2");
    let store = ParallelStore::create(&path, StoreConfig::small(8, 65_536)).unwrap();
    let apex = NameRle::from_ascii("hw.example").unwrap();
    let mut zones = ParallelZones::open(&store).unwrap();
    zones
        .create_zone(&apex, ZoneCreateMeta { soa_serial: 1 })
        .unwrap();
    let mut writer = zones.writer(&apex).unwrap();
    for chunk in 0..KEYS / BATCH {
        for offset in 0..BATCH {
            let index = chunk * BATCH + offset;
            let name = NameRle::from_ascii(&format!("h{index}.hw.example")).unwrap();
            writer
                .upsert_rrset(&name, 1, 0, &data(u8::try_from(index % 250).unwrap_or(0)))
                .unwrap();
        }
        writer.commit().unwrap();
    }
    let start_hw = store.high_water();
    let start = std::time::Instant::now();
    let mut cycle = 0_u32;
    while cycle < CYCLES {
        for _ in 0..BATCH {
            let index = cycle % KEYS;
            let name = NameRle::from_ascii(&format!("h{index}.hw.example")).unwrap();
            writer
                .upsert_rrset(&name, 1, 0, &data(u8::try_from(cycle % 250).unwrap_or(0)))
                .unwrap();
            if cycle.is_multiple_of(2) {
                let victim = cycle.saturating_add(KEYS / 2) % KEYS;
                let victim_name = NameRle::from_ascii(&format!("h{victim}.hw.example")).unwrap();
                let _ = writer.delete_rrset(&victim_name, 1, 0);
                writer
                    .upsert_rrset(
                        &victim_name,
                        1,
                        0,
                        &data(u8::try_from(cycle % 250).unwrap_or(0)),
                    )
                    .unwrap();
            }
            cycle += 1;
        }
        writer.commit().unwrap();
        if cycle == 10_000 || cycle == 50_000 {
            eprintln!(
                "high_water after {cycle} cycles: {} (free {}, reclaimed {})",
                store.high_water(),
                store.free_pool_pages(),
                store.stats().reclaimed_pages
            );
        }
    }
    eprintln!(
        "high_water before 100k cycles: {start_hw}; after: {} (free {}, reclaimed {}, elapsed {:?})",
        store.high_water(),
        store.free_pool_pages(),
        store.stats().reclaimed_pages,
        start.elapsed()
    );
    assert!(store.fsck_lite().unwrap().ok);
    assert!(store.fsck_graph().unwrap().ok);
}

fn main() {
    report_high_water();
    let mut criterion = Criterion::default().configure_from_args();
    bench_lookup(&mut criterion);
    bench_commit_reclaim(&mut criterion);
    criterion.final_summary();
}
