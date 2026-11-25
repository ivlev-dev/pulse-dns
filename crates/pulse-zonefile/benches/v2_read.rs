#![allow(missing_docs)]
#![allow(clippy::cast_precision_loss)]
//! Read-path v2: RRset/zone latency, zero-copy и аллокации на горячем пути.
//!
//! Запуск:
//!
//! ```text
//! cargo bench -p pulse-zonefile --bench v2_read
//! ```
//!
//! Бенч печатает `allocs/op` для warm `lookup_ref`, полного per-request
//! `lookup_ref` и материализующего `lookup`, а также размеры/статистику кешей.

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};

use criterion::{Criterion, criterion_group, criterion_main};

use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    ParallelStore, ParallelZones, RrsetData, StoreConfig, ZoneCreateMeta,
};

struct Counting;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

#[allow(unsafe_code)]
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc_zeroed(layout) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

const WIDE_KEYS: u32 = 5000;
const ZONES: u32 = 100;

fn rr(value: u8) -> RrsetData {
    RrsetData::from_slices(60, 0, &[&[192, 0, 2, value]]).unwrap()
}

fn big_rr() -> RrsetData {
    let payload = vec![0xAB_u8; 900];
    RrsetData::from_slices(60, 0, &[&payload]).unwrap()
}

fn key(zone: u32, index: u32) -> NameRle {
    NameRle::from_ascii(&format!("k{index}.w{zone}.example")).unwrap()
}

fn origin(index: u32) -> NameRle {
    NameRle::from_ascii(&format!("w{index}.example")).unwrap()
}

struct Fixture {
    _dir: tempfile::TempDir,
    store: &'static ParallelStore,
    zones: &'static ParallelZones<'static>,
    wide_origin: NameRle,
}

fn build(keys: u32, zones_count: u32, cache_entries: usize) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("read.v2");
    let mut config = StoreConfig::small(zones_count + 2, 1 << 20);
    config.page_cache_entries = cache_entries;
    let store: &'static ParallelStore =
        Box::leak(Box::new(ParallelStore::create(&path, config).unwrap()));
    let mut zones = ParallelZones::open(store).unwrap();
    for index in 0..zones_count {
        zones
            .create_zone(
                &origin(index),
                ZoneCreateMeta {
                    soa_serial: index + 1,
                },
            )
            .unwrap();
    }
    // Зона 0 — «широкая» (много страниц), остальные — по 8 ключей.
    for zone_index in 0..zones_count {
        let name = origin(zone_index);
        let mut writer = zones.writer(&name).unwrap();
        let count = if zone_index == 0 { keys } else { 8 };
        for index in 0..count {
            writer
                .upsert_rrset(&key(zone_index, index), 1, 0, &rr(1))
                .unwrap();
        }
        // Один overflow-RRset на зону.
        writer
            .upsert_rrset(&key(zone_index, u32::MAX), 16, 0, &big_rr())
            .unwrap();
        writer.commit().unwrap();
    }
    let zones: &'static ParallelZones<'static> = Box::leak(Box::new(zones));
    Fixture {
        _dir: dir,
        store,
        zones,
        wide_origin: origin(0),
    }
}

fn bench_lookup(c: &mut Criterion) {
    let fixture = build(WIDE_KEYS, ZONES, 1024);
    let reader = fixture.store.reader().unwrap();
    // Горячий одностраничный кейс: зона 1 (8 ключей).
    let hot_origin = origin(1);
    let hot = fixture.zones.read(&reader, &hot_origin).unwrap();
    let hot_key = key(1, 0);
    let hot_zone = fixture.zones.zone_seq(&hot_origin).unwrap();
    let wide = fixture.zones.read(&reader, &fixture.wide_origin).unwrap();
    let mut wide_index = 0_u32;

    let mut group = c.benchmark_group("v2_read");
    group.bench_function("rrset_warm_lookup_ref_single_page", |b| {
        b.iter(|| black_box(hot.lookup_ref(&hot_key, 1, 0).unwrap().is_some()));
    });
    group.bench_function("rrset_warm_lookup_ref_wide", |b| {
        b.iter(|| {
            let target = key(0, wide_index % WIDE_KEYS);
            wide_index = wide_index.wrapping_add(1);
            black_box(wide.lookup_ref(&target, 1, 0).unwrap().is_some())
        });
    });
    group.bench_function("rrset_warm_lookup_materialized", |b| {
        b.iter(|| {
            let target = key(0, wide_index % WIDE_KEYS);
            wide_index = wide_index.wrapping_add(1);
            black_box(wide.lookup(&target, 1, 0).unwrap())
        });
    });
    group.bench_function("rrset_overflow_lookup_ref", |b| {
        let target = key(0, u32::MAX);
        b.iter(|| black_box(wide.lookup_ref(&target, 16, 0).unwrap().is_some()));
    });
    group.bench_function("rrset_miss", |b| {
        let target = NameRle::from_ascii("absent.w0.example").unwrap();
        b.iter(|| black_box(wide.lookup_ref(&target, 1, 0).unwrap().is_none()));
    });
    group.bench_function("zone_snapshot_pin", |b| {
        b.iter(|| {
            let snapshot = fixture.store.zone_snapshot(&reader, hot_zone).unwrap();
            black_box(snapshot.version())
        });
    });
    group.bench_function("pin_guard_only", |b| {
        let zone = fixture.zones.zone_seq(&origin(1)).unwrap();
        let version = fixture
            .store
            .zone_snapshot(&reader, zone)
            .unwrap()
            .version();
        b.iter(|| {
            let pin = reader.pin(zone, version, 0);
            black_box(&pin);
        });
    });
    group.bench_function("head_read_only", |b| {
        b.iter(|| {
            let root = fixture.store.select_root(hot_zone, u64::MAX).unwrap();
            black_box(root.version)
        });
    });
    group.bench_function("zone_read_view", |b| {
        b.iter(|| {
            let view = fixture.zones.read(&reader, &hot_origin).unwrap();
            black_box(view.version())
        });
    });
    group.finish();

    // Полный per-request путь: новый reader + snapshot + lookup.
    let mut group = c.benchmark_group("v2_read_request");
    group.bench_function("full_lookup_ref_wide", |b| {
        let mut index = 0_u32;
        b.iter(|| {
            let reader = fixture.store.reader().unwrap();
            let view = fixture.zones.read(&reader, &fixture.wide_origin).unwrap();
            let target = key(0, index % WIDE_KEYS);
            index = index.wrapping_add(1);
            black_box(view.lookup_ref(&target, 1, 0).unwrap().is_some())
        });
    });
    group.finish();

    report_allocations(&fixture, &hot, &hot_key, &wide);
    report_latency(&hot, &hot_key, &wide);
}

/// p50/p99 по 200k итерациям (без criterion).
fn report_latency(
    hot: &pulse_zonefile::parallel::ZoneReader<'_>,
    hot_key: &NameRle,
    wide: &pulse_zonefile::parallel::ZoneReader<'_>,
) {
    const SAMPLES: usize = 200;
    const BATCH: usize = 1000;
    let wide_keys: Vec<NameRle> = (0..WIDE_KEYS).map(|index| key(0, index)).collect();
    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..100 {
        let _ = hot.lookup_ref(hot_key, 1, 0).unwrap();
    }
    for _ in 0..SAMPLES {
        let start = std::time::Instant::now();
        for _ in 0..BATCH {
            black_box(hot.lookup_ref(hot_key, 1, 0).unwrap());
        }
        let nanos = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
        samples.push(u32::try_from(nanos / BATCH as u64).unwrap_or(u32::MAX));
    }
    samples.sort_unstable();
    eprintln!(
        "latency single_page ns/op (batch {BATCH}): p50={} p99={}",
        samples[SAMPLES / 2],
        samples[SAMPLES * 99 / 100]
    );
    samples.clear();
    let mut cursor = 0_usize;
    for _ in 0..SAMPLES {
        let start = std::time::Instant::now();
        for _ in 0..BATCH {
            let target = &wide_keys[cursor % wide_keys.len()];
            cursor = cursor.wrapping_add(1);
            black_box(wide.lookup_ref(target, 1, 0).unwrap());
        }
        let nanos = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
        samples.push(u32::try_from(nanos / BATCH as u64).unwrap_or(u32::MAX));
    }
    samples.sort_unstable();
    eprintln!(
        "latency wide(5000) ns/op (batch {BATCH}): p50={} p99={}",
        samples[SAMPLES / 2],
        samples[SAMPLES * 99 / 100]
    );
}

fn report_allocations(
    fixture: &Fixture,
    hot: &pulse_zonefile::parallel::ZoneReader<'_>,
    hot_key: &NameRle,
    wide: &pulse_zonefile::parallel::ZoneReader<'_>,
) {
    const OPS: usize = 10_000;
    // Ключи предвычислены: `format!` в цикле сам аллоцирует и искажает счёт.
    let wide_keys: Vec<NameRle> = (0..WIDE_KEYS).map(|index| key(0, index)).collect();
    // Прогрев.
    for _ in 0..100 {
        let _ = hot.lookup_ref(hot_key, 1, 0).unwrap();
    }
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for _ in 0..OPS {
        black_box(hot.lookup_ref(hot_key, 1, 0).unwrap());
    }
    let warm = ALLOCATIONS.load(Ordering::Relaxed).saturating_sub(before) as f64 / OPS as f64;

    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for index in 0..OPS {
        black_box(
            wide.lookup_ref(&wide_keys[index % wide_keys.len()], 1, 0)
                .unwrap(),
        );
    }
    let wide_ref = ALLOCATIONS.load(Ordering::Relaxed).saturating_sub(before) as f64 / OPS as f64;

    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for index in 0..OPS {
        black_box(
            wide.lookup(&wide_keys[index % wide_keys.len()], 1, 0)
                .unwrap(),
        );
    }
    let materialized =
        ALLOCATIONS.load(Ordering::Relaxed).saturating_sub(before) as f64 / OPS as f64;

    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for index in 0..OPS {
        let reader = fixture.store.reader().unwrap();
        let view = fixture.zones.read(&reader, &fixture.wide_origin).unwrap();
        black_box(
            view.lookup_ref(&wide_keys[index % wide_keys.len()], 1, 0)
                .unwrap(),
        );
    }
    let request = ALLOCATIONS.load(Ordering::Relaxed).saturating_sub(before) as f64 / OPS as f64;
    eprintln!(
        "allocs/op: warm_ref={warm:.2} wide_ref={wide_ref:.2} materialized={materialized:.2} full_request={request:.2}"
    );
    eprintln!(
        "cache: page={:?} node={:?}",
        fixture.store.page_cache_stats(),
        fixture.store.node_cache_stats()
    );
}

criterion_group!(benches, bench_lookup);
criterion_main!(benches);
