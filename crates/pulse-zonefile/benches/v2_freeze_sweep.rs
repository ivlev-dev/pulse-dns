//! Bench: shared freeze overhead, онлайн-sweep throughput и commit p99 при
//! параллельном sweep.
//!
//! Запуск:
//! `cargo bench -p pulse-zonefile --bench v2_freeze_sweep`
//!
//! Переменные:
//! * `PULSE_FS_SWEEP_PAGES` — страниц-утечек на один замер (по умолчанию 512);
//! * `PULSE_FS_COMMIT_ITERS` — коммитов в замере p99 (по умолчанию 2000).

#![allow(missing_docs)]

use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    ParallelStore, ParallelZones, RrsetData, StoreConfig, SweepConfig, SyncModeV2, ZoneCreateMeta,
};

fn multi_config() -> StoreConfig {
    StoreConfig {
        multi_process: true,
        sync_mode: SyncModeV2::Sync,
        ..StoreConfig::small(8, 1 << 20)
    }
}

fn origin() -> NameRle {
    NameRle::from_ascii("bench.benchmark.example").unwrap()
}

fn key(item: u32) -> NameRle {
    NameRle::from_ascii(&format!("k{item}.bench.benchmark.example")).unwrap()
}

fn rr(value: u8) -> RrsetData {
    RrsetData::from_slices(60, 0, &[&[192, 0, 2, value]]).unwrap()
}

fn seed(store: &ParallelStore) -> u32 {
    let mut zones = ParallelZones::open(store).unwrap();
    let seq = zones
        .create_zone(&origin(), ZoneCreateMeta { soa_serial: 1 })
        .unwrap();
    let mut writer = zones.writer_by_seq(seq).unwrap();
    for item in 0..128 {
        writer
            .upsert_rrset(
                &key(item),
                1,
                0,
                &rr(u8::try_from(item % 250 + 1).unwrap_or(1)),
            )
            .unwrap();
    }
    writer.commit().unwrap();
    seq
}

fn leak(store: &ParallelStore, pages: u32) {
    let ticket = store.reserve_pages(pages).unwrap();
    for page in ticket.first_page..=ticket.last_page() {
        store.write_raw_page(page, b"bench leaked page").unwrap();
    }
    store.sync().unwrap();
}

fn bench_freeze(criterion: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("freeze-bench.v2");
    let store = ParallelStore::create(&path, multi_config()).unwrap();
    seed(&store);
    criterion.bench_function("freeze_acquire_release_multi", |bencher| {
        bencher.iter(|| {
            let guard = store.freeze().unwrap();
            black_box(guard.epoch());
        });
    });
    // Локальный (single-process) путь.
    let single_dir = tempfile::tempdir().unwrap();
    let single_path = single_dir.path().join("freeze-single.v2");
    let single = ParallelStore::create(&single_path, StoreConfig::small(8, 1 << 16)).unwrap();
    seed(&single);
    criterion.bench_function("freeze_acquire_release_single", |bencher| {
        bencher.iter(|| {
            let guard = single.freeze().unwrap();
            black_box(guard.epoch());
        });
    });
}

fn bench_sweep(criterion: &mut Criterion) {
    let pages: u32 = std::env::var("PULSE_FS_SWEEP_PAGES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(512);
    let mut group = criterion.benchmark_group("sweep_throughput");
    group.throughput(criterion::Throughput::Elements(u64::from(pages)));
    group.bench_function(format!("reclaim_{pages}_leaked_pages"), |bencher| {
        bencher.iter_batched(
            || {
                let dir = tempfile::tempdir().unwrap();
                let path = dir.path().join("sweep-bench.v2");
                let store = ParallelStore::create(&path, multi_config()).unwrap();
                seed(&store);
                leak(&store, pages);
                (dir, store)
            },
            |(_dir, store)| {
                let config = SweepConfig {
                    max_scan_pages: pages.saturating_add(4096),
                    max_leaks_per_call: pages.saturating_add(4096),
                    max_duration: Duration::from_secs(5),
                    orphan_buckets: true,
                };
                let report = store.sweep_leaks(config).unwrap();
                black_box(report.reclaimed_pages);
            },
            criterion::BatchSize::PerIteration,
        );
    });
    group.finish();
}

fn bench_commit_during_sweep(criterion: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("commit-sweep.v2");
    let store = Arc::new(ParallelStore::create(&path, multi_config()).unwrap());
    let seq = seed(&store);
    leak(&store, 2048);
    let zones = ParallelZones::open(&store).unwrap();
    let mut writer = zones.writer_by_seq(seq).unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let sweep_store = Arc::clone(&store);
    let sweep_stop = Arc::clone(&stop);
    let sweeper = std::thread::spawn(move || {
        let mut runs = 0_u64;
        while !sweep_stop.load(Ordering::Acquire) {
            let config = SweepConfig {
                max_scan_pages: 256,
                max_leaks_per_call: 256,
                max_duration: Duration::from_millis(2),
                orphan_buckets: true,
            };
            if sweep_store.sweep_leaks(config).is_ok() {
                runs = runs.saturating_add(1);
            }
        }
        runs
    });

    let iterations: usize = std::env::var("PULSE_FS_COMMIT_ITERS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(2000);
    let mut latencies = Vec::with_capacity(iterations);
    for item in 0..iterations {
        let started = Instant::now();
        writer
            .upsert_rrset(
                &key(u32::try_from(item % 4096).unwrap_or(0)),
                1,
                0,
                &rr(u8::try_from(item % 250 + 1).unwrap_or(1)),
            )
            .unwrap();
        writer.commit().unwrap();
        latencies.push(started.elapsed());
    }
    stop.store(true, Ordering::Release);
    let runs = sweeper.join().unwrap();
    latencies.sort_unstable();
    let p50 = latencies[latencies.len() / 2];
    let p99 = latencies[(latencies.len() * 99 / 100).min(latencies.len() - 1)];
    eprintln!(
        "commit during sweep: n={} sweeps={} p50={:?} p99={:?}",
        latencies.len(),
        runs,
        p50,
        p99
    );

    criterion.bench_function("commit_p99_with_background_sweep", |bencher| {
        let mut item = 0_u32;
        bencher.iter(|| {
            let started = Instant::now();
            writer
                .upsert_rrset(
                    &key(item % 4096),
                    1,
                    0,
                    &rr(u8::try_from(item % 250 + 1).unwrap_or(1)),
                )
                .unwrap();
            writer.commit().unwrap();
            item = item.wrapping_add(1);
            black_box(started.elapsed());
        });
    });
}

fn benches(criterion: &mut Criterion) {
    bench_freeze(criterion);
    bench_sweep(criterion);
    bench_commit_during_sweep(criterion);
}

criterion_group!(benches_group, benches);
criterion_main!(benches_group);
