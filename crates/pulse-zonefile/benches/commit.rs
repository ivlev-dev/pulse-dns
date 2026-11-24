#![allow(missing_docs)]
//! Бенчмарки commit-латентности и операций записи поверх реального файла.
//!
//! Запуск: `cargo bench -p pulse-zonefile --bench commit -- --quick`.

use std::hint::black_box;
use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};

use pulse_zonefile::key::NameRle;
use pulse_zonefile::{CreateConfig, RrsetData, SyncMode, ZoneFile};

fn rrset(value: u8) -> RrsetData {
    RrsetData::from_slices(300, 0, &[&[192, 0, 2, value]]).expect("rrset")
}

fn config(sync_mode: SyncMode) -> CreateConfig {
    CreateConfig {
        page_size: 4096,
        map_size: 4 * 1024 * 1024 * 1024,
        sync_mode,
        ..CreateConfig::default()
    }
}

fn prepare(path: &std::path::Path, sync_mode: SyncMode, keys: u32) -> ZoneFile {
    let mut zonefile = ZoneFile::create(path, config(sync_mode)).unwrap();
    let apex = NameRle::from_ascii("bench.example").unwrap();
    let mut writer = zonefile.write().unwrap();
    writer.create_zone(&apex, 0).unwrap();
    writer
        .upsert_rrset(
            &apex,
            &apex,
            6,
            0,
            &RrsetData::from_slices(300, 0, &[&[1, 2, 3, 4]]).unwrap(),
        )
        .unwrap();
    for index in 0..keys {
        let owner = NameRle::from_ascii(&format!("h{index:07}.bench.example")).unwrap();
        writer
            .upsert_rrset(
                &apex,
                &owner,
                1,
                0,
                &rrset(u8::try_from(index % 250).unwrap()),
            )
            .unwrap();
    }
    writer.commit(sync_mode).unwrap();
    zonefile
}

fn bench_commit_latency(criterion: &mut Criterion) {
    let apex = NameRle::from_ascii("bench.example").unwrap();
    let mut group = criterion.benchmark_group("commit_one_rr");
    group.sample_size(15);
    group.measurement_time(Duration::from_secs(3));
    for (name, mode) in [
        ("sync", SyncMode::Sync),
        ("flush", SyncMode::MetaNoSync),
        ("memory", SyncMode::NoSync),
    ] {
        group.bench_function(name, |bencher| {
            bencher.iter_custom(|iterations| {
                // Свежий файл на каждый замер: Flush/Memory без sync()
                // монотонно растят freelist, и «steady-state» через тысячи
                // коммитов измерял бы разбор растущей цепочки, а не коммит.
                let dir = tempfile::tempdir().unwrap();
                let path = dir.path().join("fresh.zonefile");
                let mut zonefile = prepare(&path, mode, 1000);
                let mut counter = 0_u8;
                let start = std::time::Instant::now();
                for _ in 0..iterations {
                    counter = counter.wrapping_add(1);
                    let mut writer = zonefile.write().unwrap();
                    writer
                        .upsert_rrset(&apex, &apex, 1, 0, &rrset(counter))
                        .unwrap();
                    let outcome = writer.commit(black_box(mode)).unwrap();
                    black_box(outcome);
                }
                start.elapsed()
            });
        });
    }
    group.finish();
}

fn bench_batch_ops(criterion: &mut Criterion) {
    const BATCH: u32 = 100;
    let dir = tempfile::tempdir().unwrap();
    let apex = NameRle::from_ascii("bench.example").unwrap();
    let path = dir.path().join("batch.zonefile");
    let mut zonefile = prepare(&path, SyncMode::Sync, 0);
    let mut group = criterion.benchmark_group("batch_100");
    group.throughput(Throughput::Elements(u64::from(BATCH)));
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(3));
    let mut next = 0_u32;
    group.bench_function("insert_sync", |bencher| {
        bencher.iter(|| {
            let mut writer = zonefile.write().unwrap();
            for _ in 0..BATCH {
                next = next.wrapping_add(1);
                let owner = NameRle::from_ascii(&format!("i{next:08}.bench.example")).unwrap();
                writer
                    .upsert_rrset(
                        &apex,
                        &owner,
                        1,
                        0,
                        &rrset(u8::try_from(next % 250).unwrap()),
                    )
                    .unwrap();
            }
            let outcome = writer.commit(SyncMode::Sync).unwrap();
            black_box(outcome);
        });
    });
    group.bench_function("delete_sync", |bencher| {
        bencher.iter(|| {
            let mut writer = zonefile.write().unwrap();
            for _ in 0..BATCH {
                let owner = NameRle::from_ascii(&format!("i{next:08}.bench.example")).unwrap();
                let _ = writer.delete_rrset(&apex, &owner, 1, 0).unwrap();
                next = next.saturating_sub(1);
            }
            let outcome = writer.commit(SyncMode::Sync).unwrap();
            black_box(outcome);
        });
    });
    group.finish();
}

fn bench_lookup_after_commit(criterion: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lookup.zonefile");
    let zonefile = prepare(&path, SyncMode::Sync, 100_000);
    drop(zonefile);
    let zonefile = ZoneFile::open(&path, pulse_zonefile::OpenConfig::default()).unwrap();
    let apex = NameRle::from_ascii("bench.example").unwrap();
    let mut group = criterion.benchmark_group("lookup_after_commit_100k");
    group.sample_size(50);
    group.bench_function("rrset", |bencher| {
        bencher.iter(|| {
            let owner = NameRle::from_ascii("h0005000.bench.example").unwrap();
            black_box(zonefile.lookup_rrset(&apex, &owner, 1, 0).unwrap())
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_commit_latency,
    bench_batch_ops,
    bench_lookup_after_commit
);
criterion_main!(benches);
