#![allow(missing_docs)]
//! Бенчи B1: parallel insert/commit по зонам и латентность снапшот-чтения.

use std::thread;

use criterion::{Criterion, black_box, criterion_group, criterion_main};

use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    ParallelStore, ParallelZones, RrsetData, StoreConfig, ZoneCreateMeta,
};

const ZONES: u32 = 8;
const COMMITS_PER_ZONE: usize = 16;

fn origin(index: u32) -> NameRle {
    NameRle::from_ascii(&format!("bench{index}.example")).unwrap()
}

fn name(index: u32, commit: usize) -> NameRle {
    NameRle::from_ascii(&format!("r{commit}.bench{index}.example")).unwrap()
}

fn data() -> RrsetData {
    RrsetData::from_slices(60, 0, &[&[192, 0, 2, 1]]).unwrap()
}

fn setup() -> (
    tempfile::TempDir,
    &'static ParallelStore,
    &'static ParallelZones<'static>,
    Vec<NameRle>,
) {
    // `Box::leak` удерживает стор живым на всё время бенча: criterion-замыкания
    // требуют `'static`, а стор создаётся один раз на группу.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bench-zones.v2");
    let config = StoreConfig::small(32, 1 << 20);
    let store: &'static ParallelStore =
        Box::leak(Box::new(ParallelStore::create(&path, config).unwrap()));
    let mut zones = ParallelZones::open(store).unwrap();
    let mut origins = Vec::new();
    for index in 0..ZONES {
        zones
            .create_zone(
                &origin(index),
                ZoneCreateMeta {
                    soa_serial: index + 1,
                },
            )
            .unwrap();
        origins.push(origin(index));
    }
    let zones: &'static ParallelZones<'static> = Box::leak(Box::new(zones));
    (dir, store, zones, origins)
}

fn bench_parallel_commit(c: &mut Criterion) {
    let (_dir, store, zones, origins) = setup();
    let mut group = c.benchmark_group("pw_v2_zone_commit_sync");
    group.sample_size(10);
    for threads in [1_usize, 4, 8] {
        group.bench_function(format!("{threads}_threads_x{ZONES}_zones"), |b| {
            b.iter(|| {
                thread::scope(|scope| {
                    for thread_index in 0..threads {
                        let origins = &origins;
                        scope.spawn(move || {
                            for (zone_index, apex) in origins.iter().enumerate() {
                                if zone_index % threads != thread_index {
                                    continue;
                                }
                                let mut writer = zones.writer(apex).unwrap();
                                for commit in 0..COMMITS_PER_ZONE {
                                    writer
                                        .upsert_rrset(
                                            &name(u32::try_from(zone_index).unwrap(), commit),
                                            1,
                                            0,
                                            &data(),
                                        )
                                        .unwrap();
                                    writer.commit().unwrap();
                                }
                                black_box(store.durable_page_limit());
                            }
                        });
                    }
                });
            });
        });
    }
    group.finish();
}

fn bench_commit_latency(c: &mut Criterion) {
    let (_dir, _store, zones, origins) = setup();
    let mut group = c.benchmark_group("pw_v2_commit_latency");
    group.sample_size(10);
    group.bench_function("one_rrset_sync", |b| {
        let mut writer = zones.writer(&origins[0]).unwrap();
        let mut commit = 0_usize;
        b.iter(|| {
            writer
                .upsert_rrset(&name(0, commit), 1, 0, &data())
                .unwrap();
            black_box(writer.commit().unwrap());
            commit += 1;
        });
    });
    group.finish();
}

fn bench_read_latency(c: &mut Criterion) {
    let (_dir, store, zones, origins) = setup();
    {
        let mut writer = zones.writer(&origins[0]).unwrap();
        writer.upsert_rrset(&name(0, 0), 1, 0, &data()).unwrap();
        writer.commit().unwrap();
    }
    let reader = store.reader().unwrap();
    let view = zones.read(&reader, &origins[0]).unwrap();
    let target = name(0, 0);
    let mut group = c.benchmark_group("pw_v2_read");
    group.bench_function("lookup_warm", |b| {
        b.iter(|| black_box(view.lookup(&target, 1, 0).unwrap()));
    });
    group.bench_function("lookup_ref_warm", |b| {
        b.iter(|| black_box(view.lookup_ref(&target, 1, 0).unwrap()));
    });
    group.bench_function("zone_snapshot_pin", |b| {
        b.iter(|| {
            let snapshot = store.zone_snapshot(&reader, view.zone()).unwrap();
            black_box(snapshot.version());
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_parallel_commit,
    bench_commit_latency,
    bench_read_latency
);
criterion_main!(benches);
