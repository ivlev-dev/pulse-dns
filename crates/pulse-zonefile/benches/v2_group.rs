#![allow(missing_docs)]
//! B2b bench: group commit против per-zone (B2a), fsync/группа, латентность.
//!
//! Запуск: `cargo bench -p pulse-zonefile --bench v2_group`.
//!
//! Печатает:
//! * `threads=N zones/s per-zone vs group` (нативный `fdatasync`);
//! * те же числа на моделируемом durable-устройстве (`fsync = 400 µs`,
//!   сериализованный на inode) — режим, ради которого делался group commit;
//! * `fsync/group`, средний размер группы;
//! * p50/p99 латентности `commit_via` для 1/4/8 потоков.

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    GroupCommitConfig, GroupCommitter, ParallelStore, ParallelZones, RrsetData, StoreConfig,
    ZoneCreateMeta,
};

const COMMITS: u32 = 16;
const ZONES_PER_THREAD: u32 = 4;

fn origin(index: u32) -> NameRle {
    NameRle::from_ascii(&format!("bench{index}.example")).unwrap()
}

fn name(zone: u32, commit: u32) -> NameRle {
    NameRle::from_ascii(&format!("r{commit}.bench{zone}.example")).unwrap()
}

fn data(zone: u32, commit: u32) -> RrsetData {
    let octets = [192, 0, 2, u8::try_from((zone + commit) % 256).unwrap()];
    RrsetData::from_slices(60, 0, &[&octets]).unwrap()
}

struct Run {
    zones_per_second: f64,
    fsyncs_per_group: f64,
    groups: u64,
    max_batch: u64,
    p50_us: f64,
    p99_us: f64,
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]
fn percentile(sorted: &[u64], percent: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let index = ((sorted.len() - 1) as f64 * percent) as usize;
    sorted[index] as f64 / 1000.0
}

fn run(
    path: &std::path::Path,
    threads: usize,
    commits: u32,
    grouped: bool,
    sync_delay: Duration,
) -> Run {
    let zones_count = u32::try_from(threads).unwrap() * ZONES_PER_THREAD;
    let mut store = ParallelStore::create(path, StoreConfig::small(128, 1 << 20)).unwrap();
    store.set_sync_delay(sync_delay);
    let store = Arc::new(store);
    {
        let mut zones = ParallelZones::open(&store).unwrap();
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
    }
    let committer = grouped.then(|| {
        Arc::new(
            GroupCommitter::with_config(
                Arc::clone(&store),
                GroupCommitConfig {
                    max_batch_delay: Duration::from_millis(1),
                    ..GroupCommitConfig::default()
                },
            )
            .unwrap(),
        )
    });
    let zones = ParallelZones::open(&store).unwrap();
    let started = Instant::now();
    let mut latencies = Vec::new();
    thread::scope(|scope| {
        let mut handles = Vec::new();
        for thread_index in 0..threads {
            let zones = &zones;
            let committer = committer.as_deref();
            handles.push(scope.spawn(move || {
                let base = u32::try_from(thread_index).unwrap() * ZONES_PER_THREAD;
                let mut local = Vec::new();
                for zone in base..base + ZONES_PER_THREAD {
                    let apex = origin(zone);
                    let mut writer = zones.writer(&apex).unwrap();
                    for commit in 0..commits {
                        writer
                            .upsert_rrset(&name(zone, commit), 1, 0, &data(zone, commit))
                            .unwrap();
                        let began = Instant::now();
                        if let Some(committer) = committer {
                            writer.commit_via(committer).unwrap();
                        } else {
                            writer.commit().unwrap();
                        }
                        local.push(u64::try_from(began.elapsed().as_nanos()).unwrap_or(u64::MAX));
                    }
                }
                local
            }));
        }
        for handle in handles {
            latencies.extend(handle.join().unwrap());
        }
    });
    let elapsed = started.elapsed().as_secs_f64();
    let stats = store.stats();
    let (groups, max_batch, fsyncs) = if let Some(committer) = committer {
        let group = committer.stats();
        Arc::try_unwrap(committer).ok().unwrap().shutdown();
        (group.groups, group.max_members, group.fsyncs)
    } else {
        (stats.group_commits, 1, stats.group_fsyncs)
    };
    latencies.sort_unstable();
    Run {
        zones_per_second: f64::from(zones_count) * f64::from(commits)
            / elapsed.max(f64::MIN_POSITIVE),
        fsyncs_per_group: if groups == 0 {
            0.0
        } else {
            #[allow(clippy::cast_precision_loss)]
            {
                fsyncs as f64 / groups as f64
            }
        },
        groups,
        max_batch,
        p50_us: percentile(&latencies, 0.50),
        p99_us: percentile(&latencies, 0.99),
    }
}

fn main() {
    let dir = tempfile::tempdir().unwrap();
    for delay in [Duration::ZERO, Duration::from_micros(400)] {
        let label = if delay.is_zero() {
            "native fsync".to_string()
        } else {
            format!("modeled fsync {}µs", delay.as_micros())
        };
        println!("== {label} ==");
        for threads in [1_usize, 4, 8] {
            let perzone = run(
                &dir.path()
                    .join(format!("perzone-{threads}-{}", delay.as_micros())),
                threads,
                COMMITS,
                false,
                delay,
            );
            let group = run(
                &dir.path()
                    .join(format!("group-{threads}-{}", delay.as_micros())),
                threads,
                COMMITS,
                true,
                delay,
            );
            let ratio = group.zones_per_second / perzone.zones_per_second.max(f64::MIN_POSITIVE);
            println!(
                "threads={threads:2} per-zone {:>9.0} z/s (p50 {:>7.0}µs p99 {:>8.0}µs) | group {:>9.0} z/s (p50 {:>7.0}µs p99 {:>8.0}µs) | ratio {ratio:.2}x",
                perzone.zones_per_second,
                perzone.p50_us,
                perzone.p99_us,
                group.zones_per_second,
                group.p50_us,
                group.p99_us,
            );
        }
        println!();
    }
    // Детали группы: fsync/группу и размер батча.
    let detail = run(
        &dir.path().join("detail"),
        8,
        COMMITS,
        true,
        Duration::from_micros(400),
    );
    println!(
        "group detail (8 потоков): groups={} max_batch={} fsync/group={:.2}",
        detail.groups, detail.max_batch, detail.fsyncs_per_group
    );
}
