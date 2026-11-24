//! B2b: group commit — батчинг зон, ровно два `fdatasync` на группу, ack после
//! публикации, backpressure, `CommitUncertain` для всей группы и измерение
//! throughput против per-zone.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    GroupCommitConfig, GroupCommitRequest, GroupCommitter, IoFaultHook, OpenConfigV2,
    ParallelError, ParallelStore, ParallelZones, RrsetData, StoreConfig, SyncModeV2,
    ZoneCreateMeta,
};

const ZONES: u32 = 8;

fn origin(index: u32) -> NameRle {
    NameRle::from_ascii(&format!("g{index}.example")).unwrap()
}

fn rr(index: u32, commit: u32) -> RrsetData {
    let octets = [
        10,
        u8::try_from(index % 256).unwrap(),
        u8::try_from(commit % 256).unwrap(),
        1,
    ];
    RrsetData::from_slices(60, 0, &[&octets]).unwrap()
}

fn name(index: u32, commit: u32) -> NameRle {
    NameRle::from_ascii(&format!("r{commit}.g{index}.example")).unwrap()
}

fn config() -> StoreConfig {
    StoreConfig::small(64, 1 << 20)
}

fn setup(path: &std::path::Path, zones_count: u32) -> (ParallelStore, Vec<NameRle>) {
    let store = ParallelStore::create(path, config()).unwrap();
    let mut zones = ParallelZones::open(&store).unwrap();
    let mut origins = Vec::new();
    for index in 0..zones_count {
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
    drop(zones);
    (store, origins)
}

#[test]
fn group_commit_two_fsyncs_and_ack_without_loss() {
    const COMMITS: u32 = 16;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("group.v2");
    let (store, origins) = setup(&path, ZONES);
    let store = Arc::new(store);
    let committer = Arc::new(
        GroupCommitter::with_config(
            Arc::clone(&store),
            GroupCommitConfig {
                max_batch_delay: Duration::from_millis(2),
                ..GroupCommitConfig::default()
            },
        )
        .unwrap(),
    );
    let zones = ParallelZones::open(&store).unwrap();
    let barrier = Barrier::new(ZONES as usize);
    let mut acked = Vec::new();
    thread::scope(|scope| {
        let mut handles = Vec::new();
        for (index, apex) in origins.iter().enumerate() {
            let apex = *apex;
            let zones = &zones;
            let committer = &committer;
            let barrier = &barrier;
            handles.push(scope.spawn(move || {
                let mut writer = zones.writer(&apex).unwrap();
                barrier.wait();
                let mut last = 0_u64;
                for commit in 0..COMMITS {
                    let index = u32::try_from(index).unwrap();
                    writer
                        .upsert_rrset(&name(index, commit), 1, 0, &rr(index, commit))
                        .unwrap();
                    let outcome = writer.commit_via(committer).unwrap();
                    last = outcome.version;
                }
                last
            }));
        }
        for handle in handles {
            acked.push(handle.join().unwrap());
        }
    });
    let group_stats = committer.stats();
    let stats = store.stats();
    assert!(group_stats.groups >= 1);
    assert_eq!(group_stats.members, u64::from(ZONES) * u64::from(COMMITS));
    assert_eq!(group_stats.fsyncs, group_stats.groups * 2);
    assert_eq!(stats.group_fsyncs, stats.group_commits * 2);
    assert!(
        group_stats.max_members > 1,
        "группы не батчились: {group_stats:?}"
    );
    drop(zones);
    Arc::try_unwrap(committer).ok().unwrap().shutdown();
    drop(store);

    let reopened = ParallelStore::open(&path, OpenConfigV2::default()).unwrap();
    let zones = ParallelZones::open(&reopened).unwrap();
    let reader = reopened.reader().unwrap();
    for (index, apex) in origins.iter().enumerate() {
        let seq = zones.zone_seq(apex).unwrap();
        let head = reopened.select_root(seq, u64::MAX).unwrap();
        assert!(
            head.version >= acked[index],
            "зона {index}: голова {} < ack {}",
            head.version,
            acked[index]
        );
        let view = zones.read(&reader, apex).unwrap();
        let last = COMMITS - 1;
        assert!(
            view.lookup(&name(u32::try_from(index).unwrap(), last), 1, 0)
                .unwrap()
                .is_some(),
            "зона {index}: последний ack-нутый RRset потерян"
        );
        assert!(view.version() >= acked[index]);
    }
    assert!(reopened.fsck_lite().unwrap().ok);
    assert!(reopened.fsck_graph().unwrap().ok);
}

/// Замер: `commits/с` для per-zone и group commit на одинаковой нагрузке.
fn measure(
    path: &std::path::Path,
    threads: usize,
    zones_per_thread: u32,
    commits: u32,
    grouped: bool,
    sync_delay: Duration,
) -> f64 {
    let zones_count = u32::try_from(threads).unwrap() * zones_per_thread;
    let (mut store, origins) = setup(path, zones_count);
    store.set_sync_delay(sync_delay);
    let store = Arc::new(store);
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
    thread::scope(|scope| {
        for thread_index in 0..threads {
            let zones = &zones;
            let committer = committer.as_deref();
            let origins = &origins;
            scope.spawn(move || {
                let base = u32::try_from(thread_index).unwrap() * zones_per_thread;
                for zone_index in base..base + zones_per_thread {
                    let apex = origins[usize::try_from(zone_index).unwrap()];
                    let mut writer = zones.writer(&apex).unwrap();
                    for commit in 0..commits {
                        writer
                            .upsert_rrset(&name(zone_index, commit), 1, 0, &rr(zone_index, commit))
                            .unwrap();
                        if let Some(committer) = committer {
                            writer.commit_via(committer).unwrap();
                        } else {
                            writer.commit().unwrap();
                        }
                    }
                }
            });
        }
    });
    let elapsed = started.elapsed().as_secs_f64();
    if let Some(committer) = committer {
        println!(
            "measure grouped={grouped} t={elapsed:.3}s stats={:?} store={:?}",
            committer.stats(),
            store.stats()
        );
        Arc::try_unwrap(committer).ok().unwrap().shutdown();
    } else {
        println!(
            "measure grouped={grouped} t={elapsed:.3}s store={:?}",
            store.stats()
        );
    }
    drop(zones);
    drop(store);
    f64::from(zones_count) * f64::from(commits) / elapsed.max(f64::MIN_POSITIVE)
}

#[test]
fn group_commit_throughput_at_least_two_x() {
    const THREADS: usize = 8;
    const ZONES_PER_THREAD: u32 = 4;
    const COMMITS: u32 = 8;
    // Моделируемая стоимость `fdatasync` устройства, где fsync доминирует
    // (на локальной ФС fsync почти бесплатен и замер не показателен).
    const SYNC_DELAY: Duration = Duration::from_micros(400);
    let dir = tempfile::tempdir().unwrap();
    let mut best_perzone = f64::MIN;
    let mut best_group = f64::MIN;
    for run in 0..3 {
        let perzone = measure(
            &dir.path().join(format!("perzone-{run}.v2")),
            THREADS,
            ZONES_PER_THREAD,
            COMMITS,
            false,
            SYNC_DELAY,
        );
        let grouped = measure(
            &dir.path().join(format!("group-{run}.v2")),
            THREADS,
            ZONES_PER_THREAD,
            COMMITS,
            true,
            SYNC_DELAY,
        );
        best_perzone = best_perzone.max(perzone);
        best_group = best_group.max(grouped);
    }
    let ratio = best_group / best_perzone.max(f64::MIN_POSITIVE);
    println!(
        "group commit: per-zone {best_perzone:.0} z/s, group {best_group:.0} z/s, ratio {ratio:.2}x"
    );
    assert!(
        ratio >= 2.0,
        "group commit медленнее ожидаемого: {best_group:.0} vs {best_perzone:.0} ({ratio:.2}x)"
    );
}

struct FailOnce(AtomicUsize);

impl IoFaultHook for FailOnce {
    fn fail_sync(&self) -> bool {
        self.0.fetch_add(1, Ordering::SeqCst) == 0
    }
}

#[test]
fn group_io_error_locks_all_zones_without_publication() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("group-fault.v2");
    let mut store = ParallelStore::create(&path, config()).unwrap();
    store.set_io_fault_hook(Box::new(FailOnce(AtomicUsize::new(0))));
    let requests = vec![
        GroupCommitRequest::new(
            pulse_zonefile::parallel::RootEntry {
                owner_zone: 1,
                version: 2,
                state: pulse_zonefile::parallel::RootState::Serving,
                ..Default::default()
            },
            SyncModeV2::Sync,
        ),
        GroupCommitRequest::new(
            pulse_zonefile::parallel::RootEntry {
                owner_zone: 2,
                version: 3,
                state: pulse_zonefile::parallel::RootState::Serving,
                ..Default::default()
            },
            SyncModeV2::Sync,
        ),
    ];
    let outcomes = store.commit_group(requests);
    assert_eq!(outcomes.len(), 2);
    for outcome in &outcomes {
        assert!(
            matches!(
                outcome,
                Err(ParallelError::ReadOnly {
                    reason: pulse_zonefile::parallel::FatalKind::CommitUncertain
                })
            ),
            "неожиданный исход группы: {outcome:?}"
        );
    }
    assert_eq!(
        store.fatal(),
        Some(pulse_zonefile::parallel::FatalKind::CommitUncertain)
    );
    for zone in [1_u32, 2] {
        assert!(matches!(
            store.select_root(zone, u64::MAX),
            Err(ParallelError::NoZoneVersion { .. })
        ));
    }
    assert!(matches!(
        store.publish_root(pulse_zonefile::parallel::RootEntry {
            owner_zone: 1,
            version: 4,
            state: pulse_zonefile::parallel::RootState::Serving,
            ..Default::default()
        }),
        Err(ParallelError::ReadOnly { .. })
    ));
    drop(store);
    let reopened = ParallelStore::open(&path, OpenConfigV2::default()).unwrap();
    assert!(reopened.fsck_lite().unwrap().ok);
    for zone in [1_u32, 2] {
        assert!(matches!(
            reopened.select_root(zone, u64::MAX),
            Err(ParallelError::NoZoneVersion { .. })
        ));
    }
}

#[test]
fn group_counts_fsyncs_across_modes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("group-modes.v2");
    let mut config = config();
    config.sync_mode = SyncModeV2::Memory;
    let store = ParallelStore::create(&path, config).unwrap();
    let requests = |version: u64| {
        vec![GroupCommitRequest::new(
            pulse_zonefile::parallel::RootEntry {
                owner_zone: 1,
                version,
                state: pulse_zonefile::parallel::RootState::Serving,
                ..Default::default()
            },
            SyncModeV2::Memory,
        )]
    };
    store.commit_group(requests(2));
    let stats = store.stats();
    assert_eq!(stats.group_fsyncs, 0);
    assert_eq!(store.durable_version(1), 0);
    // `sync()` — durable-чекпойнт: двигает `D_z` и включает липкий `Sync`.
    store.sync().unwrap();
    assert_eq!(store.durable_version(1), 2); // версия головы после commit
    assert_eq!(store.effective_mode(), SyncModeV2::Sync);
    assert!(matches!(
        store.commit_group(requests(4)),
        outcomes if outcomes.iter().all(|outcome| matches!(
            outcome,
            Err(ParallelError::DurabilityBelowFileMode { .. })
        ))
    ));
}

#[test]
fn group_backpressure_and_many_zones() {
    const COMMITS: u32 = 4;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("group-bp.v2");
    let (store, origins) = setup(&path, 16);
    let store = Arc::new(store);
    let committer = Arc::new(
        GroupCommitter::with_config(
            Arc::clone(&store),
            GroupCommitConfig {
                max_batch_zones: 4,
                queue_zones: 4,
                queue_bytes: 64 << 10,
                max_batch_delay: Duration::from_micros(200),
                bulk_bytes: 32 << 10,
                max_batch_bytes: 32 << 10,
            },
        )
        .unwrap(),
    );
    let zones = ParallelZones::open(&store).unwrap();
    let acked = AtomicU64::new(0);
    thread::scope(|scope| {
        for (index, apex) in origins.iter().enumerate() {
            let apex = *apex;
            let index = u32::try_from(index).unwrap();
            let zones = &zones;
            let committer = &committer;
            let acked = &acked;
            scope.spawn(move || {
                let mut writer = zones.writer(&apex).unwrap();
                for commit in 0..COMMITS {
                    writer
                        .upsert_rrset(&name(index, commit), 1, 0, &rr(index, commit))
                        .unwrap();
                    writer.commit_via(committer).unwrap();
                }
                acked.fetch_add(u64::from(COMMITS), Ordering::Relaxed);
            });
        }
    });
    let stats = committer.stats();
    assert!(stats.max_members <= 4);
    assert_eq!(stats.commits, acked.load(Ordering::Relaxed));
    assert_eq!(stats.fsyncs, stats.groups * 2);
    drop(zones);
    Arc::try_unwrap(committer).ok().unwrap().shutdown();
    drop(store);
    let reopened = ParallelStore::open(&path, OpenConfigV2::default()).unwrap();
    let zones = ParallelZones::open(&reopened).unwrap();
    assert_eq!(zones.zones().len(), origins.len());
    assert!(reopened.fsck_graph().unwrap().ok);
}
