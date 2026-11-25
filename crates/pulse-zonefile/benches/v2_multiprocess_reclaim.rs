//! M3 bench: create/commit/reclaim в 2/4/8 процессах.
//!
//! Замеряет:
//! * `create` — сколько зон/с каталогом, который пишут все процессы
//!   (catalog lease + commit-lock, без внешнего flock);
//! * `commit` — зона-коммиты/с на разных зонах;
//! * `reclaim` — `high_water` до/после `PULSE_MP_BENCH_CYCLES` циклов
//!   insert/delete (по умолчанию 100k коммитов на конфигурацию, если задан
//!   `PULSE_MP_BENCH_FULL=1`).
//!
//! Запуск: `cargo bench -p pulse-zonefile --bench v2_multiprocess_reclaim`.
//! Переменные: `PULSE_MP_BENCH_CYCLES` (циклов на процесс),
//! `PULSE_MP_BENCH_FULL=1` (полный 100k-прогон reclaim).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    OpenConfigV2, ParallelStore, ParallelZone, ParallelZones, RrsetData, StoreConfig, SyncModeV2,
    ZoneCreateMeta,
};

const MODE: &str = "PULSE_MPR_BENCH";
const PATH: &str = "PULSE_MPR_PATH";
const ZONES: &str = "PULSE_MPR_ZONES";
const ITERS: &str = "PULSE_MPR_ITERS";

fn origin(zone: u32) -> NameRle {
    NameRle::from_ascii(&format!("b{zone}.mprbench.example")).expect("origin")
}

fn key(zone: u32) -> NameRle {
    NameRle::from_ascii(&format!("k.b{zone}.mprbench.example")).expect("name")
}

fn rr(value: u32) -> RrsetData {
    RrsetData::from_slices(
        60,
        0,
        &[&[10, 0, 0, u8::try_from(value % 256).unwrap_or(0)]],
    )
    .expect("rrset")
}

fn open_multi(path: &Path) -> ParallelStore {
    ParallelStore::open(
        path,
        OpenConfigV2 {
            multi_process: true,
            writer_lock: false,
            ..OpenConfigV2::default()
        },
    )
    .expect("open store")
}

fn create_empty(path: &Path, capacity: u32, sync: SyncModeV2) {
    drop(
        ParallelStore::create(
            path,
            StoreConfig {
                multi_process: true,
                sync_mode: sync,
                ..StoreConfig::small(capacity, 1 << 20)
            },
        )
        .expect("create"),
    );
}

fn setup(path: &Path, zones: u32, sync: SyncModeV2) {
    create_empty(path, zones + 16, sync);
    let store = open_multi(path);
    let mut catalog = ParallelZones::open(&store).expect("catalog");
    for zone in 1..=zones {
        catalog
            .create_zone(&origin(zone), ZoneCreateMeta { soa_serial: zone })
            .expect("create zone");
    }
}

fn zones_from_env() -> Vec<u32> {
    std::env::var(ZONES)
        .unwrap_or_default()
        .split(',')
        .filter_map(|value| value.parse().ok())
        .collect()
}

fn child_create() {
    let path = PathBuf::from(std::env::var(PATH).expect("path"));
    let store = open_multi(&path);
    for zone in zones_from_env() {
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let result = {
                let mut catalog = ParallelZones::open(&store).expect("catalog");
                catalog.create_zone(&origin(zone), ZoneCreateMeta { soa_serial: zone })
            };
            match result {
                Ok(_) => break,
                Err(error) if error.is_retryable() && Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("create zone {zone}: {error}"),
            }
        }
    }
}

fn child_commit() {
    let path = PathBuf::from(std::env::var(PATH).expect("path"));
    let iterations: u32 = std::env::var(ITERS)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(50);
    let store = open_multi(&path);
    let catalog = ParallelZones::open(&store).expect("catalog");
    for zone in zones_from_env() {
        let origin = catalog.origin(zone).expect("origin");
        let mut writer = ParallelZone::open_uncached(&store, origin, zone).expect("writer");
        for iteration in 0..iterations {
            writer
                .upsert_rrset(&key(zone), 1, 0, &rr(iteration))
                .expect("upsert");
            writer.commit().expect("commit");
        }
    }
}

fn child_churn() {
    let path = PathBuf::from(std::env::var(PATH).expect("path"));
    let iterations: u32 = std::env::var(ITERS)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1000);
    let store = open_multi(&path);
    let catalog = ParallelZones::open(&store).expect("catalog");
    for zone in zones_from_env() {
        let origin = catalog.origin(zone).expect("origin");
        let mut writer = ParallelZone::open_uncached(&store, origin, zone).expect("writer");
        let name = key(zone);
        for iteration in 0..iterations {
            writer
                .upsert_rrset(&name, 1, 0, &rr(iteration))
                .expect("upsert");
            writer.commit().expect("commit");
            let _ = writer.delete_rrset(&name, 1, 0).expect("delete");
            writer.commit().expect("commit");
        }
    }
}

fn run_children(path: &Path, processes: u32, mode: &str, per_process: u32, iters: u32) -> Duration {
    let exe = std::env::current_exe().expect("current exe");
    let start = Instant::now();
    let children: Vec<_> = (0..processes)
        .map(|process| {
            let zones: Vec<String> = (0..per_process)
                .map(|slot| (process * per_process + slot + 1).to_string())
                .collect();
            Command::new(&exe)
                .arg("--child")
                .env(MODE, mode)
                .env(PATH, path)
                .env(ZONES, zones.join(","))
                .env(ITERS, iters.to_string())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("spawn")
        })
        .collect();
    for mut child in children {
        let status = child.wait().expect("wait");
        assert!(status.success(), "child failed: {status:?}");
    }
    start.elapsed()
}

#[allow(clippy::cast_precision_loss)]
fn bench_create() {
    println!("\ncreate (catalog multi-writer, Sync-memory)");
    println!("procs  zones   zones/s");
    for processes in [2_u32, 4, 8] {
        let zones_per_process = 50_u32;
        let zones = processes * zones_per_process;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(format!("create-{processes}.v2"));
        create_empty(&path, zones + 16, SyncModeV2::Memory);
        let elapsed = run_children(&path, processes, "create", zones_per_process, 0);
        println!(
            "{processes:>5}  {zones:>5}  {:>8.0}",
            f64::from(zones) / elapsed.as_secs_f64().max(f64::EPSILON)
        );
    }
}

#[allow(clippy::cast_precision_loss)]
fn bench_commit() {
    println!("\ncommit (Sync, 2 zones/process)");
    println!("procs  commits   zones/s   commit_ms");
    for processes in [2_u32, 4, 8] {
        let zones_per_process = 2_u32;
        let iterations = 40_u32;
        let zones = processes * zones_per_process;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(format!("commit-{processes}.v2"));
        setup(&path, zones, SyncModeV2::Sync);
        let elapsed = run_children(&path, processes, "commit", zones_per_process, iterations);
        let commits = u64::from(processes * zones_per_process * iterations);
        let seconds = elapsed.as_secs_f64().max(f64::EPSILON);
        println!(
            "{processes:>5}  {commits:>7}  {:>8.0}  {:>9.3}",
            commits as f64 / seconds,
            seconds * 1000.0 / commits as f64
        );
    }
}

#[allow(clippy::cast_precision_loss)]
fn bench_reclaim() {
    let full = std::env::var("PULSE_MP_BENCH_FULL").is_ok();
    println!("\nreclaim (Sync, insert+delete = 2 commits/cycle)");
    println!("procs  cycles  commits   high_water_before  high_water_after  commit_ms");
    for processes in [2_u32, 4, 8] {
        let zones_per_process = 2_u32;
        let zones = processes * zones_per_process;
        let target_commits = if full { 100_000_u64 } else { 20_000 };
        let cycles = u32::try_from(target_commits / (u64::from(processes * zones_per_process) * 2))
            .unwrap_or(1)
            .max(1);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(format!("reclaim-{processes}.v2"));
        setup(&path, zones, SyncModeV2::Sync);
        let store = open_multi(&path);
        let before = store.high_water();
        let elapsed = run_children(&path, processes, "churn", zones_per_process, cycles);
        let after = store.high_water();
        let commits = u64::from(cycles) * u64::from(processes * zones_per_process) * 2;
        let seconds = elapsed.as_secs_f64().max(f64::EPSILON);
        println!(
            "{processes:>5}  {cycles:>6}  {commits:>7}  {before:>17}  {after:>16}  {:>9.3}",
            seconds * 1000.0 / commits as f64
        );
        assert!(
            after <= before.saturating_add(u64::from(zones) * 4096),
            "high_water не стабилизировался: {before} → {after}"
        );
    }
}

fn main() {
    if std::env::args().any(|argument| argument == "--child") {
        match std::env::var(MODE).as_deref() {
            Ok("create") => child_create(),
            Ok("commit") => child_commit(),
            Ok("churn") => child_churn(),
            _ => panic!("unknown child mode"),
        }
        return;
    }
    println!("M3 multiprocess bench: create/commit/reclaim");
    bench_create();
    bench_commit();
    bench_reclaim();
}
