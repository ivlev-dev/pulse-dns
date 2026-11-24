//! M3 bench: 2/4/8 процессов пишут разные зоны одного v2-файла.
//!
//! Замеряет wall-clock `зона-коммитов/с`, среднюю латентность коммита и
//! read-latency межпроцессного снапшота. Дочерний режим — `--child` (тот же
//! бинарь, env `PULSE_MP_BENCH`).
//!
//! Запуск: `cargo bench -p pulse-zonefile --bench v2_multiprocess`.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    OpenConfigV2, ParallelStore, ParallelZone, ParallelZones, RrsetData, StoreConfig, SyncModeV2,
    ZoneCreateMeta,
};

const MODE: &str = "PULSE_MP_BENCH";
const PATH: &str = "PULSE_MP_PATH";
const ZONES: &str = "PULSE_MP_ZONES";
const ITERS: &str = "PULSE_MP_ITERS";

fn origin(zone: u32) -> NameRle {
    NameRle::from_ascii(&format!("b{zone}.example")).expect("origin")
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

fn child_write() {
    let path = PathBuf::from(std::env::var(PATH).expect("path"));
    let zones: Vec<u32> = std::env::var(ZONES)
        .unwrap_or_default()
        .split(',')
        .filter_map(|value| value.parse().ok())
        .collect();
    let iterations: u32 = std::env::var(ITERS)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(50);
    let store = open_multi(&path);
    let catalog = ParallelZones::open(&store).expect("catalog");
    for zone in zones {
        let origin = catalog.origin(zone).expect("origin");
        let mut writer = ParallelZone::open_uncached(&store, origin, zone).expect("writer");
        for iteration in 0..iterations {
            let name = NameRle::from_ascii(&format!("r.b{zone}.example")).expect("name");
            writer
                .upsert_rrset(&name, 1, 0, &rr(iteration))
                .expect("upsert");
            writer.commit().expect("commit");
        }
    }
}

fn setup(path: &Path, zones: u32) {
    let store = ParallelStore::create(
        path,
        StoreConfig {
            multi_process: true,
            sync_mode: SyncModeV2::Sync,
            ..StoreConfig::small(zones + 8, 1 << 18)
        },
    )
    .expect("create");
    let mut catalog = ParallelZones::open(&store).expect("catalog");
    for zone in 1..=zones {
        catalog
            .create_zone(&origin(zone), ZoneCreateMeta { soa_serial: zone })
            .expect("create zone");
    }
}

fn measure_read(path: &Path, zones_count: u32) -> (Duration, usize) {
    let store = open_multi(path);
    let reader = store.reader().expect("reader");
    let catalog = ParallelZones::open(&store).expect("catalog");
    let zones: Vec<u32> = (1..=zones_count).collect();
    let iterations = 2000;
    let start = Instant::now();
    let mut total = 0_usize;
    for _ in 0..iterations {
        for zone in &zones {
            let origin = catalog.origin(*zone).expect("origin");
            if let Ok(view) = catalog.read(&reader, &origin) {
                total = total.saturating_add(view.records().map_or(0, |records| records.len()));
            }
        }
    }
    let elapsed = start.elapsed();
    (elapsed / iterations, total)
}

#[allow(clippy::cast_precision_loss)]
fn main() {
    if std::env::args().any(|argument| argument == "--child") {
        child_write();
        return;
    }
    println!("M3 multiprocess bench (Sync, 2 zones/process)");
    println!("procs  zones  commits  zones/s   commit_ms  read_ns  notes");
    for processes in [2_u32, 4, 8] {
        let zones_per_process = 2_u32;
        let iterations = 40_u32;
        let zones = processes * zones_per_process;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(format!("mp{processes}.v2"));
        setup(&path, zones);

        let exe = std::env::current_exe().expect("current exe");
        let start = Instant::now();
        let children: Vec<_> = (0..processes)
            .map(|process| {
                let assigned: Vec<String> = (0..zones_per_process)
                    .map(|slot| (process * zones_per_process + slot + 1).to_string())
                    .collect();
                Command::new(&exe)
                    .arg("--child")
                    .env(MODE, "write")
                    .env(PATH, &path)
                    .env(ZONES, assigned.join(","))
                    .env(ITERS, iterations.to_string())
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
        let elapsed = start.elapsed();
        let commits = u64::from(processes * zones_per_process * iterations);
        let seconds = elapsed.as_secs_f64();
        let zones_per_second = commits as f64 / seconds.max(f64::EPSILON);
        let commit_ms = seconds * 1000.0 / commits as f64;
        let (read_iteration, _) = measure_read(&path, zones);
        let read_per_snapshot = read_iteration / zones.max(1);
        println!(
            "{processes:>5}  {zones:>5}  {commits:>7}  {zones_per_second:>8.0}  {commit_ms:>9.3}  {read:>7}  Sync",
            read = read_per_snapshot.as_nanos()
        );
    }
}
