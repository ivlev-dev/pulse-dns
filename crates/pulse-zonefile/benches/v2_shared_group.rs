//! 1/2/4/8 процессов: commits/s и p50/p99 до/после межпроцессного group
//! commit (`PULSE_MP_DIRECT_COMMIT` — старый путь, каждый процесс делает свои
//! два `fdatasync`).
//!
//! `fdatasync` моделируется задержкой `--sync-delay-ms` (по умолчанию 2 мс):
//! на локальной ФС реальный fsync слишком быстрый, чтобы показать эффект, а
//! модель воспроизводит сериализацию fsync одного inode.
//!
//! Запуск: `cargo bench -p pulse-zonefile --bench v2_shared_group`
//! (harness = false).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    OpenConfigV2, ParallelStore, ParallelZone, ParallelZones, RrsetData, StoreConfig,
    ZoneCreateMeta,
};

const CHILD: &str = "PULSE_BENCH_SHARED_CHILD";
const PATH: &str = "PULSE_BENCH_PATH";
const ZONE: &str = "PULSE_BENCH_ZONE";
const ITERS: &str = "PULSE_BENCH_ITERS";
const DELAY: &str = "PULSE_BENCH_DELAY_MS";
const LATENCIES: &str = "PULSE_BENCH_LATENCIES";
const FSYNCS: &str = "PULSE_BENCH_FSYNCS";

const ITERATIONS: u32 = 40;

fn config() -> StoreConfig {
    StoreConfig {
        multi_process: true,
        ..StoreConfig::small(64, 1 << 18)
    }
}

fn origin(zone: u32) -> NameRle {
    NameRle::from_ascii(&format!("z{zone}.bench.example")).expect("origin")
}

fn rr(value: u32) -> RrsetData {
    RrsetData::from_slices(
        60,
        0,
        &[&[10, 0, 0, u8::try_from(value % 256).unwrap_or(0)]],
    )
    .expect("rrset")
}

fn setup(path: &Path, zones: u32) {
    let store = ParallelStore::create(path, config()).expect("create");
    let mut catalog = ParallelZones::open(&store).expect("catalog");
    for zone in 1..=zones {
        catalog
            .create_zone(&origin(zone), ZoneCreateMeta { soa_serial: zone })
            .expect("create zone");
    }
}

fn child_body() -> Result<(), String> {
    let path = PathBuf::from(std::env::var(PATH).map_err(|_| "path".to_string())?);
    let zone = std::env::var(ZONE)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1);
    let iterations = std::env::var(ITERS)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(ITERATIONS);
    let delay = std::env::var(DELAY)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(2_u64);
    let mut store = ParallelStore::open(
        &path,
        OpenConfigV2 {
            read_only: false,
            writer_lock: false,
            multi_process: true,
            ..OpenConfigV2::default()
        },
    )
    .map_err(|error| error.to_string())?;
    store.set_sync_delay(Duration::from_millis(delay));
    let mut writer = ParallelZone::open_uncached(&store, origin(zone), zone)
        .map_err(|error| error.to_string())?;
    let mut latencies = Vec::with_capacity(usize::try_from(iterations).unwrap_or(0));
    for iteration in 0..iterations {
        let name = NameRle::from_ascii(&format!("k{iteration}.z{zone}.bench.example"))
            .map_err(|error| error.to_string())?;
        writer
            .upsert_rrset(&name, 1, 0, &rr(iteration))
            .map_err(|error| error.to_string())?;
        let started = Instant::now();
        writer.commit().map_err(|error| error.to_string())?;
        latencies.push(started.elapsed());
    }
    let fsyncs = store.stats().group_fsyncs;
    let groups = store.shared_group_stats().map_or(0, |stats| stats.groups);
    if let Ok(path) = std::env::var(LATENCIES) {
        let mut file = std::fs::File::create(path).map_err(|error| error.to_string())?;
        for latency in latencies {
            writeln!(file, "{}", latency.as_nanos()).map_err(|error| error.to_string())?;
        }
    }
    if let Ok(path) = std::env::var(FSYNCS) {
        std::fs::write(path, format!("{fsyncs} {groups}")).map_err(|error| error.to_string())?;
    }
    Ok(())
}

struct Run {
    commits_per_second: f64,
    p50_us: f64,
    p99_us: f64,
    fsyncs: u64,
    groups: u64,
}

#[allow(clippy::cast_precision_loss)]
fn percentile(sorted: &[u128], fraction: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    let index = ((sorted.len() - 1) as f64 * fraction).round() as usize;
    sorted
        .get(index)
        .map_or(0.0, |value| *value as f64 / 1000.0)
}

fn run(dir: &Path, processes: u32, shared: bool) -> Run {
    let path = dir.join(format!(
        "bench-{}-{processes}.v2",
        if shared { "shared" } else { "direct" }
    ));
    setup(&path, processes);
    let mut children: Vec<(Child, PathBuf, PathBuf)> = (1..=processes)
        .map(|zone| {
            let latencies = dir.join(format!(
                "lat-{}-{processes}-{zone}",
                if shared { "s" } else { "d" }
            ));
            let fsyncs = dir.join(format!(
                "fsync-{}-{processes}-{zone}",
                if shared { "s" } else { "d" }
            ));
            let mut command = Command::new(std::env::current_exe().expect("exe"));
            command
                .env(CHILD, "1")
                .env(PATH, &path)
                .env(ZONE, zone.to_string())
                .env(ITERS, ITERATIONS.to_string())
                .env(DELAY, "2")
                .env(LATENCIES, &latencies)
                .env(FSYNCS, &fsyncs)
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            if !shared {
                command.env("PULSE_MP_DIRECT_COMMIT", "1");
            }
            let child = command.spawn().expect("spawn");
            (child, latencies, fsyncs)
        })
        .collect();

    let started = Instant::now();
    let mut latencies = Vec::new();
    let mut fsyncs = 0_u64;
    let mut groups = 0_u64;
    for (child, latency_path, fsync_path) in &mut children {
        let status = child.wait().expect("wait");
        assert!(status.success(), "bench child failed: {status:?}");
        if let Ok(raw) = std::fs::read_to_string(latency_path) {
            latencies.extend(raw.lines().filter_map(|line| line.parse::<u128>().ok()));
        }
        if let Ok(raw) = std::fs::read_to_string(fsync_path) {
            let mut parts = raw.split_whitespace();
            fsyncs = fsyncs.saturating_add(parts.next().and_then(|v| v.parse().ok()).unwrap_or(0));
            groups = groups.max(parts.next().and_then(|v| v.parse().ok()).unwrap_or(0));
        }
    }
    let elapsed = started.elapsed();
    latencies.sort_unstable();
    let total = f64::from(processes) * f64::from(ITERATIONS);
    Run {
        commits_per_second: total / elapsed.as_secs_f64(),
        p50_us: percentile(&latencies, 0.50),
        p99_us: percentile(&latencies, 0.99),
        fsyncs,
        groups,
    }
}

fn main() {
    if std::env::var_os(CHILD).is_some() {
        if let Err(error) = child_body() {
            eprintln!("child failed: {error}");
            std::process::exit(1);
        }
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    println!(
        "{:>9} {:>6} {:>12} {:>10} {:>10} {:>9} {:>8}",
        "mode", "procs", "commits/s", "p50 us", "p99 us", "fsyncs", "groups"
    );
    for processes in [1_u32, 2, 4, 8] {
        for shared in [false, true] {
            let run = run(dir.path(), processes, shared);
            println!(
                "{:>9} {:>6} {:>12.0} {:>10.1} {:>10.1} {:>9} {:>8}",
                if shared { "shared" } else { "direct" },
                processes,
                run.commits_per_second,
                run.p50_us,
                run.p99_us,
                run.fsyncs,
                run.groups
            );
        }
    }
}
