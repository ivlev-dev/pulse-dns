//! M3 read bench: p50/p99 cache-warm чтения в multi-process и single-process.
//!
//! Меряются два пути:
//! * `req` — новый `ZoneReader` (снапшот) + `lookup_ref` на каждый запрос, как
//!   в DNS-процессе, который открывает снапшот на запрос;
//! * `warm` — один прогретый `ZoneReader`, только `lookup_ref`.
//!
//! Для «до/после» multi гоняется дважды: `nocache` (`page_cache_entries = 0`,
//! поведение M3-L10) и `cache` (общая генерация страниц + PageCacheV2/node
//! cache). Single-process — только с кешем (регресс-контроль).
//!
//! Запуск:
//!
//! ```text
//! cargo bench -p pulse-zonefile --bench v2_multiprocess_read
//! ```
//!
//! Переменные: `PULSE_MP_READ_ITERS` (итераций на процесс, по умолчанию
//! 40 000), `PULSE_MP_READ_PROCS` (процессов, по умолчанию 4).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    OpenConfigV2, ParallelStore, ParallelZones, RrsetData, StoreConfig, ZoneCreateMeta,
};

const MODE: &str = "PULSE_MPR_READ_MODE";
const PATH: &str = "PULSE_MPR_READ_PATH";
const ZONE: &str = "PULSE_MPR_READ_ZONE";
const ITERS: &str = "PULSE_MPR_READ_ITERS";
const RESULT: &str = "PULSE_MPR_READ_RESULT";
const CACHE: &str = "PULSE_MPR_READ_CACHE";

const KEYS: u32 = 200;
const HOT_ZONE: u32 = 4096;
const HOT_KEYS: u32 = 8;

fn origin(zone: u32) -> NameRle {
    NameRle::from_ascii(&format!("r{zone}.mprread.example")).expect("origin")
}

fn key(zone: u32, index: u32) -> NameRle {
    NameRle::from_ascii(&format!("k{index}.r{zone}.mprread.example")).expect("name")
}

fn rr(value: u8) -> RrsetData {
    RrsetData::from_slices(60, 0, &[&[192, 0, 2, value]]).expect("rrset")
}

fn open_multi(path: &Path) -> ParallelStore {
    let cache_entries: usize = std::env::var(CACHE)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1024);
    ParallelStore::open(
        path,
        OpenConfigV2 {
            multi_process: true,
            writer_lock: false,
            page_cache_entries: cache_entries,
            ..OpenConfigV2::default()
        },
    )
    .expect("open multi")
}

fn setup(path: &Path, zones: u32, multi: bool, cache_entries: usize) {
    let mut config = StoreConfig {
        multi_process: multi,
        ..StoreConfig::small(HOT_ZONE + 8, 1 << 18)
    };
    config.page_cache_entries = cache_entries;
    let store = ParallelStore::create(path, config).expect("create");
    let mut catalog = ParallelZones::open(&store).expect("catalog");
    for zone in 1..=zones {
        catalog
            .create_zone(&origin(zone), ZoneCreateMeta { soa_serial: zone })
            .expect("create zone");
        let mut writer = catalog.writer(&origin(zone)).expect("writer");
        for index in 0..KEYS {
            writer
                .upsert_rrset(
                    &key(zone, index),
                    1,
                    0,
                    &rr(u8::try_from(index % 250).unwrap_or(0)),
                )
                .expect("upsert");
        }
        writer.commit().expect("commit");
    }
    // Горячая зона на одну страницу: цель warm ≤ 1 µs.
    catalog
        .create_zone(
            &origin(HOT_ZONE),
            ZoneCreateMeta {
                soa_serial: HOT_ZONE,
            },
        )
        .expect("create hot zone");
    let mut writer = catalog.writer(&origin(HOT_ZONE)).expect("hot writer");
    for index in 0..HOT_KEYS {
        writer
            .upsert_rrset(&key(HOT_ZONE, index), 1, 0, &rr(1))
            .expect("hot upsert");
    }
    writer.commit().expect("hot commit");
}

fn percentile(sorted: &[u64], numerator: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let index = (sorted.len() - 1) * numerator / 100;
    sorted[index]
}

#[allow(clippy::cast_precision_loss)]
fn measure(
    store: &ParallelStore,
    zone: u32,
    iterations: u32,
) -> (Vec<u64>, Vec<u64>, Vec<u64>, f64) {
    let catalog = ParallelZones::open(store).expect("catalog");
    let reader = store.reader().expect("reader");
    let origin_name = origin(zone);
    let keys: Vec<NameRle> = (0..KEYS).map(|index| key(zone, index)).collect();
    let key_count = keys.len().max(1);

    let request_batch = 100_u32;
    let request_samples = (iterations / request_batch).max(1) as usize;
    let mut request = Vec::with_capacity(request_samples);
    let mut cursor = 0_usize;
    let start = Instant::now();
    for _ in 0..request_samples {
        let before = Instant::now();
        for _ in 0..request_batch {
            let view = catalog.read(&reader, &origin_name).expect("read");
            let index = cursor % key_count;
            cursor = cursor.wrapping_add(1);
            let hit = view
                .lookup_ref(&keys[index], 1, 0)
                .expect("lookup")
                .is_some();
            assert!(hit);
        }
        request.push(
            u64::try_from(before.elapsed().as_nanos()).unwrap_or(u64::MAX)
                / u64::from(request_batch),
        );
    }
    let elapsed = start.elapsed().as_secs_f64().max(f64::EPSILON);
    let qps = f64::from(
        u32::try_from(request_samples)
            .unwrap_or(u32::MAX)
            .saturating_mul(request_batch),
    ) / elapsed;

    let view = catalog.read(&reader, &origin_name).expect("warm view");
    let warm_batch = 1_000_u32;
    let warm_samples = (iterations / warm_batch).max(1) as usize;
    let mut warm = Vec::with_capacity(warm_samples);
    let mut cursor = 0_usize;
    for _ in 0..warm_samples {
        let before = Instant::now();
        for _ in 0..warm_batch {
            let index = cursor % key_count;
            cursor = cursor.wrapping_add(1);
            let hit = view
                .lookup_ref(&keys[index], 1, 0)
                .expect("warm lookup")
                .is_some();
            assert!(hit);
        }
        warm.push(
            u64::try_from(before.elapsed().as_nanos()).unwrap_or(u64::MAX) / u64::from(warm_batch),
        );
    }

    let hot_view = catalog.read(&reader, &origin(HOT_ZONE)).expect("hot view");
    let hot_keys: Vec<NameRle> = (0..HOT_KEYS).map(|index| key(HOT_ZONE, index)).collect();
    let mut hot = Vec::with_capacity(warm_samples);
    let mut cursor = 0_usize;
    for _ in 0..warm_samples {
        let before = Instant::now();
        for _ in 0..warm_batch {
            let index = cursor % hot_keys.len();
            cursor = cursor.wrapping_add(1);
            let hit = hot_view
                .lookup_ref(&hot_keys[index], 1, 0)
                .expect("hot lookup")
                .is_some();
            assert!(hit);
        }
        hot.push(
            u64::try_from(before.elapsed().as_nanos()).unwrap_or(u64::MAX) / u64::from(warm_batch),
        );
    }
    (request, warm, hot, qps)
}

fn child() {
    let path = PathBuf::from(std::env::var(PATH).expect("path"));
    let zone: u32 = std::env::var(ZONE)
        .expect("zone")
        .parse()
        .expect("zone number");
    let iterations: u32 = std::env::var(ITERS)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(40_000);
    let store = open_multi(&path);
    let (mut request, mut warm, mut hot, qps) = measure(&store, zone, iterations);
    request.sort_unstable();
    warm.sort_unstable();
    hot.sort_unstable();
    let result = PathBuf::from(std::env::var(RESULT).expect("result"));
    std::fs::write(
        &result,
        format!(
            "{},{},{},{},{},{},{qps:.0}",
            percentile(&request, 50),
            percentile(&request, 99),
            percentile(&warm, 50),
            percentile(&warm, 99),
            percentile(&hot, 50),
            percentile(&hot, 99)
        ),
    )
    .expect("write result");
}

#[allow(clippy::cast_precision_loss)]
fn read_results(dir: &Path, processes: u32) -> (u64, u64, u64, u64, u64, u64, f64) {
    let mut request_p50 = 0_u64;
    let mut request_p99 = 0_u64;
    let mut warm_p50 = 0_u64;
    let mut warm_p99 = 0_u64;
    let mut hot_p50 = 0_u64;
    let mut hot_p99 = 0_u64;
    let mut qps = 0.0_f64;
    for process in 0..processes {
        let raw = std::fs::read_to_string(dir.join(format!("result-{process}"))).expect("result");
        let fields: Vec<&str> = raw.trim().split(',').collect();
        assert_eq!(fields.len(), 7, "result format: {raw:?}");
        request_p50 = request_p50.max(fields[0].parse().expect("req p50"));
        request_p99 = request_p99.max(fields[1].parse().expect("req p99"));
        warm_p50 = warm_p50.max(fields[2].parse().expect("warm p50"));
        warm_p99 = warm_p99.max(fields[3].parse().expect("warm p99"));
        hot_p50 = hot_p50.max(fields[4].parse().expect("hot p50"));
        hot_p99 = hot_p99.max(fields[5].parse().expect("hot p99"));
        qps += fields[6].parse::<f64>().expect("qps");
    }
    (
        request_p50,
        request_p99,
        warm_p50,
        warm_p99,
        hot_p50,
        hot_p99,
        qps,
    )
}

#[allow(clippy::cast_precision_loss)]
fn bench_multi(dir: &Path, processes: u32, iterations: u32, label: &str, cache_entries: usize) {
    let path = dir.join(format!("multi-read-{label}.v2"));
    setup(&path, processes, true, cache_entries);
    let exe = std::env::current_exe().expect("current exe");
    let children: Vec<_> = (1..=processes)
        .map(|zone| {
            Command::new(&exe)
                .arg("--child")
                .env(MODE, "multi")
                .env(PATH, &path)
                .env(ZONE, zone.to_string())
                .env(ITERS, iterations.to_string())
                .env(CACHE, cache_entries.to_string())
                .env(RESULT, dir.join(format!("result-{label}-{}", zone - 1)))
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
    // Результаты лежат под `result-{process}`, чтобы `read_results` не знал
    // про label; переименовываем после прогона.
    for process in 0..processes {
        std::fs::rename(
            dir.join(format!("result-{label}-{process}")),
            dir.join(format!("result-{process}")),
        )
        .expect("rename result");
    }
    let (request_p50, request_p99, warm_p50, warm_p99, hot_p50, hot_p99, qps) =
        read_results(dir, processes);
    println!(
        "{label:<12} procs={processes:<2} req p50={request_p50:>6} ns p99={request_p99:>7} ns | warm(200) p50={warm_p50:>4} ns p99={warm_p99:>5} ns | hot(8) p50={hot_p50:>4} ns p99={hot_p99:>5} ns | qps={qps:>9.0}"
    );
}

#[allow(clippy::cast_precision_loss)]
fn bench_single(dir: &Path, iterations: u32) {
    let path = dir.join("single-read.v2");
    setup(&path, 1, false, 1024);
    let store = ParallelStore::open(
        &path,
        OpenConfigV2 {
            writer_lock: false,
            ..OpenConfigV2::default()
        },
    )
    .expect("open single");
    let (mut request, mut warm, mut hot, qps) = measure(&store, 1, iterations);
    request.sort_unstable();
    warm.sort_unstable();
    hot.sort_unstable();
    println!(
        "single       procs=1  req p50={:>6} ns p99={:>7} ns | warm(200) p50={:>4} ns p99={:>5} ns | hot(8) p50={:>4} ns p99={:>5} ns | qps={qps:>9.0}",
        percentile(&request, 50),
        percentile(&request, 99),
        percentile(&warm, 50),
        percentile(&warm, 99),
        percentile(&hot, 50),
        percentile(&hot, 99)
    );
}

fn main() {
    if std::env::args().any(|argument| argument == "--child") {
        child();
        return;
    }
    let iterations: u32 = std::env::var(ITERS)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(40_000);
    let processes: u32 = std::env::var("PULSE_MP_READ_PROCS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(4);
    let dir = tempfile::tempdir().expect("tempdir");
    println!("M3 read bench: snapshot+lookup_ref на запрос и warm lookup_ref");
    bench_multi(dir.path(), processes, iterations, "multi-nocache", 0);
    bench_multi(dir.path(), processes, iterations, "multi-cache", 1024);
    bench_single(dir.path(), iterations);
}
