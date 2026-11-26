//! Межпроцессный group commit v2 (M3, sidecar v4).
//!
//! Проверяет: 2/4/8 процессов делят одну пару `fdatasync` на группу (по
//! счётчикам sidecar), `kill -9` координатора в фазе 1/2 не теряет durable
//! версию и не блокирует остальные процессы, `fsck` остаётся чистым.
//!
//! Дочерний режим выбирается `PULSE_SG_CHILD`; без переменной `child_entry`
//! завершается мгновенно.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    CrashHook, CrashPoint, FsckLiteReport, OpenConfigV2, ParallelStore, ParallelZone,
    ParallelZones, RrsetData, StoreConfig, SyncModeV2, ZoneCreateMeta,
};

const CHILD: &str = "PULSE_SG_CHILD";
const PATH: &str = "PULSE_SG_PATH";
const ZONE: &str = "PULSE_SG_ZONE";
const ITERS: &str = "PULSE_SG_ITERS";
const RESULT: &str = "PULSE_SG_RESULT";
const CRASH_AT: &str = "PULSE_SG_CRASH_AT";
const CRASH_AFTER: &str = "PULSE_SG_CRASH_AFTER";
const CRASH_ONCE: &str = "PULSE_SG_CRASH_ONCE";
const DELAY_MS: &str = "PULSE_SG_DELAY_MS";
const READY: &str = "PULSE_SG_READY";
const GO: &str = "PULSE_SG_GO";

fn config() -> StoreConfig {
    StoreConfig {
        multi_process: true,
        sync_mode: SyncModeV2::Sync,
        ..StoreConfig::small(64, 1 << 18)
    }
}

fn origin(zone: u32) -> NameRle {
    NameRle::from_ascii(&format!("z{zone}.sg.example")).expect("origin")
}

fn key(zone: u32, iteration: u32) -> NameRle {
    NameRle::from_ascii(&format!("k{iteration}.z{zone}.sg.example")).expect("key")
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
            read_only: false,
            writer_lock: false,
            multi_process: true,
            ..OpenConfigV2::default()
        },
    )
    .expect("open multi")
}

fn setup(path: &Path, zones: u32) -> ParallelStore {
    let store = ParallelStore::create(path, config()).expect("create");
    let mut catalog = ParallelZones::open(&store).expect("catalog");
    for zone in 1..=zones {
        catalog
            .create_zone(&origin(zone), ZoneCreateMeta { soa_serial: zone })
            .expect("create zone");
    }
    drop(catalog);
    store
}

fn parse_u32(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn spawn_child(mode: &str, path: &Path, extra: &[(&str, String)]) -> Child {
    let mut command = Command::new(std::env::current_exe().expect("current exe"));
    command
        .arg("--exact")
        .arg("child_entry")
        .arg("--nocapture")
        .env(CHILD, mode)
        .env(PATH, path)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    for (name, value) in extra {
        command.env(name, value);
    }
    command.spawn().expect("spawn child")
}

fn wait_deadline(child: &mut Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait().expect("try_wait") {
            Some(status) => return status,
            None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            None => {
                let _ = child.kill();
                panic!("child не завершился за {timeout:?}");
            }
        }
    }
}

fn assert_success(mut child: Child) {
    let status = wait_deadline(&mut child, Duration::from_secs(60));
    assert!(status.success(), "child failed: {status:?}");
}

/// Барьер одновременного старта: все дети открыли стор, затем один `go`.
fn wait_barrier(ready: &[PathBuf], go: &Path) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !ready.iter().all(|path| path.exists()) {
        assert!(Instant::now() < deadline, "дети не дошли до барьера");
        std::thread::sleep(Duration::from_millis(1));
    }
    std::fs::write(go, b"go").expect("go");
}

fn read_results(path: &Path) -> Vec<(u32, u64)> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            Some((parts.next()?.parse().ok()?, parts.next()?.parse().ok()?))
        })
        .collect()
}

struct KillAt {
    point: CrashPoint,
    after: AtomicU32,
    /// Общий маркер: погибнуть должен ровно один координатор на файл.
    once: Option<PathBuf>,
}

impl CrashHook for KillAt {
    fn at(&self, point: CrashPoint) {
        if point != self.point {
            return;
        }
        // Гасим не первый, а N-й проход координатора: к этому моменту другие
        // процессы уже успевают положить запросы и ждут ack.
        let limit = self.after.load(Ordering::Acquire);
        if self.after.fetch_add(1, Ordering::AcqRel) < limit {
            return;
        }
        if let Some(path) = &self.once
            && std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .is_err()
        {
            return;
        }
        let _ =
            rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::KILL);
    }
}

#[test]
fn child_entry() {
    if std::env::var(CHILD).is_err() {
        return;
    }
    if let Err(error) = child_body() {
        panic!("child failed: {error}");
    }
}

fn child_body() -> Result<(), String> {
    let mode = std::env::var(CHILD).map_err(|_| "no mode".to_string())?;
    let path = PathBuf::from(std::env::var(PATH).map_err(|_| "no path".to_string())?);
    match mode.as_str() {
        "writer" => {
            let mut store = open_multi(&path);
            let delay = parse_u32(DELAY_MS, 0);
            if delay != 0 {
                store.set_sync_delay(Duration::from_millis(u64::from(delay)));
            }
            if let Ok(point) = std::env::var(CRASH_AT) {
                let point = parse_point(&point).ok_or_else(|| "bad point".to_string())?;
                let after = parse_u32(CRASH_AFTER, u32::MAX);
                store.set_crash_hook(Box::new(KillAt {
                    point,
                    after: AtomicU32::new(after),
                    once: std::env::var_os(CRASH_ONCE).map(PathBuf::from),
                }));
            }
            let store = Arc::new(store);
            if let Ok(ready) = std::env::var(READY) {
                std::fs::write(ready, b"1").map_err(|error| error.to_string())?;
                let go = PathBuf::from(std::env::var(GO).map_err(|_| "no go".to_string())?);
                let deadline = Instant::now() + Duration::from_secs(15);
                while !go.exists() {
                    if Instant::now() >= deadline {
                        return Err("barrier timeout".to_string());
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            let zone = parse_u32(ZONE, 1);
            let iterations = parse_u32(ITERS, 1);
            let mut writer = ParallelZone::open_uncached(&store, origin(zone), zone)
                .map_err(|error| error.to_string())?;
            let mut version = 0_u64;
            for iteration in 0..iterations {
                writer
                    .upsert_rrset(&key(zone, iteration), 1, 0, &rr(iteration))
                    .map_err(|error| error.to_string())?;
                let outcome = writer.commit().map_err(|error| error.to_string())?;
                version = outcome.version;
            }
            if let Ok(result) = std::env::var(RESULT) {
                let mut file = std::fs::File::create(result).map_err(|error| error.to_string())?;
                writeln!(file, "{zone} {version}").map_err(|error| error.to_string())?;
            }
            Ok(())
        }
        "crash_once" => {
            let mut store = open_multi(&path);
            let point = parse_point(&std::env::var(CRASH_AT).map_err(|_| "no point".to_string())?)
                .ok_or_else(|| "bad point".to_string())?;
            store.set_crash_hook(Box::new(KillAt {
                point,
                after: AtomicU32::new(0),
                once: std::env::var_os(CRASH_ONCE).map(PathBuf::from),
            }));
            let store = Arc::new(store);
            let zone = parse_u32(ZONE, 1);
            let mut writer = ParallelZone::open_uncached(&store, origin(zone), zone)
                .map_err(|error| error.to_string())?;
            writer
                .upsert_rrset(&key(zone, 999), 1, 0, &rr(999))
                .map_err(|error| error.to_string())?;
            let _ = writer.commit().map_err(|error| error.to_string())?;
            Err("crash child survived".to_string())
        }
        other => Err(format!("unknown mode {other}")),
    }
}

fn parse_point(name: &str) -> Option<CrashPoint> {
    Some(match name {
        "BeforeAllocRecord" => CrashPoint::BeforeAllocRecord,
        "AfterPhase1Writes" => CrashPoint::AfterPhase1Writes,
        "AfterPhase1Fsync" => CrashPoint::AfterPhase1Fsync,
        "BeforeRootWrite" => CrashPoint::BeforeRootWrite,
        "AfterRootCopyA" => CrashPoint::AfterRootCopyA,
        "AfterRootCopyB" => CrashPoint::AfterRootCopyB,
        "AfterPhase2Fsync" => CrashPoint::AfterPhase2Fsync,
        "BeforeHeadPublish" => CrashPoint::BeforeHeadPublish,
        "AfterHeadPublish" => CrashPoint::AfterHeadPublish,
        _ => return None,
    })
}

fn fsck(path: &Path) -> FsckLiteReport {
    let store = ParallelStore::open(
        path,
        OpenConfigV2 {
            read_only: true,
            writer_lock: false,
            multi_process: true,
            ..OpenConfigV2::default()
        },
    )
    .expect("open read");
    store.fsck_lite().expect("fsck")
}

fn zone_version(path: &Path, zone: u32) -> u64 {
    let store = open_multi(path);
    store.zone_head(zone).map_or(0, |head| head.version)
}

fn find_record(path: &Path, zone: u32, iteration: u32) -> bool {
    let store = open_multi(path);
    let catalog = ParallelZones::open(&store).expect("catalog");
    let reader = store.reader().expect("reader");
    let view = catalog.read(&reader, &origin(zone)).expect("read");
    view.lookup(&key(zone, iteration), 1, 0)
        .expect("lookup")
        .is_some()
}

/// 2/4/8 процессов: одна пара `fdatasync` на группу, потери ack нет.
#[test]
fn group_commit_scales_2_4_8_processes() {
    for processes in [2_u32, 4, 8] {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(format!("shared-{processes}.v2"));
        let iterations = 20_u32;
        let store = setup(&path, processes);
        let baseline = store.shared_group_stats().expect("stats");
        let results = dir.path().join("results");
        std::fs::create_dir_all(&results).expect("results dir");
        let go = results.join("go");
        let mut ready = Vec::new();
        let children: Vec<Child> = (1..=processes)
            .map(|zone| {
                let ready_path = results.join(format!("ready{zone}"));
                ready.push(ready_path.clone());
                spawn_child(
                    "writer",
                    &path,
                    &[
                        (ZONE, zone.to_string()),
                        (ITERS, iterations.to_string()),
                        (DELAY_MS, "1".to_string()),
                        (READY, ready_path.display().to_string()),
                        (GO, go.display().to_string()),
                        (
                            RESULT,
                            results.join(format!("z{zone}")).display().to_string(),
                        ),
                    ],
                )
            })
            .collect();
        wait_barrier(&ready, &go);
        for child in children {
            assert_success(child);
        }
        let stats = store.shared_group_stats().expect("shared stats");
        let groups = stats.groups - baseline.groups;
        let members = stats.members - baseline.members;
        let fsyncs = stats.fsyncs - baseline.fsyncs;
        assert_eq!(members, u64::from(processes) * u64::from(iterations));
        assert_eq!(fsyncs, groups * 2, "{processes} процессов: fsync {stats:?}");
        assert!(
            groups < members,
            "{processes} процессов не сгруппировали: {stats:?}"
        );
        assert!(stats.max_members >= 2, "{processes}: {stats:?}");
        drop(store);
        assert!(fsck(&path).fatal.is_none());
        for zone in 1..=processes {
            assert!(
                find_record(&path, zone, iterations - 1),
                "{processes} процессов: потерян коммит зоны {zone}"
            );
        }
    }
}

/// `kill -9` после durable-фазы 1: корень не записан, зона на прежней версии,
/// файл открывается и снова пишется.
#[test]
fn kill_after_phase1_keeps_previous_version() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("kill-phase1.v2");
    let store = setup(&path, 1);
    let before = store.zone_head(1).map_or(0, |head| head.version);

    let mut child = spawn_child(
        "crash_once",
        &path,
        &[
            (ZONE, "1".to_string()),
            (CRASH_AT, "AfterPhase1Fsync".to_string()),
        ],
    );
    let status = wait_deadline(&mut child, Duration::from_secs(30));
    assert!(!status.success(), "координатор должен был погибнуть");
    drop(store);

    assert!(fsck(&path).fatal.is_none(), "phase1 crash: fsck");
    assert_eq!(
        zone_version(&path, 1),
        before,
        "корень не должен быть виден"
    );
    assert_success(spawn_child(
        "writer",
        &path,
        &[
            (ZONE, "1".to_string()),
            (ITERS, "2".to_string()),
            (RESULT, dir.path().join("after").display().to_string()),
        ],
    ));
    assert!(find_record(&path, 1, 1));
}

/// `kill -9` после durable-фазы 2: корень durable, ack не доставлен, но
/// версия не теряется (повтор идемпотентен).
#[test]
fn kill_after_phase2_fsync_keeps_durable_version() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("kill-phase2.v2");
    let store = setup(&path, 1);

    let mut child = spawn_child(
        "crash_once",
        &path,
        &[
            (ZONE, "1".to_string()),
            (CRASH_AT, "AfterPhase2Fsync".to_string()),
        ],
    );
    let status = wait_deadline(&mut child, Duration::from_secs(30));
    assert!(!status.success(), "координатор должен был погибнуть");
    drop(store);
    assert!(fsck(&path).fatal.is_none(), "phase2 crash: fsck");
    // Запись корня durable: `recovery` обязан увидеть новую версию.
    assert!(zone_version(&path, 1) >= 3, "durable корень потерян");
    assert!(find_record(&path, 1, 999), "RRset durable-коммита потерян");
}

/// Смерть лидера, когда другие процессы уже ждут ack: они подхватывают lease,
/// доводят свои коммиты, `fsck` чист.
#[test]
fn leader_crash_with_waiters_completes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("leader-crash.v2");
    let processes = 4_u32;
    let iterations = 12_u32;
    let store = setup(&path, processes);
    let results = dir.path().join("results");
    std::fs::create_dir_all(&results).expect("results dir");
    let children: Vec<(u32, Child)> = (1..=processes)
        .map(|zone| {
            let child = spawn_child(
                "writer",
                &path,
                &[
                    (ZONE, zone.to_string()),
                    (ITERS, iterations.to_string()),
                    (DELAY_MS, "2".to_string()),
                    (CRASH_AT, "BeforeRootWrite".to_string()),
                    (CRASH_AFTER, "2".to_string()),
                    (CRASH_ONCE, results.join("crashed").display().to_string()),
                    (
                        RESULT,
                        results.join(format!("z{zone}")).display().to_string(),
                    ),
                ],
            );
            (zone, child)
        })
        .collect();
    let mut survivors = Vec::new();
    for (zone, mut child) in children {
        let status = wait_deadline(&mut child, Duration::from_secs(60));
        if status.success() {
            survivors.push(zone);
        }
    }
    drop(store);
    assert!(fsck(&path).fatal.is_none(), "leader crash: fsck");
    assert!(!survivors.is_empty(), "все процессы погибли");
    for zone in &survivors {
        let expected = read_results(&results.join(format!("z{zone}")))
            .first()
            .map_or(0, |(_, version)| *version);
        assert_eq!(
            zone_version(&path, *zone),
            expected,
            "зона {zone}: потерян ack/версия"
        );
        assert!(find_record(&path, *zone, iterations - 1));
    }
    // Лидер мёртв, но файл живой: новый коммит проходит.
    assert_success(spawn_child(
        "writer",
        &path,
        &[
            (ZONE, "1".to_string()),
            (ITERS, "1".to_string()),
            (RESULT, results.join("final").display().to_string()),
        ],
    ));
}
