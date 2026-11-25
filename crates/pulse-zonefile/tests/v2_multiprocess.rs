//! M3 (ADR 0007): межпроцессная параллельная запись в один v2-файл.
//!
//! Каждый тест запускает дочерние процессы того же тест-бинаря (`--exact
//! child_entry`) и проверяет: общий аллокатор/lease/reader table, отсутствие
//! потерь и дублей, `Busy` на зону, видимость версий читателю другого процесса,
//! `kill -9` писателя/читателя и recovery после `kill -9` в середине коммита.
//!
//! Дочерний режим выбирается переменной `PULSE_MP_CHILD`; без неё
//! `child_entry` завершается мгновенно.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    CrashHook, CrashPoint, FsckLiteReport, OpenConfigV2, ParallelError, ParallelStore,
    ParallelZone, ParallelZones, RrsetData, StoreConfig, SyncModeV2, ZoneCreateMeta,
};

const CHILD: &str = "PULSE_MP_CHILD";
const PATH: &str = "PULSE_MP_PATH";
const ZONES: &str = "PULSE_MP_ZONES";
const ZONE: &str = "PULSE_MP_ZONE";
const ITERS: &str = "PULSE_MP_ITERS";
const READY: &str = "PULSE_MP_READY";
const RESULT: &str = "PULSE_MP_RESULT";
const GO: &str = "PULSE_MP_GO";
const CREATE_LOCK: &str = "PULSE_MP_CREATE_LOCK";

fn config() -> StoreConfig {
    StoreConfig {
        multi_process: true,
        ..StoreConfig::small(32, 1 << 17)
    }
}

fn config_memory() -> StoreConfig {
    StoreConfig {
        multi_process: true,
        sync_mode: SyncModeV2::Memory,
        ..StoreConfig::small(8, 1 << 17)
    }
}

fn open_multi(path: &Path) -> Result<ParallelStore, ParallelError> {
    ParallelStore::open(
        path,
        OpenConfigV2 {
            read_only: false,
            writer_lock: false,
            multi_process: true,
            ..OpenConfigV2::default()
        },
    )
}

fn open_multi_read(path: &Path) -> Result<ParallelStore, ParallelError> {
    ParallelStore::open(
        path,
        OpenConfigV2 {
            read_only: true,
            writer_lock: false,
            multi_process: true,
            ..OpenConfigV2::default()
        },
    )
}

fn origin(zone: u32) -> NameRle {
    NameRle::from_ascii(&format!("z{zone}.mp.example")).expect("origin")
}

fn rr(zone: u32, iteration: u32) -> RrsetData {
    RrsetData::from_slices(
        60,
        0,
        &[&[
            10,
            u8::try_from(zone % 256).unwrap_or(0),
            u8::try_from(iteration % 256).unwrap_or(0),
            1,
        ]],
    )
    .expect("rrset")
}

fn setup(path: &Path, zones: u32, cfg: StoreConfig) -> ParallelStore {
    let store = ParallelStore::create(path, cfg).expect("create");
    let mut catalog = ParallelZones::open(&store).expect("catalog");
    for zone in 1..=zones {
        catalog
            .create_zone(&origin(zone), ZoneCreateMeta { soa_serial: zone })
            .expect("create zone");
    }
    store
}

fn parse_u32(name: &str) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

fn parse_list(name: &str) -> Vec<u32> {
    std::env::var(name)
        .unwrap_or_default()
        .split(',')
        .filter_map(|value| value.trim().parse().ok())
        .collect()
}

fn spawn_child(mode: &str, path: &Path, extra: &[(&str, String)]) -> Child {
    let mut command = Command::new(std::env::current_exe().expect("current exe"));
    command
        .args(["--exact", "child_entry", "--nocapture"])
        .env(CHILD, mode)
        .env(PATH, path)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    for (key, value) in extra {
        command.env(key, value);
    }
    command.spawn().expect("spawn child")
}

fn wait_ready(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        assert!(Instant::now() < deadline, "child did not become ready");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn assert_success(mut child: Child) {
    let status = child.wait().expect("wait child");
    assert!(status.success(), "child failed: {status:?}");
}

/// Пишет `iterations` версий в каждую зону `zones`; каждая версия — новый `RRset`.
fn child_write_zone(
    store: &ParallelStore,
    zone: u32,
    iterations: u32,
) -> Result<(), ParallelError> {
    let catalog = ParallelZones::open(store)?;
    let origin = catalog
        .origin(zone)
        .ok_or(ParallelError::NoZoneVersion { zone })?;
    let mut writer = open_writer(store, origin, zone)?;
    for iteration in 0..iterations {
        let name = NameRle::from_ascii(&format!("r{iteration}.z{zone}.mp.example"))
            .map_err(|_| ParallelError::InvalidArgument { field: "name" })?;
        writer.upsert_rrset(&name, 1, 0, &rr(zone, iteration))?;
        commit_retry(&mut writer)?;
    }
    Ok(())
}

fn open_writer(
    store: &ParallelStore,
    origin: NameRle,
    zone: u32,
) -> Result<ParallelZone<'_>, ParallelError> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match ParallelZone::open_uncached(store, origin, zone) {
            Ok(writer) => return Ok(writer),
            Err(error) if error.is_retryable() && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(error) => return Err(error),
        }
    }
}

fn commit_retry(writer: &mut ParallelZone<'_>) -> Result<(), ParallelError> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match writer.commit() {
            Ok(_) => return Ok(()),
            Err(error) if error.is_retryable() && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
}

#[allow(clippy::too_many_lines)]
fn child_body() -> Result<(), String> {
    let mode = std::env::var(CHILD).map_err(|_| "no child mode".to_string())?;
    let path = PathBuf::from(std::env::var(PATH).map_err(|_| "no path".to_string())?);
    match mode.as_str() {
        "writers" => {
            let store = open_multi(&path).map_err(|error| error.to_string())?;
            for zone in parse_list(ZONES) {
                child_write_zone(&store, zone, parse_u32(ITERS).max(1))
                    .map_err(|error| error.to_string())?;
            }
            Ok(())
        }
        "hold_lease" => {
            let store = open_multi(&path).map_err(|error| error.to_string())?;
            let catalog = ParallelZones::open(&store).map_err(|error| error.to_string())?;
            let zone = parse_u32(ZONE);
            let origin = catalog
                .origin(zone)
                .ok_or_else(|| format!("no zone {zone}"))?;
            let _writer = ParallelZone::open_uncached(&store, origin, zone)
                .map_err(|error| error.to_string())?;
            let ready = PathBuf::from(std::env::var(READY).map_err(|_| "no ready".to_string())?);
            std::fs::write(&ready, b"ready").map_err(|error| error.to_string())?;
            std::thread::sleep(Duration::from_secs(20));
            Ok(())
        }
        "same_zone" => {
            let store = open_multi(&path).map_err(|error| error.to_string())?;
            let catalog = ParallelZones::open(&store).map_err(|error| error.to_string())?;
            let zone = parse_u32(ZONE);
            let origin = catalog
                .origin(zone)
                .ok_or_else(|| format!("no zone {zone}"))?;
            let result = match ParallelZone::open_uncached(&store, origin, zone) {
                Ok(mut writer) => {
                    let name = NameRle::from_ascii(&format!("after.z{zone}.mp.example"))
                        .map_err(|_| "name".to_string())?;
                    writer
                        .upsert_rrset(&name, 1, 0, &rr(zone, 1))
                        .map_err(|error| error.to_string())?;
                    commit_retry(&mut writer).map_err(|error| error.to_string())?;
                    "ok"
                }
                Err(ParallelError::ZoneBusy { .. }) => "busy",
                Err(error) => return Err(error.to_string()),
            };
            if let Ok(path) = std::env::var(RESULT) {
                std::fs::write(path, result).map_err(|error| error.to_string())?;
            }
            Ok(())
        }
        "kill_writer" => {
            let store = open_multi(&path).map_err(|error| error.to_string())?;
            let zone = parse_u32(ZONE);
            let start = Instant::now();
            while start.elapsed() < Duration::from_secs(30) {
                child_write_zone(&store, zone, 1).map_err(|error| error.to_string())?;
            }
            Ok(())
        }
        "hold_reader" => {
            let store = open_multi_read(&path).map_err(|error| error.to_string())?;
            let reader = store.reader().map_err(|error| error.to_string())?;
            let zone = parse_u32(ZONE);
            let _snapshot = store
                .zone_snapshot(&reader, zone)
                .map_err(|error| error.to_string())?;
            let ready = PathBuf::from(std::env::var(READY).map_err(|_| "no ready".to_string())?);
            std::fs::write(&ready, b"ready").map_err(|error| error.to_string())?;
            std::thread::sleep(Duration::from_secs(20));
            Ok(())
        }
        "reader" => {
            let store = open_multi_read(&path).map_err(|error| error.to_string())?;
            let catalog = ParallelZones::open(&store).map_err(|error| error.to_string())?;
            let zone = parse_u32(ZONE);
            let origin = catalog
                .origin(zone)
                .ok_or_else(|| format!("no zone {zone}"))?;
            let reader = store.reader().map_err(|error| error.to_string())?;
            let mut seen = std::collections::BTreeSet::new();
            // Первый снапшот + ready, чтобы writer стартовал после читателя и
            // тест гарантированно наблюдал обе версии.
            let view = catalog
                .read(&reader, &origin)
                .map_err(|error| error.to_string())?;
            let mut last = view.version();
            seen.insert(last);
            if let Ok(ready) = std::env::var(READY) {
                std::fs::write(ready, b"ready").map_err(|error| error.to_string())?;
            }
            let deadline = Instant::now() + Duration::from_secs(20);
            while seen.len() < 2 && Instant::now() < deadline {
                match catalog.read(&reader, &origin) {
                    Ok(view) => {
                        let version = view.version();
                        assert!(version >= last, "version regressed: {version} < {last}");
                        last = version;
                        let _records = view.records().map_err(|error| error.to_string())?;
                        seen.insert(version);
                    }
                    Err(
                        ParallelError::ReaderContended
                        | ParallelError::StaleRoot { .. }
                        | ParallelError::NoZoneVersion { .. },
                    ) => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => return Err(error.to_string()),
                }
            }
            assert!(seen.len() >= 2, "reader did not observe two versions");
            Ok(())
        }
        "crash_commit" => {
            let mut store = open_multi(&path).map_err(|error| error.to_string())?;
            store.set_crash_hook(Box::new(KillAt(CrashPoint::AfterPhase1Fsync)));
            let catalog = ParallelZones::open(&store).map_err(|error| error.to_string())?;
            let zone = parse_u32(ZONE);
            let origin = catalog
                .origin(zone)
                .ok_or_else(|| format!("no zone {zone}"))?;
            let mut writer = ParallelZone::open_uncached(&store, origin, zone)
                .map_err(|error| error.to_string())?;
            let name =
                NameRle::from_ascii("crash.z1.mp.example").map_err(|_| "name".to_string())?;
            writer
                .upsert_rrset(&name, 1, 0, &rr(zone, 7))
                .map_err(|error| error.to_string())?;
            writer.commit().map_err(|error| error.to_string())?;
            Ok(())
        }
        "churn" => {
            let store = ParallelStore::open(
                &path,
                OpenConfigV2 {
                    multi_process: true,
                    read_only: false,
                    writer_lock: false,
                    ..OpenConfigV2::default()
                },
            )
            .map_err(|error| error.to_string())?;
            let catalog = ParallelZones::open(&store).map_err(|error| error.to_string())?;
            let zone = parse_u32(ZONE);
            let origin = catalog
                .origin(zone)
                .ok_or_else(|| format!("no zone {zone}"))?;
            let mut writer = open_writer(&store, origin, zone).map_err(|e| e.to_string())?;
            let iterations = parse_u32(ITERS).max(1);
            // Один ключ: цель — 10 000 циклов alloc/commit, а не размер дерева
            // (upsert нового ключа в v1-дерево сам по себе O(листа)).
            let name = NameRle::from_ascii(&format!("churn.z{zone}.mp.example"))
                .map_err(|_| "name".to_string())?;
            for iteration in 0..iterations {
                writer
                    .upsert_rrset(&name, 1, 0, &rr(zone, iteration))
                    .map_err(|error| error.to_string())?;
                retry_memory(&mut writer)?;
            }
            Ok(())
        }
        "create_zones" => {
            let store = open_multi(&path).map_err(|error| error.to_string())?;
            let zones = parse_list(ZONES);
            let lock_path = PathBuf::from(
                std::env::var(CREATE_LOCK).map_err(|_| "no create lock".to_string())?,
            );
            // Каталог — один writer (ADR 0007 §8, R4): сериализуем create
            // между процессами файловым `flock`, внутри — свежий каталог под
            // lease. Так тест проверяет lease/шарды (зоны 256/512), а не
            // потерянные обновления каталога.
            let lock = std::fs::OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .truncate(false)
                .open(&lock_path)
                .map_err(|error| error.to_string())?;
            let ready = PathBuf::from(std::env::var(READY).map_err(|_| "no ready".to_string())?);
            std::fs::write(&ready, b"ready").map_err(|error| error.to_string())?;
            let go = PathBuf::from(std::env::var(GO).map_err(|_| "no go".to_string())?);
            let start = Instant::now();
            while !go.exists() {
                if start.elapsed() > Duration::from_secs(10) {
                    return Err("no go signal".to_string());
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            for zone in zones {
                let deadline = Instant::now() + Duration::from_secs(20);
                loop {
                    rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive)
                        .map_err(|error| error.to_string())?;
                    let result = {
                        let mut catalog =
                            ParallelZones::open(&store).map_err(|error| error.to_string())?;
                        catalog
                            .create_zone(&origin(zone), ZoneCreateMeta { soa_serial: zone })
                            .map(|_| ())
                    };
                    rustix::fs::flock(&lock, rustix::fs::FlockOperation::Unlock)
                        .map_err(|error| error.to_string())?;
                    match result {
                        Ok(()) => break,
                        Err(error) => {
                            if Instant::now() >= deadline {
                                return Err(format!("create zone {zone}: {error}"));
                            }
                            std::thread::sleep(Duration::from_millis(1));
                        }
                    }
                }
            }
            Ok(())
        }
        other => Err(format!("unknown child mode {other}")),
    }
}

fn retry_memory(writer: &mut ParallelZone<'_>) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match writer.commit_with(SyncModeV2::Memory) {
            Ok(_) => return Ok(()),
            Err(error) if error.is_retryable() && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error.to_string()),
        }
    }
}

struct KillAt(CrashPoint);

impl CrashHook for KillAt {
    fn at(&self, point: CrashPoint) {
        if point == self.0 {
            let _ = rustix::process::kill_process(
                rustix::process::getpid(),
                rustix::process::Signal::KILL,
            );
        }
    }
}

/// Дочерний вход: выполняет режим из `PULSE_MP_CHILD` (иначе no-op).
#[test]
fn child_entry() {
    if std::env::var(CHILD).is_err() {
        return;
    }
    if let Err(error) = child_body() {
        panic!("child failed: {error}");
    }
}

fn verify_zones(path: &Path, zones: u32, expected: u32) {
    let store = ParallelStore::open(path, OpenConfigV2::default()).expect("reopen");
    let catalog = ParallelZones::open(&store).expect("catalog");
    let reader = store.reader().expect("reader");
    let mut versions = std::collections::BTreeSet::new();
    for zone in 1..=zones {
        let origin = catalog.origin(zone).unwrap_or_else(|| origin(zone));
        let view = catalog.read(&reader, &origin).expect("zone read");
        let records = view.records().expect("records");
        assert_eq!(
            u32::try_from(records.len()).unwrap(),
            expected,
            "zone {zone}: потеряны/задвоены RRset"
        );
        assert!(versions.insert(view.version()), "txn переиспользован");
    }
    assert!(store.fsck_lite().expect("fsck").fatal.is_none());
    assert!(store.fsck_graph().expect("graph").fatal.is_none());
}

fn fsck_multi(path: &Path) -> FsckLiteReport {
    let store = open_multi(path).expect("open multi for fsck");
    store.fsck_lite().expect("fsck")
}

/// 4 процесса × 4 зоны: параллельные коммиты, нет потерь/дублей, reopen+fsck.
#[test]
fn four_processes_four_zones_each_without_loss_or_duplicates() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("mp4.v2");
    let store = setup(&path, 16, config());
    drop(store);

    let children: Vec<Child> = (0..4)
        .map(|process| {
            let zones: Vec<String> = (0..4)
                .map(|slot| (process * 4 + slot + 1).to_string())
                .collect();
            spawn_child(
                "writers",
                &path,
                &[(ZONES, zones.join(",")), (ITERS, "20".to_string())],
            )
        })
        .collect();
    for child in children {
        assert_success(child);
    }

    verify_zones(&path, 16, 20);
}

/// Два процесса создают зоны одного файла параллельно. Каталог — один
/// writer (ADR 0007 §8, R4), поэтому create сериализован файловым `flock`;
/// проверяем, что зоны 256/512 (шард каталога в старом маппинге) не дают
/// self-deadlock и каталог не теряет записи. Дедлайн 30 с — зависание = провал.
#[test]
fn two_processes_create_zones_without_hang() {
    const PER_PROCESS: u32 = 260;
    const TOTAL: u32 = PER_PROCESS * 2;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("create2p.v2");
    let cfg = StoreConfig {
        multi_process: true,
        sync_mode: SyncModeV2::Memory,
        ..StoreConfig::small(TOTAL + 64, 1 << 16)
    };
    drop(ParallelStore::create(&path, cfg).expect("create"));

    let create_lock = dir.path().join("create.lock");
    let go = dir.path().join("go");
    let mut children = Vec::new();
    for process in 0..2_u32 {
        let start = process * PER_PROCESS + 1;
        let end = start + PER_PROCESS - 1;
        let zones: Vec<String> = (start..=end).map(|zone| zone.to_string()).collect();
        let ready = dir.path().join(format!("ready-{process}"));
        children.push(spawn_child(
            "create_zones",
            &path,
            &[
                (ZONES, zones.join(",")),
                (CREATE_LOCK, create_lock.display().to_string()),
                (READY, ready.display().to_string()),
                (GO, go.display().to_string()),
            ],
        ));
    }
    for process in 0..2_u32 {
        wait_ready(&dir.path().join(format!("ready-{process}")));
    }
    std::fs::write(&go, b"go").expect("go signal");

    let deadline = Instant::now() + Duration::from_secs(30);
    for mut child in children {
        loop {
            if let Some(status) = child.try_wait().expect("try_wait") {
                assert!(status.success(), "create child failed: {status:?}");
                break;
            }
            assert!(
                Instant::now() < deadline,
                "create в двух процессах завис (>30 с)"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    let store = open_multi(&path).expect("reopen multi");
    let catalog = ParallelZones::open(&store).expect("catalog");
    assert_eq!(
        catalog.zones().len(),
        usize::try_from(TOTAL).unwrap(),
        "каталог потерял зоны"
    );
    for zone in 1..=TOTAL {
        assert!(
            catalog.zone_seq(&origin(zone)).is_some(),
            "зона {zone} потеряна"
        );
    }
    assert!(store.fsck_lite().expect("fsck").ok);
}

/// Два процесса на одну зону: второй получает `Busy`; после `kill -9`
/// lease освобождается ядром и второй может писать.
#[test]
fn second_writer_same_zone_gets_busy_and_recovers_after_kill() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("same-zone.v2");
    let store = setup(&path, 2, config());
    drop(store);

    let ready = dir.path().join("ready");
    let mut holder = spawn_child(
        "hold_lease",
        &path,
        &[
            (ZONE, "1".to_string()),
            (READY, ready.display().to_string()),
        ],
    );
    wait_ready(&ready);

    let contender_result = dir.path().join("contender-result");
    assert_success(spawn_child(
        "same_zone",
        &path,
        &[
            (ZONE, "1".to_string()),
            (RESULT, contender_result.display().to_string()),
        ],
    ));
    assert_eq!(std::fs::read_to_string(&contender_result).unwrap(), "busy");

    holder.kill().expect("kill holder");
    let _ = holder.wait();

    // Lease снят ядром: новый writer той же зоны проходит.
    let after_result = dir.path().join("after-result");
    assert_success(spawn_child(
        "same_zone",
        &path,
        &[
            (ZONE, "1".to_string()),
            (RESULT, after_result.display().to_string()),
        ],
    ));
    assert_eq!(std::fs::read_to_string(&after_result).unwrap(), "ok");
    verify_zones(&path, 1, 1);
}

/// Читатель в другом процессе во время записи видит старые/новые версии и
/// никогда не читает несогласованный срез.
#[test]
fn reader_in_other_process_sees_consistent_versions() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("reader.v2");
    let store = setup(&path, 1, config());
    drop(store);

    let ready = dir.path().join("reader-started");
    let reader = spawn_child(
        "reader",
        &path,
        &[
            (ZONE, "1".to_string()),
            (READY, ready.display().to_string()),
        ],
    );
    wait_ready(&ready);
    let writer = spawn_child(
        "writers",
        &path,
        &[(ZONES, "1".to_string()), (ITERS, "60".to_string())],
    );
    assert_success(reader);
    assert_success(writer);
}

/// `kill -9` писателя: lease/reader очищены, чужие зоны целы, reopen работает.
#[test]
fn kill9_writer_cleans_lease_and_reader_and_keeps_other_zones() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("kill9.v2");
    let store = setup(&path, 3, config());
    drop(store);

    let mut victim = spawn_child("kill_writer", &path, &[(ZONE, "1".to_string())]);
    // Дать victim'у закоммитить несколько версий.
    std::thread::sleep(Duration::from_millis(400));
    victim.kill().expect("kill -9 writer");
    let status = victim.wait().expect("wait victim");
    assert!(!status.success(), "victim пережил kill -9");

    // Другая зона пишется после смерти соседа.
    assert_success(spawn_child(
        "writers",
        &path,
        &[(ZONES, "2".to_string()), (ITERS, "10".to_string())],
    ));

    let store = open_multi(&path).expect("reopen multi");
    let _ = store.gc_pass().expect("gc");
    assert_eq!(store.active_pins(), 0, "мёртвый reader не санитизирован");
    assert!(store.fsck_lite().expect("fsck").fatal.is_none());
    drop(store);

    // Lease убитой зоны свободен.
    assert_success(spawn_child("same_zone", &path, &[(ZONE, "1".to_string())]));
}

/// `kill -9` читателя: его слот reader table санитизируется, GC не стоит.
#[test]
fn kill9_reader_slot_is_sanitized() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("kill-reader.v2");
    let store = setup(&path, 1, config());
    drop(store);

    let ready = dir.path().join("reader-ready");
    let mut reader = spawn_child(
        "hold_reader",
        &path,
        &[
            (ZONE, "1".to_string()),
            (READY, ready.display().to_string()),
        ],
    );
    wait_ready(&ready);
    reader.kill().expect("kill reader");
    let _ = reader.wait();

    let store = open_multi(&path).expect("open");
    let _ = store.gc_pass().expect("gc");
    assert_eq!(store.active_pins(), 0);
    assert!(store.zone_head(1).is_some_and(|head| !head.is_tombstone()));
}

/// `kill -9` в середине коммита (после durable-фазы 1): зона на прежней
/// версии, `DP` не откатывается, файл открывается и пишется.
#[test]
fn kill9_during_commit_recovers_previous_version() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("crash-commit.v2");
    let store = setup(&path, 1, config());
    drop(store);

    let before = {
        let store = ParallelStore::open(&path, OpenConfigV2::default()).expect("open");
        store.zone_head(1).map_or(0, |head| head.version)
    };

    let mut child = spawn_child("crash_commit", &path, &[(ZONE, "1".to_string())]);
    let status = child.wait().expect("wait crash child");
    assert!(!status.success(), "child должен был умереть");

    let report = fsck_multi(&path);
    assert!(report.fatal.is_none(), "recovery: {report:?}");
    let store = ParallelStore::open(&path, OpenConfigV2::default()).expect("reopen");
    let head = store.zone_head(1).expect("zone head");
    assert!(
        head.version >= before,
        "неожиданная версия: {} (было {before})",
        head.version
    );
    drop(store);

    // Зона снова пишется.
    assert_success(spawn_child(
        "writers",
        &path,
        &[(ZONES, "1".to_string()), (ITERS, "3".to_string())],
    ));
}

/// 10 000 циклов alloc/commit в 2 процессах: пересечений страниц нет (`fsck`).
#[test]
fn ten_thousand_commits_in_two_processes_do_not_overlap_pages() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("churn.v2");
    let store = setup(&path, 2, config_memory());
    drop(store);

    let first = spawn_child(
        "churn",
        &path,
        &[(ZONE, "1".to_string()), (ITERS, "5000".to_string())],
    );
    let second = spawn_child(
        "churn",
        &path,
        &[(ZONE, "2".to_string()), (ITERS, "5000".to_string())],
    );
    assert_success(first);
    assert_success(second);

    let store = open_multi(&path).expect("open");
    let graph = store.fsck_graph().expect("graph");
    assert!(graph.fatal.is_none(), "пересечение/порча: {graph:?}");
    let report = store.fsck_lite().expect("fsck");
    assert!(report.fatal.is_none(), "{report:?}");
    let reader = store.reader().expect("reader");
    let catalog = ParallelZones::open(&store).expect("catalog");
    for zone in 1..=2 {
        let view = catalog.read(&reader, &origin(zone)).expect("zone snapshot");
        let records = view.records().expect("records");
        assert_eq!(records.len(), 1, "zone {zone}: {records:?}");
        assert!(view.version() > 5000, "zone {zone}: мало коммитов");
    }
}
