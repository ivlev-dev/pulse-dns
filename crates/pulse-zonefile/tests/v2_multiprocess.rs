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
    ParallelZone, ParallelZones, RrsetData, StoreConfig, SyncModeV2, ZoneCreateMeta, ZoneMetaV2,
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
const VALUE: &str = "PULSE_MP_VALUE";
const VALUE2: &str = "PULSE_MP_VALUE2";
const KEYS: &str = "PULSE_MP_KEYS";

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

fn key(zone: u32, index: u32) -> NameRle {
    NameRle::from_ascii(&format!("k{index}.z{zone}.mp.example")).expect("key")
}

/// `RRset` с последним байтом `value` (для проверки, что читатель видит новую
/// версию после переиспользования страницы).
fn value_rr(value: u8) -> RrsetData {
    RrsetData::from_slices(60, 0, &[&[192, 0, 2, value]]).expect("value rrset")
}

fn read_value(
    catalog: &ParallelZones<'_>,
    reader: &pulse_zonefile::parallel::Reader<'_>,
    zone: u32,
    index: u32,
) -> u8 {
    let origin = origin(zone);
    let view = catalog.read(reader, &origin).expect("read view");
    let record = view
        .lookup(&key(zone, index), 1, 0)
        .expect("lookup")
        .expect("record");
    *record
        .rdata
        .first()
        .and_then(|rdata| rdata.last())
        .unwrap_or(&0)
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
        "cache_reader" => {
            let store = open_multi_read(&path).map_err(|error| error.to_string())?;
            let catalog = ParallelZones::open(&store).map_err(|error| error.to_string())?;
            let zone = parse_u32(ZONE);
            let keys = parse_u32(KEYS).max(1);
            let first_value = u8::try_from(parse_u32(VALUE).max(1)).unwrap_or(u8::MAX);
            let second_value = u8::try_from(parse_u32(VALUE2).max(2)).unwrap_or(u8::MAX);
            let reader = store.reader().map_err(|error| error.to_string())?;
            for index in 0..keys {
                let value = read_value(&catalog, &reader, zone, index);
                assert_eq!(value, first_value, "warm value key {index}");
            }
            let ready = PathBuf::from(std::env::var(READY).map_err(|_| "no ready".to_string())?);
            std::fs::write(&ready, b"ready").map_err(|error| error.to_string())?;
            let go = PathBuf::from(std::env::var(GO).map_err(|_| "no go".to_string())?);
            let deadline = Instant::now() + Duration::from_secs(60);
            while !go.exists() {
                if Instant::now() >= deadline {
                    return Err("cache reader: no go signal".to_string());
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            // Кеш уже прогрет старыми образами; writer переиспользовал номера
            // страниц под lease. Новый снапшот обязан вернуть новые значения.
            for index in 0..keys {
                let value = read_value(&catalog, &reader, zone, index);
                assert_eq!(value, second_value, "stale page returned for key {index}");
            }
            let stats = store.page_cache_stats();
            assert!(stats.hits > 0, "shared raw cache did not hit: {stats:?}");
            assert!(store.node_cache_stats().hits > 0, "node cache did not hit");
            if let Ok(result) = std::env::var(RESULT) {
                std::fs::write(
                    result,
                    format!(
                        "ok,{},{},{}",
                        stats.hits,
                        stats.misses,
                        store.node_cache_stats().hits
                    ),
                )
                .map_err(|error| error.to_string())?;
            }
            Ok(())
        }
        "delete_reinsert" => {
            let store = open_multi(&path).map_err(|error| error.to_string())?;
            let catalog = ParallelZones::open(&store).map_err(|error| error.to_string())?;
            let zone = parse_u32(ZONE);
            let keys = parse_u32(KEYS).max(1);
            let value = u8::try_from(parse_u32(VALUE2).max(2)).unwrap_or(u8::MAX);
            let origin = catalog
                .origin(zone)
                .ok_or_else(|| format!("no zone {zone}"))?;
            let root_page = {
                let reader = store.reader().map_err(|error| error.to_string())?;
                let view = catalog.read(&reader, &origin).map_err(|e| e.to_string())?;
                view.root().root_page
            };
            let root_generation = store.page_generation(root_page);
            let mut writer = open_writer(&store, origin, zone).map_err(|e| e.to_string())?;
            for index in 0..keys {
                let _ = writer
                    .delete_rrset(&key(zone, index), 1, 0)
                    .map_err(|error| error.to_string())?;
            }
            commit_retry(&mut writer).map_err(|e| e.to_string())?;
            // D_z догоняет удаление; после этого пул может отдавать страницы.
            store.sync().map_err(|error| error.to_string())?;
            for index in 0..keys {
                writer
                    .upsert_rrset(&key(zone, index), 1, 0, &value_rr(value))
                    .map_err(|error| error.to_string())?;
            }
            commit_retry(&mut writer).map_err(|e| e.to_string())?;
            assert!(
                store.page_generation(root_page) > root_generation,
                "генерация освобождённой/переиспользованной страницы не выросла: \
                 {} → {}",
                root_generation,
                store.page_generation(root_page)
            );
            Ok(())
        }
        "read_write_delete" => {
            let store = open_multi(&path).map_err(|error| error.to_string())?;
            let catalog = ParallelZones::open(&store).map_err(|error| error.to_string())?;
            let zone = parse_u32(ZONE);
            let keys = parse_u32(KEYS).max(1);
            let iterations = parse_u32(ITERS).max(1);
            let reader = store.reader().map_err(|error| error.to_string())?;
            let origin = catalog
                .origin(zone)
                .ok_or_else(|| format!("no zone {zone}"))?;
            let mut writer = open_writer(&store, origin, zone).map_err(|e| e.to_string())?;
            for iteration in 0..iterations {
                // Читатель в этом же процессе видит консистентный снапшот.
                // Ключ `keys-1` не участвует в upsert/delete этой нагрузки.
                let value = read_value(&catalog, &reader, zone, keys - 1);
                assert_eq!(value, 1, "initial read zone {zone}");
                // Пишем и удаляем разные ключи: каждая транзакция освобождает
                // страницы, которые пул затем переиспользует.
                writer
                    .upsert_rrset(&key(zone, iteration % keys), 1, 0, &value_rr(2))
                    .map_err(|error| error.to_string())?;
                commit_retry(&mut writer).map_err(|e| e.to_string())?;
                let _ = writer
                    .delete_rrset(&key(zone, (iteration + 1) % keys), 1, 0)
                    .map_err(|error| error.to_string())?;
                commit_retry(&mut writer).map_err(|e| e.to_string())?;
            }
            let stats = store.page_cache_stats();
            assert!(stats.hits > 0, "zone {zone}: shared cache did not hit");
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
        "catalog_create" => {
            // Без внешнего flock: сериализация — catalog lease + commit-lock.
            let store = open_multi(&path).map_err(|error| error.to_string())?;
            for zone in parse_list(ZONES) {
                let deadline = Instant::now() + Duration::from_secs(30);
                loop {
                    let result = {
                        let mut catalog =
                            ParallelZones::open(&store).map_err(|error| error.to_string())?;
                        catalog.create_zone(&origin(zone), ZoneCreateMeta { soa_serial: zone })
                    };
                    match result {
                        Ok(_) => break,
                        Err(error) if error.is_retryable() && Instant::now() < deadline => {
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        Err(error) => return Err(format!("create zone {zone}: {error}")),
                    }
                }
            }
            Ok(())
        }
        "catalog_meta" => {
            let store = open_multi(&path).map_err(|error| error.to_string())?;
            for zone in parse_list(ZONES) {
                let deadline = Instant::now() + Duration::from_secs(30);
                loop {
                    let result = {
                        let mut catalog =
                            ParallelZones::open(&store).map_err(|error| error.to_string())?;
                        catalog.set_zone_meta(
                            &origin(zone),
                            ZoneMetaV2 {
                                default_ttl: 1000 + zone,
                                ..ZoneMetaV2::default()
                            },
                        )
                    };
                    match result {
                        Ok(_) => break,
                        Err(error) if error.is_retryable() && Instant::now() < deadline => {
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        Err(error) => return Err(format!("meta zone {zone}: {error}")),
                    }
                }
            }
            Ok(())
        }
        "catalog_churn" => {
            let store = open_multi(&path).map_err(|error| error.to_string())?;
            for zone in parse_list(ZONES) {
                let deadline = Instant::now() + Duration::from_secs(30);
                loop {
                    let result = {
                        let mut catalog =
                            ParallelZones::open(&store).map_err(|error| error.to_string())?;
                        catalog.set_zone_meta(
                            &origin(zone),
                            ZoneMetaV2 {
                                default_ttl: 1000 + zone,
                                ..ZoneMetaV2::default()
                            },
                        )
                    };
                    match result {
                        Ok(_) => break,
                        Err(error) if error.is_retryable() && Instant::now() < deadline => {
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        Err(error) => return Err(format!("meta zone {zone}: {error}")),
                    }
                }
                if zone % 2 != 0 {
                    continue;
                }
                // Tombstone → global sync (D_z) → gc каталога → повторное
                // создание на переиспользованном slot.
                loop {
                    let result = {
                        let mut catalog =
                            ParallelZones::open(&store).map_err(|error| error.to_string())?;
                        catalog.delete_zone(&origin(zone))
                    };
                    match result {
                        Ok(_) => break,
                        Err(error) if error.is_retryable() && Instant::now() < deadline => {
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        Err(error) => return Err(format!("delete zone {zone}: {error}")),
                    }
                }
                store.sync().map_err(|error| error.to_string())?;
                {
                    let mut catalog =
                        ParallelZones::open(&store).map_err(|error| error.to_string())?;
                    catalog.gc_catalog().map_err(|error| error.to_string())?;
                }
                loop {
                    let result = {
                        let mut catalog =
                            ParallelZones::open(&store).map_err(|error| error.to_string())?;
                        catalog
                            .create_zone_with_meta(
                                &origin(zone),
                                ZoneCreateMeta {
                                    soa_serial: zone + 1000,
                                },
                                ZoneMetaV2 {
                                    default_ttl: 2000 + zone,
                                    ..ZoneMetaV2::default()
                                },
                            )
                            .map(|_| ())
                    };
                    match result {
                        Ok(()) => break,
                        Err(error) if error.is_retryable() && Instant::now() < deadline => {
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        Err(error) => return Err(format!("recreate zone {zone}: {error}")),
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

/// 4 процесса читают/пишут/удаляют свои зоны одновременно; multi-кеш
/// (страницы + узлы) включён, после прогона `fsck_lite`/`fsck_graph` чисты.
#[test]
fn four_processes_read_write_delete_with_shared_cache() {
    const ZONES: u32 = 4;
    const KEYS_COUNT: u32 = 50;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("mp-rwd.v2");
    let store = setup(&path, ZONES, config());
    for zone in 1..=ZONES {
        let mut writer = open_writer(&store, origin(zone), zone).expect("writer");
        for index in 0..KEYS_COUNT {
            writer
                .upsert_rrset(&key(zone, index), 1, 0, &value_rr(1))
                .expect("insert");
        }
        writer.commit().expect("commit");
    }
    drop(store);

    let children: Vec<Child> = (1..=ZONES)
        .map(|zone| {
            spawn_child(
                "read_write_delete",
                &path,
                &[
                    (ZONE, zone.to_string()),
                    (KEYS, KEYS_COUNT.to_string()),
                    (ITERS, "8".to_string()),
                ],
            )
        })
        .collect();
    for child in children {
        assert_success(child);
    }

    let store = open_multi(&path).expect("reopen");
    let catalog = ParallelZones::open(&store).expect("catalog");
    let reader = store.reader().expect("reader");
    for zone in 1..=ZONES {
        let view = catalog.read(&reader, &origin(zone)).expect("view");
        let value = view
            .lookup(&key(zone, 0), 1, 0)
            .expect("lookup")
            .expect("record");
        assert!(!value.rdata.is_empty(), "zone {zone}: потерян RRset");
        let _ = view.records().expect("records");
    }
    assert!(store.fsck_lite().expect("fsck").fatal.is_none());
    let graph = store.fsck_graph().expect("graph");
    assert!(graph.fatal.is_none(), "{graph:?}");
    assert!(graph.leaked_pages < graph.durable_pages / 2, "{graph:?}");
}

/// Читатель в другом процессе прогревает общий кеш старыми образами; writer
/// освобождает и переиспользует номера страниц. Новый снапшот обязан вернуть
/// новые значения: ключ кеша — `(page_no, generation)`, generation возрастает
/// при освобождении/выдаче. `high_water` при этом не растёт неограниченно.
#[test]
fn reader_cache_in_other_process_does_not_serve_reused_pages() {
    const KEYS_COUNT: u32 = 120;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("mp-gen.v2");
    let store = setup(&path, 1, config());
    {
        let mut writer = open_writer(&store, origin(1), 1).expect("writer");
        for index in 0..KEYS_COUNT {
            writer
                .upsert_rrset(&key(1, index), 1, 0, &value_rr(1))
                .expect("insert");
        }
        writer.commit().expect("commit");
    }
    let before_high_water = store.high_water();
    drop(store);

    let ready = dir.path().join("cache-reader-ready");
    let go = dir.path().join("cache-reader-go");
    let result = dir.path().join("cache-reader-result");
    let reader = spawn_child(
        "cache_reader",
        &path,
        &[
            (ZONE, "1".to_string()),
            (KEYS, KEYS_COUNT.to_string()),
            (VALUE, "1".to_string()),
            (VALUE2, "2".to_string()),
            (READY, ready.display().to_string()),
            (GO, go.display().to_string()),
            (RESULT, result.display().to_string()),
        ],
    );
    wait_ready(&ready);
    assert_success(spawn_child(
        "delete_reinsert",
        &path,
        &[
            (ZONE, "1".to_string()),
            (KEYS, KEYS_COUNT.to_string()),
            (VALUE2, "2".to_string()),
        ],
    ));
    std::fs::write(&go, b"go").expect("go signal");
    assert_success(reader);

    let report = std::fs::read_to_string(&result).expect("reader result");
    assert!(report.starts_with("ok,"), "reader result: {report:?}");
    let store = open_multi(&path).expect("reopen");
    let after_high_water = store.high_water();
    assert!(
        after_high_water <= before_high_water.saturating_add(u64::from(KEYS_COUNT) * 16 + 2048),
        "страницы не переиспользованы: high_water {before_high_water} → {after_high_water}"
    );
    assert!(store.fsck_lite().expect("fsck").fatal.is_none());
    let graph = store.fsck_graph().expect("graph");
    assert!(graph.fatal.is_none(), "{graph:?}");
}

/// Выдача и перезапись страницы в multi инкрементируют общую генерацию;
/// таблица генераций живёт в sidecar и не меняет формат данных.
#[test]
fn page_generation_advances_on_alloc_and_write() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("mp-generation.v2");
    let store = open_multi_after_create(&path);
    let ticket = store.reserve_pages(4).expect("reserve");
    let page = ticket.first_page;
    let allocated = store.page_generation(page);
    assert!(allocated > 0, "генерация не выставлена при выдаче");
    for page in ticket.first_page..=ticket.last_page() {
        assert!(store.page_generation(page) > 0);
    }
    store.write_raw_page(page, b"first").expect("write");
    let written = store.page_generation(page);
    assert!(written > allocated, "генерация не выросла после записи");
    store.write_raw_page(page, b"second").expect("rewrite");
    assert!(
        store.page_generation(page) > written,
        "генерация не выросла после перезаписи"
    );
    assert!(
        store.page_generation_bytes() >= 4 * usize::try_from(ticket.pages).unwrap_or(1),
        "таблица генераций пуста"
    );
    // Single-process: учёта нет, ключ кеша остаётся generation = 0.
    let single_path = dir.path().join("single-generation.v2");
    let single =
        ParallelStore::create(&single_path, StoreConfig::small(4, 1 << 12)).expect("create single");
    let single_page = single.reserve_pages(1).expect("reserve single").first_page;
    assert_eq!(single.page_generation(single_page), 0);
    assert_eq!(single.page_generation_bytes(), 0);
}

/// `kill -9` писателя при включённом multi-кеше: lease/reader очищаются,
/// читатель другого процесса открывает файл, кеш работает, `fsck` чист.
#[test]
fn kill9_writer_with_shared_cache_reopens_and_reads() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("mp-kill-cache.v2");
    let store = setup(&path, 1, config());
    {
        let mut writer = open_writer(&store, origin(1), 1).expect("writer");
        for index in 0..32 {
            writer
                .upsert_rrset(&key(1, index), 1, 0, &value_rr(1))
                .expect("insert");
        }
        writer.commit().expect("commit");
    }
    drop(store);
    let mut victim = spawn_child("kill_writer", &path, &[(ZONE, "1".to_string())]);
    std::thread::sleep(Duration::from_millis(400));
    victim.kill().expect("kill writer");
    let _ = victim.wait();

    let store = open_multi_read(&path).expect("reopen read-only");
    let catalog = ParallelZones::open(&store).expect("catalog");
    let reader = store.reader().expect("reader");
    for _ in 0..3 {
        let view = catalog.read(&reader, &origin(1)).expect("view");
        assert!(view.lookup(&key(1, 0), 1, 0).expect("lookup").is_some());
        let _ = view.records().expect("records");
    }
    assert!(
        store.page_cache_stats().hits > 0,
        "multi read cache did not hit"
    );
    assert!(store.node_cache_stats().hits > 0, "node cache did not hit");
    drop(reader);
    drop(catalog);
    drop(store);

    let store = open_multi(&path).expect("reopen writer");
    assert!(store.fsck_lite().expect("fsck").fatal.is_none());
    assert!(store.fsck_graph().expect("graph").fatal.is_none());
}

fn open_multi_after_create(path: &Path) -> ParallelStore {
    let cfg = StoreConfig {
        multi_process: true,
        sync_mode: SyncModeV2::Memory,
        ..StoreConfig::small(32, 1 << 14)
    };
    drop(ParallelStore::create(path, cfg).expect("create"));
    open_multi(path).expect("open multi")
}

fn fsck_multi(path: &Path) -> FsckLiteReport {
    let store = open_multi(path).expect("open multi for fsck");
    store.fsck_lite().expect("fsck")
}

/// 4 процесса × 250 зон: каталог пишется параллельно без внешнего flock
/// (сериализация — catalog lease + commit-lock), читатель между процессами
/// видит консистентный каталог через polling (`refresh`).
#[test]
fn four_processes_create_1000_zones_without_external_lock() {
    const PER_PROCESS: u32 = 250;
    const TOTAL: u32 = PER_PROCESS * 4;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("catalog-1000.v2");
    let cfg = StoreConfig {
        multi_process: true,
        sync_mode: SyncModeV2::Memory,
        ..StoreConfig::small(TOTAL + 64, 1 << 18)
    };
    drop(ParallelStore::create(&path, cfg).expect("create"));

    let children: Vec<Child> = (0..4_u32)
        .map(|process| {
            let start = process * PER_PROCESS + 1;
            let end = start + PER_PROCESS - 1;
            let zones: Vec<String> = (start..=end).map(|zone| zone.to_string()).collect();
            spawn_child("catalog_create", &path, &[(ZONES, zones.join(","))])
        })
        .collect();

    let store = open_multi(&path).expect("open multi");
    let mut catalog = ParallelZones::open(&store).expect("catalog");
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        catalog.refresh().expect("refresh catalog");
        if catalog.entry_count() == usize::try_from(TOTAL).unwrap() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "каталог не собрал {TOTAL} зон: {}",
            catalog.entry_count()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    for child in children {
        assert_success(child);
    }
    catalog.refresh().expect("final refresh");
    let zones = catalog.zones();
    assert_eq!(zones.len(), usize::try_from(TOTAL).unwrap());
    let mut seqs = std::collections::HashSet::new();
    for zone in 1..=TOTAL {
        assert!(catalog.zone_seq(&origin(zone)).is_some(), "зона {zone}");
        assert!(seqs.insert(catalog.zone_seq(&origin(zone)).unwrap()));
    }
    assert!(store.fsck_lite().expect("fsck").ok);
}

/// 4 процесса: update meta, delete/gc/recreate части зон. Каталог не теряет
/// обновления; slot'ы переиспользуются, записи консистентны.
#[test]
fn four_processes_update_delete_recreate_catalog_consistently() {
    const PER_PROCESS: u32 = 40;
    const TOTAL: u32 = PER_PROCESS * 4;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("catalog-churn.v2");
    let cfg = StoreConfig {
        multi_process: true,
        sync_mode: SyncModeV2::Sync,
        ..StoreConfig::small(TOTAL + 64, 1 << 18)
    };
    let store = setup(&path, TOTAL, cfg);
    drop(store);

    let children: Vec<Child> = (0..4_u32)
        .map(|process| {
            let start = process * PER_PROCESS + 1;
            let end = start + PER_PROCESS - 1;
            let zones: Vec<String> = (start..=end).map(|zone| zone.to_string()).collect();
            spawn_child("catalog_churn", &path, &[(ZONES, zones.join(","))])
        })
        .collect();
    for child in children {
        assert_success(child);
    }

    let store = open_multi(&path).expect("open multi");
    let catalog = ParallelZones::open(&store).expect("catalog");
    let zones = catalog.zones();
    assert_eq!(zones.len(), usize::try_from(TOTAL).unwrap());
    let mut seqs = std::collections::HashSet::new();
    for zone in 1..=TOTAL {
        let origin = origin(zone);
        let seq = catalog.zone_seq(&origin).expect("zone missing");
        assert!(seqs.insert(seq), "zone_seq {seq} дублируется");
        let meta = catalog.zone_meta(&origin).expect("meta missing");
        let expected = if zone % 2 == 0 {
            2000 + zone
        } else {
            1000 + zone
        };
        assert_eq!(meta.default_ttl, expected, "zone {zone}: meta потеряна");
    }
    assert!(store.fsck_lite().expect("fsck").ok);
    assert!(store.fsck_graph().expect("graph").fatal.is_none());
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
