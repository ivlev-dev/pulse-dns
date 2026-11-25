//! M3: межпроцессная рекламация durable-пулов.
//!
//! Проверяет, что 4 процесса переиспользуют страницы только при
//! `drop_txn < min(D_z, MP всех процессов, freeze)`, `high_water`
//! стабилизируется на insert/delete-нагрузке, `kill -9` писателя не ломает
//! пулы, а читатель другого процесса не видит переиспользованную страницу.
//!
//! Дочерний режим — `PULSE_MPR_CHILD`; без него `child_entry` — no-op.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    CrashHook, CrashPoint, OpenConfigV2, ParallelError, ParallelStore, ParallelZone, ParallelZones,
    RrsetData, StoreConfig, SyncModeV2, ZoneCreateMeta,
};

const CHILD: &str = "PULSE_MPR_CHILD";
const PATH: &str = "PULSE_MPR_PATH";
const ZONE: &str = "PULSE_MPR_ZONE";
const KEYS: &str = "PULSE_MPR_KEYS";
const RESULT: &str = "PULSE_MPR_RESULT";
const READY: &str = "PULSE_MPR_READY";
const VALUE: &str = "PULSE_MPR_VALUE";
const POINT: &str = "PULSE_MPR_POINT";

fn config(zones: u32, pages: u32) -> StoreConfig {
    StoreConfig {
        multi_process: true,
        sync_mode: SyncModeV2::Sync,
        ..StoreConfig::small(zones, pages)
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
    NameRle::from_ascii(&format!("z{zone}.mpr.example")).expect("origin")
}

fn key(zone: u32, index: u32) -> NameRle {
    NameRle::from_ascii(&format!("k{index}.z{zone}.mpr.example")).expect("name")
}

fn rr(value: u8) -> RrsetData {
    RrsetData::from_slices(60, 0, &[&[192, 0, 2, value]]).expect("rrset")
}

fn setup(path: &Path, zones: u32) {
    let store = ParallelStore::create(path, config(zones + 8, 1 << 18)).expect("create");
    let mut catalog = ParallelZones::open(&store).expect("catalog");
    for zone in 1..=zones {
        catalog
            .create_zone(&origin(zone), ZoneCreateMeta { soa_serial: zone })
            .expect("create zone");
    }
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
        .args(["--exact", "child_entry", "--nocapture"])
        .env(CHILD, mode)
        .env(PATH, path)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    for (name, value) in extra {
        command.env(name, value);
    }
    command.spawn().expect("spawn child")
}

fn wait_ready(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !path.exists() {
        assert!(Instant::now() < deadline, "child did not become ready");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn assert_success(mut child: Child) {
    let status = child.wait().expect("wait child");
    assert!(status.success(), "child failed: {status:?}");
}

fn open_writer(store: &ParallelStore, zone: u32) -> Result<ParallelZone<'_>, ParallelError> {
    let catalog = ParallelZones::open(store)?;
    let origin = catalog
        .origin(zone)
        .ok_or(ParallelError::NoZoneVersion { zone })?;
    let deadline = Instant::now() + Duration::from_secs(20);
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
    let deadline = Instant::now() + Duration::from_secs(20);
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

/// Вставляет и удаляет `keys` ключей чанками; пишет `mid,after_insert,after_delete`
/// в файл результата.
fn child_churn(path: &Path, zone: u32, keys: u32) -> Result<(), String> {
    let store = open_multi(path).map_err(|error| error.to_string())?;
    let mut writer = open_writer(&store, zone).map_err(|error| error.to_string())?;
    let chunk = 100_u32;
    let mut mid = 0_u64;
    let mut start = 0_u32;
    while start < keys {
        let end = (start + chunk).min(keys);
        for index in start..end {
            writer
                .upsert_rrset(
                    &key(zone, index),
                    1,
                    0,
                    &rr(u8::try_from(index % 250).unwrap_or(0)),
                )
                .map_err(|error| error.to_string())?;
        }
        commit_retry(&mut writer).map_err(|error| error.to_string())?;
        if mid == 0 && start >= keys / 2 {
            mid = store.high_water();
        }
        start = end;
    }
    if mid == 0 {
        mid = store.high_water();
    }
    let after_insert = store.high_water();
    let mut start = 0_u32;
    while start < keys {
        let end = (start + chunk).min(keys);
        for index in start..end {
            let _ = writer
                .delete_rrset(&key(zone, index), 1, 0)
                .map_err(|error| error.to_string())?;
        }
        commit_retry(&mut writer).map_err(|error| error.to_string())?;
        start = end;
    }
    let after_delete = store.high_water();
    eprintln!(
        "zone {zone}: mid={mid} after_insert={after_insert} after_delete={after_delete} \
         dp={} free_pool={} stats={:?}",
        store.durable_page_limit(),
        store.free_pool_pages(),
        store.stats()
    );
    if let Ok(path) = std::env::var(RESULT) {
        std::fs::write(path, format!("{mid},{after_insert},{after_delete}"))
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

/// Держит снапшот версии `V` и проверяет, что пин не даёт переиспользовать
/// страницы этой версии.
fn child_reader(path: &Path, zone: u32) -> Result<(), String> {
    let store = open_multi_read(path).map_err(|error| error.to_string())?;
    let reader = store.reader().map_err(|error| error.to_string())?;
    let catalog = ParallelZones::open(&store).map_err(|error| error.to_string())?;
    let origin = catalog
        .origin(zone)
        .ok_or_else(|| format!("no zone {zone}"))?;
    let snapshot = catalog
        .read(&reader, &origin)
        .map_err(|error| error.to_string())?;
    let expected: u8 = std::env::var(VALUE)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1);
    let first = key(zone, 0);
    if let Some(record) = snapshot
        .lookup(&first, 1, 0)
        .map_err(|error| error.to_string())?
    {
        assert_eq!(
            record.rdata,
            vec![vec![192, 0, 2, expected]],
            "reader snapshot changed before churn"
        );
    }
    let ready = PathBuf::from(std::env::var(READY).map_err(|_| "no ready".to_string())?);
    std::fs::write(&ready, b"ready").map_err(|error| error.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        match snapshot.lookup(&first, 1, 0) {
            Ok(Some(record)) => assert_eq!(
                record.rdata,
                vec![vec![192, 0, 2, expected]],
                "читатель увидел переиспользованную/новую страницу"
            ),
            Ok(None) => {}
            Err(error) => return Err(format!("lookup во время churn: {error}")),
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    Ok(())
}

/// Бесконечный churn (для `kill -9`): upsert/delete одного ключа.
fn child_churn_forever(path: &Path, zone: u32) -> Result<(), String> {
    let store = open_multi(path).map_err(|error| error.to_string())?;
    let mut writer = open_writer(&store, zone).map_err(|error| error.to_string())?;
    let name = key(zone, 0);
    let ready = PathBuf::from(std::env::var(READY).map_err(|_| "no ready".to_string())?);
    std::fs::write(&ready, b"ready").map_err(|error| error.to_string())?;
    let start = Instant::now();
    let mut value = 1_u8;
    while start.elapsed() < Duration::from_secs(30) {
        writer
            .upsert_rrset(&name, 1, 0, &rr(value))
            .map_err(|error| error.to_string())?;
        commit_retry(&mut writer).map_err(|error| error.to_string())?;
        let _ = writer
            .delete_rrset(&name, 1, 0)
            .map_err(|error| error.to_string())?;
        commit_retry(&mut writer).map_err(|error| error.to_string())?;
        value = value.wrapping_add(1).max(1);
    }
    Ok(())
}

/// Проверяет инвариант durable-барьера: `DP >= high_water` и
/// `DP >= page_limit_at_commit` каждой опубликованной головы (включая
/// tombstone). Вызывается сразу после `sync()`.
fn assert_watermarks(store: &ParallelStore) {
    let dp = store.durable_page_limit();
    let cursor = store.high_water();
    assert!(
        dp >= cursor,
        "DP {dp} ниже курсора {cursor}: страницы [DP, cursor) могут быть выданы повторно"
    );
    for zone in 0..store.geometry().max_zones() {
        let Some(head) = store.zone_head(zone) else {
            continue;
        };
        assert!(
            dp >= u64::from(head.page_limit_at_commit),
            "зона {zone}: DP {dp} ниже page_limit_at_commit {} головы v{}",
            head.page_limit_at_commit,
            head.version
        );
    }
}

fn churn_zone(
    store: &ParallelStore,
    zone: u32,
    keys: u32,
    rounds: u32,
) -> Result<(), ParallelError> {
    let mut writer = open_writer(store, zone)?;
    for _ in 0..rounds {
        for index in 0..keys {
            writer.upsert_rrset(&key(zone, index), 1, 0, &rr(1))?;
        }
        commit_retry(&mut writer)?;
        store.sync()?;
        for index in 0..keys {
            let _ = writer.delete_rrset(&key(zone, index), 1, 0)?;
        }
        commit_retry(&mut writer)?;
        store.sync()?;
    }
    Ok(())
}

/// Создание, удаление (tombstone + `gc_catalog`) и повторное создание зоны в
/// multi-режиме не смешивают порядок bucket-цепочек и не понижают `DP`.
///
/// Регрессия: COW-пересборка multi-пула писала группы по возрастанию
/// `drop_txn`, а следующий append — новую группу в голову (по убыванию).
/// Загрузка такой смешанной цепочки отвергалась `WatermarkRegression`.
#[test]
fn create_delete_recreate_keeps_chain_and_watermarks_valid() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("mpr-recreate.v2");
    setup(&path, 1);
    {
        let store = open_multi(&path).expect("open");
        churn_zone(&store, 1, 24, 4).expect("churn");
        let reclaimed = store.stats().reclaimed_pages;
        assert!(
            reclaimed > 0,
            "reclaim не сработал, тест не воспроизводит баг"
        );

        let mut catalog = ParallelZones::open(&store).expect("catalog");
        catalog.delete_zone(&origin(1)).expect("delete zone");
        store.sync().expect("sync tombstone");
        let removed = catalog.gc_catalog().expect("gc catalog");
        assert_eq!(removed, vec![origin(1)]);
        assert_watermarks(&store);
        assert!(store.fsck_graph().expect("graph").fatal.is_none());
    }

    // Повторное открытие читает цепочку с диска (append + COW образы).
    let store = open_multi(&path).expect("reopen");
    assert_watermarks(&store);
    let mut catalog = ParallelZones::open(&store).expect("catalog");
    let zone_seq = catalog
        .create_zone(&origin(1), ZoneCreateMeta { soa_serial: 100 })
        .expect("recreate zone");
    assert_eq!(zone_seq, 1, "tombstone-слот должен переиспользоваться");
    drop(catalog);

    churn_zone(&store, 1, 16, 2).expect("churn after recreate");
    assert_watermarks(&store);
    let graph = store.fsck_graph().expect("graph");
    assert!(graph.fatal.is_none(), "{graph:?}");
    assert!(graph.ok, "{graph:?}");
    let report = store.fsck_lite().expect("fsck");
    assert!(report.fatal.is_none(), "{report:?}");

    // Удаление пересозданной зоны: снова tombstone, пул и каталог согласованы.
    let mut catalog = ParallelZones::open(&store).expect("catalog");
    catalog.delete_zone(&origin(1)).expect("delete recreated");
    store.sync().expect("sync");
    let _ = catalog.gc_catalog().expect("gc catalog");
    assert_watermarks(&store);
    assert!(store.fsck_graph().expect("graph").fatal.is_none());
}

/// `kill -9` в каждой точке коммита tombstone: после reopen файл либо с живой
/// зоной, либо с durable tombstone; удаление доводится до `gc_catalog`, слот
/// переиспользуется повторным созданием, fsck чист.
#[test]
fn crash_during_delete_then_recreate_is_safe() {
    let points = [
        ("before_alloc_record", CrashPoint::BeforeAllocRecord),
        ("after_phase1_fsync", CrashPoint::AfterPhase1Fsync),
        ("before_root_write", CrashPoint::BeforeRootWrite),
        ("after_root_copy_a", CrashPoint::AfterRootCopyA),
        ("after_root_copy_b", CrashPoint::AfterRootCopyB),
        ("before_head_publish", CrashPoint::BeforeHeadPublish),
        ("after_head_publish", CrashPoint::AfterHeadPublish),
    ];
    for (name, _) in points {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("mpr-delete-crash.v2");
        setup(&path, 1);
        {
            let store = open_multi(&path).expect("open");
            churn_zone(&store, 1, 16, 2).expect("seed");
            assert_watermarks(&store);
        }
        let mut child = spawn_child(
            "delete_crash",
            &path,
            &[(ZONE, "1".to_string()), (POINT, name.to_string())],
        );
        let status = child.wait().expect("wait crash child");
        assert!(!status.success(), "{name}: ребёнок должен был умереть");

        let store = open_multi(&path).expect("open after crash");
        let report = store.fsck_lite().expect("fsck lite");
        assert!(report.fatal.is_none(), "{name}: {report:?}");
        let mut catalog = ParallelZones::open(&store).expect("catalog");
        if let Some(head) = store.zone_head(1)
            && !head.is_tombstone()
        {
            catalog.delete_zone(&origin(1)).expect("finish delete");
            store.sync().expect("sync tombstone");
        } else {
            store.sync().expect("sync recovered tombstone");
        }
        let _ = catalog.gc_catalog().expect("gc catalog");
        assert_watermarks(&store);
        drop(catalog);

        let mut catalog = ParallelZones::open(&store).expect("catalog");
        let seq = catalog
            .create_zone(&origin(1), ZoneCreateMeta { soa_serial: 7 })
            .expect("recreate after crash");
        assert_eq!(seq, 1, "{name}: слот tombstone должен переиспользоваться");
        drop(catalog);
        churn_zone(&store, 1, 8, 1).expect("write after recreate");
        assert_watermarks(&store);
        let graph = store.fsck_graph().expect("graph");
        assert!(graph.fatal.is_none(), "{name}: {graph:?}");
        assert!(graph.ok, "{name}: {graph:?}");
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

/// Умирает после durable-фазы 1 (данные/bucket durable, корень — нет).
fn child_crash_phase1(path: &Path, zone: u32) -> Result<(), String> {
    let mut store = open_multi(path).map_err(|error| error.to_string())?;
    store.set_crash_hook(Box::new(KillAt(CrashPoint::AfterPhase1Fsync)));
    let mut writer = open_writer(&store, zone).map_err(|error| error.to_string())?;
    writer
        .upsert_rrset(&key(zone, 0), 1, 0, &rr(9))
        .map_err(|error| error.to_string())?;
    writer.commit().map_err(|error| error.to_string())?;
    Ok(())
}

fn parse_point(name: &str) -> Option<CrashPoint> {
    Some(match name {
        "before_alloc_record" => CrashPoint::BeforeAllocRecord,
        "after_phase1_writes" => CrashPoint::AfterPhase1Writes,
        "after_phase1_fsync" => CrashPoint::AfterPhase1Fsync,
        "before_root_write" => CrashPoint::BeforeRootWrite,
        "after_root_copy_a" => CrashPoint::AfterRootCopyA,
        "after_root_copy_b" => CrashPoint::AfterRootCopyB,
        "after_phase2_fsync" => CrashPoint::AfterPhase2Fsync,
        "before_head_publish" => CrashPoint::BeforeHeadPublish,
        "after_head_publish" => CrashPoint::AfterHeadPublish,
        _ => return None,
    })
}

/// Умирает в заданной точке коммита tombstone (`delete_zone`).
fn child_delete_crash(path: &Path, zone: u32) -> Result<(), String> {
    let point = std::env::var(POINT)
        .ok()
        .and_then(|name| parse_point(&name))
        .ok_or_else(|| "unknown crash point".to_string())?;
    let mut store = open_multi(path).map_err(|error| error.to_string())?;
    store.set_crash_hook(Box::new(KillAt(point)));
    let mut catalog = ParallelZones::open(&store).map_err(|error| error.to_string())?;
    catalog
        .delete_zone(&origin(zone))
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn child_body() -> Result<(), String> {
    let mode = std::env::var(CHILD).map_err(|_| "no child mode".to_string())?;
    let path = PathBuf::from(std::env::var(PATH).map_err(|_| "no path".to_string())?);
    let zone = parse_u32(ZONE, 1);
    match mode.as_str() {
        "churn" => child_churn(&path, zone, parse_u32(KEYS, 1000).max(1)),
        "reader" => child_reader(&path, zone),
        "churn_forever" => child_churn_forever(&path, zone),
        "crash_phase1" => child_crash_phase1(&path, zone),
        "delete_crash" => child_delete_crash(&path, zone),
        other => Err(format!("unknown child mode {other}")),
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

fn read_result(path: &Path) -> (u64, u64, u64) {
    let raw = std::fs::read_to_string(path).expect("result file");
    let fields: Vec<u64> = raw
        .split(',')
        .filter_map(|value| value.trim().parse().ok())
        .collect();
    assert_eq!(fields.len(), 3, "bad result: {raw}");
    (fields[0], fields[1], fields[2])
}

/// 4 процесса вставляют/удаляют `keys` ключей каждый. `high_water` после
/// удаления ограничен размером набора, а не числом коммитов.
fn run_churn(keys: u32, label: &str) {
    const PROCESSES: u32 = 4;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("mpr-churn.v2");
    setup(&path, PROCESSES);

    let children: Vec<Child> = (0..PROCESSES)
        .map(|process| {
            let result = dir.path().join(format!("result-{process}"));
            spawn_child(
                "churn",
                &path,
                &[
                    (ZONE, (process + 1).to_string()),
                    (KEYS, keys.to_string()),
                    (RESULT, result.display().to_string()),
                ],
            )
        })
        .collect();
    for child in children {
        assert_success(child);
    }

    let mut worst = 0_u64;
    for process in 0..PROCESSES {
        let (mid, after_insert, after_delete) =
            read_result(&dir.path().join(format!("result-{process}")));
        assert!(
            after_insert <= mid + 4 * 1024,
            "process {process}: вставка растит high_water: {mid} → {after_insert}"
        );
        assert!(
            after_delete <= after_insert + u64::from(keys) + 2048,
            "process {process}: удаление растит high_water: {after_insert} → {after_delete}"
        );
        worst = worst.max(after_delete);
    }

    let store = open_multi(&path).expect("open multi");
    let graph = store.fsck_graph().expect("graph");
    assert!(graph.fatal.is_none(), "{graph:?}");
    assert!(
        graph.leaked_pages < graph.durable_pages / 2,
        "слишком много утечек: {graph:?}"
    );
    assert!(store.fsck_lite().expect("fsck").fatal.is_none());
    eprintln!("{label}: 4-process high_water after delete = {worst}");
}

/// 4 × 1000 ключей (4k insert + 4k delete) — обычный прогон.
#[test]
fn four_processes_insert_delete_keep_high_water_bounded() {
    run_churn(1000, "8k ops");
}

/// Полный приёмочный прогон 4 × 2500 (10k insert + 10k delete). Тяжёлый в
/// debug-профиле: `cargo test -p pulse-zonefile --test v2_multiprocess_reclaim
/// -- --ignored --nocapture`.
#[test]
#[ignore = "heavy: 10k insert + 10k delete in 4 processes"]
fn four_processes_insert_delete_10k_keep_high_water_bounded() {
    run_churn(2500, "20k ops");
}

/// Читатель другого процесса держит пин; writer переписывает ту же зону.
/// Старый снапшот обязан оставаться валидным.
#[test]
fn reader_in_other_process_does_not_see_reused_pages() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("mpr-reader.v2");
    setup(&path, 1);
    {
        let store = open_multi(&path).expect("open");
        let mut writer = open_writer(&store, 1).expect("writer");
        writer
            .upsert_rrset(&key(1, 0), 1, 0, &rr(1))
            .expect("insert");
        writer.commit().expect("commit");
    }
    let ready = dir.path().join("reader-ready");
    let reader = spawn_child(
        "reader",
        &path,
        &[
            (ZONE, "1".to_string()),
            (VALUE, "1".to_string()),
            (READY, ready.display().to_string()),
        ],
    );
    wait_ready(&ready);
    let writer = spawn_child(
        "churn",
        &path,
        &[(ZONE, "1".to_string()), (KEYS, "300".to_string())],
    );
    assert_success(writer);
    assert_success(reader);
    let store = open_multi(&path).expect("open");
    assert!(store.fsck_graph().expect("graph").ok);
}

/// `kill -9` писателя посреди churn: пулы открываются, рекламация продолжается.
#[test]
fn kill9_writer_then_reclaim_is_consistent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("mpr-kill9.v2");
    setup(&path, 2);
    let ready = dir.path().join("writer-ready");
    let mut victim = spawn_child(
        "churn_forever",
        &path,
        &[
            (ZONE, "1".to_string()),
            (READY, ready.display().to_string()),
        ],
    );
    wait_ready(&ready);
    std::thread::sleep(Duration::from_millis(400));
    victim.kill().expect("kill writer");
    let _ = victim.wait();

    let store = open_multi(&path).expect("open after kill");
    let _ = store.gc_pass().expect("gc");
    assert_eq!(store.active_pins(), 0);
    let graph = store.fsck_graph().expect("graph");
    assert!(graph.fatal.is_none(), "{graph:?}");
    drop(store);

    let result = dir.path().join("after-kill");
    assert_success(spawn_child(
        "churn",
        &path,
        &[
            (ZONE, "1".to_string()),
            (KEYS, "400".to_string()),
            (RESULT, result.display().to_string()),
        ],
    ));
    let store = open_multi(&path).expect("reopen");
    assert!(store.fsck_graph().expect("graph").fatal.is_none());
}

/// `kill -9` после durable-фазы 1: корень старой версии, bucket/страницы
/// durable; после reopen рекламация не отдаёт занятую страницу.
#[test]
fn crash_after_phase1_then_reclaim_is_safe() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("mpr-crash.v2");
    setup(&path, 1);
    {
        let store = open_multi(&path).expect("open");
        let mut writer = open_writer(&store, 1).expect("writer");
        for index in 0..50 {
            writer
                .upsert_rrset(&key(1, index), 1, 0, &rr(1))
                .expect("insert");
        }
        writer.commit().expect("commit");
    }
    let mut child = spawn_child("crash_phase1", &path, &[(ZONE, "1".to_string())]);
    let status = child.wait().expect("wait crash");
    assert!(!status.success(), "child должен был умереть");

    let store = open_multi(&path).expect("open after crash");
    let report = store.fsck_lite().expect("fsck");
    assert!(report.fatal.is_none(), "{report:?}");
    let graph = store.fsck_graph().expect("graph");
    assert!(graph.fatal.is_none(), "{graph:?}");
    drop(store);

    let result = dir.path().join("after-crash");
    assert_success(spawn_child(
        "churn",
        &path,
        &[
            (ZONE, "1".to_string()),
            (KEYS, "300".to_string()),
            (RESULT, result.display().to_string()),
        ],
    ));
    let store = open_multi(&path).expect("reopen");
    assert!(store.fsck_graph().expect("graph").fatal.is_none());
}
