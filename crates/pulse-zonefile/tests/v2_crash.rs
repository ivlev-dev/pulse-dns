//! Crash-harness фазы A: `fork`-через-`Command` + `SIGKILL` во всех фазах
//! публикации, 100+ случайных итераций и детерминированные точки.
//!
//! Ребёнок — этот же test-binary (`--exact v2_crash_child`): он создаёт стор,
//! публикует корни и после каждой durable-публикации пишет ack-лог с
//! `sync_data`. Родитель убивает процесс `SIGKILL`, затем проверяет recovery:
//! `DP ≥ max acked page_limit`, `head.version ≥ max acked version`, отсутствие
//! `Corrupt`/file-fatal и монотонность `DP` после повторного открытия.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use pulse_zonefile::parallel::{
    CrashHook, CrashPoint, OpenConfigV2, ParallelError, ParallelStore, RootEntry, RootState,
    StoreConfig,
};

const READY_FILE: &str = "ready";
const ACK_FILE: &str = "acks.log";
const CHILD_TEST: &str = "v2_crash_child";

struct Ack {
    zone: u32,
    version: u64,
    page_limit: u32,
}

/// Хук, убивающий процесс в заданной точке (детерминированный крах).
struct KillAt {
    point: CrashPoint,
    armed: Arc<AtomicBool>,
}

impl CrashHook for KillAt {
    fn at(&self, point: CrashPoint) {
        if point == self.point && self.armed.load(Ordering::Acquire) {
            let _ = rustix::process::kill_process(
                rustix::process::getpid(),
                rustix::process::Signal::KILL,
            );
        }
    }
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

fn publish(store: &ParallelStore, zone: u32, version: u64) -> Result<(), String> {
    let ticket = store
        .reserve_pages(1)
        .map_err(|error| format!("{error:?}"))?;
    store
        .write_raw_page(ticket.first_page, b"crash payload")
        .map_err(|error| format!("{error:?}"))?;
    let entry = RootEntry {
        owner_zone: zone,
        version,
        root_page: ticket.first_page,
        state: RootState::Serving,
        soa_serial: u32::try_from(version).unwrap_or(u32::MAX),
        rrset_count: 1,
        ..RootEntry::default()
    };
    for _ in 0..64 {
        match store.publish_root(entry) {
            Ok(_) => return Ok(()),
            Err(ParallelError::ReaderContended) => {}
            Err(error) => return Err(format!("{error:?}")),
        }
    }
    Err("publish retry limit".into())
}

/// Дочерний процесс: публикует корни до `SIGKILL`.
#[test]
fn v2_crash_child() {
    let Some(dir) = std::env::var_os("PULSE_V2_CRASH_DIR") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let path = dir.join("crash.v2");
    let after: u64 = std::env::var("PULSE_V2_CRASH_AFTER")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(4);
    let point = std::env::var("PULSE_V2_CRASH_POINT")
        .ok()
        .and_then(|name| parse_point(&name));

    let mut config = StoreConfig::small(8, 8192);
    config.max_root_chain_pages = 32;
    let mut store = ParallelStore::create(&path, config).expect("create child store");
    let armed = Arc::new(AtomicBool::new(false));
    if let Some(point) = point {
        store.set_crash_hook(Box::new(KillAt {
            point,
            armed: Arc::clone(&armed),
        }));
    }
    File::create(dir.join(READY_FILE))
        .and_then(|mut file| file.write_all(b"1"))
        .expect("ready marker");

    let mut log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(ACK_FILE))
        .expect("ack log");
    let mut versions = [2_u64; 9];
    let mut published = 0_u64;
    loop {
        for zone in 1..=4_u32 {
            let index = zone as usize;
            let version = versions[index];
            publish(&store, zone, version).expect("child publish");
            versions[index] = version + 1;
            let head = store.select_root(zone, u64::MAX).expect("child head");
            let line = format!("{zone} {} {}\n", head.version, head.page_limit_at_commit);
            log.write_all(line.as_bytes()).expect("ack write");
            log.sync_data().expect("ack sync");
            published += 1;
            if published >= after {
                armed.store(true, Ordering::Release);
            }
        }
    }
}

fn spawn_child(dir: &std::path::Path, point: Option<CrashPoint>, after: u64) -> Child {
    let exe = std::env::current_exe().expect("current exe");
    let stderr = File::create(dir.join("child.stderr")).expect("child stderr file");
    let mut command = Command::new(exe);
    command
        .args(["--exact", CHILD_TEST, "--nocapture"])
        .env("PULSE_V2_CRASH_DIR", dir)
        .env("PULSE_V2_CRASH_AFTER", after.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr));
    if let Some(point) = point {
        let name = match point {
            CrashPoint::BeforeAllocRecord => "before_alloc_record",
            CrashPoint::AfterPhase1Writes => "after_phase1_writes",
            CrashPoint::AfterPhase1Fsync => "after_phase1_fsync",
            CrashPoint::BeforeRootWrite => "before_root_write",
            CrashPoint::AfterRootCopyA => "after_root_copy_a",
            CrashPoint::AfterRootCopyB => "after_root_copy_b",
            CrashPoint::AfterPhase2Fsync => "after_phase2_fsync",
            CrashPoint::BeforeHeadPublish => "before_head_publish",
            CrashPoint::AfterHeadPublish => "after_head_publish",
        };
        command.env("PULSE_V2_CRASH_POINT", name);
    }
    command.spawn().expect("spawn child")
}

fn wait_ready(dir: &std::path::Path, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if dir.join(READY_FILE).exists() {
            return;
        }
        if let Ok(Some(status)) = child.try_wait() {
            let mut stderr = String::new();
            let _ = File::open(dir.join("child.stderr"))
                .and_then(|mut file| file.read_to_string(&mut stderr));
            panic!("child exited before ready: {status:?}\n{stderr}");
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("child did not become ready");
}

fn read_acks(dir: &std::path::Path) -> Vec<Ack> {
    let Ok(content) = std::fs::read_to_string(dir.join(ACK_FILE)) else {
        return Vec::new();
    };
    let mut acks = Vec::new();
    for line in content.lines() {
        let mut fields = line.split_whitespace();
        let (Some(zone), Some(version), Some(limit)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let (Ok(zone), Ok(version), Ok(page_limit)) =
            (zone.parse(), version.parse(), limit.parse())
        else {
            continue;
        };
        acks.push(Ack {
            zone,
            version,
            page_limit,
        });
    }
    acks
}

fn lcg(seed: &mut u64) -> u64 {
    *seed = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *seed
}

/// Одна итерация: запуск ребёнка, `SIGKILL`, recovery и проверки.
fn run_iteration(
    dir: &std::path::Path,
    point: Option<CrashPoint>,
    after: u64,
    seed: &mut u64,
) -> usize {
    let mut child = spawn_child(dir, point, after);
    wait_ready(dir, &mut child);
    if point.is_none() {
        let delay = 1 + lcg(seed) % 4_000;
        std::thread::sleep(Duration::from_micros(delay));
    }
    let _ = child.kill();
    let _ = child.wait();

    let acks = read_acks(dir);
    let store = match ParallelStore::open(&dir.join("crash.v2"), OpenConfigV2::default()) {
        Ok(store) => store,
        Err(error) => {
            let mut stderr = String::new();
            let _ = File::open(dir.join("child.stderr"))
                .and_then(|mut file| file.read_to_string(&mut stderr));
            panic!("recovery failed: {error:?}\n{stderr}");
        }
    };
    let dp = store.durable_page_limit();
    for ack in &acks {
        assert!(
            u64::from(ack.page_limit) <= dp,
            "DP {dp} ниже acked page_limit {} зоны {}",
            ack.page_limit,
            ack.zone
        );
        let head = store
            .select_root(ack.zone, u64::MAX)
            .unwrap_or_else(|error| panic!("zone {} select: {error:?}", ack.zone));
        assert!(
            head.version >= ack.version,
            "потеряна подтверждённая публикация: zone {} version {} (head {})",
            ack.zone,
            ack.version,
            head.version
        );
    }
    let report = store
        .fsck_lite()
        .unwrap_or_else(|error| panic!("fsck failed: {error:?}"));
    assert!(
        report.ok,
        "fsck не зелёный: fatal={:?} issues={:?}",
        report.fatal, report.issues
    );
    assert!(report.fatal.is_none());

    // После recovery стор обязан остаться записываемым, а DP — не убывать.
    let max_acked = acks.iter().map(|ack| ack.version).max().unwrap_or(2);
    publish(
        &store,
        1,
        max_acked.max(store.select_root(1, u64::MAX).map_or(2, |e| e.version + 1)),
    )
    .expect("publish after recovery");
    let (dp_after, _) = store.sync().expect("sync after recovery");
    assert!(dp_after >= dp);
    drop(store);

    let reopened = ParallelStore::open(&dir.join("crash.v2"), OpenConfigV2::default())
        .expect("reopen after recovery");
    assert!(reopened.durable_page_limit() >= dp_after);
    assert!(reopened.fsck_lite().unwrap().ok);
    acks.len()
}

#[test]
fn crash_kill9_random_and_deterministic_points() {
    // Детерминированные точки: по 2 итерации на каждую фазу.
    let points = [
        CrashPoint::BeforeAllocRecord,
        CrashPoint::AfterPhase1Writes,
        CrashPoint::AfterPhase1Fsync,
        CrashPoint::BeforeRootWrite,
        CrashPoint::AfterRootCopyA,
        CrashPoint::AfterRootCopyB,
        CrashPoint::AfterPhase2Fsync,
        CrashPoint::BeforeHeadPublish,
        CrashPoint::AfterHeadPublish,
    ];
    let mut seed = 0xC0FF_EE12_3456_789A_u64;
    let mut acked = 0;
    for point in points {
        for _ in 0..2 {
            let dir = tempfile::tempdir().unwrap();
            acked += run_iteration(dir.path(), Some(point), 6, &mut seed);
        }
    }

    // 100 случайных kill -9 после разной задержки.
    for _ in 0..100 {
        let dir = tempfile::tempdir().unwrap();
        acked += run_iteration(dir.path(), None, 2, &mut seed);
    }
    assert!(
        acked >= 100,
        "слишком мало подтверждённых публикаций: {acked}"
    );
}
