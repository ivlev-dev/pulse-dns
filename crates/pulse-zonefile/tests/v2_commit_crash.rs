//! Crash-harness B1: `kill -9` на фазах коммита зоны (данные/`ALLOC_RECORD`/
//! корень/голова), затем recovery, каталог и B+tree читаются, подтверждённые
//! коммиты не потеряны.
//!
//! Ребёнок — этот же test-binary (`--exact v2_commit_crash_child`): создаёт
//! 2 зоны, затем в цикле делает upsert+commit и пишет ack-лог с `sync_data`.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    CrashHook, CrashPoint, OpenConfigV2, ParallelStore, ParallelZones, RrsetData, StoreConfig,
    ZoneCreateMeta,
};

const READY_FILE: &str = "ready";
const ACK_FILE: &str = "acks.log";
const CHILD_TEST: &str = "v2_commit_crash_child";

fn origin(index: u32) -> NameRle {
    NameRle::from_ascii(&format!("crash{index}.example")).unwrap()
}

fn rr(value: u8) -> RrsetData {
    RrsetData::from_slices(60, 0, &[&[10, 0, 0, value]]).unwrap()
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

fn point_name(point: CrashPoint) -> &'static str {
    match point {
        CrashPoint::BeforeAllocRecord => "before_alloc_record",
        CrashPoint::AfterPhase1Writes => "after_phase1_writes",
        CrashPoint::AfterPhase1Fsync => "after_phase1_fsync",
        CrashPoint::BeforeRootWrite => "before_root_write",
        CrashPoint::AfterRootCopyA => "after_root_copy_a",
        CrashPoint::AfterRootCopyB => "after_root_copy_b",
        CrashPoint::AfterPhase2Fsync => "after_phase2_fsync",
        CrashPoint::BeforeHeadPublish => "before_head_publish",
        CrashPoint::AfterHeadPublish => "after_head_publish",
    }
}

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

/// Дочерний процесс: коммитит зоны до `SIGKILL`.
#[test]
fn v2_commit_crash_child() {
    let Some(dir) = std::env::var_os("PULSE_V2_COMMIT_CRASH_DIR") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let path = dir.join("crash.v2");
    let after: u64 = std::env::var("PULSE_V2_COMMIT_CRASH_AFTER")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(6);
    let point = std::env::var("PULSE_V2_COMMIT_CRASH_POINT")
        .ok()
        .and_then(|name| parse_point(&name));

    let mut config = StoreConfig::small(8, 32_768);
    config.max_root_chain_pages = 32;
    let mut store = ParallelStore::create(&path, config).expect("create child store");
    let armed = Arc::new(AtomicBool::new(false));
    if let Some(point) = point {
        store.set_crash_hook(Box::new(KillAt {
            point,
            armed: Arc::clone(&armed),
        }));
    }
    let mut zones = ParallelZones::open(&store).expect("catalog");
    let mut log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(ACK_FILE))
        .expect("ack log");
    let mut seqs = HashMap::new();
    for index in 1..=2_u32 {
        let seq = zones
            .create_zone(&origin(index), ZoneCreateMeta { soa_serial: index })
            .expect("create zone");
        seqs.insert(index, seq);
        let version = store.select_root(seq, u64::MAX).expect("head").version;
        writeln!(log, "C {index} {seq} {version}").expect("ack create");
        log.sync_data().expect("ack sync");
    }
    File::create(dir.join(READY_FILE))
        .and_then(|mut file| file.write_all(b"1"))
        .expect("ready marker");

    let mut writer_a = zones.writer(&origin(1)).expect("writer 1");
    let mut writer_b = zones.writer(&origin(2)).expect("writer 2");
    let mut iterations = [0_u64; 3];
    let mut published = 0_u64;
    loop {
        for (index, writer) in [(1_u32, &mut writer_a), (2, &mut writer_b)] {
            let iteration = iterations[index as usize];
            let name =
                NameRle::from_ascii(&format!("r{iteration}.crash{index}.example")).expect("name");
            writer
                .upsert_rrset(&name, 1, 0, &rr(u8::try_from(iteration % 250).unwrap_or(0)))
                .expect("upsert");
            let outcome = writer.commit().expect("commit");
            writeln!(log, "Z {index} {} {iteration}", outcome.version).expect("ack commit");
            log.sync_data().expect("ack sync");
            iterations[index as usize] = iteration.saturating_add(1);
            published = published.saturating_add(1);
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
        .env("PULSE_V2_COMMIT_CRASH_DIR", dir)
        .env("PULSE_V2_COMMIT_CRASH_AFTER", after.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr));
    if let Some(point) = point {
        command.env("PULSE_V2_COMMIT_CRASH_POINT", point_name(point));
    }
    command.spawn().expect("spawn child")
}

fn wait_ready(dir: &std::path::Path, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(15);
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

struct Acks {
    created: HashMap<u32, u32>,
    /// zone index → максимальная подтверждённая итерация.
    last_iteration: HashMap<u32, u64>,
    /// zone index → максимальная подтверждённая версия.
    last_version: HashMap<u32, u64>,
}

fn read_acks(dir: &std::path::Path) -> Acks {
    let content = std::fs::read_to_string(dir.join(ACK_FILE)).unwrap_or_default();
    let mut acks = Acks {
        created: HashMap::new(),
        last_iteration: HashMap::new(),
        last_version: HashMap::new(),
    };
    for line in content.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        match fields.as_slice() {
            ["C", index, seq, _version] => {
                if let (Ok(index), Ok(seq)) = (index.parse(), seq.parse()) {
                    acks.created.insert(index, seq);
                }
            }
            ["Z", index, version, iteration] => {
                if let (Ok(index), Ok(version), Ok(iteration)) =
                    (index.parse(), version.parse(), iteration.parse())
                {
                    acks.last_version
                        .entry(index)
                        .and_modify(|current: &mut u64| *current = (*current).max(version))
                        .or_insert(version);
                    acks.last_iteration
                        .entry(index)
                        .and_modify(|current: &mut u64| *current = (*current).max(iteration))
                        .or_insert(iteration);
                }
            }
            _ => {}
        }
    }
    acks
}

fn lcg(seed: &mut u64) -> u64 {
    *seed = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *seed
}

fn run_iteration(
    dir: &std::path::Path,
    point: Option<CrashPoint>,
    after: u64,
    seed: &mut u64,
) -> usize {
    let mut child = spawn_child(dir, point, after);
    wait_ready(dir, &mut child);
    if point.is_none() {
        let delay = 1 + lcg(seed) % 8_000;
        std::thread::sleep(Duration::from_micros(delay));
        let _ = child.kill();
    } else {
        // Детерминированная точка: ждём, пока хук сам убьёт ребёнка.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                _ => {
                    let _ = child.kill();
                    break;
                }
            }
        }
    }
    let _ = child.wait();

    let acks = read_acks(dir);
    let path = dir.join("crash.v2");
    let store = ParallelStore::open(&path, OpenConfigV2::default()).unwrap_or_else(|error| {
        let mut stderr = String::new();
        let _ = File::open(dir.join("child.stderr"))
            .and_then(|mut file| file.read_to_string(&mut stderr));
        panic!("recovery failed: {error:?}\n{stderr}");
    });
    assert!(store.fatal().is_none(), "file-fatal после recovery");
    let zones = ParallelZones::open(&store).expect("catalog recovery");
    let reader = store.reader().expect("reader");
    let mut verified = 0_usize;
    for (index, seq) in &acks.created {
        let origin = origin(*index);
        assert_eq!(
            zones.zone_seq(&origin),
            Some(*seq),
            "каталог потерял зону {index}"
        );
        let head = store.select_root(*seq, u64::MAX).expect("head");
        if let Some(acked_version) = acks.last_version.get(index) {
            assert!(
                head.version >= *acked_version,
                "зона {index}: head {} < acked {}",
                head.version,
                acked_version
            );
        }
        let view = zones.read(&reader, &origin).expect("snapshot");
        if let Some(last) = acks.last_iteration.get(index) {
            for iteration in 0..=*last {
                let name = NameRle::from_ascii(&format!("r{iteration}.crash{index}.example"))
                    .expect("name");
                assert!(
                    view.lookup(&name, 1, 0).expect("lookup").is_some(),
                    "зона {index}: потерян подтверждённый r{iteration}"
                );
                verified += 1;
            }
        }
    }
    drop(reader);
    drop(zones);

    let report = store.fsck_lite().expect("fsck");
    assert!(
        report.ok,
        "fsck не зелёный: fatal={:?} issues={:?}",
        report.fatal, report.issues
    );
    let graph = store.fsck_graph().expect("graph fsck");
    assert!(
        graph.ok,
        "graph fsck не зелёный: fatal={:?} issues={:?} (leaked {})",
        graph.fatal, graph.issues, graph.leaked_pages
    );

    // После recovery стор остаётся записываемым: следующий коммит проходит.
    let zones = ParallelZones::open(&store).expect("catalog rewrite");
    for index in acks.created.keys() {
        let origin = origin(*index);
        let mut writer = zones.writer(&origin).expect("writer after recovery");
        let name = NameRle::from_ascii(&format!("after.crash{index}.example")).expect("name");
        writer
            .upsert_rrset(&name, 1, 0, &rr(1))
            .expect("upsert after");
        writer.commit().expect("commit after recovery");
    }
    drop(zones);
    let dp = store.durable_page_limit();
    drop(store);
    let reopened = ParallelStore::open(&path, OpenConfigV2::default()).expect("reopen");
    assert!(reopened.durable_page_limit() >= dp);
    assert!(reopened.fsck_lite().unwrap().ok);
    verified
}

#[test]
fn crash_kill9_commit_phases_and_random() {
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
    let mut seed = 0x5EED_1234_ABCD_9876_u64;
    let mut verified = 0;
    for point in points {
        for _ in 0..2 {
            let dir = tempfile::tempdir().unwrap();
            verified += run_iteration(dir.path(), Some(point), 8, &mut seed);
        }
    }
    for _ in 0..24 {
        let dir = tempfile::tempdir().unwrap();
        verified += run_iteration(dir.path(), None, 2, &mut seed);
    }
    assert!(verified > 0, "нет подтверждённых записей для проверки");
}
