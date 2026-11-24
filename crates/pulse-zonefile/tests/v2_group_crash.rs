//! B2b crash-harness группового коммита: `SIGKILL` в случайные моменты и в
//! детерминированные точки фаз группы. Проверяется: ack-нутые версии пережили
//! крах, частичной публикации «после ack» нет, recovery не даёт `Corrupt`.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    CrashHook, CrashPoint, GroupCommitter, OpenConfigV2, ParallelStore, ParallelZones, RrsetData,
    StoreConfig, ZoneCreateMeta,
};

const CHILD_TEST: &str = "group_crash_child";
const ZONES: u32 = 4;

fn config() -> StoreConfig {
    StoreConfig::small(16, 8192)
}

fn origin(index: u32) -> NameRle {
    NameRle::from_ascii(&format!("c{index}.example")).unwrap()
}

fn rr(value: u32) -> RrsetData {
    RrsetData::from_slices(60, 0, &[&[10, 0, 0, u8::try_from(value % 256).unwrap()]]).unwrap()
}

fn name(zone: u32, value: u32) -> NameRle {
    NameRle::from_ascii(&format!("r{value}.c{zone}.example")).unwrap()
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

/// Дочерний процесс: группами коммитит зоны и пишет ack-лог до `SIGKILL`.
#[test]
fn group_crash_child() {
    let Some(dir) = std::env::var_os("PULSE_V2_GROUP_CRASH_DIR") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let path = dir.join("group-crash.v2");
    let point = std::env::var("PULSE_V2_GROUP_CRASH_POINT")
        .ok()
        .and_then(|name| parse_point(&name));
    let mut store = ParallelStore::create(&path, config()).expect("create");
    let armed = Arc::new(AtomicBool::new(false));
    if let Some(point) = point {
        store.set_crash_hook(Box::new(KillAt {
            point,
            armed: Arc::clone(&armed),
        }));
    }
    let store = Arc::new(store);
    let mut zones = ParallelZones::open(&store).unwrap();
    let mut origins = Vec::new();
    for index in 0..ZONES {
        zones
            .create_zone(
                &origin(index),
                ZoneCreateMeta {
                    soa_serial: index + 1,
                },
            )
            .unwrap();
        origins.push(origin(index));
    }
    let committer = GroupCommitter::new(Arc::clone(&store)).expect("committer");
    let mut log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("acks.log"))
        .expect("ack log");
    let mut ready = File::create(dir.join("ready")).unwrap();
    ready.write_all(b"1").unwrap();
    let mut versions = [2_u64; ZONES as usize + 1];
    let mut ack_count = 0_u32;
    let mut zone = 0_usize;
    loop {
        let apex = origins[zone % origins.len()];
        let mut writer = zones.writer(&apex).unwrap();
        let slot = zone % versions.len();
        let value = versions[slot];
        writer
            .upsert_rrset(
                &name(u32::try_from(zone).unwrap(), u32::try_from(value).unwrap()),
                1,
                0,
                &rr(u32::try_from(value).unwrap()),
            )
            .unwrap();
        let outcome = writer.commit_via(&committer).unwrap();
        writeln!(log, "{} {}", outcome.zone, outcome.version).unwrap();
        log.sync_data().unwrap();
        versions[slot] = value + 1;
        zone = zone.saturating_add(1);
        ack_count = ack_count.saturating_add(1);
        if ack_count >= 2 {
            armed.store(true, Ordering::Release);
        }
    }
}

fn spawn_child(dir: &Path, point: Option<CrashPoint>) -> Child {
    let exe = std::env::current_exe().unwrap();
    let mut command = Command::new(exe);
    command
        .arg("--exact")
        .arg(CHILD_TEST)
        .arg("--nocapture")
        .env("PULSE_V2_GROUP_CRASH_DIR", dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(point) = point {
        let point_name = match point {
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
        command.env("PULSE_V2_GROUP_CRASH_POINT", point_name);
    }
    command.spawn().unwrap()
}

fn wait_ready(dir: &Path, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if dir.join("ready").exists() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill();
    panic!("ребёнок не стартовал");
}

fn read_acks(dir: &Path) -> Vec<(u32, u64)> {
    let Ok(text) = std::fs::read_to_string(dir.join("acks.log")) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let zone = parts.next()?.parse().ok()?;
            let version = parts.next()?.parse().ok()?;
            Some((zone, version))
        })
        .collect()
}

fn run_iteration(index: u32, point: Option<CrashPoint>) {
    let dir = std::env::temp_dir().join(format!(
        "pulse-v2-group-crash-{}-{index}-{}",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut child = spawn_child(&dir, point);
    wait_ready(&dir, &mut child);
    if point.is_none() {
        // Случайная задержка: разные точки внутри группы.
        let delay = 10 + (u64::from(index) * 37) % 80;
        thread::sleep(Duration::from_millis(delay));
    } else {
        thread::sleep(Duration::from_millis(80));
    }
    let _ = child.kill();
    let _ = child.wait();
    let acks = read_acks(&dir);
    let path = dir.join("group-crash.v2");
    let Ok(store) = ParallelStore::open(&path, OpenConfigV2::default()) else {
        let _ = std::fs::remove_dir_all(&dir);
        panic!("recovery после краха не открыл файл (iteration {index})");
    };
    assert!(
        store.fatal().is_none(),
        "file-fatal после краха: {:?}",
        store.fatal()
    );
    let mut max_acked = [0_u64; ZONES as usize + 1];
    for (zone, version) in &acks {
        let index = usize::try_from(*zone).unwrap_or(0);
        if let Some(slot) = max_acked.get_mut(index) {
            *slot = (*slot).max(*version);
        }
    }
    for zone in 1..=ZONES {
        let acked = max_acked[zone as usize];
        if acked == 0 {
            continue;
        }
        let head = store
            .select_root(zone, u64::MAX)
            .unwrap_or_else(|error| panic!("zone {zone}: {error:?}"));
        assert!(
            head.version >= acked,
            "zone {zone}: голова {} < ack {acked}",
            head.version
        );
    }
    let graph = store.fsck_graph().unwrap();
    assert!(
        graph.ok,
        "fsck после краха: fatal={:?} issues={:?}",
        graph.fatal, graph.issues
    );
    drop(store);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn group_crash_kill9_random_and_point() {
    for index in 0..10_u32 {
        run_iteration(index, None);
    }
    for (index, point) in [
        CrashPoint::BeforeAllocRecord,
        CrashPoint::AfterPhase1Writes,
        CrashPoint::AfterPhase1Fsync,
        CrashPoint::BeforeRootWrite,
        CrashPoint::AfterRootCopyA,
        CrashPoint::AfterRootCopyB,
        CrashPoint::AfterPhase2Fsync,
        CrashPoint::BeforeHeadPublish,
        CrashPoint::AfterHeadPublish,
    ]
    .into_iter()
    .enumerate()
    {
        run_iteration(100 + u32::try_from(index).unwrap(), Some(point));
    }
}
