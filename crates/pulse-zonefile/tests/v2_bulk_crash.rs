//! Crash после bulk-загрузки: `SIGKILL` в каждой точке коммита, затем
//! recovery/fsck и чтение зоны (либо старая пустая версия, либо новый набор).

use std::fs::File;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    BulkRrset, CrashHook, CrashPoint, OpenConfigV2, ParallelStore, ParallelZones, RrsetData,
    StoreConfig, ZoneCreateMeta,
};

const CHILD_TEST: &str = "v2_bulk_crash_child";
const BULK_RECORDS: u32 = 4_000;

fn config() -> StoreConfig {
    StoreConfig::small(8, 32_768)
}

fn apex() -> NameRle {
    NameRle::from_ascii("bulk-crash.example").unwrap()
}

fn records() -> Vec<BulkRrset> {
    (0..BULK_RECORDS)
        .map(|index| BulkRrset {
            name: NameRle::from_ascii(&format!("r{index:05}.bulk-crash.example")).unwrap(),
            rr_type: 1,
            subtype: 0,
            data: RrsetData::from_slices(60, 0, &[&[10, 0, 0, u8::try_from(index % 250).unwrap()]])
                .unwrap(),
        })
        .collect()
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

const POINTS: [(&str, CrashPoint); 9] = [
    ("before_alloc_record", CrashPoint::BeforeAllocRecord),
    ("after_phase1_writes", CrashPoint::AfterPhase1Writes),
    ("after_phase1_fsync", CrashPoint::AfterPhase1Fsync),
    ("before_root_write", CrashPoint::BeforeRootWrite),
    ("after_root_copy_a", CrashPoint::AfterRootCopyA),
    ("after_root_copy_b", CrashPoint::AfterRootCopyB),
    ("after_phase2_fsync", CrashPoint::AfterPhase2Fsync),
    ("before_head_publish", CrashPoint::BeforeHeadPublish),
    ("after_head_publish", CrashPoint::AfterHeadPublish),
];

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

#[test]
fn v2_bulk_crash_child() {
    let Some(dir) = std::env::var_os("PULSE_V2_BULK_CRASH_DIR") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let path = dir.join("bulk-crash.v2");
    let point = std::env::var("PULSE_V2_BULK_CRASH_POINT")
        .ok()
        .and_then(|name| parse_point(&name));
    let mut store = ParallelStore::create(&path, config()).expect("create store");
    let mut zones = ParallelZones::open(&store).expect("catalog");
    let seq = zones
        .create_zone(&apex(), ZoneCreateMeta { soa_serial: 1 })
        .expect("create zone");
    drop(zones);
    let armed = Arc::new(AtomicBool::new(false));
    if let Some(point) = point {
        store.set_crash_hook(Box::new(KillAt {
            point,
            armed: Arc::clone(&armed),
        }));
    }
    let zones = ParallelZones::open(&store).expect("catalog");
    let mut writer = zones.writer_by_seq(seq).expect("writer");
    writer.bulk_load(records()).expect("bulk load");
    armed.store(true, Ordering::Release);
    writer.commit().expect("commit");
    panic!("commit was not killed");
}

fn spawn_child(dir: &std::path::Path, point_name: &str) {
    let exe = std::env::current_exe().expect("current exe");
    let stderr = File::create(dir.join(format!("{point_name}.stderr"))).expect("stderr");
    let status = Command::new(exe)
        .args(["--exact", CHILD_TEST, "--nocapture"])
        .env("PULSE_V2_BULK_CRASH_DIR", dir)
        .env("PULSE_V2_BULK_CRASH_POINT", point_name)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr))
        .status()
        .expect("spawn child");
    assert!(
        status.code().is_none(),
        "child at {point_name} exited: {status:?}"
    );
}

#[test]
fn bulk_commit_crash_recovers() {
    for (point_name, _point) in POINTS {
        let dir = tempfile::tempdir().unwrap();
        spawn_child(dir.path(), point_name);
        let path = dir.path().join("bulk-crash.v2");
        let store = ParallelStore::open(&path, OpenConfigV2::default()).unwrap();
        let fsck = store.fsck_lite().unwrap();
        assert!(fsck.ok, "{point_name}: fsck {fsck:?}");
        let zones = ParallelZones::open(&store).unwrap();
        assert!(zones.zone_seq(&apex()).is_some(), "{point_name}: zone lost");
        let reader = store.reader().unwrap();
        let view = zones.read(&reader, &apex()).expect("read zone");
        let rows = view.records().unwrap();
        assert!(
            rows.is_empty() || rows.len() == usize::try_from(BULK_RECORDS).unwrap(),
            "{point_name}: torn bulk tree: {} rows",
            rows.len()
        );
        if rows.len() == usize::try_from(BULK_RECORDS).unwrap() {
            for row in &rows {
                assert_eq!(row.rr_type, 1);
                assert_ne!(row.rdata.len(), 0);
            }
        }
    }
}
