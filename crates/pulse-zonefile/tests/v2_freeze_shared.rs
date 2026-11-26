//! Межпроцессный `freeze()` (sidecar v5): барьер из любого процесса,
//! `min(local, shared)` в рекламации, TTL/crash-safety.
//!
//! Дочерний режим — `PULSE_FREEZE_CHILD`; без него `child_entry` — no-op.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    OpenConfigV2, ParallelError, ParallelStore, ParallelZones, RootEntry, RootState, RrsetData,
    StoreConfig, SyncModeV2, ZoneCreateMeta,
};

const CHILD: &str = "PULSE_FREEZE_CHILD";
const PATH: &str = "PULSE_FREEZE_PATH";
const DIR: &str = "PULSE_FREEZE_DIR";
const TTL_MS: &str = "PULSE_FREEZE_TTL_MS";

fn config() -> StoreConfig {
    StoreConfig {
        multi_process: true,
        sync_mode: SyncModeV2::Sync,
        ..StoreConfig::small(8, 1 << 16)
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

fn origin() -> NameRle {
    NameRle::from_ascii("freeze.example").unwrap()
}

fn rr() -> RrsetData {
    RrsetData::from_slices(60, 0, &[&[192, 0, 2, 9]]).unwrap()
}

fn seed(path: &Path) {
    let store = ParallelStore::create(path, config()).unwrap();
    let mut zones = ParallelZones::open(&store).unwrap();
    let seq = zones
        .create_zone(&origin(), ZoneCreateMeta { soa_serial: 1 })
        .unwrap();
    let mut writer = zones.writer_by_seq(seq).unwrap();
    writer
        .upsert_rrset(
            &NameRle::from_ascii("a.freeze.example").unwrap(),
            1,
            0,
            &rr(),
        )
        .unwrap();
    writer.commit().unwrap();
}

fn publish_next(store: &ParallelStore, zone: u32) -> u64 {
    let version = store
        .zone_head(zone)
        .map_or(1, |head| head.version)
        .saturating_add(1);
    publish(store, zone, version);
    version
}

fn publish(store: &ParallelStore, zone: u32, version: u64) {
    let entry = RootEntry {
        owner_zone: zone,
        version,
        root_page: 0,
        state: RootState::Serving,
        soa_serial: u32::try_from(version).unwrap(),
        ..RootEntry::default()
    };
    for _ in 0..64 {
        match store.publish_root(entry) {
            Ok(_) => return,
            Err(ParallelError::ReaderContended) => std::thread::sleep(Duration::from_millis(1)),
            Err(error) => panic!("publish {version}: {error:?}"),
        }
    }
    panic!("publish retry limit");
}

fn spawn_child(mode: &str, path: &Path, dir: &Path, ttl_ms: u64) -> Child {
    Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_entry", "--nocapture"])
        .env(CHILD, mode)
        .env(PATH, path)
        .env(DIR, dir)
        .env(TTL_MS, ttl_ms.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn child")
}

fn wait_file(path: &Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "timeout waiting {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn touch(path: &Path) {
    std::fs::write(path, b"1").unwrap();
}

fn child_freezer(path: &Path) {
    let store = open_multi(path).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match store.freeze_persist(Duration::from_secs(60)) {
            Ok(_epoch) => {
                touch(&path.with_extension(format!("winner-{}", std::process::id())));
                break;
            }
            Err(ParallelError::Busy) => {
                touch(&path.with_extension(format!("busy-{}", std::process::id())));
                break;
            }
            Err(error) if Instant::now() < deadline => {
                eprintln!("freeze retry: {error}");
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("freeze failed: {error}"),
        }
    }
}

fn child_hold_persisted(path: &Path, ttl_ms: u64) {
    let store = open_multi(path).unwrap();
    store
        .freeze_persist(Duration::from_millis(ttl_ms))
        .expect("persist freeze");
    touch(&path.with_extension(format!("ready-{}", std::process::id())));
    std::thread::sleep(Duration::from_secs(60));
}

fn child_observer(path: &Path, dir: &Path) {
    let store = open_multi(path).unwrap();
    touch(&dir.join("observer-ready"));
    let deadline = Instant::now() + Duration::from_secs(10);
    let unfreeze = dir.join("unfreeze");
    // Наблюдатель видит барьер выставленным другим процессом и фиксирует это
    // до того, как родитель снимет его.
    loop {
        if store.freeze_status().active {
            touch(&dir.join("observer-saw-active"));
            break;
        }
        assert!(
            Instant::now() < deadline + Duration::from_secs(10),
            "observer не видит общий freeze"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    while !unfreeze.exists() {
        std::thread::sleep(Duration::from_millis(2));
    }
    loop {
        if !store.freeze_status().active {
            touch(&dir.join("observer-saw-release"));
            return;
        }
        assert!(
            Instant::now() < deadline + Duration::from_secs(10),
            "release timeout"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn child_entry() {
    let Ok(mode) = std::env::var(CHILD) else {
        return;
    };
    let path = PathBuf::from(std::env::var(PATH).unwrap());
    let dir = PathBuf::from(std::env::var(DIR).unwrap_or_else(|_| ".".into()));
    let ttl_ms = std::env::var(TTL_MS)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(60_000);
    match mode.as_str() {
        "freeze" => child_freezer(&path),
        "persist" => child_hold_persisted(&path, ttl_ms),
        "observe" => child_observer(&path, &dir),
        other => panic!("unknown child mode {other}"),
    }
}

#[test]
fn four_processes_freeze_and_unfreeze_retention() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("freeze.v2");
    seed(&path);
    let store = open_multi(&path).unwrap();
    let zone = 1_u32;
    let mut last = 0;
    for _ in 0..3 {
        last = publish_next(&store, zone);
    }
    assert_eq!(store.reclaim_version(zone), last - 1);

    // Четыре процесса одновременно пытаются выставить барьер.
    let mut children: Vec<Child> = (0..4)
        .map(|index| {
            let child = spawn_child("freeze", &path, dir.path(), 60_000);
            let _ = index;
            child
        })
        .collect();
    for child in &mut children {
        let status = child.wait().unwrap();
        assert!(status.success(), "freezer child failed: {status:?}");
    }
    let (winner, busy) = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .fold((0_u32, 0_u32), |(winner, busy), entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("freeze.winner-") {
                (winner + 1, busy)
            } else if name.starts_with("freeze.busy-") {
                (winner, busy + 1)
            } else {
                (winner, busy)
            }
        });
    assert_eq!(
        (winner, busy),
        (1, 3),
        "одновременный freeze должен выиграть ровно один"
    );

    // Победитель вышел из процесса, но барьер переживает его (crash-safe) до
    // явного unfreeze: рекламация остаётся замороженной.
    let status = store.freeze_status();
    assert!(status.active, "{status:?}");
    let _frozen = store.reclaim_version(zone);
    for _ in 0..4 {
        publish_next(&store, zone);
    }
    assert_eq!(
        store.reclaim_version(zone),
        status.epoch,
        "freeze не удержал RV"
    );

    // Наблюдатель из другого процесса видит барьер, затем его снятие.
    let observer = spawn_child("observe", &path, dir.path(), 60_000);
    wait_file(&dir.path().join("observer-ready"), Duration::from_secs(5));
    wait_file(
        &dir.path().join("observer-saw-active"),
        Duration::from_secs(5),
    );
    assert!(store.unfreeze(), "unfreeze должен снять барьер");
    touch(&dir.path().join("unfreeze"));
    let status = observer.wait_with_output().unwrap();
    assert!(status.status.success(), "observer failed: {status:?}");
    wait_file(
        &dir.path().join("observer-saw-release"),
        Duration::from_secs(5),
    );
    assert!(!store.freeze_status().active);
    assert_eq!(store.reclaim_version(zone), last + 3);
}

#[test]
fn persisted_freeze_survives_kill_and_expires_by_ttl() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("kill.v2");
    seed(&path);
    let store = open_multi(&path).unwrap();
    let zone = 1_u32;
    for _ in 0..3 {
        publish_next(&store, zone);
    }

    let mut child = spawn_child("persist", &path, dir.path(), 60_000);
    wait_file(
        &path.with_extension(format!("ready-{}", child.id())),
        Duration::from_secs(5),
    );
    // `kill -9` владельца: барьер остаётся в sidecar (TTL 60 с).
    let _ = rustix::process::kill_process(
        rustix::process::Pid::from_raw(i32::try_from(child.id()).unwrap()).expect("pid"),
        rustix::process::Signal::KILL,
    );
    let _ = child.wait();
    let status = store.freeze_status();
    assert!(status.active, "freeze должен пережить kill -9: {status:?}");
    let frozen = store.reclaim_version(zone);
    publish_next(&store, zone);
    publish_next(&store, zone);
    assert_eq!(store.reclaim_version(zone), status.epoch);
    assert!(store.unfreeze());
    assert!(store.reclaim_version(zone) > frozen);

    // Короткий TTL: барьер истекает, рекламация возобновляется без unfreeze.
    let mut child = spawn_child("persist", &path, dir.path(), 300);
    wait_file(
        &path.with_extension(format!("ready-{}", child.id())),
        Duration::from_secs(5),
    );
    let _ = rustix::process::kill_process(
        rustix::process::Pid::from_raw(i32::try_from(child.id()).unwrap()).expect("pid"),
        rustix::process::Signal::KILL,
    );
    let _ = child.wait();
    let before = store.reclaim_version(zone);
    assert!(store.freeze_status().active || store.freeze_status().expired);
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let status = store.freeze_status();
        if !status.active {
            assert!(status.expired || status.epoch == 0);
            break;
        }
        assert!(Instant::now() < deadline, "TTL не истёк: {status:?}");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(store.reclaim_version(zone) >= before);
}
