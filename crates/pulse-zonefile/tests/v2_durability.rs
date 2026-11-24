//! B2b: `Flush`/`Memory` durability, липкий `Sync` и `sync()`-чекпойнт.
//!
//! `Flush` синхронизирует данные (фаза 1) и не синхронизирует корни: переживает
//! `kill -9` процесса (page cache), но power loss откатывает зону на предыдущую
//! версию. `Memory` не делает fsync вовсе. Эмуляция power loss — затирание
//! обеих ring-копий новейшей версии (torn meta): recovery обязан выбрать
//! предыдущую валидную версию без порчи.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    OpenConfigV2, ParallelError, ParallelStore, ParallelZones, RrsetData, StoreConfig, SyncModeV2,
    ZoneCreateMeta,
};

const CHILD_TEST: &str = "flush_crash_child";

fn config(mode: SyncModeV2) -> StoreConfig {
    StoreConfig {
        sync_mode: mode,
        ..StoreConfig::small(16, 4096)
    }
}

fn origin() -> NameRle {
    NameRle::from_ascii("flush.example").unwrap()
}

fn name(commit: u32) -> NameRle {
    NameRle::from_ascii(&format!("r{commit}.flush.example")).unwrap()
}

fn rr(commit: u32) -> RrsetData {
    RrsetData::from_slices(60, 0, &[&[10, 0, 0, u8::try_from(commit % 256).unwrap()]]).unwrap()
}

fn tear_root(path: &Path, page_a: u32, page_b: u32, cell: usize) {
    let file = OpenOptions::new().write(true).open(path).unwrap();
    for page in [page_a, page_b] {
        let offset = u64::from(page) * 4096 + u64::try_from(cell).unwrap();
        file.write_all_at(&[0_u8; 64], offset).unwrap();
    }
    file.sync_all().unwrap();
}

fn kill_child_and_collect(mode: &str) -> (tempfile::TempDir, Vec<u64>) {
    let dir = tempfile::tempdir().unwrap();
    let exe = std::env::current_exe().unwrap();
    let mut child = Command::new(exe)
        .arg("--exact")
        .arg(CHILD_TEST)
        .arg("--nocapture")
        .env("PULSE_V2_FLUSH_DIR", dir.path())
        .env("PULSE_V2_FLUSH_MODE", mode)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let ack_path = dir.path().join("acks.log");
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut acked = Vec::new();
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
        if let Ok(text) = std::fs::read_to_string(&ack_path) {
            acked = text
                .lines()
                .filter_map(|line| line.trim().parse::<u64>().ok())
                .collect::<Vec<_>>();
            if acked.len() >= 3 {
                break;
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    assert!(!acked.is_empty(), "ребёнок не подтвердил ни одного коммита");
    (dir, acked)
}

#[test]
fn flush_survives_process_kill() {
    let (dir, acked) = kill_child_and_collect("flush");
    let max_acked = *acked.iter().max().unwrap();
    let path = dir.path().join("flush.v2");
    let store = ParallelStore::open(&path, OpenConfigV2::default()).unwrap();
    let zones = ParallelZones::open(&store).unwrap();
    let seq = zones.zone_seq(&origin()).expect("зона");
    let head = store.select_root(seq, u64::MAX).unwrap();
    assert!(
        head.version >= max_acked,
        "Flush потерял ack-нутый коммит: голова {}, ack {max_acked}",
        head.version
    );
    let reader = store.reader().unwrap();
    let view = zones.read(&reader, &origin()).unwrap();
    assert!(view.records().unwrap().len() >= 3);
    assert!(store.fsck_lite().unwrap().ok);
    assert!(store.fsck_graph().unwrap().ok);
}

#[test]
fn memory_survives_process_kill() {
    let (dir, acked) = kill_child_and_collect("memory");
    let max_acked = *acked.iter().max().unwrap();
    let path = dir.path().join("flush.v2");
    let store = ParallelStore::open(&path, OpenConfigV2::default()).unwrap();
    assert_eq!(store.effective_mode(), SyncModeV2::Memory);
    let zones = ParallelZones::open(&store).unwrap();
    let seq = zones.zone_seq(&origin()).expect("зона");
    let head = store.select_root(seq, u64::MAX).unwrap();
    assert!(
        head.version >= max_acked,
        "Memory потерял ack-нутый коммит: голова {}, ack {max_acked}",
        head.version
    );
    assert!(store.fsck_lite().unwrap().ok);
}

/// Дочерний процесс: `Flush`-коммиты + ack-лог, живёт до `SIGKILL`.
#[test]
fn flush_crash_child() {
    let Some(dir) = std::env::var_os("PULSE_V2_FLUSH_DIR") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let path = dir.join("flush.v2");
    let mode = match std::env::var("PULSE_V2_FLUSH_MODE").as_deref() {
        Ok("memory") => SyncModeV2::Memory,
        _ => SyncModeV2::Flush,
    };
    let store = ParallelStore::create(&path, config(mode)).unwrap();
    let mut zones = ParallelZones::open(&store).unwrap();
    zones
        .create_zone(&origin(), ZoneCreateMeta { soa_serial: 1 })
        .unwrap();
    let mut log = File::create(dir.join("acks.log")).unwrap();
    let mut writer = zones.writer(&origin()).unwrap();
    let mut commit = 0_u32;
    loop {
        writer
            .upsert_rrset(&name(commit), 1, 0, &rr(commit))
            .unwrap();
        let outcome = writer.commit_with(mode).unwrap();
        writeln!(log, "{}", outcome.version).unwrap();
        log.sync_data().unwrap();
        commit = commit.saturating_add(1);
    }
}

#[test]
fn flush_power_loss_rolls_back_without_corruption() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("flush-power.v2");
    let store = ParallelStore::create(&path, config(SyncModeV2::Flush)).unwrap();
    let mut zones = ParallelZones::open(&store).unwrap();
    let seq = zones
        .create_zone(&origin(), ZoneCreateMeta { soa_serial: 1 })
        .unwrap();
    let mut writer = zones.writer(&origin()).unwrap();
    writer.upsert_rrset(&name(0), 1, 0, &rr(0)).unwrap();
    let first = writer.commit_with(SyncModeV2::Flush).unwrap();
    writer.upsert_rrset(&name(1), 1, 0, &rr(1)).unwrap();
    let second = writer.commit_with(SyncModeV2::Flush).unwrap();
    drop(writer);
    assert_eq!(store.durable_version(seq), 0);
    let slot = store.geometry().head_slot(seq).unwrap();
    let cell = slot.cell_offset(second.version);
    drop(zones);
    drop(store);

    // Power loss: корни второй версии не были fsync'нуты — теряем обе копии.
    tear_root(&path, slot.page_a, slot.page_b, cell);

    let reopened = ParallelStore::open(&path, OpenConfigV2::default()).unwrap();
    assert!(reopened.fatal().is_none());
    let head = reopened.select_root(seq, u64::MAX).unwrap();
    assert_eq!(head.version, first.version, "ожидался откат на V−1");
    let reader = reopened.reader().unwrap();
    let zones = ParallelZones::open(&reopened).unwrap();
    let view = zones.read(&reader, &origin()).unwrap();
    assert!(view.lookup(&name(0), 1, 0).unwrap().is_some());
    assert!(view.lookup(&name(1), 1, 0).unwrap().is_none());
    assert!(reopened.fsck_lite().unwrap().ok);
    assert!(reopened.fsck_graph().unwrap().ok);
}

#[test]
fn memory_survives_process_crash_and_rolls_back_on_power_loss() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("memory.v2");
    let store = ParallelStore::create(&path, config(SyncModeV2::Memory)).unwrap();
    let mut zones = ParallelZones::open(&store).unwrap();
    let seq = zones
        .create_zone(&origin(), ZoneCreateMeta { soa_serial: 1 })
        .unwrap();
    let mut writer = zones.writer(&origin()).unwrap();
    writer.upsert_rrset(&name(0), 1, 0, &rr(0)).unwrap();
    let first = writer.commit_with(SyncModeV2::Memory).unwrap();
    writer.upsert_rrset(&name(1), 1, 0, &rr(1)).unwrap();
    let second = writer.commit_with(SyncModeV2::Memory).unwrap();
    assert_eq!(store.durable_version(seq), 0);
    let slot = store.geometry().head_slot(seq).unwrap();
    let cell = slot.cell_offset(second.version);
    drop(writer);
    drop(zones);
    drop(store);

    // Process-crash: page cache жив, данные и корни на месте (без fsync).
    {
        let reopened = ParallelStore::open(&path, OpenConfigV2::default()).unwrap();
        assert_eq!(reopened.effective_mode(), SyncModeV2::Memory);
        let head = reopened.select_root(seq, u64::MAX).unwrap();
        assert_eq!(head.version, second.version);
        assert!(reopened.select_root(seq, u64::MAX).unwrap().rrset_count >= 2);
    }

    // Power loss: корни второй версии потеряны → валидный откат.
    tear_root(&path, slot.page_a, slot.page_b, cell);
    let reopened = ParallelStore::open(&path, OpenConfigV2::default()).unwrap();
    let head = reopened.select_root(seq, u64::MAX).unwrap();
    assert_eq!(head.version, first.version);
    assert!(reopened.fsck_lite().unwrap().ok);
    assert!(reopened.fsck_graph().unwrap().ok);
}

#[test]
fn sticky_sync_forbids_weaker_modes_after_first_durable_commit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sticky.v2");
    let store = ParallelStore::create(&path, config(SyncModeV2::Flush)).unwrap();
    let mut zones = ParallelZones::open(&store).unwrap();
    zones
        .create_zone(&origin(), ZoneCreateMeta { soa_serial: 1 })
        .unwrap();
    let mut writer = zones.writer(&origin()).unwrap();
    writer.upsert_rrset(&name(0), 1, 0, &rr(0)).unwrap();
    let flush = writer.commit_with(SyncModeV2::Flush).unwrap();
    assert_eq!(store.effective_mode(), SyncModeV2::Flush);
    // `Memory` слабее файлового `Flush`.
    assert!(matches!(
        writer.commit_with(SyncModeV2::Memory),
        Err(ParallelError::DurabilityBelowFileMode { .. })
    ));
    // Первый `Sync` делает режим липким.
    writer.upsert_rrset(&name(10), 1, 0, &rr(10)).unwrap();
    let sync = writer.commit_with(SyncModeV2::Sync).unwrap();
    assert_eq!(store.effective_mode(), SyncModeV2::Sync);
    assert_eq!(store.durable_version(writer.zone()), sync.version);
    for mode in [SyncModeV2::Flush, SyncModeV2::Memory] {
        writer.upsert_rrset(&name(1), 1, 0, &rr(1)).unwrap();
        assert!(matches!(
            writer.commit_with(mode),
            Err(ParallelError::DurabilityBelowFileMode { .. })
        ));
    }
    assert!(flush.version < sync.version);
    drop(writer);
    drop(zones);
    drop(store);

    let reopened = ParallelStore::open(&path, OpenConfigV2::default()).unwrap();
    assert_eq!(reopened.effective_mode(), SyncModeV2::Sync);
    let head = reopened.select_root(1, u64::MAX).unwrap();
    assert!(head.version >= sync.version);
}

#[test]
fn sync_checkpoints_flush_commits() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("checkpoint.v2");
    let store = ParallelStore::create(&path, config(SyncModeV2::Flush)).unwrap();
    let mut zones = ParallelZones::open(&store).unwrap();
    let seq = zones
        .create_zone(&origin(), ZoneCreateMeta { soa_serial: 1 })
        .unwrap();
    let mut writer = zones.writer(&origin()).unwrap();
    writer.upsert_rrset(&name(0), 1, 0, &rr(0)).unwrap();
    let outcome = writer.commit_with(SyncModeV2::Flush).unwrap();
    assert_eq!(store.durable_version(seq), 0);
    store.sync().unwrap();
    assert!(store.durable_version(seq) >= outcome.version);
    assert_eq!(store.effective_mode(), SyncModeV2::Sync);
    assert!(matches!(
        writer.commit_with(SyncModeV2::Flush),
        Err(ParallelError::DurabilityBelowFileMode { .. })
    ));
    drop(writer);
    drop(zones);
    drop(store);
    let reopened = ParallelStore::open(&path, OpenConfigV2::default()).unwrap();
    let head = reopened.select_root(seq, u64::MAX).unwrap();
    assert!(head.version >= outcome.version);
    assert!(reopened.fsck_lite().unwrap().ok);
}
