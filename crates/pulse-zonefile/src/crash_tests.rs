//! Crash-harness: kill -9 в каждой фазе коммита (`zonefile-v1.md` §15).
//!
//! Родительский тест запускает этот же lib-тест как дочерний процесс с
//! `PULSE_ZF_CRASH_PHASE`; хук в commit-пути убивает процесс через SIGKILL.
//! После каждого прогона файл переоткрывается: виден либо старый, либо новый
//! снапшот целиком, `fsck` чист.

#![cfg(test)]

use std::os::unix::process::ExitStatusExt;
use std::process::Command;

use crate::key::NameRle;
use crate::{
    CreateConfig, InvariantId, LockMode, OpenConfig, RrsetData, SyncMode, ZoneFile, ZoneFileError,
};

const APEX: &str = "example.com";
const PHASES: [&str; 8] = [
    "commit_data_mid",
    "commit_data_written",
    "commit_data_synced",
    "commit_before_meta",
    "torn_meta",
    "commit_meta_written",
    "commit_meta_synced",
    "commit_published",
];

fn writer_cfg() -> OpenConfig {
    OpenConfig {
        lock_mode: LockMode::Writer,
        ..OpenConfig::default()
    }
}

fn a(byte: u8) -> RrsetData {
    RrsetData::from_slices(300, 0, &[&[192, 0, 2, byte]]).expect("rrset")
}

fn lookup(zonefile: &ZoneFile, apex: &NameRle) -> Option<Vec<u8>> {
    zonefile
        .lookup_rrset(apex, apex, 1, 0)
        .ok()
        .flatten()
        .and_then(|view| view.rdata.first().cloned())
}

fn baseline(path: &std::path::Path) {
    let mut zonefile = ZoneFile::create(
        path,
        CreateConfig {
            map_size: 64 * 1024 * 1024,
            ..CreateConfig::default()
        },
    )
    .unwrap();
    let apex = NameRle::from_ascii(APEX).unwrap();
    let mut writer = zonefile.write().unwrap();
    writer.create_zone(&apex, 0).unwrap();
    writer
        .upsert_rrset(
            &apex,
            &apex,
            6,
            0,
            &RrsetData::from_slices(300, 0, &[&[1, 2, 3, 4]]).unwrap(),
        )
        .unwrap();
    writer
        .upsert_rrset(
            &apex,
            &apex,
            2,
            0,
            &RrsetData::from_slices(300, 0, &[&[1, 2]]).unwrap(),
        )
        .unwrap();
    writer.upsert_rrset(&apex, &apex, 1, 0, &a(1)).unwrap();
    writer.commit(SyncMode::Sync).unwrap();
}

/// Дочерний процесс; без env-переменной тест немедленно завершается.
#[test]
fn crash_child() {
    if std::env::var_os("PULSE_ZF_CRASH_CHILD").is_none() {
        return;
    }
    let path = std::path::PathBuf::from(std::env::var("PULSE_ZF_CRASH_PATH").unwrap());
    let value: u8 = std::env::var("PULSE_ZF_CRASH_VALUE")
        .unwrap()
        .parse()
        .unwrap();
    let apex = NameRle::from_ascii(APEX).unwrap();
    let mut zonefile = ZoneFile::open(&path, writer_cfg()).unwrap();
    let mut writer = zonefile.write().unwrap();
    writer.upsert_rrset(&apex, &apex, 1, 0, &a(value)).unwrap();
    let _ = writer.commit(SyncMode::Sync).unwrap();
}

#[test]
fn crash_kill_9_every_commit_phase() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    baseline(&path);
    let apex = NameRle::from_ascii(APEX).unwrap();
    let exe = std::env::current_exe().unwrap();
    let mut last = vec![192, 0, 2, 1];
    for iteration in 0..140_u32 {
        let phase = PHASES[(iteration as usize) % PHASES.len()];
        let value = u8::try_from(iteration % 250 + 2).unwrap();
        let status = Command::new(&exe)
            .arg("--exact")
            .arg("crash_tests::crash_child")
            .arg("--nocapture")
            .env("PULSE_ZF_CRASH_CHILD", "1")
            .env("PULSE_ZF_CRASH_PATH", &path)
            .env("PULSE_ZF_CRASH_PHASE", phase)
            .env("PULSE_ZF_CRASH_VALUE", value.to_string())
            .status()
            .unwrap();
        assert!(
            status.signal().is_some() || status.success(),
            "child failed on phase {phase}: {status:?}"
        );
        let zonefile = ZoneFile::open(&path, OpenConfig::default())
            .unwrap_or_else(|error| panic!("reopen after phase {phase} failed: {error:?}"));
        let current = lookup(&zonefile, &apex)
            .unwrap_or_else(|| panic!("zone/apex lost after phase {phase}"));
        let expected_new = vec![192, 0, 2, value];
        assert!(
            current == last || current == expected_new,
            "phase {phase}: unexpected value {current:?}, last {last:?}, new {expected_new:?}"
        );
        let report = zonefile
            .fsck()
            .unwrap_or_else(|error| panic!("fsck after phase {phase}: {error:?}"));
        assert!(report.is_ok(), "phase {phase}: {report:?}");
        drop(zonefile);
        last = current;
    }
    // Контроль, что тест не «застрял» на baseline: хотя бы один коммит прошёл.
    assert_ne!(last, vec![192, 0, 2, 1]);
}

#[test]
fn durability_floor_is_enforced() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let mut zonefile = ZoneFile::create(
        &path,
        CreateConfig {
            map_size: 64 * 1024 * 1024,
            sync_mode: SyncMode::Sync,
            ..CreateConfig::default()
        },
    )
    .unwrap();
    let apex = NameRle::from_ascii(APEX).unwrap();
    let mut writer = zonefile.write().unwrap();
    writer.create_zone(&apex, 0).unwrap();
    writer.commit(SyncMode::Sync).unwrap();
    let writer = zonefile.write().unwrap();
    let error = writer.commit(SyncMode::NoSync).unwrap_err();
    assert!(matches!(
        error,
        ZoneFileError::InvariantViolation(InvariantId::DurabilityBelowFileMode)
    ));
}
