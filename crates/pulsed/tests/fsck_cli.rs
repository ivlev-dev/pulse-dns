//! E2E `pulsed fsck --data <file> [--repair]` на настоящем v2-файле.

use std::process::Command;

use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    OpenConfigV2, ParallelStore, ParallelZones, RrsetData, StoreConfig, ZoneCreateMeta,
};

fn build(path: &std::path::Path) {
    let store = ParallelStore::create(path, StoreConfig::small(8, 256)).unwrap();
    let apex = NameRle::from_ascii("fsck.example").unwrap();
    let mut zones = ParallelZones::open(&store).unwrap();
    zones
        .create_zone(&apex, ZoneCreateMeta { soa_serial: 1 })
        .unwrap();
    let name = NameRle::from_ascii("www.fsck.example").unwrap();
    let mut writer = zones.writer(&apex).unwrap();
    writer
        .upsert_rrset(
            &name,
            1,
            0,
            &RrsetData::from_slices(60, 0, &[&[192, 0, 2, 1]]).unwrap(),
        )
        .unwrap();
    writer.commit().unwrap();
}

fn leak(store: &ParallelStore, pages: u32) {
    let ticket = store.reserve_pages(pages).unwrap();
    for page in ticket.first_page..=ticket.last_page() {
        store.write_raw_page(page, b"aborted").unwrap();
    }
    store.sync().unwrap();
}

#[test]
fn verify_and_repair_via_cli() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fsck.v2");
    build(&path);

    let verify = Command::new(env!("CARGO_BIN_EXE_pulsed"))
        .args(["fsck", "--data"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
    assert!(String::from_utf8_lossy(&verify.stdout).contains("ok=true"));

    {
        let store = ParallelStore::open(&path, OpenConfigV2::default()).unwrap();
        leak(&store, 8);
    }

    let repair = Command::new(env!("CARGO_BIN_EXE_pulsed"))
        .args(["fsck", "--data"])
        .arg(&path)
        .arg("--repair")
        .output()
        .unwrap();
    assert!(
        repair.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&repair.stdout),
        String::from_utf8_lossy(&repair.stderr)
    );
    let text = String::from_utf8_lossy(&repair.stdout);
    assert!(text.contains("repaired="), "{text}");
    assert!(text.contains("ok=true"), "{text}");

    // Идемпотентность: повторная проверка после repair.
    let again = Command::new(env!("CARGO_BIN_EXE_pulsed"))
        .args(["fsck", "--data"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        again.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&again.stdout),
        String::from_utf8_lossy(&again.stderr)
    );
}
