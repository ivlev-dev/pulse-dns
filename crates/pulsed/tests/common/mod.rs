//! Общие помощники e2e: временный zonefile и импорт master-файла бинарником.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use pulsed::config::{Config, Durability, TcpConfig};

pub struct TempZone {
    _dir: tempfile::TempDir,
    pub data: PathBuf,
}

impl TempZone {
    pub fn empty(label: &str) -> Self {
        let dir = tempfile::Builder::new()
            .prefix(&format!("pulsed-{label}-{}-", std::process::id()))
            .tempdir()
            .expect("temp dir");
        let data = dir.path().join("zones.pulse");
        Self { _dir: dir, data }
    }

    pub fn with_import(label: &str, origin: &str, zone: &Path) -> Self {
        let temp = Self::empty(label);
        import(&temp.data, origin, zone);
        temp
    }

    pub fn path(&self) -> &Path {
        &self.data
    }
}

pub fn example_zone() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/example.com.zone")
}

pub fn write_text(label: &str, name: &str, text: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::Builder::new()
        .prefix(&format!("pulsed-{label}-{}-", std::process::id()))
        .tempdir()
        .expect("temp dir");
    let path = dir.path().join(name);
    std::fs::write(&path, text).expect("write zone");
    (dir, path)
}

pub fn import(data: &Path, origin: &str, zone: &Path) {
    let output = Command::new(env!("CARGO_BIN_EXE_pulsed"))
        .arg("import")
        .arg("--data")
        .arg(data)
        .arg("--origin")
        .arg(origin)
        .arg(zone)
        .env_remove("PULSED_API_TOKEN")
        .output()
        .expect("run pulsed import");
    assert!(
        output.status.success(),
        "import failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

pub fn base_config(data: &Path) -> Config {
    Config {
        listen_udp: Some("127.0.0.1:0".parse().expect("udp")),
        listen_tcp: Some("127.0.0.1:0".parse().expect("tcp")),
        workers: 1,
        tcp: TcpConfig {
            idle_timeout_ms: 2000,
            ..TcpConfig::default()
        },
        zonefile: Some(data.to_path_buf()),
        durability: Durability::Flush,
        map_size: 64 * 1024 * 1024,
        ..Config::default()
    }
}

pub fn unique_serial() -> u32 {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    u32::try_from(seconds % 4_000_000_000).unwrap_or(1).max(1)
}
