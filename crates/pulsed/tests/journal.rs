//! Crash-replay и идемпотентность write-ahead журнала REST-мутаций.
//!
//! Тесты используют debug-хуки `PULSED_JOURNAL_CRASH` и
//! `PULSED_JOURNAL_FAULT` (см. `docs/ops/journal.md`), чтобы детерминированно
//! оборвать процесс в фазах intent/apply/committed и инъецировать ошибку
//! `committed`.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

mod common;

use common::PulsedChild;

use pulsed::config::{Config, Durability, TcpConfig};
use pulsed::server::{ApiOptions, Server};

const TOKEN: &str = "pd_live_journal_0123456789abcdefabcd";
const ZONE: &str = "journal.test.";
const ZONE_PATH: &str = "/api/v1/zones/journal.test.";

struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("addr").port()
}

fn http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> Option<Response> {
    let mut stream = TcpStream::connect(addr).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    let _ = write!(head, "Authorization: Bearer {TOKEN}\r\n");
    for (name, value) in headers {
        let _ = write!(head, "{name}: {value}\r\n");
    }
    if body.is_some() {
        head.push_str("Content-Type: application/json\r\n");
        let _ = write!(head, "Content-Length: {}\r\n", body.map_or(0, <[u8]>::len));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).ok()?;
    if let Some(body) = body {
        stream.write_all(body).ok()?;
    }
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).ok()?;
    parse_response(&raw)
}

fn parse_response(raw: &[u8]) -> Option<Response> {
    let end = raw.windows(4).position(|window| window == b"\r\n\r\n")?;
    let header_block = std::str::from_utf8(raw.get(..end)?).ok()?;
    let mut lines = header_block.split("\r\n");
    let status = lines.next()?.split(' ').nth(1)?.parse::<u16>().ok()?;
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
        .collect();
    Some(Response {
        status,
        headers,
        body: raw.get(end + 4..)?.to_vec(),
    })
}

fn wait_ready(addr: SocketAddr, child: &mut PulsedChild) -> bool {
    child.wait_ready(common::CHILD_READY_TIMEOUT, || {
        http(addr, "GET", "/api/v1/zones", &[], None).is_some_and(|r| r.status == 200)
    })
}

fn write_config(dir: &Path) -> PathBuf {
    let path = dir.join("pulsed.json");
    std::fs::write(
        &path,
        r#"{"listen_udp":"127.0.0.1:0","listen_tcp":null,"workers":1}"#,
    )
    .expect("config");
    path
}

fn spawn(
    label: &str,
    config: &Path,
    data: &Path,
    api: SocketAddr,
    journal_env: Option<(&str, &str)>,
) -> PulsedChild {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pulsed"));
    command
        .arg("--config")
        .arg(config)
        .arg("--data")
        .arg(data)
        .arg("--durability")
        .arg("sync")
        .arg("--api-listen")
        .arg(api.to_string())
        .arg("--api-token")
        .arg(TOKEN)
        .env_remove("PULSED_API_TOKEN")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    if let Some((name, value)) = journal_env {
        command.env(name, value);
    }
    PulsedChild::spawn(format!("journal/{label}"), &mut command)
}

fn open_server(data: &Path) -> Server {
    let config = Config {
        listen_udp: Some("127.0.0.1:0".parse().expect("udp")),
        listen_tcp: None,
        workers: 1,
        tcp: TcpConfig {
            idle_timeout_ms: 2000,
            ..TcpConfig::default()
        },
        zonefile: Some(data.to_path_buf()),
        durability: Durability::Sync,
        map_size: 64 * 1024 * 1024,
        ..Config::default()
    };
    Server::start_with_api(
        &config,
        Some(ApiOptions {
            listen: "127.0.0.1:0".parse().expect("api"),
            token: TOKEN.to_owned(),
            scopes: Vec::new(),
        }),
    )
    .expect("restart with recovery")
}

fn create_zone(api: SocketAddr) {
    let created = http(
        api,
        "PUT",
        ZONE_PATH,
        &[("If-None-Match", "*")],
        Some(br#"{"kind":"primary","default_ttl":3600}"#),
    )
    .expect("create zone");
    assert_eq!(created.status, 201, "create zone");
    let soa = format!("ns1.{ZONE} hostmaster.{ZONE} 1 3600 600 604800 300");
    let body = format!(r#"{{"ttl":3600,"records":["{soa}"]}}"#);
    assert_eq!(
        http(
            api,
            "PUT",
            &format!("{ZONE_PATH}/records/@/SOA"),
            &[],
            Some(body.as_bytes())
        )
        .expect("soa")
        .status,
        201
    );
    let ns = format!(r#"{{"ttl":3600,"records":["ns1.{ZONE}"]}}"#);
    assert_eq!(
        http(
            api,
            "PUT",
            &format!("{ZONE_PATH}/records/@/NS"),
            &[],
            Some(ns.as_bytes())
        )
        .expect("ns")
        .status,
        201
    );
}

fn zone_serial(server: &Server) -> u64 {
    let api = server.api_addr().expect("api");
    let response = http(api, "GET", ZONE_PATH, &[], None).expect("get zone");
    assert_eq!(response.status, 200, "get zone");
    response.json()["serial"].as_u64().expect("serial")
}

fn a_records(server: &Server, owner: &str) -> usize {
    let api = server.api_addr().expect("api");
    let path = format!("{ZONE_PATH}/records/{owner}/A");
    let response = http(api, "GET", &path, &[], None);
    match response {
        Some(response) if response.status == 200 => {
            response.json()["records"].as_array().map_or(0, Vec::len)
        }
        _ => 0,
    }
}

fn journal_path(data: &Path) -> PathBuf {
    let mut name = data.as_os_str().to_owned();
    name.push(".journal");
    PathBuf::from(name)
}

#[test]
fn crash_after_intent_replays_once() {
    let dir = tempfile::tempdir().expect("dir");
    let data = dir.path().join("crash-intent.v2");
    let config = write_config(dir.path());
    let api: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().expect("api");
    let mut child = spawn("base", &config, &data, api, None);
    assert!(wait_ready(api, &mut child), "server did not start");
    create_zone(api);
    let _ = child.kill();
    child.assert_dead();
    // Следующая мутация обрывает процесс сразу после записи intent.
    let mut child = spawn(
        "intent-crash",
        &config,
        &data,
        api,
        Some(("PULSED_JOURNAL_CRASH", "after_intent")),
    );
    assert!(wait_ready(api, &mut child), "server did not restart");
    let body = r#"{"ttl":60,"records":["192.0.2.77"]}"#.to_owned();
    let path = format!("{ZONE_PATH}/records/crash.after-intent.{ZONE}/A");
    let _ = http(api, "PUT", &path, &[], Some(body.as_bytes()));
    let status = child.wait_for_exit(Duration::from_secs(10));
    assert!(status.is_some(), "child did not crash");
    child.assert_dead();

    let mut server = open_server(&data);
    assert_eq!(a_records(&server, &format!("crash.after-intent.{ZONE}")), 1);
    let report = http(
        server.api_addr().expect("api"),
        "GET",
        "/metrics",
        &[],
        None,
    )
    .expect("metrics")
    .body;
    let metrics = String::from_utf8_lossy(&report);
    assert!(
        metrics
            .lines()
            .any(|line| line.starts_with("journal_replays_total ") && !line.ends_with(" 0")),
        "replay counter not incremented: {metrics}"
    );
    // Повторное открытие не применяет intent второй раз.
    let serial = zone_serial(&server);
    server.shutdown().expect("shutdown");
    drop(server);
    let mut again = open_server(&data);
    assert_eq!(zone_serial(&again), serial);
    again.shutdown().expect("shutdown");
}

#[test]
fn crash_after_apply_does_not_double_apply() {
    let dir = tempfile::tempdir().expect("dir");
    let data = dir.path().join("crash-apply.v2");
    let config = write_config(dir.path());
    let api: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().expect("api");
    let mut child = spawn("base", &config, &data, api, None);
    assert!(wait_ready(api, &mut child), "server did not start");
    create_zone(api);
    let _ = child.kill();
    child.assert_dead();

    let baseline = {
        let mut server = open_server(&data);
        let serial = zone_serial(&server);
        server.shutdown().expect("shutdown");
        serial
    };

    // Новый процесс: PUT A коммитится в zonefile, затем процесс убивается до
    // записи committed.
    let mut child = spawn(
        "apply-crash",
        &config,
        &data,
        api,
        Some(("PULSED_JOURNAL_CRASH", "after_apply")),
    );
    assert!(wait_ready(api, &mut child), "server did not restart");
    let body = r#"{"ttl":60,"records":["192.0.2.88"]}"#.to_owned();
    let path = format!("{ZONE_PATH}/records/crash.after-apply.{ZONE}/A");
    let _ = http(api, "PUT", &path, &[], Some(body.as_bytes()));
    let status = child.wait_for_exit(Duration::from_secs(10));
    assert!(status.is_some(), "child did not crash");
    child.assert_dead();

    let mut server = open_server(&data);
    assert_eq!(a_records(&server, &format!("crash.after-apply.{ZONE}")), 1);
    assert_eq!(
        zone_serial(&server),
        baseline.saturating_add(1),
        "recovery re-applied an already committed mutation"
    );
    server.shutdown().expect("shutdown");
}

#[test]
fn corrupt_tail_is_truncated_without_losing_committed_ops() {
    let dir = tempfile::tempdir().expect("dir");
    let data = dir.path().join("crash-tail.v2");
    let config = write_config(dir.path());
    let api: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().expect("api");
    let mut child = spawn("base", &config, &data, api, None);
    assert!(wait_ready(api, &mut child), "server did not start");
    create_zone(api);
    let _ = child.kill();
    child.assert_dead();

    let journal = journal_path(&data);
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&journal)
        .expect("open journal");
    file.write_all(&[0xFF; 13]).expect("corrupt tail");
    drop(file);
    let before = std::fs::metadata(&journal).expect("stat").len();

    let mut server = open_server(&data);
    assert_eq!(
        zone_serial(&server),
        2,
        "committed zone lost after tail truncation"
    );
    server.shutdown().expect("shutdown");
    let after = std::fs::metadata(&journal).expect("stat").len();
    assert!(after < before, "corrupt tail was not truncated");
}

#[test]
fn commit_fault_keeps_intent_and_retry_succeeds() {
    let dir = tempfile::tempdir().expect("dir");
    let data = dir.path().join("crash-commit.v2");
    let config = write_config(dir.path());
    let api: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().expect("api");
    let mut child = spawn(
        "commit-fault",
        &config,
        &data,
        api,
        Some(("PULSED_JOURNAL_FAULT", "commit")),
    );
    assert!(wait_ready(api, &mut child), "server did not start");

    let headers = [
        ("If-None-Match", "*"),
        ("Idempotency-Key", "journal-commit-fault-0001"),
    ];
    let body = br#"{"kind":"primary","default_ttl":3600}"#;
    let first = http(api, "PUT", ZONE_PATH, &headers, Some(body)).expect("first");
    assert_eq!(first.status, 500, "commit fault must surface as 500");
    let retry = http(api, "PUT", ZONE_PATH, &headers, Some(body)).expect("retry");
    assert!(
        (200..300).contains(&retry.status),
        "retry after commit fault failed: {}",
        retry.status
    );
    assert_eq!(retry.json()["origin"], ZONE);
    let _ = child.kill();
    child.assert_dead();
}

#[test]
fn idempotent_replay_same_key_is_stable() {
    let dir = tempfile::tempdir().expect("dir");
    let data = dir.path().join("idempotent.v2");
    let config = write_config(dir.path());
    let api: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().expect("api");
    let mut child = spawn("base", &config, &data, api, None);
    assert!(wait_ready(api, &mut child), "server did not start");

    let headers = [
        ("If-None-Match", "*"),
        ("Idempotency-Key", "journal-idem-0001"),
    ];
    let body = br#"{"kind":"primary","default_ttl":3600}"#;
    let first = http(api, "PUT", ZONE_PATH, &headers, Some(body)).expect("first");
    assert_eq!(first.status, 201);
    let replay = http(api, "PUT", ZONE_PATH, &headers, Some(body)).expect("replay");
    assert_eq!(replay.status, 201);
    assert_eq!(replay.header("idempotent-replay"), Some("true"));
    assert_eq!(replay.json()["origin"], ZONE);
    let metrics = String::from_utf8_lossy(
        &http(api, "GET", "/metrics", &[], None)
            .expect("metrics")
            .body,
    )
    .into_owned();
    for name in [
        "journal_intents_total",
        "journal_replays_total",
        "journal_compactions_total",
        "journal_errors_total",
    ] {
        assert!(metrics.contains(name), "missing metric {name}: {metrics}");
    }
    let _ = child.kill();
    child.assert_dead();
}

#[test]
fn crash_after_committed_reopens_cleanly() {
    let dir = tempfile::tempdir().expect("dir");
    let data = dir.path().join("crash-committed.v2");
    let config = write_config(dir.path());
    let api: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().expect("api");
    let mut child = spawn("base", &config, &data, api, None);
    assert!(wait_ready(api, &mut child), "server did not start");
    create_zone(api);
    let _ = child.kill();
    child.assert_dead();

    let mut child = spawn(
        "committed-crash",
        &config,
        &data,
        api,
        Some(("PULSED_JOURNAL_CRASH", "after_committed")),
    );
    assert!(wait_ready(api, &mut child), "server did not restart");
    let body = r#"{"ttl":60,"records":["192.0.2.99"]}"#.to_owned();
    let path = format!("{ZONE_PATH}/records/crash.after-committed.{ZONE}/A");
    let _ = http(api, "PUT", &path, &[], Some(body.as_bytes()));
    let status = child.wait_for_exit(Duration::from_secs(10));
    assert!(status.is_some(), "child did not crash");
    child.assert_dead();

    let mut server = open_server(&data);
    assert_eq!(
        a_records(&server, &format!("crash.after-committed.{ZONE}")),
        1
    );
    let metrics = String::from_utf8_lossy(
        &http(
            server.api_addr().expect("api"),
            "GET",
            "/metrics",
            &[],
            None,
        )
        .expect("metrics")
        .body,
    )
    .into_owned();
    assert!(
        metrics
            .lines()
            .any(|line| line.starts_with("journal_replays_total 0")),
        "committed intent was replayed: {metrics}"
    );
    server.shutdown().expect("shutdown");
}

#[test]
fn idempotent_retry_after_crash_returns_same_result() {
    let dir = tempfile::tempdir().expect("dir");
    let data = dir.path().join("crash-retry.v2");
    let config = write_config(dir.path());
    let api: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().expect("api");
    let mut child = spawn("base", &config, &data, api, None);
    assert!(wait_ready(api, &mut child), "server did not start");
    create_zone(api);
    let _ = child.kill();
    child.assert_dead();

    let mut child = spawn(
        "retry-crash",
        &config,
        &data,
        api,
        Some(("PULSED_JOURNAL_CRASH", "after_apply")),
    );
    assert!(wait_ready(api, &mut child), "server did not restart");
    let owner = format!("crash.retry.{ZONE}");
    let path = format!("{ZONE_PATH}/records/{owner}/A");
    let body = r#"{"ttl":60,"records":["192.0.2.123"]}"#.to_owned();
    let headers = [("Idempotency-Key", "journal-crash-retry-0001")];
    let _ = http(api, "PUT", &path, &headers, Some(body.as_bytes()));
    let status = child.wait_for_exit(Duration::from_secs(10));
    assert!(status.is_some(), "child did not crash");
    child.assert_dead();

    let mut server = open_server(&data);
    let retry = http(
        server.api_addr().expect("api"),
        "PUT",
        &path,
        &headers,
        Some(body.as_bytes()),
    )
    .expect("retry");
    assert_eq!(retry.status, 200, "idempotent retry after restart");
    assert_eq!(retry.header("idempotent-replay"), Some("true"));
    assert_eq!(retry.json()["records"].as_array().map_or(0, Vec::len), 1);
    assert_eq!(a_records(&server, &owner), 1);
    server.shutdown().expect("shutdown");
}
