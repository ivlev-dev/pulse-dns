//! Crash/reopen: `kill -9` во время параллельных REST-коммитов (`Sync`).
//!
//! Каждый ack-нутый `PUT` подтверждён после двух `fdatasync`, поэтому после
//! перезапуска все подтверждённые записи обязаны читаться. Незавершённые
//! запросы могли не пройти — они не проверяются.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::time::Duration;

mod common;

use common::PulsedChild;

use pulse_dns::{
    DecodeLimits, EncodeOptions, Message, Name, Question, Rclass, Rcode, Rdata, Rtype,
};
use pulse_zonefile::parallel::{OpenConfigV2, ParallelStore};
use pulsed::config::{CommitMode, Config, Durability, TcpConfig};
use pulsed::server::Server;

const TOKEN: &str = "pd_live_crash_0123456789abcdefabcd";
const ZONE: &str = "crash.test.";
const ZONE_PATH: &str = "/api/v1/zones/crash.test.";

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("addr").port()
}

fn http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
    if_none_match: bool,
) -> Option<u16> {
    let mut stream = TcpStream::connect(addr).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Authorization: Bearer {TOKEN}\r\n"
    );
    if if_none_match {
        head.push_str("If-None-Match: *\r\n");
    }
    if body.is_some() {
        head.push_str("Content-Type: application/json\r\n");
    }
    if let Some(body) = body {
        let _ = write!(head, "Content-Length: {}\r\n", body.len());
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).ok()?;
    if let Some(body) = body {
        stream.write_all(body.as_bytes()).ok()?;
    }
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).ok()?;
    let head = std::str::from_utf8(&raw[..raw.windows(4).position(|w| w == b"\r\n\r\n")?]).ok()?;
    head.lines().next()?.split(' ').nth(1)?.parse::<u16>().ok()
}

fn wait_ready(addr: SocketAddr, child: &mut PulsedChild) -> bool {
    child.wait_ready(common::CHILD_READY_TIMEOUT, || {
        http(addr, "GET", "/api/v1/zones", None, false) == Some(200)
    })
}

fn spawn_server(
    label: &str,
    config: &Path,
    data: &Path,
    api: SocketAddr,
    mode: CommitMode,
) -> PulsedChild {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pulsed"));
    command
        .arg("--config")
        .arg(config)
        .arg("--data")
        .arg(data)
        .arg("--durability")
        .arg("sync")
        .arg("--commit-mode")
        .arg(mode.as_str())
        .arg("--api-listen")
        .arg(api.to_string())
        .arg("--api-token")
        .arg(TOKEN)
        .env_remove("PULSED_API_TOKEN")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    PulsedChild::spawn(format!("crash-reopen/{label}"), &mut command)
}

#[allow(clippy::needless_pass_by_value)]
fn writer(api: SocketAddr, worker: usize, stop: Arc<AtomicBool>, acked: Sender<String>) {
    let mut record = 0_usize;
    while !stop.load(Ordering::Acquire) {
        let owner = format!("r{worker}-{record}.{ZONE}");
        let octets = format!("192.0.2.{}", (worker * 97 + record) % 250 + 1);
        let body = format!(r#"{{"ttl":60,"records":["{octets}"]}}"#);
        let path = format!("{ZONE_PATH}/records/{owner}/A");
        let mut status = http(api, "PUT", &path, Some(&body), false);
        let mut attempts = 0_u32;
        while status == Some(429) && attempts < 100 {
            std::thread::sleep(Duration::from_millis(20));
            status = http(api, "PUT", &path, Some(&body), false);
            attempts = attempts.saturating_add(1);
        }
        if status == Some(201) {
            let _ = acked.send(owner);
        } else {
            break;
        }
        record = record.saturating_add(1);
    }
}

fn recv_from(socket: &UdpSocket, buffer: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
    loop {
        match socket.recv_from(buffer) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
}

fn dns_query(server: &Server, qname: &str, qtype: Rtype) -> Message {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("client socket");
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("read timeout");
    let query = Message::query(
        0x4c4c,
        Question::new(Name::parse(qname).expect("qname"), qtype, Rclass::IN),
    )
    .encode(&EncodeOptions::compressed())
    .expect("encode");
    socket
        .send_to(&query, server.udp_addr().expect("udp"))
        .expect("send");
    let mut buffer = [0_u8; 4096];
    let (len, _) = recv_from(&socket, &mut buffer).expect("recv");
    Message::decode(&buffer[..len], &DecodeLimits::default()).expect("decode")
}

#[test]
fn kill_during_parallel_rest_commits_keeps_acked_writes() {
    for (label, mode) in [
        ("per-zone", CommitMode::PerZone),
        ("group", CommitMode::Group),
    ] {
        crash_scenario(label, mode);
    }
}

#[allow(clippy::too_many_lines)]
fn crash_scenario(label: &str, mode: CommitMode) {
    let dir = tempfile::tempdir().expect("temp dir");
    let data = dir.path().join("crash.v2");
    let config_path = dir.path().join("pulsed.json");
    std::fs::write(
        &config_path,
        r#"{"listen_udp":"127.0.0.1:0","listen_tcp":null,"workers":1}"#,
    )
    .expect("config");
    let api_port = free_port();
    let api: SocketAddr = format!("127.0.0.1:{api_port}").parse().expect("api addr");
    let mut child = spawn_server(label, &config_path, &data, api, mode);
    assert!(wait_ready(api, &mut child), "{label}: server did not start");

    assert_eq!(
        http(
            api,
            "PUT",
            ZONE_PATH,
            Some(r#"{"kind":"primary","default_ttl":3600}"#),
            true
        ),
        Some(201)
    );
    assert_eq!(
        http(
            api,
            "PUT",
            &format!("{ZONE_PATH}/records/@/SOA"),
            Some(
                r#"{"ttl":3600,"records":["ns1.crash.test. hostmaster.crash.test. 1 3600 600 604800 300"]}"#
            ),
            false
        ),
        Some(201)
    );
    assert_eq!(
        http(
            api,
            "PUT",
            &format!("{ZONE_PATH}/records/@/NS"),
            Some(r#"{"ttl":3600,"records":["ns1.crash.test."]}"#),
            false
        ),
        Some(201)
    );

    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = channel::<String>();
    let writers: Vec<_> = (0..2)
        .map(|worker| {
            let stop = Arc::clone(&stop);
            let tx = tx.clone();
            std::thread::spawn(move || writer(api, worker, stop, tx))
        })
        .collect();
    drop(tx);
    std::thread::sleep(Duration::from_millis(500));

    // `SIGKILL` в момент активных коммитов.
    let status = child.kill();
    assert!(status.is_some(), "{label}: kill did not reap the child");
    child.assert_dead();
    stop.store(true, Ordering::Release);
    for handle in writers {
        handle.join().expect("writer thread");
    }
    let acked: Vec<String> = rx.try_iter().collect();
    assert!(
        acked.len() >= 2,
        "{label}: no acked writes before crash: {}",
        acked.len()
    );

    // Перезапуск в процессе теста: recovery + чтение ack-нутых записей.
    let config = Config {
        listen_udp: Some("127.0.0.1:0".parse().expect("udp")),
        listen_tcp: None,
        workers: 1,
        tcp: TcpConfig {
            idle_timeout_ms: 2000,
            ..TcpConfig::default()
        },
        zonefile: Some(data.clone()),
        durability: Durability::Sync,
        commit_mode: mode,
        map_size: 64 * 1024 * 1024,
        ..Config::default()
    };
    let mut server = Server::start(&config).expect("reopen after crash");
    let soa = dns_query(&server, ZONE, Rtype::SOA);
    assert_eq!(
        soa.rcode(),
        Rcode::NOERROR,
        "{label}: zone must survive crash"
    );
    for owner in &acked {
        let response = dns_query(&server, owner, Rtype::A);
        assert_eq!(
            response.rcode(),
            Rcode::NOERROR,
            "{label}: acked {owner} lost"
        );
        assert_eq!(response.answers().len(), 1, "acked {owner} has no answer");
        assert!(
            matches!(response.answers()[0].rdata(), Rdata::A(_)),
            "acked {owner} has wrong rdata"
        );
    }
    server.shutdown().expect("shutdown");
    drop(server);

    let store = ParallelStore::open(&data, OpenConfigV2::default()).expect("open store");
    assert!(
        store.fsck_lite().expect("fsck").ok,
        "crash left corrupt file"
    );
    assert!(
        store.fsck_graph().expect("graph").ok,
        "crash left bad graph"
    );
}
