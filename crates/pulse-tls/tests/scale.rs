//! Масштабирование `DoT`: idle-соединения, активная нагрузка, RSS и `p99`.
//!
//! Обычные тесты проверяют 1k idle + 100 активных. Замеры на 10k соединений и
//! матрица 100/1k/10k помечены `#[ignore]`, потому что создают десятки тысяч
//! TLS-сессий и требуют release-сборки:
//!
//! ```text
//! cargo test -p pulse-tls --release --test scale -- --ignored --nocapture
//! ```

mod common;

use std::io::{BufRead, BufReader, Write as IoWrite};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use common::{TlsClient, dns_query, echo_handler, test_cert};
use pulse_tls::{DotConfig, DotServer, TlsConfig};

fn dot_server(
    cert: &common::TestCert,
    max_connections: usize,
    idle_timeout: Duration,
) -> DotServer {
    let tls = TlsConfig::for_dot(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes())
        .expect("DoT TLS config");
    let mut config = DotConfig::new("127.0.0.1:0".parse().expect("addr"), tls);
    config.max_connections = max_connections;
    config.idle_timeout = idle_timeout;
    config.handshake_timeout = Duration::from_secs(10);
    DotServer::bind(config, echo_handler).expect("bind DoT server")
}

fn rss_bytes() -> u64 {
    std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|statm| {
            statm
                .split_whitespace()
                .nth(1)
                .and_then(|value| value.parse::<u64>().ok())
        })
        .map_or(0, |pages| pages.saturating_mul(4096))
}

fn rss_bytes_of(pid: u32) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/statm"))
        .ok()
        .and_then(|statm| {
            statm
                .split_whitespace()
                .nth(1)
                .and_then(|value| value.parse::<u64>().ok())
        })
        .map_or(0, |pages| pages.saturating_mul(4096))
}

fn cpu_ticks() -> u64 {
    std::fs::read_to_string("/proc/self/stat")
        .ok()
        .and_then(|stat| {
            let fields: Vec<&str> = stat.split_whitespace().collect();
            let user = fields.get(13)?.parse::<u64>().ok()?;
            let system = fields.get(14)?.parse::<u64>().ok()?;
            Some(user.saturating_add(system))
        })
        .unwrap_or(0)
}

#[test]
fn thousand_idle_and_hundred_active() {
    let cert = test_cert();
    let mut server = dot_server(&cert, 4096, Duration::from_secs(60));
    let addr = server.local_addr();

    let before = rss_bytes();
    let mut idle = Vec::with_capacity(1000);
    for _ in 0..1000 {
        idle.push(
            TlsClient::connect(addr, &cert.cert_der, Some(b"dot")).expect("idle TLS connection"),
        );
    }
    let after = rss_bytes();
    let per_connection = after.saturating_sub(before) / 1000;
    println!(
        "1k idle DoT (client+server in one process): RSS {} -> {} MiB, ~{} KiB/connection",
        before / (1024 * 1024),
        after / (1024 * 1024),
        per_connection / 1024
    );
    assert!(server.stats().active_connections >= 1000);
    // Здесь измеряются обе стороны TLS: клиентские сессии тоже живут в этом
    // процессе. Серверный RSS без клиентов проверяет
    // `ten_thousand_idle_server_rss` (цель <= 16 KiB/conn).
    assert!(
        per_connection <= 32 * 1024,
        "combined client+server connection uses {} KiB",
        per_connection / 1024
    );

    let cert_der = Arc::new(cert.cert_der.clone());
    let mut workers = Vec::with_capacity(100);
    for id in 0..100_u16 {
        let cert_der = Arc::clone(&cert_der);
        workers.push(thread::spawn(move || {
            let mut client =
                TlsClient::connect(addr, &cert_der, Some(b"dot")).expect("active TLS connection");
            let query = dns_query(1000 + id);
            client.send_dot(&query).expect("send");
            assert_eq!(client.read_dot().expect("read"), query);
        }));
    }
    for worker in workers {
        worker.join().expect("worker");
    }
    assert_eq!(server.stats().queries, 100);
    assert!(server.stats().active_connections >= 1000);

    server.shutdown().expect("shutdown");
    drop(idle);
    assert_eq!(server.stats().active_connections, 0);
}

#[test]
#[ignore = "10k TLS-сессий; запускать в release с --ignored --nocapture"]
fn ten_thousand_idle_connections_memory() {
    let cert = test_cert();
    let mut server = dot_server(&cert, 20_000, Duration::from_secs(120));
    let addr = server.local_addr();

    let before = rss_bytes();
    let mut idle = Vec::with_capacity(10_000);
    for _ in 0..10_000 {
        idle.push(
            TlsClient::connect(addr, &cert.cert_der, Some(b"dot")).expect("idle TLS connection"),
        );
    }
    thread::sleep(Duration::from_millis(200));
    let after = rss_bytes();
    let per_connection = after.saturating_sub(before) / 10_000;
    println!(
        "10k idle DoT: RSS {} -> {} MiB, ~{} KiB/connection, active={}",
        before / (1024 * 1024),
        after / (1024 * 1024),
        per_connection / 1024,
        server.stats().active_connections
    );
    assert_eq!(server.stats().active_connections, 10_000);
    server.shutdown().expect("shutdown");
    drop(idle);
    assert_eq!(server.stats().active_connections, 0);
}

#[test]
#[ignore = "нагрузочная матрица 100/1k/10k; запускать в release"]
fn connection_scale_qps_and_p99() {
    for connections in [100_usize, 1000, 10_000] {
        let cert = test_cert();
        let mut server = dot_server(&cert, connections + 1024, Duration::from_secs(120));
        let addr = server.local_addr();
        let before = rss_bytes();
        let mut idle = Vec::with_capacity(connections);
        for _ in 0..connections {
            idle.push(
                TlsClient::connect(addr, &cert.cert_der, Some(b"dot"))
                    .expect("idle TLS connection"),
            );
        }
        let after = rss_bytes();
        let per_connection = after.saturating_sub(before) / u64::try_from(connections).unwrap_or(1);

        let workers = 64_usize;
        let requests = 100_usize;
        let cert_der = Arc::new(cert.cert_der.clone());
        let cpu_before = cpu_ticks();
        let started = Instant::now();
        let mut handles = Vec::with_capacity(workers);
        for worker in 0..workers {
            let cert_der = Arc::clone(&cert_der);
            handles.push(thread::spawn(move || {
                let mut client =
                    TlsClient::connect(addr, &cert_der, Some(b"dot")).expect("load TLS connection");
                let mut latencies = Vec::with_capacity(requests);
                for request in 0..requests {
                    let query = dns_query(u16::try_from(worker * requests + request).unwrap_or(0));
                    let start = Instant::now();
                    client.send_dot(&query).expect("send");
                    let response = client.read_dot().expect("read");
                    latencies.push(start.elapsed());
                    assert_eq!(response, query);
                }
                latencies
            }));
        }
        let mut latencies = Vec::with_capacity(workers * requests);
        for handle in handles {
            latencies.extend(handle.join().expect("load worker"));
        }
        let elapsed = started.elapsed();
        let cpu_after = cpu_ticks();
        latencies.sort_unstable();
        let p50 = latencies
            .get(latencies.len() / 2)
            .copied()
            .unwrap_or_default();
        let p99_index = latencies.len().saturating_mul(99) / 100;
        let p99 = latencies
            .get(p99_index.min(latencies.len().saturating_sub(1)))
            .copied()
            .unwrap_or_default();
        let total = u32::try_from(workers * requests).unwrap_or(u32::MAX);
        let qps = f64::from(total) / elapsed.as_secs_f64();
        let cpu_percent =
            f64::from(u32::try_from(cpu_after.saturating_sub(cpu_before)).unwrap_or(u32::MAX))
                / 100.0
                / elapsed.as_secs_f64()
                * 100.0;
        println!(
            "{connections:>5} idle + {workers} active: {qps:.0} qps, p50 {:.2} ms, p99 {:.2} ms, RSS {} MiB (~{} KiB/conn), CPU {:.0}%",
            p50.as_secs_f64() * 1000.0,
            p99.as_secs_f64() * 1000.0,
            after / (1024 * 1024),
            per_connection / 1024,
            cpu_percent
        );
        server.shutdown().expect("shutdown");
        drop(idle);
    }
}

#[test]
#[ignore = "10k raw TCP idle; запускать в release с --ignored --nocapture"]
fn ten_thousand_raw_idle_event_loop_memory() {
    use std::net::TcpStream;

    let cert = test_cert();
    let mut server = dot_server(&cert, 20_000, Duration::from_secs(120));
    let addr = server.local_addr();
    let before = rss_bytes();
    let mut idle = Vec::with_capacity(10_000);
    for _ in 0..10_000 {
        idle.push(TcpStream::connect(addr).expect("raw TCP connection"));
    }
    thread::sleep(Duration::from_millis(200));
    let after = rss_bytes();
    let per_connection = after.saturating_sub(before) / 10_000;
    println!(
        "10k raw idle TCP: RSS {} -> {} MiB, ~{} KiB/connection (server handshake state only)",
        before / (1024 * 1024),
        after / (1024 * 1024),
        per_connection / 1024
    );
    assert!(server.stats().active_connections >= 9_900);
    server.shutdown().expect("shutdown");
    drop(idle);
}

/// Дочерний процесс для замера RSS сервера без клиентских TLS-сессий.
///
/// В обычном прогоне ничего не делает: `PULSE_SCALE_CHILD_DIR` не задан.
#[test]
fn child_dot_server_memory() {
    let Some(directory) = std::env::var_os("PULSE_SCALE_CHILD_DIR") else {
        return;
    };
    let directory = std::path::PathBuf::from(directory);
    let cert = test_cert();
    std::fs::write(directory.join("cert.der"), &cert.cert_der).expect("write cert der");
    std::fs::write(directory.join("cert.pem"), cert.cert_pem.as_bytes()).expect("write cert");
    std::fs::write(directory.join("key.pem"), cert.key_pem.as_bytes()).expect("write key");
    let tls = TlsConfig::for_dot(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes())
        .expect("DoT TLS config");
    let mut config = DotConfig::new("127.0.0.1:0".parse().expect("addr"), tls);
    config.max_connections = 20_000;
    config.idle_timeout = Duration::from_secs(120);
    let mut server = DotServer::bind(config, echo_handler).expect("bind child server");
    println!("ADDR {}", server.local_addr());
    std::io::stdout().flush().expect("flush addr");

    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .expect("wait for shutdown");
    println!("RSS {}", rss_bytes());
    std::io::stdout().flush().expect("flush rss");
    server.shutdown().expect("child shutdown");
}

#[test]
#[ignore = "10k TLS-сессий в дочернем процессе; запускать в release"]
fn ten_thousand_idle_server_rss() {
    let directory = std::env::temp_dir().join(format!("pulse-scale-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("temp dir");
    let executable = std::env::current_exe().expect("current test binary");
    let mut child = Command::new(executable)
        .args(["--exact", "child_dot_server_memory", "--nocapture"])
        .env("PULSE_SCALE_CHILD_DIR", &directory)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn child server");

    let stdout = child.stdout.take().expect("child stdout");
    let mut reader = BufReader::new(stdout);
    let mut address = None;
    let mut line = String::new();
    while reader.read_line(&mut line).expect("read child line") > 0 {
        if let Some(value) = line.strip_prefix("ADDR ") {
            address = value.trim().parse().ok();
            break;
        }
        line.clear();
    }
    let address = address.expect("child server address");
    let cert_der = std::fs::read(directory.join("cert.der")).expect("read child cert");
    let before = rss_bytes_of(child.id());

    let mut idle = Vec::with_capacity(10_000);
    for _ in 0..10_000 {
        idle.push(TlsClient::connect(address, &cert_der, Some(b"dot")).expect("idle client"));
    }
    thread::sleep(Duration::from_millis(300));
    let after = rss_bytes_of(child.id());
    let per_connection = after.saturating_sub(before) / 10_000;
    println!(
        "10k idle DoT server process: RSS {} -> {} MiB, ~{} KiB/connection",
        before / (1024 * 1024),
        after / (1024 * 1024),
        per_connection / 1024
    );
    assert!(
        per_connection <= 16 * 1024,
        "server uses {} KiB per idle connection, target <= 16 KiB",
        per_connection / 1024
    );

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"\n");
    }
    drop(idle);
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(directory);
}
