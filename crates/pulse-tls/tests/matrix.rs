//! Изолированная матрица латентности TCP/DoT: `event-loop` против
//! `thread-per-connection`.
//!
//! Сервер запускается отдельным процессом (опционально на CPU 0-3), клиент —
//! в тестовом процессе, поэтому цифры не смешивают клиентскую и серверную
//! очереди. Замеры помечены `#[ignore]`: это не часть обычного прогона.
//!
//! ```text
//! cargo test -p pulse-tls --release --test matrix -- \
//!     --ignored --nocapture --test-threads=1 dot_matrix_isolated
//! ```
//!
//! Переменные окружения:
//!
//! * `PULSE_MATRIX_CONNECTIONS` — список через запятую (по умолчанию `100,1000`);
//! * `PULSE_MATRIX_WINDOWS` — окна in-flight (по умолчанию `1,64`);
//! * `PULSE_MATRIX_SECONDS` — длительность одного замера (по умолчанию `3`);
//! * `PULSE_MATRIX_THREADS` — клиентских потоков (по умолчанию `8`);
//! * `PULSE_MATRIX_TRANSPORTS` — `dot,tcp` (по умолчанию оба);
//! * `PULSE_MATRIX_SERVER_CPUS` — `taskset`-список для серверного процесса.

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::doc_markdown,
    clippy::too_many_lines
)]

mod common;

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use common::{TlsClient, dns_query, echo_handler, test_cert};
use pulse_tls::net::{ConnectionHandler, ServerHooks, SocketOptions, TcpServer};
use pulse_tls::{DotConfig, DotServer, TlsConfig};
use rustls::{ServerConnection, StreamOwned};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Клиент с length-prefixed DNS-обменом (TLS или plain TCP).
trait ProbeClient: Send + Sized {
    fn connect(address: SocketAddr, cert_der: &[u8]) -> io::Result<Self>;
    fn send(&mut self, message: &[u8]) -> io::Result<()>;
    fn receive(&mut self) -> io::Result<Vec<u8>>;
}

impl ProbeClient for TlsClient {
    fn connect(address: SocketAddr, cert_der: &[u8]) -> io::Result<Self> {
        TlsClient::connect(address, cert_der, Some(b"dot"))
    }

    fn send(&mut self, message: &[u8]) -> io::Result<()> {
        self.send_dot(message)
    }

    fn receive(&mut self) -> io::Result<Vec<u8>> {
        self.read_dot()
    }
}

struct PlainClient {
    stream: TcpStream,
}

impl ProbeClient for PlainClient {
    fn connect(address: SocketAddr, _cert_der: &[u8]) -> io::Result<Self> {
        let stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        Ok(Self { stream })
    }

    fn send(&mut self, message: &[u8]) -> io::Result<()> {
        let length = u16::try_from(message.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "message too large"))?;
        self.stream.write_all(&length.to_be_bytes())?;
        self.stream.write_all(message)
    }

    fn receive(&mut self) -> io::Result<Vec<u8>> {
        let mut prefix = [0_u8; 2];
        self.stream.read_exact(&mut prefix)?;
        let length = usize::from(u16::from_be_bytes(prefix));
        let mut message = vec![0_u8; length];
        self.stream.read_exact(&mut message)?;
        Ok(message)
    }
}

struct ServerProcess {
    child: Child,
    address: SocketAddr,
}

impl Drop for ServerProcess {
    fn drop(&mut self) {
        if let Some(mut stdin) = self.child.stdin.take() {
            let _ = stdin.write_all(b"\n");
        }
        let _ = self.child.wait();
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_seconds() -> Duration {
    let seconds = std::env::var("PULSE_MATRIX_SECONDS")
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .unwrap_or(3.0);
    Duration::from_secs_f64(seconds.max(0.2))
}

fn spawn_server(kind: &str, cert_dir: &Path) -> ServerProcess {
    let executable = std::env::current_exe().expect("current test executable");
    let cpus = std::env::var("PULSE_MATRIX_SERVER_CPUS").unwrap_or_default();
    let mut command = if cpus.is_empty() {
        Command::new(executable)
    } else {
        let mut command = Command::new("taskset");
        command.arg("-c").arg(cpus).arg(executable);
        command
    };
    let stderr =
        std::fs::File::create(cert_dir.join(format!("server-{kind}.log"))).expect("server log");
    let address_file = cert_dir.join(format!("address-{kind}"));
    let _ = std::fs::remove_file(&address_file);
    let mut child = command
        .args([
            "--ignored",
            "--exact",
            "matrix_server_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("PULSE_MATRIX_SERVER", kind)
        .env("PULSE_MATRIX_CERT_DIR", cert_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr))
        .spawn()
        .expect("spawn matrix server");
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(text) = std::fs::read_to_string(&address_file)
            && let Ok(address) = text.trim().parse()
        {
            return ServerProcess { child, address };
        }
        thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("matrix server did not publish its address");
}

fn rss_bytes(pid: u32) -> u64 {
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

fn cpu_ticks(pid: u32) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| {
            let fields: Vec<&str> = stat.split_whitespace().collect();
            let user = fields.get(13)?.parse::<u64>().ok()?;
            let system = fields.get(14)?.parse::<u64>().ok()?;
            Some(user.saturating_add(system))
        })
        .unwrap_or(0)
}

#[derive(Default)]
struct Latencies {
    samples: Vec<u64>,
    sent: u64,
    received: u64,
    errors: u64,
}

impl Latencies {
    fn record(&mut self, ns: u64) {
        self.samples.push(ns);
    }

    fn percentile(&mut self, percentile: f64) -> u64 {
        if self.samples.is_empty() {
            return 0;
        }
        self.samples.sort_unstable();
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss
        )]
        let index = ((self.samples.len().saturating_sub(1)) as f64 * percentile).round() as usize;
        self.samples.get(index).copied().unwrap_or(0)
    }
}

fn run_clients<C: ProbeClient + 'static>(
    address: SocketAddr,
    cert_der: &[u8],
    connections: usize,
    window: usize,
    duration: Duration,
) -> Latencies {
    let threads = env_usize("PULSE_MATRIX_THREADS", 8)
        .max(1)
        .min(connections.max(1));
    let window = window.clamp(1, 256);
    let cert = Arc::new(cert_der.to_vec());
    let deadline = Instant::now() + duration;
    let mut merged = Latencies::default();
    let results = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(threads);
        for thread_id in 0..threads {
            let cert = Arc::clone(&cert);
            handles.push(scope.spawn(move || {
                let span = connections.div_ceil(threads);
                let first = thread_id * span;
                let last = (first + span).min(connections);
                let mut clients = Vec::with_capacity(last.saturating_sub(first));
                for _ in first..last {
                    if let Ok(client) = C::connect(address, &cert) {
                        clients.push(client);
                    }
                }
                let mut stats = Latencies::default();
                let mut next_id = u16::try_from(thread_id)
                    .unwrap_or(u16::MAX)
                    .wrapping_mul(4099);
                let mut sent_at = Vec::with_capacity(window);
                while Instant::now() < deadline {
                    for client in &mut clients {
                        sent_at.clear();
                        for _ in 0..window {
                            if Instant::now() >= deadline {
                                break;
                            }
                            let query = dns_query(next_id);
                            next_id = next_id.wrapping_add(1);
                            let start = Instant::now();
                            if client.send(&query).is_err() {
                                stats.errors += 1;
                                break;
                            }
                            stats.sent += 1;
                            sent_at.push((start, query));
                        }
                        for (start, query) in sent_at.drain(..) {
                            match client.receive() {
                                Ok(response) if response == query => {
                                    stats.received += 1;
                                    stats.record(
                                        u64::try_from(start.elapsed().as_nanos())
                                            .unwrap_or(u64::MAX),
                                    );
                                }
                                Ok(_) | Err(_) => stats.errors += 1,
                            }
                        }
                    }
                }
                stats
            }));
        }
        let mut results = Vec::with_capacity(handles.len());
        for handle in handles {
            if let Ok(stats) = handle.join() {
                results.push(stats);
            }
        }
        results
    });
    for mut stats in results {
        merged.sent += stats.sent;
        merged.received += stats.received;
        merged.errors += stats.errors;
        merged.samples.append(&mut stats.samples);
    }
    merged
}

fn print_row(
    transport: &str,
    connections: usize,
    window: usize,
    stats: &mut Latencies,
    elapsed: Duration,
    rss: u64,
    cpu_percent: f64,
) {
    let p50 = stats.percentile(0.50);
    let p99 = stats.percentile(0.99);
    let p999 = stats.percentile(0.999);
    let qps = stats.received as f64 / elapsed.as_secs_f64().max(f64::EPSILON);
    println!(
        "{transport:<22} conn={connections:<5} win={window:<3} qps={qps:>8.0} p50={:>7.1}us p99={:>8.1}us p999={:>9.1}us RSS={:>5}MiB CPU={cpu_percent:>5.0}% sent={} recv={} err={}",
        p50 as f64 / 1000.0,
        p99 as f64 / 1000.0,
        p999 as f64 / 1000.0,
        rss / (1024 * 1024),
        stats.sent,
        stats.received,
        stats.errors,
    );
}

#[test]
#[ignore = "изолированная матрица; запускать в release с --ignored --nocapture"]
fn dot_matrix_isolated() {
    let cert = test_cert();
    let cert_dir = std::env::temp_dir().join(format!("pulse-matrix-{}", std::process::id()));
    std::fs::create_dir_all(&cert_dir).expect("cert dir");
    std::fs::write(cert_dir.join("cert.pem"), cert.cert_pem.as_bytes()).expect("cert pem");
    std::fs::write(cert_dir.join("key.pem"), cert.key_pem.as_bytes()).expect("key pem");

    let connections: Vec<usize> = std::env::var("PULSE_MATRIX_CONNECTIONS").map_or_else(
        |_| vec![100, 1000],
        |value| {
            value
                .split(',')
                .filter_map(|part| part.trim().parse().ok())
                .collect()
        },
    );
    let windows: Vec<usize> = std::env::var("PULSE_MATRIX_WINDOWS").map_or_else(
        |_| vec![1, 64],
        |value| {
            value
                .split(',')
                .filter_map(|part| part.trim().parse().ok())
                .collect()
        },
    );

    let transports: Vec<String> = std::env::var("PULSE_MATRIX_TRANSPORTS").map_or_else(
        |_| vec!["dot".to_owned(), "tcp".to_owned()],
        |value| {
            value
                .split(',')
                .map(|part| part.trim().to_owned())
                .filter(|part| !part.is_empty())
                .collect()
        },
    );

    for transport in &transports {
        for implementation in ["event-loop", "thread-per-conn"] {
            let kind = format!("{transport}-{implementation}");
            for &conn in &connections {
                for &window in &windows {
                    let server = spawn_server(&kind, &cert_dir);
                    let pid = server.child.id();
                    let before_rss = rss_bytes(pid);
                    let before_cpu = cpu_ticks(pid);
                    let started = Instant::now();
                    let duration = env_seconds();
                    let mut stats = if transport == "dot" {
                        run_clients::<TlsClient>(
                            server.address,
                            &cert.cert_der,
                            conn,
                            window,
                            duration,
                        )
                    } else {
                        run_clients::<PlainClient>(
                            server.address,
                            &cert.cert_der,
                            conn,
                            window,
                            duration,
                        )
                    };
                    let elapsed = started.elapsed();
                    let after_rss = rss_bytes(pid);
                    let cpu = cpu_ticks(pid).saturating_sub(before_cpu) as f64 / 100.0;
                    let cpu_percent = cpu / elapsed.as_secs_f64() * 100.0;
                    print_row(
                        &kind,
                        conn,
                        window,
                        &mut stats,
                        elapsed,
                        after_rss.saturating_sub(before_rss),
                        cpu_percent,
                    );
                    drop(server);
                }
            }
        }
    }
    let _ = std::fs::remove_dir_all(cert_dir);
}

fn publish_address(cert_dir: &Path, kind: &str, address: SocketAddr) {
    std::fs::write(
        cert_dir.join(format!("address-{kind}")),
        address.to_string(),
    )
    .expect("publish addr");
}

fn wait_for_stdin() {
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
}

fn tcp_echo_handler() -> ConnectionHandler {
    Arc::new(|mut stream, _peer, mut shutdown| {
        Box::pin(async move {
            let mut prefix = [0_u8; 2];
            let mut body = Vec::new();
            loop {
                let read = tokio::select! {
                    biased;
                    _ = shutdown.changed() => break,
                    read = stream.read_exact(&mut prefix) => read,
                };
                if read.is_err() {
                    break;
                }
                let length = usize::from(u16::from_be_bytes(prefix));
                body.clear();
                body.resize(length, 0);
                if stream.read_exact(&mut body).await.is_err() {
                    break;
                }
                if stream.write_all(&prefix).await.is_err()
                    || stream.write_all(&body).await.is_err()
                {
                    break;
                }
            }
        })
    })
}

/// Дочерний процесс: поднимает TCP/DoT-эхо и ждёт `\n` на stdin.
#[test]
#[ignore = "служебный режим dot_matrix_isolated"]
fn matrix_server_child() {
    let Ok(kind) = std::env::var("PULSE_MATRIX_SERVER") else {
        return;
    };
    let cert_dir = PathBuf::from(std::env::var("PULSE_MATRIX_CERT_DIR").expect("cert dir env"));
    if let Some(tcp_kind) = kind.strip_prefix("tcp-") {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind tcp");
        let address = listener.local_addr().expect("tcp addr");
        publish_address(&cert_dir, &kind, address);
        if tcp_kind == "thread-per-conn" {
            let handle = thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { continue };
                    thread::spawn(move || {
                        let _ = stream.set_nodelay(true);
                        loop {
                            let mut prefix = [0_u8; 2];
                            if stream.read_exact(&mut prefix).is_err() {
                                return;
                            }
                            let length = usize::from(u16::from_be_bytes(prefix));
                            let mut body = vec![0_u8; length];
                            if stream.read_exact(&mut body).is_err() {
                                return;
                            }
                            if stream.write_all(&prefix).is_err()
                                || stream.write_all(&body).is_err()
                            {
                                return;
                            }
                        }
                    });
                }
            });
            wait_for_stdin();
            drop(handle);
        } else {
            let mut server = TcpServer::start_with_options(
                "matrix-tcp",
                listener,
                4096,
                Duration::from_secs(120),
                ServerHooks::default(),
                SocketOptions::default(),
                tcp_echo_handler(),
            )
            .expect("start tcp server");
            wait_for_stdin();
            let _ = server.shutdown();
        }
        return;
    }

    let cert_pem = std::fs::read(cert_dir.join("cert.pem")).expect("read cert");
    let key_pem = std::fs::read(cert_dir.join("key.pem")).expect("read key");
    let tls = TlsConfig::for_dot(&cert_pem, &key_pem).expect("DoT TLS config");
    if kind == "dot-thread-per-conn" {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind baseline");
        let address = listener.local_addr().expect("baseline addr");
        publish_address(&cert_dir, &kind, address);
        let config = tls.server_config();
        let handle = thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let config = Arc::clone(&config);
                thread::spawn(move || {
                    let _ = stream.set_nodelay(true);
                    let Ok(connection) = ServerConnection::new(config) else {
                        return;
                    };
                    let mut tls = StreamOwned::new(connection, stream);
                    loop {
                        let mut prefix = [0_u8; 2];
                        if tls.read_exact(&mut prefix).is_err() {
                            return;
                        }
                        let length = usize::from(u16::from_be_bytes(prefix));
                        let mut body = vec![0_u8; length];
                        if tls.read_exact(&mut body).is_err() {
                            return;
                        }
                        if tls.write_all(&prefix).is_err()
                            || tls.write_all(&body).is_err()
                            || tls.flush().is_err()
                        {
                            return;
                        }
                    }
                });
            }
        });
        wait_for_stdin();
        drop(handle);
        return;
    }

    let mut config = DotConfig::new("127.0.0.1:0".parse().expect("addr"), tls);
    config.max_connections = 4096;
    config.idle_timeout = Duration::from_secs(120);
    config.max_messages_per_connection = 1_000_000;
    let mut server = DotServer::bind(config, echo_handler).expect("bind DoT");
    publish_address(&cert_dir, &kind, server.local_addr());
    wait_for_stdin();
    let _ = server.shutdown();
}
