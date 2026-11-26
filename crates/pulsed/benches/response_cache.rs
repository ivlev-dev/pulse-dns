//! UDP mix: qps/p50/p99 с кешем готовых ответов и без, hit rate и память.
//!
//! Запуск:
//! ```bash
//! cargo build --release -p pulsed
//! cargo bench -p pulsed --bench response_cache -- --seconds 5
//! ```

#![allow(clippy::cast_precision_loss)]

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use pulse_dns::{DecodeLimits, EncodeOptions, Message, Name, Question, Rclass, Rtype};
use pulsed::config::{Config, Durability, ResponseCacheSettings, Role, TcpConfig};

const TOKEN: &str = "pd_bench_cache_0123456789abcdefabcd";
const RECORDS: usize = 64;
const THREADS: usize = 8;
const ORIGIN: &str = "bench.test.";

struct Guard {
    child: Child,
}

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Run {
    queries: u64,
    seconds: f64,
    p50_us: f64,
    p99_us: f64,
    hits: u64,
    misses: u64,
    entries: u64,
    bytes: u64,
}

fn pulsed_bin() -> PathBuf {
    let exe = std::env::current_exe().expect("current exe");
    let profile = exe
        .parent()
        .and_then(Path::parent)
        .expect("profile directory");
    let bin = profile.join("pulsed");
    assert!(
        bin.exists(),
        "{} not found; run `cargo build --release -p pulsed` first",
        bin.display()
    );
    bin
}

fn free_udp_port() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("udp");
    socket.local_addr().expect("addr").port()
}

fn reserved_tcp_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("tcp");
    listener.local_addr().expect("addr")
}

fn master_zone() -> String {
    let mut text = format!(
        "$ORIGIN {ORIGIN}\n$TTL 60\n\
         @ IN SOA ns1.{ORIGIN} hostmaster.{ORIGIN} 1 3600 600 604800 300\n\
         @ IN NS ns1.{ORIGIN}\n\
         ns1 IN A 192.0.2.53\n\
         @ IN MX 10 mail.{ORIGIN}\n\
         mail IN A 192.0.2.54\n\
         sub IN NS ns1.sub.{ORIGIN}\n\
         ns1.sub IN A 192.0.2.55\n"
    );
    for index in 0..RECORDS {
        let _ = writeln!(text, "r{index} IN A 192.0.2.{}", index % 250 + 1);
        let _ = writeln!(
            text,
            "r{index} IN TXT \"record {index} payload for the response cache bench\""
        );
        let _ = writeln!(text, "r{index} IN AAAA 2001:db8::{index:x}");
    }
    text
}

fn prepare_data(bin: &Path, dir: &Path, map_size: u64) -> PathBuf {
    let data = dir.join("cache.v2");
    let master = dir.join("bench.zone");
    std::fs::write(&master, master_zone()).expect("write master");
    let output = Command::new(bin)
        .arg("import")
        .arg("--data")
        .arg(&data)
        .arg("--origin")
        .arg(ORIGIN)
        .arg("--durability")
        .arg("flush")
        .arg("--map-size")
        .arg(map_size.to_string())
        .arg(&master)
        .stdin(Stdio::null())
        .output()
        .expect("run pulsed import");
    assert!(
        output.status.success(),
        "import failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    data
}

fn config(
    data: &Path,
    udp: u16,
    tcp: SocketAddr,
    api: SocketAddr,
    cache: ResponseCacheSettings,
) -> Config {
    Config {
        role: Role::All,
        listen_udp: Some(SocketAddr::from(([127, 0, 0, 1], udp))),
        listen_tcp: Some(tcp),
        api_listen: Some(api),
        api_token: Some(TOKEN.to_owned()),
        api_workers: Some(16),
        api_rate_limit_per_sec: 100_000,
        workers: 0,
        dns_workers: Some(THREADS),
        zone_poll_ms: 100,
        tcp: TcpConfig {
            idle_timeout_ms: 2000,
            ..TcpConfig::default()
        },
        zonefile: Some(data.to_path_buf()),
        durability: Durability::Flush,
        map_size: 64 * 1024 * 1024,
        journal: false,
        response_cache: cache,
        ..Config::default()
    }
}

fn write_config(dir: &Path, name: &str, config: &Config) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, config.to_toml_string().expect("toml")).expect("write config");
    path
}

fn spawn(config: &Path) -> Guard {
    let child = Command::new(pulsed_bin())
        .arg("--config")
        .arg(config)
        .env_remove("PULSED_API_TOKEN")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn pulsed");
    Guard { child }
}

fn http(addr: SocketAddr, path: &str) -> Option<(u16, String)> {
    let mut stream = TcpStream::connect(addr).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    let head = format!(
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {TOKEN}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(head.as_bytes()).ok()?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).ok()?;
    let end = raw.windows(4).position(|window| window == b"\r\n\r\n")?;
    let head = std::str::from_utf8(raw.get(..end)?).ok()?;
    let status = head.lines().next()?.split(' ').nth(1)?.parse().ok()?;
    Some((
        status,
        String::from_utf8_lossy(raw.get(end + 4..)?).into_owned(),
    ))
}

fn metric(body: &str, name: &str) -> u64 {
    body.lines()
        .find_map(|line| line.strip_prefix(name)?.trim().parse().ok())
        .unwrap_or(0)
}

fn dns_roundtrip(port: u16, qname: &str, qtype: Rtype) -> Option<()> {
    let socket = UdpSocket::bind("127.0.0.1:0").ok()?;
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok()?;
    let query = Message::query(
        0x1234,
        Question::new(Name::parse(qname).ok()?, qtype, Rclass::IN),
    )
    .encode(&EncodeOptions::compressed())
    .ok()?;
    socket
        .send_to(&query, SocketAddr::from(([127, 0, 0, 1], port)))
        .ok()?;
    let mut buffer = [0_u8; 4096];
    let len = socket.recv(&mut buffer).ok()?;
    Message::decode(&buffer[..len], &DecodeLimits::default()).ok()?;
    Some(())
}

fn wait_ready(api: SocketAddr, udp: u16) -> bool {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        let api_ok = http(api, "/api/v1/zones").is_some_and(|(status, _)| status == 200);
        let dns_ok = dns_roundtrip(udp, &format!("r0.{ORIGIN}"), Rtype::A).is_some();
        if api_ok && dns_ok {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn workload() -> Vec<Vec<u8>> {
    let mut wires = Vec::new();
    for index in 0..16_usize {
        let owner = format!("r{index}.{ORIGIN}");
        for (qname, qtype) in [
            (owner.clone(), Rtype::A),
            (owner.clone(), Rtype::TXT),
            (owner.clone(), Rtype::AAAA),
            (owner.clone(), Rtype::MX),
            (format!("missing{index}.{ORIGIN}"), Rtype::A),
            (owner.clone(), Rtype::SRV),
            (format!("x.sub.{ORIGIN}"), Rtype::A),
        ] {
            let Ok(name) = Name::parse(&qname) else {
                continue;
            };
            let request = Message::query(0x4321, Question::new(name, qtype, Rclass::IN));
            if let Ok(wire) = request.encode(&EncodeOptions::compressed()) {
                wires.push(wire);
            }
        }
    }
    wires
}

fn percentiles(mut values: Vec<u64>) -> (f64, f64) {
    if values.is_empty() {
        return (0.0, 0.0);
    }
    values.sort_unstable();
    let index = |percent: usize| {
        let position = values.len().saturating_mul(percent) / 100;
        let position = position.min(values.len() - 1);
        values[position] as f64
    };
    (index(50), index(99))
}

fn run_load(port: u16, seconds: u64, api: SocketAddr) -> Run {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let wires = Arc::new(workload());
    let barrier = Arc::new(Barrier::new(THREADS));
    let started = Instant::now();
    let latencies = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..THREADS)
            .map(|thread| {
                let wires = Arc::clone(&wires);
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    let socket = UdpSocket::bind("127.0.0.1:0").expect("udp client");
                    socket
                        .set_read_timeout(Some(Duration::from_millis(250)))
                        .expect("timeout");
                    let mut buffer = [0_u8; 4096];
                    let mut latencies = Vec::new();
                    let mut cursor = thread;
                    barrier.wait();
                    while Instant::now() < deadline {
                        let Some(wire) = wires.get(cursor % wires.len()) else {
                            break;
                        };
                        cursor = cursor.wrapping_add(1);
                        let started = Instant::now();
                        if socket
                            .send_to(wire, SocketAddr::from(([127, 0, 0, 1], port)))
                            .is_err()
                        {
                            continue;
                        }
                        if socket.recv(&mut buffer).is_err() {
                            continue;
                        }
                        latencies
                            .push(u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX));
                    }
                    latencies
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|handle| handle.join().unwrap_or_default())
            .collect::<Vec<_>>()
    });
    let elapsed = started.elapsed().as_secs_f64();
    let (p50_us, p99_us) = percentiles(latencies.clone());
    let body = http(api, "/metrics")
        .map(|(_, body)| body)
        .unwrap_or_default();
    Run {
        queries: latencies.len() as u64,
        seconds: elapsed,
        p50_us,
        p99_us,
        hits: metric(&body, "pulsed_response_cache_hits_total"),
        misses: metric(&body, "pulsed_response_cache_misses_total"),
        entries: metric(&body, "pulsed_response_cache_entries"),
        bytes: metric(&body, "pulsed_response_cache_bytes"),
    }
}

fn main() {
    let mut seconds = 3_u64;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--seconds" {
            seconds = args
                .next()
                .and_then(|value| value.parse().ok())
                .unwrap_or(seconds);
        }
    }
    let dir = std::env::temp_dir().join(format!("pulsed-cache-bench-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("bench dir");
    let bin = pulsed_bin();
    let map_size = 64 * 1024 * 1024;
    let data = prepare_data(&bin, &dir, map_size);

    let mut runs = Vec::new();
    for enabled in [false, true] {
        let udp = free_udp_port();
        let tcp = reserved_tcp_addr();
        let api = reserved_tcp_addr();
        let cache = ResponseCacheSettings {
            enabled,
            max_entries: 1_000_000,
            max_bytes: 256 * 1024 * 1024,
            shards: 16,
        };
        let path = write_config(
            &dir,
            if enabled {
                "cache-on.toml"
            } else {
                "cache-off.toml"
            },
            &config(&data, udp, tcp, api, cache),
        );
        let _guard = spawn(&path);
        assert!(wait_ready(api, udp), "pulsed did not become ready");
        let run = run_load(udp, seconds, api);
        runs.push((enabled, run));
        std::thread::sleep(Duration::from_millis(100));
    }

    let mut out = String::new();
    let _ = writeln!(
        out,
        "| Кеш | qps | p50 µs | p99 µs | hit rate | hits | misses | entries | cache MiB |"
    );
    let _ = writeln!(out, "|---|---|---|---|---|---|---|---|---|");
    for (enabled, run) in &runs {
        let total = run.hits.saturating_add(run.misses).max(1);
        let hit_rate = run.hits as f64 / total as f64 * 100.0;
        let _ = writeln!(
            out,
            "| {} | {:.0} | {:.1} | {:.1} | {:.2}% | {} | {} | {} | {:.2} |",
            if *enabled { "on" } else { "off" },
            run.queries as f64 / run.seconds,
            run.p50_us,
            run.p99_us,
            hit_rate,
            run.hits,
            run.misses,
            run.entries,
            run.bytes as f64 / (1024.0 * 1024.0)
        );
    }
    if let (Some((false, off)), Some((true, on))) = (runs.first(), runs.get(1)) {
        let speedup =
            (on.queries as f64 / on.seconds) / (off.queries as f64 / off.seconds).max(1.0);
        let _ = writeln!(out, "\nqps speedup: {speedup:.2}x");
    }
    print!("{out}");
    std::fs::write(dir.join("report.md"), out).expect("write report");
    eprintln!("report: {}", dir.join("report.md").display());
}
