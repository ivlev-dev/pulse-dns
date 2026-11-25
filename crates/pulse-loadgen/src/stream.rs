//! TCP и DNS-over-TLS: closed-loop с окном in-flight на соединение.
//!
//! TCP использует length-prefix (RFC 1035 §4.2.2) и окно запросов; DoT —
//! `pulse_tls::client::DotClient` (rustls, keep-alive pool), по одному
//! запросу на поток (конкурентность задаётся числом потоков).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hdrhistogram::Histogram;
use pulse_tls::client::{ClientTlsConfig, DotClient};

use crate::mix::{Class, Mix, Rng};
use crate::wire::{self, Packet, QuerySet};
use crate::{ClassStats, ClientConfig, RunResult};

struct Sent {
    id: u16,
    class: Class,
    packet_index: usize,
    at: Instant,
}

#[derive(Default)]
struct Stats {
    sent: u64,
    received: u64,
    timeouts: u64,
    errors: u64,
    invalid: u64,
    reconnects: u64,
    histogram: Option<Histogram<u64>>,
    class_histograms: [Option<Histogram<u64>>; 5],
    class_sent: [u64; 5],
    class_received: [u64; 5],
}

impl Stats {
    fn new() -> Self {
        Self {
            histogram: Some(histogram()),
            class_histograms: std::array::from_fn(|_| Some(histogram())),
            ..Self::default()
        }
    }

    fn record(&mut self, class: Class, latency_ns: u64) {
        if let Some(histogram) = self.histogram.as_mut() {
            let _ = histogram.record(latency_ns.max(1));
        }
        if let Some(histogram) = self.class_histograms[class.index()].as_mut() {
            let _ = histogram.record(latency_ns.max(1));
        }
    }

    fn merge(&mut self, other: &Self) {
        self.sent += other.sent;
        self.received += other.received;
        self.timeouts += other.timeouts;
        self.errors += other.errors;
        self.invalid += other.invalid;
        self.reconnects += other.reconnects;
        if let (Some(left), Some(right)) = (self.histogram.as_mut(), other.histogram.as_ref()) {
            let _ = left.add(right);
        }
        for index in 0..5 {
            self.class_sent[index] += other.class_sent[index];
            self.class_received[index] += other.class_received[index];
            if let (Some(left), Some(right)) = (
                self.class_histograms[index].as_mut(),
                other.class_histograms[index].as_ref(),
            ) {
                let _ = left.add(right);
            }
        }
    }
}

fn histogram() -> Histogram<u64> {
    Histogram::new_with_bounds(1, 60_000_000_000, 3).expect("hdr histogram bounds")
}

/// TCP-прогон (closed-loop).
///
/// # Errors
///
/// Ошибка сборки рабочего набора.
pub fn run_tcp(config: &ClientConfig) -> Result<RunResult, String> {
    let queries = Arc::new(QuerySet::build(
        config.zones,
        config.rrsets_per_zone,
        config.mix,
        config.working_set,
        config.seed,
        config.edns_do,
    )?);
    let host = crate::sysinfo::host_info();
    let warmup = phase_tcp(config, &queries, config.warmup);
    let rest = config.rest.as_ref().map(crate::rest::RestHandle::start);
    let before = crate::sysinfo::snapshot();
    let mut stats = phase_tcp(config, &queries, config.duration);
    let rest = rest.map(crate::rest::RestHandle::finish);
    let after = crate::sysinfo::snapshot();
    Ok(build_result(
        config, &mut stats, &before, &after, host, rest, &warmup,
    ))
}

/// DoT-прогон (closed-loop, один запрос на поток).
///
/// # Errors
///
/// Ошибка сборки набора/TLS-конфигурации.
pub fn run_dot(config: &ClientConfig) -> Result<RunResult, String> {
    let queries = Arc::new(QuerySet::build(
        config.zones,
        config.rrsets_per_zone,
        config.mix,
        config.working_set,
        config.seed,
        config.edns_do,
    )?);
    let host = crate::sysinfo::host_info();
    let warmup = phase_dot(config, &queries, config.warmup)?;
    let rest = config.rest.as_ref().map(crate::rest::RestHandle::start);
    let before = crate::sysinfo::snapshot();
    let mut stats = phase_dot(config, &queries, config.duration)?;
    let rest = rest.map(crate::rest::RestHandle::finish);
    let after = crate::sysinfo::snapshot();
    Ok(build_result(
        config, &mut stats, &before, &after, host, rest, &warmup,
    ))
}

#[allow(clippy::too_many_arguments)]
fn build_result(
    config: &ClientConfig,
    stats: &mut Stats,
    before: &(
        crate::sysinfo::UdpCounters,
        Option<std::collections::BTreeMap<String, u64>>,
    ),
    after: &(
        crate::sysinfo::UdpCounters,
        Option<std::collections::BTreeMap<String, u64>>,
    ),
    host: crate::sysinfo::HostInfo,
    rest: Option<crate::rest::RestResult>,
    warmup: &Stats,
) -> RunResult {
    let merged_histogram = stats.histogram.take().unwrap_or_else(histogram);
    let latency = crate::report::latency_from_hist(&merged_histogram, 1.0);
    let mut classes = std::collections::BTreeMap::new();
    for class in Class::ALL {
        let index = class.index();
        let class_histogram = stats.class_histograms[index]
            .take()
            .unwrap_or_else(histogram);
        classes.insert(
            class.as_str().to_owned(),
            ClassStats {
                sent: stats.class_sent[index],
                received: stats.class_received[index],
                latency: crate::report::latency_from_hist(&class_histogram, 1.0),
            },
        );
    }
    let seconds = config.duration.as_secs_f64().max(f64::EPSILON);
    #[allow(clippy::cast_precision_loss)]
    let client_qps = stats.received as f64 / seconds;
    RunResult {
        mode: config.mode,
        qps_target: None,
        threads: config.threads,
        window: config.window,
        warmup_secs: config.warmup.as_secs_f64(),
        duration_secs: config.duration.as_secs_f64(),
        sent: stats.sent,
        received: stats.received,
        warmup_sent: warmup.sent,
        warmup_received: warmup.received,
        timeouts: stats.timeouts,
        errors: stats.errors.saturating_add(stats.reconnects),
        invalid: stats.invalid,
        suppressed: 0,
        client_qps,
        latency,
        classes,
        kernel: crate::sysinfo::delta(before, after),
        rest,
        host,
    }
}

fn phase_tcp(config: &ClientConfig, queries: &Arc<QuerySet>, duration: Duration) -> Stats {
    if duration.is_zero() {
        return Stats::new();
    }
    let threads = config.threads.max(1);
    let deadline = Instant::now() + duration;
    let mut merged = Stats::new();
    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(threads);
        for thread in 0..threads {
            let queries = Arc::clone(queries);
            handles.push(scope.spawn(move || {
                if let Some(cpus) = config.cpus.as_deref()
                    && let Err(error) = crate::affinity::pin_thread(cpus, thread)
                {
                    eprintln!("pulse-loadgen: tcp thread {thread} affinity: {error}");
                }
                tcp_thread(config, thread, &queries, deadline)
            }));
        }
        for handle in handles {
            if let Ok(stats) = handle.join() {
                merged.merge(&stats);
            }
        }
    });
    merged
}

#[allow(clippy::too_many_lines)]
fn tcp_thread(
    config: &ClientConfig,
    thread: usize,
    queries: &QuerySet,
    deadline: Instant,
) -> Stats {
    let mut stats = Stats::new();
    let mut rng = Rng::new(config.seed ^ 0x51ed_2701_u64.wrapping_mul(thread as u64 + 1));
    let mut stream: Option<TcpStream> = None;
    let mut next_id = (thread as u16).wrapping_mul(211);
    let mut packet_bytes = Vec::with_capacity(512);
    let mut frame = Vec::with_capacity(512);
    let mut response = Vec::with_capacity(4096);
    let window = config.window.clamp(1, 1024);

    while Instant::now() < deadline {
        if stream.is_none() {
            if let Ok(socket) = TcpStream::connect_timeout(&config.target, config.timeout) {
                let _ = socket.set_nodelay(true);
                let _ = socket.set_read_timeout(Some(config.timeout));
                let _ = socket.set_write_timeout(Some(config.timeout));
                stream = Some(socket);
            } else {
                stats.errors += 1;
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
        }
        let socket = stream.as_mut().expect("stream exists");
        let batch = window.min(64);
        let mut sent: Vec<Sent> = Vec::with_capacity(batch);
        let mut write_failed = false;
        for _ in 0..batch {
            if Instant::now() >= deadline {
                break;
            }
            let class = pick_class(&mut rng, config.mix);
            let packets = &queries.by_class[class.index()];
            if packets.is_empty() {
                break;
            }
            let packet_index = rng.below(packets.len() as u64) as usize;
            let packet: &Packet = &packets[packet_index];
            let id = next_id;
            next_id = next_id.wrapping_add(1);
            packet_bytes.clear();
            packet_bytes.extend_from_slice(&packet.bytes);
            wire::set_id(&mut packet_bytes, id);
            let length = u16::try_from(packet_bytes.len()).unwrap_or(u16::MAX);
            frame.clear();
            frame.extend_from_slice(&length.to_be_bytes());
            frame.extend_from_slice(&packet_bytes);
            if socket.write_all(&frame).is_err() {
                write_failed = true;
                stats.errors += 1;
                break;
            }
            stats.sent += 1;
            stats.class_sent[class.index()] += 1;
            sent.push(Sent {
                id,
                class,
                packet_index,
                at: Instant::now(),
            });
        }
        if write_failed {
            stream = None;
            stats.reconnects += 1;
            continue;
        }
        let mut read_failed = false;
        for _ in 0..sent.len() {
            let mut length = [0_u8; 2];
            if socket.read_exact(&mut length).is_err() {
                read_failed = true;
                break;
            }
            let length = usize::from(u16::from_be_bytes(length));
            response.clear();
            response.resize(length, 0);
            if socket.read_exact(&mut response).is_err() {
                read_failed = true;
                break;
            }
            let now = Instant::now();
            let id = response
                .get(..2)
                .map_or(0, |bytes| u16::from_be_bytes([bytes[0], bytes[1]]));
            let Some(index) = sent.iter().position(|entry| entry.id == id) else {
                stats.invalid += 1;
                continue;
            };
            let entry = sent.swap_remove(index);
            let latency_ns =
                u64::try_from(now.duration_since(entry.at).as_nanos()).unwrap_or(u64::MAX);
            match wire::validate_header(&response, id, entry.class.expected_rcode()) {
                Ok(()) => {
                    stats.received += 1;
                    stats.class_received[entry.class.index()] += 1;
                    stats.record(entry.class, latency_ns);
                    if config.validate_every > 0
                        && stats
                            .received
                            .is_multiple_of(u64::from(config.validate_every))
                        && let Some(packet) =
                            queries.by_class[entry.class.index()].get(entry.packet_index)
                        && let Err(_error) = wire::validate_full(
                            &response,
                            id,
                            &packet.name,
                            packet.qtype,
                            entry.class.expected_rcode(),
                        )
                    {
                        stats.invalid += 1;
                    }
                }
                Err(_) => stats.invalid += 1,
            }
        }
        if read_failed {
            stats.timeouts += u64::try_from(sent.len()).unwrap_or(0);
            stream = None;
            stats.reconnects += 1;
        }
    }
    stats
}

fn phase_dot(
    config: &ClientConfig,
    queries: &Arc<QuerySet>,
    duration: Duration,
) -> Result<Stats, String> {
    if duration.is_zero() {
        return Ok(Stats::new());
    }
    let tls = match &config.ca {
        Some(path) => ClientTlsConfig::with_ca_file(path, b"dot")
            .map_err(|error| format!("dot CA: {error}"))?,
        None => ClientTlsConfig::for_dot().map_err(|error| format!("dot TLS: {error}"))?,
    };
    let threads = config.threads.max(1);
    let deadline = Instant::now() + duration;
    let mut merged = Stats::new();
    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(threads);
        for thread in 0..threads {
            let tls = tls.clone();
            let queries = Arc::clone(queries);
            let server_name = config.server_name.clone();
            let target = config.target;
            handles.push(scope.spawn(move || {
                if let Some(cpus) = config.cpus.as_deref()
                    && let Err(error) = crate::affinity::pin_thread(cpus, thread)
                {
                    eprintln!("pulse-loadgen: dot thread {thread} affinity: {error}");
                }
                let client = DotClient::from_addr_with_tls(target, &server_name, tls);
                match client {
                    Ok(client) => dot_thread(config, thread, &queries, deadline, &client),
                    Err(error) => {
                        eprintln!("pulse-loadgen: dot thread {thread}: {error}");
                        let mut stats = Stats::new();
                        stats.errors = 1;
                        stats
                    }
                }
            }));
        }
        for handle in handles {
            if let Ok(stats) = handle.join() {
                merged.merge(&stats);
            }
        }
    });
    Ok(merged)
}

fn dot_thread(
    config: &ClientConfig,
    thread: usize,
    queries: &QuerySet,
    deadline: Instant,
    client: &DotClient,
) -> Stats {
    let mut stats = Stats::new();
    let mut rng = Rng::new(config.seed ^ 0xd07_u64.wrapping_mul(thread as u64 + 1));
    let mut packet_bytes = Vec::with_capacity(512);
    while Instant::now() < deadline {
        let class = pick_class(&mut rng, config.mix);
        let packets = &queries.by_class[class.index()];
        if packets.is_empty() {
            break;
        }
        let packet_index = rng.below(packets.len() as u64) as usize;
        let packet: &Packet = &packets[packet_index];
        let id = (stats.sent as u16).wrapping_add((thread as u16).wrapping_mul(4099));
        packet_bytes.clear();
        packet_bytes.extend_from_slice(&packet.bytes);
        wire::set_id(&mut packet_bytes, id);
        let started = Instant::now();
        stats.sent += 1;
        stats.class_sent[class.index()] += 1;
        match client.query(&packet_bytes, config.timeout, config.timeout) {
            Ok(response) => {
                let latency_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
                match wire::validate_header(&response, id, class.expected_rcode()) {
                    Ok(()) => {
                        stats.received += 1;
                        stats.class_received[class.index()] += 1;
                        stats.record(class, latency_ns);
                    }
                    Err(_) => stats.invalid += 1,
                }
            }
            Err(error) if error.is_timeout() => stats.timeouts += 1,
            Err(_) => stats.errors += 1,
        }
    }
    stats
}

fn pick_class(rng: &mut Rng, mix: Mix) -> Class {
    mix.pick(rng.below(mix.total()))
}
