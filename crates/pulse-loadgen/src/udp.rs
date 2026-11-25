//! UDP-нагрузка: open-loop (постоянная ставка) и closed-loop (окно in-flight).
//!
//! На поток — свой `UdpSocket` и свой рабочий набор пакетов. Ответы
//! сопоставляются по ID через массив `pending[65536]`; латентность меряется
//! `Instant` вокруг send/recv (клиентская сторона, как требует
//! `docs/bench/plan.md`). Потери считаются как `sent − received` плюс
//! `UdpRcvbufErrors` namespace.

use std::collections::VecDeque;
use std::net::UdpSocket;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hdrhistogram::Histogram;

use crate::mix::{Class, Mix, Rng};
use crate::wire::{self, QuerySet};
use crate::{ClassStats, ClientConfig, RunResult};

#[derive(Clone, Copy)]
struct Pending {
    sent: Instant,
    class: Class,
    packet_index: usize,
}

#[derive(Default)]
struct ThreadStats {
    sent: u64,
    received: u64,
    timeouts: u64,
    errors: u64,
    invalid: u64,
    late: u64,
    suppressed: u64,
    histogram: Option<Histogram<u64>>,
    class_histograms: [Option<Histogram<u64>>; 5],
    class_sent: [u64; 5],
    class_received: [u64; 5],
}

impl ThreadStats {
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
        self.late += other.late;
        self.suppressed += other.suppressed;
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

/// Запускает прогон: прогрев + измерение, с опциональной REST-нагрузкой.
///
/// # Errors
///
/// Ошибка сборки рабочего набора или сокета.
pub fn run(config: &ClientConfig) -> Result<RunResult, String> {
    let queries = Arc::new(QuerySet::build(
        config.zones,
        config.rrsets_per_zone,
        config.mix,
        config.working_set,
        config.seed,
        config.edns_do,
    )?);
    let host = crate::sysinfo::host_info();
    // Прогрев: page cache, TCP/TLS-handshake, аллокатор сервера.
    let warmup = phase(config, &queries, config.warmup);

    let rest = config.rest.as_ref().map(crate::rest::RestHandle::start);
    let before = crate::sysinfo::snapshot();
    let mut stats = phase(config, &queries, config.duration);
    let rest_result = rest.map(crate::rest::RestHandle::finish);
    let after = crate::sysinfo::snapshot();

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
    // Знаменатель — окно измерения, без хвостового drain (он может ждать
    // потерянные ответы до timeout и занижать qps).
    let seconds = config.duration.as_secs_f64().max(f64::EPSILON);
    #[allow(clippy::cast_precision_loss)]
    let client_qps = stats.received as f64 / seconds;
    Ok(RunResult {
        mode: config.mode,
        qps_target: config.qps,
        threads: config.threads,
        window: config.window,
        warmup_secs: config.warmup.as_secs_f64(),
        duration_secs: config.duration.as_secs_f64(),
        sent: stats.sent,
        received: stats.received,
        warmup_sent: warmup.sent,
        warmup_received: warmup.received,
        timeouts: stats.timeouts,
        errors: stats.errors,
        invalid: stats.invalid,
        suppressed: stats.suppressed,
        client_qps,
        latency,
        classes,
        kernel: crate::sysinfo::delta(&before, &after),
        rest: rest_result,
        host,
    })
}

fn phase(config: &ClientConfig, queries: &Arc<QuerySet>, duration: Duration) -> ThreadStats {
    if duration.is_zero() {
        return ThreadStats::new();
    }
    let threads = config.threads.max(1);
    let deadline = Instant::now() + duration;
    let mut merged = ThreadStats::new();
    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(threads);
        for thread in 0..threads {
            let queries = Arc::clone(queries);
            handles.push(scope.spawn(move || {
                if let Some(cpus) = config.cpus.as_deref()
                    && let Err(error) = crate::affinity::pin_thread(cpus, thread)
                {
                    eprintln!("pulse-loadgen: udp thread {thread} affinity: {error}");
                }
                match run_thread(config, thread, &queries, deadline) {
                    Ok(stats) => stats,
                    Err(error) => {
                        let mut stats = ThreadStats::new();
                        stats.errors = 1;
                        eprintln!("pulse-loadgen: thread {thread}: {error}");
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
    merged
}

#[allow(clippy::too_many_lines)]
fn run_thread(
    config: &ClientConfig,
    thread: usize,
    queries: &QuerySet,
    deadline: Instant,
) -> Result<ThreadStats, String> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|error| format!("bind: {error}"))?;
    socket
        .set_nonblocking(true)
        .map_err(|error| format!("nonblocking: {error}"))?;
    let mut stats = ThreadStats::new();
    let mut rng = Rng::new(config.seed ^ 0x9e37_79b9_7f4a_7c15_u64.wrapping_mul(thread as u64 + 1));
    let closed_loop = config.qps.is_none();
    let max_inflight = if closed_loop {
        config.window.clamp(1, 40_000)
    } else {
        config.max_inflight.clamp(1, 40_000)
    };
    let interval = config.qps.map(|qps| {
        let per_thread = qps / config.threads.max(1) as f64;
        Duration::from_secs_f64(1.0 / per_thread.max(0.001))
    });
    let mut next_send = interval.map(|interval| Instant::now() + interval);
    let mut pending: Vec<Option<Pending>> = (0..65_536).map(|_| None).collect();
    let mut in_flight = 0_usize;
    let mut queue: VecDeque<(u16, Instant)> = VecDeque::new();
    let mut next_id = (thread as u16).wrapping_mul(257);
    let mut buffer = [0_u8; 4096];
    let mut packet_bytes = Vec::with_capacity(512);
    let mut validate_counter = 0_u64;
    let mut expired_at = Instant::now();

    while Instant::now() < deadline {
        let now = Instant::now();
        let should_send = match next_send {
            Some(next) => now >= next && in_flight < max_inflight,
            None => in_flight < max_inflight,
        };
        if should_send {
            let class = pick_class(&mut rng, config.mix);
            let packets = &queries.by_class[class.index()];
            if packets.is_empty() {
                break;
            }
            let packet_index = rng.below(packets.len() as u64) as usize;
            let packet = &packets[packet_index];
            // ID должен быть свободен: при 40k in-flight и wrap 65536 старый
            // слот может быть ещё занят.
            let mut id = next_id;
            let mut tries = 0_u32;
            while pending[id as usize].is_some() {
                id = id.wrapping_add(1);
                tries += 1;
                if tries >= 65_535 {
                    break;
                }
            }
            if pending[id as usize].is_some() {
                stats.suppressed = stats.suppressed.saturating_add(1);
            } else {
                packet_bytes.clear();
                packet_bytes.extend_from_slice(&packet.bytes);
                wire::set_id(&mut packet_bytes, id);
                match socket.send_to(&packet_bytes, config.target) {
                    Ok(_) => {
                        let sent = Instant::now();
                        pending[id as usize] = Some(Pending {
                            sent,
                            class,
                            packet_index,
                        });
                        queue.push_back((id, sent));
                        in_flight += 1;
                        stats.sent += 1;
                        stats.class_sent[class.index()] += 1;
                        next_id = id.wrapping_add(1);
                    }
                    Err(_) => stats.errors += 1,
                }
            }
            if let Some(interval) = interval {
                let scheduled = next_send.map_or(now + interval, |next| next + interval);
                next_send = Some(if scheduled < now {
                    now + interval
                } else {
                    scheduled
                });
            }
        } else if let Some(next) = next_send {
            if now < next {
                let wait = next.saturating_duration_since(now);
                if wait > Duration::from_micros(200) {
                    std::thread::sleep(wait.checked_sub(Duration::from_micros(100)).unwrap());
                } else {
                    std::hint::spin_loop();
                }
            } else {
                // Ставка не достигнута: окно заполнено либо отстали.
                stats.suppressed = stats.suppressed.saturating_add(1);
                if let Some(interval) = interval {
                    next_send = Some(now + interval);
                }
            }
        } else {
            std::hint::spin_loop();
        }

        drain(
            &socket,
            &mut buffer,
            queries,
            &mut pending,
            &mut in_flight,
            &mut queue,
            &mut stats,
            &mut validate_counter,
            config,
        );
        if now.duration_since(expired_at) >= Duration::from_millis(20) {
            expired_at = now;
            expire(
                &mut pending,
                &mut in_flight,
                &mut queue,
                &mut stats,
                config.timeout,
            );
        }
    }

    // Дренаж хвоста: не дольше timeout после последней отправки.
    let drain_deadline = Instant::now() + config.timeout;
    while Instant::now() < drain_deadline && in_flight > 0 {
        drain(
            &socket,
            &mut buffer,
            queries,
            &mut pending,
            &mut in_flight,
            &mut queue,
            &mut stats,
            &mut validate_counter,
            config,
        );
        if in_flight == 0 {
            break;
        }
        std::thread::sleep(Duration::from_micros(200));
    }
    expire(
        &mut pending,
        &mut in_flight,
        &mut queue,
        &mut stats,
        Duration::ZERO,
    );
    Ok(stats)
}

fn pick_class(rng: &mut Rng, mix: Mix) -> Class {
    mix.pick(rng.below(mix.total()))
}

#[allow(clippy::too_many_arguments)]
fn drain(
    socket: &UdpSocket,
    buffer: &mut [u8],
    queries: &QuerySet,
    pending: &mut [Option<Pending>],
    in_flight: &mut usize,
    queue: &mut VecDeque<(u16, Instant)>,
    stats: &mut ThreadStats,
    validate_counter: &mut u64,
    config: &ClientConfig,
) {
    loop {
        match socket.recv_from(buffer) {
            Ok((length, _peer)) => {
                let now = Instant::now();
                let Some(id) = buffer
                    .get(..2)
                    .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
                else {
                    stats.errors += 1;
                    continue;
                };
                let Some(pending_entry) = pending[id as usize].take() else {
                    stats.late += 1;
                    continue;
                };
                *in_flight = in_flight.saturating_sub(1);
                let latency = now.duration_since(pending_entry.sent);
                let latency_ns = u64::try_from(latency.as_nanos()).unwrap_or(u64::MAX);
                let class = pending_entry.class;
                let expected_rcode = class.expected_rcode();
                match wire::validate_header(&buffer[..length], id, expected_rcode) {
                    Ok(()) => {
                        stats.received += 1;
                        stats.class_received[class.index()] += 1;
                        stats.record(class, latency_ns);
                        *validate_counter = validate_counter.saturating_add(1);
                        if config.validate_every > 0
                            && (*validate_counter).is_multiple_of(u64::from(config.validate_every))
                            && let Some(packet) =
                                queries.by_class[class.index()].get(pending_entry.packet_index)
                            && let Err(_error) = wire::validate_full(
                                &buffer[..length],
                                id,
                                &packet.name,
                                packet.qtype,
                                expected_rcode,
                            )
                        {
                            stats.invalid += 1;
                        }
                    }
                    Err(_) => stats.invalid += 1,
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => {
                stats.errors += 1;
                break;
            }
        }
    }
    // Чистим очередь от уже снятых ответов (не даём ей расти бесконечно).
    while let Some(&(id, _)) = queue.front() {
        if pending[id as usize].is_some() {
            break;
        }
        queue.pop_front();
    }
}

fn expire(
    pending: &mut [Option<Pending>],
    in_flight: &mut usize,
    queue: &mut VecDeque<(u16, Instant)>,
    stats: &mut ThreadStats,
    timeout: Duration,
) {
    let now = Instant::now();
    while let Some(&(id, sent)) = queue.front() {
        if now.duration_since(sent) < timeout {
            break;
        }
        queue.pop_front();
        if pending[id as usize].take().is_some() {
            *in_flight = in_flight.saturating_sub(1);
            stats.timeouts += 1;
        }
    }
}
