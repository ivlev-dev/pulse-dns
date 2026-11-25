//! DNS-over-HTTPS/2 (RFC 8484 + RFC 9113) closed-loop.
//!
//! На поток — одно TLS+h2-соединение; окно задаёт число одновременных
//! stream'ов. `POST /dns-query` с `application/dns-message`; ответ читается
//! целиком и валидируется по ID/RCODE.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use hdrhistogram::Histogram;
use http::{Method, Request};
use pulse_tls::client::ClientTlsConfig;
use rustls::pki_types::ServerName;

use crate::mix::{Class, Mix, Rng};
use crate::wire::{self, QuerySet};
use crate::{ClassStats, ClientConfig, RunResult};

#[derive(Default)]
struct Stats {
    sent: u64,
    received: u64,
    timeouts: u64,
    errors: u64,
    invalid: u64,
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

/// DoH h2-прогон.
///
/// # Errors
///
/// Ошибка сборки набора/TLS-конфигурации.
pub fn run(config: &ClientConfig) -> Result<RunResult, String> {
    let queries = Arc::new(QuerySet::build(
        config.zones,
        config.rrsets_per_zone,
        config.mix,
        config.working_set,
        config.seed,
    )?);
    let tls = match &config.ca {
        Some(path) => ClientTlsConfig::with_ca_file(path, b"h2")
            .map_err(|error| format!("doh CA: {error}"))?,
        None => ClientTlsConfig::with_webpki_roots(b"h2")
            .map_err(|error| format!("doh TLS: {error}"))?,
    };
    let host = crate::sysinfo::host_info();
    let warmup = phase(config, &queries, &tls, config.warmup);
    let before = crate::sysinfo::snapshot();
    let started = Instant::now();
    let mut stats = phase(config, &queries, &tls, config.duration);
    let elapsed = started.elapsed();
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
    let seconds = elapsed.as_secs_f64().max(f64::EPSILON);
    #[allow(clippy::cast_precision_loss)]
    let client_qps = stats.received as f64 / seconds;
    Ok(RunResult {
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
        errors: stats.errors,
        invalid: stats.invalid,
        suppressed: 0,
        client_qps,
        latency,
        classes,
        kernel: crate::sysinfo::delta(&before, &after),
        rest: None,
        host,
    })
}

fn phase(
    config: &ClientConfig,
    queries: &Arc<QuerySet>,
    tls: &ClientTlsConfig,
    duration: Duration,
) -> Stats {
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
            let tls = tls.clone();
            handles.push(scope.spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        eprintln!("pulse-loadgen: doh runtime: {error}");
                        return Stats::new();
                    }
                };
                runtime.block_on(doh_thread(config, thread, &queries, deadline, &tls))
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
async fn doh_thread(
    config: &ClientConfig,
    thread: usize,
    queries: &QuerySet,
    deadline: Instant,
    tls: &ClientTlsConfig,
) -> Stats {
    let mut stats = Stats::new();
    let mut rng = Rng::new(config.seed ^ 0x0d01_u64.wrapping_mul(thread as u64 + 1));
    let server_name = match ServerName::try_from(config.server_name.clone()) {
        Ok(name) => name,
        Err(error) => {
            eprintln!("pulse-loadgen: doh server name: {error}");
            return stats;
        }
    };
    let connector = tokio_rustls::TlsConnector::from(tls.config());
    let uri = format!("https://{}{}", config.server_name, config.doh_path);
    let window = config.window.clamp(1, 128);
    let mut connection: Option<(h2::client::SendRequest<Bytes>, tokio::task::JoinHandle<()>)> =
        None;

    while Instant::now() < deadline {
        if connection.is_none() {
            let connected = async {
                let stream = tokio::net::TcpStream::connect(config.target).await.ok()?;
                stream.set_nodelay(true).ok()?;
                let tls_stream = connector.connect(server_name.clone(), stream).await.ok()?;
                let (send, driver) = h2::client::handshake(tls_stream).await.ok()?;
                let driver = tokio::spawn(async move {
                    let _ = driver.await;
                });
                Some((send, driver))
            };
            if let Ok(Some(connection_value)) =
                tokio::time::timeout(config.timeout, connected).await
            {
                connection = Some(connection_value);
            } else {
                stats.errors += 1;
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        }
        let Some((send, _driver)) = connection.as_mut() else {
            continue;
        };
        let batch = window;
        let mut pending = Vec::with_capacity(batch);
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
            let packet = &packets[packet_index];
            let id = (stats.sent as u16).wrapping_add((thread as u16).wrapping_mul(8191));
            let mut body = packet.bytes.clone();
            wire::set_id(&mut body, id);
            let request = Request::builder()
                .method(Method::POST)
                .uri(&uri)
                .header("content-type", "application/dns-message")
                .body(())
                .expect("doh request");
            let Ok((response, mut stream)) = send.send_request(request, false) else {
                stats.errors += 1;
                break;
            };
            if stream.send_data(Bytes::from(body), true).is_err() {
                stats.errors += 1;
                break;
            }
            stats.sent += 1;
            stats.class_sent[class.index()] += 1;
            pending.push((id, class, Instant::now(), response));
        }
        for (id, class, started, response) in pending {
            let received = async {
                let response = response.await.ok()?;
                let mut body = Vec::new();
                let mut stream = response.into_body();
                while let Some(chunk) = stream.data().await {
                    body.extend_from_slice(&chunk.ok()?);
                }
                Some(body)
            };
            match tokio::time::timeout(config.timeout, received).await {
                Ok(Some(body)) => {
                    let latency_ns =
                        u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
                    match wire::validate_header(&body, id, class.expected_rcode()) {
                        Ok(()) => {
                            stats.received += 1;
                            stats.class_received[class.index()] += 1;
                            stats.record(class, latency_ns);
                        }
                        Err(_) => stats.invalid += 1,
                    }
                }
                Ok(None) => stats.errors += 1,
                Err(_) => stats.timeouts += 1,
            }
        }
        if stats.errors > 0 {
            connection = None;
        }
    }
    if let Some((_, driver)) = connection.take() {
        driver.abort();
    }
    stats
}

fn pick_class(rng: &mut Rng, mix: Mix) -> Class {
    mix.pick(rng.below(mix.total()))
}
