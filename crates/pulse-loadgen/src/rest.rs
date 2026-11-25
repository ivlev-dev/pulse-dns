//! Параллельная REST-нагрузка на `/api/v1` (8 зон, PUT RRset).
//!
//! Каждый writer — отдельный поток и отдельное HTTP/1.1-соединение на запрос
//! (`Connection: close`): для десятков записей/с это дешевле, чем поддерживать
//! keep-alive-парсер, и не искажает DNS-латентность.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use hdrhistogram::Histogram;

/// Параметры REST-нагрузки.
#[derive(Debug, Clone)]
pub struct RestConfig {
    /// Адрес API.
    pub api: SocketAddr,
    /// Bearer token.
    pub token: String,
    /// Число зон (записи распределяются round-robin).
    pub zones: u32,
    /// Потоков-писателей.
    pub threads: usize,
    /// Суммарная ставка, записей/с.
    pub rate: f64,
    /// Таймаут одного HTTP-запроса.
    pub timeout: Duration,
    /// Уникальный тег прогона: владельцы `w{thread}-{n}-{tag}` не конфликтуют
    /// между повторами (PUT в существующий owner без `If-Match` отвергается).
    pub tag: String,
}

impl Default for RestConfig {
    fn default() -> Self {
        Self {
            api: "127.0.0.1:8080".parse().expect("loopback"),
            token: "pd_bench_token".to_owned(),
            zones: 8,
            threads: 8,
            rate: 80.0,
            timeout: Duration::from_secs(5),
            tag: String::new(),
        }
    }
}

/// Итог REST-нагрузки.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RestResult {
    /// Запросов отправлено.
    pub requests: u64,
    /// `2xx` ответов.
    pub acked: u64,
    /// Ошибок/не-2xx.
    pub errors: u64,
    /// Фактическая ставка, записей/с.
    pub qps: f64,
    /// Латентность PUT, мкс.
    pub latency_us: crate::Latency,
}

struct WriterResult {
    requests: u64,
    acked: u64,
    errors: u64,
    histogram: Histogram<u64>,
}

/// Запущенная REST-нагрузка.
pub struct RestHandle {
    stop: Arc<AtomicBool>,
    joins: Vec<JoinHandle<WriterResult>>,
    started: Instant,
}

impl RestHandle {
    /// Запускает writer'ы.
    #[must_use]
    pub fn start(config: &RestConfig) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let started = Instant::now();
        let tag = if config.tag.is_empty() {
            format!(
                "{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |value| value.as_nanos())
            )
        } else {
            config.tag.clone()
        };
        let threads = config.threads.max(1);
        let mut joins = Vec::with_capacity(threads);
        for thread in 0..threads {
            let mut config = config.clone();
            config.tag.clone_from(&tag);
            let stop = Arc::clone(&stop);
            joins.push(std::thread::spawn(move || writer(thread, &config, &stop)));
        }
        Self {
            stop,
            joins,
            started,
        }
    }

    /// Останавливает writer'ы и агрегирует результат.
    ///
    /// # Panics
    ///
    /// Паникует, если не удалось создать HDR-гистограмму.
    #[must_use]
    pub fn finish(mut self) -> RestResult {
        self.stop.store(true, Ordering::Release);
        let mut result = RestResult::default();
        let mut histogram = Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).expect("histogram");
        for join in self.joins.drain(..) {
            let Some(partial) = join.join().ok() else {
                continue;
            };
            result.requests = result.requests.saturating_add(partial.requests);
            result.acked = result.acked.saturating_add(partial.acked);
            result.errors = result.errors.saturating_add(partial.errors);
            histogram.add(&partial.histogram).ok();
        }
        let elapsed = self.started.elapsed().as_secs_f64();
        result.qps = if elapsed > 0.0 {
            #[allow(clippy::cast_precision_loss)]
            {
                result.acked as f64 / elapsed
            }
        } else {
            0.0
        };
        result.latency_us = crate::report::latency_from_hist(&histogram, 1.0);
        result
    }
}

fn writer(thread: usize, config: &RestConfig, stop: &AtomicBool) -> WriterResult {
    let mut result = WriterResult {
        requests: 0,
        acked: 0,
        errors: 0,
        histogram: Histogram::new_with_bounds(1, 60_000_000, 3).expect("histogram"),
    };
    let mut interval =
        Duration::from_secs_f64(1.0 / config.rate.max(0.001) * config.threads as f64);
    let mut next = Instant::now();
    let mut counter = 0_u64;
    while !stop.load(Ordering::Acquire) {
        let now = Instant::now();
        if now < next {
            std::thread::sleep((next - now).min(Duration::from_millis(20)));
            continue;
        }
        next += interval;
        if now.duration_since(next) > Duration::from_millis(500) {
            next = now;
        }
        if interval.is_zero() {
            interval = Duration::from_millis(1);
        }
        let zone = config
            .zones
            .max(1)
            .wrapping_sub(1)
            .min(u32::try_from(thread).unwrap_or(0) % config.zones.max(1));
        let origin = format!("z{zone}.bench.test.");
        let owner = format!("w{thread}-{counter}-{}.{origin}", config.tag);
        let body = r#"{"ttl":60,"records":["192.0.2.1"]}"#;
        let request = format!(
            "PUT /api/v1/zones/{origin}/records/{owner}/A HTTP/1.1\r\n\
             Host: localhost\r\nConnection: close\r\n\
             Authorization: Bearer {}\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            config.token,
            body.len()
        );
        result.requests = result.requests.saturating_add(1);
        counter = counter.saturating_add(1);
        let started = Instant::now();
        match put(config, &request) {
            Ok(status) if (200..300).contains(&status) => {
                result.acked = result.acked.saturating_add(1);
            }
            _ => result.errors = result.errors.saturating_add(1),
        }
        let micros = u64::try_from(started.elapsed().as_micros())
            .unwrap_or(u64::MAX)
            .max(1);
        result.histogram.record(micros).ok();
    }
    result
}

fn put(config: &RestConfig, request: &str) -> Result<u16, std::io::Error> {
    let mut stream = TcpStream::connect_timeout(&config.api, config.timeout)?;
    stream.set_read_timeout(Some(config.timeout))?;
    stream.set_write_timeout(Some(config.timeout))?;
    stream.set_nodelay(true)?;
    stream.write_all(request.as_bytes())?;
    let mut response = Vec::with_capacity(256);
    stream.read_to_end(&mut response)?;
    let head = response
        .windows(2)
        .position(|window| window == b"\r\n")
        .map_or(&response[..], |end| &response[..end]);
    let status = std::str::from_utf8(head)
        .ok()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    Ok(status)
}
