//! Измерительный харнесс для `pulsed`: клиент нагрузки, генератор зон,
//! сэмплер памяти, аллокационный и perf-профиль.
//!
//! Крейт не входит в production-путь сервера. Все бинарники — отдельные
//! инструменты; `pulsed`/`pulse-*` production-крейты не меняются.
//!
//! # Состав
//!
//! - [`mix`] — профиль запросов и детерминированный выбор типа;
//! - [`wire`] — сборка/валидация DNS-сообщений;
//! - [`udp`] — UDP open-loop (постоянная ставка) и closed-loop (окно);
//! - [`stream`] — TCP/DNS-over-TLS closed-loop;
//! - [`doh`] — DNS-over-HTTPS/2 (h2) closed-loop;
//! - [`rest`] — параллельная REST-запись в 8 зон;
//! - [`mem`] — RSS/VmRSS/RssAnon/RssFile и smaps-сэмплер;
//! - [`sysinfo`] — счётчики ядра (`/proc/net/snmp`, `nstat`), CPU/loadavg;
//! - [`storegen`] — генерация v2-zonefile с `zones × rrsets`;
//! - [`report`] — JSON/Markdown-отчёт.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::doc_markdown)]

pub mod doh;
pub mod mem;
pub mod mix;
pub mod report;
pub mod rest;
pub mod storegen;
pub mod stream;
pub mod sysinfo;
pub mod udp;
pub mod wire;

use std::path::PathBuf;
use std::time::Duration;

/// Транспорт нагрузки.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// UDP, один сокет на поток.
    Udp,
    /// TCP с length-prefix и окном in-flight.
    Tcp,
    /// DNS-over-TLS (RFC 7858).
    Dot,
    /// DNS-over-HTTPS/2 (RFC 8484 + RFC 9113).
    DohH2,
}

impl Mode {
    /// Короткое имя для отчётов.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Dot => "dot",
            Self::DohH2 => "doh-h2",
        }
    }
}

/// Конфигурация одного нагрузочного прогона.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Адрес сервера (UDP/TCP/DoT). Для DoH h2 — адрес TLS-listener'а.
    pub target: std::net::SocketAddr,
    /// Транспорт.
    pub mode: Mode,
    /// Потоков-клиентов (для DoH — соединений).
    pub threads: usize,
    /// Целевая ставка, запросов/с. `None` — closed-loop на максимальной скорости.
    pub qps: Option<f64>,
    /// Окно in-flight для closed-loop (UDP/TCP/DoT — запросов на поток,
    /// DoH — stream'ов на соединение).
    pub window: usize,
    /// Длительность измерения.
    pub duration: Duration,
    /// Прогрев (результаты отбрасываются).
    pub warmup: Duration,
    /// Таймаут ожидания ответа.
    pub timeout: Duration,
    /// Профиль запросов.
    pub mix: mix::Mix,
    /// База зон: `z{0..zones}.bench.test.`.
    pub zones: u32,
    /// RRset на зону (для генерации имён запросов).
    pub rrsets_per_zone: u32,
    /// Seed детерминированного выбора.
    pub seed: u64,
    /// Размер рабочего набора пакетов на поток (имена, которые циклируются).
    pub working_set: usize,
    /// TLS CA в PEM (DoT/DoH h2). `None` — webpki roots.
    pub ca: Option<PathBuf>,
    /// SNI/имя сертификата.
    pub server_name: String,
    /// Путь DoH (`/dns-query`).
    pub doh_path: String,
    /// Полная валидация ответа (decode) для каждой N-й выборки; 0 — только header.
    pub validate_every: u32,
    /// Параллельная REST-нагрузка.
    pub rest: Option<rest::RestConfig>,
    /// Максимум in-flight для open-loop (защита клиента от OOM).
    pub max_inflight: usize,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            target: "127.0.0.1:5353".parse().expect("loopback"),
            mode: Mode::Udp,
            threads: 4,
            qps: Some(20_000.0),
            window: 16,
            duration: Duration::from_secs(10),
            warmup: Duration::from_secs(3),
            timeout: Duration::from_secs(1),
            mix: mix::Mix::default(),
            zones: 1,
            rrsets_per_zone: 1_000,
            seed: 0x5eed_1234_abcd_0001,
            working_set: 16_384,
            ca: None,
            server_name: "localhost".to_owned(),
            doh_path: "/dns-query".to_owned(),
            validate_every: 64,
            rest: None,
            max_inflight: 8192,
        }
    }
}

/// Итог одного прогона.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RunResult {
    /// Транспорт.
    pub mode: Mode,
    /// Целевая ставка.
    pub qps_target: Option<f64>,
    /// Потоков.
    pub threads: usize,
    /// Окно.
    pub window: usize,
    /// Прогрев, с.
    pub warmup_secs: f64,
    /// Длительность, с.
    pub duration_secs: f64,
    /// Отправлено запросов.
    pub sent: u64,
    /// Получено валидных ответов.
    pub received: u64,
    /// Отправлено за прогрев (для вычета серверных счётчиков).
    pub warmup_sent: u64,
    /// Получено за прогрев.
    pub warmup_received: u64,
    /// Таймауты.
    pub timeouts: u64,
    /// Ошибки сокета/протокола.
    pub errors: u64,
    /// Ответы с чужим ID/QR/rcode.
    pub invalid: u64,
    /// Не отправлено из-за лимита in-flight.
    pub suppressed: u64,
    /// Клиентский qps (received / измеренное время).
    pub client_qps: f64,
    /// Латентность, нс.
    pub latency: Latency,
    /// Разбивка по классам запросов.
    pub classes: std::collections::BTreeMap<String, ClassStats>,
    /// Счётчики ядра UDP до/после.
    pub kernel: sysinfo::KernelDelta,
    /// Параллельные REST-записи.
    pub rest: Option<rest::RestResult>,
    /// Параметры хоста.
    pub host: sysinfo::HostInfo,
}

/// Перцентили латентности, нс.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Latency {
    /// Минимум.
    pub min: u64,
    /// Медиана.
    pub p50: u64,
    /// 90-й перцентиль.
    pub p90: u64,
    /// 99-й перцентиль.
    pub p99: u64,
    /// 99.9-й перцентиль.
    pub p999: u64,
    /// Максимум.
    pub max: u64,
    /// Среднее.
    pub mean: f64,
}

/// Счётчики по классу запроса.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ClassStats {
    /// Отправлено.
    pub sent: u64,
    /// Получено.
    pub received: u64,
    /// Перцентили (по классу).
    pub latency: Latency,
}
