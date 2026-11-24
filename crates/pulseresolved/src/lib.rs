//! `pulseresolved` — кеширующий DNS-резолвер (composition root).
//!
//! Крейт связывает `pulse-resolver` (резолюция, кеш, blocklist, overrides,
//! DNSSEC-валидация) с транспортами: UDP через `pulse-runtime` (io_uring,
//! `SO_REUSEPORT`, N worker-потоков) и TCP на std с length-prefix framing.
//!
//! # Состав
//!
//! - [`config`] — JSON-конфигурация, CLI-overrides и валидация.
//! - [`server`] — запуск/остановка UDP, TCP и HTTP-метрик, SIGHUP-reload.
//! - [`stats`] — атомарные счётчики транспорта и рендер Prometheus.
//! - [`error`] — ошибки конфигурации и запуска.
//!
//! # Пример
//!
//! ```no_run
//! use pulseresolved::config::Config;
//! use pulseresolved::server::Server;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let config = Config::load("examples/resolver.json")?;
//! let mut server = Server::start(&config)?;
//! println!("udp={:?} tcp={:?}", server.udp_addr(), server.tcp_addr());
//! server.shutdown()?;
//! # Ok(())
//! # }
//! ```
//!
//! # Ограничения
//!
//! - Нет серверных DoT/DoH/DoQ-транспортов: защищённые транспорты есть
//!   только на стороне upstream (клиент в `pulse-tls`).
//! - RRL реализован как per-source token bucket с политикой
//!   `drop`/`refused`/`truncate`, а не как полный RRL авторитетного сервера.
//! - DNSSEC-валидация использует статические trust anchors (RFC 5011 нет).
//! - HTTP-метрики доступны только на loopback-адресе и без TLS.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::items_after_statements,
    clippy::option_if_let_else,
    clippy::manual_let_else,
    clippy::struct_excessive_bools,
    clippy::cast_possible_truncation
)]

mod anchors;
mod cli;
mod logging;
mod metrics;
mod query;
mod reload;
mod tcp;
mod udp;

pub mod config;
pub mod error;
pub mod server;
pub mod stats;

use std::process::ExitCode;

/// Точка входа бинарника `pulseresolved`.
///
/// Разбирает CLI, загружает конфигурацию, запускает сервер и обрабатывает
/// `SIGTERM`/`SIGINT` (graceful shutdown) и `SIGHUP` (перечитывание
/// blocklist).
///
/// Коды выхода: `0` — штатное завершение, `1` — ошибка запуска/остановки,
/// `2` — ошибка конфигурации или аргументов.
#[must_use]
pub fn run() -> ExitCode {
    cli::run()
}
