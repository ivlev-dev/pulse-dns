//! `pulseresolved` — кеширующий DNS-резолвер (composition root).
//!
//! Крейт связывает `pulse-resolver` (резолюция, кеш, blocklist, overrides,
//! DNSSEC-валидация) с транспортами: UDP через `pulse-runtime` (io_uring,
//! `SO_REUSEPORT`, N worker-потоков), TCP на std с length-prefix framing,
//! DoT/DoH/1.1/DoH/2/DoQ через `pulse-tls` и DNSCrypt v2 (UDP/TCP) через
//! `pulse-dnscrypt`. Все транспорты используют единый горячий путь
//! `MessageRef → Resolver::resolve_ref_into → wire`, общий ACL и per-source
//! rate limit. Сложные запросы (несколько вопросов, сжатый QNAME, лишние
//! секции) автоматически уходят на полный `Message::decode` + `resolve`.
//!
//! # Состав
//!
//! - [`config`] — TOML-конфигурация (JSON — совместимость), CLI-overrides и валидация.
//! - [`server`] — запуск/остановка всех транспортов, HTTP-метрик и SIGHUP-reload.
//! - `control` — loopback REST API управления кешем, blocklist, upstreams,
//!   trust anchors, RRL и безопасным снимком конфигурации.
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
//! let config = Config::from_path("examples/resolver.toml")?;
//! let mut server = Server::start(&config)?;
//! println!("udp={:?} tcp={:?}", server.udp_addr(), server.tcp_addr());
//! server.shutdown()?;
//! # Ok(())
//! # }
//! ```
//!
//! # Ограничения
//!
//! - RRL ([`rrl`]) работает по классам ответов, источнику и хешу имени,
//!   применяется только к открытому UDP и не реализует DNS Cookies. На
//!   DoT/DoH/DoQ/DNSCrypt действует per-source token bucket.
//! - DNSSEC-валидация использует статические anchors или RFC 5011
//!   ([`pulse_dnssec::TrustAnchorStore`]): add/revoke hold-down, состояние `0600`.
//! - HTTP-метрики и control-plane REST API доступны только на loopback-адресе
//!   и без TLS. Control API требует bearer-токен (`control_token` или
//!   `PULSERESOLVED_API_TOKEN`), лимит тела — 1 МиБ.
//! - DoH/3 не поддерживается; DNSCrypt hot-reload сертификата требует
//!   перезапуска (SIGHUP перечитывает только TLS-пару и blocklist).

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
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss
)]

mod anchors;
mod cli;
mod control;
mod logging;
mod metrics;
mod query;
mod reload;
mod secure;
mod tcp;
mod udp;

pub mod config;
pub mod error;
pub mod rrl;
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
