//! `pulsed` — авторитетный DNS-сервер (MVP).
//!
//! Крейт является **composition root** для авторитетного процесса: читает
//! JSON-настройки сервера, открывает `pulse-zonefile` (`--data`) как
//! единственный источник истины зон, поднимает UDP (`pulse-runtime`,
//! io_uring), TCP (std), DoT/DoH (`pulse-tls`), DNSCrypt v2 (`pulse-dnscrypt`)
//! и опциональный REST API (`pulse-api`) и обслуживает
//! `SIGTERM`/`SIGINT`/`SIGHUP`.
//!
//! DNS-ответы читаются из mmap v2 (`ParallelStore`/`ZoneReader`): на каждый
//! запрос берётся стабильный пин зоны и выполняется точечный поиск RRset, без
//! материализации зоны. REST-мутации открывают per-zone writer (lease), пишут
//! COW-страницы и коммитят (`--commit-mode per-zone|group`); разные зоны
//! коммитятся параллельно. Без `--data` сервер поднимается без зон и отвечает
//! `REFUSED`.
//!
//! Master-файлы импортируются отдельной командой `pulsed import --data ...`;
//! legacy v1-файл конвертируется `pulsed convert --from <v1> --to <v2>`;
//! в рантайме `.zone` не читаются, JSON-поля `zones`/`zones_files` отвергаются
//! с инструкцией миграции.
//!
//! # Состав
//!
//! - [`config`] — JSON-настройки сервера и CLI-overrides.
//! - `zonefile` — `ZoneView` поверх mmap и адаптер записи в `pulse-zonefile`.
//! - `master` — импорт RFC 1035 master-файлов (`pulsed import`).
//! - `dnssec` — загрузка ключей и DNSSEC-подпись зон в zonefile.
//! - `transfer` — AXFR/IXFR-out из zonefile, TSIG/ACL, IXFR-история и NOTIFY.
//! - `tls` — DoT/DoH-серверы и hot-reload сертификата.
//! - `dnscrypt` — DNSCrypt UDP, загрузка ключей и `dnscrypt-gencert`.
//! - [`server`] — запуск и остановка DNS/API.
//! - [`stats`] — атомарные счётчики без блокировок на горячем пути.
//!
//! # Пример
//!
//! ```no_run
//! use pulsed::config::Config;
//! use pulsed::server::Server;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let config = Config::load("examples/pulsed.json")?;
//! let mut server = Server::start(&config)?;
//! println!("udp={:?} tcp={:?}", server.udp_addr(), server.tcp_addr());
//! server.shutdown()?;
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::doc_markdown)]

mod cli;
mod dns;
mod dnscrypt;
mod dnssec;
mod logging;
mod master;
mod metrics;
mod perms;
mod secondary;
mod store;
mod tcp;
mod tls;
mod transfer;
mod udp;
mod zonefile;

pub mod config;
pub mod server;
pub mod stats;

pub use dnscrypt::DnscryptError;
pub use tls::TlsError;

use std::process::ExitCode;

/// Точка входа бинарника `pulsed`.
///
/// Разбирает CLI, загружает конфигурацию, запускает сервер и блокируется до
/// `SIGTERM`/`SIGINT`, после чего выполняет graceful shutdown.
///
/// Коды выхода: `0` — штатное завершение, `1` — ошибка запуска/остановки,
/// `2` — ошибка конфигурации или аргументов.
#[must_use]
pub fn run() -> ExitCode {
    cli::run()
}
