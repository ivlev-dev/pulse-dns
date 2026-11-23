//! `pulsed` — авторитетный DNS-сервер (MVP).
//!
//! Крейт является **composition root** для авторитетного процесса: читает
//! JSON-конфигурацию, собирает зоны в in-memory store, поднимает UDP
//! (`pulse-runtime`, io_uring) и TCP (std) транспорты и обслуживает
//! `SIGTERM`/`SIGINT`.
//!
//! # Состав
//!
//! - [`config`] — JSON-конфигурация и CLI-overrides.
//! - [`zone`] — загрузка зон и валидация инвариантов.
//! - [`server`] — запуск и остановка транспортов.
//! - [`stats`] — атомарные счётчики без блокировок на горячем пути.
//!
//! # Пример
//!
//! ```no_run
//! use pulsed::config::Config;
//! use pulsed::server::Server;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let config = Config::load("examples/zones.json")?;
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
mod logging;
mod names;
mod rdata;
mod tcp;
mod udp;

pub mod config;
pub mod server;
pub mod stats;
pub mod zone;

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
