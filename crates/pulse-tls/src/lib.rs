//! DNS over TLS (RFC 7858) и DNS over HTTPS (RFC 8484) для `pulse-dns`.
//!
//! Крейт предоставляет два синхронных сервера (std + rustls, без tokio):
//!
//! - [`DotServer`] — TLS 1.2/1.3 с ALPN `dot`, length-prefixed DNS
//!   (2 байта BE), несколько сообщений на соединение, idle timeout,
//!   лимиты соединений/размера и graceful shutdown.
//! - [`DohServer`] — HTTPS/1.1 с ALPN `http/1.1`, `POST /dns-query`
//!   (`application/dns-message`), `GET /dns-query?dns=<base64url>`,
//!   `GET /healthz`, keep-alive, лимит тела 64 KiB и коды
//!   `200/400/404/405/413/415/429/500/505`.
//!
//! Оба сервера принимают обработчик
//! `Fn(&[u8], SocketAddr) -> Option<Vec<u8>>` и возвращают готовый DNS-ответ;
//! обработчик вызывается из потока соединения. `None` закрывает соединение
//! (DoT) или даёт HTTP 500 (DoH).
//!
//! Для upstream-резолвера крейт также предоставляет синхронные клиенты
//! [`client::DotClient`] и [`client::DohClient`]: проверка сертификата по
//! webpki-roots или явному CA, ALPN `dot`/`http/1.1`, keep-alive-соединение
//! с переподключением и раздельные таймауты connect/IO.
//!
//! # Ограничения MVP
//!
//! - Только HTTP/1.1. HTTP/2 (ALPN `h2`) и HTTP/3 не поддерживаются; preface
//!   HTTP/2 получает `505`.
//! - Нет async/tokio: поток на соединение, ограниченный
//!   `max_connections`.
//! - `Cache-Control: max-age=<min TTL>` включается опционально
//!   (`DohConfig::cache_control`) и вычисляется по ответу через `pulse-dns`.
//! - Hot-reload сертификата применяется к новым соединениям; уже открытые
//!   TLS-сессии продолжают работать со старой парой.
//! - Клиент DoH поддерживает только HTTP/1.1 с `Content-Length`; chunked
//!   transfer-encoding не реализован.
//!
//! # Безопасность
//!
//! Используются только rustls и `aws-lc-rs`; TLS 1.0/1.1 отключены,
//! ALPN обязателен и проверяется после рукопожатия. Закрытый ключ не
//! попадает в `Debug`/логи. Враждебный TLS/HTTP не должен вызывать панику:
//! все ошибки разбора и I/O возвращаются как [`Error`], обработчик
//! изолирован `catch_unwind`.
//!
//! # Пример DoT
//!
//! ```no_run
//! use pulse_tls::{DotConfig, DotServer, TlsConfig};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let cert = std::fs::read("cert.pem")?;
//! let key = std::fs::read("key.pem")?;
//! let tls = TlsConfig::for_dot(&cert, &key)?;
//! let config = DotConfig::new("0.0.0.0:853".parse()?, tls);
//! let mut server = DotServer::bind(config, |query, _peer| Some(query.to_vec()))?;
//! println!("listening on {}", server.local_addr());
//! server.shutdown()?;
//! # Ok(())
//! # }
//! ```
//!
//! # Пример DoH
//!
//! ```no_run
//! use pulse_tls::{DohConfig, DohServer, TlsConfig};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let cert = std::fs::read("cert.pem")?;
//! let key = std::fs::read("key.pem")?;
//! let tls = TlsConfig::for_doh(&cert, &key)?;
//! let mut config = DohConfig::new("0.0.0.0:443".parse()?, tls);
//! config.cache_control = true;
//! let mut server = DohServer::bind(config, |query, _peer| Some(query.to_vec()))?;
//! server.shutdown()?;
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::needless_pass_by_value,
    clippy::items_after_statements,
    clippy::option_if_let_else,
    clippy::manual_let_else,
    clippy::single_match_else,
    clippy::redundant_closure_for_method_calls,
    clippy::wildcard_imports
)]

pub mod acl;
pub mod client;
pub mod doh;
pub mod dot;
pub mod error;
pub mod ratelimit;
pub mod stats;
pub mod tls;

mod http;
mod server;
mod transport;

pub use acl::Acl;
pub use client::{ClientTlsConfig, DohClient, DotClient};
pub use doh::{DohConfig, DohServer};
pub use dot::{DnsHandler, DotConfig, DotServer};
pub use error::Error;
pub use ratelimit::{RateLimitConfig, RateLimiter};
pub use stats::{Stats, StatsSnapshot};
pub use tls::TlsConfig;
