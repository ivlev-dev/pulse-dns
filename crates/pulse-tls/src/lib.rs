//! Защищённые DNS-транспорты для `pulse-dns`: DoT (RFC 7858),
//! DoH/1.1 (RFC 8484), DoH/HTTP/2 (RFC 8484 + RFC 9113),
//! DoH/HTTP/3 (RFC 8484 + RFC 9114) и DoQ (RFC 9250).
//!
//! # Серверы
//!
//! Все серверы принимают один и тот же обработчик
//! `Fn(&[u8], SocketAddr) -> Option<Vec<u8>>` (или [`DnsHandler`]) и не
//! зависят от `pulsed`, `pulse-server` или `pulse-resolver`. Конфигурация,
//! ACL и rate limit передаются параметрами, поэтому транспорт можно поднять
//! в любом бинарнике за несколько строк.
//!
//! | Транспорт | Тип | Конфиг | Feature |
//! |---|---|---|---|
//! | DoT | [`DotServer`] | [`DotConfig`] | — |
//! | DoH/1.1 | [`DohServer`] | [`DohConfig`] | — |
//! | DoH/2 | `Doh2Server` | `Doh2Config` | `http2` |
//! | DoH/3 | `Doh3Server` | `Doh3Config` | `http3` |
//! | DoQ | `DoqServer` | `DoqConfig` | `doq` |
//!
//! - [`DotServer`] — TLS 1.2/1.3 с ALPN `dot`, length-prefixed DNS
//!   (2 байта BE), несколько сообщений на соединение, idle timeout,
//!   лимиты соединений/размера и graceful shutdown.
//! - [`DohServer`] — HTTPS/1.1 с ALPN `http/1.1`, `POST /dns-query`
//!   (`application/dns-message`), `GET /dns-query?dns=<base64url>`,
//!   `GET /healthz`, keep-alive, лимит тела 64 KiB и коды
//!   `200/400/404/405/413/415/429/500/505`.
//! - `Doh2Server` — HTTPS/2 с ALPN `h2` на tokio + h2: те же маршруты,
//!   мультиплексирование stream'ов, лимит одновременных stream'ов,
//!   лимит тела 64 KiB, GOAWAY при shutdown.
//! - `Doh3Server` — HTTPS/3 с ALPN `h3` на quinn + h3: те же маршруты,
//!   QUIC multiplexing, лимит одновременных запросов, тела/заголовков,
//!   idle timeout, GOAWAY при shutdown, 0-RTT выключен.
//! - `DoqServer` — QUIC с ALPN `doq` на quinn: один двунаправленный
//!   stream на запрос, 2-байтовый length-prefix, лимиты stream'ов/размера/
//!   времени, idle timeout, 0-RTT выключен.
//!
//! Синхронные DoT/DoH/1.1 работают на std-потоках без tokio. Асинхронные
//! DoH/2, DoH/3 и DoQ включаются feature-флагами `http2`, `http3` и `doq`;
//! каждый сервер поднимает собственный tokio runtime в фоновом потоке, а
//! наружу отдаёт синхронный RAII-API (`bind` → `local_addr`/`stats` →
//! `shutdown`).
//!
//! # Пример: поднять любой транспорт
//!
//! ```no_run
//! use pulse_tls::{DotConfig, DotServer, TlsConfig};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let cert = std::fs::read("cert.pem")?;
//! let key = std::fs::read("key.pem")?;
//! let mut dot = DotServer::bind(
//!     DotConfig::new("0.0.0.0:853".parse()?, TlsConfig::for_dot(&cert, &key)?),
//!     |query: &[u8], _peer: std::net::SocketAddr| Some(query.to_vec()),
//! )?;
//! dot.shutdown()?;
//! # Ok(())
//! # }
//! ```
//!
//! DoH/2, DoH/3 и DoQ поднимаются так же:
//! `Doh2Server::bind(Doh2Config::new(addr, TlsConfig::for_doh2(&cert, &key)?), handler)`,
//! `Doh3Server::bind(Doh3Config::new(addr, TlsConfig::for_doh3(&cert, &key)?), handler)`
//! и `DoqServer::bind(DoqConfig::new(addr, TlsConfig::for_doq(&cert, &key)?), handler)`.
//!
//! Для upstream-резолвера крейт также предоставляет синхронные клиенты
//! [`client::DotClient`] и [`client::DohClient`]: проверка сертификата по
//! webpki-roots или явному CA, ALPN `dot`/`http/1.1`, пул keep-alive
//! соединений (по умолчанию 4) с переподключением, cooldown/backoff и
//! раздельными таймаутами connect/IO.
//!
//! # Ограничения
//!
//! - DoH/3 реализован только как сервер; HTTP/3-клиента для upstream нет.
//!   HTTP/1.1-сервер отвечает `505` на preface HTTP/2; для HTTP/2
//!   используйте `Doh2Server`, для HTTP/3 — `Doh3Server`.
//! - DoT/DoH/1.1 — поток на соединение, ограниченный `max_connections`.
//! - `Cache-Control: max-age=<min TTL>` включается опционально
//!   (`DohConfig::cache_control`/`Doh2Config::cache_control`/
//!   `Doh3Config::cache_control`) и вычисляется по ответу через `pulse-dns`.
//! - Hot-reload сертификата применяется к новым соединениям; уже открытые
//!   сессии продолжают работать со старой парой. DoQ и DoH/3 применяют новый
//!   сертификат к новым QUIC-соединениям через `set_server_config`.
//! - Клиент DoH поддерживает только HTTP/1.1 с `Content-Length`; chunked
//!   transfer-encoding не реализован.
//! - 0-RTT для DoQ и DoH/3 не включается.
//! - HTTP/3 используется только для DoH; WebTransport, server push и
//!   datagrams выключены.
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

#[cfg(feature = "http2")]
pub mod doh2;
#[cfg(feature = "http3")]
pub mod doh3;
#[cfg(feature = "doq")]
pub mod doq;

mod doh_core;
mod http;
mod pool;
mod server;
mod transport;

pub use acl::Acl;
pub use client::{ClientTlsConfig, DohClient, DotClient};
pub use doh::{DohConfig, DohServer};
pub use dot::{DnsHandler, DotConfig, DotServer};
pub use error::Error;
pub use pool::{DEFAULT_POOL_SIZE, MAX_POOL_SIZE, PoolConfig, PoolStats};
pub use ratelimit::{RateLimitConfig, RateLimiter};
pub use stats::{Stats, StatsSnapshot};
pub use tls::TlsConfig;

#[cfg(feature = "http2")]
pub use doh2::{Doh2Config, Doh2Server};
#[cfg(feature = "http3")]
pub use doh3::{Doh3Config, Doh3Server};
#[cfg(feature = "doq")]
pub use doq::{DoqConfig, DoqServer};
