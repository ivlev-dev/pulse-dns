//! Кеширующий DNS-резолвер: iterative/forward, RRset-кеш, blocklist и overrides.
//!
//! Крейт предоставляет `Resolver`, который принимает обычный
//! [`pulse_dns::Message`] и возвращает готовый DNS-ответ. Сетевой транспорт —
//! UDP с TCP-fallback, EDNS0 и 0x20; состояние (кеш, health forwarder-ов,
//! счётчики) потокобезопасно и не требует внешнего мьютекса на горячем пути.
//!
//! # Возможности
//!
//! - **Итеративная резолюция** от встроенных root hints: NS-делегирования,
//!   bailiwick, glue, CNAME-цепочки (16), глубина 32, бюджет 64 запроса,
//!   параллельный опрос 1–3 NS, опциональная qname minimization.
//! - **Forward-режим** со смешанными upstream (UDP, TCP, DNS-over-TLS,
//!   DNS-over-HTTPS/1.1), round-robin, health-счётчиками, cooldown и
//!   failover по порядку; DoT/DoH проверяют сертификат (webpki-roots или
//!   явный CA) и держат keep-alive-соединение на upstream.
//! - **Кеш**: шардированные `RwLock`-шарды с открытой адресацией, ключ по
//!   wire-байтам `(qname, qtype, qclass)`, компактные wire-записи, TTL как
//!   absolute deadline, approximate-LRU, negative caching RFC 2308, лимиты
//!   записей/памяти, метрики. [`Resolver::resolve_into`] кодирует попадание
//!   в caller-буфер без аллокаций и построения [`pulse_dns::Message`].
//! - **DNSSEC-кеш**: результат проверки цепочки (`zone` + отпечаток DNSKEY)
//!   и пары RRset+RRSIG переиспользуется между запросами; смена DNSKEY/DS
//!   или trust anchors инвалидирует доказательства.
//! - **Blocklist**: домены/hosts/`@@allow`/`*.wildcard`, суффиксное дерево,
//!   NXDOMAIN или null-address по выбору, атомарная перезагрузка.
//! - **Overrides**: A/AAAA/CNAME, приоритет выше blocklist и upstream.
//! - **DNSSEC** (опционально): цепочка DS → DNSKEY → RRSIG через
//!   `pulse-dnssec`, AD-бит, SERVFAIL на BOGUS, NSEC/NSEC3 proofs.
//!
//! # Пример
//!
//! ```no_run
//! use std::net::{Ipv4Addr, SocketAddr};
//!
//! use pulse_dns::{Name, Rtype, Ttl};
//! use pulse_resolver::{Override, Resolver, ResolverConfig};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut config = ResolverConfig::forward(vec![
//!     "1.1.1.1:53".parse::<SocketAddr>()?,
//!     "8.8.8.8:53".parse::<SocketAddr>()?,
//! ]);
//! config.overrides.push(Override::a(
//!     Name::parse("router.home")?,
//!     Ttl::new(60)?,
//!     Ipv4Addr::new(192, 168, 1, 1),
//! ));
//! let resolver = Resolver::new(config)?;
//! let response = resolver.resolve_qname(&Name::parse("router.home")?, Rtype::A);
//! assert_eq!(response.answers().len(), 1);
//! # Ok(())
//! # }
//! ```
//!
//! # Ограничения MVP
//!
//! - Нет DoQ и io_uring: транспорт блокирующий UDP/TCP/DoT/DoH.
//! - DoH-клиент поддерживает только HTTP/1.1 и `Content-Length`; chunked и
//!   HTTP/2/3 не реализованы.
//! - `ANY` и трансферы получают `NOTIMP` (антиамплификация).
//! - DNSSEC без RRSIG считается insecure (см. модуль `dnssec`).
//! - Приватные адреса в ответах не фильтруются (SEC-RES-010, вне v1).
//! - DoT/DoH-upstream держат пул keep-alive-соединений (`ResolverConfig::pool`,
//!   по умолчанию 4): последовательные запросы переиспользуют соединение,
//!   параллельные занимают до `size` слотов, при обрыве — переподключение с
//!   cooldown/backoff. DoH по-прежнему только HTTP/1.1.

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
    clippy::too_many_lines,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::items_after_statements,
    clippy::return_self_not_must_use,
    clippy::option_if_let_else,
    clippy::manual_let_else,
    clippy::struct_excessive_bools
)]

pub mod blocklist;
pub mod cache;
pub mod config;
mod dnssec;
pub mod error;
mod forward;
mod iterative;
pub mod overrides;
mod resolver;
pub mod root_hints;
mod rrutil;
mod upstream;

pub use blocklist::{Blocklist, BlocklistError, BlocklistStats};
pub use cache::{Cache, CacheSnapshot};
pub use config::{
    BlockResponse, BlocklistConfig, CacheConfig, DnssecConfig, ForwardConfig, HttpsUpstream,
    IterativeConfig, Mode, Override, ResolverConfig, TimeoutConfig, TlsUpstream, TrustAnchorConfig,
    UpstreamConfig, UpstreamPoolConfig,
};
pub use error::ResolverError;
pub use overrides::{OverrideOutcome, Overrides};
pub use resolver::{
    CancellationToken, ResolveContext, ResolvedResponse, Resolver, ResponseMeta, StatsSnapshot,
    UpstreamStatus,
};
pub use upstream::UpstreamStats;
