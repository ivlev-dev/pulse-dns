//! `pulse-master`: разбор и сериализация master-файлов зон (RFC 1035 §5.1).
//!
//! Крейт читает BIND-совместимые zone-файлы в доменные [`pulse_dns::Record`],
//! проверяет инварианты зоны и умеет печатать записи обратно в стабильный
//! текст для export и round-trip.
//!
//! # Возможности
//!
//! - строки, комментарии `;`, группировка `(...)`, кавычки с escape `\DDD`/`\X`;
//! - `$ORIGIN`, `$TTL`, `$INCLUDE` (с ограничением каталога, глубины и циклов);
//! - наследование owner/class/TTL между строками;
//! - RDATA: A, AAAA, NS, CNAME, DNAME, PTR, MX, TXT, SOA, SRV, CAA, DS,
//!   DNSKEY, RRSIG, NSEC/NSEC3/NSEC3PARAM, TLSA, SVCB/HTTPS и RFC 3597
//!   `\# <len> <hex>`;
//! - ошибки с именем файла, строкой и колонкой; TTL при импорте clamp'ится
//!   с предупреждением (INV-3).
//!
//! `$GENERATE` намеренно не поддерживается и возвращает явную ошибку.
//!
//! # Пример
//!
//! ```
//! use pulse_dns::Name;
//! use pulse_master::{parse_zone, to_text, TextOptions};
//!
//! let text = "\
//! $ORIGIN example.com.
//! $TTL 3600
//! @ IN SOA ns1 hostmaster 2026010101 7200 900 1209600 300
//! @ IN NS ns1
//! ns1 IN A 192.0.2.53
//! ";
//! let zone = parse_zone(Name::parse("example.com.").unwrap(), text).unwrap();
//! assert_eq!(zone.records.len(), 3);
//! assert_eq!(zone.default_ttl.unwrap().as_u32(), 3600);
//!
//! let exported = to_text(
//!     &zone.records,
//!     &TextOptions {
//!         origin: Some(zone.origin.clone()),
//!         default_ttl: zone.default_ttl,
//!         sort: false,
//!     },
//! );
//! let reparsed = parse_zone(zone.origin.clone(), &exported).unwrap();
//! assert_eq!(reparsed.records, zone.records);
//! ```
//!
//! # Ограничения
//!
//! - только класс `IN` (INV-10);
//! - `$INCLUDE` требует явного [`ParseOptions::include_root`];
//! - имена в RDATA и владельцы всегда канонизируются в нижний регистр
//!   доменом [`pulse_dns::Name`].

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
    clippy::similar_names
)]

mod codec;
mod error;
mod format;
mod lexer;
mod limits;
mod name;
mod parser;
mod present;
mod rdata;
mod ttl;

pub use error::{ErrorKind, Location, ParseError, Warning, WarningKind};
pub use format::{TextOptions, to_text};
pub use limits::Limits;
pub use parser::{
    ParseOptions, ParsedZone, parse_zone, parse_zone_fragment, parse_zone_fragment_with_options,
    parse_zone_with_options,
};
