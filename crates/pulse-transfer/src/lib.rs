//! `pulse-transfer`: TSIG, AXFR/IXFR и NOTIFY поверх `pulse-dns`.
//!
//! Крейт реализует протокольные механизмы репликации зон:
//!
//! - **TSIG** (RFC 8945): HMAC-SHA1/224/256/384/512. HMAC-MD5 и неизвестные
//!   алгоритмы отвергаются с [`TsigError::UnsupportedAlgorithm`]. MAC
//!   constant-time, время `±fudge`, replay-cache, multi-message MAC chain для
//!   AXFR/IXFR.
//! - **AXFR** (RFC 5936): клиент и сервер поверх синхронных `Read + Write`
//!   с TCP length-prefix, SOA first/last, лимитами и TSIG.
//! - **IXFR** (RFC 1995): дельты, история версий, fallback на AXFR,
//!   проверка последовательности serial по RFC 1982.
//! - **NOTIFY** (RFC 1996): запрос/ответ, qtype SOA, ACL source/zone, TSIG.
//!
//! # Транспорт
//!
//! Крейт не зависит от `TcpStream`: [`AxfrClient`], [`AxfrServer`],
//! [`IxfrClient`], [`IxfrServer`] принимают любой тип, реализующий
//! [`std::io::Read`] и [`std::io::Write`]. Таймаут в [`TransferLimits`]
//! проверяется между операциями; для блокирующих сокетов дополнительно
//! настройте `set_read_timeout`/`set_write_timeout`.
//!
//! # Безопасность
//!
//! - HMAC-SHA256 — алгоритм по умолчанию; SHA-512 допустим.
//! - Секрет TSIG zeroize-ится, `Debug` ключа не содержит секрета.
//! - HMAC-MD5 не поддерживается; legacy — только SHA1+ (по RFC 8945 SHA1
//!   допустим для совместимости, но не рекомендуется).
//! - Сервер AXFR/IXFR требует TSIG (`TransferConfig::require_tsig`); ACL
//!   проверяется вызывающим слоем. NOTIFY имеет [`NotifyPolicy`] с ACL
//!   source/zone (SEC-REP-001/002).
//!
//! # Пример AXFR-сессии
//!
//! ```no_run
//! use std::error::Error;
//! use std::net::TcpStream;
//!
//! use pulse_dns::Name;
//! use pulse_transfer::AxfrClient;
//!
//! # fn main() -> Result<(), Box<dyn Error>> {
//! let origin = Name::parse("example.com")?;
//! let mut stream = TcpStream::connect("127.0.0.1:53")?;
//! let mut client = AxfrClient::new(stream);
//! let zone = client.transfer(&origin, 0x1234, None, 1_700_000_000)?;
//! println!("{} records", zone.records().len());
//! # Ok(())
//! # }
//! ```
//!
//! # Лимиты
//!
//! Все трансферы ограничены [`TransferLimits`] (число записей/байтов/
//! сообщений и таймаут). Декодер `pulse-dns` не паникует на враждебном
//! вводе; этот крейт также не использует `unsafe` и не паникует.

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
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::too_many_lines,
    clippy::struct_excessive_bools,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::items_after_statements,
    clippy::many_single_char_names,
    clippy::single_match_else,
    clippy::unnecessary_wraps
)]

mod net;
mod raw;
mod server;
mod stream;

pub mod axfr;
pub mod error;
pub mod ixfr;
pub mod notify;
pub mod tsig;
pub mod zone;

pub use axfr::{AxfrClient, AxfrServer, build_axfr_query, build_signed_axfr_query};
pub use error::{LimitKind, TransferError, TsigError, TsigErrorCode};
pub use ixfr::{
    IxfrClient, IxfrOutcome, IxfrServer, ZoneDelta, ZoneHistory, apply_ixfr, build_ixfr_query,
};
pub use net::{read_message, write_message};
pub use notify::{
    EncodedNotify, NotifyIgnoreReason, NotifyOutcome, NotifyPolicy, NotifyRequest, NotifyResponse,
    NotifyServer,
};
pub use server::TransferStats;
pub use tsig::{
    TsigAlgorithm, TsigEnvelope, TsigKey, TsigKeyPolicy, TsigRecord, TsigReplayCache,
    TsigSignParams, TsigStreamVerifier, VerifiedTsig, append_tsig, build_tsig_error_response,
    encode_u48, parse_tsig,
};
pub use zone::{TransferConfig, TransferLimits, ZoneSnapshot, apply_deltas, soa_serial};
