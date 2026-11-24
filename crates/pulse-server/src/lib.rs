//! Authoritative serving: DNS ответы поверх доменной модели `pulse-dns`.
//!
//! Крейт содержит **чистую** логику авторитетного ответа: поиск в зоне через
//! порт [`ZoneView`], композицию CNAME/DNAME/wildcard/referral, негативные
//! ответы, политику EDNS0 и усечение по транспорту. Сетевого ввода-вывода и
//! хранилища здесь нет: зону предоставляет адаптер (in-memory реализация для
//! тестов — `testkit::InMemoryZone`, позже — `pulse-zonefile`).
//!
//! # Состав
//!
//! - [`domain`] — доменные типы ответа: [`domain::LookupOutcome`],
//!   [`domain::ZoneState`].
//! - [`application`] — порт [`application::ZoneView`], движок
//!   [`application::QueryEngine`] и счётчики [`application::QueryStats`].
//! - [`dnssec`] — подпись зоны (DNSKEY/NSEC/RRSIG) и NSEC-цепочка.
//! - `testkit` — in-memory зона (feature `testkit`, включена по умолчанию).
//!
//! # Политики
//!
//! - **ANY** — минимальный ответ по RFC 8482: синтезированный `HINFO`
//!   (`CPU = "RFC8482"`, пустой `OS`) для существующего имени; TTL по
//!   умолчанию 3600 и настраивается через
//!   [`application::EngineConfig::any_hinfo_ttl`]. Для реального владельца
//!   `CNAME` возвращается сам `CNAME` (RFC 8482 §4.2). Wildcard-CNAME
//!   синтезируется только если имени `QNAME` не существует; существующее
//!   имя, включая apex и empty non-terminal, получает `HINFO`.
//! - **DNAME** — поддерживается (RFC 6672): синтез `CNAME` и продолжение
//!   разбора цели внутри зоны; переполнение имени при синтезе → `YXDOMAIN`.
//!   `DNAME` в apex не применяется и отвергается `InMemoryZone` (INV-6).
//! - **Циклы CNAME/DNAME** — обнаруженный цикл даёт `SERVFAIL`
//!   (BIND-совместимо); лимит цепочки 16 остаётся для нециклических цепочек.
//! - **Эхо 0x20** — регистр `QNAME` пока не сохраняется: `pulse_dns::Name`
//!   канонизирует имя в нижний регистр, поэтому в ответе вопрос уходит в
//!   каноническом виде. Это документированный gap (SEC-DNS-011) до появления
//!   транспорта, который сохраняет сырые байты запроса.
//! - **RRSIG** — при `DO = 1` подписи прикладываются к answer/authority/
//!   additional через [`application::ZoneView::lookup_all_rrsig`], включая
//!   негативные ответы; при `DO = 0` подписи не отдаются. `AD` на
//!   authoritative-сервере всегда `0`. Для подписанных зон негативные ответы
//!   дополняются denial-записями + RRSIG по политике зоны: NSEC (покрытие
//!   QNAME и wildcard, NSEC самого имени) или NSEC3 (closest encloser,
//!   next closer, wildcard, DS-NODATA).
//! - **CNAME → делегирование** — если цель `CNAME`/`DNAME` находится ниже
//!   zone cut, цепочка останавливается на уже собранном ответе: клиент или
//!   резолвер получит referral отдельным запросом.
//! - **Negative TTL** — `min(SOA.ttl, SOA.minimum, 10800)` (INV-14).
//! - **EDNS** — `OPT` эхо-ится с payload `min(max(client, 512), 1232)`
//!   (значения ниже 512 трактуются как 512 по RFC 6891 §6.2.5); версия ≠ 0 →
//!   `BADVERS`; неизвестные опции безопасно игнорируются (SEC-DNS-007).
//! - **Рекурсия** — не обслуживается: `RA = 0`, `RD` эхо-ится, запрос вне
//!   обслуживаемых зон получает `REFUSED` (SEC-DNS-009). Класс, отличный от
//!   класса зоны (кроме `QCLASS = ANY`), и зона не в `Serving` — тоже
//!   `REFUSED`.
//! - **Трансферы** — `AXFR`/`IXFR`/`TSIG`/`TKEY`/`OPT` в `QTYPE` получают
//!   `NOTIMP`: транспорт и zone transfer вне этого этапа; динамические
//!   обновления (`UPDATE`) и `NOTIFY` — тоже `NOTIMP` до реализации
//!   репликации.
//!
//! # Пример
//!
//! ```
//! # #[cfg(feature = "testkit")]
//! # fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use std::sync::Arc;
//! use pulse_dns::{Message, Name, Question, Rclass, Rtype, Ttl, Rdata, Rrset};
//! use pulse_server::application::{QueryEngine, Transport};
//! use pulse_server::testkit::InMemoryZone;
//!
//! let origin = Name::parse("example.com")?;
//! let mut zone = InMemoryZone::new(origin.clone());
//! zone.insert(Rrset::new(
//!     origin.clone(),
//!     Rtype::A,
//!     Rclass::IN,
//!     Ttl::new(300)?,
//!     [Rdata::A("192.0.2.1".parse()?)],
//! )?)?;
//!
//! let engine = QueryEngine::new(vec![Arc::new(zone)]);
//! let query = Message::query(
//!     0x1234,
//!     Question::new(origin, Rtype::A, Rclass::IN),
//! );
//! let response = engine.respond(&query, Transport::Udp);
//! assert_eq!(response.id(), 0x1234);
//! assert_eq!(response.answers().len(), 1);
//! # Ok(())
//! # }
//! # #[cfg(feature = "testkit")]
//! # assert!(run().is_ok());
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
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::doc_markdown)]

pub mod application;
pub mod dnssec;
pub mod domain;
#[cfg(feature = "testkit")]
pub mod testkit;

pub use application::{
    EngineConfig, NEGATIVE_TTL_CAP, QueryEngine, QueryError, QueryStats, StatsSnapshot, Transport,
    ZoneView,
};
pub use domain::{DenialKind, LookupOutcome, ZoneState};
