//! Shared kernel `pulse-dns`: доменные типы DNS и wire-format.
//!
//! Крейт реализует протокольную часть системы (RFC 1035, 2181, 1982, 3597,
//! 4034, 6891, 8945) и не содержит I/O, async или зависимостей от других
//! крейтов workspace. Все конструкторы валидируют входные данные, а декодер
//! wire-формата не паникует на произвольных байтах.
//!
//! # Состав
//!
//! - [`domain`] — `Name`, `Rtype`, `Rclass`, `Ttl`, `Serial`, `Rdata`,
//!   `Record`, `Rrset`, `Question`, `Message`.
//! - [`wire`] — кодирование/декодирование пакетов, EDNS0 (OPT) и лимиты.
//! - [`canonical`] — каноническая форма для DNSSEC (RFC 4034 §6).
//!
//! # Пример
//!
//! ```
//! use pulse_dns::domain::{Message, Name, Question, Rclass, Rtype};
//! use pulse_dns::wire::{DecodeLimits, EncodeOptions};
//!
//! let name = Name::parse("example.com").unwrap();
//! let question = Question::new(name, Rtype::A, Rclass::IN);
//! let query = Message::query(0x1234, question);
//!
//! let bytes = query.encode(&EncodeOptions::default()).unwrap();
//! let decoded = Message::decode(&bytes, &DecodeLimits::default()).unwrap();
//! assert_eq!(decoded.id(), 0x1234);
//! assert_eq!(decoded.questions().len(), 1);
//! ```
//!
//! # Лимиты
//!
//! Все лимиты из ADR 0004 (SEC-DNS-001…003) заданы константами в
//! [`wire`] и применяются как декодером, так и конструкторами.

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

pub mod canonical;
pub mod domain;
pub mod wire;

pub use domain::{
    CaaTag, Class, DnskeyData, DsData, Edns, EdnsError, EdnsOption, Flags, Header, MAX_LABEL_LEN,
    MAX_LABELS, MAX_NAME_TEXT_LEN, MAX_NAME_WIRE_LEN, MAX_RRSET_RECORDS, Message, Name, NameError,
    NameRef, Nsec3Data, Nsec3ParamData, NsecData, Opcode, Question, Rclass, Rcode, Rdata,
    RdataError, Record, RecordError, RrType, Rrset, RrsetError, RrsigData, Rtype, Serial, SoaData,
    SvcParam, SvcbData, TTL_MAX, TlsaData, Ttl, TtlError, TxtData, TypeBitmap, name_cmp,
};
pub use wire::{
    Checkpoint, DecodeError, DecodeLimits, EDNS_DEFAULT_PAYLOAD, EDNS_MAX_PAYLOAD, EncodeError,
    EncodeOptions, EncodeScratch, Encoder, HeaderCounts, MAX_COMPRESSION_POINTERS, MAX_MESSAGE_LEN,
    MAX_RECORDS, MAX_UDP_PAYLOAD, MessageRef, edns_wire_len,
};
