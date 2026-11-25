//! Wire-format: кодирование и декодирование DNS-пакетов.
//!
//! Лимиты соответствуют ADR 0004 §2 (SEC-DNS-001…005):
//!
//! - сообщение — не более 65535 октетов;
//! - имя — не более 255 октетов, метка — 1..=63;
//! - цепочка указателей сжатия — не более 128, указатель строго назад;
//! - записей в сообщении — не более 4096.
//!
//! Декодер не паникует и не зацикливается на враждебном вводе: все чтения
//! выполняются через проверяемые `get`-операции.

use std::io;

use thiserror::Error;

use crate::domain::{NameError, RdataError, Rtype};

pub(crate) mod decode;
pub(crate) mod encode;
mod message_ref;
pub(crate) mod rdata;

pub use encode::{Checkpoint, EncodeScratch, Encoder, HeaderCounts, edns_wire_len};
pub use message_ref::MessageRef;

/// Максимальная длина DNS-сообщения (TCP, RFC 1035 §4.2.2).
pub const MAX_MESSAGE_LEN: usize = 65_535;
/// Максимальное число указателей сжатия в одной цепочке (SEC-DNS-002).
pub const MAX_COMPRESSION_POINTERS: usize = 128;
/// Максимальное число записей в сообщении (SEC-DNS-003).
pub const MAX_RECORDS: usize = 4096;
/// UDP payload без EDNS0 (RFC 1035).
pub const MAX_UDP_PAYLOAD: usize = 512;
/// Рекомендуемый EDNS0 UDP payload (SEC-DNS-001).
pub const EDNS_DEFAULT_PAYLOAD: u16 = 1232;
/// Верхняя граница EDNS0 UDP payload, которую обслуживает сервер.
pub const EDNS_MAX_PAYLOAD: u16 = 4096;

/// Ошибка декодирования wire-формата.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DecodeError {
    /// Сообщение длиннее 65535 октетов.
    #[error("message is {len} octets long (max {MAX_MESSAGE_LEN})")]
    MessageTooLong {
        /// Фактическая длина.
        len: usize,
    },
    /// Недостаточно байтов для поля.
    #[error("truncated message at offset {offset} while reading {field}")]
    Truncated {
        /// Позиция в сообщении.
        offset: usize,
        /// Имя поля.
        field: &'static str,
    },
    /// Имя длиннее 255 октетов.
    #[error("name at offset {offset} exceeds {max} octets")]
    NameTooLong {
        /// Начало имени.
        offset: usize,
        /// Максимум.
        max: usize,
    },
    /// Недопустимый октет в позиции длины метки.
    #[error("invalid label type 0x{value:02x} at offset {offset}")]
    BadLabelType {
        /// Позиция.
        offset: usize,
        /// Октет.
        value: u8,
    },
    /// Указатель сжатия указывает вперёд или на себя (SEC-DNS-002).
    #[error(
        "compression pointer at offset {offset} points to {target} (must be strictly backward)"
    )]
    ForwardPointer {
        /// Позиция указателя.
        offset: usize,
        /// Цель указателя.
        target: usize,
    },
    /// Указатель сжатия указывает в DNS-заголовок.
    #[error("compression pointer at offset {offset} points into the header ({target})")]
    PointerIntoHeader {
        /// Позиция указателя.
        offset: usize,
        /// Цель указателя.
        target: usize,
    },
    /// Указатель сжатия указывает не на начало метки/сжатого имени.
    #[error(
        "compression pointer at offset {offset} targets {target}, which is not a known label/name start"
    )]
    PointerNotLabelStart {
        /// Позиция указателя.
        offset: usize,
        /// Цель указателя.
        target: usize,
    },
    /// Слишком длинная цепочка указателей.
    #[error("compression pointer chain at offset {offset} exceeds {limit} pointers")]
    TooManyPointers {
        /// Позиция, где превышен лимит.
        offset: usize,
        /// Лимит.
        limit: usize,
    },
    /// Имя не проходит доменную валидацию.
    #[error("invalid name at offset {offset}: {source}")]
    InvalidName {
        /// Начало имени.
        offset: usize,
        /// Причина.
        #[source]
        source: NameError,
    },
    /// Превышен лимит записей в секции.
    #[error("section {section} has {count} records (max {limit})")]
    RecordLimitExceeded {
        /// Секция.
        section: &'static str,
        /// Количество.
        count: usize,
        /// Лимит.
        limit: usize,
    },
    /// RDLENGTH выходит за границы сообщения.
    #[error("rdata at offset {offset} with length {len} exceeds remaining {remaining} bytes")]
    RdataOutOfBounds {
        /// Позиция RDATA.
        offset: usize,
        /// RDLENGTH.
        len: usize,
        /// Остаток сообщения.
        remaining: usize,
    },
    /// RDATA короче, чем требует формат.
    #[error("rdata for {rr_type} is truncated while reading {field}")]
    RdataTruncated {
        /// Тип записи.
        rr_type: Rtype,
        /// Поле.
        field: &'static str,
    },
    /// RDATA не проходит валидацию.
    #[error("invalid rdata for {rr_type}: {source}")]
    RdataInvalid {
        /// Тип записи.
        rr_type: Rtype,
        /// Причина.
        #[source]
        source: RdataError,
    },
    /// В RDATA остались непрочитанные байты.
    #[error("rdata for {rr_type} has trailing bytes at offset {offset}")]
    RdataTrailing {
        /// Тип записи.
        rr_type: Rtype,
        /// Позиция.
        offset: usize,
    },
    /// Более одного OPT в сообщении.
    #[error("duplicate OPT record")]
    DuplicateOpt,
    /// OPT вне additional.
    #[error("OPT record is only allowed in the additional section")]
    OptOutsideAdditional,
    /// OPT с непустым owner.
    #[error("OPT owner name must be root")]
    OptOwnerNotRoot,
    /// OPT не может быть RDATA.
    #[error("OPT is a pseudo-record and cannot appear as RDATA")]
    OptAsRdata,
    /// Усечённая EDNS0-опция.
    #[error("truncated EDNS0 option at offset {offset}")]
    OptTruncated {
        /// Позиция опции.
        offset: usize,
    },
    /// Некорректный OPT (bounds уже проверены, но поле не сходится).
    #[error("invalid OPT record: {reason}")]
    InvalidOpt {
        /// Причина.
        reason: &'static str,
    },
    /// RDATA длиннее 65535 октетов.
    #[error("rdata is {len} octets long (max 65535)")]
    RdataTooLong {
        /// Фактическая длина.
        len: usize,
    },
    /// После последней секции остались лишние байты.
    #[error("trailing bytes after DNS message at offset {offset}")]
    TrailingBytes {
        /// Первый лишний байт.
        offset: usize,
    },
}

/// Ошибка кодирования wire-формата.
#[derive(Debug, Error)]
pub enum EncodeError {
    /// Итоговое сообщение длиннее 65535.
    #[error("encoded message is {len} octets long (max {MAX_MESSAGE_LEN})")]
    MessageTooLong {
        /// Фактическая длина.
        len: usize,
    },
    /// Слишком много записей/вопросов в секции.
    #[error("section {section} has {count} entries (max {max})")]
    SectionTooLarge {
        /// Секция.
        section: &'static str,
        /// Количество.
        count: usize,
        /// Максимум.
        max: usize,
    },
    /// RDATA длиннее 65535.
    #[error("rdata for {rr_type} is {len} octets long (max 65535)")]
    RdataTooLong {
        /// Тип записи.
        rr_type: Rtype,
        /// Длина.
        len: usize,
    },
    /// RDATA не проходит доменную валидацию.
    #[error("invalid rdata for {rr_type}: {source}")]
    InvalidRdata {
        /// Тип записи.
        rr_type: Rtype,
        /// Причина.
        #[source]
        source: RdataError,
    },
    /// Тип RR не совпадает с типом RDATA.
    #[error("rdata type {actual} does not match record type {declared}")]
    RecordTypeMismatch {
        /// Тип из заголовка RR.
        declared: Rtype,
        /// Тип RDATA.
        actual: Rtype,
    },
    /// Целевой срез меньше, чем нужно для сообщения.
    #[error("buffer of {capacity} octets is too small (needs at least {needed})")]
    BufferTooSmall {
        /// Размер переданного буфера.
        capacity: usize,
        /// Минимальная требуемая длина (нижняя оценка на момент отказа).
        needed: usize,
    },
    /// Ошибка записи в целевой поток.
    #[error("i/o error while writing message: {0}")]
    Io(#[from] io::Error),
    /// Внутренняя ошибка построения буфера (не должна возникать).
    #[error("internal encoder error: {reason}")]
    Internal {
        /// Причина.
        reason: &'static str,
    },
}

/// Опции кодирования.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodeOptions {
    /// Использовать компрессию имён (RFC 1035 §4.1.4).
    pub compress_names: bool,
}

impl EncodeOptions {
    /// Кодирование с компрессией (по умолчанию).
    #[must_use]
    pub const fn compressed() -> Self {
        Self {
            compress_names: true,
        }
    }

    /// Кодирование без компрессии (каноническая wire-форма).
    #[must_use]
    pub const fn uncompressed() -> Self {
        Self {
            compress_names: false,
        }
    }
}

impl Default for EncodeOptions {
    fn default() -> Self {
        Self::compressed()
    }
}

/// Лимиты декодирования.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeLimits {
    /// Максимальное число записей во всех секциях (включая OPT).
    pub max_records: usize,
}

impl DecodeLimits {
    /// Лимиты по умолчанию ([`MAX_RECORDS`]).
    #[must_use]
    pub const fn default_limits() -> Self {
        Self {
            max_records: MAX_RECORDS,
        }
    }
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self::default_limits()
    }
}
