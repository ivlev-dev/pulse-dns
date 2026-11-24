//! Типизированные ошибки TSIG и трансферов зон.

use std::fmt;
use std::io;

use pulse_dns::{DecodeError, EncodeError, NameError, Rcode, RdataError, RecordError};
use thiserror::Error;

/// Значение поля `Error` в TSIG RR (RFC 8945 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct TsigErrorCode(u16);

impl TsigErrorCode {
    /// Ошибки нет.
    pub const NONE: Self = Self(0);
    /// MAC не совпал (16).
    pub const BADSIG: Self = Self(16);
    /// Ключ или алгоритм неизвестен (17).
    pub const BADKEY: Self = Self(17);
    /// Время подписи вне допустимого окна (18).
    pub const BADTIME: Self = Self(18);
    /// Усечение MAC недопустимо для локальной политики (22).
    pub const BADTRUNC: Self = Self(22);

    /// Создаёт код из wire-значения.
    #[must_use]
    pub const fn from_u16(value: u16) -> Self {
        Self(value)
    }

    /// Wire-значение.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Является ли код ошибкой.
    #[must_use]
    pub const fn is_error(self) -> bool {
        self.0 != 0
    }
}

impl fmt::Display for TsigErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self.0 {
            0 => "NOERROR",
            16 => "BADSIG",
            17 => "BADKEY",
            18 => "BADTIME",
            22 => "BADTRUNC",
            other => return write!(f, "TSIG-ERROR-{other}"),
        };
        f.write_str(name)
    }
}

impl From<u16> for TsigErrorCode {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

/// Ошибка TSIG-операции.
#[derive(Debug, Error)]
pub enum TsigError {
    /// Алгоритм TSIG не поддерживается.
    #[error(
        "unsupported TSIG algorithm {name}; supported: hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha384, hmac-sha512"
    )]
    UnsupportedAlgorithm {
        /// Имя алгоритма из TSIG.
        name: String,
    },
    /// Секрет ключа пуст.
    #[error("TSIG secret must not be empty")]
    EmptySecret,
    /// Имя ключа в TSIG не совпало с ожидаемым.
    #[error("TSIG key name mismatch: expected {expected}, got {actual}")]
    KeyNameMismatch {
        /// Ожидаемое имя.
        expected: String,
        /// Полученное имя.
        actual: String,
    },
    /// Алгоритм в TSIG не совпал с ожидаемым.
    #[error("TSIG algorithm mismatch: expected {expected}, got {actual}")]
    AlgorithmMismatch {
        /// Ожидаемый алгоритм.
        expected: String,
        /// Полученный алгоритм.
        actual: String,
    },
    /// MAC не совпал.
    #[error("TSIG MAC verification failed")]
    BadSig,
    /// MAC пуст там, где подпись обязательна.
    #[error("TSIG MAC is empty")]
    Unsigned,
    /// MAC короче минимально допустимого.
    #[error("TSIG MAC is {len} octets (minimum {minimum})")]
    MacTooShort {
        /// Длина MAC.
        len: usize,
        /// Минимум.
        minimum: usize,
    },
    /// MAC длиннее выхода алгоритма.
    #[error("TSIG MAC is {len} octets (algorithm produces {maximum})")]
    MacTooLong {
        /// Длина MAC.
        len: usize,
        /// Выход алгоритма.
        maximum: usize,
    },
    /// Недопустимая длина усечения при подписи.
    #[error(
        "invalid TSIG truncation length {len} (algorithm produces {maximum}, minimum {minimum})"
    )]
    InvalidTruncation {
        /// Запрошенная длина.
        len: usize,
        /// Минимум.
        minimum: usize,
        /// Максимум.
        maximum: usize,
    },
    /// Время подписи вне окна fudge.
    #[error("TSIG time {signed} is outside +/-{fudge} seconds of {now}")]
    TimeSkew {
        /// Локальное время.
        now: u64,
        /// Время в TSIG.
        signed: u64,
        /// Допуск.
        fudge: u16,
    },
    /// Полученный fudge больше локального максимума.
    #[error("TSIG fudge {received} exceeds local maximum {maximum}")]
    FudgeTooLarge {
        /// Полученный fudge.
        received: u16,
        /// Максимум.
        maximum: u16,
    },
    /// Повторное или устаревшее сообщение.
    #[error("TSIG replay detected for key {key}: time {time} is not newer than {previous}")]
    Replay {
        /// Имя ключа.
        key: String,
        /// Время сообщения.
        time: u64,
        /// Ранее принятое время.
        previous: u64,
    },
    /// Original ID не совпал с ожидаемым.
    #[error("TSIG original ID {actual} does not match expected {expected}")]
    OriginalIdMismatch {
        /// Ожидаемый ID.
        expected: u16,
        /// ID из TSIG.
        actual: u16,
    },
    /// Время не помещается в 48 бит.
    #[error("TSIG time {value} does not fit into 48 bits")]
    InvalidTime {
        /// Значение.
        value: u64,
    },
    /// Структура TSIG нарушена.
    #[error("malformed TSIG: {reason}")]
    Malformed {
        /// Причина.
        reason: &'static str,
    },
    /// TSIG отсутствует, хотя обязателен.
    #[error("TSIG record is required")]
    Missing,
    /// TSIG присутствует, хотя не ожидался.
    #[error("unexpected TSIG record")]
    Unexpected,
    /// Закодированное сообщение не помещается в TCP-кадр.
    #[error("signed message is too large ({len} octets)")]
    MessageTooLarge {
        /// Длина.
        len: usize,
    },
    /// Ошибка декодирования DNS.
    #[error(transparent)]
    Decode(#[from] DecodeError),
    /// Ошибка кодирования DNS.
    #[error(transparent)]
    Encode(#[from] EncodeError),
    /// Ошибка записи.
    #[error(transparent)]
    Record(#[from] RecordError),
    /// Ошибка RDATA.
    #[error(transparent)]
    Rdata(#[from] RdataError),
    /// Ошибка имени.
    #[error(transparent)]
    Name(#[from] NameError),
}

impl TsigError {
    /// Соответствующий код поля TSIG `Error`, если ошибка протокольная.
    #[must_use]
    pub const fn error_code(&self) -> Option<TsigErrorCode> {
        match self {
            Self::KeyNameMismatch { .. }
            | Self::AlgorithmMismatch { .. }
            | Self::UnsupportedAlgorithm { .. }
            | Self::Missing => Some(TsigErrorCode::BADKEY),
            Self::BadSig | Self::Unsigned | Self::OriginalIdMismatch { .. } => {
                Some(TsigErrorCode::BADSIG)
            }
            Self::MacTooShort { .. } | Self::MacTooLong { .. } | Self::InvalidTruncation { .. } => {
                Some(TsigErrorCode::BADTRUNC)
            }
            Self::TimeSkew { .. } | Self::FudgeTooLarge { .. } | Self::Replay { .. } => {
                Some(TsigErrorCode::BADTIME)
            }
            Self::EmptySecret
            | Self::InvalidTime { .. }
            | Self::Malformed { .. }
            | Self::Unexpected
            | Self::MessageTooLarge { .. }
            | Self::Decode(_)
            | Self::Encode(_)
            | Self::Record(_)
            | Self::Rdata(_)
            | Self::Name(_) => None,
        }
    }
}

/// Вид исчерпанного лимита.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LimitKind {
    /// Число записей.
    Records,
    /// Число байтов.
    Bytes,
    /// Число сообщений.
    Messages,
    /// Число дельт IXFR.
    Deltas,
}

impl fmt::Display for LimitKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Records => "records",
            Self::Bytes => "bytes",
            Self::Messages => "messages",
            Self::Deltas => "deltas",
        };
        f.write_str(name)
    }
}

/// Ошибка трансфера, NOTIFY или разбора зоны.
#[derive(Debug, Error)]
pub enum TransferError {
    /// Ошибка TSIG.
    #[error(transparent)]
    Tsig(#[from] TsigError),
    /// Ошибка декодирования DNS.
    #[error(transparent)]
    Decode(#[from] DecodeError),
    /// Ошибка кодирования DNS.
    #[error(transparent)]
    Encode(#[from] EncodeError),
    /// Ошибка ввода-вывода.
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    /// Нарушение протокола.
    #[error("protocol error: {reason}")]
    Protocol {
        /// Причина.
        reason: &'static str,
    },
    /// Нарушение инвариантов зоны.
    #[error("zone error: {reason}")]
    Zone {
        /// Причина.
        reason: &'static str,
    },
    /// Нарушение последовательности serial.
    #[error("serial error: {reason}")]
    Serial {
        /// Причина.
        reason: &'static str,
    },
    /// Исчерпан лимит.
    #[error("limit {kind} exceeded: {value} > {limit}")]
    Limit {
        /// Вид лимита.
        kind: LimitKind,
        /// Фактическое значение.
        value: u64,
        /// Лимит.
        limit: u64,
    },
    /// Таймаут трансфера.
    #[error("transfer timed out")]
    Timeout,
    /// Сервер вернул ошибку.
    #[error("server returned {rcode}")]
    Server {
        /// DNS RCODE.
        rcode: Rcode,
        /// Код TSIG `Error`, если был.
        tsig_error: Option<TsigErrorCode>,
    },
    /// Сообщение не помещается в TCP-кадр.
    #[error("message is too large ({len} octets)")]
    MessageTooLarge {
        /// Длина.
        len: usize,
    },
    /// Трансфер оборвался до завершения.
    #[error("incomplete transfer: {reason}")]
    Truncated {
        /// Причина.
        reason: &'static str,
    },
    /// Ошибка записи.
    #[error(transparent)]
    Record(#[from] RecordError),
    /// Ошибка RDATA.
    #[error(transparent)]
    Rdata(#[from] RdataError),
    /// Ошибка имени.
    #[error(transparent)]
    Name(#[from] NameError),
}

impl TransferError {
    /// Создаёт ошибку нарушения протокола.
    #[must_use]
    pub const fn protocol(reason: &'static str) -> Self {
        Self::Protocol { reason }
    }

    /// Создаёт ошибку зоны.
    #[must_use]
    pub const fn zone(reason: &'static str) -> Self {
        Self::Zone { reason }
    }

    /// Создаёт ошибку serial.
    #[must_use]
    pub const fn serial(reason: &'static str) -> Self {
        Self::Serial { reason }
    }

    /// Создаёт ошибку лимита.
    #[must_use]
    pub fn limit(kind: LimitKind, value: u64, limit: u64) -> Self {
        Self::Limit { kind, value, limit }
    }
}
