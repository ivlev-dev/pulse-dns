//! Типизированные ошибки DNSCrypt v2.
//!
//! Все операции крейта возвращают [`enum@Error`]; паники и `unwrap` в
//! библиотечном коде запрещены. Ошибки аутентификации намеренно не
//! различают причину (неверный ключ, MAC, сертификат), чтобы не давать
//! оракула.

use thiserror::Error;

/// Ошибка DNSCrypt-операции.
#[derive(Debug, Error)]
pub enum Error {
    /// Пакет короче структурного минимума.
    #[error("packet is {len} bytes, minimum is {min}")]
    PacketTooShort {
        /// Фактическая длина.
        len: usize,
        /// Требуемая длина.
        min: usize,
    },
    /// Пакет длиннее допустимого транспортом.
    #[error("packet is {len} bytes, maximum is {max}")]
    PacketTooLong {
        /// Фактическая длина.
        len: usize,
        /// Максимальная длина.
        max: usize,
    },
    /// `client-magic` не соответствует ни одному сертификату сервера.
    #[error("unknown client magic")]
    UnknownClientMagic,
    /// Магия сертификата не равна `DNSC`.
    #[error("certificate magic mismatch")]
    CertificateMagicMismatch,
    /// Версия криптографической конструкции не поддерживается.
    #[error("unsupported encryption system version {major}.{minor}")]
    UnsupportedEsVersion {
        /// Старший байт `es-version`.
        major: u8,
        /// Младший байт `es-version`.
        minor: u8,
    },
    /// Минорная версия протокола не поддерживается.
    #[error("unsupported protocol minor version {0}")]
    UnsupportedMinorVersion(u16),
    /// Сертификат короче фиксированной части.
    #[error("certificate is {len} bytes, minimum is {min}")]
    CertificateTooShort {
        /// Фактическая длина.
        len: usize,
        /// Минимальная длина.
        min: usize,
    },
    /// Сертификат длиннее допустимого.
    #[error("certificate is {len} bytes, maximum is {max}")]
    CertificateTooLong {
        /// Фактическая длина.
        len: usize,
        /// Максимальная длина.
        max: usize,
    },
    /// `ts-start >= ts-end`.
    #[error("certificate validity range is empty: start {start} >= end {end}")]
    InvalidValidityRange {
        /// Начало действия.
        start: u32,
        /// Конец действия.
        end: u32,
    },
    /// Сертификат ещё не вступил в силу.
    #[error("certificate is not valid yet: now {now} < start {start}")]
    CertificateNotYetValid {
        /// Текущее время Unix.
        now: u64,
        /// Начало действия.
        start: u32,
    },
    /// Сертификат истёк.
    #[error("certificate expired: now {now} > end {end}")]
    CertificateExpired {
        /// Текущее время Unix.
        now: u64,
        /// Конец действия.
        end: u32,
    },
    /// Подпись сертификата не прошла проверку.
    #[error("certificate signature verification failed")]
    InvalidCertificateSignature,
    /// `client-magic` начинается с семи нулевых байт (коллизия с QUIC).
    #[error("client magic must not start with seven zero bytes")]
    InvalidClientMagic,
    /// Два сертификата используют одну и ту же `client-magic`.
    #[error("duplicate client magic")]
    DuplicateClientMagic,
    /// Открытый ключ резолвера не совпадает с сертификатом.
    #[error("resolver key does not match certificate")]
    ResolverKeyMismatch,
    /// AEAD-аутентификация не прошла.
    #[error("authenticated decryption failed")]
    DecryptionFailed,
    /// AEAD-шифрование не удалось.
    #[error("encryption failed")]
    EncryptionFailed,
    /// Некорректное дополнение ISO/IEC 7816-4.
    #[error("invalid ISO/IEC 7816-4 padding")]
    InvalidPadding,
    /// Повторное использование клиентского nonce.
    #[error("replayed client nonce")]
    ReplayedNonce,
    /// Ответ не помещается в лимит транспорта.
    #[error("response needs {needed} bytes, transport limit is {max}")]
    ResponseTooLarge {
        /// Требуемое число байт.
        needed: usize,
        /// Допустимый лимит.
        max: usize,
    },
    /// Некорректный TCP-префикс длины.
    #[error("invalid TCP length-prefixed frame")]
    InvalidTcpFrame,
    /// Магия ответа не равна `r6fnvWj8`.
    #[error("resolver magic mismatch")]
    InvalidResolverMagic,
    /// Клиентская половина nonce в ответе не совпала с запросом.
    #[error("response nonce does not match the query nonce")]
    NonceMismatch,
    /// Ошибка декодирования DNS-сообщения.
    #[error("DNS decode failed: {0}")]
    DnsDecode(#[from] pulse_dns::DecodeError),
    /// Ошибка кодирования DNS-сообщения.
    #[error("DNS encode failed: {0}")]
    DnsEncode(#[from] pulse_dns::EncodeError),
    /// Ошибка построения DNS-записи.
    #[error("DNS record error: {0}")]
    DnsRecord(#[from] pulse_dns::RecordError),
    /// Ошибка RDATA.
    #[error("DNS RDATA error: {0}")]
    DnsRdata(#[from] pulse_dns::RdataError),
    /// Ошибка доменного имени.
    #[error("DNS name error: {0}")]
    DnsName(#[from] pulse_dns::NameError),
    /// Текст сертификата не является ни raw, ни hex, ни base64.
    #[error("certificate text is neither raw, hex, nor base64")]
    InvalidCertificateText,
    /// Некорректная hex-строка.
    #[error("invalid hex string")]
    HexDecode,
    /// Некорректная base64-строка.
    #[error("invalid base64 string")]
    Base64Decode,
    /// Нет действующего сертификата, подходящего по версии.
    #[error("no valid certificate for the requested provider")]
    NoValidCertificate,
    /// Обработчик DNS-запроса вернул ошибку.
    #[error("query handler failed: {0}")]
    Handler(String),
    /// Обработчик вернул пустой ответ.
    #[error("query handler returned an empty response")]
    EmptyResponse,
    /// Источник случайных чисел недоступен.
    #[error("random number generator failed: {0}")]
    Random(String),
    /// Внутренний мьютекс отравлен.
    #[error("internal lock poisoned")]
    LockPoisoned,
    /// Некорректная конфигурация сервера.
    #[error("invalid configuration: {field}")]
    InvalidConfig {
        /// Имя неверного параметра.
        field: &'static str,
    },
}

impl From<getrandom::Error> for Error {
    fn from(error: getrandom::Error) -> Self {
        Self::Random(error.to_string())
    }
}
