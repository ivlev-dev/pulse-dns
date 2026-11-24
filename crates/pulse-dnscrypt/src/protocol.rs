//! Константы протокола DNSCrypt v2.

/// Старшая версия протокола (префикс имени провайдера).
pub const PROTOCOL_MAJOR: u8 = 2;

/// Магия сертификата: `DNSC` (§12).
pub const CERT_MAGIC: [u8; 4] = *b"DNSC";

/// Магия ответа резолвера: `r6fnvWj8` (§7).
pub const RESOLVER_MAGIC: [u8; 8] = *b"r6fnvWj8";

/// `es-version` для X25519-XChaCha20-Poly1305 (§11).
pub const ES_VERSION_XCHACHA20POLY1305: [u8; 2] = [0x00, 0x02];

/// `es-version` для X25519-XSalsa20-Poly1305 (не реализован).
pub const ES_VERSION_XSALSA20POLY1305: [u8; 2] = [0x00, 0x01];

/// Минорная версия протокола (§12).
pub const PROTOCOL_MINOR_VERSION: [u8; 2] = [0x00, 0x00];

/// Длина `client-magic`.
pub const CLIENT_MAGIC_LEN: usize = 8;

/// Длина фиксированной части сертификата без расширений.
pub const CERT_FIXED_LEN: usize = 124;

/// Максимальная длина сертификата (ограничение TXT RDATA).
pub const MAX_CERTIFICATE_LEN: usize = 65_000;

/// Начальная минимальная длина UDP-запроса (§3).
pub const DEFAULT_MIN_QUERY_LEN: usize = 256;

/// Лимит UDP-пакета DNSCrypt по умолчанию.
pub const MAX_UDP_PACKET: usize = 4096;

/// Лимит TCP-полезной нагрузки (префикс длины — 2 байта).
pub const MAX_TCP_PACKET: usize = u16::MAX as usize;

/// TTL anti-replay по умолчанию, секунды.
pub const DEFAULT_REPLAY_TTL_SECS: u64 = 300;

/// Ёмкость anti-replay по умолчанию.
pub const DEFAULT_REPLAY_CAPACITY: usize = 65_536;

/// Префикс имени провайдера.
pub const PROVIDER_NAME_PREFIX: &str = "2.dnscrypt-cert.";
