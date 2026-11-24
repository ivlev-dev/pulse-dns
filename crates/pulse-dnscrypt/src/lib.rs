//! DNSCrypt v2: сертификаты, сервер и клиент.
//!
//! Крейт реализует протокол DNSCrypt версии 2
//! (<https://dnscrypt.info/protocol/>) поверх `pulse-dns`:
//!
//! - **Сертификаты** (§12): `DNSC`-формат, подпись Ed25519 ключом провайдера,
//!   срок действия, серийный номер, расширения; выбор по максимальному
//!   `serial`; TXT-запись `2.dnscrypt-cert.<zone>`.
//! - **Крипто** (§11): `X25519-XChaCha20Poly1305` в точности как
//!   `crypto_box_curve25519xchacha20poly1305` из libsodium — HChaCha20 над
//!   X25519 shared secret, NaCl-layout `secretbox` (MAC 16 байт впереди
//!   шифротекста, без AAD). Реализация — [`crypto_box::ChaChaBox`]
//!   (RustCrypto, vetted); IETF-вариант `XChaCha20-Poly1305` несовместим и не
//!   используется.
//! - **Сервер** (§2–§10): разбор `client-magic`/`client-pk`/`client-nonce`,
//!   проверка сертификата и времени, расшифровка, anti-replay кэш, обработчик
//!   запроса, дополнение ISO/IEC 7816-4, усечение UDP-ответов с TC.
//! - **Клиент**: построение запроса по сертификату и расшифровка ответа — для
//!   тестов и interop.
//!
//! # Соответствие спецификации
//!
//! | Раздел | Что реализовано |
//! |---|---|
//! | §2 | `<dnscrypt-query>`, half-nonce, `client-pk` |
//! | §3, §5 | ISO/IEC 7816-4, `min-query-len`, TCP-дополнение |
//! | §4, §6 | UDP/TCP, 2-байтовый префикс длины |
//! | §7, §8 | `<dnscrypt-response>`, resolver nonce, детерминированное дополнение |
//! | §9, §10 | усечение UDP с TC, TCP без усечения |
//! | §11 | X25519-XChaCha20Poly1305, MAC впереди |
//! | §12 | сертификат, подпись, serial, срок, TXT |
//!
//! # Пример
//!
//! ```no_run
//! use pulse_dnscrypt::{
//!     Certificate, CertificateParams, DnscryptClient, DnscryptServer, ProviderKeypair,
//!     ResolverKeypair, ServerConfig, Transport,
//! };
//!
//! let provider = ProviderKeypair::generate()?;
//! let resolver = ResolverKeypair::generate()?;
//! let params = CertificateParams::new(
//!     resolver.public_key().to_bytes(),
//!     [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
//!     1,
//!     1_700_000_000,
//!     1_700_086_400,
//! );
//! let certificate = Certificate::sign(&provider, params)?;
//!
//! let mut server = DnscryptServer::new(provider.public_key(), ServerConfig::default())?;
//! server.add_certificate(certificate.clone(), resolver)?;
//! let client = DnscryptClient::new(certificate, provider.public_key(), 1_700_000_000)?;
//!
//! let query = client.build_query(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00", Transport::Udp)?;
//! # let _ = (server, query);
//! # Ok::<(), pulse_dnscrypt::Error>(())
//! ```
//!
//! # Безопасность
//!
//! Секретные ключи не выводятся в `Debug`; секретный X25519-ключ можно
//! получить только через [`ResolverKeypair::to_secret_bytes`]
//! (`Zeroizing`). Anti-replay проверяется после успешной аутентификации,
//! чтобы не засорять кэш мусорными пакетами. Сертификаты принимаются только с
//! проверенной подписью Ed25519.

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
    clippy::similar_names,
    clippy::needless_pass_by_value,
    clippy::return_self_not_must_use,
    clippy::items_after_statements,
    clippy::option_if_let_else,
    clippy::manual_let_else,
    clippy::single_match_else,
    clippy::redundant_closure_for_method_calls,
    clippy::wildcard_imports
)]

pub mod cert;
pub mod client;
pub mod clock;
pub mod crypto;
pub mod error;
pub mod keys;
pub mod padding;
pub mod protocol;
pub mod replay;
pub mod server;
pub mod transport;
pub mod util;

pub use cert::{
    Certificate, CertificateParams, CertificateSet, provider_name, random_client_magic,
};
pub use client::{DnscryptClient, MIN_CLIENT_QUERY_LEN, PendingQuery};
pub use clock::{Clock, ManualClock, SystemClock};
pub use crypto::{HALF_NONCE_LEN, MAC_LEN, NONCE_LEN, query_nonce, random_bytes, response_nonce};
pub use error::Error;
pub use keys::{
    KEY_LEN, ProviderKeypair, ProviderPublicKey, ResolverKeypair, ResolverPublicKey, SIGNATURE_LEN,
};
pub use padding::{
    MAX_PAD_LEN, MIN_PAD_LEN, MIN_QUERY_PACKET_LEN, MIN_RESPONSE_PACKET_LEN, PAD_BLOCK_LEN,
    PAD_MARKER, QUERY_HEADER_LEN, QUERY_PACKET_OVERHEAD, RESPONSE_HEADER_LEN,
    RESPONSE_PACKET_OVERHEAD, pad_to_len, response_padded_len, round_up_block, tcp_pad_len,
    udp_query_padded_len, unpad,
};
pub use protocol::{
    CERT_FIXED_LEN, CERT_MAGIC, CLIENT_MAGIC_LEN, DEFAULT_MIN_QUERY_LEN, DEFAULT_REPLAY_CAPACITY,
    DEFAULT_REPLAY_TTL_SECS, ES_VERSION_XCHACHA20POLY1305, ES_VERSION_XSALSA20POLY1305,
    MAX_CERTIFICATE_LEN, MAX_TCP_PACKET, MAX_UDP_PACKET, PROTOCOL_MAJOR, PROTOCOL_MINOR_VERSION,
    PROVIDER_NAME_PREFIX, RESOLVER_MAGIC,
};
pub use replay::NonceCache;
pub use server::{DnscryptServer, QueryHandler, ServerConfig, decode_tcp_frame, encode_tcp_frame};
pub use transport::Transport;
pub use util::{from_base64, from_hex, to_base64, to_hex};
