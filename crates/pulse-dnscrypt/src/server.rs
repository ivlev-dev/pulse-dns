//! Серверная сторона DNSCrypt v2 (§2–§10).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use pulse_dns::{DecodeLimits, EncodeOptions, Message};
use zeroize::Zeroizing;

use crate::cert::Certificate;
use crate::clock::{Clock, SystemClock};
use crate::crypto::{
    HALF_NONCE_LEN, MAC_LEN, open, query_nonce, random_bytes, response_nonce, seal, shared_box,
};
use crate::error::Error;
use crate::keys::{KEY_LEN, ProviderPublicKey, ResolverKeypair, ResolverPublicKey};
use crate::padding::{
    MIN_QUERY_PACKET_LEN, PAD_BLOCK_LEN, QUERY_HEADER_LEN, RESPONSE_HEADER_LEN,
    RESPONSE_PACKET_OVERHEAD, pad_to_len, response_padded_len, unpad,
};
use crate::protocol::{
    CLIENT_MAGIC_LEN, DEFAULT_MIN_QUERY_LEN, DEFAULT_REPLAY_CAPACITY, DEFAULT_REPLAY_TTL_SECS,
    MAX_TCP_PACKET, MAX_UDP_PACKET, RESOLVER_MAGIC,
};
use crate::replay::NonceCache;
use crate::transport::Transport;

/// Обработчик расшифрованного DNS-запроса.
///
/// Реализован для любых замыканий `Fn(&[u8]) -> Result<Vec<u8>, E>`.
pub trait QueryHandler {
    /// Тип ошибки обработчика.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Обрабатывает DNS-запрос и возвращает DNS-ответ.
    ///
    /// # Errors
    ///
    /// Любая ошибка обработчика; сервер вернёт [`Error::Handler`].
    fn handle_query(&self, query: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

impl<F, E> QueryHandler for F
where
    F: Fn(&[u8]) -> Result<Vec<u8>, E>,
    E: std::error::Error + Send + Sync + 'static,
{
    type Error = E;

    fn handle_query(&self, query: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self(query)
    }
}

/// Конфигурация сервера.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerConfig {
    /// Минимальная длина дополненного UDP-запроса, кратна 64 (§3).
    pub min_query_len: usize,
    /// Максимальный размер UDP-пакета DNSCrypt.
    pub max_udp_packet: usize,
    /// Максимальная полезная нагрузка TCP (без 2-байтового префикса).
    pub max_tcp_packet: usize,
    /// Время жизни записи anti-replay, секунды.
    pub replay_ttl_secs: u64,
    /// Ёмкость anti-replay.
    pub replay_capacity: usize,
    /// Включать anti-replay проверку nonce.
    ///
    /// Спецификация (§9) разрешает принимать любой nonce; задача требует
    /// anti-replay, поэтому по умолчанию защита включена. Отключение полезно
    /// только для строгого следования §9 в тестовых сценариях.
    pub replay_protection: bool,
    /// Усекать UDP-ответы с установкой TC вместо ошибки (§9).
    pub truncate_udp_responses: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            min_query_len: DEFAULT_MIN_QUERY_LEN,
            max_udp_packet: MAX_UDP_PACKET,
            max_tcp_packet: MAX_TCP_PACKET,
            replay_ttl_secs: DEFAULT_REPLAY_TTL_SECS,
            replay_capacity: DEFAULT_REPLAY_CAPACITY,
            replay_protection: true,
            truncate_udp_responses: true,
        }
    }
}

impl ServerConfig {
    fn validate(&self) -> Result<(), Error> {
        if self.min_query_len == 0 || !self.min_query_len.is_multiple_of(PAD_BLOCK_LEN) {
            return Err(Error::InvalidConfig {
                field: "min_query_len",
            });
        }
        if self.max_udp_packet < MIN_QUERY_PACKET_LEN {
            return Err(Error::InvalidConfig {
                field: "max_udp_packet",
            });
        }
        if self.max_tcp_packet < MIN_QUERY_PACKET_LEN || self.max_tcp_packet > MAX_TCP_PACKET {
            return Err(Error::InvalidConfig {
                field: "max_tcp_packet",
            });
        }
        if self.replay_protection && self.replay_ttl_secs == 0 {
            return Err(Error::InvalidConfig {
                field: "replay_ttl_secs",
            });
        }
        if self.replay_protection && self.replay_capacity == 0 {
            return Err(Error::InvalidConfig {
                field: "replay_capacity",
            });
        }
        Ok(())
    }
}

struct ServerCertificate {
    certificate: Certificate,
    keypair: ResolverKeypair,
}

/// Сервер DNSCrypt v2.
pub struct DnscryptServer {
    provider_pk: ProviderPublicKey,
    config: ServerConfig,
    certificates: Vec<ServerCertificate>,
    magics: HashMap<[u8; CLIENT_MAGIC_LEN], usize>,
    replay: Option<Mutex<NonceCache>>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for DnscryptServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DnscryptServer")
            .field("provider_pk", &self.provider_pk)
            .field("certificates", &self.certificates.len())
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl DnscryptServer {
    /// Создаёт сервер с системными часами.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] или ошибка создания anti-replay кэша.
    pub fn new(provider_pk: ProviderPublicKey, config: ServerConfig) -> Result<Self, Error> {
        Self::with_clock(provider_pk, config, Arc::new(SystemClock))
    }

    /// Создаёт сервер с явными часами (для тестов).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] или ошибка создания anti-replay кэша.
    pub fn with_clock(
        provider_pk: ProviderPublicKey,
        config: ServerConfig,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, Error> {
        config.validate()?;
        let replay = if config.replay_protection {
            Some(Mutex::new(NonceCache::new(
                config.replay_ttl_secs,
                config.replay_capacity,
            )?))
        } else {
            None
        };
        Ok(Self {
            provider_pk,
            config,
            certificates: Vec::new(),
            magics: HashMap::new(),
            replay,
            clock,
        })
    }

    /// Конфигурация сервера.
    #[must_use]
    pub const fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// Добавляет подписанный сертификат и соответствующий ключ резолвера.
    ///
    /// Сертификат проверяется подписью провайдера; ключ должен совпадать с
    /// `resolver-pk` из сертификата. Для ротации можно добавить несколько
    /// сертификатов с разными `client-magic`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidCertificateSignature`], [`Error::ResolverKeyMismatch`]
    /// или [`Error::DuplicateClientMagic`].
    pub fn add_certificate(
        &mut self,
        certificate: Certificate,
        keypair: ResolverKeypair,
    ) -> Result<(), Error> {
        certificate.verify(&self.provider_pk)?;
        if certificate.resolver_pk() != &keypair.public_key().to_bytes() {
            return Err(Error::ResolverKeyMismatch);
        }
        if self.magics.contains_key(certificate.client_magic()) {
            return Err(Error::DuplicateClientMagic);
        }
        let index = self.certificates.len();
        self.magics.insert(*certificate.client_magic(), index);
        self.certificates.push(ServerCertificate {
            certificate,
            keypair,
        });
        Ok(())
    }

    /// Обрабатывает UDP-пакет.
    ///
    /// # Errors
    ///
    /// Любая ошибка разбора/аутентификации. Согласно §9 некорректные запросы
    /// следует игнорировать.
    pub fn handle_udp<H: QueryHandler>(
        &self,
        packet: &[u8],
        handler: &H,
    ) -> Result<Vec<u8>, Error> {
        self.handle_udp_at(packet, self.clock.now_unix_secs(), handler)
    }

    /// Обрабатывает UDP-пакет в момент `now` (Unix-секунды).
    ///
    /// # Errors
    ///
    /// Любая ошибка разбора/аутентификации.
    pub fn handle_udp_at<H: QueryHandler>(
        &self,
        packet: &[u8],
        now: u64,
        handler: &H,
    ) -> Result<Vec<u8>, Error> {
        if packet.len() > self.config.max_udp_packet {
            return Err(Error::PacketTooLong {
                len: packet.len(),
                max: self.config.max_udp_packet,
            });
        }
        self.process(packet, now, Transport::Udp, handler)
    }

    /// Обрабатывает TCP-пакет (без 2-байтового префикса) и возвращает
    /// length-prefixed кадр.
    ///
    /// # Errors
    ///
    /// Любая ошибка разбора/аутентификации.
    pub fn handle_tcp<H: QueryHandler>(
        &self,
        packet: &[u8],
        handler: &H,
    ) -> Result<Vec<u8>, Error> {
        self.handle_tcp_at(packet, self.clock.now_unix_secs(), handler)
    }

    /// Обрабатывает TCP-пакет в момент `now` и возвращает кадр с префиксом.
    ///
    /// # Errors
    ///
    /// Любая ошибка разбора/аутентификации.
    pub fn handle_tcp_at<H: QueryHandler>(
        &self,
        packet: &[u8],
        now: u64,
        handler: &H,
    ) -> Result<Vec<u8>, Error> {
        if packet.len() > self.config.max_tcp_packet {
            return Err(Error::PacketTooLong {
                len: packet.len(),
                max: self.config.max_tcp_packet,
            });
        }
        let response = self.process(packet, now, Transport::Tcp, handler)?;
        encode_tcp_frame(&response)
    }

    /// Принимает length-prefixed TCP-кадр и возвращает length-prefixed ответ.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidTcpFrame`] или ошибки обработки.
    pub fn handle_tcp_frame<H: QueryHandler>(
        &self,
        frame: &[u8],
        handler: &H,
    ) -> Result<Vec<u8>, Error> {
        self.handle_tcp_frame_at(frame, self.clock.now_unix_secs(), handler)
    }

    /// Принимает TCP-кадр в момент `now` и возвращает кадр ответа.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidTcpFrame`] или ошибки обработки.
    pub fn handle_tcp_frame_at<H: QueryHandler>(
        &self,
        frame: &[u8],
        now: u64,
        handler: &H,
    ) -> Result<Vec<u8>, Error> {
        let packet = decode_tcp_frame(frame)?;
        self.handle_tcp_at(packet, now, handler)
    }

    fn process<H: QueryHandler>(
        &self,
        packet: &[u8],
        now: u64,
        transport: Transport,
        handler: &H,
    ) -> Result<Vec<u8>, Error> {
        let parsed = self.parse_query(packet, now)?;
        if let Some(replay) = &self.replay {
            let mut replay = replay.lock().map_err(|_| Error::LockPoisoned)?;
            replay.check_and_insert(parsed.client_pk.to_bytes(), parsed.client_nonce, now)?;
        }
        let response = handler
            .handle_query(&parsed.query)
            .map_err(|error| Error::Handler(error.to_string()))?;
        if response.is_empty() {
            return Err(Error::EmptyResponse);
        }
        let max_packet = match transport {
            Transport::Udp => self.config.max_udp_packet.min(packet.len()),
            Transport::Tcp => self.config.max_tcp_packet,
        };
        let shared = shared_box(&parsed.client_pk, parsed.keypair);
        match Self::seal_response(&shared, &parsed.client_nonce, &response, max_packet) {
            Ok(response_packet) => Ok(response_packet),
            Err(Error::ResponseTooLarge { .. })
                if transport == Transport::Udp && self.config.truncate_udp_responses =>
            {
                let truncated = truncate_dns(&response)?;
                Self::seal_response(&shared, &parsed.client_nonce, &truncated, max_packet)
            }
            Err(error) => Err(error),
        }
    }

    fn parse_query<'a>(&'a self, packet: &[u8], now: u64) -> Result<ParsedQuery<'a>, Error> {
        let magic: [u8; CLIENT_MAGIC_LEN] = array_at(packet, 0).ok_or(Error::PacketTooShort {
            len: packet.len(),
            min: MIN_QUERY_PACKET_LEN,
        })?;
        let index = *self.magics.get(&magic).ok_or(Error::UnknownClientMagic)?;
        let entry = self
            .certificates
            .get(index)
            .ok_or(Error::UnknownClientMagic)?;
        entry.certificate.validate_at(now)?;
        let client_pk: [u8; KEY_LEN] = array_at(packet, 8).ok_or(Error::PacketTooShort {
            len: packet.len(),
            min: MIN_QUERY_PACKET_LEN,
        })?;
        let client_nonce: [u8; HALF_NONCE_LEN] =
            array_at(packet, 8 + KEY_LEN).ok_or(Error::PacketTooShort {
                len: packet.len(),
                min: MIN_QUERY_PACKET_LEN,
            })?;
        let ciphertext = packet
            .get(QUERY_HEADER_LEN..)
            .ok_or(Error::PacketTooShort {
                len: packet.len(),
                min: MIN_QUERY_PACKET_LEN,
            })?;
        if ciphertext.len() < MAC_LEN + 1 {
            return Err(Error::PacketTooShort {
                len: packet.len(),
                min: MIN_QUERY_PACKET_LEN,
            });
        }
        let client_pk = ResolverPublicKey::from_bytes(client_pk)?;
        let shared = shared_box(&client_pk, &entry.keypair);
        let plaintext = open(&shared, &query_nonce(&client_nonce), ciphertext)?;
        let unpadded = unpad(&plaintext)?;
        if unpadded.is_empty() {
            return Err(Error::InvalidPadding);
        }
        Ok(ParsedQuery {
            keypair: &entry.keypair,
            client_pk,
            client_nonce,
            query: Zeroizing::new(unpadded.to_vec()),
        })
    }

    fn seal_response(
        shared: &crypto_box::ChaChaBox,
        client_nonce: &[u8; HALF_NONCE_LEN],
        response: &[u8],
        max_packet: usize,
    ) -> Result<Vec<u8>, Error> {
        let resolver_nonce: [u8; HALF_NONCE_LEN] = random_bytes()?;
        let nonce = response_nonce(client_nonce, &resolver_nonce);
        let padded_len = response_padded_len(response.len(), client_nonce)?;
        let needed = RESPONSE_PACKET_OVERHEAD.saturating_add(padded_len);
        if needed > max_packet {
            return Err(Error::ResponseTooLarge {
                needed,
                max: max_packet,
            });
        }
        let padded = pad_to_len(response, padded_len)?;
        let ciphertext = seal(shared, &nonce, &padded)?;
        let mut packet = Vec::with_capacity(RESPONSE_HEADER_LEN.saturating_add(ciphertext.len()));
        packet.extend_from_slice(&RESOLVER_MAGIC);
        packet.extend_from_slice(&nonce);
        packet.extend_from_slice(&ciphertext);
        Ok(packet)
    }
}

struct ParsedQuery<'a> {
    keypair: &'a ResolverKeypair,
    client_pk: ResolverPublicKey,
    client_nonce: [u8; HALF_NONCE_LEN],
    query: Zeroizing<Vec<u8>>,
}

/// Кодирует TCP-кадр: 2 байта длины (big-endian) + payload.
///
/// # Errors
///
/// [`Error::PacketTooLong`], если payload больше 65535 байт.
pub fn encode_tcp_frame(payload: &[u8]) -> Result<Vec<u8>, Error> {
    let len = u16::try_from(payload.len()).map_err(|_| Error::PacketTooLong {
        len: payload.len(),
        max: MAX_TCP_PACKET,
    })?;
    let mut frame = Vec::with_capacity(2 + payload.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// Разбирает TCP-кадр и возвращает полезную нагрузку.
///
/// # Errors
///
/// [`Error::InvalidTcpFrame`], если префикс отсутствует или payload короче
/// заявленной длины.
pub fn decode_tcp_frame(frame: &[u8]) -> Result<&[u8], Error> {
    let prefix: [u8; 2] = array_at(frame, 0).ok_or(Error::InvalidTcpFrame)?;
    let len = usize::from(u16::from_be_bytes(prefix));
    frame
        .get(2..)
        .and_then(|rest| rest.get(..len))
        .ok_or(Error::InvalidTcpFrame)
}

/// Усекает DNS-ответ: копирует заголовок и вопрос, выставляет TC (§9).
fn truncate_dns(response: &[u8]) -> Result<Vec<u8>, Error> {
    let message = Message::decode(response, &DecodeLimits::default())?;
    let flags = message.flags().with_tc(true);
    let mut truncated = Message::new(message.id(), flags);
    for question in message.questions() {
        truncated.add_question(question.clone());
    }
    truncated
        .encode(&EncodeOptions::default())
        .map_err(Error::from)
}

fn array_at<const N: usize>(bytes: &[u8], start: usize) -> Option<[u8; N]> {
    let end = start.checked_add(N)?;
    bytes.get(start..end)?.try_into().ok()
}
