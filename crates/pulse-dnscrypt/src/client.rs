//! Клиентская сторона DNSCrypt v2 (для тестов и interop).

use crate::cert::Certificate;
use crate::crypto::{HALF_NONCE_LEN, MAC_LEN, open, query_nonce, random_bytes, seal, shared_box};
use crate::error::Error;
use crate::keys::{ProviderPublicKey, ResolverKeypair, ResolverPublicKey};
use crate::padding::{
    MAX_PAD_LEN, MIN_QUERY_PACKET_LEN, QUERY_HEADER_LEN, RESPONSE_HEADER_LEN,
    RESPONSE_PACKET_OVERHEAD, pad_to_len, round_up_block, tcp_pad_len, udp_query_padded_len, unpad,
};
use crate::protocol::{DEFAULT_MIN_QUERY_LEN, MAX_TCP_PACKET, MAX_UDP_PACKET, RESOLVER_MAGIC};
use crate::server::{decode_tcp_frame, encode_tcp_frame};
use crate::transport::Transport;

/// Отправленный запрос: пакет и его клиентский nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingQuery {
    packet: Vec<u8>,
    client_nonce: [u8; HALF_NONCE_LEN],
    transport: Transport,
}

impl PendingQuery {
    /// Готовый пакет (для TCP — с 2-байтовым префиксом длины).
    #[must_use]
    pub fn packet(&self) -> &[u8] {
        &self.packet
    }

    /// Клиентский nonce, необходимый для проверки ответа.
    #[must_use]
    pub const fn client_nonce(&self) -> &[u8; HALF_NONCE_LEN] {
        &self.client_nonce
    }

    /// Транспорт запроса.
    #[must_use]
    pub const fn transport(&self) -> Transport {
        self.transport
    }
}

/// Клиент DNSCrypt v2.
#[derive(Debug, Clone)]
pub struct DnscryptClient {
    certificate: Certificate,
    resolver_pk: ResolverPublicKey,
    keypair: ResolverKeypair,
    provider_pk: ProviderPublicKey,
}

impl DnscryptClient {
    /// Создаёт клиента по сертификату, проверяя подпись и срок действия.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidCertificateSignature`],
    /// [`Error::CertificateNotYetValid`], [`Error::CertificateExpired`] или
    /// [`Error::Random`].
    pub fn new(
        certificate: Certificate,
        provider_pk: ProviderPublicKey,
        now: u64,
    ) -> Result<Self, Error> {
        let keypair = ResolverKeypair::generate()?;
        Self::with_keypair(certificate, provider_pk, now, keypair)
    }

    /// Создаёт клиента с заданной ключевой парой (для тестов).
    ///
    /// # Errors
    ///
    /// Ошибки проверки сертификата.
    pub fn with_keypair(
        certificate: Certificate,
        provider_pk: ProviderPublicKey,
        now: u64,
        keypair: ResolverKeypair,
    ) -> Result<Self, Error> {
        certificate.verify(&provider_pk)?;
        certificate.validate_at(now)?;
        let resolver_pk = certificate.resolver_public_key()?;
        Ok(Self {
            certificate,
            resolver_pk,
            keypair,
            provider_pk,
        })
    }

    /// Выбранный сертификат.
    #[must_use]
    pub const fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    /// Открытый ключ клиента (X25519).
    #[must_use]
    pub fn public_key(&self) -> ResolverPublicKey {
        self.keypair.public_key()
    }

    /// Открытый ключ провайдера, которому доверяет клиент.
    #[must_use]
    pub const fn provider_public_key(&self) -> &ProviderPublicKey {
        &self.provider_pk
    }

    /// Строит зашифрованный запрос со случайным nonce.
    ///
    /// # Errors
    ///
    /// [`Error::Random`], [`Error::InvalidPadding`] или
    /// [`Error::EncryptionFailed`].
    pub fn build_query(&self, query: &[u8], transport: Transport) -> Result<PendingQuery, Error> {
        let client_nonce: [u8; HALF_NONCE_LEN] = random_bytes()?;
        self.build_query_with_nonce(query, transport, client_nonce)
    }

    /// Строит зашифрованный запрос с явным nonce.
    ///
    /// Вызывающий обязан не повторять `client_nonce` для одной и той же пары
    /// `(client-sk, resolver-pk)`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPadding`] или [`Error::EncryptionFailed`].
    pub fn build_query_with_nonce(
        &self,
        query: &[u8],
        transport: Transport,
        client_nonce: [u8; HALF_NONCE_LEN],
    ) -> Result<PendingQuery, Error> {
        let padded = match transport {
            Transport::Udp => {
                let max_plaintext = MAX_UDP_PACKET
                    .saturating_sub(QUERY_HEADER_LEN)
                    .saturating_sub(MAC_LEN);
                let padded_len = udp_query_padded_len(
                    query.len(),
                    DEFAULT_MIN_QUERY_LEN,
                    max_plaintext & !(crate::padding::PAD_BLOCK_LEN - 1),
                )?;
                pad_to_len(query, padded_len)?
            }
            Transport::Tcp => {
                let max_plaintext = MAX_TCP_PACKET
                    .saturating_sub(QUERY_HEADER_LEN)
                    .saturating_sub(MAC_LEN);
                let selector: [u8; 1] = random_bytes()?;
                let pad_len = tcp_pad_len(query.len(), selector.first().copied().unwrap_or(0));
                let target = query.len().saturating_add(pad_len);
                if target > max_plaintext || pad_len > MAX_PAD_LEN {
                    return Err(Error::InvalidPadding);
                }
                pad_to_len(query, target)?
            }
        };
        let shared = shared_box(&self.resolver_pk, &self.keypair);
        let ciphertext = seal(&shared, &query_nonce(&client_nonce), &padded)?;
        let mut packet = Vec::with_capacity(QUERY_HEADER_LEN.saturating_add(ciphertext.len()));
        packet.extend_from_slice(self.certificate.client_magic());
        packet.extend_from_slice(&self.keypair.public_key().to_bytes());
        packet.extend_from_slice(&client_nonce);
        packet.extend_from_slice(&ciphertext);
        if transport.is_tcp() {
            packet = encode_tcp_frame(&packet)?;
        }
        Ok(PendingQuery {
            packet,
            client_nonce,
            transport,
        })
    }

    /// Проверяет и расшифровывает ответ на запрос [`PendingQuery`].
    ///
    /// # Errors
    ///
    /// [`Error::InvalidTcpFrame`], [`Error::InvalidResolverMagic`],
    /// [`Error::NonceMismatch`], [`Error::DecryptionFailed`] или
    /// [`Error::InvalidPadding`].
    pub fn decrypt_response(
        &self,
        pending: &PendingQuery,
        response: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let payload = match pending.transport {
            Transport::Udp => response,
            Transport::Tcp => decode_tcp_frame(response)?,
        };
        let magic: [u8; 8] = payload
            .get(..8)
            .ok_or(Error::PacketTooShort {
                len: payload.len(),
                min: RESPONSE_PACKET_OVERHEAD,
            })?
            .try_into()
            .map_err(|_| Error::InvalidResolverMagic)?;
        if magic != RESOLVER_MAGIC {
            return Err(Error::InvalidResolverMagic);
        }
        let nonce: [u8; 24] = payload
            .get(8..RESPONSE_HEADER_LEN)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(Error::PacketTooShort {
                len: payload.len(),
                min: RESPONSE_PACKET_OVERHEAD,
            })?;
        if nonce.get(..HALF_NONCE_LEN) != Some(pending.client_nonce.as_slice()) {
            return Err(Error::NonceMismatch);
        }
        let ciphertext = payload
            .get(RESPONSE_HEADER_LEN..)
            .ok_or(Error::PacketTooShort {
                len: payload.len(),
                min: RESPONSE_PACKET_OVERHEAD,
            })?;
        if ciphertext.len() < MAC_LEN + 1 {
            return Err(Error::PacketTooShort {
                len: payload.len(),
                min: RESPONSE_PACKET_OVERHEAD,
            });
        }
        let shared = shared_box(&self.resolver_pk, &self.keypair);
        let plaintext = open(&shared, &nonce, ciphertext)?;
        let unpadded = unpad(&plaintext)?;
        Ok(unpadded.to_vec())
    }
}

/// Минимальный размер валидного DNSCrypt-запроса.
pub const MIN_CLIENT_QUERY_LEN: usize = MIN_QUERY_PACKET_LEN;

/// Округляет длину вверх до 64 (экспортируется для тестов).
#[must_use]
pub const fn padded_len(len: usize) -> usize {
    round_up_block(len)
}
