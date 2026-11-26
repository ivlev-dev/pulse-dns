//! SIG(0) — подпись DNS-запроса и транзакции (RFC 2931).
//!
//! SIG(0) — это `SIG`-запись (type 24) с `type covered = 0`, добавляемая в
//! конец Additional-секции. Она подписывает не RRset, а само сообщение:
//!
//! ```text
//! request:  data = SIG RDATA without signature | request without SIG(0)
//! response: data = SIG RDATA without signature | full request | response without SIG(0)
//! ```
//!
//! RDATA кодируется в каноническом виде: `signer name` — в нижнем регистре и
//! без сжатия (RFC 4034 §6.2), поля `type covered`, `algorithm`, `labels`,
//! `original TTL`, `expiration`, `inception`, `key tag` — как в wire-формате.
//!
//! Модуль отвечает только за формат и криптографическую проверку. Политика
//! (какие ключи разрешены, replay-кэш, окно времени) задаётся вызывающим
//! сервером.
//!
//! # Пример
//!
//! ```
//! use pulse_dns::Name;
//! use pulse_dnssec::sig0::Sig0Signature;
//!
//! let signer = Name::parse("host.example.com").unwrap();
//! let expected = 2 + 1 + 1 + 4 + 4 + 4 + 2 + signer.wire_len();
//! let sig = Sig0Signature::new(15, 0, 1_700_000_300, 1_700_000_000, 1234, signer);
//! let rdata = sig.rdata_without_signature();
//! assert_eq!(rdata.len(), expected);
//! ```

use pulse_dns::{DnskeyData, Name, Rclass, Rdata, Record, Rtype, Ttl};
use thiserror::Error;

use crate::algorithm::Algorithm;
use crate::key::PrivateKey;
use crate::rdata_util::key_tag;
use crate::verify::verify_message_signature;

/// Тип SIG-записи (RFC 2535 / IANA).
pub const RTYPE_SIG0: u16 = 24;

/// Минимальный размер SIG RDATA без подписи (без signer name).
const FIXED_RDATA_LEN: usize = 2 + 1 + 1 + 4 + 4 + 4 + 2;

/// Максимальный размер подписи (RSA-8192).
pub const MAX_SIGNATURE_LEN: usize = 1024;

/// Ошибка разбора или проверки SIG(0).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Sig0Error {
    /// Сообщение короче DNS-заголовка.
    #[error("message is too short for a DNS header")]
    ShortHeader,
    /// Секция сообщения выходит за границы пакета.
    #[error("malformed DNS message: {reason}")]
    Malformed {
        /// Причина.
        reason: &'static str,
    },
    /// Подпись не найдена.
    #[error("message has no SIG(0) record")]
    Missing,
    /// SIG(0) не является последней записью Additional-секции.
    #[error("SIG(0) must be the last record of the additional section")]
    NotLast,
    /// Некорректная RDATA.
    #[error("invalid SIG(0) RDATA: {reason}")]
    InvalidRdata {
        /// Причина.
        reason: &'static str,
    },
    /// Имя signer сжато указателем.
    #[error("SIG(0) signer name must not be compressed")]
    CompressedSigner,
    /// Неизвестный или несовпадающий ключ.
    #[error("SIG(0) key mismatch")]
    KeyMismatch,
    /// Подпись вне окна валидности.
    #[error("SIG(0) signature is outside its validity window")]
    TimeInvalid,
    /// Слишком широкое окно валидности.
    #[error("SIG(0) validity window is too wide")]
    ValidityTooWide,
    /// Криптографическая проверка не прошла.
    #[error("SIG(0) signature verification failed")]
    BadSignature,
    /// Ошибка кодирования ответа.
    #[error("cannot encode SIG(0) response: {reason}")]
    Encode {
        /// Причина.
        reason: &'static str,
    },
}

/// Разобранная SIG(0)-подпись.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sig0Signature {
    /// Поле type covered (для SIG(0) всегда 0).
    pub type_covered: u16,
    /// Алгоритм DNSSEC.
    pub algorithm: u8,
    /// Поле labels (для SIG(0) не используется, обычно 0).
    pub labels: u8,
    /// Original TTL (для SIG(0) не используется, обычно 0).
    pub original_ttl: u32,
    /// Конец окна валидности (UNIX).
    pub expiration: u32,
    /// Начало окна валидности (UNIX).
    pub inception: u32,
    /// Key tag публичного ключа.
    pub key_tag: u16,
    /// Имя подписавшего (principal).
    pub signer: Name,
    /// Подпись.
    pub signature: Vec<u8>,
}

impl Sig0Signature {
    /// Создаёт SIG(0) без подписи.
    #[must_use]
    pub fn new(
        algorithm: u8,
        original_ttl: u32,
        expiration: u32,
        inception: u32,
        key_tag: u16,
        signer: Name,
    ) -> Self {
        Self {
            type_covered: 0,
            algorithm,
            labels: 0,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer,
            signature: Vec::new(),
        }
    }

    /// Разбирает RDATA SIG-записи.
    ///
    /// # Errors
    ///
    /// [`Sig0Error`] при нехватке полей, сжатом signer name или слишком
    /// длинной подписи.
    pub fn parse_rdata(rdata: &[u8]) -> Result<Self, Sig0Error> {
        if rdata.len() < FIXED_RDATA_LEN + 1 {
            return Err(Sig0Error::InvalidRdata {
                reason: "rdata is shorter than the fixed fields plus signer name",
            });
        }
        let mut cursor = Cursor::new(rdata);
        let type_covered = cursor.u16("type covered")?;
        let algorithm = cursor.u8("algorithm")?;
        let labels = cursor.u8("labels")?;
        let original_ttl = cursor.u32("original ttl")?;
        let expiration = cursor.u32("expiration")?;
        let inception = cursor.u32("inception")?;
        let key_tag = cursor.u16("key tag")?;
        let signer = cursor.name()?;
        let signature = cursor.rest().to_vec();
        if signature.len() > MAX_SIGNATURE_LEN {
            return Err(Sig0Error::InvalidRdata {
                reason: "signature is too long",
            });
        }
        Ok(Self {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer,
            signature,
        })
    }

    /// Канонические байты RDATA без подписи.
    #[must_use]
    pub fn rdata_without_signature(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(FIXED_RDATA_LEN + self.signer.wire_len() + self.signature.len());
        out.extend_from_slice(&self.type_covered.to_be_bytes());
        out.push(self.algorithm);
        out.push(self.labels);
        out.extend_from_slice(&self.original_ttl.to_be_bytes());
        out.extend_from_slice(&self.expiration.to_be_bytes());
        out.extend_from_slice(&self.inception.to_be_bytes());
        out.extend_from_slice(&self.key_tag.to_be_bytes());
        out.extend_from_slice(self.signer.as_wire());
        out
    }

    /// Полные байты RDATA с подписью.
    #[must_use]
    pub fn rdata(&self) -> Vec<u8> {
        let mut out = self.rdata_without_signature();
        out.extend_from_slice(&self.signature);
        out
    }

    /// Превращает в wire-запись (owner root, class ANY, TTL 0).
    ///
    /// # Errors
    ///
    /// [`Sig0Error`] при невозможности построить RR.
    pub fn to_record(&self) -> Result<Record, Sig0Error> {
        let rdata = Rdata::unknown(Rtype::from_u16(RTYPE_SIG0), self.rdata()).map_err(|_| {
            Sig0Error::Encode {
                reason: "SIG RDATA rejected by pulse-dns",
            }
        })?;
        Record::new(
            Name::root(),
            Rtype::from_u16(RTYPE_SIG0),
            Rclass::ANY,
            Ttl::ZERO,
            rdata,
        )
        .map_err(|_| Sig0Error::Encode {
            reason: "SIG record rejected by pulse-dns",
        })
    }

    /// Проверяет окно валидности и ширину окна.
    ///
    /// # Errors
    ///
    /// [`Sig0Error::TimeInvalid`] вне окна, [`Sig0Error::ValidityTooWide`]
    /// если окно шире `max_validity`.
    pub fn check_time(&self, now: u32, max_validity: u32) -> Result<(), Sig0Error> {
        let lifetime = self.expiration.wrapping_sub(self.inception);
        if lifetime == 0 || lifetime > max_validity {
            return Err(Sig0Error::ValidityTooWide);
        }
        if !(self.inception..=self.expiration).contains(&now) {
            return Err(Sig0Error::TimeInvalid);
        }
        Ok(())
    }
}

/// Найденная SIG(0) вместе с её позицией в пакете.
#[derive(Debug, Clone)]
pub struct Sig0Location {
    /// Разобранная подпись.
    pub signature: Sig0Signature,
    /// Смещение начала RR.
    pub offset: usize,
    /// Смещение конца RR.
    pub end: usize,
}

/// Ищет SIG(0) в Additional-секции.
///
/// # Errors
///
/// [`Sig0Error::Malformed`] при выходе за границы, [`Sig0Error::NotLast`],
/// если SIG(0) не последняя запись, [`Sig0Error::InvalidRdata`] при
/// некорректной RDATA.
pub fn find_sig0(raw: &[u8]) -> Result<Option<Sig0Location>, Sig0Error> {
    if raw.len() < 12 {
        return Err(Sig0Error::ShortHeader);
    }
    let qdcount = usize::from(u16_at(raw, 4).ok_or(Sig0Error::ShortHeader)?);
    let ancount = usize::from(u16_at(raw, 6).ok_or(Sig0Error::ShortHeader)?);
    let nscount = usize::from(u16_at(raw, 8).ok_or(Sig0Error::ShortHeader)?);
    let arcount = usize::from(u16_at(raw, 10).ok_or(Sig0Error::ShortHeader)?);
    let mut cursor = Cursor::at(raw, 12);
    for _ in 0..qdcount {
        cursor.skip_name()?;
        cursor.skip(4, "question fields")?;
    }
    for _ in 0..ancount.saturating_add(nscount) {
        cursor.skip_name()?;
        let fixed = cursor.take(10, "rr header")?;
        let rdlength = usize::from(u16_at(fixed, 8).ok_or(Sig0Error::Malformed {
            reason: "rr header is too short",
        })?);
        cursor.skip(rdlength, "rdata")?;
    }
    let mut found: Option<Sig0Location> = None;
    for index in 0..arcount {
        let start = cursor.position();
        cursor.skip_name()?;
        let fixed = cursor.take(10, "rr header")?;
        let rr_type = u16_at(fixed, 0).ok_or(Sig0Error::Malformed {
            reason: "rr header is too short",
        })?;
        let rdlength = usize::from(u16_at(fixed, 8).ok_or(Sig0Error::Malformed {
            reason: "rr header is too short",
        })?);
        let rdata = cursor.take(rdlength, "rdata")?;
        if rr_type == RTYPE_SIG0 {
            let signature = Sig0Signature::parse_rdata(rdata)?;
            if signature.type_covered == 0 {
                if found.is_some() {
                    return Err(Sig0Error::InvalidRdata {
                        reason: "more than one SIG(0) record",
                    });
                }
                let end = cursor.position();
                if index + 1 != arcount || end != raw.len() {
                    return Err(Sig0Error::NotLast);
                }
                found = Some(Sig0Location {
                    signature,
                    offset: start,
                    end,
                });
            }
        }
    }
    Ok(found)
}

/// Собирает данные, которые подписывал отправитель запроса.
///
/// # Errors
///
/// [`Sig0Error::Malformed`], если SIG(0) не последняя запись.
pub fn request_signed_data(raw: &[u8], location: &Sig0Location) -> Result<Vec<u8>, Sig0Error> {
    if location.end != raw.len() || raw.len() < 12 {
        return Err(Sig0Error::Malformed {
            reason: "SIG(0) is not the last record",
        });
    }
    let arcount = u16_at(raw, 10).ok_or(Sig0Error::ShortHeader)?;
    let arcount = arcount.checked_sub(1).ok_or(Sig0Error::Malformed {
        reason: "ARCOUNT is zero",
    })?;
    let mut header = header_bytes(raw)?;
    header
        .get_mut(10..12)
        .ok_or(Sig0Error::ShortHeader)?
        .copy_from_slice(&arcount.to_be_bytes());
    let mut data = Vec::with_capacity(location.offset);
    data.extend_from_slice(&header);
    data.extend_from_slice(raw.get(12..location.offset).ok_or(Sig0Error::Malformed {
        reason: "SIG(0) offset is out of bounds",
    })?);
    Ok(data)
}

/// Проверяет SIG(0) запроса.
///
/// Возвращает подпись для replay-кэша вызывающего.
///
/// # Errors
///
/// [`Sig0Error::Missing`] если подписи нет; ошибки ключа, времени и подписи.
pub fn verify_request(
    raw: &[u8],
    dnskey: &DnskeyData,
    now: u32,
    max_validity: u32,
) -> Result<Sig0Signature, Sig0Error> {
    let location = find_sig0(raw)?.ok_or(Sig0Error::Missing)?;
    let signature = &location.signature;
    if signature.algorithm != dnskey.algorithm() || signature.key_tag != key_tag(dnskey) {
        return Err(Sig0Error::KeyMismatch);
    }
    signature.check_time(now, max_validity)?;
    let mut data = signature.rdata_without_signature();
    data.extend_from_slice(&request_signed_data(raw, &location)?);
    verify_message_signature(
        Algorithm::from_u8(signature.algorithm),
        dnskey,
        &data,
        &signature.signature,
    )
    .map_err(|_| Sig0Error::BadSignature)?;
    Ok(signature.clone())
}

/// Подписывает ответ SIG(0).
///
/// `query` — полный запрос (включая его SIG(0)), `response` — уже
/// закодированный ответ без SIG(0). Возвращает ответ с добавленной подписью.
///
/// # Errors
///
/// [`Sig0Error`] при ошибке подписи или кодирования.
#[allow(clippy::too_many_arguments)]
pub fn sign_response(
    query: &[u8],
    response: &[u8],
    signer: &Name,
    key: &PrivateKey,
    dnskey: &DnskeyData,
    now: u32,
    validity: u32,
    inception_skew: u32,
) -> Result<Vec<u8>, Sig0Error> {
    if response.len() < 12 {
        return Err(Sig0Error::ShortHeader);
    }
    let expiration = now.saturating_add(validity);
    let inception = now.saturating_sub(inception_skew);
    let mut signature = Sig0Signature::new(
        key.algorithm().as_u8(),
        0,
        expiration,
        inception,
        key_tag(dnskey),
        signer.clone(),
    );
    let mut data = signature.rdata_without_signature();
    data.extend_from_slice(query);
    data.extend_from_slice(response);
    signature.signature = key
        .sign_message(&data)
        .map_err(|_| Sig0Error::BadSignature)?;
    append_record(response, &signature)
}

fn append_record(response: &[u8], signature: &Sig0Signature) -> Result<Vec<u8>, Sig0Error> {
    let rdata = signature.rdata();
    let rdlength = u16::try_from(rdata.len()).map_err(|_| Sig0Error::Encode {
        reason: "SIG RDATA is too long",
    })?;
    // owner root + type + class ANY + TTL 0 + RDLENGTH + RDATA.
    let encoded_len = 1 + 2 + 2 + 4 + 2 + rdata.len();
    let arcount = u16_at(response, 10).ok_or(Sig0Error::ShortHeader)?;
    let arcount = arcount.checked_add(1).ok_or(Sig0Error::Encode {
        reason: "ARCOUNT overflow",
    })?;
    let total = response.len().saturating_add(encoded_len);
    if total > usize::from(u16::MAX) {
        return Err(Sig0Error::Encode {
            reason: "response exceeds 65535 bytes",
        });
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(response);
    out.get_mut(10..12)
        .ok_or(Sig0Error::ShortHeader)?
        .copy_from_slice(&arcount.to_be_bytes());
    out.push(0);
    out.extend_from_slice(&RTYPE_SIG0.to_be_bytes());
    out.extend_from_slice(&Rclass::ANY.as_u16().to_be_bytes());
    out.extend_from_slice(&0_u32.to_be_bytes());
    out.extend_from_slice(&rdlength.to_be_bytes());
    out.extend_from_slice(&rdata);
    Ok(out)
}

/// Разбирает ответ и проверяет его SIG(0).
///
/// `query` — полный запрос, `response` — полный ответ с SIG(0).
///
/// # Errors
///
/// [`Sig0Error`] если подпись отсутствует, просрочена или неверна.
pub fn verify_response(
    query: &[u8],
    response: &[u8],
    dnskey: &DnskeyData,
    now: u32,
    max_validity: u32,
) -> Result<Sig0Signature, Sig0Error> {
    let location = find_sig0(response)?.ok_or(Sig0Error::Missing)?;
    let signature = &location.signature;
    if signature.algorithm != dnskey.algorithm() || signature.key_tag != key_tag(dnskey) {
        return Err(Sig0Error::KeyMismatch);
    }
    signature.check_time(now, max_validity)?;
    let without = response
        .get(..location.offset)
        .ok_or(Sig0Error::Malformed {
            reason: "SIG(0) offset is out of bounds",
        })?;
    let mut header = header_bytes(without)?;
    let arcount = u16_at(&header, 10).ok_or(Sig0Error::ShortHeader)?;
    let arcount = arcount.checked_sub(1).ok_or(Sig0Error::Malformed {
        reason: "ARCOUNT is zero",
    })?;
    header
        .get_mut(10..12)
        .ok_or(Sig0Error::ShortHeader)?
        .copy_from_slice(&arcount.to_be_bytes());
    let mut data = signature.rdata_without_signature();
    data.extend_from_slice(query);
    data.extend_from_slice(&header);
    data.extend_from_slice(without.get(12..).ok_or(Sig0Error::ShortHeader)?);
    verify_message_signature(
        Algorithm::from_u8(signature.algorithm),
        dnskey,
        &data,
        &signature.signature,
    )
    .map_err(|_| Sig0Error::BadSignature)?;
    Ok(signature.clone())
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let value: [u8; 2] = bytes.get(offset..end)?.try_into().ok()?;
    Some(u16::from_be_bytes(value))
}

fn header_bytes(raw: &[u8]) -> Result<[u8; 12], Sig0Error> {
    raw.get(..12)
        .and_then(|slice| <[u8; 12]>::try_from(slice).ok())
        .ok_or(Sig0Error::ShortHeader)
}

struct Cursor<'a> {
    source: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(source: &'a [u8]) -> Self {
        Self {
            source,
            position: 0,
        }
    }

    const fn at(source: &'a [u8], position: usize) -> Self {
        Self { source, position }
    }

    const fn position(&self) -> usize {
        self.position
    }

    fn take(&mut self, length: usize, reason: &'static str) -> Result<&'a [u8], Sig0Error> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(Sig0Error::Malformed { reason })?;
        let slice = self
            .source
            .get(self.position..end)
            .ok_or(Sig0Error::Malformed { reason })?;
        self.position = end;
        Ok(slice)
    }

    fn skip(&mut self, length: usize, reason: &'static str) -> Result<(), Sig0Error> {
        let _ = self.take(length, reason)?;
        Ok(())
    }

    fn u8(&mut self, reason: &'static str) -> Result<u8, Sig0Error> {
        let bytes = self.take(1, reason)?;
        bytes
            .first()
            .copied()
            .ok_or(Sig0Error::Malformed { reason })
    }

    fn u16(&mut self, reason: &'static str) -> Result<u16, Sig0Error> {
        let bytes = self.take(2, reason)?;
        match bytes {
            [high, low] => Ok(u16::from_be_bytes([*high, *low])),
            _ => Err(Sig0Error::Malformed { reason }),
        }
    }

    fn u32(&mut self, reason: &'static str) -> Result<u32, Sig0Error> {
        let bytes = self.take(4, reason)?;
        match bytes {
            [a, b, c, d] => Ok(u32::from_be_bytes([*a, *b, *c, *d])),
            _ => Err(Sig0Error::Malformed { reason }),
        }
    }

    fn rest(&mut self) -> &'a [u8] {
        let rest = self.source.get(self.position..).unwrap_or_default();
        self.position = self.source.len();
        rest
    }

    /// Пропускает DNS-имя, поддерживая указатели сжатия.
    fn skip_name(&mut self) -> Result<(), Sig0Error> {
        loop {
            let length = self.u8("name length")?;
            match length & 0xC0 {
                0x00 => {
                    if length == 0 {
                        return Ok(());
                    }
                    self.skip(usize::from(length), "name label")?;
                }
                0xC0 => {
                    self.skip(1, "compression pointer")?;
                    return Ok(());
                }
                _ => {
                    return Err(Sig0Error::Malformed {
                        reason: "invalid label length",
                    });
                }
            }
        }
    }

    fn name(&mut self) -> Result<Name, Sig0Error> {
        let start = self.position;
        loop {
            let length = self.u8("signer name length")?;
            if length == 0 {
                break;
            }
            if length & 0xC0 != 0 {
                return Err(Sig0Error::CompressedSigner);
            }
            self.skip(usize::from(length), "signer label")?;
        }
        let bytes = self
            .source
            .get(start..self.position)
            .ok_or(Sig0Error::Malformed {
                reason: "signer name is out of bounds",
            })?;
        Name::from_wire(bytes).map_err(|_| Sig0Error::InvalidRdata {
            reason: "invalid signer name",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pulse_dns::{Flags, Message, Opcode, Question, Rtype};

    fn dnskey(key: &PrivateKey) -> DnskeyData {
        key.dnskey(256).expect("dnskey")
    }

    fn request(raw_extra: bool) -> Vec<u8> {
        let mut message = Message::new(7, Flags::new().with_opcode(Opcode::UPDATE));
        message.add_question(Question::new(
            Name::parse("example.com").unwrap(),
            Rtype::SOA,
            Rclass::IN,
        ));
        message
            .encode(&pulse_dns::EncodeOptions::compressed())
            .expect("encode");
        if raw_extra {
            message.add_additional(
                Record::new(
                    Name::root(),
                    Rtype::from_u16(RTYPE_SIG0),
                    Rclass::ANY,
                    Ttl::ZERO,
                    Rdata::unknown(Rtype::from_u16(RTYPE_SIG0), vec![0, 0, 15, 0, 0, 0, 0, 0])
                        .expect("rdata"),
                )
                .expect("record"),
            );
        }
        message
            .encode(&pulse_dns::EncodeOptions::compressed())
            .expect("encode")
    }

    #[test]
    fn parse_rejects_compressed_signer() {
        let mut rdata = vec![0_u8; 18];
        rdata.push(0xC0);
        rdata.push(0x00);
        let error = Sig0Signature::parse_rdata(&rdata).expect_err("compressed");
        assert_eq!(error, Sig0Error::CompressedSigner);
    }

    #[test]
    fn sign_and_verify_request() {
        let key = PrivateKey::generate(Algorithm::ED25519).expect("key");
        let public = dnskey(&key);
        let signer = Name::parse("host.example.com").unwrap();
        let now = 1_700_000_000_u32;
        let message = request(false);
        let mut signature =
            Sig0Signature::new(15, 0, now + 300, now - 10, key_tag(&public), signer.clone());
        let mut data = signature.rdata_without_signature();
        data.extend_from_slice(&message);
        signature.signature = key.sign_message(&data).expect("sign");
        let signed = append_record(&message, &signature).expect("append");
        let verified = verify_request(&signed, &public, now, 600).expect("verify");
        assert_eq!(verified.signer, signer);
        assert_eq!(verified.signature, signature.signature);
    }

    #[test]
    fn wrong_key_and_time_are_rejected() {
        let key = PrivateKey::generate(Algorithm::ED25519).expect("key");
        let other = PrivateKey::generate(Algorithm::ED25519).expect("other");
        let public = dnskey(&key);
        let now = 1_700_000_000_u32;
        let message = request(false);
        let mut signature = Sig0Signature::new(
            15,
            0,
            now + 300,
            now - 10,
            key_tag(&public),
            Name::parse("host.example.com").unwrap(),
        );
        let mut data = signature.rdata_without_signature();
        data.extend_from_slice(&message);
        signature.signature = key.sign_message(&data).expect("sign");
        let signed = append_record(&message, &signature).expect("append");
        verify_request(&signed, &public, now, 600).expect("verify");
        assert_eq!(
            verify_request(&signed, &dnskey(&other), now, 600).expect_err("key"),
            Sig0Error::KeyMismatch
        );
        assert_eq!(
            verify_request(&signed, &public, now + 400, 600).expect_err("time"),
            Sig0Error::TimeInvalid
        );
        assert_eq!(
            verify_request(&signed, &public, now, 100).expect_err("window"),
            Sig0Error::ValidityTooWide
        );
    }

    #[test]
    fn response_signature_covers_query() {
        let key = PrivateKey::generate(Algorithm::ED25519).expect("key");
        let public = dnskey(&key);
        let signer = Name::parse("ns1.example.com").unwrap();
        let now = 1_700_000_000_u32;
        let query = request(false);
        let response = request(false);
        let signed = sign_response(&query, &response, &signer, &key, &public, now, 300, 10)
            .expect("sign response");
        let verified = verify_response(&query, &signed, &public, now, 600).expect("verify");
        assert_eq!(verified.signer, signer);
        let other_query = request(true);
        assert_eq!(
            verify_response(&other_query, &signed, &public, now, 600).expect_err("query"),
            Sig0Error::BadSignature
        );
    }
}
