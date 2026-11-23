//! RDATA: типизированные данные DNS-записей (`domain-model.md` §2.3).

use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};

use thiserror::Error;

use super::name::{Name, NameError};
use super::rr::Rtype;
use super::serial::Serial;

/// Ошибка валидации RDATA.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RdataError {
    /// Поле пустое, хотя обязано содержать данные.
    #[error("field {field} must not be empty")]
    Empty {
        /// Имя поля.
        field: &'static str,
    },
    /// Недопустимая длина поля.
    #[error("field {field} has invalid length {len}")]
    InvalidLength {
        /// Имя поля.
        field: &'static str,
        /// Фактическая длина.
        len: usize,
    },
    /// Недопустимое значение поля.
    #[error("field {field} has invalid value")]
    InvalidValue {
        /// Имя поля.
        field: &'static str,
    },
    /// RDATA целиком больше 65535 октетов.
    #[error("rdata is {len} octets long (max 65535)")]
    TooLong {
        /// Фактическая длина.
        len: usize,
    },
    /// Неизвестный тип закодирован как известный.
    #[error("type {rr_type} is known and cannot use opaque RDATA")]
    KnownTypeAsUnknown {
        /// Тип записи.
        rr_type: Rtype,
    },
    /// Некорректная структура type bitmap.
    #[error("invalid type bitmap: {reason}")]
    TypeBitmap {
        /// Причина.
        reason: &'static str,
    },
    /// Ошибка доменного имени.
    #[error(transparent)]
    Name(#[from] NameError),
}

/// SOA RDATA (RFC 1035 §3.3.13).
///
/// Таймеры SOA — полные `u32` по RFC 1035; clamp `2^31−1` применяется только
/// к TTL самой записи ([`super::ttl::Ttl`]), но не к этим полям.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SoaData {
    /// Primary master name server.
    pub mname: Name,
    /// Responsible mailbox.
    pub rname: Name,
    /// Serial зоны.
    pub serial: Serial,
    /// Refresh interval (полный `u32`).
    pub refresh: u32,
    /// Retry interval (полный `u32`).
    pub retry: u32,
    /// Expire interval (полный `u32`).
    pub expire: u32,
    /// Negative caching TTL (полный `u32`).
    pub minimum: u32,
}

impl SoaData {
    /// Создаёт SOA-данные.
    #[must_use]
    pub const fn new(
        mname: Name,
        rname: Name,
        serial: Serial,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    ) -> Self {
        Self {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        }
    }
}

/// TXT-данные: один или несколько character-string (RFC 1035 §3.3).
///
/// Сегмент — 0..=255 октетов (пустой character-string легален), суммарная
/// wire-длина (с длинами) ≤ 65535.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TxtData(Vec<Vec<u8>>);

impl TxtData {
    /// Создаёт TXT-данные, проверяя длину сегментов.
    ///
    /// # Errors
    ///
    /// [`RdataError`], если сегментов нет, сегмент длиннее 255 октетов или
    /// суммарная RDATA больше 65535.
    pub fn new(segments: impl IntoIterator<Item = Vec<u8>>) -> Result<Self, RdataError> {
        let segments: Vec<Vec<u8>> = segments.into_iter().collect();
        if segments.is_empty() {
            return Err(RdataError::Empty { field: "txt" });
        }
        let mut total = 0_usize;
        for segment in &segments {
            if segment.len() > usize::from(u8::MAX) {
                return Err(RdataError::InvalidLength {
                    field: "txt segment",
                    len: segment.len(),
                });
            }
            total = total
                .checked_add(segment.len() + 1)
                .ok_or(RdataError::TooLong { len: usize::MAX })?;
        }
        if total > usize::from(u16::MAX) {
            return Err(RdataError::TooLong { len: total });
        }
        Ok(Self(segments))
    }

    /// Сегменты TXT.
    #[must_use]
    pub fn segments(&self) -> &[Vec<u8>] {
        &self.0
    }
}

/// Тег CAA (RFC 8659).
///
/// Регистр сохраняется как на wire: tag — не domain name, lowercase из
/// RFC 4034 §6.2 к нему не применяется.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CaaTag(Vec<u8>);

impl CaaTag {
    /// Создаёт тег: 1..=255 ASCII-букв/цифр; байты сохраняются без изменения.
    ///
    /// # Errors
    ///
    /// [`RdataError`], если тег пуст, длиннее 255 или содержит посторонние
    /// символы.
    pub fn new(tag: impl AsRef<[u8]>) -> Result<Self, RdataError> {
        let tag = tag.as_ref();
        if tag.is_empty() || tag.len() > usize::from(u8::MAX) {
            return Err(RdataError::InvalidLength {
                field: "caa tag",
                len: tag.len(),
            });
        }
        if !tag.iter().all(u8::is_ascii_alphanumeric) {
            return Err(RdataError::InvalidValue { field: "caa tag" });
        }
        Ok(Self(tag.to_vec()))
    }

    /// Тег `issue`.
    #[must_use]
    pub fn issue() -> Self {
        Self(b"issue".to_vec())
    }

    /// Тег `issuewild`.
    #[must_use]
    pub fn issuewild() -> Self {
        Self(b"issuewild".to_vec())
    }

    /// Тег `iodef`.
    #[must_use]
    pub fn iodef() -> Self {
        Self(b"iodef".to_vec())
    }

    /// Байты тега.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Сравнение тегов без учёта регистра ASCII.
    ///
    /// Wire-форма хранит регистр как есть; семантика CAA-тегов
    /// регистронезависима.
    #[must_use]
    pub fn eq_ignore_ascii_case(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }
}

impl fmt::Display for CaaTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for &byte in &self.0 {
            f.write_char(char::from(byte))?;
        }
        Ok(())
    }
}

/// DS RDATA (RFC 4034 §5.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DsData {
    key_tag: u16,
    algorithm: u8,
    digest_type: u8,
    digest: Vec<u8>,
}

impl DsData {
    /// Создаёт DS-данные.
    ///
    /// # Errors
    ///
    /// [`RdataError`], если digest пуст или больше 65535.
    pub fn new(
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: impl Into<Vec<u8>>,
    ) -> Result<Self, RdataError> {
        let digest = digest.into();
        if digest.is_empty() {
            return Err(RdataError::Empty { field: "ds digest" });
        }
        if digest.len() > usize::from(u16::MAX) {
            return Err(RdataError::TooLong { len: digest.len() });
        }
        let expected = match digest_type {
            1 => Some(20),
            2 => Some(32),
            4 => Some(48),
            _ => None,
        };
        if let Some(expected) = expected
            && digest.len() != expected
        {
            return Err(RdataError::InvalidLength {
                field: "ds digest",
                len: digest.len(),
            });
        }
        Ok(Self {
            key_tag,
            algorithm,
            digest_type,
            digest,
        })
    }

    /// Key tag.
    #[must_use]
    pub const fn key_tag(&self) -> u16 {
        self.key_tag
    }

    /// DNSSEC algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> u8 {
        self.algorithm
    }

    /// Digest type.
    #[must_use]
    pub const fn digest_type(&self) -> u8 {
        self.digest_type
    }

    /// Digest.
    #[must_use]
    pub fn digest(&self) -> &[u8] {
        &self.digest
    }
}

/// DNSKEY RDATA (RFC 4034 §2.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnskeyData {
    flags: u16,
    protocol: u8,
    algorithm: u8,
    public_key: Vec<u8>,
}

impl DnskeyData {
    /// Создаёт DNSKEY-данные.
    ///
    /// # Errors
    ///
    /// [`RdataError`], если protocol не равен 3 (RFC 4034 §2.1), ключ пуст
    /// или больше 65535.
    pub fn new(
        flags: u16,
        protocol: u8,
        algorithm: u8,
        public_key: impl Into<Vec<u8>>,
    ) -> Result<Self, RdataError> {
        if protocol != 3 {
            return Err(RdataError::InvalidValue {
                field: "dnskey protocol",
            });
        }
        let public_key = public_key.into();
        if public_key.is_empty() {
            return Err(RdataError::Empty {
                field: "dnskey public key",
            });
        }
        if public_key.len() > usize::from(u16::MAX) {
            return Err(RdataError::TooLong {
                len: public_key.len(),
            });
        }
        Ok(Self {
            flags,
            protocol,
            algorithm,
            public_key,
        })
    }

    /// Flags (bit 0x0100 — zone key, 0x0001 — SEP).
    #[must_use]
    pub const fn flags(&self) -> u16 {
        self.flags
    }

    /// Protocol (всегда 3).
    #[must_use]
    pub const fn protocol(&self) -> u8 {
        self.protocol
    }

    /// Algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> u8 {
        self.algorithm
    }

    /// Публичный ключ.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

/// RRSIG RDATA (RFC 4034 §3.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RrsigData {
    type_covered: Rtype,
    algorithm: u8,
    labels: u8,
    original_ttl: u32,
    signature_expiration: u32,
    signature_inception: u32,
    key_tag: u16,
    signer_name: Name,
    signature: Vec<u8>,
}

impl RrsigData {
    /// Создаёт RRSIG-данные.
    ///
    /// `original_ttl` — полный `u32`: это подписанные данные, clamp не
    /// применяется (в отличие от TTL самой RR).
    ///
    /// # Errors
    ///
    /// [`RdataError`], если подпись пуста или больше 65535.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        type_covered: Rtype,
        algorithm: u8,
        labels: u8,
        original_ttl: u32,
        signature_expiration: u32,
        signature_inception: u32,
        key_tag: u16,
        signer_name: Name,
        signature: impl Into<Vec<u8>>,
    ) -> Result<Self, RdataError> {
        let signature = signature.into();
        if signature.is_empty() {
            return Err(RdataError::Empty {
                field: "rrsig signature",
            });
        }
        if signature.len() > usize::from(u16::MAX) {
            return Err(RdataError::TooLong {
                len: signature.len(),
            });
        }
        Ok(Self {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            signature_expiration,
            signature_inception,
            key_tag,
            signer_name,
            signature,
        })
    }

    /// Тип, к которому относится подпись.
    #[must_use]
    pub const fn type_covered(&self) -> Rtype {
        self.type_covered
    }

    /// Algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> u8 {
        self.algorithm
    }

    /// Число меток в исходном имени.
    #[must_use]
    pub const fn labels(&self) -> u8 {
        self.labels
    }

    /// Original TTL (полный `u32`, как в подписанных данных).
    #[must_use]
    pub const fn original_ttl(&self) -> u32 {
        self.original_ttl
    }

    /// Время истечения (секунды UNIX).
    #[must_use]
    pub const fn signature_expiration(&self) -> u32 {
        self.signature_expiration
    }

    /// Время начала действия (секунды UNIX).
    #[must_use]
    pub const fn signature_inception(&self) -> u32 {
        self.signature_inception
    }

    /// Key tag.
    #[must_use]
    pub const fn key_tag(&self) -> u16 {
        self.key_tag
    }

    /// Signer name.
    #[must_use]
    pub const fn signer_name(&self) -> &Name {
        &self.signer_name
    }

    /// Подпись.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Проверяет валидность окна подписи (RFC 1982, INV-18).
    #[must_use]
    pub fn is_valid_at(&self, now: u32) -> bool {
        let now = Serial::new(now);
        let inception = Serial::new(self.signature_inception);
        let expiration = Serial::new(self.signature_expiration);
        let not_before = now == inception || now.is_newer_than(inception) == Some(true);
        let not_after = now == expiration || expiration.is_newer_than(now) == Some(true);
        not_before && not_after
    }
}

/// Type bitmap (RFC 4034 §4.1.2): окна window/bitmap.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypeBitmap(Vec<u8>);

impl TypeBitmap {
    /// Разбирает и валидирует type bitmap из wire-формы.
    ///
    /// Пустой bitmap запрещён (используйте [`TypeBitmap::new_allow_empty`]
    /// для NSEC3 empty non-terminal).
    ///
    /// # Errors
    ///
    /// [`RdataError::TypeBitmap`] при пустом/некорректном bitmap.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, RdataError> {
        Self::build(bytes.into(), false)
    }

    /// Разбирает bitmap, допуская пустое значение.
    ///
    /// RFC 5155 §8.5: NSEC3 для empty non-terminal содержит пустой Type Bit
    /// Maps. Структурная валидация непустого bitmap остаётся строгой.
    ///
    /// # Errors
    ///
    /// [`RdataError::TypeBitmap`] при некорректной структуре.
    pub fn new_allow_empty(bytes: impl Into<Vec<u8>>) -> Result<Self, RdataError> {
        Self::build(bytes.into(), true)
    }

    fn build(bytes: Vec<u8>, allow_empty: bool) -> Result<Self, RdataError> {
        validate_bitmap(&bytes, allow_empty)?;
        Ok(Self(bytes))
    }

    /// Строит bitmap из набора типов.
    #[must_use]
    pub fn from_types(types: impl IntoIterator<Item = Rtype>) -> Self {
        let mut windows: BTreeMap<u8, Vec<u8>> = BTreeMap::new();
        for rr_type in types {
            let value = rr_type.as_u16();
            let window = u8::try_from(value >> 8).unwrap_or(u8::MAX);
            let low = u8::try_from(value & 0x00FF).unwrap_or(0);
            let octet = usize::from(low / 8);
            let mask = 0x80_u8 >> (low % 8);
            let block = windows.entry(window).or_default();
            if block.len() <= octet {
                block.resize(octet + 1, 0);
            }
            if let Some(slot) = block.get_mut(octet) {
                *slot |= mask;
            }
        }

        let mut bytes = Vec::new();
        for (window, block) in windows {
            bytes.push(window);
            bytes.push(u8::try_from(block.len()).unwrap_or(32));
            bytes.extend_from_slice(&block);
        }
        Self(bytes)
    }

    /// Wire-форма bitmap.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Содержит ли bitmap указанный тип.
    #[must_use]
    pub fn contains(&self, rr_type: Rtype) -> bool {
        let value = rr_type.as_u16();
        let window = u8::try_from(value >> 8).unwrap_or(u8::MAX);
        let low = u8::try_from(value & 0x00FF).unwrap_or(0);
        let mut position = 0_usize;
        while let (Some(&current), Some(&length)) = (self.0.get(position), self.0.get(position + 1))
        {
            let length = usize::from(length);
            if current == window {
                let octet = usize::from(low / 8);
                if octet >= length {
                    return false;
                }
                let Some(&byte) = self.0.get(position + 2 + octet) else {
                    return false;
                };
                return byte & (0x80 >> (low % 8)) != 0;
            }
            position = position.saturating_add(2 + length);
        }
        false
    }

    /// Список типов в bitmap.
    #[must_use]
    pub fn types(&self) -> Vec<Rtype> {
        let mut result = Vec::new();
        let mut position = 0_usize;
        while let (Some(&window), Some(&length)) = (self.0.get(position), self.0.get(position + 1))
        {
            let length = usize::from(length);
            for octet in 0..length {
                let Some(&byte) = self.0.get(position + 2 + octet) else {
                    break;
                };
                for bit in 0..8_u16 {
                    if byte & (0x80 >> bit) != 0 {
                        let octet = u16::try_from(octet).unwrap_or(0);
                        let value = (u16::from(window) << 8) | (octet * 8 + bit);
                        result.push(Rtype::from_u16(value));
                    }
                }
            }
            position = position.saturating_add(2 + length);
        }
        result
    }

    /// Пуст ли bitmap (допустимо только для NSEC3 empty non-terminal).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

fn validate_bitmap(bytes: &[u8], allow_empty: bool) -> Result<(), RdataError> {
    if bytes.is_empty() {
        if allow_empty {
            return Ok(());
        }
        return Err(RdataError::TypeBitmap {
            reason: "empty bitmap",
        });
    }
    let mut position = 0_usize;
    let mut previous_window: Option<u8> = None;
    while position < bytes.len() {
        let Some(&window) = bytes.get(position) else {
            return Err(RdataError::TypeBitmap {
                reason: "truncated window",
            });
        };
        let Some(&length) = bytes.get(position + 1) else {
            return Err(RdataError::TypeBitmap {
                reason: "truncated window length",
            });
        };
        if length == 0 || length > 32 {
            return Err(RdataError::TypeBitmap {
                reason: "window length outside 1..=32",
            });
        }
        if let Some(previous) = previous_window
            && window <= previous
        {
            return Err(RdataError::TypeBitmap {
                reason: "windows not strictly increasing",
            });
        }
        previous_window = Some(window);
        let start = position + 2;
        let end = start + usize::from(length);
        let Some(block) = bytes.get(start..end) else {
            return Err(RdataError::TypeBitmap {
                reason: "truncated bitmap block",
            });
        };
        if block.last().copied() == Some(0) {
            return Err(RdataError::TypeBitmap {
                reason: "trailing zero octet in bitmap block",
            });
        }
        position = end;
    }
    Ok(())
}

/// NSEC RDATA (RFC 4034 §4.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NsecData {
    next_domain: Name,
    type_bitmap: TypeBitmap,
}

impl NsecData {
    /// Создаёт NSEC-данные.
    ///
    /// # Errors
    ///
    /// [`RdataError`], если bitmap пуст.
    pub fn new(next_domain: Name, type_bitmap: TypeBitmap) -> Result<Self, RdataError> {
        if type_bitmap.is_empty() {
            return Err(RdataError::Empty {
                field: "nsec bitmap",
            });
        }
        Ok(Self {
            next_domain,
            type_bitmap,
        })
    }

    /// Следующее имя в каноническом порядке.
    #[must_use]
    pub const fn next_domain(&self) -> &Name {
        &self.next_domain
    }

    /// Type bitmap.
    #[must_use]
    pub const fn type_bitmap(&self) -> &TypeBitmap {
        &self.type_bitmap
    }
}

/// NSEC3 RDATA (RFC 5155 §3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Nsec3Data {
    hash_algorithm: u8,
    flags: u8,
    iterations: u16,
    salt: Vec<u8>,
    next_hashed_owner: Vec<u8>,
    type_bitmap: TypeBitmap,
}

impl Nsec3Data {
    /// Создаёт NSEC3-данные.
    ///
    /// Пустой Type Bit Maps допустим для empty non-terminal (RFC 5155 §8.5).
    ///
    /// # Errors
    ///
    /// [`RdataError`], если salt длиннее 255, next hash пуст/длиннее 255,
    /// для algorithm 1 hash length ≠ 20 или bitmap структурно некорректен.
    pub fn new(
        hash_algorithm: u8,
        flags: u8,
        iterations: u16,
        salt: impl Into<Vec<u8>>,
        next_hashed_owner: impl Into<Vec<u8>>,
        type_bitmap: TypeBitmap,
    ) -> Result<Self, RdataError> {
        let salt = salt.into();
        let next_hashed_owner = next_hashed_owner.into();
        if salt.len() > usize::from(u8::MAX) {
            return Err(RdataError::InvalidLength {
                field: "nsec3 salt",
                len: salt.len(),
            });
        }
        if next_hashed_owner.is_empty() || next_hashed_owner.len() > usize::from(u8::MAX) {
            return Err(RdataError::InvalidLength {
                field: "nsec3 next hashed owner",
                len: next_hashed_owner.len(),
            });
        }
        if hash_algorithm == 1 && next_hashed_owner.len() != 20 {
            return Err(RdataError::InvalidLength {
                field: "nsec3 next hashed owner",
                len: next_hashed_owner.len(),
            });
        }
        Ok(Self {
            hash_algorithm,
            flags,
            iterations,
            salt,
            next_hashed_owner,
            type_bitmap,
        })
    }

    /// Hash algorithm.
    #[must_use]
    pub const fn hash_algorithm(&self) -> u8 {
        self.hash_algorithm
    }

    /// Flags.
    #[must_use]
    pub const fn flags(&self) -> u8 {
        self.flags
    }

    /// Iterations.
    #[must_use]
    pub const fn iterations(&self) -> u16 {
        self.iterations
    }

    /// Salt.
    #[must_use]
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// Next hashed owner.
    #[must_use]
    pub fn next_hashed_owner(&self) -> &[u8] {
        &self.next_hashed_owner
    }

    /// Type bitmap.
    #[must_use]
    pub const fn type_bitmap(&self) -> &TypeBitmap {
        &self.type_bitmap
    }
}

/// NSEC3PARAM RDATA (RFC 5155 §4).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Nsec3ParamData {
    hash_algorithm: u8,
    flags: u8,
    iterations: u16,
    salt: Vec<u8>,
}

impl Nsec3ParamData {
    /// Создаёт NSEC3PARAM-данные.
    ///
    /// # Errors
    ///
    /// [`RdataError`], если salt длиннее 255.
    pub fn new(
        hash_algorithm: u8,
        flags: u8,
        iterations: u16,
        salt: impl Into<Vec<u8>>,
    ) -> Result<Self, RdataError> {
        let salt = salt.into();
        if salt.len() > usize::from(u8::MAX) {
            return Err(RdataError::InvalidLength {
                field: "nsec3param salt",
                len: salt.len(),
            });
        }
        Ok(Self {
            hash_algorithm,
            flags,
            iterations,
            salt,
        })
    }

    /// Hash algorithm.
    #[must_use]
    pub const fn hash_algorithm(&self) -> u8 {
        self.hash_algorithm
    }

    /// Flags.
    #[must_use]
    pub const fn flags(&self) -> u8 {
        self.flags
    }

    /// Iterations.
    #[must_use]
    pub const fn iterations(&self) -> u16 {
        self.iterations
    }

    /// Salt.
    #[must_use]
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }
}

/// TLSA RDATA (RFC 6698 §2.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TlsaData {
    usage: u8,
    selector: u8,
    matching: u8,
    certificate_association_data: Vec<u8>,
}

impl TlsaData {
    /// Создаёт TLSA-данные.
    ///
    /// # Errors
    ///
    /// [`RdataError`], если association data пусты или больше 65535.
    pub fn new(
        usage: u8,
        selector: u8,
        matching: u8,
        certificate_association_data: impl Into<Vec<u8>>,
    ) -> Result<Self, RdataError> {
        let data = certificate_association_data.into();
        if data.is_empty() {
            return Err(RdataError::Empty {
                field: "tlsa association data",
            });
        }
        if data.len() > usize::from(u16::MAX) {
            return Err(RdataError::TooLong { len: data.len() });
        }
        let expected = match matching {
            1 => Some(32),
            2 => Some(64),
            _ => None,
        };
        if let Some(expected) = expected
            && data.len() != expected
        {
            return Err(RdataError::InvalidLength {
                field: "tlsa association data",
                len: data.len(),
            });
        }
        Ok(Self {
            usage,
            selector,
            matching,
            certificate_association_data: data,
        })
    }

    /// Certificate usage.
    #[must_use]
    pub const fn usage(&self) -> u8 {
        self.usage
    }

    /// Selector.
    #[must_use]
    pub const fn selector(&self) -> u8 {
        self.selector
    }

    /// Matching type.
    #[must_use]
    pub const fn matching(&self) -> u8 {
        self.matching
    }

    /// Certificate association data.
    #[must_use]
    pub fn certificate_association_data(&self) -> &[u8] {
        &self.certificate_association_data
    }
}

/// Один SVCB/HTTPS SvcParam (RFC 9460 §2.2), значение непрозрачно.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SvcParam {
    key: u16,
    value: Vec<u8>,
}

impl SvcParam {
    /// Ключ `mandatory`.
    pub const KEY_MANDATORY: u16 = 0;
    /// Ключ `alpn`.
    pub const KEY_ALPN: u16 = 1;
    /// Ключ `port`.
    pub const KEY_PORT: u16 = 3;
    /// Ключ `ipv4hint`.
    pub const KEY_IPV4HINT: u16 = 4;
    /// Ключ `ech`.
    pub const KEY_ECH: u16 = 5;
    /// Ключ `ipv6hint`.
    pub const KEY_IPV6HINT: u16 = 6;

    /// Создаёт параметр, валидируя известные ключи:
    /// `mandatory` — непустой строго возрастающий список ключей без нуля,
    /// `port` — 2 байта, `ipv4hint` — кратно 4, `ipv6hint` — кратно 16.
    ///
    /// # Errors
    ///
    /// [`RdataError::TooLong`] или [`RdataError::InvalidLength`] /
    /// [`RdataError::InvalidValue`] для некорректного известного ключа.
    pub fn new(key: u16, value: impl Into<Vec<u8>>) -> Result<Self, RdataError> {
        let value = value.into();
        if value.len() > usize::from(u16::MAX) {
            return Err(RdataError::TooLong { len: value.len() });
        }
        match key {
            Self::KEY_MANDATORY => validate_mandatory(&value)?,
            Self::KEY_PORT if value.len() != 2 => {
                return Err(RdataError::InvalidLength {
                    field: "svcb port",
                    len: value.len(),
                });
            }
            Self::KEY_IPV4HINT if !value.len().is_multiple_of(4) => {
                return Err(RdataError::InvalidLength {
                    field: "svcb ipv4hint",
                    len: value.len(),
                });
            }
            Self::KEY_IPV6HINT if !value.len().is_multiple_of(16) => {
                return Err(RdataError::InvalidLength {
                    field: "svcb ipv6hint",
                    len: value.len(),
                });
            }
            _ => {}
        }
        Ok(Self { key, value })
    }

    /// Ключ параметра.
    #[must_use]
    pub const fn key(&self) -> u16 {
        self.key
    }

    /// Значение параметра.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

fn validate_mandatory(value: &[u8]) -> Result<(), RdataError> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return Err(RdataError::InvalidLength {
            field: "svcb mandatory",
            len: value.len(),
        });
    }
    let mut previous: Option<u16> = None;
    let (pairs, _remainder) = value.as_chunks::<2>();
    for chunk in pairs {
        let key = u16::from_be_bytes(*chunk);
        if key == 0 || previous.is_some_and(|previous| key <= previous) {
            return Err(RdataError::InvalidValue {
                field: "svcb mandatory",
            });
        }
        previous = Some(key);
    }
    Ok(())
}

/// SVCB/HTTPS RDATA (RFC 9460), базовая поддержка.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SvcbData {
    priority: u16,
    target: Name,
    params: Vec<SvcParam>,
}

impl SvcbData {
    /// Создаёт SVCB-данные, требуя строго возрастающий порядок ключей.
    ///
    /// # Errors
    ///
    /// [`RdataError::InvalidValue`], если ключи повторяются или не
    /// отсортированы.
    pub fn new(priority: u16, target: Name, params: Vec<SvcParam>) -> Result<Self, RdataError> {
        for pair in params.windows(2) {
            let (Some(left), Some(right)) = (pair.first(), pair.get(1)) else {
                continue;
            };
            if left.key >= right.key {
                return Err(RdataError::InvalidValue {
                    field: "svcb params order",
                });
            }
        }
        Ok(Self {
            priority,
            target,
            params,
        })
    }

    /// Priority (0 — alias mode).
    #[must_use]
    pub const fn priority(&self) -> u16 {
        self.priority
    }

    /// TargetName.
    #[must_use]
    pub const fn target(&self) -> &Name {
        &self.target
    }

    /// Параметры в возрастающем порядке ключей.
    #[must_use]
    pub fn params(&self) -> &[SvcParam] {
        &self.params
    }
}

/// RDATA DNS-записи.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Rdata {
    /// IPv4-адрес.
    A(Ipv4Addr),
    /// IPv6-адрес.
    Aaaa(Ipv6Addr),
    /// Name server.
    Ns(Name),
    /// Canonical name.
    Cname(Name),
    /// Start of authority.
    Soa(SoaData),
    /// Pointer.
    Ptr(Name),
    /// Mail exchange.
    Mx {
        /// Preference.
        preference: u16,
        /// Exchange host.
        exchange: Name,
    },
    /// Text.
    Txt(TxtData),
    /// Service locator.
    Srv {
        /// Priority.
        priority: u16,
        /// Weight.
        weight: u16,
        /// Port.
        port: u16,
        /// Target host.
        target: Name,
    },
    /// CAA.
    Caa {
        /// Flags.
        flags: u8,
        /// Tag.
        tag: CaaTag,
        /// Value.
        value: Vec<u8>,
    },
    /// Delegation name.
    Dname(Name),
    /// Delegation signer.
    Ds(DsData),
    /// DNSSEC public key.
    Dnskey(DnskeyData),
    /// DNSSEC signature.
    Rrsig(RrsigData),
    /// NSEC.
    Nsec(NsecData),
    /// NSEC3.
    Nsec3(Nsec3Data),
    /// NSEC3PARAM.
    Nsec3Param(Nsec3ParamData),
    /// TLSA.
    Tlsa(TlsaData),
    /// SVCB.
    Svcb(SvcbData),
    /// HTTPS.
    Https(SvcbData),
    /// Непрозрачные данные неизвестного типа (RFC 3597).
    Unknown {
        /// Тип записи.
        rr_type: Rtype,
        /// RDATA байт-в-байт.
        rdata: Vec<u8>,
    },
}

impl Rdata {
    /// Создаёт непрозрачные RDATA для неизвестного типа.
    ///
    /// # Errors
    ///
    /// [`RdataError::KnownTypeAsUnknown`], если тип известен крейту.
    pub fn unknown(rr_type: Rtype, rdata: impl Into<Vec<u8>>) -> Result<Self, RdataError> {
        if rr_type.is_known() {
            return Err(RdataError::KnownTypeAsUnknown { rr_type });
        }
        let rdata = rdata.into();
        if rdata.len() > usize::from(u16::MAX) {
            return Err(RdataError::TooLong { len: rdata.len() });
        }
        Ok(Self::Unknown { rr_type, rdata })
    }

    /// Детерминированное отображение варианта в тип записи.
    #[must_use]
    pub const fn rr_type(&self) -> Rtype {
        match self {
            Self::A(_) => Rtype::A,
            Self::Aaaa(_) => Rtype::AAAA,
            Self::Ns(_) => Rtype::NS,
            Self::Cname(_) => Rtype::CNAME,
            Self::Soa(_) => Rtype::SOA,
            Self::Ptr(_) => Rtype::PTR,
            Self::Mx { .. } => Rtype::MX,
            Self::Txt(_) => Rtype::TXT,
            Self::Srv { .. } => Rtype::SRV,
            Self::Caa { .. } => Rtype::CAA,
            Self::Dname(_) => Rtype::DNAME,
            Self::Ds(_) => Rtype::DS,
            Self::Dnskey(_) => Rtype::DNSKEY,
            Self::Rrsig(_) => Rtype::RRSIG,
            Self::Nsec(_) => Rtype::NSEC,
            Self::Nsec3(_) => Rtype::NSEC3,
            Self::Nsec3Param(_) => Rtype::NSEC3PARAM,
            Self::Tlsa(_) => Rtype::TLSA,
            Self::Svcb(_) => Rtype::SVCB,
            Self::Https(_) => Rtype::HTTPS,
            Self::Unknown { rr_type, .. } => *rr_type,
        }
    }

    /// Проверяет инварианты RDATA, которые нельзя гарантировать типом enum.
    ///
    /// # Errors
    ///
    /// [`RdataError`] для некорректных длин/полей.
    pub fn validate(&self) -> Result<(), RdataError> {
        match self {
            Self::Caa { value, .. } if value.len() > usize::from(u16::MAX) => {
                Err(RdataError::TooLong { len: value.len() })
            }
            Self::Unknown { rr_type, rdata } => {
                if rr_type.is_known() {
                    return Err(RdataError::KnownTypeAsUnknown { rr_type: *rr_type });
                }
                if rdata.len() > usize::from(u16::MAX) {
                    return Err(RdataError::TooLong { len: rdata.len() });
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Длина RDATA в wire-форме (без RDLENGTH) в октетах.
    ///
    /// Для валидных данных совпадает с канонической wire-формой. Может быть
    /// больше 65535, если RDATA собрана в обход валидирующих конструкторов;
    /// `Record`/`Rrset` такую запись не примут.
    #[must_use]
    pub fn wire_len(&self) -> usize {
        self.to_canonical_wire().len()
    }

    /// Каноническая wire-форма RDATA без имени/сжатия (RFC 4034 §6.2).
    #[must_use]
    pub fn to_canonical_wire(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write_canonical_wire(&mut out);
        out
    }

    /// Записывает каноническую wire-форму RDATA в `out`.
    pub fn write_canonical_wire(&self, out: &mut Vec<u8>) {
        let mut writer = CanonicalRdataWriter { out };
        crate::wire::rdata::write_rdata(self, &mut writer);
    }

    /// Разбирает RDATA без сжатия имён.
    ///
    /// # Errors
    ///
    /// [`crate::wire::DecodeError`] при некорректных данных.
    pub fn from_wire(rr_type: Rtype, bytes: &[u8]) -> Result<Self, crate::wire::DecodeError> {
        crate::wire::decode::decode_standalone_rdata(rr_type, bytes)
    }
}

impl PartialOrd for Rdata {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Rdata {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        sort_rank(self)
            .cmp(&sort_rank(other))
            .then_with(|| self.rr_type().as_u16().cmp(&other.rr_type().as_u16()))
            .then_with(|| self.to_canonical_wire().cmp(&other.to_canonical_wire()))
    }
}

const fn sort_rank(rdata: &Rdata) -> u8 {
    match rdata {
        Rdata::A(_) => 0,
        Rdata::Aaaa(_) => 1,
        Rdata::Ns(_) => 2,
        Rdata::Cname(_) => 3,
        Rdata::Soa(_) => 4,
        Rdata::Ptr(_) => 5,
        Rdata::Mx { .. } => 6,
        Rdata::Txt(_) => 7,
        Rdata::Srv { .. } => 8,
        Rdata::Caa { .. } => 9,
        Rdata::Dname(_) => 10,
        Rdata::Ds(_) => 11,
        Rdata::Dnskey(_) => 12,
        Rdata::Rrsig(_) => 13,
        Rdata::Nsec(_) => 14,
        Rdata::Nsec3(_) => 15,
        Rdata::Nsec3Param(_) => 16,
        Rdata::Tlsa(_) => 17,
        Rdata::Svcb(_) => 18,
        Rdata::Https(_) => 19,
        Rdata::Unknown { .. } => 20,
    }
}

/// Писатель, складывающий каноническую RDATA в `Vec<u8>`.
struct CanonicalRdataWriter<'a> {
    out: &'a mut Vec<u8>,
}

impl crate::wire::rdata::RdataOut for CanonicalRdataWriter<'_> {
    fn bytes(&mut self, value: &[u8]) {
        self.out.extend_from_slice(value);
    }

    fn name(&mut self, name: &Name, _compressible: bool) {
        self.out.extend_from_slice(name.as_wire());
    }
}
