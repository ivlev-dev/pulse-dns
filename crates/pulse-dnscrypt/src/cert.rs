//! Сертификаты DNSCrypt v2 (§12): подпись, разбор, выбор, TXT-запись.

use pulse_dns::{Name, Rclass, Rdata, Record, Rtype, Ttl, TxtData};

use crate::error::Error;
use crate::keys::{KEY_LEN, ProviderKeypair, ProviderPublicKey, ResolverPublicKey, SIGNATURE_LEN};
use crate::protocol::{
    CERT_FIXED_LEN, CERT_MAGIC, CLIENT_MAGIC_LEN, ES_VERSION_XCHACHA20POLY1305,
    MAX_CERTIFICATE_LEN, PROTOCOL_MINOR_VERSION, PROVIDER_NAME_PREFIX,
};
use crate::util;

/// Параметры нового сертификата.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateParams {
    /// Краткосрочный открытый ключ резолвера (X25519).
    pub resolver_pk: [u8; KEY_LEN],
    /// `client-magic`, который клиент ставит в начало запроса.
    pub client_magic: [u8; CLIENT_MAGIC_LEN],
    /// Серийный номер (big-endian на wire).
    pub serial: u32,
    /// Начало действия, Unix-время.
    pub ts_start: u32,
    /// Конец действия (включительно), Unix-время.
    pub ts_end: u32,
    /// Расширения (пусто в текущей версии).
    pub extensions: Vec<u8>,
}

impl CertificateParams {
    /// Создаёт параметры без расширений.
    #[must_use]
    pub const fn new(
        resolver_pk: [u8; KEY_LEN],
        client_magic: [u8; CLIENT_MAGIC_LEN],
        serial: u32,
        ts_start: u32,
        ts_end: u32,
    ) -> Self {
        Self {
            resolver_pk,
            client_magic,
            serial,
            ts_start,
            ts_end,
            extensions: Vec::new(),
        }
    }
}

/// Подписанный сертификат DNSCrypt v2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    es_version: [u8; 2],
    minor_version: [u8; 2],
    signature: [u8; SIGNATURE_LEN],
    resolver_pk: [u8; KEY_LEN],
    client_magic: [u8; CLIENT_MAGIC_LEN],
    serial: u32,
    ts_start: u32,
    ts_end: u32,
    extensions: Vec<u8>,
}

impl Certificate {
    /// Подписывает новый сертификат ключом провайдера.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidValidityRange`], [`Error::InvalidClientMagic`] или
    /// [`Error::CertificateTooLong`].
    pub fn sign(provider: &ProviderKeypair, params: CertificateParams) -> Result<Self, Error> {
        validate_client_magic(params.client_magic)?;
        if params.ts_start >= params.ts_end {
            return Err(Error::InvalidValidityRange {
                start: params.ts_start,
                end: params.ts_end,
            });
        }
        if CERT_FIXED_LEN.saturating_add(params.extensions.len()) > MAX_CERTIFICATE_LEN {
            return Err(Error::CertificateTooLong {
                len: CERT_FIXED_LEN.saturating_add(params.extensions.len()),
                max: MAX_CERTIFICATE_LEN,
            });
        }
        let mut certificate = Self {
            es_version: ES_VERSION_XCHACHA20POLY1305,
            minor_version: PROTOCOL_MINOR_VERSION,
            signature: [0_u8; SIGNATURE_LEN],
            resolver_pk: params.resolver_pk,
            client_magic: params.client_magic,
            serial: params.serial,
            ts_start: params.ts_start,
            ts_end: params.ts_end,
            extensions: params.extensions,
        };
        certificate.signature = provider.sign(&certificate.signed_data());
        Ok(certificate)
    }

    /// Разбирает сертификат из wire-формы.
    ///
    /// Подпись **не** проверяется; для этого вызовите [`Self::verify`].
    ///
    /// # Errors
    ///
    /// [`Error::CertificateTooShort`], [`Error::CertificateTooLong`],
    /// [`Error::CertificateMagicMismatch`], [`Error::UnsupportedEsVersion`],
    /// [`Error::UnsupportedMinorVersion`] или [`Error::InvalidClientMagic`].
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < CERT_FIXED_LEN {
            return Err(Error::CertificateTooShort {
                len: bytes.len(),
                min: CERT_FIXED_LEN,
            });
        }
        if bytes.len() > MAX_CERTIFICATE_LEN {
            return Err(Error::CertificateTooLong {
                len: bytes.len(),
                max: MAX_CERTIFICATE_LEN,
            });
        }
        let mut input = bytes;
        let magic = take::<4>(&mut input)?;
        if magic != CERT_MAGIC {
            return Err(Error::CertificateMagicMismatch);
        }
        let es_version = take::<2>(&mut input)?;
        if es_version != ES_VERSION_XCHACHA20POLY1305 {
            return Err(Error::UnsupportedEsVersion {
                major: es_version.first().copied().unwrap_or(0),
                minor: es_version.get(1).copied().unwrap_or(0),
            });
        }
        let minor_version = take::<2>(&mut input)?;
        let minor = u16::from_be_bytes(minor_version);
        if minor_version != PROTOCOL_MINOR_VERSION {
            return Err(Error::UnsupportedMinorVersion(minor));
        }
        let signature = take::<SIGNATURE_LEN>(&mut input)?;
        let resolver_pk = take::<KEY_LEN>(&mut input)?;
        let client_magic = take::<CLIENT_MAGIC_LEN>(&mut input)?;
        validate_client_magic(client_magic)?;
        let serial = u32::from_be_bytes(take::<4>(&mut input)?);
        let ts_start = u32::from_be_bytes(take::<4>(&mut input)?);
        let ts_end = u32::from_be_bytes(take::<4>(&mut input)?);
        if ts_start >= ts_end {
            return Err(Error::InvalidValidityRange {
                start: ts_start,
                end: ts_end,
            });
        }
        Ok(Self {
            es_version,
            minor_version,
            signature,
            resolver_pk,
            client_magic,
            serial,
            ts_start,
            ts_end,
            extensions: input.to_vec(),
        })
    }

    /// Сериализует сертификат в wire-форму.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CERT_FIXED_LEN.saturating_add(self.extensions.len()));
        out.extend_from_slice(&CERT_MAGIC);
        out.extend_from_slice(&self.es_version);
        out.extend_from_slice(&self.minor_version);
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&self.resolver_pk);
        out.extend_from_slice(&self.client_magic);
        out.extend_from_slice(&self.serial.to_be_bytes());
        out.extend_from_slice(&self.ts_start.to_be_bytes());
        out.extend_from_slice(&self.ts_end.to_be_bytes());
        out.extend_from_slice(&self.extensions);
        out
    }

    /// Hex-представление всего сертификата.
    #[must_use]
    pub fn to_hex(&self) -> String {
        util::to_hex(&self.to_bytes())
    }

    /// Base64-представление всего сертификата.
    #[must_use]
    pub fn to_base64(&self) -> String {
        util::to_base64(&self.to_bytes())
    }

    /// Разбирает сертификат из hex.
    ///
    /// # Errors
    ///
    /// Ошибки [`Error::HexDecode`] и [`Self::parse`].
    pub fn from_hex(text: &str) -> Result<Self, Error> {
        Self::parse(&util::from_hex(text)?)
    }

    /// Разбирает сертификат из base64.
    ///
    /// # Errors
    ///
    /// Ошибки [`Error::Base64Decode`] и [`Self::parse`].
    pub fn from_base64(text: &str) -> Result<Self, Error> {
        Self::parse(&util::from_base64(text)?)
    }

    /// Проверяет подпись Ed25519 ключом провайдера.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidCertificateSignature`].
    pub fn verify(&self, provider: &ProviderPublicKey) -> Result<(), Error> {
        if provider.verify(&self.signed_data(), &self.signature) {
            Ok(())
        } else {
            Err(Error::InvalidCertificateSignature)
        }
    }

    /// Проверяет, что сертификат действует в момент `now` (Unix-секунды).
    ///
    /// # Errors
    ///
    /// [`Error::CertificateNotYetValid`] или [`Error::CertificateExpired`].
    pub fn validate_at(&self, now: u64) -> Result<(), Error> {
        let start = u64::from(self.ts_start);
        let end = u64::from(self.ts_end);
        if now < start {
            return Err(Error::CertificateNotYetValid {
                now,
                start: self.ts_start,
            });
        }
        if now > end {
            return Err(Error::CertificateExpired {
                now,
                end: self.ts_end,
            });
        }
        Ok(())
    }

    /// Действует ли сертификат в момент `now`.
    #[must_use]
    pub fn is_valid_at(&self, now: u64) -> bool {
        self.validate_at(now).is_ok()
    }

    /// Магия сертификата (всегда [`CERT_MAGIC`]).
    #[must_use]
    pub const fn magic(&self) -> &[u8; 4] {
        &CERT_MAGIC
    }

    /// Версия криптографической конструкции.
    #[must_use]
    pub const fn es_version(&self) -> [u8; 2] {
        self.es_version
    }

    /// Минорная версия протокола.
    #[must_use]
    pub const fn minor_version(&self) -> [u8; 2] {
        self.minor_version
    }

    /// Подпись провайдера.
    #[must_use]
    pub const fn signature(&self) -> &[u8; SIGNATURE_LEN] {
        &self.signature
    }

    /// Открытый ключ резолвера (X25519).
    #[must_use]
    pub const fn resolver_pk(&self) -> &[u8; KEY_LEN] {
        &self.resolver_pk
    }

    /// Открытый ключ резолвера как типизированное значение.
    ///
    /// # Errors
    ///
    /// В текущей реализации ошибка невозможна; сигнатура оставлена для
    /// совместимости.
    pub fn resolver_public_key(&self) -> Result<ResolverPublicKey, Error> {
        ResolverPublicKey::from_bytes(self.resolver_pk)
    }

    /// `client-magic`.
    #[must_use]
    pub const fn client_magic(&self) -> &[u8; CLIENT_MAGIC_LEN] {
        &self.client_magic
    }

    /// Серийный номер.
    #[must_use]
    pub const fn serial(&self) -> u32 {
        self.serial
    }

    /// Начало действия.
    #[must_use]
    pub const fn ts_start(&self) -> u32 {
        self.ts_start
    }

    /// Конец действия (включительно).
    #[must_use]
    pub const fn ts_end(&self) -> u32 {
        self.ts_end
    }

    /// Расширения сертификата.
    #[must_use]
    pub fn extensions(&self) -> &[u8] {
        &self.extensions
    }

    /// Собирает `Record` (`TXT`) с бинарным сертификатом.
    ///
    /// Сертификат разбивается на character-string по 255 байт; клиенты
    /// конкатенируют сегменты (так же поступает dnscrypt-proxy).
    ///
    /// # Errors
    ///
    /// Ошибки [`Error::DnsRdata`] и [`Error::DnsRecord`].
    pub fn to_txt_record(&self, owner: &Name, ttl: Ttl) -> Result<Record, Error> {
        let bytes = self.to_bytes();
        let segments = bytes
            .chunks(u8::MAX as usize)
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        let rdata = Rdata::Txt(TxtData::new(segments)?);
        Record::new(owner.clone(), Rtype::TXT, Rclass::IN, ttl, rdata).map_err(Error::from)
    }

    /// Извлекает сертификат из TXT RDATA.
    ///
    /// Поддерживается сырой бинарный сертификат (канонический вариант), а
    /// также hex/base64-текст для отладочных дампов.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidCertificateText`] или ошибки [`Self::parse`].
    pub fn from_txt_rdata(rdata: &Rdata) -> Result<Self, Error> {
        let Rdata::Txt(txt) = rdata else {
            return Err(Error::InvalidCertificateText);
        };
        let mut joined = Vec::new();
        for segment in txt.segments() {
            joined.extend_from_slice(segment);
        }
        if starts_with_magic(&joined) {
            return Self::parse(&joined);
        }
        if let Ok(text) = std::str::from_utf8(&joined) {
            if let Ok(decoded) = util::from_hex(text)
                && starts_with_magic(&decoded)
            {
                return Self::parse(&decoded);
            }
            if let Ok(decoded) = util::from_base64(text)
                && starts_with_magic(&decoded)
            {
                return Self::parse(&decoded);
            }
        }
        Err(Error::InvalidCertificateText)
    }

    /// Подписываемые данные: `resolver-pk || client-magic || serial ||
    /// ts-start || ts-end || extensions`.
    fn signed_data(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(KEY_LEN + CLIENT_MAGIC_LEN + 12 + self.extensions.len());
        out.extend_from_slice(&self.resolver_pk);
        out.extend_from_slice(&self.client_magic);
        out.extend_from_slice(&self.serial.to_be_bytes());
        out.extend_from_slice(&self.ts_start.to_be_bytes());
        out.extend_from_slice(&self.ts_end.to_be_bytes());
        out.extend_from_slice(&self.extensions);
        out
    }
}

/// Набор сертификатов с выбором по серийному номеру.
#[derive(Debug, Clone, Default)]
pub struct CertificateSet {
    certificates: Vec<Certificate>,
}

impl CertificateSet {
    /// Создаёт пустой набор.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            certificates: Vec::new(),
        }
    }

    /// Создаёт набор и проверяет уникальность `client-magic`.
    ///
    /// # Errors
    ///
    /// [`Error::DuplicateClientMagic`].
    pub fn from_certificates(certificates: Vec<Certificate>) -> Result<Self, Error> {
        let mut set = Self::new();
        for certificate in certificates {
            set.push(certificate)?;
        }
        Ok(set)
    }

    /// Добавляет сертификат.
    ///
    /// # Errors
    ///
    /// [`Error::DuplicateClientMagic`], если магия уже занята.
    pub fn push(&mut self, certificate: Certificate) -> Result<(), Error> {
        if self
            .certificates
            .iter()
            .any(|existing| existing.client_magic == certificate.client_magic)
        {
            return Err(Error::DuplicateClientMagic);
        }
        self.certificates.push(certificate);
        Ok(())
    }

    /// Все сертификаты набора.
    #[must_use]
    pub fn certificates(&self) -> &[Certificate] {
        &self.certificates
    }

    /// Выбирает действующий сертификат с максимальным `serial`.
    ///
    /// Проверяются подпись провайдера и срок действия; сертификаты с
    /// неподдерживаемой версией не проходят [`Certificate::parse`] ещё на
    /// входе.
    ///
    /// # Errors
    ///
    /// [`Error::NoValidCertificate`], если ни один сертификат не подходит.
    pub fn select(&self, provider: &ProviderPublicKey, now: u64) -> Result<&Certificate, Error> {
        let mut best: Option<&Certificate> = None;
        for certificate in &self.certificates {
            if certificate.verify(provider).is_err() || !certificate.is_valid_at(now) {
                continue;
            }
            if best.is_none_or(|current| certificate.serial > current.serial) {
                best = Some(certificate);
            }
        }
        best.ok_or(Error::NoValidCertificate)
    }
}

/// Строит имя провайдера `2.dnscrypt-cert.<zone>`.
///
/// # Errors
///
/// [`Error::DnsName`], если зона не позволяет построить имя.
pub fn provider_name(zone: &Name) -> Result<Name, Error> {
    Name::parse(&format!("{PROVIDER_NAME_PREFIX}{zone}")).map_err(Error::from)
}

/// Генерирует `client-magic`, не начинающуюся с семи нулей.
///
/// Седьмой нулевой байт при необходимости заменяется на `0x01`, чтобы
/// избежать коллизии с QUIC.
///
/// # Errors
///
/// [`Error::Random`].
pub fn random_client_magic() -> Result<[u8; CLIENT_MAGIC_LEN], Error> {
    let mut magic: [u8; CLIENT_MAGIC_LEN] = crate::crypto::random_bytes()?;
    if magic.iter().take(7).all(|byte| *byte == 0)
        && let Some(first) = magic.first_mut()
    {
        *first = 1;
    }
    Ok(magic)
}

fn validate_client_magic(magic: [u8; CLIENT_MAGIC_LEN]) -> Result<(), Error> {
    if magic.iter().take(7).all(|byte| *byte == 0) {
        return Err(Error::InvalidClientMagic);
    }
    Ok(())
}

fn starts_with_magic(bytes: &[u8]) -> bool {
    bytes.get(..CERT_MAGIC.len()) == Some(CERT_MAGIC.as_slice())
}

fn take<const N: usize>(input: &mut &[u8]) -> Result<[u8; N], Error> {
    let (head, tail) = input
        .split_at_checked(N)
        .ok_or(Error::CertificateTooShort {
            len: input.len(),
            min: N,
        })?;
    *input = tail;
    head.try_into()
        .map_err(|_| Error::CertificateTooShort { len: N, min: N })
}
