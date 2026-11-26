//! Подпись авторитетной зоны и построение NSEC-цепочки (RFC 4033/4034/4035).
//!
//! Модуль выполняет **офлайн-подпись** загруженной зоны: добавляет apex
//! `DNSKEY`, строит denial-цепочку (NSEC или NSEC3) для всех имён зоны
//! (включая empty non-terminals), подписывает `DNSKEY` ключом KSK/CSK,
//! остальные авторитетные RRset — ключами ZSK/CSK. `DS` не генерируется: он
//! публикуется родительской зоной.
//!
//! # Границы
//!
//! - NSEC3-подпись: SHA-1, настраиваемые salt/iterations, Opt-Out = 0;
//!   `NSEC3PARAM` публикуется в apex. NSEC3 для secondary-зон не
//!   реализован;
//! - `NS` в точке делегирования и glue ниже cut не подписываются;
//! - existing `RRSIG`/`NSEC`/`NSEC3`/`NSEC3PARAM`/`DNSKEY` во входном наборе
//!   отбрасываются и пересоздаются (повторная подпись безопасна).
//!
//! # Пример
//!
//! ```
//! use pulse_dns::{Name, Rclass, Rdata, Rrset, Rtype, Serial, SoaData, Ttl};
//! use pulse_dnssec::{Algorithm, PrivateKey};
//! use pulse_server::dnssec::{KeyRole, ZoneSigner, ZoneSigningKey};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let origin = Name::parse("example.com")?;
//! let soa = Rrset::new(
//!     origin.clone(),
//!     Rtype::SOA,
//!     Rclass::IN,
//!     Ttl::new(3600)?,
//!     [Rdata::Soa(SoaData::new(
//!         Name::parse("ns1.example.com")?,
//!         Name::parse("hostmaster.example.com")?,
//!         Serial::new(1),
//!         3600,
//!         600,
//!         604_800,
//!         300,
//!     ))],
//! )?;
//! let signer = ZoneSigner::new(
//!     vec![ZoneSigningKey::new(
//!         PrivateKey::generate(Algorithm::ED25519)?,
//!         KeyRole::Csk,
//!     )?],
//!     2_592_000,
//!     300,
//! )?;
//! let signed = signer.sign_zone(&origin, &[soa], 1_700_000_000)?;
//! assert!(signed.rrsets.iter().any(|rrset| rrset.rr_type() == Rtype::DNSKEY));
//! # Ok(())
//! # }
//! ```

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;

use pulse_dns::{
    DnskeyData, Name, Nsec3Data, Nsec3ParamData, NsecData, Rclass, Rdata, Rrset, RrsigData, Rtype,
    Ttl, TtlError, TypeBitmap,
};
use pulse_dnssec::denial::{MAX_NSEC3_ITERATIONS, nsec3_owner_name};
use pulse_dnssec::rdata_util::nsec3_hash;
use pulse_dnssec::{
    DNSKEY_FLAG_SEP, DNSKEY_FLAG_ZONE_KEY, DenialError, KeyError, PrivateKey, SignError,
    SignOptions, sign_rrset,
};
use thiserror::Error;

use crate::domain::DenialKind;

/// Роль DNSSEC-ключа в зоне.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRole {
    /// Key Signing Key: подписывает `DNSKEY` RRset (SEP-бит установлен).
    Ksk,
    /// Zone Signing Key: подписывает данные зоны.
    Zsk,
    /// Combined Signing Key: подписывает и `DNSKEY`, и данные.
    Csk,
}

impl KeyRole {
    /// DNSKEY flags по умолчанию для роли (RFC 4034 §2.1.1).
    #[must_use]
    pub const fn flags(self) -> u16 {
        match self {
            Self::Ksk | Self::Csk => DNSKEY_FLAG_ZONE_KEY | DNSKEY_FLAG_SEP,
            Self::Zsk => DNSKEY_FLAG_ZONE_KEY,
        }
    }

    /// Подписывает ли ключ `DNSKEY` RRset.
    #[must_use]
    pub const fn signs_dnskey(self) -> bool {
        matches!(self, Self::Ksk | Self::Csk)
    }

    /// Подписывает ли ключ данные зоны (кроме `DNSKEY`).
    #[must_use]
    pub const fn signs_data(self) -> bool {
        matches!(self, Self::Zsk | Self::Csk)
    }

    /// Разбирает строковое имя роли (`ksk`, `zsk`, `csk`).
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "ksk" => Some(Self::Ksk),
            "zsk" => Some(Self::Zsk),
            "csk" => Some(Self::Csk),
            _ => None,
        }
    }

    /// Строковое имя роли.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ksk => "ksk",
            Self::Zsk => "zsk",
            Self::Csk => "csk",
        }
    }
}

/// Параметры NSEC3-цепочки для подписи.
///
/// Поддерживается только hash algorithm SHA-1 (alg 1). Opt-Out включается
/// явно через [`Nsec3Config::with_opt_out`] и требует, чтобы insecure
/// делегирования (NS без DS) были исключены из цепочки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nsec3Config {
    salt: Vec<u8>,
    iterations: u16,
    opt_out: bool,
}

impl Nsec3Config {
    /// Hash algorithm SHA-1 (единственный поддерживаемый, RFC 5155 §5).
    pub const HASH_SHA1: u8 = 1;

    /// Создаёт параметры NSEC3.
    ///
    /// # Errors
    ///
    /// [`Nsec3ConfigError::SaltTooLong`] или
    /// [`Nsec3ConfigError::IterationsTooHigh`].
    pub fn new(salt: impl Into<Vec<u8>>, iterations: u16) -> Result<Self, Nsec3ConfigError> {
        let salt = salt.into();
        if salt.len() > usize::from(u8::MAX) {
            return Err(Nsec3ConfigError::SaltTooLong { len: salt.len() });
        }
        if iterations > MAX_NSEC3_ITERATIONS {
            return Err(Nsec3ConfigError::IterationsTooHigh {
                iterations,
                max: MAX_NSEC3_ITERATIONS,
            });
        }
        Ok(Self {
            salt,
            iterations,
            opt_out: false,
        })
    }

    /// Включает/выключает Opt-Out (RFC 5155 §6).
    #[must_use]
    pub const fn with_opt_out(mut self, opt_out: bool) -> Self {
        self.opt_out = opt_out;
        self
    }

    /// Соль (сырые байты).
    #[must_use]
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// Число дополнительных hash-итераций.
    #[must_use]
    pub const fn iterations(&self) -> u16 {
        self.iterations
    }

    /// Включён ли Opt-Out.
    #[must_use]
    pub const fn opt_out(&self) -> bool {
        self.opt_out
    }
}

/// Ошибка параметров NSEC3.
#[derive(Debug, Error)]
pub enum Nsec3ConfigError {
    /// Соль длиннее 255 октетов.
    #[error("NSEC3 salt is {len} octets long (max 255)")]
    SaltTooLong {
        /// Длина соли.
        len: usize,
    },
    /// Итерации выше лимита валидатора.
    #[error("NSEC3 iterations {iterations} exceed limit {max}")]
    IterationsTooHigh {
        /// Запрошенные итерации.
        iterations: u16,
        /// Лимит.
        max: u16,
    },
}

/// Политика denial-of-existence при подписи зоны.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum DenialPolicy {
    /// NSEC-цепочка (RFC 4034).
    #[default]
    Nsec,
    /// NSEC3-цепочка (RFC 5155; опционально Opt-Out).
    Nsec3(Nsec3Config),
}

impl DenialPolicy {
    /// Механизм, который публикует подписанная зона.
    #[must_use]
    pub const fn kind(&self) -> DenialKind {
        match self {
            Self::Nsec => DenialKind::Nsec,
            Self::Nsec3(_) => DenialKind::Nsec3,
        }
    }
}

/// Приватный ключ подписи с ролью и DNSKEY flags.
///
/// `Debug` не печатает материал ключа: только алгоритм, роль и flags.
pub struct ZoneSigningKey {
    key: PrivateKey,
    role: KeyRole,
    flags: u16,
    signs: bool,
}

impl fmt::Debug for ZoneSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ZoneSigningKey")
            .field("algorithm", &self.key.algorithm().name())
            .field("role", &self.role.as_str())
            .field("flags", &self.flags)
            .field("signs", &self.signs)
            .field("material", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl ZoneSigningKey {
    /// Создаёт ключ с flags по умолчанию для роли.
    ///
    /// # Errors
    ///
    /// [`ZoneSignerError::Key`], если публичный DNSKEY не строится.
    pub fn new(key: PrivateKey, role: KeyRole) -> Result<Self, ZoneSignerError> {
        Self::with_flags(key, role, role.flags())
    }

    /// Создаёт ключ с явными DNSKEY flags.
    ///
    /// # Errors
    ///
    /// [`ZoneSignerError::Key`], если публичный DNSKEY не строится.
    pub fn with_flags(key: PrivateKey, role: KeyRole, flags: u16) -> Result<Self, ZoneSignerError> {
        let candidate = Self {
            key,
            role,
            flags,
            signs: true,
        };
        candidate.dnskey()?;
        Ok(candidate)
    }

    /// Помечает ключ как «только публикуемый» (pre-publish/retired).
    ///
    /// DNSKEY ключа попадает в apex, но RRSIG им не создаются (RFC 7583).
    #[must_use]
    pub const fn publish_only(mut self) -> Self {
        self.signs = false;
        self
    }

    /// Участвует ли ключ в подписи (а не только в публикации DNSKEY).
    #[must_use]
    pub const fn signs(&self) -> bool {
        self.signs
    }

    /// Роль ключа.
    #[must_use]
    pub const fn role(&self) -> KeyRole {
        self.role
    }

    /// DNSKEY flags подписи.
    #[must_use]
    pub const fn flags(&self) -> u16 {
        self.flags
    }

    /// Алгоритм ключа.
    #[must_use]
    pub const fn algorithm(&self) -> pulse_dnssec::Algorithm {
        self.key.algorithm()
    }

    /// Публичный DNSKEY.
    ///
    /// # Errors
    ///
    /// [`KeyError`] при некорректном публичном ключе.
    pub fn dnskey(&self) -> Result<DnskeyData, KeyError> {
        self.key.dnskey(self.flags)
    }

    /// Key tag публичного DNSKEY (RFC 4034 Appendix B).
    ///
    /// # Errors
    ///
    /// [`KeyError`] при некорректном публичном ключе.
    pub fn key_tag(&self) -> Result<u16, KeyError> {
        Ok(pulse_dnssec::key_tag(&self.dnskey()?))
    }
}

/// Набор ключей для подписи одной зоны.
pub struct ZoneSigner {
    keys: Vec<ZoneSigningKey>,
    dnskey_signers: Vec<usize>,
    data_signers: Vec<usize>,
    validity: u32,
    inception_skew: u32,
}

impl fmt::Debug for ZoneSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ZoneSigner")
            .field("keys", &self.keys)
            .field("dnskey_signers", &self.dnskey_signers)
            .field("data_signers", &self.data_signers)
            .field("validity", &self.validity)
            .field("inception_skew", &self.inception_skew)
            .finish()
    }
}

impl ZoneSigner {
    /// Создаёт подписант из непустого набора ключей.
    ///
    /// Если нет KSK/CSK, `DNSKEY` подписывается всеми ключами; если нет
    /// ZSK/CSK, данные подписываются всеми ключами. Это позволяет
    /// использовать один ключ как CSK без отдельной настройки.
    ///
    /// # Errors
    ///
    /// [`ZoneSignerError::NoKeys`] для пустого набора,
    /// [`ZoneSignerError::InvalidValidity`] при `validity == 0`.
    pub fn new(
        keys: Vec<ZoneSigningKey>,
        validity: u32,
        inception_skew: u32,
    ) -> Result<Self, ZoneSignerError> {
        if keys.is_empty() {
            return Err(ZoneSignerError::NoKeys);
        }
        if validity == 0 {
            return Err(ZoneSignerError::InvalidValidity);
        }
        let mut dnskey_signers: Vec<usize> = keys
            .iter()
            .enumerate()
            .filter_map(|(index, key)| (key.role().signs_dnskey() && key.signs()).then_some(index))
            .collect();
        if dnskey_signers.is_empty() {
            dnskey_signers = (0..keys.len()).collect();
        }
        let mut data_signers: Vec<usize> = keys
            .iter()
            .enumerate()
            .filter_map(|(index, key)| (key.role().signs_data() && key.signs()).then_some(index))
            .collect();
        if data_signers.is_empty() {
            data_signers = (0..keys.len()).collect();
        }
        Ok(Self {
            keys,
            dnskey_signers,
            data_signers,
            validity,
            inception_skew,
        })
    }

    /// Ключи зоны.
    #[must_use]
    pub fn keys(&self) -> &[ZoneSigningKey] {
        &self.keys
    }

    /// Срок действия подписи в секундах.
    #[must_use]
    pub const fn validity(&self) -> u32 {
        self.validity
    }

    /// Запас на расхождение часов в секундах.
    #[must_use]
    pub const fn inception_skew(&self) -> u32 {
        self.inception_skew
    }

    /// Подписывает зону и возвращает полный набор RRset с DNSSEC-записями.
    ///
    /// # Errors
    ///
    /// [`SignZoneError`] при отсутствии apex `SOA`, некорректных данных,
    /// ошибке ключа или подписи.
    pub fn sign_zone(
        &self,
        origin: &Name,
        rrsets: &[Rrset],
        now: u32,
    ) -> Result<SignedZone, SignZoneError> {
        sign_zone(origin, rrsets, self, now)
    }

    /// Подписывает зону с выбранной denial-политикой (NSEC или NSEC3).
    ///
    /// # Errors
    ///
    /// [`SignZoneError`] при нарушении структуры зоны или ошибке криптографии.
    pub fn sign_zone_with(
        &self,
        origin: &Name,
        rrsets: &[Rrset],
        now: u32,
        denial: &DenialPolicy,
    ) -> Result<SignedZone, SignZoneError> {
        sign_zone_with(origin, rrsets, self, now, denial)
    }

    /// Подписывает один RRset данных текущими ZSK/CSK.
    ///
    /// Используется инкрементальной переподписью после DNS UPDATE: меняется
    /// только затронутый набор, остальные `RRSIG` зоны сохраняются.
    ///
    /// # Errors
    ///
    /// [`SignZoneError::Sign`] при ошибке ключа/подписи.
    pub fn sign_data_rrset(
        &self,
        origin: &Name,
        rrset: &Rrset,
        now: u32,
    ) -> Result<Vec<RrsigData>, SignZoneError> {
        let mut signatures = Vec::with_capacity(self.data_signers.len());
        for index in &self.data_signers {
            let Some(key) = self.keys.get(*index) else {
                continue;
            };
            let options = SignOptions::new(origin.clone(), now, self.validity)
                .with_skew(self.inception_skew)
                .with_original_ttl(rrset.ttl().as_u32())
                .with_dnskey_flags(key.flags());
            let signature =
                sign_rrset(&key.key, rrset, &options).map_err(|error| SignZoneError::Sign {
                    zone: origin.clone(),
                    owner: rrset.owner().clone(),
                    rr_type: rrset.rr_type(),
                    source: error,
                })?;
            signatures.push(signature);
        }
        Ok(signatures)
    }
}

/// Результат подписи зоны.
#[derive(Debug, Clone)]
pub struct SignedZone {
    /// RRset зоны вместе с `DNSKEY`/`NSEC`/`NSEC3`/`RRSIG`.
    pub rrsets: Vec<Rrset>,
    /// Публичные DNSKEY зоны.
    pub dnskeys: Vec<DnskeyData>,
    /// Key tags публичных DNSKEY (для аудита/API).
    pub key_tags: Vec<u16>,
    /// Сколько RRSIG сгенерировано.
    pub rrsig_count: usize,
    /// Опубликованный механизм denial-of-existence.
    pub denial: DenialKind,
}

/// Ошибка построения подписанта.
#[derive(Debug, Error)]
pub enum ZoneSignerError {
    /// Не передан ни один ключ.
    #[error("at least one signing key is required")]
    NoKeys,
    /// Нулевой срок действия подписи.
    #[error("signature validity must be greater than zero")]
    InvalidValidity,
    /// Ошибка ключа.
    #[error(transparent)]
    Key(#[from] KeyError),
}

/// Ошибка подписи зоны.
#[derive(Debug, Error)]
pub enum SignZoneError {
    /// У зоны нет настроенных ключей подписи.
    #[error("zone {zone}: no DNSSEC signing keys configured")]
    NoKeys {
        /// Origin зоны.
        zone: Name,
    },
    /// В зоне нет apex `SOA`.
    #[error("zone {zone}: apex SOA is required for signing")]
    MissingSoa {
        /// Origin зоны.
        zone: Name,
    },
    /// Владелец RRset вне зоны.
    #[error("zone {zone}: owner {owner} is outside the zone")]
    OwnerOutsideZone {
        /// Origin зоны.
        zone: Name,
        /// Владелец.
        owner: Name,
    },
    /// Некорректный TTL.
    #[error("zone {zone}: invalid ttl: {source}")]
    Ttl {
        /// Origin зоны.
        zone: Name,
        /// Причина.
        #[source]
        source: TtlError,
    },
    /// Некорректный RRset.
    #[error("zone {zone}: invalid rrset: {source}")]
    Rrset {
        /// Origin зоны.
        zone: Name,
        /// Причина.
        #[source]
        source: pulse_dns::RrsetError,
    },
    /// Некорректные RDATA (NSEC bitmap).
    #[error("zone {zone}: invalid rdata: {source}")]
    Rdata {
        /// Origin зоны.
        zone: Name,
        /// Причина.
        #[source]
        source: pulse_dns::RdataError,
    },
    /// Ошибка ключа.
    #[error("zone {zone}: key error: {source}")]
    Key {
        /// Origin зоны.
        zone: Name,
        /// Причина.
        #[source]
        source: KeyError,
    },
    /// Ошибка построения denial-цепочки.
    #[error("zone {zone}: denial error: {source}")]
    Denial {
        /// Origin зоны.
        zone: Name,
        /// Причина.
        #[source]
        source: DenialError,
    },
    /// Ошибка подписи RRset.
    #[error("zone {zone}: cannot sign {owner} {rr_type}: {source}")]
    Sign {
        /// Origin зоны.
        zone: Name,
        /// Владелец подписываемого набора.
        owner: Name,
        /// Тип подписываемого набора.
        rr_type: Rtype,
        /// Причина.
        #[source]
        source: SignError,
    },
    /// Ошибка чтения/записи транзакционного порта.
    #[error("zone {zone}: {reason}")]
    Edit {
        /// Origin зоны.
        zone: Name,
        /// Причина.
        reason: String,
    },
    /// Коллизия SHA-1 хешей NSEC3 у разных имён.
    #[error("zone {zone}: NSEC3 hash collision for {first} and {second}")]
    Nsec3Collision {
        /// Origin зоны.
        zone: Name,
        /// Первое имя.
        first: Name,
        /// Второе имя.
        second: Name,
    },
}

impl SignZoneError {
    fn ttl(zone: &Name, error: TtlError) -> Self {
        Self::Ttl {
            zone: zone.clone(),
            source: error,
        }
    }

    fn rrset(zone: &Name, error: pulse_dns::RrsetError) -> Self {
        Self::Rrset {
            zone: zone.clone(),
            source: error,
        }
    }

    fn rdata(zone: &Name, error: pulse_dns::RdataError) -> Self {
        Self::Rdata {
            zone: zone.clone(),
            source: error,
        }
    }

    fn key(zone: &Name, error: KeyError) -> Self {
        Self::Key {
            zone: zone.clone(),
            source: error,
        }
    }

    fn denial(zone: &Name, error: DenialError) -> Self {
        Self::Denial {
            zone: zone.clone(),
            source: error,
        }
    }
}

/// Подписывает зону.
///
/// # Errors
///
/// [`SignZoneError`] при нарушении структуры зоны или ошибке криптографии.
#[allow(clippy::too_many_lines)]
pub fn sign_zone(
    origin: &Name,
    rrsets: &[Rrset],
    signer: &ZoneSigner,
    now: u32,
) -> Result<SignedZone, SignZoneError> {
    sign_zone_with(origin, rrsets, signer, now, &DenialPolicy::Nsec)
}

/// Подписывает зону с явной denial-политикой.
///
/// При `DenialPolicy::Nsec3` в apex добавляется `NSEC3PARAM`, а для каждого
/// авторитетного имени (включая empty non-terminals и secure-делегирования)
/// строится hashed-владелец `<base32hex(SHA-1(name))>.zone`. При включённом
/// Opt-Out insecure-делегирования (NS без DS) из цепочки исключаются.
///
/// # Errors
///
/// [`SignZoneError`] при нарушении структуры зоны, ошибке denial-цепочки или
/// криптографии.
#[allow(clippy::too_many_lines)]
pub fn sign_zone_with(
    origin: &Name,
    rrsets: &[Rrset],
    signer: &ZoneSigner,
    now: u32,
    denial: &DenialPolicy,
) -> Result<SignedZone, SignZoneError> {
    validate_owners(origin, rrsets)?;

    // 1. Отбрасываем прежние DNSSEC-записи: подпись всегда пересоздаётся.
    let mut data: HashMap<(Name, Rtype), Rrset> = HashMap::with_capacity(rrsets.len());
    for rrset in rrsets {
        if is_dnssec_type(rrset.rr_type()) {
            continue;
        }
        data.insert((rrset.owner().clone(), rrset.rr_type()), rrset.clone());
    }

    let soa = data
        .get(&(origin.clone(), Rtype::SOA))
        .ok_or_else(|| SignZoneError::MissingSoa {
            zone: origin.clone(),
        })?;
    let soa_ttl = soa.ttl().as_u32();
    let soa_minimum = soa
        .rdatas()
        .iter()
        .find_map(|rdata| match rdata {
            Rdata::Soa(data) => Some(data.minimum),
            _ => None,
        })
        .unwrap_or(soa_ttl);
    let nsec_ttl = Ttl::new(soa_ttl.min(soa_minimum).min(pulse_dns::TTL_MAX))
        .map_err(|error| SignZoneError::ttl(origin, error))?;
    let dnskey_ttl = Ttl::new(soa_ttl.min(pulse_dns::TTL_MAX))
        .map_err(|error| SignZoneError::ttl(origin, error))?;

    let cuts = collect_cuts(origin, &data);
    let nodes = collect_nodes(origin, &data, &cuts);
    let types = collect_types(&data, &cuts, &nodes);

    // 2. DNSKEY RRset в apex (публичные ключи всех ролей).
    let mut dnskeys = Vec::with_capacity(signer.keys().len());
    let mut key_tags = Vec::with_capacity(signer.keys().len());
    for key in signer.keys() {
        let dnskey = key
            .dnskey()
            .map_err(|error| SignZoneError::key(origin, error))?;
        key_tags.push(pulse_dnssec::key_tag(&dnskey));
        dnskeys.push(dnskey);
    }
    let dnskey_rrset = Rrset::new(
        origin.clone(),
        Rtype::DNSKEY,
        Rclass::IN,
        dnskey_ttl,
        dnskeys.iter().cloned().map(Rdata::Dnskey),
    )
    .map_err(|error| SignZoneError::rrset(origin, error))?;
    data.insert((origin.clone(), Rtype::DNSKEY), dnskey_rrset);

    // 3. Denial-цепочка: NSEC (канонический порядок) или NSEC3
    //    (hash-порядок). NSEC3PARAM публикуется в apex.
    match denial {
        DenialPolicy::Nsec => {
            build_nsec_chain(origin, &mut data, &types, &nodes, nsec_ttl)?;
        }
        DenialPolicy::Nsec3(config) => {
            build_nsec3_chain(origin, &mut data, &types, &nodes, nsec_ttl, config)?;
        }
    }

    // 4. Подпись: DNSKEY — KSK/CSK, данные — ZSK/CSK. NS в точке cut и
    //    glue ниже cut не подписываются.
    let mut signatures: HashMap<Name, (Ttl, Vec<Rdata>)> = HashMap::new();
    let mut rrsig_count = 0_usize;
    for ((owner, rr_type), rrset) in &data {
        let signers = if matches!(*rr_type, Rtype::NSEC3 | Rtype::NSEC3PARAM) {
            // NSEC3-владелец синтетический: подписываем данными, не проверяя
            // совпадение с точкой делегирования.
            Some(signer.data_signers.as_slice())
        } else {
            signers_for(owner, *rr_type, &cuts, signer)
        };
        let Some(signers) = signers else {
            continue;
        };
        for index in signers {
            let Some(key) = signer.keys().get(*index) else {
                continue;
            };
            let options = SignOptions::new(origin.clone(), now, signer.validity())
                .with_skew(signer.inception_skew())
                .with_original_ttl(rrset.ttl().as_u32())
                .with_dnskey_flags(key.flags());
            let rrsig =
                sign_rrset(&key.key, rrset, &options).map_err(|error| SignZoneError::Sign {
                    zone: origin.clone(),
                    owner: owner.clone(),
                    rr_type: *rr_type,
                    source: error,
                })?;
            rrsig_count += 1;
            let entry = signatures
                .entry(owner.clone())
                .or_insert_with(|| (rrset.ttl(), Vec::new()));
            if rrset.ttl() < entry.0 {
                entry.0 = rrset.ttl();
            }
            entry.1.push(Rdata::Rrsig(rrsig));
        }
    }
    for (owner, (ttl, rdatas)) in signatures {
        if rdatas.is_empty() {
            continue;
        }
        let rrset = Rrset::new(owner.clone(), Rtype::RRSIG, Rclass::IN, ttl, rdatas)
            .map_err(|error| SignZoneError::rrset(origin, error))?;
        data.insert((owner, Rtype::RRSIG), rrset);
    }

    // 5. Детерминированный порядок результата.
    let mut output: Vec<Rrset> = data.into_values().collect();
    output.sort_by(|left, right| {
        left.owner()
            .cmp_canonical(right.owner())
            .then_with(|| left.rr_type().as_u16().cmp(&right.rr_type().as_u16()))
    });
    Ok(SignedZone {
        rrsets: output,
        dnskeys,
        key_tags,
        rrsig_count,
        denial: denial.kind(),
    })
}

/// Строит NSEC-цепочку: каждый узел указывает на следующий в каноническом
/// порядке; последний замыкается на первый.
fn build_nsec_chain(
    origin: &Name,
    data: &mut HashMap<(Name, Rtype), Rrset>,
    types: &HashMap<Name, BTreeSet<Rtype>>,
    nodes: &HashSet<Name>,
    nsec_ttl: Ttl,
) -> Result<(), SignZoneError> {
    let mut ordered: Vec<Name> = nodes.iter().cloned().collect();
    ordered.sort_by(Name::cmp_canonical);
    for (index, name) in ordered.iter().enumerate() {
        let Some(next) = ordered.get((index + 1) % ordered.len()) else {
            continue;
        };
        let mut bitmap_types: BTreeSet<Rtype> = types.get(name).cloned().unwrap_or_default();
        bitmap_types.insert(Rtype::NSEC);
        bitmap_types.insert(Rtype::RRSIG);
        let bitmap = TypeBitmap::from_types(bitmap_types);
        let nsec = NsecData::new(next.clone(), bitmap)
            .map_err(|error| SignZoneError::rdata(origin, error))?;
        let rrset = Rrset::new(
            name.clone(),
            Rtype::NSEC,
            Rclass::IN,
            nsec_ttl,
            [Rdata::Nsec(nsec)],
        )
        .map_err(|error| SignZoneError::rrset(origin, error))?;
        data.insert((name.clone(), Rtype::NSEC), rrset);
    }
    Ok(())
}

/// Строит NSEC3-цепочку (SHA-1) и apex `NSEC3PARAM`.
///
/// При `opt_out = true` insecure-делегирования (NS без DS) не получают
/// NSEC3-запись и остаются вне hash-цепочки; флаг Opt-Out устанавливается
/// на всех NSEC3 зоны (RFC 5155 §6, §7.1).
fn build_nsec3_chain(
    origin: &Name,
    data: &mut HashMap<(Name, Rtype), Rrset>,
    types: &HashMap<Name, BTreeSet<Rtype>>,
    nodes: &HashSet<Name>,
    nsec_ttl: Ttl,
    config: &Nsec3Config,
) -> Result<(), SignZoneError> {
    let insecure = insecure_delegations(origin, data);
    let mut hashes: BTreeMap<Vec<u8>, BTreeSet<Rtype>> = BTreeMap::new();
    for name in nodes {
        if config.opt_out() && insecure.contains(name) {
            continue;
        }
        let hash = nsec3_hash(name, config.salt(), config.iterations());
        let entry = hashes.entry(hash).or_default();
        if let Some(node_types) = types.get(name) {
            entry.extend(node_types.iter().copied());
        }
    }
    let apex_hash = nsec3_hash(origin, config.salt(), config.iterations());
    let apex_types = hashes.entry(apex_hash).or_default();
    apex_types.insert(Rtype::DNSKEY);
    apex_types.insert(Rtype::NSEC3PARAM);

    let entries: Vec<(Vec<u8>, BTreeSet<Rtype>)> = hashes.into_iter().collect();
    for (index, (hash, entry_types)) in entries.iter().enumerate() {
        let Some((next_hash, _)) = entries.get((index + 1) % entries.len()) else {
            continue;
        };
        let mut bitmap_types = entry_types.clone();
        // Empty non-terminal: bitmap остаётся пустым (RFC 5155 §7.1).
        if !bitmap_types.is_empty() {
            bitmap_types.insert(Rtype::RRSIG);
        }
        let bitmap = TypeBitmap::from_types(bitmap_types);
        let owner =
            nsec3_owner_name(origin, hash).map_err(|error| SignZoneError::denial(origin, error))?;
        let nsec3 = Nsec3Data::new(
            Nsec3Config::HASH_SHA1,
            u8::from(config.opt_out()),
            config.iterations(),
            config.salt().to_vec(),
            next_hash.clone(),
            bitmap,
        )
        .map_err(|error| SignZoneError::rdata(origin, error))?;
        let rrset = Rrset::new(
            owner.clone(),
            Rtype::NSEC3,
            Rclass::IN,
            nsec_ttl,
            [Rdata::Nsec3(nsec3)],
        )
        .map_err(|error| SignZoneError::rrset(origin, error))?;
        data.insert((owner, Rtype::NSEC3), rrset);
    }

    let param = Nsec3ParamData::new(
        Nsec3Config::HASH_SHA1,
        0,
        config.iterations(),
        config.salt().to_vec(),
    )
    .map_err(|error| SignZoneError::rdata(origin, error))?;
    let rrset = Rrset::new(
        origin.clone(),
        Rtype::NSEC3PARAM,
        Rclass::IN,
        nsec_ttl,
        [Rdata::Nsec3Param(param)],
    )
    .map_err(|error| SignZoneError::rrset(origin, error))?;
    data.insert((origin.clone(), Rtype::NSEC3PARAM), rrset);
    Ok(())
}

fn validate_owners(origin: &Name, rrsets: &[Rrset]) -> Result<(), SignZoneError> {
    for rrset in rrsets {
        if !rrset.owner().is_subdomain_of(origin) {
            return Err(SignZoneError::OwnerOutsideZone {
                zone: origin.clone(),
                owner: rrset.owner().clone(),
            });
        }
    }
    Ok(())
}

fn is_dnssec_type(rr_type: Rtype) -> bool {
    matches!(
        rr_type,
        Rtype::RRSIG | Rtype::NSEC | Rtype::NSEC3 | Rtype::NSEC3PARAM | Rtype::DNSKEY
    )
}

fn collect_cuts(origin: &Name, data: &HashMap<(Name, Rtype), Rrset>) -> HashSet<Name> {
    data.keys()
        .filter(|(owner, rr_type)| *rr_type == Rtype::NS && owner != origin)
        .map(|(owner, _)| owner.clone())
        .collect()
}

/// Делегирования без DS — кандидаты на Opt-Out.
fn insecure_delegations(origin: &Name, data: &HashMap<(Name, Rtype), Rrset>) -> HashSet<Name> {
    collect_cuts(origin, data)
        .into_iter()
        .filter(|owner| !data.contains_key(&(owner.clone(), Rtype::DS)))
        .collect()
}

fn delegation_for<'a>(cuts: &'a HashSet<Name>, name: &Name) -> Option<&'a Name> {
    cuts.iter()
        .filter(|cut| name.is_subdomain_of(cut))
        .max_by_key(|cut| cut.label_count())
}

fn collect_nodes(
    origin: &Name,
    data: &HashMap<(Name, Rtype), Rrset>,
    cuts: &HashSet<Name>,
) -> HashSet<Name> {
    let mut nodes = HashSet::new();
    for (owner, _) in data.keys() {
        let mut current = Some(owner.clone());
        while let Some(name) = current {
            nodes.insert(name.clone());
            if &name == origin {
                break;
            }
            current = name.parent();
        }
    }
    // Names strictly below a zone cut are not authoritative and do not get
    // NSEC records.
    nodes.retain(|name| match delegation_for(cuts, name) {
        Some(cut) => cut == name,
        None => true,
    });
    nodes
}

fn collect_types(
    data: &HashMap<(Name, Rtype), Rrset>,
    cuts: &HashSet<Name>,
    nodes: &HashSet<Name>,
) -> HashMap<Name, BTreeSet<Rtype>> {
    let mut types: HashMap<Name, BTreeSet<Rtype>> = HashMap::with_capacity(nodes.len());
    for name in nodes {
        types.insert(name.clone(), BTreeSet::new());
    }
    for (owner, rr_type) in data.keys() {
        let Some(entry) = types.get_mut(owner) else {
            continue;
        };
        if let Some(cut) = delegation_for(cuts, owner) {
            if cut != owner {
                continue;
            }
            // At a delegation point only NS and DS are parent-side data.
            if !matches!(*rr_type, Rtype::NS | Rtype::DS) {
                continue;
            }
        }
        entry.insert(*rr_type);
    }
    types
}

fn signers_for<'a>(
    owner: &Name,
    rr_type: Rtype,
    cuts: &HashSet<Name>,
    signer: &'a ZoneSigner,
) -> Option<&'a [usize]> {
    let is_dnskey = rr_type == Rtype::DNSKEY;
    if let Some(cut) = delegation_for(cuts, owner) {
        if cut != owner {
            return None;
        }
        if rr_type == Rtype::NS {
            return None;
        }
        if rr_type != Rtype::DS && rr_type != Rtype::NSEC {
            return None;
        }
    }
    if is_dnskey {
        Some(&signer.dnskey_signers)
    } else {
        Some(&signer.data_signers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pulse_dns::{Serial, SoaData};
    use pulse_dnssec::{Algorithm, VerifyOptions, verify_rrsig};

    fn name(text: &str) -> Name {
        Name::parse(text).expect("test name")
    }

    fn ttl(value: u32) -> Ttl {
        Ttl::new(value).expect("test ttl")
    }

    fn rrset(owner: &str, rr_type: Rtype, rdatas: impl IntoIterator<Item = Rdata>) -> Rrset {
        Rrset::new(name(owner), rr_type, Rclass::IN, ttl(300), rdatas).expect("test rrset")
    }

    fn soa() -> Rrset {
        Rrset::new(
            name("example.com"),
            Rtype::SOA,
            Rclass::IN,
            ttl(3600),
            [Rdata::Soa(SoaData::new(
                name("ns1.example.com"),
                name("hostmaster.example.com"),
                Serial::new(1),
                3600,
                600,
                604_800,
                300,
            ))],
        )
        .expect("soa")
    }

    fn signer() -> ZoneSigner {
        ZoneSigner::new(
            vec![
                ZoneSigningKey::new(
                    PrivateKey::generate(Algorithm::ED25519).expect("key"),
                    KeyRole::Csk,
                )
                .expect("key"),
            ],
            86_400,
            300,
        )
        .expect("signer")
    }

    fn zone() -> Vec<Rrset> {
        vec![
            soa(),
            rrset(
                "example.com",
                Rtype::NS,
                [Rdata::Ns(name("ns1.example.com"))],
            ),
            rrset(
                "ns1.example.com",
                Rtype::A,
                [Rdata::A("192.0.2.1".parse().expect("ip"))],
            ),
            rrset(
                "www.example.com",
                Rtype::A,
                [Rdata::A("192.0.2.2".parse().expect("ip"))],
            ),
            rrset(
                "*.wild.example.com",
                Rtype::A,
                [Rdata::A("192.0.2.3".parse().expect("ip"))],
            ),
            rrset(
                "sub.example.com",
                Rtype::NS,
                [Rdata::Ns(name("ns.sub.example.com"))],
            ),
            rrset(
                "ns.sub.example.com",
                Rtype::A,
                [Rdata::A("192.0.2.4".parse().expect("ip"))],
            ),
        ]
    }

    fn rrsigs(signed: &[Rrset], owner: &Name, covered: Rtype) -> Vec<pulse_dns::RrsigData> {
        signed
            .iter()
            .filter(|rrset| rrset.owner() == owner && rrset.rr_type() == Rtype::RRSIG)
            .flat_map(|rrset| rrset.rdatas().iter())
            .filter_map(|rdata| match rdata {
                Rdata::Rrsig(sig) if sig.type_covered() == covered => Some(sig.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn signs_authoritative_data_and_builds_nsec_chain() {
        let origin = name("example.com");
        let signed = signer()
            .sign_zone(&origin, &zone(), 1_700_000_000)
            .expect("sign");
        let dnskeys = &signed.dnskeys;
        let options = VerifyOptions::new(1_700_000_000);

        let dnskey_rrset = signed
            .rrsets
            .iter()
            .find(|rrset| rrset.owner() == &origin && rrset.rr_type() == Rtype::DNSKEY)
            .expect("dnskey rrset");
        let dnskey_sigs = rrsigs(&signed.rrsets, &origin, Rtype::DNSKEY);
        assert_ne!(dnskey_sigs.len(), 0);
        for signature in &dnskey_sigs {
            assert!(
                dnskeys
                    .iter()
                    .any(|key| verify_rrsig(dnskey_rrset, signature, key, &options).is_ok())
            );
        }

        let owner = name("www.example.com");
        let a_rrset = signed
            .rrsets
            .iter()
            .find(|rrset| rrset.owner() == &owner && rrset.rr_type() == Rtype::A)
            .expect("a rrset");
        let signatures = rrsigs(&signed.rrsets, &owner, Rtype::A);
        assert_ne!(signatures.len(), 0, "A must be signed");
        for signature in &signatures {
            assert!(
                dnskeys
                    .iter()
                    .any(|key| verify_rrsig(a_rrset, signature, key, &options).is_ok())
            );
        }

        // NSEC chain covers apex, wildcard owner, cut and the ENT (`wild`).
        let mut nsec_owners: Vec<Name> = signed
            .rrsets
            .iter()
            .filter(|rrset| rrset.rr_type() == Rtype::NSEC)
            .map(|rrset| rrset.owner().clone())
            .collect();
        nsec_owners.sort_by(Name::cmp_canonical);
        let expected = [
            "example.com",
            "ns1.example.com",
            "sub.example.com",
            "wild.example.com",
            "*.wild.example.com",
            "www.example.com",
        ];
        assert_eq!(nsec_owners.len(), expected.len());
        for (owner, expected) in nsec_owners.iter().zip(expected) {
            assert_eq!(owner, &name(expected));
        }
        for (index, owner) in nsec_owners.iter().enumerate() {
            let rrset = signed
                .rrsets
                .iter()
                .find(|rrset| rrset.owner() == owner && rrset.rr_type() == Rtype::NSEC)
                .expect("nsec rrset");
            let Rdata::Nsec(nsec) = rrset.rdatas().iter().next().expect("nsec rdata") else {
                panic!("expected NSEC rdata");
            };
            let next = &nsec_owners[(index + 1) % nsec_owners.len()];
            assert_eq!(nsec.next_domain(), next, "NSEC next at {owner}");
            assert!(nsec.type_bitmap().contains(Rtype::NSEC));
            assert!(nsec.type_bitmap().contains(Rtype::RRSIG));
            assert_ne!(rrsigs(&signed.rrsets, owner, Rtype::NSEC).len(), 0);
        }

        // Delegation NS and glue below the cut stay unsigned.
        let cut = name("sub.example.com");
        assert_eq!(rrsigs(&signed.rrsets, &cut, Rtype::NS).len(), 0);
        let glue = name("ns.sub.example.com");
        assert_eq!(rrsigs(&signed.rrsets, &glue, Rtype::A).len(), 0);
        assert!(
            !signed
                .rrsets
                .iter()
                .any(|rrset| rrset.owner() == &glue && rrset.rr_type() == Rtype::NSEC)
        );
    }

    #[test]
    fn missing_soa_is_rejected() {
        let origin = name("example.com");
        let error = signer()
            .sign_zone(&origin, &[], 1_700_000_000)
            .expect_err("SOA is required");
        assert!(matches!(error, SignZoneError::MissingSoa { .. }));
    }

    fn delegation_zone() -> Vec<Rrset> {
        let mut records = zone();
        // secure delegation: NS + DS
        records.push(rrset(
            "secure.example.com",
            Rtype::NS,
            [Rdata::Ns(name("ns.secure.example.com"))],
        ));
        records.push(rrset(
            "secure.example.com",
            Rtype::DS,
            [Rdata::Ds(
                pulse_dns::DsData::new(12345, 15, 2, vec![0xAB; 32]).expect("ds"),
            )],
        ));
        records.push(rrset(
            "ns.secure.example.com",
            Rtype::A,
            [Rdata::A("192.0.2.5".parse().expect("ip"))],
        ));
        // insecure delegation: NS only
        records.push(rrset(
            "insecure.example.com",
            Rtype::NS,
            [Rdata::Ns(name("ns.insecure.example.com"))],
        ));
        records.push(rrset(
            "ns.insecure.example.com",
            Rtype::A,
            [Rdata::A("192.0.2.6".parse().expect("ip"))],
        ));
        records
    }

    fn nsec3_rrsets(signed: &SignedZone, origin: &Name) -> Vec<Rrset> {
        signed
            .rrsets
            .iter()
            .filter(|rrset| {
                rrset.rr_type() == Rtype::NSEC3 && rrset.owner().is_subdomain_of(origin)
            })
            .cloned()
            .collect()
    }

    #[test]
    fn opt_out_omits_insecure_delegation_and_sets_flag() {
        let origin = name("example.com");
        let signer = signer();
        let denial = DenialPolicy::Nsec3(
            Nsec3Config::new(vec![0xAA, 0xBB], 0)
                .expect("config")
                .with_opt_out(true),
        );
        let output = signer
            .sign_zone_with(&origin, &delegation_zone(), 1_700_000_000, &denial)
            .expect("sign opt-out");
        let records = nsec3_rrsets(&output, &origin);
        assert_ne!(records.len(), 0);

        let params = Nsec3Config::new(vec![0xAA, 0xBB], 0).expect("params");
        let insecure_hash = pulse_dnssec::rdata_util::nsec3_hash(
            &name("insecure.example.com"),
            params.salt(),
            params.iterations(),
        );
        let secure_hash = pulse_dnssec::rdata_util::nsec3_hash(
            &name("secure.example.com"),
            params.salt(),
            params.iterations(),
        );
        let mut hashes = Vec::new();
        for rrset in &records {
            let label = rrset.owner().first_label().expect("label");
            hashes.push(pulse_dnssec::denial::base32hex::decode(label).expect("base32hash"));
            let Rdata::Nsec3(data) = rrset.rdatas().first().expect("nsec3") else {
                panic!("expected NSEC3");
            };
            assert_eq!(data.flags() & 1, 1, "Opt-Out flag must be set");
        }
        assert!(
            !hashes.iter().any(|hash| hash == &insecure_hash),
            "insecure delegation must be omitted from NSEC3 chain"
        );
        assert!(
            hashes.iter().any(|hash| hash == &secure_hash),
            "secure delegation must stay in NSEC3 chain"
        );

        // Apex не должен потерять свои типы из-за фильтра insecure-делегирований.
        let apex_hash = pulse_dnssec::rdata_util::nsec3_hash(&origin, params.salt(), 0);
        let apex = records
            .iter()
            .find(|rrset| {
                rrset
                    .owner()
                    .first_label()
                    .and_then(|label| pulse_dnssec::denial::base32hex::decode(label).ok())
                    .is_some_and(|hash| hash == apex_hash)
            })
            .expect("apex NSEC3");
        let Rdata::Nsec3(apex_data) = apex.rdatas().first().expect("apex rdata") else {
            panic!("expected NSEC3");
        };
        assert!(apex_data.type_bitmap().contains(Rtype::SOA));
        assert!(apex_data.type_bitmap().contains(Rtype::NS));
        assert!(apex_data.type_bitmap().contains(Rtype::DNSKEY));
    }

    #[test]
    fn opt_out_proof_marks_referral_insecure() {
        use pulse_dnssec::DenialLimits;
        use pulse_dnssec::denial::nsec3_ds_nodata;

        let origin = name("example.com");
        let denial = DenialPolicy::Nsec3(
            Nsec3Config::new(vec![0x01, 0x02], 0)
                .expect("config")
                .with_opt_out(true),
        );
        let output = signer()
            .sign_zone_with(&origin, &delegation_zone(), 1_700_000_000, &denial)
            .expect("sign opt-out");

        let proofs: Vec<pulse_dnssec::Nsec3Proof> = output
            .rrsets
            .iter()
            .filter(|rrset| rrset.rr_type() == Rtype::NSEC3)
            .filter_map(|rrset| {
                let record = pulse_dns::Record::new(
                    rrset.owner().clone(),
                    Rtype::NSEC3,
                    Rclass::IN,
                    rrset.ttl(),
                    rrset.rdatas().first().cloned().expect("rdata"),
                )
                .expect("record");
                pulse_dnssec::Nsec3Proof::from_record(&record, DenialLimits::new()).ok()
            })
            .collect();
        let outcome = nsec3_ds_nodata(
            &name("insecure.example.com"),
            &origin,
            &proofs,
            DenialLimits::new(),
        )
        .expect("opt-out DS proof");
        assert!(
            outcome.opt_out,
            "insecure delegation must be proven Opt-Out"
        );
        assert!(!outcome.is_secure());
    }
}
