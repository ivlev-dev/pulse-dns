//! Типизированные ошибки `pulse-dnssec`.
//!
//! Ошибки не содержат секретного материала: только алгоритмы, длины, имена
//! и позиционные признаки. Тексты библиотечных ошибок (`aws-lc-rs`)
//! ретранслируются как есть — они не включают байты ключей.

use std::path::PathBuf;

use thiserror::Error;

use crate::algorithm::Algorithm;

/// Ошибки работы с ключами (генерация, импорт, экспорт).
#[derive(Debug, Error)]
pub enum KeyError {
    /// Алгоритм не поддерживается для ключевых операций.
    #[error("algorithm {algorithm} is not supported for private keys")]
    UnsupportedAlgorithm {
        /// Алгоритм DNSSEC.
        algorithm: Algorithm,
    },
    /// Алгоритм, переданный при импорте, не совпадает с содержимым файла.
    #[error("key material algorithm {actual} does not match requested {expected}")]
    AlgorithmMismatch {
        /// Запрошенный алгоритм.
        expected: Algorithm,
        /// Фактический алгоритм материала.
        actual: Algorithm,
    },
    /// Библиотека отклонила ключевой материал.
    #[error("key rejected: {reason}")]
    KeyRejected {
        /// Причина от библиотеки (без материала ключа).
        reason: String,
    },
    /// Некорректный PKCS#8 DER.
    #[error("invalid PKCS#8 DER: {reason}")]
    BadPkcs8 {
        /// Причина (структурная).
        reason: &'static str,
    },
    /// Некорректный PEM.
    #[error("invalid PEM: {reason}")]
    BadPem {
        /// Причина (структурная).
        reason: &'static str,
    },
    /// Некорректный BIND-файл приватного ключа.
    #[error("invalid BIND private key file: {reason}")]
    BadBindPrivate {
        /// Причина (структурная).
        reason: &'static str,
    },
    /// Некорректный BIND/zone-файл DNSKEY.
    #[error("invalid DNSKEY file: {reason}")]
    BadDnskeyFile {
        /// Причина (структурная).
        reason: &'static str,
    },
    /// Обязательное поле отсутствует.
    #[error("missing required field {field}")]
    MissingField {
        /// Имя поля.
        field: &'static str,
    },
    /// Некорректный base64.
    #[error("invalid base64 in field {field}")]
    InvalidBase64 {
        /// Имя поля.
        field: &'static str,
    },
    /// Неподдерживаемый размер RSA-ключа.
    #[error("RSA key size {bits} bits is not supported (allowed: 2048, 4096)")]
    RsaKeySize {
        /// Фактический размер.
        bits: usize,
    },
    /// Слишком слабый ключ.
    #[error("key is too weak: {bits} bits (minimum 2048)")]
    WeakKey {
        /// Фактический размер.
        bits: usize,
    },
    /// Некорректный публичный ключ.
    #[error("invalid public key: {reason}")]
    InvalidPublicKey {
        /// Причина.
        reason: &'static str,
    },
    /// Ошибка CSPRNG.
    #[error("random number generator failed")]
    Random,
    /// Ошибка криптографической операции.
    #[error("cryptographic operation failed: {reason}")]
    Crypto {
        /// Причина.
        reason: String,
    },
    /// Структурная ошибка DER.
    #[error("DER encoding error: {reason}")]
    Der {
        /// Причина.
        reason: &'static str,
    },
    /// Формат BIND не представляет данный алгоритм.
    #[error("algorithm {algorithm} cannot be represented in BIND key format")]
    BindNotSupported {
        /// Алгоритм.
        algorithm: Algorithm,
    },
}

/// Ошибки подписи RRset.
#[derive(Debug, Error)]
pub enum SignError {
    /// Алгоритм запрещён для подписи политикой.
    #[error("algorithm {algorithm} is not allowed for signing")]
    AlgorithmNotAllowed {
        /// Алгоритм ключа.
        algorithm: Algorithm,
    },
    /// Signer name не является предком владельца RRset.
    #[error("signer {signer} is not an ancestor of {owner}")]
    SignerNotAncestor {
        /// Владелец RRset.
        owner: String,
        /// Signer name.
        signer: String,
    },
    /// Некорректное окно валидности.
    #[error("invalid signature validity window")]
    InvalidValidity,
    /// `original_ttl` меньше TTL RRset.
    #[error("original TTL {original_ttl} is below RRset TTL {rrset_ttl}")]
    OriginalTtlBelowRrsetTtl {
        /// Original TTL из параметров.
        original_ttl: u32,
        /// TTL RRset.
        rrset_ttl: u32,
    },
    /// `original_ttl` вне допустимого диапазона.
    #[error("original TTL {ttl} exceeds 2^31-1")]
    OriginalTtlOutOfRange {
        /// Значение.
        ttl: u32,
    },
    /// Слишком много меток для поля Labels.
    #[error("owner name has {labels} labels; RRSIG Labels field cannot hold it")]
    LabelsOverflow {
        /// Количество меток.
        labels: usize,
    },
    /// Ошибка ключа.
    #[error(transparent)]
    Key(#[from] KeyError),
    /// Ошибка кодирования RRset.
    #[error(transparent)]
    Rrset(#[from] pulse_dns::RrsetError),
    /// Ошибка криптографической операции.
    #[error("signing failed: {reason}")]
    Crypto {
        /// Причина.
        reason: String,
    },
}

/// Ошибки валидации RRSIG.
#[derive(Debug, Error)]
pub enum VerifyError {
    /// Алгоритм не разрешён политикой.
    #[error("algorithm {algorithm} is not allowed by policy")]
    AlgorithmNotAllowed {
        /// Алгоритм.
        algorithm: Algorithm,
    },
    /// Legacy SHA-1 алгоритм выключен.
    #[error("legacy SHA-1 algorithm {algorithm} requires explicit opt-in")]
    LegacyDisabled {
        /// Алгоритм.
        algorithm: Algorithm,
    },
    /// Алгоритм RRSIG не совпадает с алгоритмом DNSKEY.
    #[error("RRSIG algorithm {rrsig} does not match DNSKEY algorithm {dnskey}")]
    AlgorithmMismatch {
        /// Алгоритм подписи.
        rrsig: u8,
        /// Алгоритм ключа.
        dnskey: u8,
    },
    /// Key tag не совпадает.
    #[error("RRSIG key tag {rrsig} does not match DNSKEY key tag {dnskey}")]
    KeyTagMismatch {
        /// Key tag подписи.
        rrsig: u16,
        /// Key tag ключа.
        dnskey: u16,
    },
    /// RRSIG покрывает другой тип.
    #[error("RRSIG covers {covered}, but RRset type is {rrset}")]
    TypeMismatch {
        /// Тип из RRSIG.
        covered: pulse_dns::Rtype,
        /// Тип RRset.
        rrset: pulse_dns::Rtype,
    },
    /// Класс RRset не IN.
    #[error("RRset class {class} is not IN")]
    ClassNotIn {
        /// Класс.
        class: pulse_dns::Rclass,
    },
    /// Signer name не является предком владельца.
    #[error("signer {signer} is not an ancestor of {owner}")]
    SignerNotAncestor {
        /// Владелец RRset.
        owner: String,
        /// Signer name.
        signer: String,
    },
    /// Поле Labels больше числа меток владельца.
    #[error("RRSIG labels {labels} exceed owner label count {owner_labels}")]
    LabelsExceedOwner {
        /// Labels из RRSIG.
        labels: u8,
        /// Меток во владельце.
        owner_labels: usize,
    },
    /// Разница меток не соответствует wildcard-развёртыванию.
    #[error("RRSIG labels {labels} differ from owner labels {owner_labels} by more than one")]
    WildcardLabelsMismatch {
        /// Labels из RRSIG.
        labels: u8,
        /// Меток во владельце.
        owner_labels: usize,
    },
    /// TTL RRset больше original TTL.
    #[error("RRset TTL {rrset_ttl} exceeds RRSIG original TTL {original_ttl}")]
    OriginalTtlBelowRrsetTtl {
        /// TTL RRset.
        rrset_ttl: u32,
        /// Original TTL.
        original_ttl: u32,
    },
    /// Подпись истекла.
    #[error("signature expired: now {now}, expiration {expiration}")]
    Expired {
        /// Текущее время.
        now: u32,
        /// Время истечения.
        expiration: u32,
    },
    /// Подпись ещё не вступила в силу.
    #[error("signature not yet valid: now {now}, inception {inception}")]
    NotYetValid {
        /// Текущее время.
        now: u32,
        /// Начало действия.
        inception: u32,
    },
    /// Окно валидности неоднозначно по RFC 1982.
    #[error("signature validity window is ambiguous (RFC 1982)")]
    AmbiguousTimeWindow,
    /// DNSKEY не является zone key.
    #[error("DNSKEY flags {flags:#06x} do not have the zone key bit set")]
    DnskeyNotZoneKey {
        /// Flags DNSKEY.
        flags: u16,
    },
    /// Неверный протокол DNSKEY.
    #[error("DNSKEY protocol {protocol} is not 3")]
    DnskeyProtocol {
        /// Protocol.
        protocol: u8,
    },
    /// RSA-ключ слабее 2048 бит.
    #[error("RSA key is too weak: {bits} bits (minimum 2048)")]
    WeakRsaKey {
        /// Фактический размер.
        bits: usize,
    },
    /// Некорректный публичный ключ DNSKEY.
    #[error("invalid DNSKEY public key: {reason}")]
    BadPublicKey {
        /// Причина.
        reason: &'static str,
    },
    /// Некорректная длина подписи для алгоритма.
    #[error("signature length {actual} is invalid for this algorithm (expected {expected})")]
    BadSignatureLength {
        /// Ожидаемая длина.
        expected: usize,
        /// Фактическая длина.
        actual: usize,
    },
    /// Подпись не прошла проверку ни одним ключом.
    #[error("no DNSKEY matched the RRSIG algorithm and key tag")]
    NoMatchingDnskey,
    /// Ошибка криптографической проверки.
    #[error("signature verification failed")]
    Crypto,
    /// Внутренняя ошибка кодирования.
    #[error(transparent)]
    Rrset(#[from] pulse_dns::RrsetError),
}

/// Ошибки DS.
#[derive(Debug, Error)]
pub enum DsError {
    /// Digest type не поддерживается.
    #[error("DS digest type {digest_type} is not supported")]
    UnsupportedDigestType {
        /// Digest type.
        digest_type: u8,
    },
    /// Legacy SHA-1 digest выключен.
    #[error("legacy DS digest type {digest_type} requires explicit opt-in")]
    LegacyDigestDisabled {
        /// Digest type.
        digest_type: u8,
    },
    /// Длина digest не соответствует типу.
    #[error("digest length {actual} does not match {expected} for digest type {digest_type}")]
    DigestLength {
        /// Digest type.
        digest_type: u8,
        /// Ожидаемая длина.
        expected: usize,
        /// Фактическая длина.
        actual: usize,
    },
    /// Алгоритм DNSKEY не совпадает с DS.
    #[error("DS algorithm {ds} does not match DNSKEY algorithm {dnskey}")]
    AlgorithmMismatch {
        /// Алгоритм DS.
        ds: u8,
        /// Алгоритм DNSKEY.
        dnskey: u8,
    },
    /// Key tag не совпадает.
    #[error("DS key tag {ds} does not match DNSKEY key tag {dnskey}")]
    KeyTagMismatch {
        /// Key tag DS.
        ds: u16,
        /// Key tag DNSKEY.
        dnskey: u16,
    },
    /// RSA-ключ слабее 2048 бит.
    #[error("RSA key is too weak: {bits} bits (minimum 2048)")]
    WeakKey {
        /// Фактический размер.
        bits: usize,
    },
}

/// Ошибки denial-of-existence (NSEC/NSEC3).
#[derive(Debug, Error)]
pub enum DenialError {
    /// Пустой denial proof.
    #[error("denial proof is empty")]
    EmptyProof,
    /// Запись не является NSEC.
    #[error("record is not NSEC")]
    NotNsec,
    /// Слишком много proof-записей (DoS-лимит).
    #[error("denial proof contains {count} records (max {max})")]
    TooManyRecords {
        /// Количество.
        count: usize,
        /// Лимит.
        max: usize,
    },
    /// NSEC-владелец вне зоны.
    #[error("NSEC owner {name} is outside zone {zone}")]
    NsecOwnerOutsideZone {
        /// Владелец.
        name: String,
        /// Зона.
        zone: String,
    },
    /// NSEC `next domain` вне зоны.
    #[error("NSEC next domain {name} is outside zone {zone}")]
    NsecNextOutsideZone {
        /// Next domain.
        name: String,
        /// Зона.
        zone: String,
    },
    /// NSEC не покрывает имя.
    #[error("no NSEC record covers {name}")]
    NsecDoesNotCover {
        /// Имя.
        name: String,
    },
    /// NSEC не соответствует имени.
    #[error("no NSEC record matches {name}")]
    NsecDoesNotMatch {
        /// Имя.
        name: String,
    },
    /// Тип присутствует в bitmap.
    #[error("type {rr_type} is present in the type bitmap")]
    TypePresent {
        /// Тип.
        rr_type: pulse_dns::Rtype,
    },
    /// CNAME присутствует в bitmap.
    #[error("CNAME is present in the type bitmap")]
    CnamePresent,
    /// DNAME присутствует в bitmap.
    #[error("DNAME is present in the type bitmap")]
    DnamePresent,
    /// NS присутствует без SOA (делегирование).
    #[error("NS is present without SOA: not an authoritative answer")]
    DelegationWithoutSoa,
    /// Не найден closest encloser.
    #[error("closest encloser not found for {name}")]
    ClosestEncloserNotFound {
        /// Имя.
        name: String,
    },
    /// Next closer name не покрыт.
    #[error("next closer name {name} is not covered")]
    NextCloserNotCovered {
        /// Имя.
        name: String,
    },
    /// Wildcard не покрыт.
    #[error("wildcard {name} is not covered")]
    WildcardNotCovered {
        /// Wildcard.
        name: String,
    },
    /// Opt-Out не установлен, хотя требуется.
    #[error("opt-out flag is required but not set")]
    OptOutRequired,
    /// Opt-Out установлен неожиданно.
    #[error("opt-out flag is not allowed here")]
    OptOutUnexpected,
    /// Ошибка генерации случайной соли NSEC3.
    #[error("cannot generate a random NSEC3 salt")]
    Nsec3SaltRandom,
    /// NSEC3 hash algorithm не поддерживается.
    #[error("NSEC3 hash algorithm {algorithm} is not supported")]
    Nsec3HashUnsupported {
        /// Алгоритм.
        algorithm: u8,
    },
    /// Неизвестные флаги NSEC3.
    #[error("NSEC3 flags {flags} contain undefined bits")]
    Nsec3Flags {
        /// Флаги.
        flags: u8,
    },
    /// Превышен лимит итераций.
    #[error("NSEC3 iterations {iterations} exceed limit {max}")]
    Nsec3IterationsTooHigh {
        /// Итерации.
        iterations: u16,
        /// Лимит.
        max: u16,
    },
    /// Несогласованные параметры NSEC3 в наборе.
    #[error("NSEC3 records use inconsistent hash/salt/iterations parameters")]
    Nsec3InconsistentParams,
    /// Владелец NSEC3 вне зоны.
    #[error("NSEC3 owner {name} is outside zone {zone}")]
    Nsec3OwnerOutsideZone {
        /// Владелец.
        name: String,
        /// Зона.
        zone: String,
    },
    /// Некорректный base32hex-хеш в имени владельца NSEC3.
    #[error("NSEC3 owner hash label is invalid: {reason}")]
    Nsec3OwnerHash {
        /// Причина.
        reason: &'static str,
    },
    /// Не найдено NSEC3, соответствующее имени.
    #[error("no NSEC3 record matches {name}")]
    Nsec3NoMatch {
        /// Имя.
        name: String,
    },
    /// Не найдено NSEC3, покрывающее имя.
    #[error("no NSEC3 record covers {name}")]
    Nsec3NoCover {
        /// Имя.
        name: String,
    },
    /// DS присутствует там, где ожидался NODATA.
    #[error("DS is present in the type bitmap")]
    DsPresent,
    /// Имя существует, поэтому NXDOMAIN-доказательство неверно.
    #[error("name {name} exists")]
    NameExists {
        /// Имя.
        name: String,
    },
    /// Wildcard существует, поэтому NXDOMAIN-доказательство неверно.
    #[error("wildcard {name} exists")]
    WildcardExists {
        /// Wildcard.
        name: String,
    },
    /// SOA отсутствует в apex NSEC3.
    #[error("SOA is absent at the zone apex")]
    SoaMissing,
}

/// Ошибки trust anchors.
#[derive(Debug, Error)]
pub enum TrustAnchorError {
    /// Ошибка разбора файла.
    #[error("trust anchor parse error: {reason}")]
    Parse {
        /// Причина.
        reason: &'static str,
    },
    /// Ошибка ввода-вывода.
    #[error("trust anchor I/O error: {source}")]
    Io {
        /// Источник.
        #[from]
        source: std::io::Error,
    },
    /// Нет активного anchor на указанное время.
    #[error("no active trust anchor at time {now}")]
    NoActiveAnchor {
        /// Время.
        now: u32,
    },
    /// Неверный размер digest.
    #[error("trust anchor digest length {actual} is invalid for digest type {digest_type}")]
    DigestLength {
        /// Digest type.
        digest_type: u8,
        /// Фактическая длина.
        actual: usize,
    },
    /// Неверный digest type.
    #[error("trust anchor digest type {digest_type} is not supported")]
    DigestType {
        /// Digest type.
        digest_type: u8,
    },
    /// Некорректная дата.
    #[error("invalid UTC timestamp in trust anchor: {value}")]
    Timestamp {
        /// Значение.
        value: String,
    },
}

/// Ошибки файловых операций с ключами.
#[derive(Debug, Error)]
pub enum KeyFileError {
    /// Ошибка ввода-вывода.
    #[error("key file I/O error at {path}: {source}")]
    Io {
        /// Путь.
        path: PathBuf,
        /// Источник.
        source: std::io::Error,
    },
    /// Небезопасные права доступа.
    #[error("unsafe permissions {mode:04o} on {path}")]
    Permissions {
        /// Путь.
        path: PathBuf,
        /// Фактический режим.
        mode: u32,
    },
    /// Ожидался каталог.
    #[error("path {path} is not a directory")]
    NotADirectory {
        /// Путь.
        path: PathBuf,
    },
    /// Не удалось создать временный файл.
    #[error("could not create a unique temporary file in {directory}")]
    TempFile {
        /// Каталог.
        directory: PathBuf,
    },
    /// Ошибка разбора ключа.
    #[error(transparent)]
    Key(#[from] KeyError),
}

/// Ошибки цепочки доверия DS → DNSKEY(KSK) → DNSKEY(ZSK) → RRSIG.
#[derive(Debug, Error)]
pub enum ChainError {
    /// RRset принадлежит другой зоне.
    #[error("RRset owner {actual} does not match zone {expected}")]
    ZoneMismatch {
        /// Ожидаемая зона.
        expected: String,
        /// Фактический владелец.
        actual: String,
    },
    /// RRset не является DNSKEY.
    #[error("RRset type {rr_type} is not DNSKEY")]
    NotDnskeyRrset {
        /// Тип RRset.
        rr_type: pulse_dns::Rtype,
    },
    /// В DNSKEY RRset нет ключей.
    #[error("DNSKEY RRset is empty")]
    EmptyDnskeyRrset,
    /// Ни один DNSKEY не соответствует DS (BOGUS).
    #[error("no DNSKEY matches the DS set (bogus)")]
    NoMatchingDs,
    /// DNSKEY RRset не подписан валидным KSK.
    #[error("DNSKEY RRset is not signed by a DS-matched KSK (bogus)")]
    DnskeyNotSelfSigned,
    /// Нет валидной подписи RRset доверенным ключом.
    #[error("RRset has no valid signature from the validated DNSKEY set (bogus)")]
    NoValidSignature,
    /// Ошибка валидации подписи.
    #[error(transparent)]
    Verify(#[from] VerifyError),
    /// Ошибка DS.
    #[error(transparent)]
    Ds(#[from] DsError),
}

/// Общая ошибка крейта.
#[derive(Debug, Error)]
pub enum Error {
    /// Ключи.
    #[error(transparent)]
    Key(#[from] KeyError),
    /// Подпись.
    #[error(transparent)]
    Sign(#[from] SignError),
    /// Валидация.
    #[error(transparent)]
    Verify(#[from] VerifyError),
    /// DS.
    #[error(transparent)]
    Ds(#[from] DsError),
    /// Цепочка доверия.
    #[error(transparent)]
    Chain(#[from] ChainError),
    /// Denial.
    #[error(transparent)]
    Denial(#[from] DenialError),
    /// Trust anchors.
    #[error(transparent)]
    TrustAnchor(#[from] TrustAnchorError),
    /// Файлы ключей.
    #[error(transparent)]
    KeyFile(#[from] KeyFileError),
}
