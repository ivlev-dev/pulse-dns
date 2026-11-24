//! Автоматическое обновление trust anchors (RFC 5011).
//!
//! Модуль реализует состояние доверенных KSK и правила add/revoke
//! hold-down поверх валидированного `DNSKEY` RRset. Наблюдение обязано
//! выполняться только после успешной проверки подписи RRset'а обычной
//! цепочкой доверия — модуль не проверяет RRSIG и не доверяет сети.
//!
//! # Состояния
//!
//! - [`AnchorStatus::Valid`] — anchor используется для валидации;
//! - [`AnchorStatus::AddPending`] — новый KSK увиден, идёт add hold-down
//!   (по умолчанию 30 дней); при исчезновении из зоны кандидат откатывается;
//! - [`AnchorStatus::RevokePending`] — у действующего anchor установлен
//!   REVOKE-бит (RFC 5011 §2.5), идёт revoke hold-down (30 дней), после
//!   которого anchor удаляется.
//!
//! # Персистентность
//!
//! Состояние хранится в JSON-файле, записывается атомарно (`0600`, каталог
//! `0700`). Секретов в файле нет: только открытые digest'ы, key tag'и и
//! временные метки.
//!
//! # Пример
//!
//! ```
//! use pulse_dnssec::trust_update::{TrustAnchorPolicy, TrustAnchorStore};
//! use pulse_dnssec::builtin_root_anchors;
//!
//! let mut store = TrustAnchorStore::with_policy(TrustAnchorPolicy::default());
//! let now = 1_767_225_600;
//! store.seed(&builtin_root_anchors(), now);
//! assert_eq!(store.active_set(now).len(), 2);
//! ```
//!
//! Наблюдение выполняется только для RRset, уже проверенного цепочкой
//! DS → DNSKEY → RRSIG; сам модуль подписи не проверяет.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use pulse_dns::{DsData, Name, Rdata, Rrset};
use serde::{Deserialize, Serialize};

use crate::ds::{DIGEST_SHA256, DsPolicy, ds_from_dnskey};
use crate::keyfile::write_secret_file;
use crate::secret::SecretRef;
use crate::trust_anchor::{TrustAnchor, TrustAnchorSet};

/// Длительность hold-down по умолчанию (30 дней, RFC 5011 §2.4.1).
pub const RFC_5011_HOLD_DOWN_SECS: u32 = 30 * 86_400;

/// Флаг REVOKE в `DNSKEY` (RFC 5011 §2.1).
pub const DNSKEY_FLAG_REVOKE: u16 = 0x0080;

/// Политика обновления anchors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustAnchorPolicy {
    /// Сколько секунд новый KSK должен присутствовать до активации.
    pub add_hold_down: u32,
    /// Сколько секунд отозванный KSK остаётся удаляемым.
    pub revoke_hold_down: u32,
}

impl TrustAnchorPolicy {
    /// Создаёт политику с явными hold-down.
    #[must_use]
    pub const fn new(add_hold_down: u32, revoke_hold_down: u32) -> Self {
        Self {
            add_hold_down,
            revoke_hold_down,
        }
    }
}

impl Default for TrustAnchorPolicy {
    fn default() -> Self {
        Self {
            add_hold_down: RFC_5011_HOLD_DOWN_SECS,
            revoke_hold_down: RFC_5011_HOLD_DOWN_SECS,
        }
    }
}

/// Состояние anchor в наборе.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorStatus {
    /// Anchor доверенный и участвует в валидации.
    Valid,
    /// Кандидат на добавление, идёт hold-down.
    AddPending,
    /// Отозван, идёт hold-down до удаления.
    RevokePending,
}

impl AnchorStatus {
    /// Строковое имя для API/логов.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::AddPending => "add_pending",
            Self::RevokePending => "revoke_pending",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AnchorRecord {
    key_tag: u16,
    algorithm: u8,
    digest_type: u8,
    digest: String,
    valid_from: Option<u32>,
    valid_until: Option<u32>,
    status: AnchorStatus,
    hold_down_until: u32,
    last_seen: u32,
    missing_since: Option<u32>,
}

impl AnchorRecord {
    fn from_anchor(
        anchor: &TrustAnchor,
        status: AnchorStatus,
        now: u32,
        hold_down_until: u32,
    ) -> Self {
        Self {
            key_tag: anchor.key_tag(),
            algorithm: anchor.algorithm(),
            digest_type: anchor.digest_type(),
            digest: encode_hex(anchor.digest()),
            valid_from: anchor.valid_from(),
            valid_until: anchor.valid_until(),
            status,
            hold_down_until,
            last_seen: now,
            missing_since: None,
        }
    }

    fn to_anchor(&self) -> Option<TrustAnchor> {
        let digest = decode_hex(&self.digest)?;
        TrustAnchor::new(
            self.key_tag,
            self.algorithm,
            self.digest_type,
            digest,
            self.valid_from,
            self.valid_until,
        )
        .ok()
    }

    fn matches_ds(&self, ds: &DsData) -> bool {
        self.key_tag == ds.key_tag()
            && self.algorithm == ds.algorithm()
            && self.digest_type == ds.digest_type()
            && decode_hex(&self.digest).is_some_and(|digest| digest == ds.digest())
    }
}

/// Наблюдённый KSK из валидированного `DNSKEY` RRset.
#[derive(Debug, Clone)]
struct ObservedKey {
    ds: DsData,
    revoked: bool,
}

/// Изменения, применённые одним наблюдением.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UpdateReport {
    /// Новых кандидатов добавлено.
    pub added: usize,
    /// Кандидатов активировано после add hold-down.
    pub activated: usize,
    /// Действующих anchors помечено отозванными.
    pub revoked: usize,
    /// Anchor'ов удалено (revoke hold-down истёк или откат).
    pub removed: usize,
    /// Сколько anchors осталось в наборе.
    pub total: usize,
}

impl UpdateReport {
    /// Были ли изменения состояния.
    #[must_use]
    pub const fn changed(self) -> bool {
        self.added > 0 || self.activated > 0 || self.revoked > 0 || self.removed > 0
    }
}

/// Ошибка загрузки/сохранения состояния anchors.
#[derive(Debug, thiserror::Error)]
pub enum TrustUpdateError {
    /// Ошибка файлового ввода-вывода.
    #[error("trust anchor state {path}: {source}")]
    Io {
        /// Путь.
        path: PathBuf,
        /// Причина.
        #[source]
        source: std::io::Error,
    },
    /// Некорректный JSON состояния.
    #[error("trust anchor state {path}: {source}")]
    Json {
        /// Путь.
        path: PathBuf,
        /// Причина.
        #[source]
        source: serde_json::Error,
    },
    /// Небезопасные права файла состояния.
    #[error("trust anchor state {path} has insecure mode {mode:o}; expected 0600")]
    InsecurePermissions {
        /// Путь.
        path: PathBuf,
        /// Фактический режим.
        mode: u32,
    },
    /// Ошибка атомарной записи.
    #[error("cannot persist trust anchor state {path}: {source}")]
    Persist {
        /// Путь.
        path: PathBuf,
        /// Причина.
        #[source]
        source: crate::error::KeyFileError,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StateFile {
    version: u32,
    policy: TrustAnchorPolicy,
    anchors: Vec<AnchorRecord>,
}

const STATE_VERSION: u32 = 1;

/// Персистентный набор trust anchors с RFC 5011 hold-down.
#[derive(Debug)]
pub struct TrustAnchorStore {
    path: Option<PathBuf>,
    policy: TrustAnchorPolicy,
    anchors: Vec<AnchorRecord>,
}

impl TrustAnchorStore {
    /// Создаёт пустой набор в памяти без персистентности.
    #[must_use]
    pub fn with_policy(policy: TrustAnchorPolicy) -> Self {
        Self {
            path: None,
            policy,
            anchors: Vec::new(),
        }
    }

    /// Открывает состояние из файла (или создаёт пустое).
    ///
    /// # Errors
    ///
    /// [`TrustUpdateError::Io`], [`TrustUpdateError::Json`],
    /// [`TrustUpdateError::InsecurePermissions`].
    pub fn open(
        path: impl Into<PathBuf>,
        policy: TrustAnchorPolicy,
    ) -> Result<Self, TrustUpdateError> {
        let path = path.into();
        if !path.exists() {
            return Ok(Self {
                path: Some(path),
                policy,
                anchors: Vec::new(),
            });
        }
        check_permissions(&path)?;
        let text = fs::read_to_string(&path).map_err(|source| TrustUpdateError::Io {
            path: path.clone(),
            source,
        })?;
        let state: StateFile =
            serde_json::from_str(&text).map_err(|source| TrustUpdateError::Json {
                path: path.clone(),
                source,
            })?;
        Ok(Self {
            path: Some(path),
            // Политика задаётся конфигурацией; файл хранит её для аудита.
            policy,
            anchors: state.anchors,
        })
    }

    /// Путь файла состояния, если набор персистентный.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Действующая политика.
    #[must_use]
    pub const fn policy(&self) -> TrustAnchorPolicy {
        self.policy
    }

    /// Переопределяет политику (например, для тестов).
    pub fn set_policy(&mut self, policy: TrustAnchorPolicy) {
        self.policy = policy;
    }

    /// Добавляет доверенные anchors (seed из конфигурации/встроенного набора).
    ///
    /// Уже существующие записи не меняются; новые помечаются [`AnchorStatus::Valid`]
    /// и получают `validFrom` из anchor (или `now`). Возвращает число
    /// добавленных.
    pub fn seed(&mut self, anchors: &[TrustAnchor], now: u32) -> usize {
        let mut added = 0;
        for anchor in anchors {
            if self
                .anchors
                .iter()
                .any(|record| record_matches_anchor(record, anchor))
            {
                continue;
            }
            let mut record = AnchorRecord::from_anchor(anchor, AnchorStatus::Valid, now, now);
            record.valid_from = anchor.valid_from().or(Some(now));
            self.anchors.push(record);
            added += 1;
        }
        added
    }

    /// Срез записей для аудита/API.
    #[must_use]
    pub fn anchors(&self) -> Vec<(TrustAnchor, AnchorStatus, u32)> {
        self.anchors
            .iter()
            .filter_map(|record| {
                record
                    .to_anchor()
                    .map(|anchor| (anchor, record.status, record.hold_down_until))
            })
            .collect()
    }

    /// Активный набор для валидации на момент `now`.
    #[must_use]
    pub fn active_set(&self, now: u32) -> TrustAnchorSet {
        TrustAnchorSet::from_anchors(
            self.anchors
                .iter()
                .filter(|record| {
                    matches!(
                        record.status,
                        AnchorStatus::Valid | AnchorStatus::RevokePending
                    )
                })
                .filter_map(AnchorRecord::to_anchor)
                .filter(|anchor| anchor.is_active_at(now))
                .collect(),
        )
    }

    /// Применяет наблюдение валидированного `DNSKEY` RRset.
    ///
    /// Учитываются только SEP-KSK. Возвращает сводку изменений.
    pub fn observe_validated_dnskey(
        &mut self,
        zone: &Name,
        rrset: &Rrset,
        now: u32,
    ) -> UpdateReport {
        let observed = observed_keys(zone, rrset);
        let mut report = UpdateReport::default();

        // 1. Обновляем существующие записи.
        let mut retained: Vec<AnchorRecord> = Vec::with_capacity(self.anchors.len());
        for mut record in self.anchors.drain(..) {
            let Some(key) = observed.iter().find(|key| record.matches_ds(&key.ds)) else {
                // Ключ исчез из зоны: кандидат откатывается сразу, действующий
                // trust anchor удаляется только по истечении hold-down.
                match record.status {
                    AnchorStatus::AddPending => {
                        report.removed += 1;
                        continue;
                    }
                    AnchorStatus::Valid | AnchorStatus::RevokePending => {
                        let missing_since = *record.missing_since.get_or_insert(now);
                        if now.saturating_sub(missing_since) >= self.policy.revoke_hold_down {
                            report.removed += 1;
                            continue;
                        }
                        retained.push(record);
                        continue;
                    }
                }
            };
            record.last_seen = now;
            record.missing_since = None;
            match record.status {
                AnchorStatus::Valid => {
                    if key.revoked {
                        record.status = AnchorStatus::RevokePending;
                        record.hold_down_until = now.saturating_add(self.policy.revoke_hold_down);
                        report.revoked += 1;
                    }
                }
                AnchorStatus::AddPending => {
                    if key.revoked {
                        // Отзыв до завершения add hold-down — кандидат
                        // отбрасывается (RFC 5011 §4.2).
                        report.removed += 1;
                        continue;
                    }
                    if now >= record.hold_down_until {
                        record.status = AnchorStatus::Valid;
                        record.valid_from = Some(record.hold_down_until);
                        report.activated += 1;
                    }
                }
                AnchorStatus::RevokePending => {
                    if now >= record.hold_down_until {
                        report.removed += 1;
                        continue;
                    }
                }
            }
            retained.push(record);
        }

        // 2. Новые KSK становятся кандидатами.
        for key in &observed {
            if key.revoked {
                continue;
            }
            if retained.iter().any(|record| record.matches_ds(&key.ds)) {
                continue;
            }
            let Ok(anchor) = TrustAnchor::from_ds(&key.ds, None, None) else {
                continue;
            };
            let hold_down_until = now.saturating_add(self.policy.add_hold_down);
            retained.push(AnchorRecord::from_anchor(
                &anchor,
                AnchorStatus::AddPending,
                now,
                hold_down_until,
            ));
            report.added += 1;
        }

        self.anchors = retained;
        report.total = self.anchors.len();
        report
    }

    /// Продвигает время: активирует кандидатов и удаляет отозванные anchors.
    ///
    /// Нужен для работы без новых наблюдений (например, периодический tick).
    pub fn advance(&mut self, now: u32) -> UpdateReport {
        let mut report = UpdateReport::default();
        let mut retained = Vec::with_capacity(self.anchors.len());
        for mut record in self.anchors.drain(..) {
            match record.status {
                AnchorStatus::AddPending if now >= record.hold_down_until => {
                    record.status = AnchorStatus::Valid;
                    record.valid_from = Some(record.hold_down_until);
                    report.activated += 1;
                    retained.push(record);
                }
                AnchorStatus::RevokePending if now >= record.hold_down_until => {
                    report.removed += 1;
                }
                _ => retained.push(record),
            }
        }
        self.anchors = retained;
        report.total = self.anchors.len();
        report
    }

    /// Удаляет anchor вручную (административный отзыв).
    pub fn remove(&mut self, key_tag: u16, digest_type: u8) -> usize {
        let before = self.anchors.len();
        self.anchors
            .retain(|record| record.key_tag != key_tag || record.digest_type != digest_type);
        before - self.anchors.len()
    }

    /// Сериализует состояние в JSON.
    ///
    /// # Errors
    ///
    /// [`TrustUpdateError::Json`] при ошибке сериализации.
    pub fn to_json(&self) -> Result<String, TrustUpdateError> {
        let state = StateFile {
            version: STATE_VERSION,
            policy: self.policy,
            anchors: self.anchors.clone(),
        };
        serde_json::to_string_pretty(&state).map_err(|source| TrustUpdateError::Json {
            path: PathBuf::from("<memory>"),
            source,
        })
    }

    /// Загружает состояние из JSON-строки (без привязки к файлу).
    ///
    /// # Errors
    ///
    /// [`TrustUpdateError::Json`] при некорректном JSON.
    pub fn from_json(text: &str) -> Result<Self, TrustUpdateError> {
        let state: StateFile =
            serde_json::from_str(text).map_err(|source| TrustUpdateError::Json {
                path: PathBuf::from("<memory>"),
                source,
            })?;
        Ok(Self {
            path: None,
            policy: state.policy,
            anchors: state.anchors,
        })
    }

    /// Атомарно записывает состояние в файл `0600` (каталог `0700`).
    ///
    /// # Errors
    ///
    /// [`TrustUpdateError::Persist`] при ошибке записи;
    /// [`TrustUpdateError::Json`] при ошибке сериализации.
    pub fn persist(&self) -> Result<(), TrustUpdateError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let json = self.to_json()?;
        write_secret_file(
            path,
            &SecretRef::from_slice(json.as_bytes()),
            &crate::keyfile::NoopAudit,
            None,
        )
        .map_err(|source| TrustUpdateError::Persist {
            path: path.clone(),
            source,
        })
    }
}

impl Clone for TrustAnchorStore {
    fn clone(&self) -> Self {
        Self {
            path: self.path.clone(),
            policy: self.policy,
            anchors: self.anchors.clone(),
        }
    }
}

impl PartialEq for TrustAnchorStore {
    fn eq(&self, other: &Self) -> bool {
        self.policy == other.policy && self.anchors == other.anchors
    }
}

impl Eq for TrustAnchorStore {}

/// Публичный снимок trust anchor без ключевого материала.
///
/// Содержит только метаданные, пригодные для control-plane API: key tag,
/// алгоритм, digest type, состояние и сроки. Приватных ключей здесь нет.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustAnchorSnapshot {
    /// Key tag.
    pub key_tag: u16,
    /// Алгоритм DNSKEY.
    pub algorithm: u8,
    /// Тип digest (DS).
    pub digest_type: u8,
    /// Состояние в наборе.
    pub state: AnchorStatus,
    /// Начало действия.
    pub valid_from: Option<u32>,
    /// Конец действия.
    pub valid_until: Option<u32>,
    /// Окончание hold-down (для кандидатов/отозванных).
    pub hold_down_until: Option<u32>,
}

/// Провайдер anchors для резолвера: текущий набор + приём наблюдений.
///
/// Реализация обязана быть потокобезопасной; резолвер вызывает её из
/// параллельных запросов.
pub trait TrustAnchorProvider: fmt::Debug + Send + Sync {
    /// Активные DS для зоны `zone` на момент `now`.
    fn anchors(&self, zone: &Name, now: u32) -> Vec<DsData>;
    /// Наблюдение валидированного `DNSKEY` RRset зоны `zone`.
    fn observe_validated_dnskey(&self, zone: &Name, rrset: &Rrset, now: u32);
    /// Снимок anchors без секретов (для control-plane API).
    fn snapshot(&self) -> Vec<TrustAnchorSnapshot> {
        Vec::new()
    }
    /// Перечитывает состояние с диска.
    ///
    /// Провайдеры без персистентного состояния возвращают `Ok(0)`.
    ///
    /// # Errors
    ///
    /// [`TrustUpdateError`] при ошибке чтения или проверки прав файла.
    fn reload(&self, _now: u32) -> Result<usize, TrustUpdateError> {
        Ok(0)
    }
}

/// Потокобезопасная обёртка над [`TrustAnchorStore`].
#[derive(Debug)]
pub struct SharedTrustAnchors {
    store: Mutex<TrustAnchorStore>,
}

impl SharedTrustAnchors {
    /// Создаёт общий набор.
    #[must_use]
    pub fn new(store: TrustAnchorStore) -> Self {
        Self {
            store: Mutex::new(store),
        }
    }

    /// Выполняет операцию под блокировкой.
    ///
    /// # Errors
    ///
    /// Ошибка операции (например, записи состояния).
    pub fn with_store<T>(&self, operation: impl FnOnce(&mut TrustAnchorStore) -> T) -> T {
        let mut guard = self
            .store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        operation(&mut guard)
    }

    /// Снимок состояния (для API/тестов).
    #[must_use]
    pub fn snapshot(&self) -> TrustAnchorStore {
        self.with_store(|store| store.clone())
    }

    fn reload_from_disk(&self, now: u32) -> Result<usize, TrustUpdateError> {
        self.with_store(|store| {
            let Some(path) = store.path().map(Path::to_path_buf) else {
                return Ok(store.anchors().len());
            };
            let policy = store.policy();
            let mut fresh = TrustAnchorStore::open(path, policy)?;
            fresh.advance(now);
            *store = fresh;
            Ok(store.anchors().len())
        })
    }
}

impl TrustAnchorProvider for SharedTrustAnchors {
    fn anchors(&self, zone: &Name, now: u32) -> Vec<DsData> {
        self.with_store(|store| {
            store
                .active_set(now)
                .to_ds_set(now, DsPolicy::strict())
                .unwrap_or_default()
        })
        .into_iter()
        // Store хранит anchors независимо от зоны; для резолвера это
        // root-only набор, поэтому отдаём его только для корня.
        .filter(|_| zone == &Name::root())
        .collect()
    }

    fn observe_validated_dnskey(&self, zone: &Name, rrset: &Rrset, now: u32) {
        if zone != &Name::root() {
            return;
        }
        self.with_store(|store| {
            let report = store.observe_validated_dnskey(zone, rrset, now);
            if report.changed() {
                let _ = store.persist();
            }
        });
    }

    fn snapshot(&self) -> Vec<TrustAnchorSnapshot> {
        self.with_store(|store| {
            store
                .anchors()
                .into_iter()
                .map(|(anchor, state, hold_down_until)| TrustAnchorSnapshot {
                    key_tag: anchor.key_tag(),
                    algorithm: anchor.algorithm(),
                    digest_type: anchor.digest_type(),
                    state,
                    valid_from: anchor.valid_from(),
                    valid_until: anchor.valid_until(),
                    hold_down_until: Some(hold_down_until),
                })
                .collect()
        })
    }

    fn reload(&self, now: u32) -> Result<usize, TrustUpdateError> {
        self.reload_from_disk(now)
    }
}

fn record_matches_anchor(record: &AnchorRecord, anchor: &TrustAnchor) -> bool {
    record.key_tag == anchor.key_tag()
        && record.algorithm == anchor.algorithm()
        && record.digest_type == anchor.digest_type()
        && record.digest == encode_hex(anchor.digest())
}

fn observed_keys(zone: &Name, rrset: &Rrset) -> Vec<ObservedKey> {
    if rrset.rr_type() != pulse_dns::Rtype::DNSKEY {
        return Vec::new();
    }
    let mut observed = Vec::new();
    for rdata in rrset.rdatas() {
        let Rdata::Dnskey(key) = rdata else {
            continue;
        };
        if key.flags() & crate::key::DNSKEY_FLAG_SEP == 0 {
            continue;
        }
        let revoked = key.flags() & DNSKEY_FLAG_REVOKE != 0;
        // RFC 5011 §2.5: REVOKE меняет flags/key tag, но доверенный материал
        // тот же. DS для сопоставления считается без REVOKE-бита.
        let plain = if revoked {
            let Ok(plain) = pulse_dns::DnskeyData::new(
                key.flags() & !DNSKEY_FLAG_REVOKE,
                key.protocol(),
                key.algorithm(),
                key.public_key().to_vec(),
            ) else {
                continue;
            };
            plain
        } else {
            key.clone()
        };
        let Ok(ds) = ds_from_dnskey(zone, &plain, DIGEST_SHA256, DsPolicy::strict()) else {
            continue;
        };
        observed.push(ObservedKey { ds, revoked });
    }
    observed
}

fn check_permissions(path: &Path) -> Result<(), TrustUpdateError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)
        .map_err(|source| TrustUpdateError::Io {
            path: path.to_path_buf(),
            source,
        })?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o077 != 0 {
        return Err(TrustUpdateError::InsecurePermissions {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let high = HEX.get(usize::from(byte >> 4)).copied().unwrap_or(b'0');
        let low = HEX.get(usize::from(byte & 0x0F)).copied().unwrap_or(b'0');
        out.push(char::from(high));
        out.push(char::from(low));
    }
    out
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut index = 0;
    while index < bytes.len() {
        let high = hex_value(*bytes.get(index)?)?;
        let low = hex_value(*bytes.get(index + 1)?)?;
        out.push((high << 4) | low);
        index += 2;
    }
    Some(out)
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::Algorithm;
    use crate::key::PrivateKey;
    use pulse_dns::{Rclass, Rtype, Ttl};

    fn rrset(keys: &[(&PrivateKey, u16)]) -> Rrset {
        let rdatas: Vec<Rdata> = keys
            .iter()
            .map(|(key, flags)| Rdata::Dnskey(key.dnskey(*flags).expect("dnskey")))
            .collect();
        Rrset::new(
            Name::root(),
            Rtype::DNSKEY,
            Rclass::IN,
            Ttl::new(3600).expect("ttl"),
            rdatas,
        )
        .expect("rrset")
    }

    fn policy() -> TrustAnchorPolicy {
        TrustAnchorPolicy::new(100, 200)
    }

    #[test]
    fn add_hold_down_then_activate_is_idempotent() {
        let key = PrivateKey::generate(Algorithm::ED25519).expect("key");
        let observed = rrset(&[(&key, 257)]);
        let mut store = TrustAnchorStore::with_policy(policy());
        let first = store.observe_validated_dnskey(&Name::root(), &observed, 1_000);
        assert_eq!(first.added, 1);
        // Повторное наблюдение не продлевает hold-down.
        let second = store.observe_validated_dnskey(&Name::root(), &observed, 1_050);
        assert!(!second.changed());
        let pending = store.anchors();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].1, AnchorStatus::AddPending);
        assert_eq!(pending[0].2, 1_100);
        // До hold-down anchor не активен.
        assert!(store.active_set(1_099).is_empty());
        let third = store.observe_validated_dnskey(&Name::root(), &observed, 1_100);
        assert_eq!(third.activated, 1);
        let active = store.active_set(1_100);
        assert_eq!(active.len(), 1);
        assert_eq!(active.anchors()[0].valid_from(), Some(1_100));
    }

    #[test]
    fn pending_candidate_is_rolled_back_when_missing() {
        let key = PrivateKey::generate(Algorithm::ED25519).expect("key");
        let mut store = TrustAnchorStore::with_policy(policy());
        store.observe_validated_dnskey(&Name::root(), &rrset(&[(&key, 257)]), 0);
        assert_eq!(store.anchors().len(), 1);
        let other = PrivateKey::generate(Algorithm::ED25519).expect("other");
        let report = store.observe_validated_dnskey(&Name::root(), &rrset(&[(&other, 257)]), 10);
        assert_eq!(report.removed, 1, "pending candidate must be rolled back");
        assert_eq!(store.anchors().len(), 1);
    }

    #[test]
    fn revoke_hold_down_removes_anchor() {
        let key = PrivateKey::generate(Algorithm::ED25519).expect("key");
        let mut store = TrustAnchorStore::with_policy(policy());
        store.seed(&builtin_anchor(&key), 0);
        let revoked = rrset(&[(&key, 0x0101 | DNSKEY_FLAG_REVOKE)]);
        let report = store.observe_validated_dnskey(&Name::root(), &revoked, 1_000);
        assert_eq!(report.revoked, 1);
        // В течение hold-down anchor ещё используется.
        assert_eq!(store.active_set(1_100).len(), 1);
        store.advance(1_200);
        assert!(store.active_set(1_200).is_empty());
    }

    #[test]
    fn revoked_pending_key_is_discarded() {
        let key = PrivateKey::generate(Algorithm::ED25519).expect("key");
        let mut store = TrustAnchorStore::with_policy(policy());
        store.observe_validated_dnskey(&Name::root(), &rrset(&[(&key, 257)]), 0);
        let report = store.observe_validated_dnskey(
            &Name::root(),
            &rrset(&[(&key, 0x0101 | DNSKEY_FLAG_REVOKE)]),
            40,
        );
        assert_eq!(report.removed, 1);
        assert_eq!(store.anchors().len(), 0);
    }

    #[test]
    fn state_json_roundtrip_and_seed_is_stable() {
        let key = PrivateKey::generate(Algorithm::ED25519).expect("key");
        let mut store = TrustAnchorStore::with_policy(policy());
        store.observe_validated_dnskey(&Name::root(), &rrset(&[(&key, 257)]), 5);
        let json = store.to_json().expect("json");
        let mut loaded = TrustAnchorStore::from_json(&json).expect("parse");
        assert_eq!(loaded, store);
        let anchors = store.active_set(0);
        assert!(anchors.is_empty());
        loaded.seed(&builtin_anchor(&key), 0);
        assert_eq!(loaded.anchors().len(), 1);
        // seed не дублирует уже известный anchor.
        loaded.seed(&builtin_anchor(&key), 20);
        assert_eq!(loaded.anchors().len(), 1);
    }

    #[test]
    fn persistent_store_writes_0600() {
        let directory = tempfile::tempdir().expect("dir");
        let path = directory.path().join("state/anchors.json");
        let key = PrivateKey::generate(Algorithm::ED25519).expect("key");
        let mut store = TrustAnchorStore::open(&path, policy()).expect("open");
        store.observe_validated_dnskey(&Name::root(), &rrset(&[(&key, 257)]), 1);
        store.persist().expect("persist");
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777
        };
        assert_eq!(mode, 0o600);
        let reopened = TrustAnchorStore::open(&path, policy()).expect("reopen");
        assert_eq!(reopened.anchors().len(), 1);
    }

    fn builtin_anchor(key: &PrivateKey) -> Vec<TrustAnchor> {
        let dnskey = key.dnskey(257).expect("dnskey");
        let ds =
            ds_from_dnskey(&Name::root(), &dnskey, DIGEST_SHA256, DsPolicy::strict()).expect("ds");
        vec![TrustAnchor::from_ds(&ds, Some(0), None).expect("anchor")]
    }
}
