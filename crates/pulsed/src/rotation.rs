//! Автоматическая ротация DNSSEC-ключей (RFC 7583, pre-publish/double-sign).
//!
//! Движок хранит состояние ключей зоны в JSON-файле (`0600`, атомарная
//! запись) и приватные ключи в каталоге `0700`. Жизненный цикл ключа:
//!
//! 1. [`KeyStage::PrePublish`] — DNSKEY опубликован, RRSIG не создаются;
//! 2. [`KeyStage::DoubleSign`] — новый и старый ключи подписывают зону;
//! 3. [`KeyStage::Active`] — новый ключ единственный подписант;
//! 4. [`KeyStage::Retired`] — старый DNSKEY ещё публикуется (propagation),
//!    но не подписывает; после `retire` секунд удаляется вместе с файлом.
//!
//! Ротация запускается по возрасту активного ключа и продвигается вызовами
//! [`RotationEngine::advance`] (старт сервера, `/sign`, периодический tick).
//!
//! # Пример
//!
//! ```
//! use std::time::{SystemTime, UNIX_EPOCH};
//!
//! use pulse_dns::{Name, Rclass, Rdata, Rrset, Rtype, Serial, SoaData, Ttl};
//! use pulse_dnssec::{Algorithm, NoopAudit, PrivateKey, write_key_pair};
//! use pulse_server::dnssec::KeyRole;
//! use pulsed::rotation::{InitialKey, RotationEngine, RotationPolicy};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let directory = tempfile::tempdir()?;
//! let origin = Name::parse("example.com")?;
//! let now = u32::try_from(
//!     SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
//! )?;
//! let ksk = PrivateKey::generate(Algorithm::ED25519)?;
//! let zsk = PrivateKey::generate(Algorithm::ED25519)?;
//! let key_dir = directory.path().join("keys");
//! let ksk_paths = write_key_pair(&key_dir, &origin, &ksk, 257, &NoopAudit)?;
//! let zsk_paths = write_key_pair(&key_dir, &origin, &zsk, 256, &NoopAudit)?;
//! let initial = vec![
//!     InitialKey::new(KeyRole::Ksk, 257, ksk_paths.private),
//!     InitialKey::new(KeyRole::Zsk, 256, zsk_paths.private),
//! ];
//! let mut engine = RotationEngine::open(
//!     &origin,
//!     key_dir.clone(),
//!     key_dir.join("rotation.json"),
//!     RotationPolicy::default(),
//!     86_400,
//!     300,
//!     &initial,
//!     now,
//! )?;
//! engine.advance(now)?;
//! let signer = engine.signer()?;
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
//! let signed = signer.sign_zone(&origin, &[soa], now)?;
//! assert!(signed.rrsets.iter().any(|rrset| rrset.rr_type() == Rtype::DNSKEY));
//! # Ok(())
//! # }
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use pulse_dns::Name;
use pulse_dnssec::{
    Algorithm, KeyError, KeyFileError, NoopAudit, PrivateKey, key_tag, keyfile, write_key_pair,
};
use pulse_server::dnssec::{KeyRole, ZoneSigner, ZoneSignerError, ZoneSigningKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const STATE_VERSION: u32 = 1;

/// Политика ротации ключей.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationPolicy {
    /// Алгоритм новых ключей.
    pub algorithm: Algorithm,
    /// Срок жизни ZSK в секундах.
    pub zsk_lifetime: u32,
    /// Срок жизни KSK в секундах.
    pub ksk_lifetime: u32,
    /// Длительность pre-publish фазы.
    pub pre_publish: u32,
    /// Длительность double-sign фазы.
    pub double_sign: u32,
    /// Сколько секунд retired-ключ остаётся опубликованным.
    pub retire: u32,
    /// Интервал фоновой проверки ротации.
    pub tick: u32,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            algorithm: Algorithm::ED25519,
            zsk_lifetime: 90 * 86_400,
            ksk_lifetime: 365 * 86_400,
            pre_publish: 86_400,
            double_sign: 86_400,
            retire: 7 * 86_400,
            tick: 300,
        }
    }
}

impl RotationPolicy {
    /// Проверяет, что фазы укладываются в срок жизни ключа.
    ///
    /// # Errors
    ///
    /// [`RotationError::InvalidPolicy`] при нулевых/противоречивых значениях.
    pub fn validate(&self) -> Result<(), RotationError> {
        if self.pre_publish == 0 || self.double_sign == 0 || self.retire == 0 || self.tick == 0 {
            return Err(RotationError::InvalidPolicy {
                reason: "pre_publish, double_sign, retire and tick must be non-zero",
            });
        }
        let window = u64::from(self.pre_publish) + u64::from(self.double_sign);
        for lifetime in [self.zsk_lifetime, self.ksk_lifetime] {
            if u64::from(lifetime) <= window {
                return Err(RotationError::InvalidPolicy {
                    reason: "lifetime must exceed pre_publish + double_sign",
                });
            }
        }
        Ok(())
    }

    /// Срок жизни ключа роли.
    #[must_use]
    pub const fn lifetime(self, role: KeyRole) -> u32 {
        match role {
            KeyRole::Ksk => self.ksk_lifetime,
            KeyRole::Zsk | KeyRole::Csk => self.zsk_lifetime,
        }
    }
}

/// Стадия жизненного цикла ключа.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStage {
    /// DNSKEY опубликован, подписи нет.
    PrePublish,
    /// Ключ подписывает одновременно со старым.
    DoubleSign,
    /// Единственный активный подписант роли.
    Active,
    /// DNSKEY ещё опубликован, подписи нет; ждёт удаления.
    Retired,
}

impl KeyStage {
    /// Строковое имя для API/логов.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PrePublish => "pre_publish",
            Self::DoubleSign => "double_sign",
            Self::Active => "active",
            Self::Retired => "retired",
        }
    }

    /// Участвует ли ключ в подписи.
    #[must_use]
    pub const fn signs(self) -> bool {
        matches!(self, Self::DoubleSign | Self::Active)
    }
}

/// Начальный ключ для bootstrap состояния.
#[derive(Debug, Clone)]
pub struct InitialKey {
    /// Роль.
    pub role: KeyRole,
    /// DNSKEY flags.
    pub flags: u16,
    /// Путь к приватному ключу.
    pub private_path: PathBuf,
}

impl InitialKey {
    /// Создаёт описание начального ключа.
    #[must_use]
    pub fn new(role: KeyRole, flags: u16, private_path: impl Into<PathBuf>) -> Self {
        Self {
            role,
            flags,
            private_path: private_path.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyRecord {
    role: String,
    key_tag: u16,
    flags: u16,
    created_at: u32,
    #[serde(default)]
    active_since: Option<u32>,
    stage: KeyStage,
    pre_publish_until: u32,
    activate_at: u32,
    retire_at: Option<u32>,
    private_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StateFile {
    version: u32,
    origin: String,
    keys: Vec<KeyRecord>,
}

/// Сводка изменений, применённых [`RotationEngine::advance`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RotationReport {
    /// Создано новых ключей (bootstrap/repair).
    pub created: usize,
    /// Ключей переведено в pre-publish.
    pub pre_published: usize,
    /// Ключей переведено в double-sign.
    pub double_signed: usize,
    /// Ключей активировано.
    pub activated: usize,
    /// Ключей отправлено в retire.
    pub retired: usize,
    /// Ключей удалено после propagation.
    pub removed: usize,
}

impl RotationReport {
    /// Были ли изменения.
    #[must_use]
    pub const fn changed(self) -> bool {
        self.created > 0
            || self.pre_published > 0
            || self.double_signed > 0
            || self.activated > 0
            || self.retired > 0
            || self.removed > 0
    }
}

/// Публичное состояние ключа для API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyStatus {
    /// Key tag.
    pub key_tag: u16,
    /// Роль (`ksk`/`zsk`).
    pub role: String,
    /// Стадия.
    pub stage: KeyStage,
    /// Время создания.
    pub created_at: u32,
    /// Ближайший переход (если есть).
    pub next_transition: Option<u32>,
}

/// Снимок состояния ротации зоны.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationStatus {
    /// Ключи.
    pub keys: Vec<KeyStatus>,
    /// Ближайшее событие.
    pub next_event_at: Option<u32>,
}

/// Ошибка движка ротации.
#[derive(Debug, Error)]
pub enum RotationError {
    /// Некорректная политика.
    #[error("invalid key rotation policy: {reason}")]
    InvalidPolicy {
        /// Причина.
        reason: &'static str,
    },
    /// Состояние относится к другой зоне.
    #[error("rotation state belongs to zone {actual}, expected {expected}")]
    OriginMismatch {
        /// Зона из файла.
        actual: String,
        /// Ожидаемая зона.
        expected: String,
    },
    /// Нет ключа обязательной роли.
    #[error("rotation requires exactly one {role} key, found {count}")]
    MissingRole {
        /// Роль.
        role: &'static str,
        /// Найдено ключей.
        count: usize,
    },
    /// Состояние повреждено или пусто.
    #[error("invalid key rotation state {path}: {reason}")]
    InvalidState {
        /// Путь.
        path: PathBuf,
        /// Причина.
        reason: String,
    },
    /// Ошибка файла состояния.
    #[error("key rotation state {path}: {source}")]
    Io {
        /// Путь.
        path: PathBuf,
        /// Причина.
        #[source]
        source: std::io::Error,
    },
    /// Ошибка записи состояния.
    #[error("cannot persist key rotation state {path}: {source}")]
    Persist {
        /// Путь.
        path: PathBuf,
        /// Причина.
        #[source]
        source: KeyFileError,
    },
    /// Ошибка генерации/чтения ключа.
    #[error("key rotation key error: {source}")]
    Key {
        /// Причина.
        #[source]
        source: KeyError,
    },
    /// Ошибка файла ключа.
    #[error("key rotation key file {path}: {source}")]
    KeyFile {
        /// Путь.
        path: PathBuf,
        /// Причина.
        #[source]
        source: KeyFileError,
    },
    /// Ошибка построения подписанта.
    #[error("key rotation signer: {source}")]
    Signer {
        /// Причина.
        #[source]
        source: ZoneSignerError,
    },
}

/// Движок ротации одной зоны.
#[derive(Debug)]
pub struct RotationEngine {
    origin: Name,
    key_dir: PathBuf,
    state_path: PathBuf,
    policy: RotationPolicy,
    validity: u32,
    inception_skew: u32,
    state: StateFile,
}

impl RotationEngine {
    /// Открывает движок: загружает состояние или создаёт его из начальных
    /// ключей (по одному KSK и ZSK).
    ///
    /// # Errors
    ///
    /// [`RotationError`] при некорректной политике, состоянии или наборе
    /// начальных ключей.
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        origin: &Name,
        key_dir: PathBuf,
        state_path: PathBuf,
        policy: RotationPolicy,
        validity: u32,
        inception_skew: u32,
        initial: &[InitialKey],
        now: u32,
    ) -> Result<Self, RotationError> {
        policy.validate()?;
        if validity == 0 {
            return Err(RotationError::InvalidPolicy {
                reason: "signature validity must be non-zero",
            });
        }
        let state = if state_path.exists() {
            let text = fs::read_to_string(&state_path).map_err(|source| RotationError::Io {
                path: state_path.clone(),
                source,
            })?;
            let state: StateFile =
                serde_json::from_str(&text).map_err(|source| RotationError::InvalidState {
                    path: state_path.clone(),
                    reason: source.to_string(),
                })?;
            if state.origin != origin.to_string() {
                return Err(RotationError::OriginMismatch {
                    actual: state.origin,
                    expected: origin.to_string(),
                });
            }
            state
        } else {
            Self::bootstrap(origin, initial, now)?
        };
        let engine = Self {
            origin: origin.clone(),
            key_dir,
            state_path,
            policy,
            validity,
            inception_skew,
            state,
        };
        engine.persist()?;
        Ok(engine)
    }

    fn bootstrap(
        origin: &Name,
        initial: &[InitialKey],
        now: u32,
    ) -> Result<StateFile, RotationError> {
        let mut keys = Vec::with_capacity(initial.len());
        for (role, name) in [(KeyRole::Ksk, "KSK"), (KeyRole::Zsk, "ZSK")] {
            let matching: Vec<&InitialKey> =
                initial.iter().filter(|key| key.role == role).collect();
            let [key] = matching.as_slice() else {
                return Err(RotationError::MissingRole {
                    role: name,
                    count: matching.len(),
                });
            };
            let private = keyfile::read_private_key_file(&key.private_path).map_err(|source| {
                RotationError::KeyFile {
                    path: key.private_path.clone(),
                    source,
                }
            })?;
            let dnskey = private
                .dnskey(key.flags)
                .map_err(|source| RotationError::Key { source })?;
            keys.push(KeyRecord {
                role: role.as_str().to_owned(),
                key_tag: key_tag(&dnskey),
                flags: key.flags,
                created_at: now,
                active_since: Some(now),
                stage: KeyStage::Active,
                pre_publish_until: now,
                activate_at: now,
                retire_at: None,
                private_path: key.private_path.clone(),
            });
        }
        Ok(StateFile {
            version: STATE_VERSION,
            origin: origin.to_string(),
            keys,
        })
    }

    /// Зона движка.
    #[must_use]
    pub fn origin(&self) -> &Name {
        &self.origin
    }

    /// Путь файла состояния.
    #[must_use]
    pub fn state_path(&self) -> &Path {
        &self.state_path
    }

    /// Политика.
    #[must_use]
    pub const fn policy(&self) -> RotationPolicy {
        self.policy
    }

    /// Продвигает состояние по времени `now`.
    ///
    /// # Errors
    ///
    /// [`RotationError`] при ошибке генерации/записи ключа или состояния.
    #[allow(clippy::too_many_lines)]
    pub fn advance(&mut self, now: u32) -> Result<RotationReport, RotationError> {
        let mut report = RotationReport::default();

        // 1. Удаляем retired-ключи после propagation.
        let mut retained = Vec::with_capacity(self.state.keys.len());
        for record in self.state.keys.drain(..) {
            if record.stage == KeyStage::Retired && record.retire_at.is_some_and(|at| now >= at) {
                let _ = fs::remove_file(&record.private_path);
                let _ = fs::remove_file(record.private_path.with_extension("key"));
                report.removed += 1;
                continue;
            }
            retained.push(record);
        }
        self.state.keys = retained;

        // 2. Продвигаем фазы до устойчивого состояния.
        for _ in 0..8 {
            let mut changed = false;

            for record in &mut self.state.keys {
                if record.stage == KeyStage::PrePublish && now >= record.pre_publish_until {
                    record.stage = KeyStage::DoubleSign;
                    report.double_signed += 1;
                    changed = true;
                }
            }

            let ready: Vec<(usize, KeyRole)> = self
                .state
                .keys
                .iter()
                .enumerate()
                .filter(|(_, record)| {
                    record.stage == KeyStage::DoubleSign && now >= record.activate_at
                })
                .filter_map(|(index, record)| record.role().map(|role| (index, role)))
                .collect();
            for (index, role) in ready {
                if let Some(record) = self.state.keys.get_mut(index) {
                    record.stage = KeyStage::Active;
                    record.active_since = Some(now);
                }
                report.activated += 1;
                changed = true;
                for (other_index, other) in self.state.keys.iter_mut().enumerate() {
                    if other_index != index
                        && other.role() == Some(role)
                        && other.stage == KeyStage::Active
                    {
                        other.stage = KeyStage::Retired;
                        other.retire_at = Some(now.saturating_add(self.policy.retire));
                        report.retired += 1;
                    }
                }
            }

            for role in [KeyRole::Ksk, KeyRole::Zsk] {
                if !self
                    .state
                    .keys
                    .iter()
                    .any(|record| record.role() == Some(role) && record.stage == KeyStage::Active)
                {
                    self.state
                        .keys
                        .push(self.generate(role, now, KeyStage::Active, now, now)?);
                    if let Some(record) = self
                        .state
                        .keys
                        .last_mut()
                        .filter(|record| record.role() == Some(role))
                    {
                        record.active_since = Some(now);
                    }
                    report.created += 1;
                    changed = true;
                }
            }

            for role in [KeyRole::Ksk, KeyRole::Zsk] {
                let has_successor = self.state.keys.iter().any(|record| {
                    record.role() == Some(role)
                        && matches!(record.stage, KeyStage::PrePublish | KeyStage::DoubleSign)
                });
                if has_successor {
                    continue;
                }
                let Some(active) =
                    self.state.keys.iter().find(|record| {
                        record.role() == Some(role) && record.stage == KeyStage::Active
                    })
                else {
                    continue;
                };
                let lifetime = u64::from(self.policy.lifetime(role));
                let window =
                    u64::from(self.policy.pre_publish) + u64::from(self.policy.double_sign);
                let active_since = active.active_since.unwrap_or(active.created_at);
                let start = u64::from(active_since) + lifetime.saturating_sub(window);
                if u64::from(now) < start {
                    continue;
                }
                let activate_at =
                    u32::try_from(u64::from(active_since) + lifetime).unwrap_or(u32::MAX);
                let pre_publish_until = activate_at.saturating_sub(self.policy.double_sign);
                let stage = if now < pre_publish_until {
                    KeyStage::PrePublish
                } else {
                    KeyStage::DoubleSign
                };
                self.state.keys.push(self.generate(
                    role,
                    now,
                    stage,
                    pre_publish_until,
                    activate_at,
                )?);
                report.pre_published += 1;
                changed = true;
            }

            if !changed {
                break;
            }
        }

        if report.changed() {
            self.persist()?;
        }
        Ok(report)
    }

    fn generate(
        &self,
        role: KeyRole,
        now: u32,
        stage: KeyStage,
        pre_publish_until: u32,
        activate_at: u32,
    ) -> Result<KeyRecord, RotationError> {
        let key = PrivateKey::generate(self.policy.algorithm)
            .map_err(|source| RotationError::Key { source })?;
        let flags = role.flags();
        let paths = write_key_pair(&self.key_dir, &self.origin, &key, flags, &NoopAudit).map_err(
            |source| RotationError::KeyFile {
                path: self.key_dir.clone(),
                source,
            },
        )?;
        let dnskey = key
            .dnskey(flags)
            .map_err(|source| RotationError::Key { source })?;
        Ok(KeyRecord {
            role: role.as_str().to_owned(),
            key_tag: key_tag(&dnskey),
            flags,
            created_at: now,
            active_since: None,
            stage,
            pre_publish_until,
            activate_at,
            retire_at: None,
            private_path: paths.private,
        })
    }

    /// Строит подписант из текущего состояния.
    ///
    /// # Errors
    ///
    /// [`RotationError`] при чтении ключей или построении [`ZoneSigner`].
    pub fn signer(&self) -> Result<ZoneSigner, RotationError> {
        let mut keys = Vec::with_capacity(self.state.keys.len());
        let mut ordered: Vec<&KeyRecord> = self.state.keys.iter().collect();
        ordered.sort_by_key(|record| (record.role().map(role_order), stage_order(record.stage)));
        for record in ordered {
            let Some(role) = record.role() else {
                continue;
            };
            let private =
                keyfile::read_private_key_file(&record.private_path).map_err(|source| {
                    RotationError::KeyFile {
                        path: record.private_path.clone(),
                        source,
                    }
                })?;
            let mut key = ZoneSigningKey::with_flags(private, role, record.flags)
                .map_err(|source| RotationError::Signer { source })?;
            if !record.stage.signs() {
                key = key.publish_only();
            }
            keys.push(key);
        }
        ZoneSigner::new(keys, self.validity, self.inception_skew)
            .map_err(|source| RotationError::Signer { source })
    }

    /// Снимок состояния для `/keys`.
    #[must_use]
    pub fn status(&self) -> RotationStatus {
        let mut keys: Vec<KeyStatus> = self
            .state
            .keys
            .iter()
            .map(|record| KeyStatus {
                key_tag: record.key_tag,
                role: record.role.clone(),
                stage: record.stage,
                created_at: record.created_at,
                next_transition: next_transition(record, self.policy),
            })
            .collect();
        keys.sort_by_key(|key| (key.role.clone(), key.stage));
        let next_event_at = keys.iter().filter_map(|key| key.next_transition).min();
        RotationStatus {
            keys,
            next_event_at,
        }
    }
}

impl KeyRecord {
    fn role(&self) -> Option<KeyRole> {
        match self.role.as_str() {
            "ksk" => Some(KeyRole::Ksk),
            "zsk" => Some(KeyRole::Zsk),
            "csk" => Some(KeyRole::Csk),
            _ => None,
        }
    }
}

fn next_transition(record: &KeyRecord, policy: RotationPolicy) -> Option<u32> {
    match record.stage {
        KeyStage::PrePublish => Some(record.pre_publish_until),
        KeyStage::DoubleSign => Some(record.activate_at),
        KeyStage::Retired => record.retire_at,
        KeyStage::Active => {
            let role = record.role()?;
            let active_since = record.active_since.unwrap_or(record.created_at);
            let window = u64::from(policy.pre_publish) + u64::from(policy.double_sign);
            let start =
                u64::from(active_since) + u64::from(policy.lifetime(role)).saturating_sub(window);
            Some(u32::try_from(start).unwrap_or(u32::MAX))
        }
    }
}

const fn role_order(role: KeyRole) -> u8 {
    match role {
        KeyRole::Ksk => 0,
        KeyRole::Csk => 1,
        KeyRole::Zsk => 2,
    }
}

const fn stage_order(stage: KeyStage) -> u8 {
    match stage {
        KeyStage::Active => 0,
        KeyStage::DoubleSign => 1,
        KeyStage::PrePublish => 2,
        KeyStage::Retired => 3,
    }
}

impl RotationEngine {
    fn persist(&self) -> Result<(), RotationError> {
        let json = serde_json::to_vec_pretty(&self.state).map_err(|source| {
            RotationError::InvalidState {
                path: self.state_path.clone(),
                reason: source.to_string(),
            }
        })?;
        keyfile::write_secret_file(
            &self.state_path,
            &pulse_dnssec::SecretRef::from_slice(&json),
            &NoopAudit,
            None,
        )
        .map_err(|source| RotationError::Persist {
            path: self.state_path.clone(),
            source,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pulse_dns::{Rclass, Rdata, Rrset, Rtype, Serial, SoaData, Ttl};
    use pulse_dnssec::{VerifyOptions, verify_rrsig};
    use pulse_server::dnssec::{DenialPolicy, KeyRole};

    struct Fixture {
        directory: tempfile::TempDir,
        origin: Name,
        engine: RotationEngine,
    }

    fn policy() -> RotationPolicy {
        RotationPolicy {
            algorithm: Algorithm::ED25519,
            zsk_lifetime: 1_000,
            ksk_lifetime: 1_000,
            pre_publish: 100,
            double_sign: 100,
            retire: 100,
            tick: 10,
        }
    }

    fn fixture(now: u32) -> Fixture {
        let directory = tempfile::tempdir().expect("dir");
        let origin = Name::parse("example.com").expect("origin");
        let key_dir = directory.path().join("keys");
        let ksk = PrivateKey::generate(Algorithm::ED25519).expect("ksk");
        let zsk = PrivateKey::generate(Algorithm::ED25519).expect("zsk");
        let ksk_paths =
            write_key_pair(&key_dir, &origin, &ksk, 257, &NoopAudit).expect("write ksk");
        let zsk_paths =
            write_key_pair(&key_dir, &origin, &zsk, 256, &NoopAudit).expect("write zsk");
        let initial = vec![
            InitialKey::new(KeyRole::Ksk, 257, ksk_paths.private),
            InitialKey::new(KeyRole::Zsk, 256, zsk_paths.private),
        ];
        let engine = RotationEngine::open(
            &origin,
            key_dir,
            directory.path().join("state/rotation.json"),
            policy(),
            86_400,
            300,
            &initial,
            now,
        )
        .expect("open");
        Fixture {
            directory,
            origin,
            engine,
        }
    }

    fn soa(origin: &Name) -> Rrset {
        Rrset::new(
            origin.clone(),
            Rtype::SOA,
            Rclass::IN,
            Ttl::new(3600).expect("ttl"),
            [Rdata::Soa(SoaData::new(
                Name::parse("ns1.example.com").expect("ns"),
                Name::parse("hostmaster.example.com").expect("hm"),
                Serial::new(1),
                3600,
                600,
                604_800,
                300,
            ))],
        )
        .expect("soa")
    }

    fn verify_stage(engine: &RotationEngine, origin: &Name, now: u32) -> Vec<u16> {
        let signer = engine.signer().expect("signer");
        let output = signer
            .sign_zone_with(origin, &[soa(origin)], now, &DenialPolicy::Nsec)
            .expect("sign");
        let dnskeys = &output.dnskeys;
        let options = VerifyOptions::new(now);
        for covered in [Rtype::DNSKEY, Rtype::SOA] {
            let rrset = output
                .rrsets
                .iter()
                .find(|rrset| rrset.owner() == origin && rrset.rr_type() == covered)
                .expect("rrset");
            let signatures: Vec<_> = output
                .rrsets
                .iter()
                .filter(|rrset| rrset.owner() == origin && rrset.rr_type() == Rtype::RRSIG)
                .flat_map(Rrset::rdatas)
                .filter_map(|rdata| match rdata {
                    Rdata::Rrsig(signature) if signature.type_covered() == covered => {
                        Some(signature.clone())
                    }
                    _ => None,
                })
                .collect();
            assert!(!signatures.is_empty(), "no RRSIG for {covered}");
            assert!(
                signatures.iter().any(|signature| dnskeys
                    .iter()
                    .any(|key| verify_rrsig(rrset, signature, key, &options).is_ok())),
                "no valid signature for {covered}"
            );
        }
        dnskeys.iter().map(key_tag).collect()
    }

    #[test]
    fn lifecycle_pre_publish_double_sign_switch_retire() {
        let mut fixture = fixture(1_000);
        let origin = fixture.origin.clone();
        assert_eq!(fixture.engine.status().keys.len(), 2);
        assert!(
            fixture
                .engine
                .status()
                .keys
                .iter()
                .all(|key| key.stage == KeyStage::Active)
        );
        verify_stage(&fixture.engine, &origin, 1_000);

        // Pre-publish: новые ключи опубликованы, но не подписывают.
        let report = fixture.engine.advance(1_800).expect("advance");
        assert_eq!(report.pre_published, 2);
        let status = fixture.engine.status();
        assert_eq!(status.keys.len(), 4);
        assert_eq!(
            status
                .keys
                .iter()
                .filter(|key| key.stage == KeyStage::PrePublish)
                .count(),
            2
        );
        verify_stage(&fixture.engine, &origin, 1_800);

        // Double-sign: новый и старый ключи подписывают.
        fixture.engine.advance(1_900).expect("advance");
        assert_eq!(
            fixture
                .engine
                .status()
                .keys
                .iter()
                .filter(|key| key.stage == KeyStage::DoubleSign)
                .count(),
            2
        );
        let tags = verify_stage(&fixture.engine, &origin, 1_900);
        assert_eq!(tags.len(), 4);

        // Switch: новый ключ активен, старый retired (публикуется).
        fixture.engine.advance(2_000).expect("advance");
        let status = fixture.engine.status();
        assert_eq!(
            status
                .keys
                .iter()
                .filter(|key| key.stage == KeyStage::Active)
                .count(),
            2
        );
        assert_eq!(
            status
                .keys
                .iter()
                .filter(|key| key.stage == KeyStage::Retired)
                .count(),
            2
        );
        verify_stage(&fixture.engine, &origin, 2_000);

        // Retire: старые ключи удалены после propagation.
        let report = fixture.engine.advance(2_100).expect("advance");
        assert_eq!(report.removed, 2);
        assert_eq!(fixture.engine.status().keys.len(), 2);
        assert!(
            fixture
                .engine
                .status()
                .keys
                .iter()
                .all(|key| key.stage == KeyStage::Active)
        );
        verify_stage(&fixture.engine, &origin, 2_100);
    }

    #[test]
    fn state_and_keys_survive_restart() {
        let mut fixture = fixture(1_000);
        fixture.engine.advance(1_800).expect("advance");
        let before = fixture.engine.status();
        let state_path = fixture.engine.state_path().to_path_buf();
        let key_dir = fixture.directory.path().join("keys");
        drop(fixture.engine);

        let mut reopened = RotationEngine::open(
            &Name::parse("example.com").expect("origin"),
            key_dir,
            state_path.clone(),
            policy(),
            86_400,
            300,
            &[],
            1_800,
        )
        .expect("reopen");
        assert_eq!(reopened.status(), before);
        reload_verify(&mut reopened);
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(&state_path)
                .expect("state metadata")
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(mode, 0o600, "rotation state must be 0600");
    }

    fn reload_verify(engine: &mut RotationEngine) {
        let origin = Name::parse("example.com").expect("origin");
        engine.advance(1_900).expect("advance after restart");
        verify_stage(engine, &origin, 1_900);
    }
}
