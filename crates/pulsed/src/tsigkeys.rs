//! Управляемые TSIG-ключи: конфигурация + состояние процесса.
//!
//! Ключи из секции `tsig_keys` неизменяемы и загружаются из конфигурации.
//! Ключи, созданные через REST (`/api/v1/tsig-keys`), хранятся в отдельном
//! JSON-файле `0600` (атомарная запись) и доступны `UPDATE`, входящим
//! AXFR/IXFR и NOTIFY без перезапуска. `SIGHUP` перечитывает state-файл.
//!
//! Секрет никогда не попадает в [`TsigKeyView`], `Debug`, логи и ответы API.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use pulse_dns::Name;
use pulse_dnssec::SecretRef;
use pulse_transfer::{TsigKey, TsigKeyPolicy};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config::{TsigKeyConfig, parse_tsig_algorithm};
use crate::perms;

const STATE_VERSION: u32 = 1;

/// Ошибка хранилища TSIG-ключей.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TsigKeyStoreError {
    /// Ключ уже существует (в конфигурации или в state-файле).
    #[error("TSIG key {name} already exists")]
    Exists {
        /// Имя ключа.
        name: String,
    },
    /// Ключ не найден.
    #[error("TSIG key {name} not found")]
    NotFound {
        /// Имя ключа.
        name: String,
    },
    /// Ключ объявлен в конфигурации и не может быть удалён через API.
    #[error("TSIG key {name} is configured in tsig_keys and is immutable")]
    Immutable {
        /// Имя ключа.
        name: String,
    },
    /// Некорректный ввод.
    #[error("invalid TSIG key: {reason}")]
    Invalid {
        /// Причина.
        reason: String,
    },
    /// Ошибка state-файла.
    #[error("TSIG key state {path}: {reason}")]
    State {
        /// Путь.
        path: String,
        /// Причина.
        reason: String,
    },
}

/// Публичное представление ключа (без секрета).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsigKeyView {
    /// Имя ключа.
    pub name: Name,
    /// Алгоритм (`hmac-sha256`, …).
    pub algorithm: String,
    /// Время создания (UNIX).
    pub created_at: u64,
    /// Время последнего успешного использования (UNIX), если было.
    pub last_used: Option<u64>,
    /// Ключ объявлен в конфигурации (нельзя удалить через API).
    pub configured: bool,
}

/// Один ключ в памяти.
pub(crate) struct TsigKeyEntry {
    pub(crate) key: Arc<TsigKey>,
    secret: SecretRef,
    algorithm: String,
    created_at: u64,
    last_used: AtomicU64,
    configured: bool,
}

impl TsigKeyEntry {
    fn view(&self) -> TsigKeyView {
        TsigKeyView {
            name: self.key.name().clone(),
            algorithm: self.algorithm.clone(),
            created_at: self.created_at,
            last_used: match self.last_used.load(Ordering::Relaxed) {
                0 => None,
                value => Some(value),
            },
            configured: self.configured,
        }
    }
}

/// Общее хранилище TSIG-ключей.
pub(crate) struct TsigKeyStore {
    path: Option<PathBuf>,
    keys: RwLock<HashMap<Name, Arc<TsigKeyEntry>>>,
    configured: HashSet<Name>,
}

impl TsigKeyStore {
    /// Загружает конфигурационные ключи и state-файл.
    ///
    /// # Errors
    ///
    /// [`TsigKeyStoreError`] при некорректном ключе или state-файле.
    pub(crate) fn load(
        keys: &[TsigKeyConfig],
        path: Option<PathBuf>,
    ) -> Result<Self, TsigKeyStoreError> {
        let mut map = HashMap::with_capacity(keys.len());
        let mut configured = HashSet::with_capacity(keys.len());
        for config in keys {
            let (name, entry) = build_entry(
                &config.name,
                &config.algorithm,
                &STANDARD.decode(config.secret.trim()).map_err(|error| {
                    TsigKeyStoreError::Invalid {
                        reason: format!("key {:?} secret is not base64: {error}", config.name),
                    }
                })?,
                now_unix(),
                true,
            )?;
            if map.insert(name.clone(), Arc::new(entry)).is_some() {
                return Err(TsigKeyStoreError::Invalid {
                    reason: format!("duplicate configured key {name}"),
                });
            }
            configured.insert(name);
        }
        let store = Self {
            path,
            keys: RwLock::new(map),
            configured,
        };
        store.reload()?;
        Ok(store)
    }

    /// Перечитывает state-файл (SIGHUP / старт).
    ///
    /// Конфигурационные ключи остаются; управляемые ключи заменяются
    /// содержимым файла. Возвращает число загруженных управляемых ключей.
    ///
    /// # Errors
    ///
    /// [`TsigKeyStoreError::State`] при ошибке чтения/разбора.
    pub(crate) fn reload(&self) -> Result<usize, TsigKeyStoreError> {
        let Some(path) = &self.path else {
            return Ok(0);
        };
        if !path.exists() {
            return Ok(0);
        }
        perms::ensure_private(path, "TSIG key state").map_err(|reason| {
            TsigKeyStoreError::State {
                path: path.display().to_string(),
                reason,
            }
        })?;
        let text = std::fs::read_to_string(path).map_err(|error| TsigKeyStoreError::State {
            path: path.display().to_string(),
            reason: error.to_string(),
        })?;
        let state: StateFile =
            serde_json::from_str(&text).map_err(|error| TsigKeyStoreError::State {
                path: path.display().to_string(),
                reason: error.to_string(),
            })?;
        if state.version != STATE_VERSION {
            return Err(TsigKeyStoreError::State {
                path: path.display().to_string(),
                reason: format!("unsupported state version {}", state.version),
            });
        }
        let mut managed = HashMap::with_capacity(state.keys.len());
        for record in state.keys {
            let secret = STANDARD.decode(record.secret.trim()).map_err(|error| {
                TsigKeyStoreError::State {
                    path: path.display().to_string(),
                    reason: format!("key {} secret is not base64: {error}", record.name),
                }
            })?;
            let (name, entry) = build_entry(
                &record.name,
                &record.algorithm,
                &secret,
                record.created_at,
                false,
            )
            .map_err(|error| TsigKeyStoreError::State {
                path: path.display().to_string(),
                reason: error.to_string(),
            })?;
            if self.configured.contains(&name)
                || managed.insert(name.clone(), Arc::new(entry)).is_some()
            {
                return Err(TsigKeyStoreError::State {
                    path: path.display().to_string(),
                    reason: format!("duplicate key {name}"),
                });
            }
        }
        let loaded = managed.len();
        let mut keys = self.keys.write().unwrap_or_else(PoisonError::into_inner);
        keys.retain(|name, _| self.configured.contains(name));
        keys.extend(managed);
        Ok(loaded)
    }

    /// Ключ по имени (для TSIG-проверки и transfer).
    pub(crate) fn get(&self, name: &Name) -> Option<Arc<TsigKeyEntry>> {
        self.keys
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(name)
            .cloned()
    }

    /// Ключ по имени для transfer-слоя.
    pub(crate) fn key(&self, name: &Name) -> Option<Arc<TsigKey>> {
        self.get(name).map(|entry| Arc::clone(&entry.key))
    }

    /// Отмечает успешное использование ключа.
    pub(crate) fn mark_used(&self, name: &Name, now: u64) {
        if let Some(entry) = self.get(name) {
            entry.last_used.store(now.max(1), Ordering::Relaxed);
        }
    }

    /// Список ключей в детерминированном порядке.
    pub(crate) fn list(&self) -> Vec<TsigKeyView> {
        let keys = self.keys.read().unwrap_or_else(PoisonError::into_inner);
        let mut views: Vec<TsigKeyView> = keys.values().map(|entry| entry.view()).collect();
        views.sort_by(|left, right| left.name.cmp_canonical(&right.name));
        views
    }

    /// Создаёт управляемый ключ и атомарно сохраняет state-файл.
    ///
    /// # Errors
    ///
    /// [`TsigKeyStoreError`] при дубликате, некорректном алгоритме/секрете или
    /// ошибке записи.
    pub(crate) fn create(
        &self,
        name: &str,
        algorithm: &str,
        secret: &[u8],
    ) -> Result<TsigKeyView, TsigKeyStoreError> {
        let (name, entry) = build_entry(name, algorithm, secret, now_unix(), false)?;
        {
            let mut keys = self.keys.write().unwrap_or_else(PoisonError::into_inner);
            if keys.contains_key(&name) {
                return Err(TsigKeyStoreError::Exists {
                    name: name.to_string(),
                });
            }
            keys.insert(name.clone(), Arc::new(entry));
            if let Err(error) = self.persist_locked(&keys) {
                keys.remove(&name);
                return Err(error);
            }
        }
        self.get(&name)
            .map(|entry| entry.view())
            .ok_or_else(|| TsigKeyStoreError::NotFound {
                name: name.to_string(),
            })
    }

    /// Удаляет управляемый ключ.
    ///
    /// # Errors
    ///
    /// [`TsigKeyStoreError`] если ключ отсутствует, объявлен в конфигурации
    /// или state-файл не записался.
    pub(crate) fn delete(&self, name: &Name) -> Result<(), TsigKeyStoreError> {
        let mut keys = self.keys.write().unwrap_or_else(PoisonError::into_inner);
        let Some(removed) = keys.get(name).cloned() else {
            return Err(TsigKeyStoreError::NotFound {
                name: name.to_string(),
            });
        };
        if removed.configured {
            return Err(TsigKeyStoreError::Immutable {
                name: name.to_string(),
            });
        }
        keys.remove(name);
        if let Err(error) = self.persist_locked(&keys) {
            keys.insert(name.clone(), removed);
            return Err(error);
        }
        Ok(())
    }

    fn persist_locked(
        &self,
        keys: &HashMap<Name, Arc<TsigKeyEntry>>,
    ) -> Result<(), TsigKeyStoreError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let mut managed: Vec<&Arc<TsigKeyEntry>> =
            keys.values().filter(|entry| !entry.configured).collect();
        managed.sort_by(|left, right| left.key.name().cmp_canonical(right.key.name()));
        let state = StateFile {
            version: STATE_VERSION,
            keys: managed
                .into_iter()
                .map(|entry| StateKey {
                    name: entry.key.name().to_string(),
                    algorithm: entry.algorithm.clone(),
                    secret: STANDARD.encode(entry.secret.expose()),
                    created_at: entry.created_at,
                })
                .collect(),
        };
        let json = serde_json::to_vec_pretty(&state).map_err(|error| TsigKeyStoreError::State {
            path: path.display().to_string(),
            reason: error.to_string(),
        })?;
        keyfile_write_private(path, &json).map_err(|reason| TsigKeyStoreError::State {
            path: path.display().to_string(),
            reason,
        })
    }
}

/// Проверяет и создаёт ключ.
fn build_entry(
    name: &str,
    algorithm: &str,
    secret: &[u8],
    created_at: u64,
    configured: bool,
) -> Result<(Name, TsigKeyEntry), TsigKeyStoreError> {
    let parsed = Name::parse(name.trim()).map_err(|error| TsigKeyStoreError::Invalid {
        reason: format!("invalid name {name:?}: {error}"),
    })?;
    if parsed == Name::root() || parsed.labels().any(|label| label == b"*") {
        return Err(TsigKeyStoreError::Invalid {
            reason: format!("name {name:?} must be a non-root name without wildcards"),
        });
    }
    let algorithm =
        parse_tsig_algorithm(algorithm).map_err(|error| TsigKeyStoreError::Invalid {
            reason: error.to_string(),
        })?;
    if secret.is_empty() {
        return Err(TsigKeyStoreError::Invalid {
            reason: "secret must not be empty".to_owned(),
        });
    }
    let key = TsigKey::new_with_policy(
        parsed.clone(),
        algorithm,
        secret.to_vec(),
        TsigKeyPolicy::default(),
    )
    .map_err(|error| TsigKeyStoreError::Invalid {
        reason: error.to_string(),
    })?;
    Ok((
        parsed,
        TsigKeyEntry {
            key: Arc::new(key),
            secret: SecretRef::from_slice(secret),
            algorithm: algorithm.name().to_owned(),
            created_at,
            last_used: AtomicU64::new(0),
            configured,
        },
    ))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

/// Атомарно пишет state-файл с правами `0600` (без требования `0700` к
/// каталогу: путь задаёт администратор, а секрет защищает сам файл).
fn keyfile_write_private(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("tsig-keys.json");
    let unique = format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos())
    );
    let temporary = parent.join(unique);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|error| format!("cannot create {}: {error}", temporary.display()))?;
    let write = (|| -> std::io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&temporary, path)?;
        if let Ok(directory) = std::fs::File::open(parent) {
            let _ = directory.sync_all();
        }
        Ok(())
    })();
    if let Err(error) = write {
        let _ = std::fs::remove_file(&temporary);
        return Err(format!("cannot write {}: {error}", path.display()));
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct StateFile {
    version: u32,
    #[serde(default)]
    keys: Vec<StateKey>,
}

#[derive(Serialize, Deserialize)]
struct StateKey {
    name: String,
    algorithm: String,
    secret: String,
    #[serde(default)]
    created_at: u64,
}

/// Проверяет, что адрес входит в подсеть (для политики UPDATE).
pub(crate) fn cidr_contains(cidr: &str, address: IpAddr) -> Option<bool> {
    let value = cidr.trim();
    let (network, prefix) = match value.split_once('/') {
        Some((network, prefix)) => (network, Some(prefix)),
        None => (value, None),
    };
    let network: IpAddr = network.parse().ok()?;
    let prefix = match prefix {
        Some(prefix) => prefix.parse::<u8>().ok()?,
        None => {
            if network.is_ipv4() {
                32
            } else {
                128
            }
        }
    };
    match (network, address) {
        (IpAddr::V4(network), IpAddr::V4(address)) => {
            if prefix > 32 {
                return None;
            }
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix))
            };
            Some((u32::from(network) & mask) == (u32::from(address) & mask))
        }
        (IpAddr::V6(network), IpAddr::V6(address)) => {
            if prefix > 128 {
                return None;
            }
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix))
            };
            Some((u128::from(network) & mask) == (u128::from(address) & mask))
        }
        _ => Some(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "c2VjcmV0";

    fn config() -> TsigKeyConfig {
        TsigKeyConfig {
            name: "configured.example".to_owned(),
            algorithm: "hmac-sha256".to_owned(),
            secret: SECRET.to_owned(),
        }
    }

    #[test]
    fn configured_keys_are_immutable_and_managed_keys_persist() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("tsig.json");
        let store = TsigKeyStore::load(&[config()], Some(path.clone())).expect("load");
        assert_eq!(store.list().len(), 1);
        let name = Name::parse("managed.example").expect("name");
        store
            .create("managed.example", "hmac-sha512", b"another")
            .expect("create");
        assert_eq!(store.list().len(), 2);
        assert!(matches!(
            store.delete(&Name::parse("configured.example").expect("name")),
            Err(TsigKeyStoreError::Immutable { .. })
        ));
        store.delete(&name).expect("delete");
        let text = std::fs::read_to_string(&path).expect("state");
        assert!(!text.contains("managed.example"));
        store
            .create("managed.example", "hmac-sha512", b"another")
            .expect("create again");
        let reloaded = TsigKeyStore::load(&[config()], Some(path)).expect("reload");
        assert!(reloaded.get(&name).is_some());
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(directory.path().join("tsig.json"))
                .expect("meta")
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn rejects_bad_input_and_duplicates() {
        let store = TsigKeyStore::load(&[], None).expect("load");
        store
            .create("key.example", "hmac-sha256", b"secret")
            .expect("create");
        assert!(matches!(
            store.create("key.example", "hmac-sha256", b"secret"),
            Err(TsigKeyStoreError::Exists { .. })
        ));
        assert!(store.create(".", "hmac-sha256", b"secret").is_err());
        assert!(store.create("key2.example", "sha1", b"secret").is_ok());
        assert!(store.create("key3.example", "hmac-sha256", b"").is_err());
    }

    #[test]
    fn rotation_creates_new_key_before_deleting_old() {
        let store = TsigKeyStore::load(&[], None).expect("load");
        let old = Name::parse("old.example").expect("name");
        let new = Name::parse("new.example").expect("name");
        store
            .create("old.example", "hmac-sha256", b"old-secret")
            .expect("old");
        store
            .create("new.example", "hmac-sha512", b"new-secret")
            .expect("new");
        store.delete(&old).expect("delete old");
        assert!(store.get(&old).is_none());
        assert_eq!(
            store.get(&new).expect("new").view().algorithm,
            "hmac-sha512"
        );
    }

    #[test]
    fn cidr_matching_for_policy() {
        assert_eq!(
            cidr_contains("10.0.0.0/8", "10.1.2.3".parse().unwrap()),
            Some(true)
        );
        assert_eq!(
            cidr_contains("10.0.0.0/8", "11.1.2.3".parse().unwrap()),
            Some(false)
        );
        assert_eq!(
            cidr_contains("2001:db8::/32", "2001:db8::1".parse().unwrap()),
            Some(true)
        );
        assert_eq!(cidr_contains("bad", "10.0.0.1".parse().unwrap()), None);
    }
}
