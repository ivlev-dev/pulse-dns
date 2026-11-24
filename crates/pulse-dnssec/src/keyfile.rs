//! Атомарная запись ключевых файлов и аудит операций.
//!
//! Инварианты (ADR-0004 SEC-CR-003):
//! - каталог ключей — `0700`, файлы — `0600`;
//! - запись атомарна: temp-файл в том же каталоге, `fsync`, `rename`,
//!   `fsync` каталога;
//! - аудит фиксирует операцию, алгоритм, key tag и путь — **никогда** не
//!   материал ключа.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use pulse_dns::{Name, TTL_MAX};
use zeroize::Zeroizing;

use crate::algorithm::Algorithm;
use crate::bind;
use crate::error::KeyFileError;
use crate::key::PrivateKey;
use crate::secret::SecretRef;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Операция с ключом для аудита.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyOperation {
    /// Генерация.
    Generate,
    /// Импорт из файла/формата.
    Import,
    /// Экспорт (в память/файл).
    Export,
    /// Загрузка в память.
    Load,
    /// Запись файла.
    Write,
    /// Удаление.
    Remove,
}

/// Аудит-событие операции с ключом. Секретов не содержит.
#[derive(Debug, Clone)]
pub struct KeyAuditEvent {
    /// Операция.
    pub operation: KeyOperation,
    /// Алгоритм.
    pub algorithm: Algorithm,
    /// Key tag, если известен.
    pub key_tag: Option<u16>,
    /// Путь, если применим.
    pub path: Option<PathBuf>,
}

/// Приёмник аудита ключевых операций.
pub trait KeyAudit: Send + Sync {
    /// Записывает событие. Реализация не должна логировать материал ключа
    /// (в событии его нет).
    fn record(&self, event: &KeyAuditEvent);
}

/// Аудит-заглушка.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopAudit;

impl KeyAudit for NoopAudit {
    fn record(&self, _event: &KeyAuditEvent) {}
}

impl<F> KeyAudit for F
where
    F: Fn(&KeyAuditEvent) + Send + Sync,
{
    fn record(&self, event: &KeyAuditEvent) {
        self(event);
    }
}

/// Пути записанной пары ключей.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyFilePaths {
    /// Публичный `.key`.
    pub public: PathBuf,
    /// Приватный `.private`.
    pub private: PathBuf,
}

/// Создаёт каталог `0700` или проверяет права существующего.
///
/// # Errors
///
/// [`KeyFileError::Permissions`], если у существующего каталога есть
/// групповые/прочие биты; [`KeyFileError::Io`] при ошибке ФС.
pub fn ensure_private_directory(directory: &Path) -> Result<(), KeyFileError> {
    match fs::symlink_metadata(directory) {
        Ok(metadata) => {
            if !metadata.file_type().is_dir() {
                return Err(KeyFileError::NotADirectory {
                    path: directory.to_path_buf(),
                });
            }
            let mode = metadata.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(KeyFileError::Permissions {
                    path: directory.to_path_buf(),
                    mode,
                });
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(directory)
                .map_err(|source| KeyFileError::Io {
                    path: directory.to_path_buf(),
                    source,
                })?;
            let mode = fs::metadata(directory)
                .map_err(|source| KeyFileError::Io {
                    path: directory.to_path_buf(),
                    source,
                })?
                .permissions()
                .mode()
                & 0o777;
            if mode & 0o077 != 0 {
                return Err(KeyFileError::Permissions {
                    path: directory.to_path_buf(),
                    mode,
                });
            }
            Ok(())
        }
        Err(source) => Err(KeyFileError::Io {
            path: directory.to_path_buf(),
            source,
        }),
    }
}

/// Атомарно пишет секретный материал в `0600`-файл.
///
/// # Errors
///
/// [`KeyFileError::Io`] при ошибке ФС, [`KeyFileError::Permissions`] при
/// небезопасных правах каталога, [`KeyFileError::TempFile`] при
/// невозможности создать уникальный temp-файл.
pub fn write_secret_file(
    path: &Path,
    material: &SecretRef,
    audit: &dyn KeyAudit,
    event: Option<&KeyAuditEvent>,
) -> Result<(), KeyFileError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    ensure_private_directory(parent)?;
    let temporary = unique_temp_path(path)?;
    let result = write_temp_and_rename(&temporary, path, material.expose());
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result?;
    if let Some(mut event) = event.cloned() {
        event.operation = KeyOperation::Write;
        event.path = Some(path.to_path_buf());
        audit.record(&event);
    }
    Ok(())
}

fn write_temp_and_rename(temporary: &Path, path: &Path, bytes: &[u8]) -> Result<(), KeyFileError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(temporary)
        .map_err(|source| KeyFileError::Io {
            path: temporary.to_path_buf(),
            source,
        })?;
    file.write_all(bytes).map_err(|source| KeyFileError::Io {
        path: temporary.to_path_buf(),
        source,
    })?;
    file.sync_all().map_err(|source| KeyFileError::Io {
        path: temporary.to_path_buf(),
        source,
    })?;
    drop(file);
    fs::set_permissions(temporary, fs::Permissions::from_mode(0o600)).map_err(|source| {
        KeyFileError::Io {
            path: temporary.to_path_buf(),
            source,
        }
    })?;
    fs::rename(temporary, path).map_err(|source| KeyFileError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if let Some(parent) = path.parent() {
        let directory = File::open(parent).map_err(|source| KeyFileError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
        directory.sync_all().map_err(|source| KeyFileError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

fn sanitize_owner_stem(owner: &str) -> String {
    owner
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn unique_temp_path(path: &Path) -> Result<PathBuf, KeyFileError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| KeyFileError::TempFile {
            directory: parent.to_path_buf(),
        })?;
    for _ in 0..16 {
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(".{name}.tmp.{}.{counter}", std::process::id()));
        if !temporary.exists() {
            return Ok(temporary);
        }
    }
    Err(KeyFileError::TempFile {
        directory: parent.to_path_buf(),
    })
}

/// Записывает пару `K*.key` / `K*.private` в каталог `0700`.
///
/// Имя файла — BIND-совместимое: `K<owner>+<alg>+<keytag>`.
///
/// # Errors
///
/// Ошибки каталога/записи/экспорта ключа.
pub fn write_key_pair(
    directory: &Path,
    owner: &Name,
    key: &PrivateKey,
    flags: u16,
    audit: &dyn KeyAudit,
) -> Result<KeyFilePaths, KeyFileError> {
    ensure_private_directory(directory)?;
    let dnskey = key.dnskey(flags)?;
    let key_tag = crate::rdata_util::key_tag(&dnskey);
    let owner_text = owner.to_string();
    let owner_stem = if owner_text == "." {
        String::from(".")
    } else {
        sanitize_owner_stem(owner_text.trim_end_matches('.'))
    };
    let base = format!("K{}+{:03}+{:05}", owner_stem, dnskey.algorithm(), key_tag);
    let public_path = directory.join(format!("{base}.key"));
    let private_path = directory.join(format!("{base}.private"));

    let ttl = TTL_MAX.min(3600);
    let public_text = bind::format_dnskey_line(owner, ttl, &dnskey);
    let private_secret = bind::format_private_key(key)?;
    let event = KeyAuditEvent {
        operation: KeyOperation::Write,
        algorithm: key.algorithm(),
        key_tag: Some(key_tag),
        path: None,
    };
    write_secret_file(&private_path, &private_secret, audit, Some(&event))?;
    write_secret_file(
        &public_path,
        &SecretRef::from_slice(public_text.as_bytes()),
        audit,
        Some(&event),
    )?;
    Ok(KeyFilePaths {
        public: public_path,
        private: private_path,
    })
}

/// Читает и разбирает `.private`-файл.
///
/// # Errors
///
/// [`KeyFileError::Io`] при ошибке чтения, [`KeyFileError::Key`] при
/// разборе.
pub fn read_private_key_file(path: &Path) -> Result<PrivateKey, KeyFileError> {
    let text = Zeroizing::new(fs::read_to_string(path).map_err(|source| KeyFileError::Io {
        path: path.to_path_buf(),
        source,
    })?);
    if text.contains("-----BEGIN") {
        return Err(KeyFileError::Key(crate::error::KeyError::BadBindPrivate {
            reason: "PKCS#8 PEM is not a BIND private key file",
        }));
    }
    Ok(bind::parse_private_key(&text)?)
}
