//! Write-ahead journal (outbox) для REST-мутаций.
//!
//! Файл `<data>.journal` — append-only лог намерений и их исходов. Формат
//! версионирован, каждая запись кадрируется длиной и CRC32, а последовательный
//! номер (`seq`) позволяет обнаружить разрыв. Заголовок файла:
//!
//! ```text
//! magic: 8 байт "PULSEJNL"
//! version: u32 LE (1)
//! header CRC32: u32 LE
//! ```
//!
//! Кадр: `len: u32 LE`, `crc32: u32 LE`, `payload[len]` — JSON-запись.
//! Поэтому хвост, оборванный посреди записи, распознаётся и обрезается
//! ([`Journal::open`]); предыдущие операции не теряются.
//!
//! # Жизненный цикл мутации
//!
//! 1. `intent` — операция и её метаданные (`op_id`, метод/путь, SHA-256 тела,
//!    ожидаемый ETag/версия) пишутся до применения; запись синхронизируется
//!    (`fsync` при `fsync = true`).
//! 2. Zonefile-коммит выполняется адаптером [`crate::port::ZoneAdmin`].
//! 3. `committed` — фиксирует версию и HTTP-ответ; только после этого клиент
//!    получает `2xx`.
//! 4. `aborted` — клиентская ошибка (4xx), чтобы recovery не повторял
//!    заведомо невалидную операцию.
//!
//! Recovery применяет `intent` без `committed`/`aborted`. Идемпотентность
//! обеспечивается двумя механизмами: `op_id`, детерминированно выведенный из
//! `Idempotency-Key`, и проверкой целевого состояния (например, RRset уже
//! содержит нужный набор) — повторно применённая операция пропускается.
//!
//! # Ограничения
//!
//! Секреты (заголовок `Authorization`, тело запроса) в журнал не пишутся:
//! сохраняются только метаданные, хеш тела и нормализованная операция. Тело
//! ответа хранится для точного replay после рестарта; оно не содержит
//! credentials.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use pulse_dns::{Name, Rdata, Rtype};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::codec::{hex_lower, parse_rtype};
use crate::error::{AdminError, NotFound};
use crate::http::HttpResponse;
use crate::port::{
    Precondition, Preconditions, RrsetInput, RrsetPatch, ZoneAdmin, ZoneKind, ZoneMetaInput,
    ZoneSettingsPatch,
};
use crate::rdata_text::parse_rdata;

/// Версия формата журнала, которую понимает этот код.
pub const FORMAT_VERSION: u32 = 1;

/// Суффикс журнала по умолчанию: `<zonefile>.journal`.
pub const DEFAULT_SUFFIX: &str = ".journal";

/// Порог compaction по умолчанию: 8 MiB.
pub const DEFAULT_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Сколько разрешённых (committed/aborted) записей сохранять при compaction
/// сверх незавершённых. Нужно для идемпотентных повторов после рестарта.
pub const DEFAULT_RETAIN_RESOLVED: usize = 1024;

const MAGIC: &[u8; 8] = b"PULSEJNL";
const HEADER_LEN: usize = 16;
const FRAME_HEADER_LEN: usize = 8;
const MIN_MAX_BYTES: u64 = 4096;
const MAX_RECORD_BYTES: usize = 64 * 1024 * 1024;

/// Ошибка журнала.
#[derive(Debug, Error)]
pub enum JournalError {
    /// Ошибка ввода-вывода.
    #[error("journal {path}: {action}: {source}")]
    Io {
        /// Путь журнала.
        path: PathBuf,
        /// Действие.
        action: &'static str,
        /// Причина.
        #[source]
        source: io::Error,
    },
    /// Некорректная конфигурация.
    #[error("journal configuration error: {0}")]
    Config(String),
    /// Файл журнала несовместим с этой версией.
    #[error(
        "journal {path} uses format version {found}, but this binary supports only version {supported}"
    )]
    IncompatibleVersion {
        /// Путь журнала.
        path: PathBuf,
        /// Найденная версия.
        found: u32,
        /// Поддерживаемая версия.
        supported: u32,
    },
    /// Файл журнала повреждён.
    #[error("journal {path} is corrupt: {reason}")]
    Corrupt {
        /// Путь журнала.
        path: PathBuf,
        /// Причина.
        reason: String,
    },
    /// Recovery не смог применить намерение.
    #[error("journal recovery failed for op {op_id}: {reason}")]
    Recovery {
        /// Идентификатор операции.
        op_id: String,
        /// Причина.
        reason: String,
    },
    /// Тестовая инъекция ошибки (debug-сборка).
    #[error("journal fault injected: {0}")]
    Injected(&'static str),
}

impl JournalError {
    fn io(path: &Path, action: &'static str, source: io::Error) -> Self {
        Self::Io {
            path: path.to_path_buf(),
            action,
            source,
        }
    }
}

/// Конфигурация журнала.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalConfig {
    /// Путь файла журнала.
    pub path: PathBuf,
    /// Порог compaction в байтах.
    pub max_bytes: u64,
    /// Синхронизировать каждую запись (`fsync`).
    pub fsync: bool,
    /// Сколько разрешённых записей сохранять при compaction.
    pub retain_resolved: usize,
}

impl JournalConfig {
    /// Конфигурация с дефолтами.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            max_bytes: DEFAULT_MAX_BYTES,
            fsync: true,
            retain_resolved: DEFAULT_RETAIN_RESOLVED,
        }
    }
}

/// Снимок счётчиков журнала.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JournalMetrics {
    /// Записей `intent` добавлено.
    pub intents: u64,
    /// Намерений повторено при recovery или replay.
    pub replays: u64,
    /// Успешных compaction.
    pub compactions: u64,
    /// Ошибок журнала (I/O, повреждение, обрезка, injection).
    pub errors: u64,
}

impl JournalMetrics {
    /// Рендер в формате Prometheus.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("# HELP journal_intents_total Write-ahead intents appended to the journal.\n");
        out.push_str("# TYPE journal_intents_total counter\n");
        out.push_str(&format!("journal_intents_total {}\n", self.intents));
        out.push_str(
            "# HELP journal_replays_total Intents replayed during recovery or idempotent replay.\n",
        );
        out.push_str("# TYPE journal_replays_total counter\n");
        out.push_str(&format!("journal_replays_total {}\n", self.replays));
        out.push_str("# HELP journal_compactions_total Successful journal compactions.\n");
        out.push_str("# TYPE journal_compactions_total counter\n");
        out.push_str(&format!("journal_compactions_total {}\n", self.compactions));
        out.push_str("# HELP journal_errors_total Journal I/O, corruption and injection errors.\n");
        out.push_str("# TYPE journal_errors_total counter\n");
        out.push_str(&format!("journal_errors_total {}\n", self.errors));
        out
    }
}

/// Отчёт recovery.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    /// Незавершённых намерений найдено.
    pub pending: usize,
    /// Намерений применено.
    pub replayed: usize,
    /// Намерений пропущено как уже применённые.
    pub skipped: usize,
    /// Намерений отклонено (невалидная операция).
    pub aborted: usize,
    /// Обрезано байт повреждённого хвоста.
    pub truncated_bytes: u64,
}

/// Что делать с намерением при `begin`.
#[derive(Debug)]
pub(crate) enum Begin {
    /// Новое намерение; можно применять.
    New,
    /// Намерение уже есть, но без исхода (предыдущая попытка/рестарт).
    Pending,
    /// Тот же `op_id`, но другое тело запроса.
    Conflict,
    /// Операция уже завершена; точный сохранённый ответ.
    Response(StoredResponse),
    /// Операция завершена, но ответ не сохранился (crash между commit и
    /// `committed`); ответ нужно восстановить из состояния store.
    Committed {
        /// Версия после коммита.
        version: u64,
    },
    /// Операция была отклонена до применения.
    Aborted {
        /// Код/причина отказа.
        reason: String,
    },
}

/// Сохранённый HTTP-ответ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoredResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl StoredResponse {
    fn capture(response: &HttpResponse) -> Self {
        Self {
            status: response.status,
            headers: response.headers.clone(),
            body: response.body.clone(),
        }
    }

    pub(crate) fn into_http(self) -> HttpResponse {
        let mut response = HttpResponse {
            status: self.status,
            headers: self.headers,
            body: self.body,
        };
        response.set_header("Idempotent-Replay", "true");
        response
    }
}

/// Намерение мутации (то, что попадает в `intent`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct IntentRecord {
    /// Детерминированный идентификатор операции.
    pub(crate) op_id: String,
    /// Время намерения (unix ns).
    pub(crate) timestamp_unix_ns: u64,
    /// HTTP-метод.
    pub(crate) method: String,
    /// HTTP-путь.
    pub(crate) path: String,
    /// SHA-256 тела запроса в hex.
    pub(crate) body_sha256: String,
    /// Ожидаемый ETag (`If-Match`).
    pub(crate) expected_etag: Option<String>,
    /// Ожидаемая версия, если её удалось вывести из ETag.
    pub(crate) expected_version: Option<u64>,
    /// `If-None-Match`.
    pub(crate) if_none_match: Option<String>,
    /// Сама операция.
    pub(crate) operation: JournalOp,
}

/// Нормализованная операция для replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub(crate) enum JournalOp {
    /// Создание/замена зоны.
    PutZone {
        /// Origin.
        origin: String,
        /// Вид зоны.
        kind: String,
        /// TTL по умолчанию.
        default_ttl: u32,
        /// Denial.
        denial: String,
    },
    /// Удаление зоны.
    DeleteZone {
        /// Origin.
        origin: String,
    },
    /// Создание/замена RRset.
    PutRrset {
        /// Origin.
        origin: String,
        /// Владелец.
        owner: String,
        /// Тип.
        rr_type: String,
        /// TTL.
        ttl: u32,
        /// RDATA в presentation-формате.
        records: Vec<String>,
    },
    /// Частичное изменение RRset.
    PatchRrset {
        /// Origin.
        origin: String,
        /// Владелец.
        owner: String,
        /// Тип.
        rr_type: String,
        /// Новый TTL.
        ttl: Option<u32>,
        /// Добавляемые RDATA.
        add: Vec<String>,
        /// Удаляемые RDATA.
        remove: Vec<String>,
    },
    /// Удаление RRset.
    DeleteRrset {
        /// Origin.
        origin: String,
        /// Владелец.
        owner: String,
        /// Тип.
        rr_type: String,
    },
    /// Изменение настроек зоны.
    PatchSettings {
        /// Origin.
        origin: String,
        /// Новый TTL по умолчанию.
        default_ttl: Option<u32>,
        /// Новая политика denial.
        denial: Option<String>,
    },
}

/// Конверт записи на диске.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "record", rename_all = "snake_case")]
enum Record {
    Intent {
        seq: u64,
        intent: IntentRecord,
    },
    Committed {
        seq: u64,
        op_id: String,
        version: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        response: Option<StoredResponseWire>,
    },
    Aborted {
        seq: u64,
        op_id: String,
        reason: String,
        #[serde(default)]
        retryable: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        response: Option<StoredResponseWire>,
    },
}

impl Record {
    fn seq(&self) -> u64 {
        match self {
            Self::Intent { seq, .. } | Self::Committed { seq, .. } | Self::Aborted { seq, .. } => {
                *seq
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredResponseWire {
    status: u16,
    #[serde(default)]
    headers: Vec<(String, String)>,
    /// Тело в base64 (JSON-массив байт раздувает файл).
    body_b64: String,
}

impl StoredResponseWire {
    fn capture(response: &StoredResponse) -> Self {
        Self {
            status: response.status,
            headers: response.headers.clone(),
            body_b64: BASE64.encode(&response.body),
        }
    }

    fn into_response(self) -> StoredResponse {
        StoredResponse {
            status: self.status,
            headers: self.headers,
            body: BASE64.decode(self.body_b64).unwrap_or_default(),
        }
    }
}

#[derive(Debug, Clone)]
struct Entry {
    op_id: String,
    intent: Option<IntentRecord>,
    status: EntryStatus,
}

#[derive(Debug, Clone)]
enum EntryStatus {
    Pending,
    Committed {
        version: u64,
        response: Option<StoredResponse>,
    },
    Aborted {
        reason: String,
        retryable: bool,
        response: Option<StoredResponse>,
    },
}

struct Inner {
    file: File,
    size: u64,
    next_seq: u64,
    entries: Vec<Entry>,
    index: HashMap<String, usize>,
    truncated_bytes: u64,
}

/// Append-only журнал.
pub struct Journal {
    path: PathBuf,
    max_bytes: u64,
    fsync: bool,
    retain_resolved: usize,
    inner: Mutex<Inner>,
    intents: AtomicU64,
    replays: AtomicU64,
    compactions: AtomicU64,
    errors: AtomicU64,
}

impl std::fmt::Debug for Journal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Journal")
            .field("path", &self.path)
            .field("max_bytes", &self.max_bytes)
            .field("fsync", &self.fsync)
            .finish_non_exhaustive()
    }
}

impl Journal {
    /// Открывает существующий журнал или создаёт новый.
    ///
    /// Повреждённый хвост обрезается до последней валидной записи.
    ///
    /// # Errors
    ///
    /// [`JournalError`] при ошибке I/O, несовместимой версии или повреждённом
    /// заголовке.
    pub fn open(config: JournalConfig) -> Result<Self, JournalError> {
        if config.max_bytes < MIN_MAX_BYTES {
            return Err(JournalError::Config(format!(
                "max_bytes must be at least {MIN_MAX_BYTES}, got {}",
                config.max_bytes
            )));
        }
        let path = config.path;
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&path)
            .map_err(|error| JournalError::io(&path, "open", error))?;
        let mut errors = 0_u64;
        let length = file
            .metadata()
            .map_err(|error| JournalError::io(&path, "stat", error))?
            .len();
        let mut bytes = Vec::new();
        if length == 0 {
            write_header(&mut file, &path)?;
        } else if length < HEADER_LEN as u64 {
            file.seek(SeekFrom::Start(0))
                .map_err(|error| JournalError::io(&path, "seek", error))?;
            file.read_to_end(&mut bytes)
                .map_err(|error| JournalError::io(&path, "read", error))?;
            if bytes.get(..8).is_some_and(|magic| magic == MAGIC) {
                if let Some(found) = version_of_partial_header(&bytes) {
                    if found != FORMAT_VERSION {
                        return Err(JournalError::IncompatibleVersion {
                            path,
                            found,
                            supported: FORMAT_VERSION,
                        });
                    }
                }
            }
            // Оборванное создание файла: заголовка ещё нет, данных тем более.
            file.set_len(0)
                .map_err(|error| JournalError::io(&path, "truncate header", error))?;
            write_header(&mut file, &path)?;
            errors = errors.saturating_add(1);
        } else {
            file.seek(SeekFrom::Start(0))
                .map_err(|error| JournalError::io(&path, "seek", error))?;
            file.read_to_end(&mut bytes)
                .map_err(|error| JournalError::io(&path, "read", error))?;
            validate_header(&path, &bytes)?;
        }
        let mut inner = Inner {
            file,
            size: 0,
            next_seq: 1,
            entries: Vec::new(),
            index: HashMap::new(),
            truncated_bytes: 0,
        };
        let mut truncated = 0_u64;
        if bytes.len() > HEADER_LEN {
            let scan = scan_records(&bytes, &mut inner);
            if scan.valid_end < bytes.len() {
                truncated = u64::try_from(bytes.len() - scan.valid_end).unwrap_or(u64::MAX);
                inner
                    .file
                    .set_len(scan.valid_end as u64)
                    .map_err(|error| JournalError::io(&path, "truncate tail", error))?;
                sync_data(&inner.file, &path)?;
                errors = errors.saturating_add(1);
            }
        }
        inner.size = inner
            .file
            .metadata()
            .map_err(|error| JournalError::io(&path, "stat", error))?
            .len();
        inner.next_seq = scan_next_seq(&inner);
        inner.truncated_bytes = truncated;
        Ok(Self {
            path,
            max_bytes: config.max_bytes,
            fsync: config.fsync,
            retain_resolved: config.retain_resolved.max(1),
            inner: Mutex::new(inner),
            intents: AtomicU64::new(0),
            replays: AtomicU64::new(0),
            compactions: AtomicU64::new(0),
            errors: AtomicU64::new(errors),
        })
    }

    /// Учитывает replay, отданный клиенту из журнала.
    pub(crate) fn note_replay(&self) {
        self.replays.fetch_add(1, Ordering::Relaxed);
    }

    /// Учитывает ошибку журнала, которую вызывающая сторона обработала сама.
    pub(crate) fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Снимок счётчиков.
    pub fn metrics(&self) -> JournalMetrics {
        JournalMetrics {
            intents: self.intents.load(Ordering::Relaxed),
            replays: self.replays.load(Ordering::Relaxed),
            compactions: self.compactions.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
        }
    }

    /// Применяет незавершённые намерения к store.
    ///
    /// Вызывается один раз на старте, до запуска транспортов.
    ///
    /// # Errors
    ///
    /// [`JournalError::Recovery`] при ошибке хранилища; незавершённое
    /// намерение остаётся в журнале для следующей попытки.
    pub fn recover(&self, store: &dyn ZoneAdmin) -> Result<RecoveryReport, JournalError> {
        let pending: Vec<IntentRecord> = {
            let inner = self.lock();
            inner
                .entries
                .iter()
                .filter(|entry| matches!(&entry.status, EntryStatus::Pending))
                .filter_map(|entry| entry.intent.clone())
                .collect()
        };
        let mut report = RecoveryReport {
            pending: pending.len(),
            truncated_bytes: {
                let inner = self.lock();
                inner.truncated_bytes
            },
            ..RecoveryReport::default()
        };
        for intent in pending {
            match intent.operation.already_applied(store) {
                Ok(Some(version)) => {
                    self.write_committed(&intent.op_id, version, None)?;
                    report.skipped = report.skipped.saturating_add(1);
                    self.replays.fetch_add(1, Ordering::Relaxed);
                }
                Ok(None) => match intent.apply(store) {
                    Ok(version) => {
                        self.write_committed(&intent.op_id, version, None)?;
                        report.replayed = report.replayed.saturating_add(1);
                        self.replays.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(error) if is_client_error(&error) => {
                        self.write_aborted(&intent.op_id, &error_code(&error), false, None)?;
                        report.aborted = report.aborted.saturating_add(1);
                    }
                    Err(error) => {
                        return Err(JournalError::Recovery {
                            op_id: intent.op_id,
                            reason: error.to_string(),
                        });
                    }
                },
                Err(error) => {
                    return Err(JournalError::Recovery {
                        op_id: intent.op_id,
                        reason: error.to_string(),
                    });
                }
            }
        }
        self.maybe_compact();
        Ok(report)
    }

    pub(crate) fn begin(&self, intent: IntentRecord) -> Result<Begin, JournalError> {
        let mut inner = self.lock();
        if let Some(&position) = inner.index.get(&intent.op_id) {
            let entry = inner.entries.get(position);
            if let Some(existing) = entry.and_then(|entry| entry.intent.as_ref()) {
                if existing.body_sha256 != intent.body_sha256 {
                    return Ok(Begin::Conflict);
                }
            }
            return Ok(match entry.map(|entry| &entry.status) {
                Some(EntryStatus::Pending) => Begin::Pending,
                Some(EntryStatus::Committed { version, response }) => match response {
                    Some(response) => Begin::Response(response.clone()),
                    None => Begin::Committed { version: *version },
                },
                Some(EntryStatus::Aborted {
                    reason,
                    retryable,
                    response,
                }) => {
                    if *retryable {
                        let seq = inner.next_seq;
                        append_record(
                            &mut inner,
                            &self.path,
                            self.fsync,
                            &Record::Intent {
                                seq,
                                intent: intent.clone(),
                            },
                        )?;
                        if let Some(position) = inner.index.get(&intent.op_id).copied() {
                            if let Some(entry) = inner.entries.get_mut(position) {
                                entry.intent = Some(intent.clone());
                                entry.status = EntryStatus::Pending;
                            }
                        }
                        self.intents.fetch_add(1, Ordering::Relaxed);
                        drop(inner);
                        self.maybe_compact();
                        return Ok(Begin::New);
                    }
                    match response {
                        Some(response) => Begin::Response(response.clone()),
                        None => Begin::Aborted {
                            reason: reason.clone(),
                        },
                    }
                }
                None => Begin::New,
            });
        }
        let seq = inner.next_seq;
        append_record(
            &mut inner,
            &self.path,
            self.fsync,
            &Record::Intent {
                seq,
                intent: intent.clone(),
            },
        )?;
        let position = inner.entries.len();
        inner.entries.push(Entry {
            op_id: intent.op_id.clone(),
            intent: Some(intent.clone()),
            status: EntryStatus::Pending,
        });
        inner.index.insert(intent.op_id, position);
        self.intents.fetch_add(1, Ordering::Relaxed);
        drop(inner);
        self.maybe_compact();
        Ok(Begin::New)
    }

    pub(crate) fn commit(
        &self,
        op_id: &str,
        version: u64,
        response: Option<&HttpResponse>,
    ) -> Result<(), JournalError> {
        if take_fault("commit") {
            self.errors.fetch_add(1, Ordering::Relaxed);
            return Err(JournalError::Injected("commit"));
        }
        self.write_committed(op_id, version, response)
    }

    pub(crate) fn abort(
        &self,
        op_id: &str,
        reason: &str,
        retryable: bool,
        response: Option<&HttpResponse>,
    ) -> Result<(), JournalError> {
        self.write_aborted(op_id, reason, retryable, response)
    }

    fn write_committed(
        &self,
        op_id: &str,
        version: u64,
        response: Option<&HttpResponse>,
    ) -> Result<(), JournalError> {
        let stored = response.map(StoredResponse::capture);
        let mut inner = self.lock();
        if let Some(entry) = inner
            .index
            .get(op_id)
            .and_then(|position| inner.entries.get(*position))
        {
            if matches!(&entry.status, EntryStatus::Committed { .. }) {
                return Ok(());
            }
        }
        let wire = stored
            .clone()
            .map(|response| StoredResponseWire::capture(&response));
        let seq = inner.next_seq;
        append_record(
            &mut inner,
            &self.path,
            self.fsync,
            &Record::Committed {
                seq,
                op_id: op_id.to_owned(),
                version,
                response: wire,
            },
        )?;
        update_status(
            &mut inner,
            op_id,
            EntryStatus::Committed {
                version,
                response: stored,
            },
        );
        drop(inner);
        self.maybe_compact();
        Ok(())
    }

    fn write_aborted(
        &self,
        op_id: &str,
        reason: &str,
        retryable: bool,
        response: Option<&HttpResponse>,
    ) -> Result<(), JournalError> {
        let stored = response.map(StoredResponse::capture);
        let mut inner = self.lock();
        if let Some(entry) = inner
            .index
            .get(op_id)
            .and_then(|position| inner.entries.get(*position))
        {
            if matches!(&entry.status, EntryStatus::Aborted { .. }) {
                return Ok(());
            }
        }
        let wire = stored
            .clone()
            .map(|response| StoredResponseWire::capture(&response));
        let seq = inner.next_seq;
        append_record(
            &mut inner,
            &self.path,
            self.fsync,
            &Record::Aborted {
                seq,
                op_id: op_id.to_owned(),
                reason: reason.to_owned(),
                retryable,
                response: wire,
            },
        )?;
        update_status(
            &mut inner,
            op_id,
            EntryStatus::Aborted {
                reason: reason.to_owned(),
                retryable,
                response: stored,
            },
        );
        drop(inner);
        self.maybe_compact();
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn maybe_compact(&self) {
        let should = {
            let inner = self.lock();
            inner.size >= self.max_bytes
        };
        if !should {
            return;
        }
        if let Err(error) = self.compact() {
            self.errors.fetch_add(1, Ordering::Relaxed);
            log_error(&format!("journal compaction failed: {error}"));
        }
    }

    /// Переписывает журнал, сохраняя незавершённые намерения и последние
    /// `retain_resolved` завершённых.
    ///
    /// # Errors
    ///
    /// [`JournalError`] при ошибке I/O; старый файл остаётся нетронутым.
    pub fn compact(&self) -> Result<(), JournalError> {
        let mut inner = self.lock();
        let keep = compaction_set(&inner.entries, self.retain_resolved);
        let mut bytes = Vec::new();
        write_header_bytes(&mut bytes);
        let mut seq = 1_u64;
        for position in &keep {
            let Some(entry) = inner.entries.get(*position) else {
                continue;
            };
            if let Some(intent) = &entry.intent {
                encode_record(
                    &mut bytes,
                    &Record::Intent {
                        seq,
                        intent: intent.clone(),
                    },
                )?;
                seq = seq.saturating_add(1);
            }
            match &entry.status {
                EntryStatus::Pending => {}
                EntryStatus::Committed { version, response } => {
                    encode_record(
                        &mut bytes,
                        &Record::Committed {
                            seq,
                            op_id: entry.op_id.clone(),
                            version: *version,
                            response: response
                                .clone()
                                .map(|response| StoredResponseWire::capture(&response)),
                        },
                    )?;
                    seq = seq.saturating_add(1);
                }
                EntryStatus::Aborted {
                    reason,
                    retryable,
                    response,
                } => {
                    encode_record(
                        &mut bytes,
                        &Record::Aborted {
                            seq,
                            op_id: entry.op_id.clone(),
                            reason: reason.clone(),
                            retryable: *retryable,
                            response: response
                                .clone()
                                .map(|response| StoredResponseWire::capture(&response)),
                        },
                    )?;
                    seq = seq.saturating_add(1);
                }
            }
        }
        let temp = temp_path(&self.path);
        write_atomic(&temp, &self.path, &bytes)?;
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .open(&self.path)
            .map_err(|error| JournalError::io(&self.path, "reopen after compaction", error))?;
        inner.file = file;
        inner.size = bytes.len() as u64;
        inner.next_seq = seq;
        let mut kept_entries = Vec::with_capacity(keep.len());
        let mut index = HashMap::with_capacity(keep.len());
        for position in keep {
            if let Some(entry) = inner.entries.get(position) {
                index.insert(entry.op_id.clone(), kept_entries.len());
                kept_entries.push(entry.clone());
            }
        }
        inner.entries = kept_entries;
        inner.index = index;
        drop(inner);
        self.compactions.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

/// Строит намерение из запроса.
pub(crate) fn intent(
    op_id: &str,
    method: &str,
    path: &str,
    body_sha256: &str,
    preconditions: &Preconditions,
    operation: JournalOp,
) -> IntentRecord {
    let expected_etag = preconditions.if_match.as_ref().map(precondition_text);
    let if_none_match = preconditions.if_none_match.as_ref().map(precondition_text);
    let expected_version = expected_etag.as_deref().and_then(version_from_etag);
    IntentRecord {
        op_id: op_id.to_owned(),
        timestamp_unix_ns: now_unix_ns(),
        method: method.to_owned(),
        path: path.to_owned(),
        body_sha256: body_sha256.to_owned(),
        expected_etag,
        expected_version,
        if_none_match,
        operation,
    }
}

/// Хеш тела запроса в hex.
pub(crate) fn body_hash_hex(body: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(body);
    let digest = hasher.finalize();
    hex_lower(&digest)
}

/// Точка аварийного завершения для crash-тестов (debug-сборка).
pub(crate) fn crash_point(name: &str) {
    if !cfg!(debug_assertions) {
        return;
    }
    let Ok(wanted) = std::env::var("PULSED_JOURNAL_CRASH") else {
        return;
    };
    if wanted != name {
        return;
    }
    let pid = std::process::id().to_string();
    let _ = std::process::Command::new("kill")
        .arg("-9")
        .arg(pid)
        .status();
    std::process::abort();
}

fn take_fault(name: &str) -> bool {
    if !cfg!(debug_assertions) {
        return false;
    }
    static FIRED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    let Ok(spec) = std::env::var("PULSED_JOURNAL_FAULT") else {
        return false;
    };
    if !spec.split(',').any(|item| item == name) {
        return false;
    }
    !FIRED.swap(true, Ordering::SeqCst)
}

impl IntentRecord {
    fn preconditions(&self) -> Preconditions {
        Preconditions {
            if_match: self.expected_etag.as_deref().map(parse_precondition),
            if_none_match: self.if_none_match.as_deref().map(parse_precondition),
        }
    }

    fn apply(&self, store: &dyn ZoneAdmin) -> Result<u64, AdminError> {
        let preconditions = self.preconditions();
        match &self.operation {
            JournalOp::PutZone {
                origin,
                kind,
                default_ttl,
                denial,
            } => {
                let origin = parse_name(origin)?;
                let kind = ZoneKind::parse(kind)
                    .ok_or_else(|| admin_parse("journal: invalid zone kind"))?;
                let default_ttl = pulse_dns::Ttl::new(*default_ttl)
                    .map_err(|error| admin_parse(&format!("journal: invalid ttl: {error}")))?;
                let denial = crate::port::Denial::parse(denial)
                    .ok_or_else(|| admin_parse("journal: invalid denial"))?;
                let meta = ZoneMetaInput {
                    kind,
                    default_ttl,
                    denial,
                };
                let outcome = store.put_zone(&origin, &meta, &preconditions)?;
                Ok(outcome.value().version)
            }
            JournalOp::DeleteZone { origin } => {
                let origin = parse_name(origin)?;
                store.delete_zone(&origin, &preconditions)?;
                Ok(0)
            }
            JournalOp::PutRrset {
                origin,
                owner,
                rr_type,
                ttl,
                records,
            } => {
                let origin = parse_name(origin)?;
                let owner = parse_name(owner)?;
                let rr_type = parse_journal_rtype(rr_type)?;
                let ttl = pulse_dns::Ttl::new(*ttl)
                    .map_err(|error| admin_parse(&format!("journal: invalid ttl: {error}")))?;
                let rdata = parse_records(records, rr_type)?;
                let input = RrsetInput { ttl, rdata };
                store.put_rrset(&origin, &owner, rr_type, &input, &preconditions)?;
                version_of(store, &origin)
            }
            JournalOp::PatchRrset {
                origin,
                owner,
                rr_type,
                ttl,
                add,
                remove,
            } => {
                let origin = parse_name(origin)?;
                let owner = parse_name(owner)?;
                let rr_type = parse_journal_rtype(rr_type)?;
                let ttl = ttl
                    .map(pulse_dns::Ttl::new)
                    .transpose()
                    .map_err(|error| admin_parse(&format!("journal: invalid ttl: {error}")))?;
                let patch = RrsetPatch {
                    ttl,
                    add: parse_records(add, rr_type)?,
                    remove: parse_records(remove, rr_type)?,
                };
                store.patch_rrset(&origin, &owner, rr_type, &patch, &preconditions)?;
                version_of(store, &origin)
            }
            JournalOp::DeleteRrset {
                origin,
                owner,
                rr_type,
            } => {
                let origin = parse_name(origin)?;
                let owner = parse_name(owner)?;
                let rr_type = parse_journal_rtype(rr_type)?;
                store.delete_rrset(&origin, &owner, rr_type, &preconditions)?;
                version_of(store, &origin)
            }
            JournalOp::PatchSettings {
                origin,
                default_ttl,
                denial,
            } => {
                let origin = parse_name(origin)?;
                let default_ttl = default_ttl
                    .map(pulse_dns::Ttl::new)
                    .transpose()
                    .map_err(|error| admin_parse(&format!("journal: invalid ttl: {error}")))?;
                let denial = match denial {
                    None => None,
                    Some(value) => Some(
                        crate::port::Denial::parse(value)
                            .ok_or_else(|| admin_parse("journal: invalid denial"))?,
                    ),
                };
                let patch = ZoneSettingsPatch {
                    default_ttl,
                    denial,
                };
                let view = store.patch_settings(&origin, &patch, &preconditions)?;
                Ok(view.version)
            }
        }
    }
}

impl JournalOp {
    pub(crate) fn already_applied(&self, store: &dyn ZoneAdmin) -> Result<Option<u64>, AdminError> {
        match self {
            JournalOp::PutZone {
                origin,
                kind,
                default_ttl,
                denial,
            } => {
                let origin = parse_name(origin)?;
                match store.get_zone(&origin) {
                    Ok(zone) => {
                        let same = zone.kind.as_str() == kind
                            && zone.default_ttl.as_u32() == *default_ttl
                            && zone.denial.as_str() == denial;
                        Ok(same.then_some(zone.version))
                    }
                    Err(AdminError::NotFound(NotFound::Zone)) => Ok(None),
                    Err(error) => Err(error),
                }
            }
            JournalOp::DeleteZone { origin } => {
                let origin = parse_name(origin)?;
                match store.get_zone(&origin) {
                    Ok(_) => Ok(None),
                    Err(AdminError::NotFound(NotFound::Zone)) => Ok(Some(0)),
                    Err(error) => Err(error),
                }
            }
            JournalOp::PutRrset {
                origin,
                owner,
                rr_type,
                ttl,
                records,
            } => {
                let origin_name = parse_name(origin)?;
                let owner_name = parse_name(owner)?;
                let rr_type = parse_journal_rtype(rr_type)?;
                let expected = parse_records(records, rr_type)?;
                match store.get_rrset(&origin_name, &owner_name, rr_type) {
                    Ok(view) => {
                        let same =
                            view.ttl.as_u32() == *ttl && as_set(&view.rdata) == as_set(&expected);
                        if same {
                            version_of(store, &origin_name).map(Some)
                        } else {
                            Ok(None)
                        }
                    }
                    Err(AdminError::NotFound(_)) => Ok(None),
                    Err(error) => Err(error),
                }
            }
            JournalOp::PatchRrset {
                origin,
                owner,
                rr_type,
                ttl,
                add,
                remove,
            } => {
                let origin_name = parse_name(origin)?;
                let owner_name = parse_name(owner)?;
                let rr_type = parse_journal_rtype(rr_type)?;
                let add = parse_records(add, rr_type)?;
                let remove = parse_records(remove, rr_type)?;
                match store.get_rrset(&origin_name, &owner_name, rr_type) {
                    Ok(view) => {
                        let current: std::collections::BTreeSet<Rdata> =
                            view.rdata.iter().cloned().collect();
                        let ttl_ok = ttl.is_none_or(|ttl| view.ttl.as_u32() == ttl);
                        let add_ok = add.iter().all(|record| current.contains(record));
                        let remove_ok = remove.iter().all(|record| !current.contains(record));
                        if ttl_ok && add_ok && remove_ok {
                            version_of(store, &origin_name).map(Some)
                        } else {
                            Ok(None)
                        }
                    }
                    Err(AdminError::NotFound(_)) => {
                        // PATCH, удаливший последнюю запись, оставляет RRset
                        // отсутствующим.
                        if add.is_empty() {
                            version_of(store, &origin_name).map(Some)
                        } else {
                            Ok(None)
                        }
                    }
                    Err(error) => Err(error),
                }
            }
            JournalOp::DeleteRrset {
                origin,
                owner,
                rr_type,
            } => {
                let origin_name = parse_name(origin)?;
                let owner_name = parse_name(owner)?;
                let rr_type = parse_journal_rtype(rr_type)?;
                match store.get_rrset(&origin_name, &owner_name, rr_type) {
                    Ok(_) => Ok(None),
                    Err(AdminError::NotFound(_)) => version_of(store, &origin_name).map(Some),
                    Err(error) => Err(error),
                }
            }
            JournalOp::PatchSettings {
                origin,
                default_ttl,
                denial,
            } => {
                let origin = parse_name(origin)?;
                match store.get_settings(&origin) {
                    Ok(view) => {
                        let ttl_ok =
                            default_ttl.is_none_or(|ttl| view.settings.default_ttl.as_u32() == ttl);
                        let denial_ok = denial
                            .as_deref()
                            .is_none_or(|denial| view.settings.denial.as_str() == denial);
                        Ok((ttl_ok && denial_ok).then_some(view.version))
                    }
                    Err(AdminError::NotFound(_)) => Ok(None),
                    Err(error) => Err(error),
                }
            }
        }
    }
}

fn version_of(store: &dyn ZoneAdmin, origin: &Name) -> Result<u64, AdminError> {
    match store.get_zone(origin) {
        Ok(zone) => Ok(zone.version),
        // Операция удалила последний ресурс зоны/саму зону: версии нет,
        // но намерение уже применено.
        Err(AdminError::NotFound(NotFound::Zone)) => Ok(0),
        Err(error) => Err(error),
    }
}

fn as_set(records: &[Rdata]) -> std::collections::BTreeSet<Rdata> {
    records.iter().cloned().collect()
}

fn parse_records(records: &[String], rr_type: Rtype) -> Result<Vec<Rdata>, AdminError> {
    records
        .iter()
        .map(|record| {
            parse_rdata(rr_type, record)
                .map_err(|error| admin_parse(&format!("journal: invalid rdata: {error}")))
        })
        .collect()
}

fn parse_journal_rtype(value: &str) -> Result<Rtype, AdminError> {
    parse_rtype(value).ok_or_else(|| admin_parse("journal: invalid rr type"))
}

fn parse_name(value: &str) -> Result<Name, AdminError> {
    Name::parse(value).map_err(|error| admin_parse(&format!("journal: invalid name: {error}")))
}

fn admin_parse(reason: &str) -> AdminError {
    AdminError::Storage(reason.to_owned())
}

fn precondition_text(precondition: &Precondition) -> String {
    match precondition {
        Precondition::Any => "*".to_owned(),
        Precondition::Tag(tag) => tag.clone(),
        Precondition::Tags(tags) => tags.join(","),
    }
}

fn parse_precondition(value: &str) -> Precondition {
    if value.trim() == "*" {
        return Precondition::Any;
    }
    let tags: Vec<String> = value
        .split(',')
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .map(str::to_owned)
        .collect();
    if tags.len() == 1 {
        tags.into_iter()
            .next()
            .map_or(Precondition::Any, Precondition::Tag)
    } else {
        Precondition::Tags(tags)
    }
}

fn version_from_etag(tag: &str) -> Option<u64> {
    let version = tag.split("-v").nth(1)?.split('-').next()?;
    version.parse().ok()
}

fn update_status(inner: &mut Inner, op_id: &str, status: EntryStatus) {
    if let Some(position) = inner.index.get(op_id).copied() {
        if let Some(entry) = inner.entries.get_mut(position) {
            entry.status = status;
        }
    }
}

fn is_client_error(error: &AdminError) -> bool {
    matches!(
        error,
        AdminError::NotFound(_)
            | AdminError::Conflict(_)
            | AdminError::PreconditionFailed { .. }
            | AdminError::PreconditionRequired
            | AdminError::InvariantViolation(_)
            | AdminError::InvalidCursor
            | AdminError::Busy
    )
}

fn error_code(error: &AdminError) -> String {
    match error {
        AdminError::NotFound(NotFound::Zone) => "zone_not_found",
        AdminError::NotFound(NotFound::Rrset) => "rrset-not-found",
        AdminError::Conflict(crate::error::Conflict::ZoneExists) => "zone-exists",
        AdminError::Conflict(crate::error::Conflict::RrsetExists) => "rrset-exists",
        AdminError::Conflict(crate::error::Conflict::ZoneBusy) | AdminError::Busy => "zone-busy",
        AdminError::Conflict(crate::error::Conflict::ZoneReadOnly) => "zone-read-only",
        AdminError::PreconditionFailed { .. } => "precondition-failed",
        AdminError::PreconditionRequired => "precondition-required",
        AdminError::InvariantViolation(_) => "validation-failed",
        AdminError::InvalidCursor => "bad-request",
        AdminError::Internal | AdminError::Storage(_) => "storage-error",
    }
    .to_owned()
}

fn log_error(message: &str) {
    eprintln!("journal error: {message}");
}

fn now_unix_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
        })
}

fn write_header(file: &mut File, path: &Path) -> Result<(), JournalError> {
    let mut header = Vec::with_capacity(HEADER_LEN);
    write_header_bytes(&mut header);
    file.write_all(&header)
        .map_err(|error| JournalError::io(path, "write header", error))?;
    sync_data(file, path)
}

fn write_header_bytes(out: &mut Vec<u8>) {
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    let crc = crc32(out.get(..12).unwrap_or_default());
    out.extend_from_slice(&crc.to_le_bytes());
}

fn version_of_partial_header(bytes: &[u8]) -> Option<u32> {
    bytes
        .get(8..12)
        .and_then(|slice| <[u8; 4]>::try_from(slice).ok())
        .map(u32::from_le_bytes)
}

fn validate_header(path: &Path, bytes: &[u8]) -> Result<(), JournalError> {
    if bytes.len() < HEADER_LEN {
        return Err(JournalError::Corrupt {
            path: path.to_path_buf(),
            reason: "file is shorter than the journal header".to_owned(),
        });
    }
    if bytes.get(..8).is_none_or(|magic| magic != MAGIC) {
        return Err(JournalError::Corrupt {
            path: path.to_path_buf(),
            reason: "bad magic; not a pulse journal".to_owned(),
        });
    }
    let Some(version_bytes) = bytes
        .get(8..12)
        .and_then(|slice| <[u8; 4]>::try_from(slice).ok())
    else {
        return Err(JournalError::Corrupt {
            path: path.to_path_buf(),
            reason: "journal header is truncated".to_owned(),
        });
    };
    let Some(crc_bytes) = bytes
        .get(12..16)
        .and_then(|slice| <[u8; 4]>::try_from(slice).ok())
    else {
        return Err(JournalError::Corrupt {
            path: path.to_path_buf(),
            reason: "journal header is truncated".to_owned(),
        });
    };
    let version = u32::from_le_bytes(version_bytes);
    let crc = u32::from_le_bytes(crc_bytes);
    if version != FORMAT_VERSION {
        return Err(JournalError::IncompatibleVersion {
            path: path.to_path_buf(),
            found: version,
            supported: FORMAT_VERSION,
        });
    }
    if crc != crc32(bytes.get(..12).unwrap_or_default()) {
        return Err(JournalError::Corrupt {
            path: path.to_path_buf(),
            reason: "header checksum mismatch".to_owned(),
        });
    }
    Ok(())
}

struct Scan {
    valid_end: usize,
}

fn scan_records(bytes: &[u8], inner: &mut Inner) -> Scan {
    let mut cursor = HEADER_LEN;
    while cursor < bytes.len() {
        let Some(header) = bytes.get(cursor..cursor.saturating_add(FRAME_HEADER_LEN)) else {
            break;
        };
        let Ok(length_bytes) = <[u8; 4]>::try_from(header.get(..4).unwrap_or_default()) else {
            break;
        };
        let Ok(checksum_bytes) = <[u8; 4]>::try_from(header.get(4..8).unwrap_or_default()) else {
            break;
        };
        let length = u32::from_le_bytes(length_bytes);
        let checksum = u32::from_le_bytes(checksum_bytes);
        let length = usize::try_from(length).unwrap_or(usize::MAX);
        if length == 0 || length > MAX_RECORD_BYTES {
            break;
        }
        let start = cursor.saturating_add(FRAME_HEADER_LEN);
        let Some(payload) = bytes.get(start..start.saturating_add(length)) else {
            break;
        };
        if crc32(payload) != checksum {
            break;
        }
        let Ok(record) = serde_json::from_slice::<Record>(payload) else {
            break;
        };
        apply_record(inner, record);
        cursor = start.saturating_add(length);
    }
    Scan { valid_end: cursor }
}

fn apply_record(inner: &mut Inner, record: Record) {
    inner.next_seq = inner.next_seq.max(record.seq().saturating_add(1));
    match record {
        Record::Intent { intent, .. } => {
            if let Some(position) = inner.index.get(&intent.op_id).copied() {
                if let Some(entry) = inner.entries.get_mut(position) {
                    if matches!(
                        &entry.status,
                        EntryStatus::Aborted {
                            retryable: true,
                            ..
                        }
                    ) {
                        entry.intent = Some(intent);
                        entry.status = EntryStatus::Pending;
                    }
                }
                return;
            }
            let position = inner.entries.len();
            inner.index.insert(intent.op_id.clone(), position);
            inner.entries.push(Entry {
                op_id: intent.op_id.clone(),
                intent: Some(intent),
                status: EntryStatus::Pending,
            });
        }
        Record::Committed {
            op_id,
            version,
            response,
            ..
        } => {
            let response = response.map(StoredResponseWire::into_response);
            let status = EntryStatus::Committed { version, response };
            if let Some(position) = inner.index.get(&op_id).copied() {
                if let Some(entry) = inner.entries.get_mut(position) {
                    entry.status = status;
                }
            } else {
                let position = inner.entries.len();
                inner.index.insert(op_id.clone(), position);
                inner.entries.push(Entry {
                    op_id,
                    intent: None,
                    status,
                });
            }
        }
        Record::Aborted {
            op_id,
            reason,
            retryable,
            response,
            ..
        } => {
            let response = response.map(StoredResponseWire::into_response);
            let status = EntryStatus::Aborted {
                reason,
                retryable,
                response,
            };
            if let Some(position) = inner.index.get(&op_id).copied() {
                if let Some(entry) = inner.entries.get_mut(position) {
                    entry.status = status;
                }
            } else {
                let position = inner.entries.len();
                inner.index.insert(op_id.clone(), position);
                inner.entries.push(Entry {
                    op_id,
                    intent: None,
                    status,
                });
            }
        }
    }
}

fn scan_next_seq(inner: &Inner) -> u64 {
    inner.next_seq.max(1)
}

fn append_record(
    inner: &mut Inner,
    path: &Path,
    fsync: bool,
    record: &Record,
) -> Result<(), JournalError> {
    let mut bytes = Vec::new();
    encode_record(&mut bytes, record)?;
    inner
        .file
        .write_all(&bytes)
        .map_err(|error| JournalError::io(path, "append", error))?;
    if fsync {
        sync_data(&inner.file, path)?;
    }
    inner.size = inner.size.saturating_add(bytes.len() as u64);
    inner.next_seq = inner.next_seq.max(record.seq().saturating_add(1));
    Ok(())
}

fn encode_record(out: &mut Vec<u8>, record: &Record) -> Result<(), JournalError> {
    let payload = serde_json::to_vec(record)
        .map_err(|error| JournalError::Config(format!("cannot encode journal record: {error}")))?;
    if payload.len() > MAX_RECORD_BYTES {
        return Err(JournalError::Config(format!(
            "journal record of {} bytes exceeds the {MAX_RECORD_BYTES}-byte limit",
            payload.len()
        )));
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| JournalError::Config("journal record is too large".to_owned()))?;
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(&crc32(&payload).to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(())
}

fn compaction_set(entries: &[Entry], retain_resolved: usize) -> Vec<usize> {
    let resolved: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| !matches!(&entry.status, EntryStatus::Pending))
        .map(|(position, _)| position)
        .collect();
    let keep_resolved = resolved.len().saturating_sub(retain_resolved);
    let mut keep: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter(|(position, entry)| {
            matches!(&entry.status, EntryStatus::Pending)
                || resolved
                    .get(keep_resolved..)
                    .is_some_and(|tail| tail.contains(position))
        })
        .map(|(position, _)| position)
        .collect();
    keep.sort_unstable();
    keep
}

fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".compact");
    PathBuf::from(name)
}

fn write_atomic(temp: &Path, target: &Path, bytes: &[u8]) -> Result<(), JournalError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(temp)
        .map_err(|error| JournalError::io(temp, "create compaction file", error))?;
    file.write_all(bytes)
        .map_err(|error| JournalError::io(temp, "write compaction file", error))?;
    file.sync_all()
        .map_err(|error| JournalError::io(temp, "sync compaction file", error))?;
    std::fs::rename(temp, target)
        .map_err(|error| JournalError::io(target, "rename compaction file", error))?;
    if let Some(parent) = target.parent() {
        if let Ok(directory) = File::open(parent) {
            let _ = directory.sync_all();
        }
    }
    Ok(())
}

fn sync_data(file: &File, path: &Path) -> Result<(), JournalError> {
    file.sync_data()
        .map_err(|error| JournalError::io(path, "fsync", error))
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFF_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent(op_id: &str) -> IntentRecord {
        IntentRecord {
            op_id: op_id.to_owned(),
            timestamp_unix_ns: 1,
            method: "PUT".to_owned(),
            path: "/api/v1/zones/example.com.".to_owned(),
            body_sha256: "00".to_owned(),
            expected_etag: None,
            expected_version: None,
            if_none_match: None,
            operation: JournalOp::DeleteZone {
                origin: "example.com.".to_owned(),
            },
        }
    }

    fn journal(path: &Path) -> Journal {
        Journal::open(JournalConfig {
            path: path.to_path_buf(),
            max_bytes: 4096,
            fsync: true,
            retain_resolved: 2,
        })
        .expect("journal")
    }

    #[test]
    fn roundtrip_intent_then_committed() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("data.journal");
        let log = journal(&path);
        assert!(matches!(
            log.begin(intent("op1")).expect("begin"),
            Begin::New
        ));
        log.commit("op1", 7, None).expect("commit");
        drop(log);
        let reopened = journal(&path);
        let inner = reopened.lock();
        assert_eq!(inner.entries.len(), 1);
        assert!(matches!(
            inner.entries[0].status,
            EntryStatus::Committed { version: 7, .. }
        ));
    }

    #[test]
    fn corrupt_tail_is_truncated_and_previous_kept() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("data.journal");
        let log = journal(&path);
        log.begin(intent("op1")).expect("begin");
        log.commit("op1", 1, None).expect("commit");
        log.begin(intent("op2")).expect("begin");
        drop(log);
        let mut file = OpenOptions::new().append(true).open(&path).expect("open");
        file.write_all(&[0xFF; 7]).expect("corrupt");
        drop(file);
        let reopened = journal(&path);
        let inner = reopened.lock();
        assert_eq!(inner.entries.len(), 2);
        assert!(matches!(inner.entries[1].status, EntryStatus::Pending));
        drop(inner);
        let len = std::fs::metadata(&path).expect("stat").len();
        let reopened2 = journal(&path);
        drop(reopened2);
        assert_eq!(std::fs::metadata(&path).expect("stat").len(), len);
    }

    #[test]
    fn same_key_different_body_conflicts() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("data.journal");
        let log = journal(&path);
        assert!(matches!(
            log.begin(intent("op1")).expect("begin"),
            Begin::New
        ));
        let mut changed = intent("op1");
        changed.body_sha256 = "ff".to_owned();
        assert!(matches!(
            log.begin(changed).expect("begin"),
            Begin::Conflict
        ));
    }

    #[test]
    fn incompatible_version_is_rejected() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("data.journal");
        std::fs::write(&path, b"PULSEJNL\x02\x00\x00\x00\x00\x00\x00\x00").expect("write");
        assert!(matches!(
            Journal::open(JournalConfig::new(&path)),
            Err(JournalError::IncompatibleVersion { found: 2, .. })
        ));
    }

    #[test]
    fn compaction_keeps_pending_and_bounds_resolved() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("data.journal");
        let log = journal(&path);
        for index in 0..10 {
            let op = format!("op{index}");
            log.begin(intent(&op)).expect("begin");
            log.commit(&op, index, None).expect("commit");
        }
        log.begin(intent("pending")).expect("begin");
        log.compact().expect("compact");
        let inner = log.lock();
        assert!(inner.entries.iter().any(|entry| {
            entry.intent.as_ref().is_some_and(|i| i.op_id == "pending")
                && matches!(&entry.status, EntryStatus::Pending)
        }));
        let resolved = inner
            .entries
            .iter()
            .filter(|entry| !matches!(&entry.status, EntryStatus::Pending))
            .count();
        assert_eq!(resolved, 2);
    }

    #[test]
    fn version_from_zone_etag() {
        assert_eq!(version_from_etag("z1-v42-t9"), Some(42));
        assert_eq!(version_from_etag("rr_deadbeef"), None);
    }
}
