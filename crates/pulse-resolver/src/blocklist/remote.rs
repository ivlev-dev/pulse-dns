//! Blocklist-источники по HTTPS: скачивание, условные запросы и кэш.
//!
//! Менеджер [`RemoteBlocklist`] не блокирует горячий путь резолвера: он
//! держит тексты источников, скачивает их по `GET`, поддерживает
//! `If-None-Match`/`If-Modified-Since`, лимит размера, таймауты, повторы с
//! backoff и ограниченные редиректы (по умолчанию выключены, разрешён один
//! переход на тот же хост). Скачанный снимок атомарно пишется в
//! `cache_dir/<hash>.list` (права `0600`), метаданные (`ETag`,
//! `Last-Modified`, время) — в `<hash>.meta`.
//!
//! При старте [`RemoteBlocklist::new`] поднимает последний снимок из кэша;
//! первый сетевой запрос выполняется в фоне вызывающим кодом. При ошибке
//! сети/размера/редиректа старый текст остаётся в силе (fail-safe).
//!
//! Защита от SSRF: только `https`, проверка TLS по `webpki-roots` плюс
//! дополнительный PEM-CA, опциональный `allow_hosts` и запрет приватных
//! адресов для хостов вне этого списка.

use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use thiserror::Error;

/// Периодичность обновления по умолчанию (24 часа).
pub const DEFAULT_REFRESH_SECS: u64 = 86_400;
/// Лимит размера одного источника по умолчанию (64 MiB).
pub const DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024;
/// Таймаут одной попытки скачивания по умолчанию.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// Число повторов после первой неудачной попытки.
pub const DEFAULT_RETRIES: u32 = 2;
/// Начальный backoff между повторами.
pub const DEFAULT_BACKOFF: Duration = Duration::from_secs(1);

const MAX_URL_BYTES: usize = 2048;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_CHUNK_LINE_BYTES: usize = 1024;
const MAX_TRAILER_BYTES: usize = 4096;
const MAX_REDIRECTS: usize = 1;
const CACHE_META_LIMIT: u64 = 64 * 1024;
const MAX_BACKOFF: Duration = Duration::from_secs(3600);

/// Формат удалённого источника.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SourceFormat {
    /// Автоопределение: hosts-строки (`IP domain…`) и plain-домены.
    #[default]
    Auto,
    /// Только hosts-формат (строки с IP-адресом); `@@allow` разрешён.
    Hosts,
    /// Только plain-домены: одна запись в строке.
    Domains,
}

/// Описание удалённого источника.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSource {
    /// URL вида `https://host/path` (только HTTPS).
    pub url: String,
    /// Индивидуальная периодичность; `None` — общая, `0` — только вручную.
    pub refresh_secs: Option<u64>,
    /// Ожидаемый формат.
    pub format: SourceFormat,
}

impl RemoteSource {
    /// Создаёт источник с автоопределением формата.
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            refresh_secs: None,
            format: SourceFormat::Auto,
        }
    }

    /// Задаёт индивидуальную периодичность.
    #[must_use]
    pub fn with_refresh_secs(mut self, refresh_secs: u64) -> Self {
        self.refresh_secs = Some(refresh_secs);
        self
    }

    /// Задаёт формат источника.
    #[must_use]
    pub const fn with_format(mut self, format: SourceFormat) -> Self {
        self.format = format;
        self
    }

    /// Проверяет, что URL корректен и использует HTTPS.
    ///
    /// # Errors
    ///
    /// [`RemoteError::InvalidUrl`] или [`RemoteError::NotHttps`].
    pub fn validate_url(&self) -> Result<(), RemoteError> {
        parse_https_url(&self.url).map(|_| ())
    }
}

/// Параметры удалённых blocklist-источников.
#[derive(Debug, Clone)]
pub struct RemoteBlocklistConfig {
    /// Источники в порядке объединения.
    pub sources: Vec<RemoteSource>,
    /// Общая периодичность в секундах (0 — только SIGHUP/API).
    pub refresh_secs: u64,
    /// Каталог кэша.
    pub cache_dir: PathBuf,
    /// Лимит размера одного источника.
    pub max_bytes: u64,
    /// Разрешить один редирект на тот же хост.
    pub allow_redirects: bool,
    /// Разрешённые хосты источников; пусто — любой публичный хост.
    pub allow_hosts: Vec<String>,
    /// Таймаут одной попытки (включая TLS и чтение тела).
    pub timeout: Duration,
    /// Число повторов после первой неудачной попытки.
    pub retries: u32,
    /// Начальный backoff между повторами.
    pub backoff: Duration,
    /// Дополнительный PEM-CA (в дополнение к `webpki-roots`).
    pub ca_file: Option<PathBuf>,
}

impl Default for RemoteBlocklistConfig {
    fn default() -> Self {
        Self {
            sources: Vec::new(),
            refresh_secs: DEFAULT_REFRESH_SECS,
            cache_dir: default_cache_dir(),
            max_bytes: DEFAULT_MAX_BYTES,
            allow_redirects: false,
            allow_hosts: Vec::new(),
            timeout: DEFAULT_TIMEOUT,
            retries: DEFAULT_RETRIES,
            backoff: DEFAULT_BACKOFF,
            ca_file: None,
        }
    }
}

impl RemoteBlocklistConfig {
    /// Проверяет параметры без сетевых операций.
    ///
    /// # Errors
    ///
    /// [`RemoteError::InvalidConfig`] или ошибка разбора URL.
    pub fn validate(&self) -> Result<(), RemoteError> {
        if self.max_bytes == 0 {
            return Err(RemoteError::InvalidConfig(
                "max_bytes must be positive".to_owned(),
            ));
        }
        if self.timeout.is_zero() {
            return Err(RemoteError::InvalidConfig(
                "timeout must be positive".to_owned(),
            ));
        }
        if self.retries > 10 {
            return Err(RemoteError::InvalidConfig(
                "retries must be at most 10".to_owned(),
            ));
        }
        if self.backoff.is_zero() {
            return Err(RemoteError::InvalidConfig(
                "backoff must be positive".to_owned(),
            ));
        }
        if self.cache_dir.as_os_str().is_empty() {
            return Err(RemoteError::InvalidConfig(
                "cache_dir must not be empty".to_owned(),
            ));
        }
        for host in &self.allow_hosts {
            if host.is_empty() || host.chars().any(|ch| ch.is_whitespace() || ch.is_control()) {
                return Err(RemoteError::InvalidConfig(
                    "allow_hosts entries must be non-empty host names".to_owned(),
                ));
            }
        }
        for source in &self.sources {
            source.validate_url()?;
            if source.refresh_secs.is_some_and(|secs| secs > 604_800) {
                return Err(RemoteError::InvalidConfig(
                    "source refresh_secs must be at most 604800".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// Каталог кэша по умолчанию: `$XDG_CACHE_HOME/pulseresolved/blocklist`,
/// затем `$HOME/.cache/...`, затем системный temp.
#[must_use]
pub fn default_cache_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_CACHE_HOME").filter(|value| !value.is_empty()) {
        return PathBuf::from(dir).join("pulseresolved").join("blocklist");
    }
    if let Some(home) = std::env::var_os("HOME").filter(|value| !value.is_empty()) {
        return PathBuf::from(home)
            .join(".cache")
            .join("pulseresolved")
            .join("blocklist");
    }
    std::env::temp_dir().join("pulseresolved").join("blocklist")
}

/// Ошибка скачивания или кэширования источника.
#[derive(Debug, Error)]
pub enum RemoteError {
    /// Некорректный URL.
    #[error("invalid blocklist url: {0}")]
    InvalidUrl(String),
    /// Схема не HTTPS.
    #[error("blocklist source must use https: {0}")]
    NotHttps(String),
    /// Некорректные параметры.
    #[error("invalid remote blocklist configuration: {0}")]
    InvalidConfig(String),
    /// Хост не входит в `allow_hosts`.
    #[error("blocklist source host {host} is not allowed")]
    HostNotAllowed {
        /// Хост.
        host: String,
    },
    /// Хост разрешился только в приватные адреса.
    #[error("blocklist source host {host} resolves to non-public address {address}")]
    PrivateAddress {
        /// Хост.
        host: String,
        /// Адрес.
        address: IpAddr,
    },
    /// Не удалось разрешить хост.
    #[error("blocklist source host {host} did not resolve")]
    NoAddresses {
        /// Хост.
        host: String,
    },
    /// Тело ответа превысило лимит.
    #[error("blocklist source exceeds {limit} bytes")]
    TooLarge {
        /// Лимит.
        limit: u64,
    },
    /// Редирект запрещён или небезопасен.
    #[error("blocklist redirect is not allowed: {reason}")]
    RedirectDenied {
        /// Причина.
        reason: String,
    },
    /// Не-200 HTTP-статус.
    #[error("blocklist source returned HTTP {status}")]
    HttpStatus {
        /// Статус.
        status: u16,
    },
    /// Некорректный HTTP/TLS-ответ.
    #[error("blocklist response is invalid: {reason}")]
    Protocol {
        /// Причина.
        reason: String,
    },
    /// Ошибка TLS.
    #[error("blocklist TLS error: {0}")]
    Tls(String),
    /// Ошибка ввода-вывода.
    #[error("blocklist i/o error: {0}")]
    Io(#[from] io::Error),
    /// Таймаут.
    #[error("blocklist fetch timed out")]
    Timeout,
    /// Сервер ответил 304, но кэшированного тела нет.
    #[error("blocklist source returned 304 without a cached copy")]
    NoCachedCopy,
}

impl RemoteError {
    fn is_retryable(&self) -> bool {
        match self {
            Self::Io(_) | Self::Timeout | Self::Tls(_) => true,
            Self::HttpStatus { status } => *status == 429 || *status >= 500,
            Self::InvalidUrl(_)
            | Self::NotHttps(_)
            | Self::InvalidConfig(_)
            | Self::HostNotAllowed { .. }
            | Self::PrivateAddress { .. }
            | Self::NoAddresses { .. }
            | Self::TooLarge { .. }
            | Self::RedirectDenied { .. }
            | Self::Protocol { .. }
            | Self::NoCachedCopy => false,
        }
    }
}

/// Состояние одного источника.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSourceStatus {
    /// URL.
    pub url: String,
    /// Есть ли снимок в памяти (кэш или успешное скачивание).
    pub active: bool,
    /// Время последнего успешного ответа (unix, секунды; 0 — не было).
    pub last_success_ts: u64,
    /// Размер последнего снимка.
    pub bytes: u64,
    /// `ETag` последнего ответа.
    pub etag: Option<String>,
    /// `Last-Modified` последнего ответа.
    pub last_modified: Option<String>,
    /// Последняя ошибка (без содержимого списка).
    pub last_error: Option<String>,
    /// Эффективная периодичность (0 — только вручную).
    pub refresh_secs: u64,
    /// Через сколько секунд следующий автоматический запрос.
    pub next_refresh_in_secs: Option<u64>,
}

/// Ошибка одного источника в отчёте обновления.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSourceError {
    /// URL.
    pub url: String,
    /// Текст ошибки.
    pub error: String,
}

/// Итог одного прохода обновления.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RemoteRefreshReport {
    /// Сколько источников обновлено (200).
    pub updated: usize,
    /// Сколько источников ответили 304.
    pub not_modified: usize,
    /// Сколько источников завершились ошибкой.
    pub failed: usize,
    /// Сколько байт получено в этом проходе.
    pub bytes: u64,
    /// Сколько снимков не удалось записать в кэш.
    pub persist_failed: usize,
    /// Изменился ли хотя бы один снимок в памяти.
    pub changed: bool,
    /// Ошибки по источникам (без содержимого списков).
    pub errors: Vec<RemoteSourceError>,
}

impl RemoteRefreshReport {
    /// Число успешных ответов (200 + 304).
    #[must_use]
    pub const fn successes(&self) -> usize {
        self.updated.saturating_add(self.not_modified)
    }
}

struct SourceState {
    source: RemoteSource,
    cache_key: String,
    body: Option<Arc<str>>,
    etag: Option<String>,
    last_modified: Option<String>,
    last_success_ts: u64,
    bytes: u64,
    last_error: Option<String>,
    failures: u32,
    next_attempt: Option<Instant>,
}

impl SourceState {
    fn due(&self, now: Instant) -> bool {
        match self.next_attempt {
            Some(at) => now >= at,
            None => self.body.is_none(),
        }
    }

    fn schedule_success(&mut self, config: &RemoteBlocklistConfig, now: Instant) {
        let interval = self.source.refresh_secs.unwrap_or(config.refresh_secs);
        self.next_attempt = if interval == 0 {
            None
        } else {
            Some(now + jitter(Duration::from_secs(interval)))
        };
    }

    fn schedule_failure(&mut self, config: &RemoteBlocklistConfig, now: Instant) {
        let exponent = self.failures.saturating_sub(1).min(10);
        let factor = 1_u32 << exponent;
        let delay = config
            .backoff
            .checked_mul(factor)
            .unwrap_or(MAX_BACKOFF)
            .min(MAX_BACKOFF);
        self.next_attempt = Some(now + delay);
    }

    fn validators(&self) -> Validators<'_> {
        Validators {
            etag: self.etag.as_deref(),
            last_modified: self.last_modified.as_deref(),
        }
    }
}

/// Набор скачанных удалённых источников.
pub struct RemoteBlocklist {
    config: RemoteBlocklistConfig,
    tls: Arc<ClientConfig>,
    sources: Vec<SourceState>,
}

impl std::fmt::Debug for RemoteBlocklist {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RemoteBlocklist")
            .field("sources", &self.sources.len())
            .field("cache_dir", &self.config.cache_dir)
            .finish_non_exhaustive()
    }
}

impl RemoteBlocklist {
    /// Создаёт менеджер, поднимая доступные снимки из кэша.
    ///
    /// Сеть не используется. Повреждённые и несовпадающие с URL записи кэша
    /// молча игнорируются.
    ///
    /// # Errors
    ///
    /// [`RemoteError::InvalidConfig`] при некорректных параметрах, ошибка
    /// чтения `ca_file`, сборки rustls или создания `cache_dir`.
    pub fn new(config: RemoteBlocklistConfig) -> Result<Self, RemoteError> {
        config.validate()?;
        ensure_cache_dir(&config.cache_dir)?;
        let tls = build_tls(config.ca_file.as_deref())?;
        let mut sources = Vec::with_capacity(config.sources.len());
        for source in &config.sources {
            if sources
                .iter()
                .any(|state: &SourceState| state.source.url == source.url)
            {
                continue;
            }
            let cache_key = cache_key(&source.url);
            let cached = load_cache(&config.cache_dir, &cache_key, &source.url, config.max_bytes);
            let (body, etag, last_modified, last_success_ts, bytes) = match cached {
                Some(entry) => (
                    Some(entry.body),
                    entry.etag,
                    entry.last_modified,
                    entry.fetched_ts,
                    entry.bytes,
                ),
                None => (None, None, None, 0, 0),
            };
            sources.push(SourceState {
                source: source.clone(),
                cache_key,
                body,
                etag,
                last_modified,
                last_success_ts,
                bytes,
                last_error: None,
                failures: 0,
                // Сеть в фоне сразу после старта: даже кэш считается
                // устаревшим для первого прохода.
                next_attempt: Some(Instant::now()),
            });
        }
        Ok(Self {
            config,
            tls,
            sources,
        })
    }

    /// Тексты активных источников в порядке конфигурации.
    #[must_use]
    pub fn texts(&self) -> Vec<(SourceFormat, &str)> {
        self.sources
            .iter()
            .filter_map(|state| {
                state
                    .body
                    .as_deref()
                    .map(|body| (state.source.format, body))
            })
            .collect()
    }

    /// Есть ли хоть один снимок в памяти.
    #[must_use]
    pub fn has_snapshot(&self) -> bool {
        self.sources.iter().any(|state| state.body.is_some())
    }

    /// Число источников.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sources.len()
    }

    /// Нет ли источников.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    /// Параметры менеджера.
    #[must_use]
    pub const fn config(&self) -> &RemoteBlocklistConfig {
        &self.config
    }

    /// Ближайший автоматический запрос.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Instant> {
        self.sources
            .iter()
            .filter_map(|state| state.next_attempt)
            .min()
    }

    /// Статусы источников для диагностики и control API.
    #[must_use]
    pub fn statuses(&self) -> Vec<RemoteSourceStatus> {
        let now = Instant::now();
        self.sources
            .iter()
            .map(|state| {
                let refresh_secs = state
                    .source
                    .refresh_secs
                    .unwrap_or(self.config.refresh_secs);
                RemoteSourceStatus {
                    url: state.source.url.clone(),
                    active: state.body.is_some(),
                    last_success_ts: state.last_success_ts,
                    bytes: state.bytes,
                    etag: state.etag.clone(),
                    last_modified: state.last_modified.clone(),
                    last_error: state.last_error.clone(),
                    refresh_secs,
                    next_refresh_in_secs: state
                        .next_attempt
                        .map(|at| at.saturating_duration_since(now).as_secs()),
                }
            })
            .collect()
    }

    /// Обновляет источники, у которых наступил срок.
    pub fn refresh_due(&mut self) -> RemoteRefreshReport {
        self.refresh_sources(false)
    }

    /// Обновляет все источники немедленно (SIGHUP/control API).
    pub fn refresh_all(&mut self) -> RemoteRefreshReport {
        self.refresh_sources(true)
    }

    fn refresh_sources(&mut self, force: bool) -> RemoteRefreshReport {
        let now = Instant::now();
        let mut report = RemoteRefreshReport::default();
        for state in &mut self.sources {
            if !force && !state.due(now) {
                continue;
            }
            let validators = state.validators();
            let outcome = fetch_source(&self.config, &self.tls, &state.source.url, validators);
            match outcome {
                Ok(FetchOutcome::Updated {
                    body,
                    etag,
                    last_modified,
                    bytes,
                }) => {
                    let bytes_len = u64::try_from(body.len()).unwrap_or(u64::MAX);
                    state.body = Some(body);
                    state.etag = etag;
                    state.last_modified = last_modified;
                    state.last_success_ts = unix_now();
                    state.bytes = bytes_len;
                    state.last_error = None;
                    state.failures = 0;
                    state.schedule_success(&self.config, Instant::now());
                    report.updated = report.updated.saturating_add(1);
                    report.bytes = report.bytes.saturating_add(bytes);
                    report.changed = true;
                    if let Some(body) = state.body.as_deref()
                        && let Err(error) = persist_cache(
                            &self.config.cache_dir,
                            &state.cache_key,
                            &state.source.url,
                            body,
                            state.etag.as_deref(),
                            state.last_modified.as_deref(),
                            state.last_success_ts,
                        )
                    {
                        state.last_error = Some(error.to_string());
                        report.persist_failed = report.persist_failed.saturating_add(1);
                    }
                }
                Ok(FetchOutcome::NotModified {
                    etag,
                    last_modified,
                }) => {
                    if let Some(value) = etag {
                        state.etag = Some(value);
                    }
                    if let Some(value) = last_modified {
                        state.last_modified = Some(value);
                    }
                    state.last_success_ts = unix_now();
                    state.last_error = None;
                    state.failures = 0;
                    state.schedule_success(&self.config, Instant::now());
                    report.not_modified = report.not_modified.saturating_add(1);
                }
                Err(error) => {
                    state.failures = state.failures.saturating_add(1);
                    state.last_error = Some(error.to_string());
                    state.schedule_failure(&self.config, Instant::now());
                    report.failed = report.failed.saturating_add(1);
                    report.errors.push(RemoteSourceError {
                        url: state.source.url.clone(),
                        error: error.to_string(),
                    });
                }
            }
        }
        report
    }
}

fn jitter(base: Duration) -> Duration {
    let secs = base.as_secs();
    if secs < 10 {
        return base;
    }
    let spread = secs / 10;
    let mut random = [0_u8; 8];
    let value = if getrandom::fill(&mut random).is_ok() {
        u64::from_le_bytes(random)
    } else {
        unix_now()
    };
    let offset = i64::try_from(value % (spread.saturating_mul(2).saturating_add(1)))
        .unwrap_or(0)
        .saturating_sub(i64::try_from(spread).unwrap_or(0));
    let adjusted = i64::try_from(secs)
        .unwrap_or(i64::MAX)
        .saturating_add(offset);
    Duration::from_secs(u64::try_from(adjusted).unwrap_or(secs))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn cache_key(url: &str) -> String {
    // FNV-1a 64: стабильный ключ имени файла без криптографии.
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in url.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

fn ensure_cache_dir(directory: &Path) -> io::Result<()> {
    if directory.is_dir() {
        return Ok(());
    }
    fs::create_dir_all(directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

struct CachedEntry {
    body: Arc<str>,
    etag: Option<String>,
    last_modified: Option<String>,
    fetched_ts: u64,
    bytes: u64,
}

fn load_cache(directory: &Path, key: &str, url: &str, max_bytes: u64) -> Option<CachedEntry> {
    let meta_path = directory.join(format!("{key}.meta"));
    let list_path = directory.join(format!("{key}.list"));
    let meta = fs::metadata(&meta_path).ok()?;
    if meta.len() > CACHE_META_LIMIT {
        return None;
    }
    let text = fs::read_to_string(&meta_path).ok()?;
    let mut stored_url = None;
    let mut etag = None;
    let mut last_modified = None;
    let mut fetched_ts = 0_u64;
    let mut declared_bytes = None;
    for line in text.lines() {
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        match name {
            "url" => stored_url = Some(value.to_owned()),
            "etag" if !value.is_empty() => etag = Some(value.to_owned()),
            "last_modified" if !value.is_empty() => last_modified = Some(value.to_owned()),
            "fetched" => fetched_ts = value.parse().ok()?,
            "bytes" => declared_bytes = value.parse::<u64>().ok(),
            _ => {}
        }
    }
    if stored_url.as_deref() != Some(url) {
        return None;
    }
    let metadata = fs::metadata(&list_path).ok()?;
    if metadata.len() > max_bytes {
        return None;
    }
    let bytes = fs::read(&list_path).ok()?;
    let size = u64::try_from(bytes.len()).ok()?;
    if size > max_bytes {
        return None;
    }
    if let Some(declared) = declared_bytes
        && declared != size
    {
        return None;
    }
    let text = String::from_utf8(bytes).ok()?;
    Some(CachedEntry {
        body: Arc::from(text),
        etag,
        last_modified,
        fetched_ts,
        bytes: size,
    })
}

#[allow(clippy::too_many_arguments)]
fn persist_cache(
    directory: &Path,
    key: &str,
    url: &str,
    body: &str,
    etag: Option<&str>,
    last_modified: Option<&str>,
    fetched_ts: u64,
) -> Result<(), RemoteError> {
    let list_path = directory.join(format!("{key}.list"));
    let meta_path = directory.join(format!("{key}.meta"));
    write_atomic(&list_path, body.as_bytes())?;
    let mut meta = String::with_capacity(256);
    meta.push_str("version=1\n");
    meta.push_str("url=");
    meta.push_str(url);
    meta.push('\n');
    meta.push_str("etag=");
    meta.push_str(etag.unwrap_or_default());
    meta.push('\n');
    meta.push_str("last_modified=");
    meta.push_str(last_modified.unwrap_or_default());
    meta.push('\n');
    let _ = writeln!(meta, "fetched={fetched_ts}");
    let _ = writeln!(meta, "bytes={}", body.len());
    write_atomic(&meta_path, meta.as_bytes())?;
    Ok(())
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<(), RemoteError> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| RemoteError::InvalidConfig("cache file name is invalid".to_owned()))?;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let temp = path.with_file_name(format!(".{file_name}.{}.{nanos}.tmp", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&temp)?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, path)?;
        Ok::<(), io::Error>(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(&temp);
        return Err(RemoteError::Io(error));
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct Validators<'a> {
    etag: Option<&'a str>,
    last_modified: Option<&'a str>,
}

struct HttpsUrl {
    host: String,
    port: u16,
    path: String,
}

fn parse_https_url(url: &str) -> Result<HttpsUrl, RemoteError> {
    if url.len() > MAX_URL_BYTES {
        return Err(RemoteError::InvalidUrl(url.to_owned()));
    }
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| RemoteError::InvalidUrl(url.to_owned()))?;
    if !scheme.eq_ignore_ascii_case("https") {
        return Err(RemoteError::NotHttps(url.to_owned()));
    }
    let rest = rest.split('#').next().unwrap_or(rest);
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, "/".to_owned()),
    };
    if authority.is_empty()
        || authority.contains('@')
        || authority.contains('\\')
        || authority
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control())
        || path.chars().any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return Err(RemoteError::InvalidUrl(url.to_owned()));
    }
    let (host, port) = split_host_port(authority)?;
    if host.is_empty() || !host.is_ascii() {
        return Err(RemoteError::InvalidUrl(url.to_owned()));
    }
    Ok(HttpsUrl {
        host: host.to_ascii_lowercase(),
        port,
        path,
    })
}

fn split_host_port(authority: &str) -> Result<(String, u16), RemoteError> {
    let invalid = || RemoteError::InvalidUrl(authority.to_owned());
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']').ok_or_else(invalid)?;
        let port = match after.strip_prefix(':') {
            Some(port) if !port.is_empty() => port.parse::<u16>().map_err(|_| invalid())?,
            Some(_) => return Err(invalid()),
            None => 443,
        };
        return Ok((host.to_owned(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|ch| ch.is_ascii_digit()) => {
            Ok((host.to_owned(), port.parse::<u16>().map_err(|_| invalid())?))
        }
        Some(_) => Err(invalid()),
        None => Ok((authority.to_owned(), 443)),
    }
}

fn host_header(url: &HttpsUrl) -> String {
    let host = if url.host.contains(':') {
        format!("[{}]", url.host)
    } else {
        url.host.clone()
    };
    if url.port == 443 {
        host
    } else {
        format!("{host}:{}", url.port)
    }
}

fn host_allowed(allow_hosts: &[String], host: &str) -> bool {
    if allow_hosts.is_empty() {
        return true;
    }
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    allow_hosts.iter().any(|entry| {
        let entry = entry.trim().trim_start_matches('.').to_ascii_lowercase();
        host == entry || host.ends_with(&format!(".{entry}"))
    })
}

fn is_private(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_private_v4(address),
        IpAddr::V6(address) => is_private_v6(address),
    }
}

fn is_private_v4(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    a == 0
        || address.is_loopback()
        || address.is_private()
        || address.is_link_local()
        || address.is_broadcast()
        || address.is_documentation()
        || address.is_unspecified()
        || address.is_multicast()
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && (b == 18 || b == 19))
        || a >= 224
}

fn is_private_v6(address: Ipv6Addr) -> bool {
    if let Some(v4) = address.to_ipv4_mapped() {
        return is_private_v4(v4);
    }
    let segments = address.segments();
    let documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;
    address.is_loopback()
        || address.is_unspecified()
        || address.is_unique_local()
        || address.is_unicast_link_local()
        || address.is_multicast()
        || documentation
}

fn resolve_host(
    config: &RemoteBlocklistConfig,
    host: &str,
    port: u16,
) -> Result<Vec<SocketAddr>, RemoteError> {
    if !host_allowed(&config.allow_hosts, host) {
        return Err(RemoteError::HostNotAllowed {
            host: host.to_owned(),
        });
    }
    let explicit = !config.allow_hosts.is_empty();
    let mut addresses: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|_| RemoteError::NoAddresses {
            host: host.to_owned(),
        })?
        .collect();
    if addresses.is_empty() {
        return Err(RemoteError::NoAddresses {
            host: host.to_owned(),
        });
    }
    addresses.sort();
    addresses.dedup();
    if !explicit {
        for address in &addresses {
            if is_private(address.ip()) {
                return Err(RemoteError::PrivateAddress {
                    host: host.to_owned(),
                    address: address.ip(),
                });
            }
        }
    }
    Ok(addresses)
}

fn build_tls(ca_file: Option<&Path>) -> Result<Arc<ClientConfig>, RemoteError> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = ca_file {
        let pem = fs::read(path)?;
        let certificates = CertificateDer::pem_slice_iter(&pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| RemoteError::InvalidConfig(format!("invalid CA PEM: {error}")))?;
        if certificates.is_empty() {
            return Err(RemoteError::InvalidConfig(
                "CA PEM contains no certificates".to_owned(),
            ));
        }
        for certificate in certificates {
            roots
                .add(certificate)
                .map_err(|error| RemoteError::InvalidConfig(format!("invalid CA: {error}")))?;
        }
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|error| RemoteError::Tls(error.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

struct TlsStream {
    connection: ClientConnection,
    socket: TcpStream,
}

impl TlsStream {
    fn connect(
        tls: &ClientConfig,
        address: SocketAddr,
        server_name: &str,
        deadline: Instant,
    ) -> Result<Self, RemoteError> {
        let timeout = remaining(deadline)?;
        let mut socket = TcpStream::connect_timeout(&address, timeout)?;
        socket.set_nodelay(true)?;
        let name = parse_server_name(server_name)?;
        let mut connection = ClientConnection::new(Arc::new(tls.clone()), name)
            .map_err(|error| RemoteError::Tls(error.to_string()))?;
        while connection.is_handshaking() {
            let timeout = remaining(deadline)?;
            socket.set_read_timeout(Some(timeout))?;
            socket.set_write_timeout(Some(timeout))?;
            match connection.complete_io(&mut socket) {
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    if Instant::now() >= deadline {
                        return Err(RemoteError::Timeout);
                    }
                }
                Err(error) => return Err(RemoteError::Io(error)),
            }
        }
        match connection.alpn_protocol() {
            Some(protocol) if protocol == b"http/1.1" => {}
            Some(protocol) => {
                return Err(RemoteError::Protocol {
                    reason: format!("unexpected ALPN {protocol:?}"),
                });
            }
            None => {
                return Err(RemoteError::Protocol {
                    reason: "server did not negotiate http/1.1".to_owned(),
                });
            }
        }
        Ok(Self { connection, socket })
    }

    fn write_all(&mut self, data: &[u8], deadline: Instant) -> Result<(), RemoteError> {
        self.connection
            .writer()
            .write_all(data)
            .map_err(RemoteError::Io)?;
        while self.connection.wants_write() {
            let timeout = remaining(deadline)?;
            self.socket.set_write_timeout(Some(timeout))?;
            match self.connection.write_tls(&mut self.socket) {
                Ok(0) => {
                    return Err(RemoteError::Io(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "TLS write returned zero bytes",
                    )));
                }
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(RemoteError::Timeout);
                }
                Err(error) => return Err(RemoteError::Io(error)),
            }
        }
        Ok(())
    }

    fn read(&mut self, buffer: &mut [u8], deadline: Instant) -> Result<usize, RemoteError> {
        loop {
            match self.connection.reader().read(buffer) {
                Ok(read) => return Ok(read),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(RemoteError::Io(error)),
            }
            let timeout = remaining(deadline)?;
            self.socket.set_read_timeout(Some(timeout))?;
            let read = match self.connection.read_tls(&mut self.socket) {
                Ok(read) => read,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(RemoteError::Timeout);
                }
                Err(error) => return Err(RemoteError::Io(error)),
            };
            if read == 0 {
                return Err(RemoteError::Io(io::Error::from(
                    io::ErrorKind::UnexpectedEof,
                )));
            }
            self.connection
                .process_new_packets()
                .map_err(|error| RemoteError::Tls(error.to_string()))?;
        }
    }
}

impl Drop for TlsStream {
    fn drop(&mut self) {
        let _ = self
            .socket
            .set_write_timeout(Some(Duration::from_millis(100)));
        self.connection.send_close_notify();
        while self.connection.wants_write() {
            match self.connection.write_tls(&mut self.socket) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        let _ = self.socket.shutdown(std::net::Shutdown::Both);
    }
}

fn parse_server_name(value: &str) -> Result<ServerName<'static>, RemoteError> {
    if let Ok(address) = value.parse::<IpAddr>() {
        return Ok(ServerName::IpAddress(address.into()));
    }
    ServerName::try_from(value.to_owned()).map_err(|_| RemoteError::InvalidUrl(value.to_owned()))
}

fn remaining(deadline: Instant) -> Result<Duration, RemoteError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(RemoteError::Timeout);
    }
    Ok(remaining)
}

enum FetchOutcome {
    Updated {
        body: Arc<str>,
        etag: Option<String>,
        last_modified: Option<String>,
        bytes: u64,
    },
    NotModified {
        etag: Option<String>,
        last_modified: Option<String>,
    },
}

enum Reply {
    Body {
        body: Vec<u8>,
        etag: Option<String>,
        last_modified: Option<String>,
    },
    NotModified {
        etag: Option<String>,
        last_modified: Option<String>,
    },
    Redirect {
        location: String,
    },
}

fn fetch_source(
    config: &RemoteBlocklistConfig,
    tls: &ClientConfig,
    url: &str,
    validators: Validators<'_>,
) -> Result<FetchOutcome, RemoteError> {
    let mut target = parse_https_url(url)?;
    let mut redirects = 0_usize;
    loop {
        let reply = with_retries(config, tls, &target, validators)?;
        match reply {
            Reply::Body {
                body,
                etag,
                last_modified,
            } => {
                let text = String::from_utf8(body).map_err(|_| RemoteError::Protocol {
                    reason: "body is not valid UTF-8".to_owned(),
                })?;
                let bytes = u64::try_from(text.len()).unwrap_or(u64::MAX);
                return Ok(FetchOutcome::Updated {
                    body: Arc::from(text),
                    etag,
                    last_modified,
                    bytes,
                });
            }
            Reply::NotModified {
                etag,
                last_modified,
            } => {
                return Ok(FetchOutcome::NotModified {
                    etag,
                    last_modified,
                });
            }
            Reply::Redirect { location } => {
                if !config.allow_redirects || redirects >= MAX_REDIRECTS {
                    return Err(RemoteError::RedirectDenied {
                        reason: format!("redirect limit exceeded at {location}"),
                    });
                }
                let next = resolve_redirect(&target, &location)?;
                if next.host != target.host || next.port != target.port {
                    return Err(RemoteError::RedirectDenied {
                        reason: format!("cross-host redirect to {}:{}", next.host, next.port),
                    });
                }
                target = next;
                redirects = redirects.saturating_add(1);
            }
        }
    }
}

fn resolve_redirect(current: &HttpsUrl, location: &str) -> Result<HttpsUrl, RemoteError> {
    if location
        .chars()
        .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return Err(RemoteError::RedirectDenied {
            reason: "Location contains whitespace or control characters".to_owned(),
        });
    }
    if location.starts_with('/') {
        return Ok(HttpsUrl {
            host: current.host.clone(),
            port: current.port,
            path: location.to_owned(),
        });
    }
    parse_https_url(location)
}

fn with_retries(
    config: &RemoteBlocklistConfig,
    tls: &ClientConfig,
    url: &HttpsUrl,
    validators: Validators<'_>,
) -> Result<Reply, RemoteError> {
    let attempts = config.retries.saturating_add(1);
    let mut attempt = 0_u32;
    loop {
        match http_get(config, tls, url, validators) {
            Ok(reply) => return Ok(reply),
            Err(error) => {
                attempt = attempt.saturating_add(1);
                if attempt >= attempts || !error.is_retryable() {
                    return Err(error);
                }
                let exponent = attempt.saturating_sub(1).min(10);
                let delay = config
                    .backoff
                    .checked_mul(1_u32 << exponent)
                    .unwrap_or(MAX_BACKOFF)
                    .min(MAX_BACKOFF);
                std::thread::sleep(delay);
            }
        }
    }
}

fn http_get(
    config: &RemoteBlocklistConfig,
    tls: &ClientConfig,
    url: &HttpsUrl,
    validators: Validators<'_>,
) -> Result<Reply, RemoteError> {
    let deadline = Instant::now()
        .checked_add(config.timeout)
        .ok_or_else(|| RemoteError::InvalidConfig("timeout is too large".to_owned()))?;
    let addresses = resolve_host(config, &url.host, url.port)?;
    let mut last_error = RemoteError::NoAddresses {
        host: url.host.clone(),
    };
    let mut stream = None;
    for address in &addresses {
        match TlsStream::connect(tls, *address, &url.host, deadline) {
            Ok(connected) => {
                stream = Some(connected);
                break;
            }
            Err(error) => last_error = error,
        }
    }
    let Some(mut stream) = stream else {
        return Err(last_error);
    };
    let mut request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: pulseresolved/{}\r\nAccept: text/plain, */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n",
        url.path,
        host_header(url),
        env!("CARGO_PKG_VERSION")
    );
    if let Some(etag) = validators.etag {
        request.push_str("If-None-Match: ");
        request.push_str(etag);
        request.push_str("\r\n");
    }
    if let Some(last_modified) = validators.last_modified {
        request.push_str("If-Modified-Since: ");
        request.push_str(last_modified);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes(), deadline)?;
    let (head, mut pending) = read_head(&mut stream, deadline)?;
    let parsed = parse_head(&head)?;
    match parsed.status {
        200 => {
            let body = read_body(
                &mut stream,
                &mut pending,
                &parsed,
                config.max_bytes,
                deadline,
            )?;
            Ok(Reply::Body {
                body,
                etag: parsed.etag,
                last_modified: parsed.last_modified,
            })
        }
        304 => Ok(Reply::NotModified {
            etag: parsed.etag,
            last_modified: parsed.last_modified,
        }),
        301 | 302 | 303 | 307 | 308 => {
            let location = parsed.location.ok_or_else(|| RemoteError::Protocol {
                reason: "redirect without Location".to_owned(),
            })?;
            Ok(Reply::Redirect { location })
        }
        status => Err(RemoteError::HttpStatus { status }),
    }
}

struct ParsedHead {
    status: u16,
    content_length: Option<u64>,
    chunked: bool,
    etag: Option<String>,
    last_modified: Option<String>,
    location: Option<String>,
}

fn read_head(stream: &mut TlsStream, deadline: Instant) -> Result<(Vec<u8>, Vec<u8>), RemoteError> {
    let mut buffer = Vec::with_capacity(4096);
    loop {
        if let Some(end) = find_head_end(&buffer) {
            let head = buffer.drain(..end).collect::<Vec<u8>>();
            return Ok((head, buffer));
        }
        if buffer.len() >= MAX_HEADER_BYTES {
            return Err(RemoteError::TooLarge {
                limit: u64::try_from(MAX_HEADER_BYTES).unwrap_or(u64::MAX),
            });
        }
        let capacity = MAX_HEADER_BYTES.saturating_sub(buffer.len());
        let mut chunk = [0_u8; 4096];
        let want = chunk.len().min(capacity);
        let slice = chunk.get_mut(..want).ok_or_else(|| RemoteError::Protocol {
            reason: "head chunk out of bounds".to_owned(),
        })?;
        let read = stream.read(slice, deadline)?;
        if read == 0 {
            return Err(RemoteError::Io(io::Error::from(
                io::ErrorKind::UnexpectedEof,
            )));
        }
        let data = chunk.get(..read).ok_or_else(|| RemoteError::Protocol {
            reason: "head read out of bounds".to_owned(),
        })?;
        buffer.extend_from_slice(data);
    }
}

fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position.saturating_add(4))
}

fn parse_head(head: &[u8]) -> Result<ParsedHead, RemoteError> {
    let text = std::str::from_utf8(head).map_err(|_| RemoteError::Protocol {
        reason: "HTTP head is not valid UTF-8".to_owned(),
    })?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    if !version.eq_ignore_ascii_case("HTTP/1.1") && !version.eq_ignore_ascii_case("HTTP/1.0") {
        return Err(RemoteError::Protocol {
            reason: format!("unsupported HTTP version {version:?}"),
        });
    }
    let status = parts
        .next()
        .ok_or_else(|| RemoteError::Protocol {
            reason: "missing HTTP status".to_owned(),
        })?
        .parse::<u16>()
        .map_err(|_| RemoteError::Protocol {
            reason: "invalid HTTP status".to_owned(),
        })?;
    let mut content_length = None;
    let mut chunked = false;
    let mut etag = None;
    let mut last_modified = None;
    let mut location = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = Some(value.parse::<u64>().map_err(|_| RemoteError::Protocol {
                reason: "invalid Content-Length".to_owned(),
            })?);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("chunked"));
        } else if name.eq_ignore_ascii_case("etag") {
            etag = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("last-modified") {
            last_modified = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("location") {
            location = Some(value.to_owned());
        }
    }
    Ok(ParsedHead {
        status,
        content_length,
        chunked,
        etag,
        last_modified,
        location,
    })
}

fn read_body(
    stream: &mut TlsStream,
    pending: &mut Vec<u8>,
    head: &ParsedHead,
    max_bytes: u64,
    deadline: Instant,
) -> Result<Vec<u8>, RemoteError> {
    if head.chunked {
        return read_chunked(stream, pending, max_bytes, deadline);
    }
    match head.content_length {
        Some(length) => {
            if length > max_bytes {
                return Err(RemoteError::TooLarge { limit: max_bytes });
            }
            let length =
                usize::try_from(length).map_err(|_| RemoteError::TooLarge { limit: max_bytes })?;
            let mut body = Vec::with_capacity(length.min(64 * 1024));
            body.extend_from_slice(pending);
            pending.clear();
            if body.len() > length {
                body.truncate(length);
            }
            fill_body(stream, &mut body, length, max_bytes, deadline)?;
            Ok(body)
        }
        None => read_to_limit(stream, pending, max_bytes, deadline),
    }
}

fn fill_body(
    stream: &mut TlsStream,
    body: &mut Vec<u8>,
    length: usize,
    max_bytes: u64,
    deadline: Instant,
) -> Result<(), RemoteError> {
    let mut chunk = [0_u8; 8192];
    while body.len() < length {
        let want = (length.saturating_sub(body.len())).min(chunk.len());
        let slice = chunk.get_mut(..want).ok_or_else(|| RemoteError::Protocol {
            reason: "body chunk out of bounds".to_owned(),
        })?;
        let read = stream.read(slice, deadline)?;
        if read == 0 {
            return Err(RemoteError::Io(io::Error::from(
                io::ErrorKind::UnexpectedEof,
            )));
        }
        let data = chunk.get(..read).ok_or_else(|| RemoteError::Protocol {
            reason: "body read out of bounds".to_owned(),
        })?;
        let next = u64::try_from(body.len().saturating_add(read)).unwrap_or(u64::MAX);
        if next > max_bytes {
            return Err(RemoteError::TooLarge { limit: max_bytes });
        }
        body.extend_from_slice(data);
    }
    Ok(())
}

fn read_to_limit(
    stream: &mut TlsStream,
    pending: &mut Vec<u8>,
    max_bytes: u64,
    deadline: Instant,
) -> Result<Vec<u8>, RemoteError> {
    let mut body = Vec::new();
    body.append(pending);
    check_limit(body.len(), max_bytes)?;
    let mut chunk = [0_u8; 8192];
    loop {
        let read = stream.read(&mut chunk, deadline)?;
        if read == 0 {
            return Ok(body);
        }
        let data = chunk.get(..read).ok_or_else(|| RemoteError::Protocol {
            reason: "body read out of bounds".to_owned(),
        })?;
        let next = u64::try_from(body.len().saturating_add(read)).unwrap_or(u64::MAX);
        check_limit_u64(next, max_bytes)?;
        body.extend_from_slice(data);
    }
}

fn read_chunked(
    stream: &mut TlsStream,
    pending: &mut Vec<u8>,
    max_bytes: u64,
    deadline: Instant,
) -> Result<Vec<u8>, RemoteError> {
    let mut body = Vec::new();
    loop {
        let line = read_line(stream, pending, MAX_CHUNK_LINE_BYTES, deadline)?;
        let size_text = line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_text, 16).map_err(|_| RemoteError::Protocol {
            reason: "invalid chunk size".to_owned(),
        })?;
        if size == 0 {
            let mut trailer = 0_usize;
            loop {
                let line = read_line(stream, pending, MAX_TRAILER_BYTES, deadline)?;
                if line.is_empty() {
                    break;
                }
                trailer = trailer.saturating_add(line.len());
                if trailer > MAX_TRAILER_BYTES {
                    return Err(RemoteError::TooLarge {
                        limit: u64::try_from(MAX_TRAILER_BYTES).unwrap_or(u64::MAX),
                    });
                }
            }
            return Ok(body);
        }
        let next = u64::try_from(body.len().saturating_add(size)).unwrap_or(u64::MAX);
        check_limit_u64(next, max_bytes)?;
        read_exact_into(stream, pending, size, &mut body, deadline)?;
        let terminator = read_line(stream, pending, 8, deadline)?;
        if !terminator.is_empty() {
            return Err(RemoteError::Protocol {
                reason: "chunk is not terminated by CRLF".to_owned(),
            });
        }
    }
}

fn check_limit(size: usize, max_bytes: u64) -> Result<(), RemoteError> {
    check_limit_u64(u64::try_from(size).unwrap_or(u64::MAX), max_bytes)
}

fn check_limit_u64(size: u64, max_bytes: u64) -> Result<(), RemoteError> {
    if size > max_bytes {
        return Err(RemoteError::TooLarge { limit: max_bytes });
    }
    Ok(())
}

fn read_line(
    stream: &mut TlsStream,
    pending: &mut Vec<u8>,
    limit: usize,
    deadline: Instant,
) -> Result<String, RemoteError> {
    loop {
        if let Some(position) = pending.iter().position(|byte| *byte == b'\n') {
            let mut line = pending.drain(..=position).collect::<Vec<u8>>();
            if line.last() == Some(&b'\n') {
                line.pop();
            }
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if line.len() > limit {
                return Err(RemoteError::TooLarge {
                    limit: u64::try_from(limit).unwrap_or(u64::MAX),
                });
            }
            return String::from_utf8(line).map_err(|_| RemoteError::Protocol {
                reason: "chunk line is not valid UTF-8".to_owned(),
            });
        }
        if pending.len() > limit {
            return Err(RemoteError::TooLarge {
                limit: u64::try_from(limit).unwrap_or(u64::MAX),
            });
        }
        read_more(stream, pending, deadline)?;
    }
}

fn read_exact_into(
    stream: &mut TlsStream,
    pending: &mut Vec<u8>,
    length: usize,
    body: &mut Vec<u8>,
    deadline: Instant,
) -> Result<(), RemoteError> {
    let mut filled = 0_usize;
    while filled < length {
        if pending.is_empty() {
            read_more(stream, pending, deadline)?;
        }
        let need = length.saturating_sub(filled);
        let available = need.min(pending.len());
        let take = pending.drain(..available).collect::<Vec<u8>>();
        filled = filled.saturating_add(take.len());
        body.extend_from_slice(&take);
    }
    Ok(())
}

fn read_more(
    stream: &mut TlsStream,
    pending: &mut Vec<u8>,
    deadline: Instant,
) -> Result<(), RemoteError> {
    let mut chunk = [0_u8; 8192];
    let read = stream.read(&mut chunk, deadline)?;
    if read == 0 {
        return Err(RemoteError::Io(io::Error::from(
            io::ErrorKind::UnexpectedEof,
        )));
    }
    let data = chunk.get(..read).ok_or_else(|| RemoteError::Protocol {
        reason: "chunk read out of bounds".to_owned(),
    })?;
    pending.extend_from_slice(data);
    Ok(())
}
