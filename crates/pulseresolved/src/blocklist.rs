//! Единый снимок blocklist: локальные файлы + удалённые HTTPS-источники.
//!
//! Сервис собирает [`Blocklist`] из локальных файлов и скачанных текстов и
//! атомарно подменяет снимок в [`Resolver`]. Фоновый поток вызывает
//! [`BlocklistService::tick`]: он перечитывает локальные файлы по
//! `reload_secs` и обновляет удалённые источники по их `refresh_secs`.
//! SIGHUP и control API вызывают [`BlocklistService::reload`] — немедленное
//! обновление всех источников.
//!
//! Сетевые ошибки не роняют сервис: старый снимок остаётся в силе
//! (fail-safe), а ошибки попадают в метрики и лог без содержимого списков.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use pulse_resolver::{
    Blocklist, BlocklistStats, RemoteBlocklist, RemoteRefreshReport, RemoteSourceStatus, Resolver,
    ResolverError,
};

use crate::config::Config;
use crate::error::ServerError;
use crate::logging;
use crate::stats::Stats;

const MIN_WAKE: Duration = Duration::from_millis(50);

/// Общий снимок blocklist и расписание обновлений.
pub(crate) struct BlocklistService {
    resolver: Resolver,
    stats: Arc<Stats>,
    paths: Vec<PathBuf>,
    allowlist: Vec<String>,
    remote: Option<Mutex<RemoteBlocklist>>,
    local_interval: Option<Duration>,
    local_next: Mutex<Instant>,
}

impl BlocklistService {
    /// Создаёт сервис; кэш удалённых источников читается сразу, сеть — нет.
    ///
    /// # Errors
    ///
    /// [`ServerError::BlocklistRemote`] при некорректных параметрах или
    /// недоступном каталоге кэша.
    pub(crate) fn new(
        resolver: Resolver,
        stats: Arc<Stats>,
        config: &Config,
    ) -> Result<Self, ServerError> {
        let sources = config.blocklist.remote_sources();
        let remote = if sources.is_empty() {
            None
        } else {
            let remote = RemoteBlocklist::new(config.blocklist.remote_config())
                .map_err(|error| ServerError::BlocklistRemote(error.to_string()))?;
            Some(Mutex::new(remote))
        };
        let local_interval = (config.blocklist.reload_secs > 0)
            .then(|| Duration::from_secs(config.blocklist.reload_secs));
        let local_next = Instant::now() + local_interval.unwrap_or(Duration::from_hours(8760));
        Ok(Self {
            resolver,
            stats,
            paths: config.blocklist.paths.clone(),
            allowlist: config.blocklist.allowlist.clone(),
            remote,
            local_interval,
            local_next: Mutex::new(local_next),
        })
    }

    /// Применяет кэшированный удалённый снимок до старта транспортов.
    ///
    /// # Errors
    ///
    /// Ошибка чтения локальных файлов blocklist.
    pub(crate) fn load_initial(&self) -> Result<BlocklistStats, ResolverError> {
        if self.remote.is_some() {
            self.rebuild()
        } else {
            Ok(self.resolver.blocklist().stats())
        }
    }

    /// Немедленно перечитывает локальные файлы и все удалённые источники.
    ///
    /// # Errors
    ///
    /// Ошибка чтения локального файла; в этом случае старый снимок остаётся.
    pub(crate) fn reload(&self) -> Result<BlocklistStats, ResolverError> {
        let outcome = self.reload_inner();
        self.finish_reload(&outcome);
        outcome
    }

    fn reload_inner(&self) -> Result<BlocklistStats, ResolverError> {
        self.refresh(true)?;
        self.rebuild()
    }

    /// Обновляет только источники, у которых наступил срок.
    ///
    /// # Errors
    ///
    /// Ошибка пересборки локального снимка после успешного скачивания.
    pub(crate) fn refresh_due(&self) -> Result<Option<RemoteRefreshReport>, ResolverError> {
        self.refresh(false)
    }

    /// Один шаг фонового worker'а.
    pub(crate) fn tick(&self) {
        let now = Instant::now();
        let local_due = self
            .local_interval
            .is_some_and(|_| now >= *self.local_next_guard());
        if local_due {
            let outcome = self.rebuild();
            self.finish_reload(&outcome);
            if let Some(interval) = self.local_interval {
                *self.local_next_guard() = Instant::now() + interval;
            }
        }
        if let Err(error) = self.refresh_due() {
            self.stats.reload_failed();
            logging::error(
                "blocklist",
                &format!("remote refresh could not rebuild snapshot: {error}"),
            );
        }
    }

    /// Сколько ждать до следующего шага worker'а.
    pub(crate) fn next_delay(&self) -> Option<Duration> {
        let remote_next = self
            .remote
            .as_ref()
            .and_then(|remote| remote_guard(remote).next_deadline());
        let local_next = self.local_interval.map(|_| *self.local_next_guard());
        remote_next
            .into_iter()
            .chain(local_next)
            .min()
            .map(|at| at.saturating_duration_since(Instant::now()).max(MIN_WAKE))
    }

    /// Есть ли что обновлять в фоне.
    pub(crate) fn is_active(&self) -> bool {
        self.remote.is_some() || self.local_interval.is_some()
    }

    /// Настроены ли удалённые источники.
    pub(crate) fn remote_configured(&self) -> bool {
        self.remote.is_some()
    }

    /// Статусы удалённых источников.
    pub(crate) fn remote_statuses(&self) -> Vec<RemoteSourceStatus> {
        self.remote
            .as_ref()
            .map_or_else(Vec::new, |remote| remote_guard(remote).statuses())
    }

    fn refresh(&self, force: bool) -> Result<Option<RemoteRefreshReport>, ResolverError> {
        let Some(remote) = &self.remote else {
            return Ok(None);
        };
        let report = {
            let mut guard = remote_guard(remote);
            if force {
                guard.refresh_all()
            } else {
                guard.refresh_due()
            }
        };
        self.stats.blocklist_refresh(&report);
        log_report(&report);
        if report.changed {
            self.rebuild()?;
        }
        Ok(Some(report))
    }

    fn rebuild(&self) -> Result<BlocklistStats, ResolverError> {
        let list = match &self.remote {
            Some(remote) => {
                let guard = remote_guard(remote);
                let texts = guard.texts();
                Blocklist::load_combined(&self.paths, &texts, &self.allowlist)?
            }
            None => Blocklist::load_combined(&self.paths, &[], &self.allowlist)?,
        };
        self.resolver.replace_blocklist(list)
    }

    fn local_next_guard(&self) -> MutexGuard<'_, Instant> {
        self.local_next
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn finish_reload(&self, outcome: &Result<BlocklistStats, ResolverError>) {
        match outcome {
            Ok(stats) => {
                self.stats.reload_ok();
                logging::info(
                    "blocklist",
                    &format!(
                        "snapshot applied: blocked={} allowed={} skipped={}",
                        stats.blocked, stats.allowed, stats.skipped
                    ),
                );
            }
            Err(error) => {
                self.stats.reload_failed();
                logging::error(
                    "blocklist",
                    &format!("reload failed; previous snapshot kept: {error}"),
                );
            }
        }
    }
}

fn remote_guard(remote: &Mutex<RemoteBlocklist>) -> MutexGuard<'_, RemoteBlocklist> {
    remote.lock().unwrap_or_else(PoisonError::into_inner)
}

fn log_report(report: &RemoteRefreshReport) {
    for source in &report.errors {
        logging::warn(
            "blocklist",
            &format!("fetch failed for {}: {}", source.url, source.error),
        );
    }
    if report.updated > 0 || report.not_modified > 0 || report.failed > 0 {
        logging::info(
            "blocklist",
            &format!(
                "remote refresh: updated={} not_modified={} failed={} bytes={}",
                report.updated, report.not_modified, report.failed, report.bytes
            ),
        );
    }
}
