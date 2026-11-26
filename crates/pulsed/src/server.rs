//! Запуск и остановка DNS-транспортов (UDP/TCP/DoT/DoH/DoQ/DNSCrypt) и
//! встроенного REST API.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use pulse_api::auth::TokenConfig;
use pulse_api::config::ApiConfig;
use pulse_api::journal::{Journal, JournalConfig, JournalError};
use pulse_api::server::{ApiServerError, RunningServer, serve_with_journal};
use pulse_runtime::affinity;
use pulse_server::StatsSnapshot as QueryStatsSnapshot;
use thiserror::Error;

use crate::config::{Config, ConfigError, Role};
use crate::dnscrypt::{DnscryptError, DnscryptService, DnscryptTcpService};
use crate::dnssec::{self, DnssecError};
use crate::metrics::{EnabledTransports, TransportMetrics};
use crate::secondary::SecondaryScheduler;
use crate::stats::{Stats, StatsSnapshot};
use crate::store::{self, SharedZoneAdmin};
use crate::tcp::TcpService;
use crate::tls::{TlsError, TlsTransports};
use crate::transfer::{self, NotifyDispatcher};
use crate::udp::UdpService;

/// Параметры встроенного REST API.
#[derive(Clone, PartialEq, Eq)]
pub struct ApiOptions {
    /// Loopback-адрес API (TLS в MVP нет; публичный bind отклоняется).
    pub listen: SocketAddr,
    /// Bearer-токен. Не логируется и не попадает в `Debug`.
    pub token: String,
    /// Per-zone allowlist (точные origin или `*.suffix.`); пусто — все зоны.
    pub scopes: Vec<String>,
}

impl fmt::Debug for ApiOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiOptions")
            .field("listen", &self.listen)
            .field("token", &"***")
            .field("scopes", &self.scopes)
            .finish()
    }
}

/// Запущенный сервер.
///
/// `Server::start` сначала валидирует конфигурацию и зоны, затем загружает их
/// в общий in-memory store, привязывает TCP-listener и UDP-сокеты. Если любой
/// шаг падает, уже запущенные части останавливаются через `Drop`.
pub struct Server {
    admin: Arc<SharedZoneAdmin>,
    stats: Arc<Stats>,
    metrics: Arc<TransportMetrics>,
    udp: Option<UdpService>,
    tcp: Option<TcpService>,
    tls: Option<TlsTransports>,
    dnscrypt: Option<DnscryptService>,
    dnscrypt_tcp: Option<DnscryptTcpService>,
    api: Option<RunningServer>,
    secondary: Option<SecondaryScheduler>,
    rotation: Option<RotationScheduler>,
    zone_poll: Option<ZonePoller>,
}

impl Server {
    /// Запускает DNS-сервер без REST API.
    ///
    /// # Errors
    ///
    /// См. [`Server::start_with_api`].
    pub fn start(config: &Config) -> Result<Self, ServerError> {
        Self::start_with_api(config, None)
    }

    /// Запускает DNS-сервер и, если задан `api`, встроенный REST API.
    ///
    /// Единственный источник истины — `pulse-zonefile` (`config.zonefile`,
    /// CLI `--data`). DNS-ответы читаются из mmap, REST-мутации пишут в тот же
    /// файл. Без zonefile сервер поднимается без зон и отвечает `REFUSED`.
    ///
    /// # Errors
    ///
    /// [`ServerError::Config`] при некорректной конфигурации,
    /// [`ServerError::Store`] при открытии zonefile/initial snapshot,
    /// [`ServerError::TcpStart`] / [`ServerError::Udp`] при ошибке транспорта,
    /// [`ServerError::Api`] при ошибке конфигурации или запуска API.
    #[allow(clippy::too_many_lines)]
    pub fn start_with_api(config: &Config, api: Option<ApiOptions>) -> Result<Self, ServerError> {
        config.validate()?;
        pulse_tls::net::configure_runtime(pulse_tls::net::RuntimeSettings {
            worker_threads: (config.tcp_workers > 0).then_some(config.tcp_workers),
            ..pulse_tls::net::RuntimeSettings::default()
        })
        .map_err(|error| ServerError::Runtime(error.to_string()))?;
        let role = config.role;
        // Пересечение с `sched_getaffinity`/cpuset проверяется до открытия
        // zonefile и сокетов: пустое пересечение — ошибка старта, а не тихий
        // запуск без пиннинга. `cpu_affinity` в конфиге уже не пересекается
        // между DNS и API (см. `Config::validate_cpu_affinity`).
        let dns_affinity = if role.serves_dns() {
            resolve_affinity("dns_cpu_affinity", &config.dns_cpu_affinity)?
        } else {
            Vec::new()
        };
        let api_affinity = if role.serves_api() {
            resolve_affinity("api_cpu_affinity", &config.api_cpu_affinity)?
        } else {
            Vec::new()
        };
        if role == Role::Api && api.is_none() {
            return Err(ServerError::Store(
                "role=api requires REST API options (--api-listen and --api-token)".to_owned(),
            ));
        }
        let dnssec = dnssec::load(config).map_err(ServerError::Dnssec)?;
        let store = match &config.zonefile {
            Some(path) => {
                let store = Arc::new(
                    crate::zonefile::ZoneStore::open_or_create(
                        path,
                        config.map_size,
                        config.durability.sync_mode_v2(),
                        config.commit_mode,
                        role.is_multi_process(),
                    )
                    .map_err(|error| ServerError::Store(error.to_string()))?,
                );
                crate::logging::info(
                    "zonefile",
                    &format!(
                        "opened zone file {} (role={role}, multi_process={})",
                        path.display(),
                        role.is_multi_process()
                    ),
                );
                Some(store)
            }
            None => None,
        };
        if let Some(store) = &store {
            // Подпись меняет зону: в роли `dns` и `api` это делает только
            // `all`-процесс или REST `/sign`, иначе два процесса конкурируют
            // за lease и пишут одновременно.
            if role == Role::All {
                let signed =
                    store::sign_configured_zones(store, &dnssec).map_err(ServerError::Store)?;
                if signed > 0 {
                    crate::logging::info(
                        "dnssec",
                        &format!("{signed} zone(s) signed into zonefile at startup"),
                    );
                }
            }
        } else if dnssec.origins().next().is_some() {
            return Err(ServerError::Store(
                "dnssec zones require --data <zonefile>".to_owned(),
            ));
        }
        let notify = if role != Role::Api && !config.transfer.notify.is_empty() {
            let key = transfer::notify_key(&config.transfer, &config.tsig_keys)
                .map_err(|error| ServerError::Store(error.to_string()))?;
            Some(Arc::new(
                NotifyDispatcher::start(&config.transfer, key).map_err(ServerError::Notify)?,
            ))
        } else {
            None
        };
        let admin = Arc::new(SharedZoneAdmin::new(store, dnssec, config, notify).map_err(
            |error| ServerError::Store(format!("cannot build initial DNS snapshot: {error}")),
        )?);
        // Журнал принадлежит роли `api`: два процесса не должны повторять одни
        // и те же интенты. `dns` читает зоны напрямую из файла.
        let journal = match config.journal_file() {
            Some(path) if role.serves_api() => Some(Arc::new(
                Journal::open(JournalConfig {
                    path: path.clone(),
                    max_bytes: config.journal_max_bytes,
                    fsync: config.journal_fsync,
                    retain_resolved: pulse_api::journal::DEFAULT_RETAIN_RESOLVED,
                })
                .map_err(ServerError::Journal)?,
            )),
            _ => None,
        };
        if let Some(journal) = &journal {
            let report = journal.recover(&*admin).map_err(ServerError::Journal)?;
            if report.pending > 0 {
                crate::logging::info(
                    "journal",
                    &format!(
                        "journal recovery: pending={} replayed={} skipped={} aborted={} truncated_bytes={}",
                        report.pending,
                        report.replayed,
                        report.skipped,
                        report.aborted,
                        report.truncated_bytes
                    ),
                );
            }
        }
        let secondary = if role.serves_dns() && admin.has_secondary_zones() {
            Some(
                SecondaryScheduler::start(Arc::downgrade(&admin))
                    .map_err(ServerError::Secondary)?,
            )
        } else {
            None
        };
        let rotation = match admin.rotation_tick() {
            Some(interval) if role.serves_dns() => Some(
                RotationScheduler::start(Arc::downgrade(&admin), interval)
                    .map_err(ServerError::Rotation)?,
            ),
            _ => None,
        };
        let stats = Arc::new(Stats::new());
        let metrics = Arc::new(TransportMetrics::new(EnabledTransports {
            dot: config.dot_listen.is_some(),
            doh: config.doh_listen.is_some(),
            doh_h2: config.doh_h2_listen.is_some(),
            doh3: config.doh3_listen.is_some(),
            doq: config.doq_listen.is_some(),
            dnscrypt: config.dnscrypt_listen.is_some(),
            dnscrypt_tcp: config.dnscrypt_tcp_listen.is_some(),
        }));
        let tls = if role.serves_dns() {
            TlsTransports::start(
                config,
                Arc::clone(&admin),
                Arc::clone(&stats),
                Arc::clone(&metrics),
            )?
        } else {
            None
        };
        let dnscrypt = match config.dnscrypt_listen {
            Some(addr) if role.serves_dns() => Some(DnscryptService::start(
                config,
                addr,
                &dns_affinity,
                Arc::clone(&admin),
                Arc::clone(&stats),
                Arc::clone(&metrics),
            )?),
            _ => None,
        };
        let dnscrypt_tcp = match config.dnscrypt_tcp_listen {
            Some(addr) if role.serves_dns() => Some(DnscryptTcpService::start(
                config,
                addr,
                &dns_affinity,
                Arc::clone(&admin),
                Arc::clone(&stats),
                Arc::clone(&metrics),
            )?),
            _ => None,
        };

        let tcp = match config.listen_tcp {
            Some(addr) if role.serves_dns() => Some(
                TcpService::start(
                    addr,
                    config.tcp.max_connections,
                    config.tcp.idle_timeout(),
                    &admin,
                    Arc::clone(&stats),
                    config.tcp_nodelay,
                    (config.busy_poll_us > 0).then_some(config.busy_poll_us),
                )
                .map_err(|source| ServerError::TcpStart { addr, source })?,
            ),
            _ => None,
        };
        let udp = match config.listen_udp {
            Some(addr) if role.serves_dns() => Some(UdpService::start(
                addr,
                config.effective_dns_workers(),
                &dns_affinity,
                config.huge_pages.runtime(),
                Arc::clone(&admin),
                Arc::clone(&stats),
            )?),
            _ => None,
        };
        let api = match api {
            Some(options) if role.serves_api() => {
                let tokens = vec![TokenConfig {
                    id: "pulsed-api".to_owned(),
                    token: options.token,
                    scopes: vec!["admin".to_owned()],
                    zone_scope: if options.scopes.is_empty() {
                        None
                    } else {
                        Some(options.scopes)
                    },
                }];
                let mut api_config = ApiConfig::new(tokens);
                api_config.bind = options.listen;
                api_config.rate_limit_per_sec = config.api_rate_limit_per_sec;
                if let Some(workers) = config.api_workers {
                    api_config.max_connections = workers;
                }
                api_config.cpu_affinity.clone_from(&api_affinity);
                let metric_source = {
                    let metrics = Arc::clone(&metrics);
                    let admin = Arc::clone(&admin);
                    Arc::new(move || {
                        let mut text = metrics.render();
                        text.push_str(&crate::metrics::render_response_cache(
                            &admin.response_cache_metrics(),
                        ));
                        text
                    })
                };
                Some(serve_with_journal(
                    api_config,
                    Arc::clone(&admin),
                    Some(metric_source),
                    journal.clone(),
                )?)
            }
            _ => None,
        };
        let zone_poll = if role == Role::Dns && config.zonefile.is_some() && config.zone_poll_ms > 0
        {
            Some(
                ZonePoller::start(
                    Arc::downgrade(&admin),
                    Duration::from_millis(config.zone_poll_ms),
                )
                .map_err(ServerError::ZonePoll)?,
            )
        } else {
            None
        };

        Ok(Self {
            admin,
            stats,
            metrics,
            udp,
            tcp,
            tls,
            dnscrypt,
            dnscrypt_tcp,
            api,
            secondary,
            rotation,
            zone_poll,
        })
    }

    /// Фактический UDP-адрес (полезен при `port = 0`).
    #[must_use]
    pub fn udp_addr(&self) -> Option<SocketAddr> {
        self.udp.as_ref().map(UdpService::local_addr)
    }

    /// Фактический TCP-адрес (полезен при `port = 0`).
    #[must_use]
    pub fn tcp_addr(&self) -> Option<SocketAddr> {
        self.tcp.as_ref().map(TcpService::local_addr)
    }

    /// Фактический DoT-адрес (полезен при `port = 0`).
    #[must_use]
    pub fn dot_addr(&self) -> Option<SocketAddr> {
        self.tls.as_ref().and_then(TlsTransports::dot_addr)
    }

    /// Фактический DoH-адрес (полезен при `port = 0`).
    #[must_use]
    pub fn doh_addr(&self) -> Option<SocketAddr> {
        self.tls.as_ref().and_then(TlsTransports::doh_addr)
    }

    /// Фактический DoH/HTTP/2-адрес (полезен при `port = 0`).
    #[must_use]
    pub fn doh_h2_addr(&self) -> Option<SocketAddr> {
        self.tls.as_ref().and_then(TlsTransports::doh_h2_addr)
    }

    /// Фактический DoH/HTTP/3-адрес (полезен при `port = 0`).
    #[must_use]
    pub fn doh3_addr(&self) -> Option<SocketAddr> {
        self.tls.as_ref().and_then(TlsTransports::doh3_addr)
    }

    /// Фактический DoQ-адрес (полезен при `port = 0`).
    #[must_use]
    pub fn doq_addr(&self) -> Option<SocketAddr> {
        self.tls.as_ref().and_then(TlsTransports::doq_addr)
    }

    /// Фактический DNSCrypt-адрес (полезен при `port = 0`).
    #[must_use]
    pub fn dnscrypt_addr(&self) -> Option<SocketAddr> {
        self.dnscrypt.as_ref().map(DnscryptService::local_addr)
    }

    /// Фактический адрес DNSCrypt over TCP (полезен при `port = 0`).
    #[must_use]
    pub fn dnscrypt_tcp_addr(&self) -> Option<SocketAddr> {
        self.dnscrypt_tcp
            .as_ref()
            .map(DnscryptTcpService::local_addr)
    }

    /// Снимок счётчиков DoT, если DoT запущен.
    #[must_use]
    pub fn dot_stats(&self) -> Option<pulse_tls::StatsSnapshot> {
        self.tls.as_ref().and_then(TlsTransports::dot_stats)
    }

    /// Снимок счётчиков DoH, если DoH запущен.
    #[must_use]
    pub fn doh_stats(&self) -> Option<pulse_tls::StatsSnapshot> {
        self.tls.as_ref().and_then(TlsTransports::doh_stats)
    }

    /// Снимок счётчиков DoH/HTTP/2, если транспорт запущен.
    #[must_use]
    pub fn doh_h2_stats(&self) -> Option<pulse_tls::StatsSnapshot> {
        self.tls.as_ref().and_then(TlsTransports::doh_h2_stats)
    }

    /// Снимок счётчиков DoH/HTTP/3, если транспорт запущен.
    #[must_use]
    pub fn doh3_stats(&self) -> Option<pulse_tls::StatsSnapshot> {
        self.tls.as_ref().and_then(TlsTransports::doh3_stats)
    }

    /// Снимок счётчиков DoQ, если транспорт запущен.
    #[must_use]
    pub fn doq_stats(&self) -> Option<pulse_tls::StatsSnapshot> {
        self.tls.as_ref().and_then(TlsTransports::doq_stats)
    }

    /// Снимок счётчиков DNSCrypt UDP, если DNSCrypt запущен.
    #[must_use]
    pub fn dnscrypt_stats(&self) -> Option<pulse_runtime::ServerStats> {
        self.dnscrypt.as_ref().map(DnscryptService::stats)
    }

    /// Имя DNSCrypt-провайдера из конфигурации.
    #[must_use]
    pub fn dnscrypt_provider_name(&self) -> Option<&str> {
        self.dnscrypt
            .as_ref()
            .and_then(DnscryptService::provider_name)
            .or_else(|| {
                self.dnscrypt_tcp
                    .as_ref()
                    .and_then(DnscryptTcpService::provider_name)
            })
    }

    /// Серийный номер загруженного DNSCrypt-сертификата.
    #[must_use]
    pub fn dnscrypt_serial(&self) -> Option<u32> {
        self.dnscrypt
            .as_ref()
            .map(DnscryptService::serial)
            .or_else(|| self.dnscrypt_tcp.as_ref().map(DnscryptTcpService::serial))
    }

    /// Конец действия DNSCrypt-сертификата (Unix-время).
    #[must_use]
    pub fn dnscrypt_valid_until(&self) -> Option<u32> {
        self.dnscrypt
            .as_ref()
            .map(DnscryptService::valid_until)
            .or_else(|| {
                self.dnscrypt_tcp
                    .as_ref()
                    .map(DnscryptTcpService::valid_until)
            })
    }

    /// Число DNSCrypt UDP worker'ов.
    #[must_use]
    pub fn dnscrypt_workers(&self) -> Option<usize> {
        self.dnscrypt.as_ref().map(DnscryptService::workers)
    }

    /// Перечитывает TLS-сертификат для новых DoT/DoH-соединений.
    ///
    /// # Errors
    ///
    /// [`TlsError`] при ошибке чтения или парсинга PEM. Если TLS не
    /// настроен, вызов ничего не делает.
    pub fn reload_tls(&self) -> Result<(), TlsError> {
        match &self.tls {
            Some(tls) => tls.reload(),
            None => Ok(()),
        }
    }

    /// Рендер счётчиков DoT/DoH/DNSCrypt в формате Prometheus.
    ///
    /// Те же строки добавляются к `GET /metrics` встроенного REST API.
    #[must_use]
    pub fn transport_metrics(&self) -> String {
        let mut text = self.metrics.render();
        text.push_str(&crate::metrics::render_response_cache(
            &self.admin.response_cache_metrics(),
        ));
        text
    }

    /// Снимок метрик кеша готовых ответов.
    #[must_use]
    pub fn response_cache_metrics(&self) -> pulse_server::ResponseCacheMetrics {
        self.admin.response_cache_metrics()
    }

    /// Фактический адрес API (полезен при `port = 0`).
    #[must_use]
    pub fn api_addr(&self) -> Option<SocketAddr> {
        self.api.as_ref().map(RunningServer::addr)
    }

    /// Число UDP worker'ов, если UDP запущен.
    #[must_use]
    pub fn udp_workers(&self) -> Option<usize> {
        self.udp.as_ref().map(UdpService::workers)
    }

    /// Бэкенд UDP-рантайма, если UDP запущен.
    #[must_use]
    pub fn udp_backend(&self) -> Option<pulse_runtime::BackendKind> {
        self.udp.as_ref().map(UdpService::backend)
    }

    /// Снимок счётчиков сервера.
    #[must_use]
    pub fn stats(&self) -> StatsSnapshot {
        self.stats.snapshot()
    }

    /// Снимок счётчиков `QueryEngine` (NXDOMAIN/NODATA/REFUSED/…).
    #[must_use]
    pub fn query_stats(&self) -> QueryStatsSnapshot {
        self.admin.query_stats().snapshot()
    }

    /// Снимок счётчиков UDP-рантайма, если UDP запущен.
    #[must_use]
    pub fn udp_stats(&self) -> Option<pulse_runtime::ServerStats> {
        self.udp.as_ref().map(UdpService::stats)
    }

    /// Зоны, помеченные входящим NOTIFY к обновлению.
    #[must_use]
    pub fn pending_transfer_updates(&self) -> Vec<pulse_dns::Name> {
        self.admin.pending_updates()
    }

    /// Последняя ошибка secondary-зоны (для диагностики и тестов).
    #[must_use]
    pub fn secondary_last_error(&self, origin: &pulse_dns::Name) -> Option<String> {
        self.admin.secondary_last_error(origin)
    }

    /// Останавливает API, транспорты и дожидается завершения потоков.
    ///
    /// API останавливается первым, чтобы во время shutdown не появлялись новые
    /// мутации. Идемпотентен: повторный вызов возвращает `Ok(())`.
    ///
    /// # Errors
    ///
    /// [`ServerError::Tcp`] при ошибке join'а TCP-потока,
    /// [`ServerError::Udp`] при ошибке остановки UDP worker'ов.
    pub fn shutdown(&mut self) -> Result<(), ServerError> {
        if let Some(api) = self.api.take() {
            api.shutdown();
        }
        if let Some(secondary) = self.secondary.take() {
            secondary.shutdown();
        }
        if let Some(rotation) = self.rotation.take() {
            rotation.shutdown();
        }
        if let Some(zone_poll) = self.zone_poll.take() {
            zone_poll.shutdown();
        }
        let mut first_error = None;
        if let Some(mut tls) = self.tls.take()
            && let Err(error) = tls.shutdown()
        {
            first_error = Some(ServerError::Tls(error));
        }
        if let Some(dnscrypt) = self.dnscrypt.take()
            && let Err(error) = dnscrypt.shutdown()
        {
            first_error.get_or_insert(ServerError::Dnscrypt(DnscryptError::Runtime(error)));
        }
        if let Some(mut dnscrypt_tcp) = self.dnscrypt_tcp.take()
            && let Err(error) = dnscrypt_tcp.shutdown()
        {
            first_error.get_or_insert(ServerError::Dnscrypt(error));
        }
        if let Some(mut tcp) = self.tcp.take()
            && let Err(error) = tcp.shutdown()
        {
            first_error.get_or_insert(ServerError::Tcp(error.to_string()));
        }
        if let Some(udp) = self.udp.take()
            && let Err(error) = udp.shutdown()
        {
            first_error.get_or_insert(ServerError::Udp(error));
        }
        if let Err(error) = self.admin.shutdown() {
            first_error.get_or_insert(ServerError::Store(format!(
                "cannot sync persistent zone file: {error}"
            )));
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

/// Фоновый опрос новых версий zonefile ролью `dns`.
///
/// Перечитывает каталог и головы зон, обновляя только изменившиеся view.
/// Данные зон не копируются: точечные чтения идут из mmap по текущей голове.
struct ZonePoller {
    stop: Arc<AtomicBool>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl ZonePoller {
    fn start(admin: Weak<SharedZoneAdmin>, interval: Duration) -> io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop);
        let handle = thread::Builder::new()
            .name("pulse-zone-poll".to_owned())
            .spawn(move || {
                while !stop_clone.load(Ordering::Acquire) {
                    if let Some(admin) = admin.upgrade() {
                        match admin.poll_zonefile() {
                            Ok(0) => {}
                            Ok(changed) => crate::logging::info(
                                "zonefile",
                                &format!(
                                    "dns role: applied {changed} external zone change(s) from zone file"
                                ),
                            ),
                            Err(error) => {
                                crate::logging::warn("zonefile", &error);
                            }
                        }
                    } else {
                        break;
                    }
                    // Просыпаемся чаще интервала, чтобы shutdown не ждал tick.
                    let mut remaining = interval;
                    let tick = Duration::from_millis(25);
                    while remaining > Duration::ZERO && !stop_clone.load(Ordering::Acquire) {
                        let sleep = remaining.min(tick);
                        thread::sleep(sleep);
                        remaining = remaining.saturating_sub(sleep);
                    }
                }
            })?;
        Ok(Self {
            stop,
            handle: Mutex::new(Some(handle)),
        })
    }

    fn shutdown(&self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self
            .handle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            let _ = handle.join();
        }
    }
}

impl Drop for ZonePoller {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Фоновый планировщик ротации ключей.
///
/// Продвигает состояние по возрасту ключей и переподписывает зоны, у которых
/// произошёл переход. Если администратор уже выгружен, поток завершается.
struct RotationScheduler {
    stop: Arc<AtomicBool>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl RotationScheduler {
    fn start(admin: Weak<SharedZoneAdmin>, interval: Duration) -> io::Result<Self> {
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&shutdown_flag);
        let handle = thread::Builder::new()
            .name("pulse-rotation".to_owned())
            .spawn(move || {
                while !worker_stop.load(Ordering::Acquire) {
                    if let Some(admin) = admin.upgrade() {
                        admin.advance_rotations();
                    } else {
                        break;
                    }
                    // Просыпаемся чаще интервала, чтобы shutdown не ждал tick.
                    let mut remaining = interval;
                    let step = Duration::from_millis(100);
                    while remaining > Duration::ZERO && !worker_stop.load(Ordering::Acquire) {
                        let sleep = remaining.min(step);
                        thread::sleep(sleep);
                        remaining = remaining.saturating_sub(sleep);
                    }
                }
            })?;
        Ok(Self {
            stop: shutdown_flag,
            handle: Mutex::new(Some(handle)),
        })
    }

    fn shutdown(&self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self
            .handle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            let _ = handle.join();
        }
    }
}

impl Drop for RotationScheduler {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Ошибка запуска или остановки сервера.
#[derive(Debug, Error)]
pub enum ServerError {
    /// Некорректная конфигурация.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// Ошибка запуска/остановки DoT или DoH.
    #[error(transparent)]
    Tls(#[from] TlsError),
    /// Ошибка запуска/остановки DNSCrypt.
    #[error(transparent)]
    Dnscrypt(#[from] DnscryptError),
    /// Ошибка загрузки зон в store или построения DNS-снапшота.
    #[error("zone store error: {0}")]
    Store(String),
    /// Ошибка загрузки DNSSEC-ключей.
    #[error(transparent)]
    Dnssec(#[from] DnssecError),
    /// Не удалось запустить TCP-транспорт.
    #[error("cannot start TCP listener {addr}: {source}")]
    TcpStart {
        /// Запрошенный адрес.
        addr: SocketAddr,
        /// Причина.
        #[source]
        source: io::Error,
    },
    /// TCP-транспорт не остановился штатно.
    #[error("TCP shutdown failed: {0}")]
    Tcp(String),
    /// Ошибка UDP-рантайма.
    #[error(transparent)]
    Udp(#[from] pulse_runtime::RuntimeError),
    /// Не удалось настроить общий tokio runtime TCP/DoT/DoH.
    #[error("cannot configure TCP runtime: {0}")]
    Runtime(String),
    /// Не удалось запустить фоновый NOTIFY-воркер.
    #[error("cannot start NOTIFY worker: {0}")]
    Notify(#[source] io::Error),
    /// Не удалось запустить фоновый secondary-планировщик.
    #[error("cannot start secondary scheduler: {0}")]
    Secondary(#[source] io::Error),
    /// Не удалось запустить фоновый планировщик ротации.
    #[error("cannot start key rotation scheduler: {0}")]
    Rotation(#[source] io::Error),
    /// Не удалось запустить фоновый опрос zonefile.
    #[error("cannot start zone poll worker: {0}")]
    ZonePoll(#[source] io::Error),
    /// Ошибка встроенного API.
    #[error(transparent)]
    Api(#[from] ApiServerError),
    /// Ошибка write-ahead журнала или его recovery.
    #[error("journal error: {0}")]
    Journal(#[from] JournalError),
    /// Список CPU не пересекается с `sched_getaffinity`/cpuset.
    #[error("CPU affinity error: {0}")]
    Affinity(String),
}

/// Проверить `cpu_affinity` из конфига против маски процесса.
///
/// Пустой список — пиннинга нет. Непустой пересекается с разрешёнными CPU;
/// пустое пересечение — [`ServerError::Affinity`].
fn resolve_affinity(name: &str, cpus: &[usize]) -> Result<Vec<usize>, ServerError> {
    if cpus.is_empty() {
        return Ok(Vec::new());
    }
    affinity::resolve(cpus).map_err(|error| ServerError::Affinity(format!("{name}: {error}")))
}
