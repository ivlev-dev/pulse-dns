//! Запуск и остановка транспортов, HTTP-метрик и фонового reload.

use std::net::SocketAddr;
use std::sync::Arc;

use pulse_resolver::{BlocklistStats, Resolver, ResolverError};

use crate::blocklist::BlocklistService;
use crate::config::Config;
use crate::control::{ControlService, ControlState};
use crate::error::ServerError;
use crate::metrics::{MetricsService, MetricsSource, SecureMetrics};
use crate::query::{Processor, Transport};
use crate::reload::Reloader;
use crate::rrl::{Rrl, RrlSnapshot};
use crate::secure::{DnscryptService, Doh2Service, DohService, DoqService, DotService, handler};
use crate::stats::{Stats, StatsSnapshot};
use crate::tcp::TcpService;
use crate::udp::UdpService;

/// Результат SIGHUP-перезагрузки.
#[derive(Debug)]
pub struct ReloadOutcome {
    /// Перечитывание blocklist.
    pub blocklist: Result<BlocklistStats, ResolverError>,
    /// Перечитывание TLS-сертификата (ошибка уже отформатирована).
    pub tls: Result<(), String>,
}

/// Запущенный резолвер.
///
/// `Server::start` валидирует конфигурацию, создаёт [`Resolver`], поднимает
/// UDP/TCP и защищённые транспорты (DoT, DoH/1.1, DoH/2, DoQ, DNSCrypt) и
/// (опционально) HTTP-метрики. Если любой шаг падает, уже запущенные части
/// останавливаются через `Drop`.
pub struct Server {
    resolver: Resolver,
    stats: Arc<Stats>,
    blocklist: Arc<BlocklistService>,
    rrl: Option<Arc<Rrl>>,
    udp: Option<UdpService>,
    tcp: Option<TcpService>,
    dot: Option<DotService>,
    doh: Option<DohService>,
    doh2: Option<Doh2Service>,
    doq: Option<DoqService>,
    dnscrypt: Option<DnscryptService>,
    metrics: Option<MetricsService>,
    control: Option<ControlService>,
    reloader: Option<Reloader>,
}

impl Server {
    /// Запускает резолвер.
    ///
    /// # Errors
    ///
    /// [`ServerError::Config`] / [`ServerError::Resolver`] при некорректной
    /// конфигурации, [`ServerError::TcpStart`] / [`ServerError::Udp`] при
    /// ошибке транспорта, [`ServerError::SecureStart`] / [`ServerError::Dnscrypt`]
    /// при ошибке защищённого транспорта, [`ServerError::MetricsStart`] при
    /// занятом адресе метрик.
    pub fn start(config: &Config) -> Result<Self, ServerError> {
        // Пиннинг проверяется до bind: пустое пересечение с маской процесса —
        // ошибка старта. Значение уже пересечено, чужие CPU не используются.
        let cpu_affinity = if config.control_cpu_affinity.is_empty() {
            Vec::new()
        } else {
            pulse_runtime::affinity::resolve(&config.control_cpu_affinity)
                .map_err(|error| ServerError::Affinity(format!("control_cpu_affinity: {error}")))?
        };
        let resolver = Resolver::new(config.resolver_config()?)?;
        let stats = Arc::new(Stats::new());
        let blocklist = Arc::new(BlocklistService::new(
            resolver.clone(),
            Arc::clone(&stats),
            config,
        )?);
        blocklist.load_initial()?;
        let acl = config.build_acl()?;
        let tls_acl = config.build_tls_acl()?;
        let limiter = config.build_rate_limiter()?;
        let action = config.rate_limit_action();
        let rrl = config.build_rrl()?;
        let processor = Arc::new(Processor::new(
            resolver.clone(),
            Arc::clone(&stats),
            acl,
            tls_acl,
            limiter,
            action,
            rrl.clone(),
        ));

        let tcp = match config.listen_tcp {
            Some(addr) => Some(
                TcpService::start(
                    addr,
                    config.tcp.max_connections,
                    config.tcp.idle_timeout(),
                    Arc::clone(&processor),
                    Arc::clone(&stats),
                )
                .map_err(|source| ServerError::TcpStart { addr, source })?,
            ),
            None => None,
        };
        let udp = match config.listen_udp {
            Some(addr) => Some(UdpService::start(
                addr,
                config.workers,
                &cpu_affinity,
                Arc::clone(&processor),
            )?),
            None => None,
        };
        let dot = match config.dot_listen {
            Some(addr) => Some(DotService::start(
                addr,
                config,
                handler(Arc::clone(&processor), Transport::Dot),
            )?),
            None => None,
        };
        let doh = match config.doh_listen {
            Some(addr) => Some(DohService::start(
                addr,
                config,
                handler(Arc::clone(&processor), Transport::Doh),
            )?),
            None => None,
        };
        let doh2 = match config.doh2_listen {
            Some(addr) => Some(Doh2Service::start(
                addr,
                config,
                handler(Arc::clone(&processor), Transport::Doh2),
            )?),
            None => None,
        };
        let doq = match config.doq_listen {
            Some(addr) => Some(DoqService::start(
                addr,
                config,
                handler(Arc::clone(&processor), Transport::Doq),
            )?),
            None => None,
        };
        let dnscrypt = if config.has_dnscrypt_transport() {
            Some(DnscryptService::start(
                config,
                Arc::clone(&processor),
                Arc::clone(&stats),
            )?)
        } else {
            None
        };

        let secure_metrics = SecureMetrics {
            dot: dot.as_ref().map(DotService::stats_handle),
            doh: doh.as_ref().map(DohService::stats_handle),
            doh2: doh2.as_ref().map(Doh2Service::stats_handle),
            doq: doq.as_ref().map(DoqService::stats_handle),
        };
        let metrics_source = MetricsSource::new(
            resolver.clone(),
            Arc::clone(&stats),
            rrl.clone(),
            secure_metrics,
        );
        let metrics = match config.metrics_listen {
            Some(addr) => Some(
                MetricsService::start(addr, metrics_source.clone())
                    .map_err(|source| ServerError::MetricsStart { addr, source })?,
            ),
            None => None,
        };
        let control = match config.control_listen {
            Some(addr) => {
                let token = config.effective_control_token().ok_or_else(|| {
                    ServerError::Config(crate::error::ConfigError::invalid(
                        "control_listen requires control_token or PULSERESOLVED_API_TOKEN",
                    ))
                })?;
                if !token.is_valid() {
                    return Err(ServerError::Config(crate::error::ConfigError::invalid(
                        "control token must be 1..=4096 visible ASCII characters without spaces",
                    )));
                }
                let state = ControlState::new(
                    resolver.clone(),
                    Arc::clone(&blocklist),
                    rrl.clone(),
                    metrics_source,
                    config.clone(),
                    token.expose().as_bytes().to_vec(),
                );
                Some(
                    ControlService::start(addr, state, &cpu_affinity)
                        .map_err(|source| ServerError::ControlStart { addr, source })?,
                )
            }
            None => None,
        };
        let reloader = if blocklist.is_active() {
            Some(Reloader::start(Arc::clone(&blocklist)).map_err(ServerError::Reload)?)
        } else {
            None
        };

        Ok(Self {
            resolver,
            stats,
            blocklist,
            rrl,
            udp,
            tcp,
            dot,
            doh,
            doh2,
            doq,
            dnscrypt,
            metrics,
            control,
            reloader,
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

    /// Фактический DoT-адрес.
    #[must_use]
    pub fn dot_addr(&self) -> Option<SocketAddr> {
        self.dot.as_ref().map(DotService::addr)
    }

    /// Фактический DoH/1.1-адрес.
    #[must_use]
    pub fn doh_addr(&self) -> Option<SocketAddr> {
        self.doh.as_ref().map(DohService::addr)
    }

    /// Фактический DoH/2-адрес.
    #[must_use]
    pub fn doh2_addr(&self) -> Option<SocketAddr> {
        self.doh2.as_ref().map(Doh2Service::addr)
    }

    /// Фактический DoQ-адрес.
    #[must_use]
    pub fn doq_addr(&self) -> Option<SocketAddr> {
        self.doq.as_ref().map(DoqService::addr)
    }

    /// Фактический DNSCrypt UDP-адрес.
    #[must_use]
    pub fn dnscrypt_udp_addr(&self) -> Option<SocketAddr> {
        self.dnscrypt.as_ref().and_then(DnscryptService::udp_addr)
    }

    /// Фактический DNSCrypt TCP-адрес.
    #[must_use]
    pub fn dnscrypt_tcp_addr(&self) -> Option<SocketAddr> {
        self.dnscrypt.as_ref().and_then(DnscryptService::tcp_addr)
    }

    /// Фактический адрес HTTP-метрик.
    #[must_use]
    pub fn metrics_addr(&self) -> Option<SocketAddr> {
        self.metrics.as_ref().map(MetricsService::addr)
    }

    /// Фактический адрес control-plane API.
    #[must_use]
    pub fn control_addr(&self) -> Option<SocketAddr> {
        self.control.as_ref().map(ControlService::addr)
    }

    /// Число UDP worker'ов, если UDP запущен.
    #[must_use]
    pub fn udp_workers(&self) -> Option<usize> {
        self.udp.as_ref().map(UdpService::workers)
    }

    /// Бэкенд UDP-рантайма.
    #[must_use]
    pub fn udp_backend(&self) -> Option<pulse_runtime::BackendKind> {
        self.udp.as_ref().map(UdpService::backend)
    }

    /// Снимок счётчиков процесса.
    #[must_use]
    pub fn stats(&self) -> StatsSnapshot {
        self.stats.snapshot()
    }

    /// Снимок счётчиков UDP-рантайма.
    #[must_use]
    pub fn udp_stats(&self) -> Option<pulse_runtime::ServerStats> {
        self.udp.as_ref().map(UdpService::stats)
    }

    /// Снимок статистики DoT.
    #[must_use]
    pub fn dot_stats(&self) -> Option<pulse_tls::StatsSnapshot> {
        self.dot.as_ref().map(DotService::stats)
    }

    /// Снимок статистики DoH/1.1.
    #[must_use]
    pub fn doh_stats(&self) -> Option<pulse_tls::StatsSnapshot> {
        self.doh.as_ref().map(DohService::stats)
    }

    /// Снимок статистики DoH/2.
    #[must_use]
    pub fn doh2_stats(&self) -> Option<pulse_tls::StatsSnapshot> {
        self.doh2.as_ref().map(Doh2Service::stats)
    }

    /// Снимок статистики DoQ.
    #[must_use]
    pub fn doq_stats(&self) -> Option<pulse_tls::StatsSnapshot> {
        self.doq.as_ref().map(DoqService::stats)
    }

    /// Снимок статистики резолвера (кеш, blocklist, DNSSEC, upstream).
    #[must_use]
    pub fn resolver_stats(&self) -> pulse_resolver::StatsSnapshot {
        self.resolver.stats()
    }

    /// Снимок статистики RRL (`None`, если RRL выключен).
    #[must_use]
    pub fn rrl_stats(&self) -> Option<RrlSnapshot> {
        self.rrl.as_ref().map(|rrl| rrl.snapshot())
    }

    /// Резолвер (для диагностики и встраивания).
    #[must_use]
    pub fn resolver(&self) -> &Resolver {
        &self.resolver
    }

    /// Перечитывает blocklist из файлов конфигурации.
    ///
    /// # Errors
    ///
    /// [`ResolverError::Blocklist`] при ошибке чтения любого файла; в этом
    /// случае старый список остаётся в силе.
    pub fn reload_blocklist(&self) -> Result<BlocklistStats, ResolverError> {
        self.blocklist.reload()
    }

    /// Статусы удалённых blocklist-источников (для диагностики).
    #[must_use]
    pub fn blocklist_remote_statuses(&self) -> Vec<pulse_resolver::RemoteSourceStatus> {
        self.blocklist.remote_statuses()
    }

    /// Настроены ли удалённые HTTPS-источники blocklist.
    #[must_use]
    pub fn has_remote_blocklist(&self) -> bool {
        self.blocklist.remote_configured()
    }

    /// Перечитывает TLS-сертификат/ключ для новых соединений.
    ///
    /// Уже открытые TLS-сессии продолжают работать со старой парой; DoQ
    /// применяет новый сертификат к новым QUIC-соединениям.
    ///
    /// # Errors
    ///
    /// Первая ошибка чтения/разбора PEM или применения конфигурации.
    pub fn reload_tls(&self) -> Result<(), ServerError> {
        let mut loaded = false;
        let mut first_error = None;
        if let Some(dot) = &self.dot {
            loaded = true;
            if let Err(error) = dot.reload() {
                first_error = Some(error);
            }
        }
        if let Some(doh) = &self.doh {
            loaded = true;
            if let Err(error) = doh.reload() {
                first_error.get_or_insert(error);
            }
        }
        if let Some(doh2) = &self.doh2 {
            loaded = true;
            if let Err(error) = doh2.reload() {
                first_error.get_or_insert(error);
            }
        }
        if let Some(doq) = &self.doq {
            loaded = true;
            if let Err(error) = doq.reload() {
                first_error.get_or_insert(error);
            }
        }
        if !loaded {
            return Ok(());
        }
        if let Some(error) = first_error {
            self.stats.tls_reload_failed();
            Err(error)
        } else {
            self.stats.tls_reload_ok();
            Ok(())
        }
    }

    /// SIGHUP: перечитывает blocklist и TLS-сертификат.
    ///
    /// Оба шага независимы: ошибка одного не мешает второму.
    #[must_use]
    pub fn reload(&self) -> ReloadOutcome {
        let blocklist = self.reload_blocklist();
        let tls = self.reload_tls().map_err(|error| error.to_string());
        ReloadOutcome { blocklist, tls }
    }

    /// Останавливает фоновый reload, HTTP-метрики, DNSCrypt, DoT/DoH/DoQ, TCP и UDP.
    ///
    /// Идемпотентен: повторный вызов возвращает `Ok(())`.
    ///
    /// # Errors
    ///
    /// Первая ошибка остановки любого транспорта.
    pub fn shutdown(&mut self) -> Result<(), ServerError> {
        if let Some(mut reloader) = self.reloader.take() {
            reloader.stop();
        }
        if let Some(mut control) = self.control.take() {
            control.shutdown();
        }
        if let Some(mut metrics) = self.metrics.take() {
            metrics.shutdown();
        }
        let mut first_error = None;
        if let Some(mut dnscrypt) = self.dnscrypt.take()
            && let Err(error) = dnscrypt.shutdown()
        {
            first_error = Some(error);
        }
        if let Some(mut dot) = self.dot.take()
            && let Err(error) = dot.shutdown()
        {
            first_error = Some(error);
        }
        if let Some(mut doh) = self.doh.take()
            && let Err(error) = doh.shutdown()
        {
            first_error.get_or_insert(error);
        }
        if let Some(mut doh2) = self.doh2.take()
            && let Err(error) = doh2.shutdown()
        {
            first_error.get_or_insert(error);
        }
        if let Some(mut doq) = self.doq.take()
            && let Err(error) = doq.shutdown()
        {
            first_error.get_or_insert(error);
        }
        if let Some(mut tcp) = self.tcp.take()
            && let Err(error) = tcp.shutdown()
        {
            first_error.get_or_insert_with(|| ServerError::Tcp(error.to_string()));
        }
        if let Some(udp) = self.udp.take()
            && let Err(error) = udp.shutdown()
        {
            first_error.get_or_insert(ServerError::Udp(error));
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}
