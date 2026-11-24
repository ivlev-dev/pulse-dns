//! Запуск и остановка UDP/TCP/HTTP-метрик и фонового reload.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use pulse_resolver::{BlocklistStats, Resolver, ResolverError};

use crate::config::Config;
use crate::error::ServerError;
use crate::metrics::{MetricsService, MetricsSource};
use crate::query::Processor;
use crate::reload::{Reloader, reload_now};
use crate::stats::{Stats, StatsSnapshot};
use crate::tcp::TcpService;
use crate::udp::UdpService;

/// Запущенный резолвер.
///
/// `Server::start` валидирует конфигурацию, создаёт [`Resolver`], поднимает
/// TCP-listener, UDP-сокеты и (опционально) HTTP-метрики. Если любой шаг
/// падает, уже запущенные части останавливаются через `Drop`.
pub struct Server {
    resolver: Resolver,
    stats: Arc<Stats>,
    udp: Option<UdpService>,
    tcp: Option<TcpService>,
    metrics: Option<MetricsService>,
    reloader: Option<Reloader>,
}

impl Server {
    /// Запускает резолвер.
    ///
    /// # Errors
    ///
    /// [`ServerError::Config`] / [`ServerError::Resolver`] при некорректной
    /// конфигурации, [`ServerError::TcpStart`] / [`ServerError::Udp`] при
    /// ошибке транспорта, [`ServerError::MetricsStart`] при занятом адресе
    /// метрик.
    pub fn start(config: &Config) -> Result<Self, ServerError> {
        let resolver = Resolver::new(config.resolver_config()?)?;
        let stats = Arc::new(Stats::new());
        let processor = Arc::new(Processor::new(resolver.clone(), Arc::clone(&stats)));

        let metrics = match config.metrics_listen {
            Some(addr) => Some(
                MetricsService::start(
                    addr,
                    MetricsSource::new(resolver.clone(), Arc::clone(&stats)),
                )
                .map_err(|source| ServerError::MetricsStart { addr, source })?,
            ),
            None => None,
        };
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
            Some(addr) => Some(UdpService::start(addr, config.workers, processor)?),
            None => None,
        };
        let reloader = if config.blocklist.reload_secs > 0 && !config.blocklist.paths.is_empty() {
            Some(
                Reloader::start(
                    resolver.clone(),
                    Arc::clone(&stats),
                    Duration::from_secs(config.blocklist.reload_secs),
                )
                .map_err(ServerError::Reload)?,
            )
        } else {
            None
        };

        Ok(Self {
            resolver,
            stats,
            udp,
            tcp,
            metrics,
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

    /// Фактический адрес HTTP-метрик.
    #[must_use]
    pub fn metrics_addr(&self) -> Option<SocketAddr> {
        self.metrics.as_ref().map(MetricsService::addr)
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

    /// Снимок статистики резолвера (кеш, blocklist, DNSSEC, upstream).
    #[must_use]
    pub fn resolver_stats(&self) -> pulse_resolver::StatsSnapshot {
        self.resolver.stats()
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
        reload_now(&self.resolver, &self.stats)
    }

    /// Останавливает фоновый reload, HTTP-метрики, TCP и UDP.
    ///
    /// Идемпотентен: повторный вызов возвращает `Ok(())`.
    ///
    /// # Errors
    ///
    /// [`ServerError::Tcp`] при ошибке join'а TCP-acceptor'а,
    /// [`ServerError::Udp`] при ошибке остановки UDP worker'ов.
    pub fn shutdown(&mut self) -> Result<(), ServerError> {
        if let Some(mut reloader) = self.reloader.take() {
            reloader.stop();
        }
        if let Some(mut metrics) = self.metrics.take() {
            metrics.shutdown();
        }
        let mut first_error = None;
        if let Some(mut tcp) = self.tcp.take()
            && let Err(error) = tcp.shutdown()
        {
            first_error = Some(ServerError::Tcp(error.to_string()));
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
