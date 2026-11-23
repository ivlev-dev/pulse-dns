//! Запуск и остановка UDP/TCP транспортов.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use pulse_server::{QueryEngine, StatsSnapshot as QueryStatsSnapshot};
use thiserror::Error;

use crate::config::{Config, ConfigError};
use crate::stats::{Stats, StatsSnapshot};
use crate::tcp::TcpService;
use crate::udp::UdpService;
use crate::zone::{self, ZoneError};

/// Запущенный сервер.
///
/// `Server::start` сначала валидирует конфигурацию и зоны, затем привязывает
/// TCP-listener и UDP-сокеты. Если любой шаг падает, уже запущенные части
/// останавливаются через `Drop`.
pub struct Server {
    engine: Arc<QueryEngine>,
    stats: Arc<Stats>,
    udp: Option<UdpService>,
    tcp: Option<TcpService>,
}

impl Server {
    /// Запускает сервер с заданной конфигурацией.
    ///
    /// # Errors
    ///
    /// [`ServerError::Config`] / [`ServerError::Zone`] при некорректной
    /// конфигурации, [`ServerError::TcpStart`] / [`ServerError::Udp`] при
    /// ошибке привязки сокетов или запуска worker'ов.
    pub fn start(config: &Config) -> Result<Self, ServerError> {
        config.validate()?;
        let engine = Arc::new(zone::build_engine(&config.zones)?);
        let stats = Arc::new(Stats::new());

        let tcp = match config.listen_tcp {
            Some(addr) => Some(
                TcpService::start(
                    addr,
                    config.tcp.max_connections,
                    config.tcp.idle_timeout(),
                    Arc::clone(&engine),
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
                Arc::clone(&engine),
                Arc::clone(&stats),
            )?),
            None => None,
        };

        Ok(Self {
            engine,
            stats,
            udp,
            tcp,
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
        self.engine.stats().snapshot()
    }

    /// Снимок счётчиков UDP-рантайма, если UDP запущен.
    #[must_use]
    pub fn udp_stats(&self) -> Option<pulse_runtime::ServerStats> {
        self.udp.as_ref().map(UdpService::stats)
    }

    /// Останавливает транспорты и дожидается завершения потоков.
    ///
    /// Идемпотентен: повторный вызов возвращает `Ok(())`.
    ///
    /// # Errors
    ///
    /// [`ServerError::Tcp`] при ошибке join'а TCP-потока,
    /// [`ServerError::Udp`] при ошибке остановки UDP worker'ов.
    pub fn shutdown(&mut self) -> Result<(), ServerError> {
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

/// Ошибка запуска или остановки сервера.
#[derive(Debug, Error)]
pub enum ServerError {
    /// Некорректная конфигурация.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// Некорректная зона.
    #[error(transparent)]
    Zone(#[from] ZoneError),
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
}
