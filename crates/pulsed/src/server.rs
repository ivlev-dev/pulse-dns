//! Запуск и остановка UDP/TCP транспортов и встроенного REST API.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use pulse_api::auth::TokenConfig;
use pulse_api::config::ApiConfig;
use pulse_api::memory::InMemoryZoneAdmin;
use pulse_api::server::{ApiServerError, RunningServer, serve};
use pulse_server::StatsSnapshot as QueryStatsSnapshot;
use thiserror::Error;

use crate::config::{Config, ConfigError};
use crate::stats::{Stats, StatsSnapshot};
use crate::store::{self, SharedZoneAdmin};
use crate::tcp::TcpService;
use crate::udp::UdpService;
use crate::zone::ZoneError;

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
    udp: Option<UdpService>,
    tcp: Option<TcpService>,
    api: Option<RunningServer>,
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
    /// JSON-зоны загружаются в [`InMemoryZoneAdmin`] — он является источником
    /// истины для DNS и для API. API и DNS используют один store, поэтому
    /// успешная мутация сразу подменяет снапшот `QueryEngine`.
    ///
    /// # Errors
    ///
    /// [`ServerError::Config`] / [`ServerError::Zone`] при некорректной
    /// конфигурации, [`ServerError::Store`] при загрузке зон в store,
    /// [`ServerError::TcpStart`] / [`ServerError::Udp`] при ошибке транспорта,
    /// [`ServerError::Api`] при ошибке конфигурации или запуска API.
    pub fn start_with_api(config: &Config, api: Option<ApiOptions>) -> Result<Self, ServerError> {
        config.validate()?;
        let store = Arc::new(InMemoryZoneAdmin::new());
        store::load_config(&store, config).map_err(ServerError::Store)?;
        let admin = Arc::new(SharedZoneAdmin::new(store).map_err(|error| {
            ServerError::Store(format!("cannot build initial DNS snapshot: {error}"))
        })?);
        let stats = Arc::new(Stats::new());

        let tcp = match config.listen_tcp {
            Some(addr) => Some(
                TcpService::start(
                    addr,
                    config.tcp.max_connections,
                    config.tcp.idle_timeout(),
                    Arc::clone(&admin),
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
                Arc::clone(&admin),
                Arc::clone(&stats),
            )?),
            None => None,
        };
        let api = match api {
            Some(options) => {
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
                Some(serve(api_config, Arc::clone(&admin))?)
            }
            None => None,
        };

        Ok(Self {
            admin,
            stats,
            udp,
            tcp,
            api,
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
    /// Ошибка загрузки зон в store или построения DNS-снапшота.
    #[error("zone store error: {0}")]
    Store(String),
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
    /// Ошибка встроенного API.
    #[error(transparent)]
    Api(#[from] ApiServerError),
}
