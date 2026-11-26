//! Интеграция `pulse-tls` (DoT/DoH) в `pulsed`.
//!
//! Оба сервера используют один и тот же путь ответа, что и UDP/TCP:
//! `decode → QueryEngine (mmap snapshot) → encode`. Сертификат читается из
//! файлов; `SIGHUP` и `tls_reload_secs` перечитывают пару для новых
//! соединений (открытые TLS-сессии остаются на старой паре).

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use pulse_server::Transport;
use pulse_tls::{
    Acl, DnsHandler, Doh2Config, Doh2Server, Doh3Config, Doh3Server, DohConfig, DohServer,
    DoqConfig, DoqServer, DotConfig, DotServer, Stats as TlsStats, TlsConfig,
};
use thiserror::Error;

use crate::config::Config;
use crate::dns;
use crate::metrics::TransportMetrics;
use crate::stats::Stats;
use crate::store::SharedZoneAdmin;

/// Ошибка запуска или перезагрузки DoT/DoH.
#[derive(Debug, Error)]
pub enum TlsError {
    /// Некорректная TLS-пара или файл сертификата.
    #[error("TLS configuration error: {0}")]
    Config(String),
    /// Не удалось запустить DoT.
    #[error("cannot start DoT listener {addr}: {source}")]
    DotStart {
        /// Запрошенный адрес.
        addr: SocketAddr,
        /// Причина.
        #[source]
        source: pulse_tls::Error,
    },
    /// Не удалось запустить DoH.
    #[error("cannot start DoH listener {addr}: {source}")]
    DohStart {
        /// Запрошенный адрес.
        addr: SocketAddr,
        /// Причина.
        #[source]
        source: pulse_tls::Error,
    },
    /// Не удалось запустить DoH/HTTP/2.
    #[error("cannot start DoH/HTTP/2 listener {addr}: {source}")]
    Doh2Start {
        /// Запрошенный адрес.
        addr: SocketAddr,
        /// Причина.
        #[source]
        source: pulse_tls::Error,
    },
    /// Не удалось запустить DoQ.
    #[error("cannot start DoQ listener {addr}: {source}")]
    DoqStart {
        /// Запрошенный адрес.
        addr: SocketAddr,
        /// Причина.
        #[source]
        source: pulse_tls::Error,
    },
    /// Не удалось запустить DoH/HTTP/3.
    #[error("cannot start DoH/HTTP/3 listener {addr}: {source}")]
    Doh3Start {
        /// Запрошенный адрес.
        addr: SocketAddr,
        /// Причина.
        #[source]
        source: pulse_tls::Error,
    },
    /// Остановка DoT завершилась ошибкой.
    #[error("DoT shutdown failed: {0}")]
    DotShutdown(#[source] pulse_tls::Error),
    /// Остановка DoH завершилась ошибкой.
    #[error("DoH shutdown failed: {0}")]
    DohShutdown(#[source] pulse_tls::Error),
    /// Остановка DoH/HTTP/2 завершилась ошибкой.
    #[error("DoH/HTTP/2 shutdown failed: {0}")]
    Doh2Shutdown(#[source] pulse_tls::Error),
    /// Остановка DoQ завершилась ошибкой.
    #[error("DoQ shutdown failed: {0}")]
    DoqShutdown(#[source] pulse_tls::Error),
    /// Остановка DoH/HTTP/3 завершилась ошибкой.
    #[error("DoH/HTTP/3 shutdown failed: {0}")]
    Doh3Shutdown(#[source] pulse_tls::Error),
    /// Не удалось перечитать сертификат.
    #[error("cannot reload TLS certificate: {0}")]
    Reload(#[source] pulse_tls::Error),
}

/// Запущенные DoT/DoH-серверы.
pub(crate) struct TlsTransports {
    dot: Option<DotServer>,
    doh: Option<DohServer>,
    doh_h2: Option<Doh2Server>,
    doh3: Option<Doh3Server>,
    doq: Option<DoqServer>,
    dot_counts: Arc<TlsStats>,
    doh_counts: Arc<TlsStats>,
    doh_h2_counts: Arc<TlsStats>,
    doh3_counts: Arc<TlsStats>,
    doq_counts: Arc<TlsStats>,
    metrics: Arc<TransportMetrics>,
}

impl TlsTransports {
    /// Запускает настроенные DoT/DoH-серверы.
    ///
    /// # Errors
    ///
    /// [`TlsError`] при ошибке чтения сертификата, ACL или bind.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn start(
        config: &Config,
        admin: Arc<SharedZoneAdmin>,
        stats: Arc<Stats>,
        metrics: Arc<TransportMetrics>,
    ) -> Result<Option<Self>, TlsError> {
        if config.dot_listen.is_none()
            && config.doh_listen.is_none()
            && config.doh_h2_listen.is_none()
            && config.doh3_listen.is_none()
            && config.doq_listen.is_none()
        {
            return Ok(None);
        }
        let cert_path = config
            .tls_cert
            .as_deref()
            .ok_or_else(|| TlsError::Config("tls_cert is not configured".to_owned()))?;
        let key_path = config
            .tls_key
            .as_deref()
            .ok_or_else(|| TlsError::Config("tls_key is not configured".to_owned()))?;
        crate::perms::ensure_private(key_path, "tls_key").map_err(TlsError::Config)?;
        let acl = build_acl(&config.tls_allow_from)?;
        let handler: DnsHandler = Arc::new(move |request: &[u8], _peer| {
            let engine = admin.engine();
            dns::respond(request, Transport::Tcp, &engine, &stats)
        });

        let dot = match config.dot_listen {
            Some(addr) => {
                let tls = dot_tls_config(cert_path, key_path)?;
                let mut dot_config = DotConfig::new(addr, tls);
                dot_config.max_connections = config.dot_max_connections;
                dot_config.request_timeout = Duration::from_millis(config.request_timeout_ms);
                dot_config.nodelay = config.tcp_nodelay;
                dot_config.busy_poll_us = (config.busy_poll_us > 0).then_some(config.busy_poll_us);
                dot_config.acl.clone_from(&acl);
                Some(
                    DotServer::bind_shared(dot_config, Arc::clone(&handler), metrics.dot_stats())
                        .map_err(|source| TlsError::DotStart { addr, source })?,
                )
            }
            None => None,
        };
        let doh = match config.doh_listen {
            Some(addr) => {
                let tls = doh_tls_config(cert_path, key_path)?;
                let mut doh_config = DohConfig::new(addr, tls);
                doh_config.max_connections = config.doh_max_connections;
                doh_config.acl.clone_from(&acl);
                doh_config.cache_control = true;
                Some(
                    DohServer::bind_shared(doh_config, Arc::clone(&handler), metrics.doh_stats())
                        .map_err(|source| TlsError::DohStart { addr, source })?,
                )
            }
            None => None,
        };
        let doh_h2 = match config.doh_h2_listen {
            Some(addr) => {
                let tls = doh2_tls_config(cert_path, key_path)?;
                let mut h2_config = Doh2Config::new(addr, tls);
                h2_config.max_connections = config.doh_h2_max_connections;
                h2_config.max_concurrent_streams = config.doh_h2_max_streams;
                h2_config.acl.clone_from(&acl);
                h2_config.cache_control = true;
                Some(
                    Doh2Server::bind_shared(
                        h2_config,
                        Arc::clone(&handler),
                        metrics.doh_h2_stats(),
                    )
                    .map_err(|source| TlsError::Doh2Start { addr, source })?,
                )
            }
            None => None,
        };
        let doh3 = match config.doh3_listen {
            Some(addr) => {
                let tls = doh3_tls_config(cert_path, key_path)?;
                let mut h3_config = Doh3Config::new(addr, tls);
                h3_config.max_connections = config.doh3_max_connections;
                h3_config.max_concurrent_requests = config.doh3_max_concurrent_requests;
                h3_config.idle_timeout = Duration::from_millis(config.doh3_idle_timeout_ms);
                h3_config.acl.clone_from(&acl);
                h3_config.cache_control = true;
                Some(
                    Doh3Server::bind_shared(h3_config, Arc::clone(&handler), metrics.doh3_stats())
                        .map_err(|source| TlsError::Doh3Start { addr, source })?,
                )
            }
            None => None,
        };
        let doq = match config.doq_listen {
            Some(addr) => {
                let tls = doq_tls_config(cert_path, key_path)?;
                let mut doq_config = DoqConfig::new(addr, tls);
                doq_config.max_connections = config.doq_max_connections;
                doq_config.max_streams = config.doq_max_streams;
                doq_config.max_message_size = config.doq_max_message_size;
                doq_config.idle_timeout = Duration::from_millis(config.doq_idle_timeout_ms);
                doq_config.acl = acl;
                Some(
                    DoqServer::bind_shared(doq_config, Arc::clone(&handler), metrics.doq_stats())
                        .map_err(|source| TlsError::DoqStart { addr, source })?,
                )
            }
            None => None,
        };
        Ok(Some(Self {
            dot,
            doh,
            doh_h2,
            doh3,
            doq,
            dot_counts: metrics.dot_stats(),
            doh_counts: metrics.doh_stats(),
            doh_h2_counts: metrics.doh_h2_stats(),
            doh3_counts: metrics.doh3_stats(),
            doq_counts: metrics.doq_stats(),
            metrics,
        }))
    }

    /// Фактический DoT-адрес.
    pub(crate) fn dot_addr(&self) -> Option<SocketAddr> {
        self.dot.as_ref().map(DotServer::local_addr)
    }

    /// Фактический DoH-адрес.
    pub(crate) fn doh_addr(&self) -> Option<SocketAddr> {
        self.doh.as_ref().map(DohServer::local_addr)
    }

    /// Фактический DoH/HTTP/2-адрес.
    pub(crate) fn doh_h2_addr(&self) -> Option<SocketAddr> {
        self.doh_h2.as_ref().map(Doh2Server::local_addr)
    }

    /// Фактический DoH/HTTP/3-адрес.
    pub(crate) fn doh3_addr(&self) -> Option<SocketAddr> {
        self.doh3.as_ref().map(Doh3Server::local_addr)
    }

    /// Фактический DoQ-адрес.
    pub(crate) fn doq_addr(&self) -> Option<SocketAddr> {
        self.doq.as_ref().map(DoqServer::local_addr)
    }

    /// Снимок счётчиков DoT, если DoT запущен.
    pub(crate) fn dot_stats(&self) -> Option<pulse_tls::StatsSnapshot> {
        self.dot.as_ref().map(|_| self.dot_counts.snapshot())
    }

    /// Снимок счётчиков DoH, если DoH запущен.
    pub(crate) fn doh_stats(&self) -> Option<pulse_tls::StatsSnapshot> {
        self.doh.as_ref().map(|_| self.doh_counts.snapshot())
    }

    /// Снимок счётчиков DoH/HTTP/2, если транспорт запущен.
    pub(crate) fn doh_h2_stats(&self) -> Option<pulse_tls::StatsSnapshot> {
        self.doh_h2.as_ref().map(|_| self.doh_h2_counts.snapshot())
    }

    /// Снимок счётчиков DoH/HTTP/3, если транспорт запущен.
    pub(crate) fn doh3_stats(&self) -> Option<pulse_tls::StatsSnapshot> {
        self.doh3.as_ref().map(|_| self.doh3_counts.snapshot())
    }

    /// Снимок счётчиков DoQ, если транспорт запущен.
    pub(crate) fn doq_stats(&self) -> Option<pulse_tls::StatsSnapshot> {
        self.doq.as_ref().map(|_| self.doq_counts.snapshot())
    }

    /// Перечитывает пару сертификат/ключ для новых соединений.
    ///
    /// Если настроено несколько транспортов, перезагружаются все; первая
    /// ошибка возвращается после попытки обновить каждый.
    ///
    /// # Errors
    ///
    /// [`TlsError::Reload`] при ошибке чтения или парсинга PEM.
    pub(crate) fn reload(&self) -> Result<(), TlsError> {
        let mut first_error = None;
        if let Some(dot) = &self.dot
            && let Err(error) = dot.reload_from_files()
        {
            first_error = Some(error);
        }
        if let Some(doh) = &self.doh
            && let Err(error) = doh.reload_from_files()
        {
            first_error.get_or_insert(error);
        }
        if let Some(doh_h2) = &self.doh_h2
            && let Err(error) = doh_h2.reload_from_files()
        {
            first_error.get_or_insert(error);
        }
        if let Some(doh3) = &self.doh3
            && let Err(error) = doh3.reload_from_files()
        {
            first_error.get_or_insert(error);
        }
        if let Some(doq) = &self.doq
            && let Err(error) = doq.reload_from_files()
        {
            first_error.get_or_insert(error);
        }
        if let Some(error) = first_error {
            self.metrics.tls_reload_error();
            Err(TlsError::Reload(error))
        } else {
            self.metrics.tls_reload();
            Ok(())
        }
    }

    /// Останавливает DoT/DoH.
    ///
    /// # Errors
    ///
    /// [`TlsError`] при ошибке join'а accept-потока.
    pub(crate) fn shutdown(&mut self) -> Result<(), TlsError> {
        let mut first_error = None;
        if let Some(mut dot) = self.dot.take()
            && let Err(error) = dot.shutdown()
        {
            first_error = Some(TlsError::DotShutdown(error));
        }
        if let Some(mut doh) = self.doh.take()
            && let Err(error) = doh.shutdown()
        {
            first_error.get_or_insert(TlsError::DohShutdown(error));
        }
        if let Some(mut doh_h2) = self.doh_h2.take()
            && let Err(error) = doh_h2.shutdown()
        {
            first_error.get_or_insert(TlsError::Doh2Shutdown(error));
        }
        if let Some(mut doh3) = self.doh3.take()
            && let Err(error) = doh3.shutdown()
        {
            first_error.get_or_insert(TlsError::Doh3Shutdown(error));
        }
        if let Some(mut doq) = self.doq.take()
            && let Err(error) = doq.shutdown()
        {
            first_error.get_or_insert(TlsError::DoqShutdown(error));
        }
        first_error.map_or(Ok(()), Err)
    }
}

fn dot_tls_config(cert: &Path, key: &Path) -> Result<TlsConfig, TlsError> {
    TlsConfig::from_pem_files(cert, key, &[b"dot"])
        .map_err(|error| TlsError::Config(format!("DoT certificate: {error}")))
}

fn doh_tls_config(cert: &Path, key: &Path) -> Result<TlsConfig, TlsError> {
    TlsConfig::from_pem_files(cert, key, &[b"http/1.1"])
        .map_err(|error| TlsError::Config(format!("DoH certificate: {error}")))
}

fn doh2_tls_config(cert: &Path, key: &Path) -> Result<TlsConfig, TlsError> {
    TlsConfig::from_pem_files(cert, key, &[b"h2"])
        .map_err(|error| TlsError::Config(format!("DoH/HTTP/2 certificate: {error}")))
}

fn doh3_tls_config(cert: &Path, key: &Path) -> Result<TlsConfig, TlsError> {
    TlsConfig::from_pem_files(cert, key, &[b"h3"])
        .map_err(|error| TlsError::Config(format!("DoH/HTTP/3 certificate: {error}")))
}

fn doq_tls_config(cert: &Path, key: &Path) -> Result<TlsConfig, TlsError> {
    TlsConfig::from_pem_files(cert, key, &[b"doq"])
        .map_err(|error| TlsError::Config(format!("DoQ certificate: {error}")))
}

fn build_acl(rules: &[String]) -> Result<Option<Acl>, TlsError> {
    if rules.is_empty() {
        return Ok(None);
    }
    Acl::from_cidrs(rules)
        .map(Some)
        .map_err(|error| TlsError::Config(format!("tls_allow_from: {error}")))
}
