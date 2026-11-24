//! Интеграция `pulse-tls` (DoT/DoH) в `pulsed`.
//!
//! Оба сервера используют один и тот же путь ответа, что и UDP/TCP:
//! `decode → QueryEngine (mmap snapshot) → encode`. Сертификат читается из
//! файлов; `SIGHUP` и `tls_reload_secs` перечитывают пару для новых
//! соединений (открытые TLS-сессии остаются на старой паре).

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use pulse_server::Transport;
use pulse_tls::{
    Acl, DnsHandler, DohConfig, DohServer, DotConfig, DotServer, Stats as TlsStats, TlsConfig,
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
    /// Остановка DoT завершилась ошибкой.
    #[error("DoT shutdown failed: {0}")]
    DotShutdown(#[source] pulse_tls::Error),
    /// Остановка DoH завершилась ошибкой.
    #[error("DoH shutdown failed: {0}")]
    DohShutdown(#[source] pulse_tls::Error),
    /// Не удалось перечитать сертификат.
    #[error("cannot reload TLS certificate: {0}")]
    Reload(#[source] pulse_tls::Error),
}

/// Запущенные DoT/DoH-серверы.
pub(crate) struct TlsTransports {
    dot: Option<DotServer>,
    doh: Option<DohServer>,
    dot_counts: Arc<TlsStats>,
    doh_counts: Arc<TlsStats>,
    metrics: Arc<TransportMetrics>,
}

impl TlsTransports {
    /// Запускает настроенные DoT/DoH-серверы.
    ///
    /// # Errors
    ///
    /// [`TlsError`] при ошибке чтения сертификата, ACL или bind.
    pub(crate) fn start(
        config: &Config,
        admin: Arc<SharedZoneAdmin>,
        stats: Arc<Stats>,
        metrics: Arc<TransportMetrics>,
    ) -> Result<Option<Self>, TlsError> {
        if config.dot_listen.is_none() && config.doh_listen.is_none() {
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
                doh_config.acl = acl;
                doh_config.cache_control = true;
                Some(
                    DohServer::bind_shared(doh_config, Arc::clone(&handler), metrics.doh_stats())
                        .map_err(|source| TlsError::DohStart { addr, source })?,
                )
            }
            None => None,
        };
        Ok(Some(Self {
            dot,
            doh,
            dot_counts: metrics.dot_stats(),
            doh_counts: metrics.doh_stats(),
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

    /// Снимок счётчиков DoT, если DoT запущен.
    pub(crate) fn dot_stats(&self) -> Option<pulse_tls::StatsSnapshot> {
        self.dot.as_ref().map(|_| self.dot_counts.snapshot())
    }

    /// Снимок счётчиков DoH, если DoH запущен.
    pub(crate) fn doh_stats(&self) -> Option<pulse_tls::StatsSnapshot> {
        self.doh.as_ref().map(|_| self.doh_counts.snapshot())
    }

    /// Перечитывает пару сертификат/ключ для новых соединений.
    ///
    /// Если DoT и DoH настроены, перезагружаются оба; первая ошибка
    /// возвращается после попытки обновить оба.
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

fn build_acl(rules: &[String]) -> Result<Option<Acl>, TlsError> {
    if rules.is_empty() {
        return Ok(None);
    }
    Acl::from_cidrs(rules)
        .map(Some)
        .map_err(|error| TlsError::Config(format!("tls_allow_from: {error}")))
}
