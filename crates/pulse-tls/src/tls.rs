//! Загрузка PEM-сертификата/ключа и сборка rustls `ServerConfig`.
//!
//! Используется только `aws-lc-rs` provider из rustls; TLS 1.0/1.1
//! не включаются, TLS 1.3 предпочтителен. Сертификат можно заменить на лету
//! методом [`TlsConfig::reload`] — новые соединения увидят новую пару,
//! существующие продолжат работу со старой.

use std::fmt;
use std::fs;
use std::io::{BufReader, Cursor};
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};

use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ServerConnection;

use crate::error::Error;

const ALPN_MAX_LEN: usize = 255;

struct Inner {
    config: RwLock<Arc<ServerConfig>>,
    provider: Arc<CryptoProvider>,
    alpn: Vec<Vec<u8>>,
    paths: Option<(PathBuf, PathBuf)>,
}

/// TLS-конфигурация сервера с возможностью hot-reload сертификата.
#[derive(Clone)]
pub struct TlsConfig {
    inner: Arc<Inner>,
}

impl fmt::Debug for TlsConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsConfig")
            .field("alpn", &self.inner.alpn)
            .field("reloadable_from_files", &self.inner.paths.is_some())
            .finish_non_exhaustive()
    }
}

impl TlsConfig {
    /// Создаёт конфигурацию из PEM-байтов сертификата (цепочки) и ключа.
    ///
    /// `alpn` — список допустимых протоколов; для DoT используйте
    /// [`TlsConfig::for_dot`], для DoH — [`TlsConfig::for_doh`].
    ///
    /// # Errors
    ///
    /// Ошибка чтения PEM, отсутствие сертификата/ключа, несовпадение ключа и
    /// сертификата, некорректный ALPN.
    pub fn from_pem(cert_pem: &[u8], key_pem: &[u8], alpn: &[&[u8]]) -> Result<Self, Error> {
        let alpn = validate_alpn(alpn)?;
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = build_server_config(&provider, cert_pem, key_pem, &alpn)?;
        Ok(Self {
            inner: Arc::new(Inner {
                config: RwLock::new(Arc::new(config)),
                provider,
                alpn,
                paths: None,
            }),
        })
    }

    /// Создаёт конфигурацию из файлов и запоминает пути для
    /// [`TlsConfig::reload_from_files`].
    ///
    /// # Errors
    ///
    /// См. [`TlsConfig::from_pem`], плюс ошибки чтения файлов.
    pub fn from_pem_files(
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
        alpn: &[&[u8]],
    ) -> Result<Self, Error> {
        let cert_path = cert_path.as_ref().to_path_buf();
        let key_path = key_path.as_ref().to_path_buf();
        let cert_pem = fs::read(&cert_path)?;
        let key_pem = fs::read(&key_path)?;
        let alpn = validate_alpn(alpn)?;
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = build_server_config(&provider, &cert_pem, &key_pem, &alpn)?;
        Ok(Self {
            inner: Arc::new(Inner {
                config: RwLock::new(Arc::new(config)),
                provider,
                alpn,
                paths: Some((cert_path, key_path)),
            }),
        })
    }

    /// Конфигурация для DoT (ALPN `dot`, RFC 7858/8310).
    ///
    /// # Errors
    ///
    /// См. [`TlsConfig::from_pem`].
    pub fn for_dot(cert_pem: &[u8], key_pem: &[u8]) -> Result<Self, Error> {
        Self::from_pem(cert_pem, key_pem, &[b"dot"])
    }

    /// Конфигурация для DoH HTTP/1.1 (ALPN `http/1.1`).
    ///
    /// # Errors
    ///
    /// См. [`TlsConfig::from_pem`].
    pub fn for_doh(cert_pem: &[u8], key_pem: &[u8]) -> Result<Self, Error> {
        Self::from_pem(cert_pem, key_pem, &[b"http/1.1"])
    }

    /// Заменяет сертификат и ключ новыми PEM-байтами.
    ///
    /// Новая конфигурация собирается полностью до подмены: при ошибке
    /// продолжает действовать старая.
    ///
    /// # Errors
    ///
    /// См. [`TlsConfig::from_pem`].
    pub fn reload(&self, cert_pem: &[u8], key_pem: &[u8]) -> Result<(), Error> {
        let config =
            build_server_config(&self.inner.provider, cert_pem, key_pem, &self.inner.alpn)?;
        let mut current = self
            .inner
            .config
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        *current = Arc::new(config);
        Ok(())
    }

    /// Перечитывает сертификат и ключ из путей, заданных в
    /// [`TlsConfig::from_pem_files`].
    ///
    /// # Errors
    ///
    /// [`Error::NoCertificatePaths`], если конфигурация создана из байтов,
    /// либо ошибки чтения/парсинга.
    pub fn reload_from_files(&self) -> Result<(), Error> {
        let (cert_path, key_path) = self.inner.paths.as_ref().ok_or(Error::NoCertificatePaths)?;
        let cert_pem = fs::read(cert_path)?;
        let key_pem = fs::read(key_path)?;
        self.reload(&cert_pem, &key_pem)
    }

    /// Текущая rustls-конфигурация для нового соединения.
    #[must_use]
    pub fn server_config(&self) -> Arc<ServerConfig> {
        let config = self
            .inner
            .config
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        Arc::clone(&config)
    }

    /// Список ALPN-протоколов.
    #[must_use]
    pub fn alpn_protocols(&self) -> &[Vec<u8>] {
        &self.inner.alpn
    }

    /// Проверяет, что клиент согласовал ожидаемый ALPN.
    ///
    /// # Errors
    ///
    /// [`Error::AlpnMissing`] или [`Error::AlpnMismatch`].
    pub fn verify_alpn(&self, connection: &ServerConnection) -> Result<(), Error> {
        let expected = self
            .inner
            .alpn
            .first()
            .ok_or(Error::InvalidConfig("ALPN list is empty"))?;
        match connection.alpn_protocol() {
            Some(protocol)
                if self
                    .inner
                    .alpn
                    .iter()
                    .any(|allowed| allowed.as_slice() == protocol) =>
            {
                Ok(())
            }
            Some(protocol) => Err(Error::AlpnMismatch {
                expected: expected.clone(),
                got: protocol.to_vec(),
            }),
            None => Err(Error::AlpnMissing),
        }
    }
}

fn validate_alpn(alpn: &[&[u8]]) -> Result<Vec<Vec<u8>>, Error> {
    if alpn.is_empty() {
        return Err(Error::InvalidConfig("ALPN list must not be empty"));
    }
    let mut result: Vec<Vec<u8>> = Vec::with_capacity(alpn.len());
    for protocol in alpn {
        if protocol.is_empty() || protocol.len() > ALPN_MAX_LEN {
            return Err(Error::InvalidConfig("ALPN protocol length is invalid"));
        }
        if result
            .iter()
            .any(|existing| existing.as_slice() == *protocol)
        {
            return Err(Error::InvalidConfig("duplicate ALPN protocol"));
        }
        result.push(protocol.to_vec());
    }
    Ok(result)
}

fn build_server_config(
    provider: &Arc<CryptoProvider>,
    cert_pem: &[u8],
    key_pem: &[u8],
    alpn: &[Vec<u8>],
) -> Result<ServerConfig, Error> {
    let certificates = parse_certificates(cert_pem)?;
    let key = parse_private_key(key_pem)?;
    let mut config = ServerConfig::builder_with_provider(Arc::clone(provider))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .with_no_client_auth()
        .with_single_cert(certificates, key)?;
    config.alpn_protocols = alpn.to_vec();
    // DoT/DoH не используют TLS 1.3 early data.
    config.max_early_data_size = 0;
    Ok(config)
}

fn parse_certificates(cert_pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, Error> {
    let mut reader = BufReader::new(Cursor::new(cert_pem));
    let certificates = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    if certificates.is_empty() {
        return Err(Error::NoCertificates);
    }
    Ok(certificates)
}

fn parse_private_key(key_pem: &[u8]) -> Result<PrivateKeyDer<'static>, Error> {
    let mut reader = BufReader::new(Cursor::new(key_pem));
    rustls_pemfile::private_key(&mut reader)?.ok_or(Error::NoPrivateKey)
}
