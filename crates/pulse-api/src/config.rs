//! Конфигурация HTTP-сервера управления.

use std::net::SocketAddr;
use std::time::Duration;

use thiserror::Error;

use crate::auth::{AuthConfigError, Authenticator, TokenConfig};

/// Лимит тела запроса по умолчанию: 16 MiB (ADR 0004 SEC-API-005).
pub const DEFAULT_MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
/// Таймаут чтения запроса по умолчанию: 30 с (`rest-v1.md` §2.5).
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Таймаут записи ответа по умолчанию.
pub const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// TTL записи идемпотентности по умолчанию: 10 минут (MVP).
pub const DEFAULT_IDEMPOTENCY_TTL: Duration = Duration::from_secs(600);
/// Ёмкость in-memory LRU идемпотентности.
pub const DEFAULT_IDEMPOTENCY_CAPACITY: usize = 1024;
/// Rate limit по умолчанию: 100 rps на токен (`rest-v1.md` §2.5).
pub const DEFAULT_RATE_LIMIT_PER_SEC: u32 = 100;
/// Максимум одновременных соединений.
pub const DEFAULT_MAX_CONNECTIONS: usize = 64;

/// Ошибка конфигурации сервера.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ApiConfigError {
    /// Нарушение модели безопасности bind (ADR 0004 SEC-API-001/003).
    #[error("refusing to bind {addr}: only loopback bind is allowed without TLS")]
    NonLoopbackBind {
        /// Запрошенный адрес.
        addr: SocketAddr,
    },
    /// Нет ни одного токена.
    #[error("at least one API token must be configured")]
    NoTokens,
    /// Некорректный лимит тела.
    #[error("max_body_bytes must be greater than zero")]
    ZeroBodyLimit,
    /// Некорректный rate limit.
    #[error("rate_limit_per_sec must be greater than zero")]
    ZeroRateLimit,
    /// Некорректный лимит соединений.
    #[error("max_connections must be greater than zero")]
    ZeroConnectionLimit,
    /// Нулевой таймаут.
    #[error("timeouts must be greater than zero")]
    ZeroTimeout,
    /// Нулевая ёмкость кэша идемпотентности.
    #[error("idempotency_capacity must be greater than zero")]
    ZeroIdempotencyCapacity,
    /// Ошибка конфигурации токенов.
    #[error(transparent)]
    Auth(#[from] AuthConfigError),
}

/// Конфигурация API-сервера.
#[derive(Debug, Clone)]
pub struct ApiConfig {
    /// Адрес прослушивания. Разрешён только loopback без TLS.
    pub bind: SocketAddr,
    /// Bearer-токены и их права.
    pub tokens: Vec<TokenConfig>,
    /// Максимальный размер тела запроса.
    pub max_body_bytes: usize,
    /// Общий таймаут чтения запроса (заголовки + тело).
    pub request_timeout: Duration,
    /// Таймаут записи ответа.
    pub write_timeout: Duration,
    /// Rate limit запросов в секунду на токен.
    pub rate_limit_per_sec: u32,
    /// Время жизни записи идемпотентности.
    pub idempotency_ttl: Duration,
    /// Ёмкость LRU идемпотентности.
    pub idempotency_capacity: usize,
    /// Максимум одновременных соединений.
    pub max_connections: usize,
}

impl ApiConfig {
    /// Конфигурация с дефолтами и заданными токенами.
    ///
    /// Bind по умолчанию — `127.0.0.1:8080`.
    pub fn new(tokens: Vec<TokenConfig>) -> Self {
        Self {
            bind: SocketAddr::from(([127, 0, 0, 1], 8080)),
            tokens,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            write_timeout: DEFAULT_WRITE_TIMEOUT,
            rate_limit_per_sec: DEFAULT_RATE_LIMIT_PER_SEC,
            idempotency_ttl: DEFAULT_IDEMPOTENCY_TTL,
            idempotency_capacity: DEFAULT_IDEMPOTENCY_CAPACITY,
            max_connections: DEFAULT_MAX_CONNECTIONS,
        }
    }

    /// Проверяет конфигурацию и собирает аутентификатор.
    ///
    /// # Errors
    ///
    /// [`ApiConfigError`] при нарушении security-политики bind или
    /// некорректных лимитах/токенах.
    pub fn validate(&self) -> Result<Authenticator, ApiConfigError> {
        if !self.bind.ip().is_loopback() {
            return Err(ApiConfigError::NonLoopbackBind { addr: self.bind });
        }
        if self.tokens.is_empty() {
            return Err(ApiConfigError::NoTokens);
        }
        if self.max_body_bytes == 0 {
            return Err(ApiConfigError::ZeroBodyLimit);
        }
        if self.rate_limit_per_sec == 0 {
            return Err(ApiConfigError::ZeroRateLimit);
        }
        if self.max_connections == 0 {
            return Err(ApiConfigError::ZeroConnectionLimit);
        }
        if self.request_timeout.is_zero() || self.write_timeout.is_zero() {
            return Err(ApiConfigError::ZeroTimeout);
        }
        if self.idempotency_capacity == 0 {
            return Err(ApiConfigError::ZeroIdempotencyCapacity);
        }
        let authenticator = Authenticator::new(&self.tokens)?;
        Ok(authenticator)
    }
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_loopback_rejected() {
        let mut config = ApiConfig::new(vec![crate::auth::TokenConfig {
            id: "a".to_owned(),
            token: "secret".to_owned(),
            scopes: vec!["admin".to_owned()],
            zone_scope: None,
        }]);
        config.bind = SocketAddr::from(([0, 0, 0, 0], 8080));
        assert!(matches!(
            config.validate(),
            Err(ApiConfigError::NonLoopbackBind { .. })
        ));
    }

    #[test]
    fn empty_tokens_rejected() {
        let config = ApiConfig::new(Vec::new());
        assert!(matches!(config.validate(), Err(ApiConfigError::NoTokens)));
    }
}
