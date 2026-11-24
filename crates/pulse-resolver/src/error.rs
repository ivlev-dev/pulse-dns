//! Типизированные ошибки резолвера.
//!
//! Ошибки не содержат секретов и не включают сырые пакеты: только имена,
//! адреса, лимиты и структурные причины.

use std::io;

use pulse_dns::{DecodeError, EncodeError, Rcode};
use thiserror::Error;

use crate::blocklist::BlocklistError;

/// Ошибка конфигурации или резолюции.
#[derive(Debug, Error)]
pub enum ResolverError {
    /// Конфигурация некорректна.
    #[error("invalid resolver configuration: {reason}")]
    Config {
        /// Причина.
        reason: String,
    },
    /// Запрос не является поддерживаемым одиночным QUERY.
    #[error("invalid request: {reason}")]
    InvalidRequest {
        /// Причина.
        reason: &'static str,
    },
    /// Нет ни одного настроенного upstream/forwarder.
    #[error("no upstream servers configured")]
    NoUpstream,
    /// Истёк общий дедлайн резолюции.
    #[error("resolution timed out")]
    Timeout,
    /// Резолюция отменена вызывающим.
    #[error("resolution cancelled")]
    Cancelled,
    /// Ошибка сокета или файла.
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    /// Ошибка защищённого upstream-транспорта (DoT/DoH).
    #[error("upstream transport error: {reason}")]
    Transport {
        /// Причина без секретов.
        reason: String,
    },
    /// Не удалось разобрать ответ upstream.
    #[error("malformed upstream response: {0}")]
    Decode(#[from] DecodeError),
    /// Не удалось закодировать запрос.
    #[error("failed to encode query: {0}")]
    Encode(#[from] EncodeError),
    /// Ответ не соответствует запросу (ID/вопрос/peer/регистр 0x20).
    #[error("upstream response mismatch: {reason}")]
    Mismatch {
        /// Причина.
        reason: &'static str,
    },
    /// Upstream вернул ошибку, которую нельзя отдать как ответ.
    #[error("upstream {server} returned {rcode}")]
    UpstreamRcode {
        /// Сервер.
        server: String,
        /// Код.
        rcode: Rcode,
    },
    /// Делегирование вернулось в уже посещённую зону.
    #[error("delegation loop at {zone}")]
    DelegationLoop {
        /// Зона.
        zone: String,
    },
    /// CNAME-цепочка длиннее лимита.
    #[error("cname chain exceeds {limit} records")]
    CnameChainTooLong {
        /// Лимит.
        limit: usize,
    },
    /// Обнаружен цикл CNAME.
    #[error("cname loop at {name}")]
    CnameLoop {
        /// Имя.
        name: String,
    },
    /// Превышена максимальная глубина рекурсии.
    #[error("resolution depth exceeds {limit}")]
    DepthExceeded {
        /// Лимит.
        limit: usize,
    },
    /// Исчерпан бюджет запросов на одну резолюцию.
    #[error("query budget exhausted ({limit} queries)")]
    QueryBudgetExhausted {
        /// Лимит.
        limit: usize,
    },
    /// Не удалось найти адреса авторитетных серверов зоны.
    #[error("no reachable nameserver for {zone}")]
    NoNameserver {
        /// Зона.
        zone: String,
    },
    /// Ответ не содержит ни делегирования, ни данных, ни SOA.
    #[error("upstream response made no progress at {zone}")]
    NoProgress {
        /// Зона.
        zone: String,
    },
    /// DNSSEC-валидация провалилась (BOGUS).
    #[error("dnssec validation failed: {reason}")]
    Bogus {
        /// Причина.
        reason: String,
    },
    /// Ошибка загрузки/разбора blocklist.
    #[error(transparent)]
    Blocklist(#[from] BlocklistError),
    /// Внутреннее нарушение инварианта (не должно возникать).
    #[error("internal resolver error: {reason}")]
    Internal {
        /// Причина.
        reason: &'static str,
    },
}

impl ResolverError {
    /// Создаёт ошибку конфигурации из строки.
    #[must_use]
    pub fn config(reason: impl Into<String>) -> Self {
        Self::Config {
            reason: reason.into(),
        }
    }

    /// Соответствующий RCODE для ответа клиенту.
    #[must_use]
    pub fn rcode(&self) -> Rcode {
        match self {
            Self::InvalidRequest { .. } => Rcode::FORMERR,
            Self::Config { .. }
            | Self::NoUpstream
            | Self::Timeout
            | Self::Cancelled
            | Self::Io(_)
            | Self::Transport { .. }
            | Self::Decode(_)
            | Self::Encode(_)
            | Self::Mismatch { .. }
            | Self::UpstreamRcode { .. }
            | Self::DelegationLoop { .. }
            | Self::CnameChainTooLong { .. }
            | Self::CnameLoop { .. }
            | Self::DepthExceeded { .. }
            | Self::QueryBudgetExhausted { .. }
            | Self::NoNameserver { .. }
            | Self::NoProgress { .. }
            | Self::Bogus { .. }
            | Self::Internal { .. }
            | Self::Blocklist(_) => Rcode::SERVFAIL,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bogus_maps_to_servfail() {
        let error = ResolverError::Bogus {
            reason: "test".to_owned(),
        };
        assert_eq!(error.rcode(), Rcode::SERVFAIL);
    }

    #[test]
    fn invalid_request_maps_to_formerr() {
        let error = ResolverError::InvalidRequest { reason: "qdcount" };
        assert_eq!(error.rcode(), Rcode::FORMERR);
    }
}
