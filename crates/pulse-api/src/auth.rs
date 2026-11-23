//! Bearer-аутентификация, scopes и per-zone allowlist.
//!
//! Модель соответствует `docs/api/rest-v1.md` §2 и ADR 0004 SEC-API-002/014.
//! Токены задаются конфигурацией процесса; сравнение выполняется в
//! constant-time, перебор не прерывается на первом совпадении.

use std::fmt;

use pulse_dns::Name;
use subtle::ConstantTimeEq;
use thiserror::Error;

/// Полный набор scopes v1 (`docs/api/rest-v1.md` §2.2).
const KNOWN_SCOPES: &[&str] = &[
    "zones:read",
    "zones:write",
    "zones:delete",
    "zones:export",
    "replication:read",
    "replication:manage",
    "keys:read",
    "keys:write",
    "keys:export",
    "cache:read",
    "cache:purge",
    "policy:read",
    "policy:write",
    "server:read",
    "server:write",
    "metrics:read",
    "jobs:read",
    "jobs:cancel",
    "audit:read",
    "tokens:admin",
    "admin",
];

/// Ошибка конфигурации аутентификации.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AuthConfigError {
    /// У токена пустой идентификатор.
    #[error("token id must not be empty")]
    EmptyTokenId,
    /// Секрет токена пуст.
    #[error("token secret must not be empty")]
    EmptyToken,
    /// Дублирующийся идентификатор токена.
    #[error("duplicate token id `{id}`")]
    DuplicateTokenId {
        /// Идентификатор.
        id: String,
    },
    /// Неизвестный scope.
    #[error("unknown scope `{scope}` in token `{token_id}`")]
    UnknownScope {
        /// Идентификатор токена.
        token_id: String,
        /// Scope.
        scope: String,
    },
    /// Некорректный origin-шаблон allowlist.
    #[error("invalid zone scope pattern `{pattern}`: {reason}")]
    InvalidZonePattern {
        /// Шаблон.
        pattern: String,
        /// Причина.
        reason: String,
    },
}

/// Конфигурация одного bearer-токена.
///
/// Для MVP секрет хранится в конфиге процесса; хеширование хранилища токенов
/// появится вместе с постоянным token store. Секрет никогда не попадает в
/// аудит-лог и не возвращается по API.
#[derive(Clone, PartialEq, Eq)]
pub struct TokenConfig {
    /// Публичный идентификатор для аудита (не секрет).
    pub id: String,
    /// Секрет токена (`Authorization: Bearer <token>`).
    pub token: String,
    /// Scopes; поддерживаются точные значения, `group:*` и `admin`/`*`.
    pub scopes: Vec<String>,
    /// Origin-шаблоны allowlist: `example.com.` (точно) или `*.internal.`
    /// (поддомены). `None` — доступ ко всем зонам.
    pub zone_scope: Option<Vec<String>>,
}

impl fmt::Debug for TokenConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenConfig")
            .field("id", &self.id)
            .field("token", &"***")
            .field("scopes", &self.scopes)
            .field("zone_scope", &self.zone_scope)
            .finish()
    }
}

/// Набор прав токена.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeSet {
    scopes: Vec<String>,
}

impl ScopeSet {
    /// Разбирает и валидирует scopes.
    ///
    /// # Errors
    ///
    /// [`AuthConfigError::UnknownScope`] для неизвестного значения.
    pub fn parse(token_id: &str, scopes: &[String]) -> Result<Self, AuthConfigError> {
        for scope in scopes {
            if !is_known_scope(scope) {
                return Err(AuthConfigError::UnknownScope {
                    token_id: token_id.to_owned(),
                    scope: scope.clone(),
                });
            }
        }
        Ok(Self {
            scopes: scopes.to_vec(),
        })
    }

    /// Проверяет наличие scope с учётом `group:*`, `admin` и `*`.
    pub fn allows(&self, required: &str) -> bool {
        self.scopes.iter().any(|scope| {
            if scope == "*" || scope == "admin" {
                return true;
            }
            if scope == required {
                return true;
            }
            match required.split_once(':') {
                Some((group, _)) => scope == &format!("{group}:*"),
                None => false,
            }
        })
    }

    /// Перечисление scopes (для диагностики; секретов не содержит).
    pub fn as_slice(&self) -> &[String] {
        &self.scopes
    }
}

fn is_known_scope(scope: &str) -> bool {
    if scope == "*" || KNOWN_SCOPES.contains(&scope) {
        return true;
    }
    let Some(group) = scope.strip_suffix(":*") else {
        return false;
    };
    KNOWN_SCOPES.iter().any(|known| {
        known
            .split_once(':')
            .is_some_and(|(known_group, _)| known_group == group)
    })
}

/// Один origin-шаблон allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ZonePattern {
    Exact(Name),
    Suffix(Name),
}

/// Per-zone allowlist токена.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneScope {
    patterns: Vec<ZonePattern>,
}

impl ZoneScope {
    /// Разбирает список шаблонов.
    ///
    /// # Errors
    ///
    /// [`AuthConfigError::InvalidZonePattern`] для некорректного имени.
    pub fn parse(patterns: &[String]) -> Result<Self, AuthConfigError> {
        let mut parsed = Vec::with_capacity(patterns.len());
        for pattern in patterns {
            let pattern_trimmed = pattern.trim();
            if pattern_trimmed.is_empty() {
                return Err(AuthConfigError::InvalidZonePattern {
                    pattern: pattern.clone(),
                    reason: "empty pattern".to_owned(),
                });
            }
            if pattern_trimmed == "*" {
                parsed.push(ZonePattern::Suffix(Name::root()));
                continue;
            }
            if let Some(rest) = pattern_trimmed.strip_prefix("*.") {
                let name =
                    Name::parse(rest).map_err(|error| AuthConfigError::InvalidZonePattern {
                        pattern: pattern.clone(),
                        reason: error.to_string(),
                    })?;
                if name == Name::root() {
                    return Err(AuthConfigError::InvalidZonePattern {
                        pattern: pattern.clone(),
                        reason: "wildcard over root is not allowed".to_owned(),
                    });
                }
                parsed.push(ZonePattern::Suffix(name));
            } else {
                let name = Name::parse(pattern_trimmed).map_err(|error| {
                    AuthConfigError::InvalidZonePattern {
                        pattern: pattern.clone(),
                        reason: error.to_string(),
                    }
                })?;
                if name == Name::root() {
                    return Err(AuthConfigError::InvalidZonePattern {
                        pattern: pattern.clone(),
                        reason: "root zone is not allowed".to_owned(),
                    });
                }
                parsed.push(ZonePattern::Exact(name));
            }
        }
        Ok(Self { patterns: parsed })
    }

    /// Разрешён ли доступ к зоне.
    pub fn allows(&self, origin: &Name) -> bool {
        self.patterns.iter().any(|pattern| match pattern {
            ZonePattern::Exact(name) => name == origin,
            ZonePattern::Suffix(name) => {
                if name == &Name::root() {
                    true
                } else {
                    origin.label_count() > name.label_count() && origin.is_subdomain_of(name)
                }
            }
        })
    }

    /// Пустой allowlist (ни одна зона не разрешена).
    pub fn deny_all() -> Self {
        Self {
            patterns: Vec::new(),
        }
    }
}

/// Аутентифицированный субъект запроса.
#[derive(Debug, Clone)]
pub struct Principal {
    /// Идентификатор токена для аудита и ключей идемпотентности.
    pub token_id: String,
    /// Scopes.
    pub scopes: ScopeSet,
    /// Per-zone allowlist.
    pub zone_scope: Option<ZoneScope>,
}

impl Principal {
    /// Проверяет allowlist зоны.
    pub fn zone_allowed(&self, origin: &Name) -> bool {
        self.zone_scope
            .as_ref()
            .is_none_or(|scope| scope.allows(origin))
    }

    /// Проверяет operation-scope.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.allows(scope)
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.token_id)
    }
}

#[derive(Clone)]
struct StoredToken {
    id: String,
    secret: Vec<u8>,
    scopes: ScopeSet,
    zone_scope: Option<ZoneScope>,
}

/// Проверка bearer-токенов.
#[derive(Clone)]
pub struct Authenticator {
    tokens: Vec<StoredToken>,
}

impl fmt::Debug for Authenticator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ids: Vec<&str> = self.tokens.iter().map(|token| token.id.as_str()).collect();
        f.debug_struct("Authenticator")
            .field("tokens", &ids)
            .finish()
    }
}

impl Authenticator {
    /// Создаёт аутентификатор из конфигурации токенов.
    ///
    /// # Errors
    ///
    /// [`AuthConfigError`] при пустом/дублирующемся id, пустом секрете,
    /// неизвестном scope или некорректном origin-шаблоне.
    pub fn new(tokens: &[TokenConfig]) -> Result<Self, AuthConfigError> {
        let mut stored: Vec<StoredToken> = Vec::with_capacity(tokens.len());
        for token in tokens {
            if token.id.trim().is_empty() {
                return Err(AuthConfigError::EmptyTokenId);
            }
            if token.token.is_empty() {
                return Err(AuthConfigError::EmptyToken);
            }
            if stored.iter().any(|existing| existing.id == token.id) {
                return Err(AuthConfigError::DuplicateTokenId {
                    id: token.id.clone(),
                });
            }
            let scopes = ScopeSet::parse(&token.id, &token.scopes)?;
            let zone_scope = match &token.zone_scope {
                Some(patterns) => Some(ZoneScope::parse(patterns)?),
                None => None,
            };
            stored.push(StoredToken {
                id: token.id.clone(),
                secret: token.token.as_bytes().to_vec(),
                scopes,
                zone_scope,
            });
        }
        Ok(Self { tokens: stored })
    }

    /// Аутентифицирует заголовок `Authorization`.
    ///
    /// Возвращает `None` для отсутствующего/некорректного/неизвестного токена.
    /// Сравнение constant-time по всем записям без early-return.
    pub fn authenticate(&self, header: &str) -> Option<Principal> {
        let token = parse_bearer(header)?;
        let candidate = token.as_bytes();
        let mut matched_index: Option<usize> = None;
        for (index, stored) in self.tokens.iter().enumerate() {
            let equal = stored.secret.ct_eq(candidate);
            if bool::from(equal) {
                matched_index = Some(index);
            }
        }
        matched_index.and_then(|index| {
            self.tokens.get(index).map(|stored| Principal {
                token_id: stored.id.clone(),
                scopes: stored.scopes.clone(),
                zone_scope: stored.zone_scope.clone(),
            })
        })
    }
}

fn parse_bearer(header: &str) -> Option<&str> {
    let header = header.trim();
    let (scheme, value) = header.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    let value = value.trim();
    if value.is_empty()
        || value.len() > 4096
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return None;
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(id: &str, scopes: &[&str], zone_scope: Option<&[&str]>) -> TokenConfig {
        TokenConfig {
            id: id.to_owned(),
            token: "pd_live_secret".to_owned(),
            scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
            zone_scope: zone_scope.map(|patterns| {
                patterns
                    .iter()
                    .map(|pattern| (*pattern).to_owned())
                    .collect()
            }),
        }
    }

    #[test]
    fn scope_wildcards() {
        let set = ScopeSet::parse("t", &["zones:*".to_owned()]).unwrap();
        assert!(set.allows("zones:read"));
        assert!(set.allows("zones:delete"));
        assert!(!set.allows("keys:read"));
        let admin = ScopeSet::parse("t", &["admin".to_owned()]).unwrap();
        assert!(admin.allows("tokens:admin"));
    }

    #[test]
    fn bearer_requires_scheme() {
        let auth = Authenticator::new(&[token("a", &["zones:read"], None)]).unwrap();
        assert!(auth.authenticate("Bearer pd_live_secret").is_some());
        assert!(auth.authenticate("bearer pd_live_secret").is_some());
        assert!(auth.authenticate("Basic pd_live_secret").is_none());
        assert!(auth.authenticate("Bearer").is_none());
        assert!(auth.authenticate("Bearer wrong").is_none());
    }

    #[test]
    fn zone_scope_exact_and_wildcard() {
        let scope =
            ZoneScope::parse(&["example.com.".to_owned(), "*.internal.".to_owned()]).unwrap();
        assert!(scope.allows(&Name::parse("example.com.").unwrap()));
        assert!(!scope.allows(&Name::parse("www.example.com.").unwrap()));
        assert!(scope.allows(&Name::parse("a.internal.").unwrap()));
        assert!(scope.allows(&Name::parse("a.b.internal.").unwrap()));
        assert!(!scope.allows(&Name::parse("internal.").unwrap()));
        assert!(!scope.allows(&Name::parse("other.").unwrap()));
    }

    #[test]
    fn unknown_scope_rejected() {
        let error = Authenticator::new(&[token("a", &["bogus"], None)]).unwrap_err();
        assert!(matches!(error, AuthConfigError::UnknownScope { .. }));
    }

    #[test]
    fn duplicate_id_rejected() {
        let error = Authenticator::new(&[
            token("a", &["zones:read"], None),
            token("a", &["zones:write"], None),
        ])
        .unwrap_err();
        assert!(matches!(error, AuthConfigError::DuplicateTokenId { .. }));
    }
}
