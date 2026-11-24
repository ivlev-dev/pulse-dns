//! In-memory ring-буфер аудита управляющих операций (`rest-v1.md` §7.10).
//!
//! Хранятся только метаданные: principal (id токена), действие, ресурс,
//! результат, причина и `request_id`. Тело запроса, секреты и source IP в
//! аудит не попадают.

use std::collections::VecDeque;
use std::sync::{Mutex, PoisonError};
use std::time::SystemTime;

use crate::base64url;

/// Запись аудита.
#[derive(Debug, Clone)]
pub(crate) struct AuditEntry {
    /// Монотонный номер (курсор).
    pub(crate) seq: u64,
    /// Время события.
    pub(crate) at: SystemTime,
    /// Principal (id токена, не секрет).
    pub(crate) principal: String,
    /// Действие (`zone.create`, `rrset.put`, ...).
    pub(crate) action: String,
    /// Ресурс (origin или path).
    pub(crate) resource: String,
    /// Результат (`success`/`failed`/`denied`).
    pub(crate) result: String,
    /// Причина/код ошибки.
    pub(crate) reason: Option<String>,
    /// Идентификатор запроса.
    pub(crate) request_id: String,
}

/// Фильтр аудита.
#[derive(Debug, Clone, Default)]
pub(crate) struct AuditQuery {
    /// Размер страницы.
    pub(crate) limit: u32,
    /// Непрозрачный курсор.
    pub(crate) cursor: Option<String>,
    /// Фильтр по principal.
    pub(crate) principal: Option<String>,
    /// Фильтр по действию.
    pub(crate) action: Option<String>,
    /// Фильтр по результату.
    pub(crate) result: Option<String>,
}

/// Страница аудита.
#[derive(Debug, Clone)]
pub(crate) struct AuditPage {
    /// Записи в порядке возрастания `seq`.
    pub(crate) items: Vec<AuditEntry>,
    /// Курсор следующей страницы.
    pub(crate) next_cursor: Option<String>,
    /// Есть ли ещё записи.
    pub(crate) has_more: bool,
}

/// Ring-буфер аудита.
pub(crate) struct AuditLog {
    inner: Mutex<AuditInner>,
    capacity: usize,
}

struct AuditInner {
    next_seq: u64,
    entries: VecDeque<AuditEntry>,
}

impl AuditLog {
    /// Создаёт буфер ёмкостью `capacity`.
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(AuditInner {
                next_seq: 1,
                entries: VecDeque::new(),
            }),
            capacity: capacity.max(64),
        }
    }

    /// Добавляет запись.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record(
        &self,
        principal: &str,
        action: &str,
        resource: &str,
        result: &str,
        reason: Option<&str>,
        request_id: &str,
    ) {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let seq = inner.next_seq;
        inner.next_seq = inner.next_seq.saturating_add(1);
        inner.entries.push_back(AuditEntry {
            seq,
            at: SystemTime::now(),
            principal: sanitize(principal, 128),
            action: sanitize(action, 128),
            resource: sanitize(resource, 512),
            result: sanitize(result, 32),
            reason: reason.map(|reason| sanitize(reason, 128)),
            request_id: sanitize(request_id, 128),
        });
        while inner.entries.len() > self.capacity {
            inner.entries.pop_front();
        }
    }

    /// Читает страницу.
    pub(crate) fn list(&self, query: &AuditQuery) -> AuditPage {
        let limit = if query.limit == 0 {
            50
        } else {
            query.limit.min(500)
        } as usize;
        let cursor = query
            .cursor
            .as_deref()
            .and_then(base64url::decode)
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .and_then(|text| text.parse::<u64>().ok());
        let inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let mut items: Vec<AuditEntry> = inner
            .entries
            .iter()
            .filter(|entry| cursor.is_none_or(|cursor| entry.seq > cursor))
            .filter(|entry| {
                query
                    .principal
                    .as_deref()
                    .is_none_or(|principal| entry.principal == principal)
            })
            .filter(|entry| {
                query
                    .action
                    .as_deref()
                    .is_none_or(|action| entry.action == action)
            })
            .filter(|entry| {
                query
                    .result
                    .as_deref()
                    .is_none_or(|result| entry.result == result)
            })
            .cloned()
            .collect();
        items.sort_by_key(|entry| entry.seq);
        let mut has_more = false;
        if items.len() > limit {
            items.truncate(limit);
            has_more = true;
        }
        let next_cursor = if has_more {
            items
                .last()
                .map(|entry| base64url::encode(entry.seq.to_string().as_bytes()))
        } else {
            None
        };
        AuditPage {
            items,
            next_cursor,
            has_more,
        }
    }
}

fn sanitize(value: &str, max: usize) -> String {
    value
        .chars()
        .take(max)
        .map(|character| {
            if character.is_whitespace() || character.is_control() {
                '_'
            } else {
                character
            }
        })
        .collect()
}
