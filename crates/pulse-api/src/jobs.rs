//! In-memory реестр асинхронных операций (`docs/api/rest-v1.md` §6).
//!
//! Jobs живут `ttl` после завершения и не содержат секретов: только вид,
//! ресурс, состояние, результат и машиночитаемую ошибку. Отменённые и
//! завершённые записи остаются доступными на чтение до истечения TTL.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use serde_json::Value;

use crate::base64url;

/// Состояние job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JobState {
    /// Ожидает запуска.
    Pending,
    /// Выполняется.
    Running,
    /// Завершён успешно.
    Done,
    /// Завершён с ошибкой.
    Failed,
    /// Отменён.
    Cancelled,
}

impl JobState {
    /// Строковое значение для API.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Done => "done",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    /// Терминальное ли состояние.
    pub(crate) const fn is_terminal(self) -> bool {
        matches!(self, Self::Done | Self::Failed | Self::Cancelled)
    }
}

/// Ошибка job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JobFailure {
    /// Машиночитаемый вид ошибки.
    pub(crate) kind: String,
    /// Человекочитаемое описание без внутренних деталей.
    pub(crate) detail: String,
    /// Можно ли повторить операцию.
    pub(crate) retryable: bool,
}

impl JobFailure {
    /// Создаёт ошибку.
    pub(crate) fn new(kind: impl Into<String>, detail: impl Into<String>, retryable: bool) -> Self {
        Self {
            kind: kind.into(),
            detail: detail.into(),
            retryable,
        }
    }
}

/// Запись job.
#[derive(Debug, Clone)]
pub(crate) struct JobRecord {
    /// Идентификатор `job_...`.
    pub(crate) id: String,
    /// Монотонный номер для keyset-пагинации.
    pub(crate) seq: u64,
    /// Вид операции (`zone_transfer`, `zone_import`, ...).
    pub(crate) kind: String,
    /// Ресурс (`/api/v1/zones/example.com.`).
    pub(crate) resource: String,
    /// Зона, если операция zone-scoped (для allowlist-фильтра).
    pub(crate) zone: Option<String>,
    /// Состояние.
    pub(crate) state: JobState,
    /// Создан.
    pub(crate) created_at: SystemTime,
    /// Запущен.
    pub(crate) started_at: Option<SystemTime>,
    /// Завершён.
    pub(crate) finished_at: Option<SystemTime>,
    /// Истекает (для завершённых).
    pub(crate) expires_at: Option<SystemTime>,
    /// Результат.
    pub(crate) result: Option<Value>,
    /// Ошибка.
    pub(crate) error: Option<JobFailure>,
    /// Можно ли отменить.
    pub(crate) cancellable: bool,
    /// Флаг отмены для worker'а.
    pub(crate) cancel: Arc<AtomicBool>,
}

/// Результат отмены.
#[derive(Debug, Clone)]
pub(crate) enum CancelOutcome {
    /// Отмена запрошена/выполнена (`202`).
    Accepted(JobRecord),
    /// Job уже завершён (`200`).
    Terminal(JobRecord),
    /// Job не найден/истёк.
    NotFound,
}

/// Фильтр списка jobs.
#[derive(Debug, Clone, Default)]
pub(crate) struct JobQuery {
    /// Размер страницы.
    pub(crate) limit: u32,
    /// Непрозрачный курсор.
    pub(crate) cursor: Option<String>,
    /// Фильтр по состоянию.
    pub(crate) state: Option<JobState>,
    /// Фильтр по виду.
    pub(crate) kind: Option<String>,
    /// Фильтр по зоне (для `/zones/{z}/transfers`).
    pub(crate) zone: Option<String>,
}

/// Страница jobs.
#[derive(Debug, Clone)]
pub(crate) struct JobPage {
    /// Записи.
    pub(crate) items: Vec<JobRecord>,
    /// Следующий курсор.
    pub(crate) next_cursor: Option<String>,
    /// Есть ли ещё.
    pub(crate) has_more: bool,
}

struct Inner {
    next_seq: u64,
    next_id: u64,
    jobs: HashMap<String, JobRecord>,
    order: VecDeque<String>,
}

/// Реестр jobs.
pub(crate) struct JobRegistry {
    inner: Mutex<Inner>,
    ttl: Duration,
    capacity: usize,
}

impl JobRegistry {
    /// Создаёт реестр.
    pub(crate) fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                next_seq: 1,
                next_id: 1,
                jobs: HashMap::new(),
                order: VecDeque::new(),
            }),
            ttl,
            capacity: capacity.max(16),
        }
    }

    /// Создаёт job и возвращает его идентификатор.
    pub(crate) fn create(
        &self,
        kind: &str,
        resource: &str,
        zone: Option<String>,
        cancellable: bool,
    ) -> String {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let seq = inner.next_seq;
        inner.next_seq = inner.next_seq.saturating_add(1);
        let id_number = inner.next_id;
        inner.next_id = inner.next_id.saturating_add(1);
        let id = format!("job_{seq:016x}_{id_number:08x}");
        let record = JobRecord {
            id: id.clone(),
            seq,
            kind: kind.to_owned(),
            resource: resource.to_owned(),
            zone,
            state: JobState::Pending,
            created_at: SystemTime::now(),
            started_at: None,
            finished_at: None,
            expires_at: None,
            result: None,
            error: None,
            cancellable,
            cancel: Arc::new(AtomicBool::new(false)),
        };
        inner.jobs.insert(id.clone(), record);
        inner.order.push_back(id.clone());
        inner.evict(self.capacity);
        id
    }

    /// Помечает job выполняющимся.
    pub(crate) fn start(&self, id: &str) -> bool {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(record) = inner.jobs.get_mut(id) else {
            return false;
        };
        if record.state != JobState::Pending {
            return false;
        }
        record.state = JobState::Running;
        record.started_at = Some(SystemTime::now());
        true
    }

    /// Завершает job.
    pub(crate) fn finish(&self, id: &str, outcome: Result<Value, JobFailure>) {
        let now = SystemTime::now();
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let ttl = self.ttl;
        let Some(record) = inner.jobs.get_mut(id) else {
            return;
        };
        if record.state.is_terminal() {
            return;
        }
        record.finished_at = Some(now);
        record.expires_at = now.checked_add(ttl);
        if record.cancel.load(Ordering::Acquire) {
            record.state = JobState::Cancelled;
            record.result = None;
            record.error = None;
            return;
        }
        match outcome {
            Ok(value) => {
                record.state = JobState::Done;
                record.result = Some(value);
                record.error = None;
            }
            Err(error) => {
                record.state = JobState::Failed;
                record.result = None;
                record.error = Some(error);
            }
        }
    }

    /// Отменяет job.
    pub(crate) fn cancel(&self, id: &str) -> CancelOutcome {
        let now = SystemTime::now();
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(record) = inner.jobs.get_mut(id) else {
            return CancelOutcome::NotFound;
        };
        if record.state.is_terminal() {
            return CancelOutcome::Terminal(record.clone());
        }
        record.cancel.store(true, Ordering::Release);
        if record.state == JobState::Pending {
            record.state = JobState::Cancelled;
            record.finished_at = Some(now);
            record.expires_at = now.checked_add(self.ttl);
        }
        CancelOutcome::Accepted(record.clone())
    }

    /// Читает job.
    pub(crate) fn get(&self, id: &str) -> Option<JobRecord> {
        let now = SystemTime::now();
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.remove_expired(now);
        inner.jobs.get(id).cloned()
    }

    /// Список jobs с keyset-пагинацией.
    pub(crate) fn list(&self, query: &JobQuery) -> JobPage {
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
        let now = SystemTime::now();
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.remove_expired(now);
        let mut records: Vec<JobRecord> = inner
            .order
            .iter()
            .filter_map(|id| inner.jobs.get(id).cloned())
            .filter(|record| cursor.is_none_or(|cursor| record.seq > cursor))
            .filter(|record| query.state.is_none_or(|state| record.state == state))
            .filter(|record| query.kind.as_deref().is_none_or(|kind| record.kind == kind))
            .filter(|record| {
                query
                    .zone
                    .as_deref()
                    .is_none_or(|zone| record.zone.as_deref() == Some(zone))
            })
            .collect();
        records.sort_by_key(|record| record.seq);
        let mut has_more = false;
        if records.len() > limit {
            records.truncate(limit);
            has_more = true;
        }
        let next_cursor = if has_more {
            records
                .last()
                .map(|record| base64url::encode(record.seq.to_string().as_bytes()))
        } else {
            None
        };
        JobPage {
            items: records,
            next_cursor,
            has_more,
        }
    }
}

impl Inner {
    fn remove_expired(&mut self, now: SystemTime) {
        let expired: Vec<String> = self
            .jobs
            .iter()
            .filter(|(_, record)| record.expires_at.is_some_and(|expires| now >= expires))
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired {
            self.jobs.remove(&id);
            self.order.retain(|candidate| candidate != &id);
        }
    }

    fn evict(&mut self, capacity: usize) {
        while self.jobs.len() > capacity {
            let Some(id) = self.order.pop_front() else {
                break;
            };
            self.jobs.remove(&id);
        }
    }
}
