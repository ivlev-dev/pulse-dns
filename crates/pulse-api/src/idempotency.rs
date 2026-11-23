//! In-memory идемпотентность (`Idempotency-Key`).
//!
//! Ключ уникален в рамках `(token_id, method, path)`; тело сравнивается по
//! SHA-256. Успешные ответы (2xx) сохраняются на TTL; повторы получают тот же
//! ответ с `Idempotent-Replay: true`. Конфликт тела и параллельный повтор
//! различаются по кодам.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::http::HttpResponse;

const MAX_KEY_BYTES: usize = 512;

/// Результат начала идемпотентной операции.
#[derive(Debug)]
pub(crate) enum Begin {
    /// Ключ новый; выполнение разрешено.
    New,
    /// Повтор с тем же телом; нужно вернуть сохранённый ответ.
    Replay(HttpResponse),
    /// Тот же ключ с другим телом.
    Conflict,
    /// Первый запрос ещё выполняется.
    InProgress,
}

struct Entry {
    body_hash: [u8; 32],
    created: Instant,
    last_used: u64,
    state: State,
}

enum State {
    InProgress,
    Done {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
}

#[derive(Default)]
struct Inner {
    entries: HashMap<String, Entry>,
    tick: u64,
}

/// Хранилище идемпотентных ответов с LRU-вытеснением.
pub(crate) struct IdempotencyStore {
    inner: Mutex<Inner>,
    ttl: Duration,
    capacity: usize,
}

impl IdempotencyStore {
    /// Создаёт хранилище.
    pub(crate) fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            ttl,
            capacity: capacity.max(1),
        }
    }

    /// Начинает операцию.
    pub(crate) fn begin(&self, key: &str, body_hash: [u8; 32]) -> Begin {
        if key.len() > MAX_KEY_BYTES {
            return Begin::Conflict;
        }
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.tick = inner.tick.wrapping_add(1);
        let tick = inner.tick;
        let now = Instant::now();
        inner
            .entries
            .retain(|_, entry| now.duration_since(entry.created) <= self.ttl);
        if let Some(entry) = inner.entries.get_mut(key) {
            if entry.body_hash != body_hash {
                return Begin::Conflict;
            }
            match &entry.state {
                State::InProgress => Begin::InProgress,
                State::Done {
                    status,
                    headers,
                    body,
                } => {
                    entry.last_used = tick;
                    let mut response = HttpResponse {
                        status: *status,
                        headers: headers.clone(),
                        body: body.clone(),
                    };
                    response.set_header("Idempotent-Replay", "true");
                    Begin::Replay(response)
                }
            }
        } else {
            if inner.entries.len() >= self.capacity {
                evict_lru(&mut inner);
            }
            inner.entries.insert(
                key.to_owned(),
                Entry {
                    body_hash,
                    created: now,
                    last_used: tick,
                    state: State::InProgress,
                },
            );
            Begin::New
        }
    }

    /// Сохраняет успешный ответ.
    pub(crate) fn complete(&self, key: &str, response: &HttpResponse) {
        if !(200..300).contains(&response.status) {
            self.abort(key);
            return;
        }
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.tick = inner.tick.wrapping_add(1);
        let tick = inner.tick;
        if let Some(entry) = inner.entries.get_mut(key) {
            entry.last_used = tick;
            entry.state = State::Done {
                status: response.status,
                headers: response.headers.clone(),
                body: response.body.clone(),
            };
        }
    }

    /// Удаляет запись (ошибка/4xx/5xx).
    pub(crate) fn abort(&self, key: &str) {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.entries.remove(key);
    }
}

fn evict_lru(inner: &mut Inner) {
    if let Some(oldest) = inner
        .entries
        .iter()
        .min_by_key(|(_, entry)| entry.last_used)
        .map(|(key, _)| key.clone())
    {
        inner.entries.remove(&oldest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(status: u16, body: &str) -> HttpResponse {
        HttpResponse::json(status, serde_json::json!({ "body": body }))
    }

    #[test]
    fn replay_same_body() {
        let store = IdempotencyStore::new(Duration::from_secs(60), 8);
        let key = "token|PUT|/api/v1/zones/example.com.";
        assert!(matches!(store.begin(key, [1; 32]), Begin::New));
        store.complete(key, &response(201, "created"));
        match store.begin(key, [1; 32]) {
            Begin::Replay(response) => {
                assert_eq!(response.status, 201);
                assert_eq!(response.header("Idempotent-Replay"), Some("true"));
            }
            other => panic!("expected replay, got {other:?}"),
        }
    }

    #[test]
    fn different_body_conflicts() {
        let store = IdempotencyStore::new(Duration::from_secs(60), 8);
        let key = "k";
        assert!(matches!(store.begin(key, [1; 32]), Begin::New));
        assert!(matches!(store.begin(key, [2; 32]), Begin::Conflict));
    }

    #[test]
    fn in_progress_detected() {
        let store = IdempotencyStore::new(Duration::from_secs(60), 8);
        assert!(matches!(store.begin("k", [1; 32]), Begin::New));
        assert!(matches!(store.begin("k", [1; 32]), Begin::InProgress));
    }

    #[test]
    fn abort_removes() {
        let store = IdempotencyStore::new(Duration::from_secs(60), 8);
        assert!(matches!(store.begin("k", [1; 32]), Begin::New));
        store.abort("k");
        assert!(matches!(store.begin("k", [1; 32]), Begin::New));
    }

    #[test]
    fn lru_eviction() {
        let store = IdempotencyStore::new(Duration::from_secs(60), 2);
        for key in ["a", "b"] {
            assert!(matches!(store.begin(key, [1; 32]), Begin::New));
        }
        assert!(matches!(store.begin("c", [1; 32]), Begin::New));
        assert!(matches!(store.begin("a", [1; 32]), Begin::New));
    }

    #[test]
    fn errors_not_stored() {
        let store = IdempotencyStore::new(Duration::from_secs(60), 8);
        assert!(matches!(store.begin("k", [1; 32]), Begin::New));
        store.complete("k", &response(422, "bad"));
        assert!(matches!(store.begin("k", [1; 32]), Begin::New));
    }
}
