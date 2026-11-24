//! Источник времени для проверки сертификатов и anti-replay.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Абстрактные часы в секундах Unix.
pub trait Clock: Send + Sync {
    /// Текущее время в секундах с 1970-01-01 UTC.
    fn now_unix_secs(&self) -> u64;
}

/// Системные часы.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs())
    }
}

/// Ручные часы для детерминированных тестов.
#[derive(Debug, Default)]
pub struct ManualClock {
    now: AtomicU64,
}

impl ManualClock {
    /// Создаёт часы с заданным временем.
    #[must_use]
    pub fn new(now_unix_secs: u64) -> Self {
        Self {
            now: AtomicU64::new(now_unix_secs),
        }
    }

    /// Устанавливает время.
    pub fn set(&self, now_unix_secs: u64) {
        self.now.store(now_unix_secs, Ordering::Relaxed);
    }

    /// Продвигает время вперёд.
    pub fn advance(&self, seconds: u64) {
        let current = self.now.load(Ordering::Relaxed);
        self.now
            .store(current.saturating_add(seconds), Ordering::Relaxed);
    }
}

impl Clock for ManualClock {
    fn now_unix_secs(&self) -> u64 {
        self.now.load(Ordering::Relaxed)
    }
}
