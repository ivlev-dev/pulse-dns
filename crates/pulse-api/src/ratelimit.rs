//! Простой per-token token bucket.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Решение лимитера.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Decision {
    /// Разрешён ли запрос.
    pub(crate) allowed: bool,
    /// Остаток.
    pub(crate) remaining: u32,
    /// Лимит.
    pub(crate) limit: u32,
    /// Секунды до пополнения/сброса.
    pub(crate) reset_seconds: u32,
    /// `Retry-After` для отказа.
    pub(crate) retry_after: Option<u32>,
}

/// Per-token rate limiter.
pub(crate) struct RateLimiter {
    rate: f64,
    capacity: f64,
    limit: u32,
    inner: Mutex<HashMap<String, Bucket>>,
}

impl RateLimiter {
    /// Создаёт лимитер.
    pub(crate) fn new(rate_per_second: u32) -> Self {
        let rate = f64::from(rate_per_second.max(1));
        Self {
            rate,
            capacity: rate,
            limit: rate_per_second.max(1),
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Проверяет запрос.
    pub(crate) fn check(&self, token_id: &str) -> Decision {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if inner.len() > 4096 {
            inner.retain(|_, bucket| now.duration_since(bucket.last).as_secs() < 600);
        }
        let bucket = inner.entry(token_id.to_owned()).or_insert(Bucket {
            tokens: self.capacity,
            last: now,
        });
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rate).min(self.capacity);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            let reset = ((self.capacity - bucket.tokens) / self.rate).ceil();
            Decision {
                allowed: true,
                remaining: bucket.tokens.floor().max(0.0) as u32,
                limit: self.limit,
                reset_seconds: seconds(reset),
                retry_after: None,
            }
        } else {
            let retry = ((1.0 - bucket.tokens) / self.rate).ceil();
            Decision {
                allowed: false,
                remaining: 0,
                limit: self.limit,
                reset_seconds: seconds(retry),
                retry_after: Some(seconds(retry).max(1)),
            }
        }
    }
}

fn seconds(value: f64) -> u32 {
    if !value.is_finite() || value <= 0.0 {
        return 0;
    }
    u32::try_from(value.ceil() as u64).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_after_budget() {
        let limiter = RateLimiter::new(2);
        assert!(limiter.check("t").allowed);
        assert!(limiter.check("t").allowed);
        let denied = limiter.check("t");
        assert!(!denied.allowed);
        assert_eq!(denied.retry_after, Some(1));
    }

    #[test]
    fn separate_tokens_have_separate_buckets() {
        let limiter = RateLimiter::new(1);
        assert!(limiter.check("a").allowed);
        assert!(limiter.check("b").allowed);
        assert!(!limiter.check("a").allowed);
    }
}
