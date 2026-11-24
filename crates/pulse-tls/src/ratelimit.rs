//! Простой per-IP token bucket.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::error::Error;

const STALE_AFTER: Duration = Duration::from_secs(300);
const MAX_BUCKETS_HARD_LIMIT: usize = 1_000_000;

/// Настройки rate limiter.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RateLimitConfig {
    /// Максимальный запас токенов (он же burst).
    pub burst: u32,
    /// Пополнение токенов в секунду.
    pub refill_per_sec: f64,
    /// Максимум записей (IP) в таблице.
    pub max_entries: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            burst: 100,
            refill_per_sec: 20.0,
            max_entries: 10_000,
        }
    }
}

impl RateLimitConfig {
    fn validate(self) -> Result<(), Error> {
        if self.burst == 0 {
            return Err(Error::InvalidConfig("rate limit burst must be positive"));
        }
        if !self.refill_per_sec.is_finite() || self.refill_per_sec <= 0.0 {
            return Err(Error::InvalidConfig(
                "rate limit refill_per_sec must be finite and positive",
            ));
        }
        if self.max_entries == 0 || self.max_entries > MAX_BUCKETS_HARD_LIMIT {
            return Err(Error::InvalidConfig(
                "rate limit max_entries is out of range",
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Per-IP token bucket с ограниченной таблицей.
///
/// Если таблица заполнена и среди записей нет «остывших», новые адреса
/// отклоняются: это защищает память от потока уникальных source IP.
#[derive(Debug)]
pub struct RateLimiter {
    config: RateLimitConfig,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

impl RateLimiter {
    /// Создаёт limiter.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] при некорректных параметрах.
    pub fn new(config: RateLimitConfig) -> Result<Self, Error> {
        config.validate()?;
        Ok(Self {
            config,
            buckets: Mutex::new(HashMap::new()),
        })
    }

    /// Проверяет запрос и списывает один токен.
    #[must_use]
    pub fn allow(&self, ip: IpAddr) -> bool {
        self.allow_at(ip, Instant::now())
    }

    /// Настройки limiter.
    #[must_use]
    pub fn config(&self) -> RateLimitConfig {
        self.config
    }

    fn allow_at(&self, ip: IpAddr, now: Instant) -> bool {
        let mut buckets = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(bucket) = buckets.get_mut(&ip) {
            refill(bucket, now, self.config);
            bucket.last = now;
            if bucket.tokens >= 1.0 {
                bucket.tokens -= 1.0;
                return true;
            }
            return false;
        }
        if buckets.len() >= self.config.max_entries {
            buckets.retain(|_, bucket| now.duration_since(bucket.last) < STALE_AFTER);
            if buckets.len() >= self.config.max_entries {
                return false;
            }
        }
        buckets.insert(
            ip,
            Bucket {
                tokens: f64::from(self.config.burst) - 1.0,
                last: now,
            },
        );
        true
    }
}

fn refill(bucket: &mut Bucket, now: Instant, config: RateLimitConfig) {
    let elapsed = now.duration_since(bucket.last).as_secs_f64();
    let capacity = f64::from(config.burst);
    bucket.tokens = (bucket.tokens + elapsed * config.refill_per_sec).min(capacity);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter() -> RateLimiter {
        RateLimiter::new(RateLimitConfig {
            burst: 2,
            refill_per_sec: 1.0,
            max_entries: 8,
        })
        .expect("limiter")
    }

    #[test]
    fn burst_then_refill() {
        let limiter = limiter();
        let ip: IpAddr = "192.0.2.1".parse().expect("ip");
        let start = Instant::now();
        assert!(limiter.allow_at(ip, start));
        assert!(limiter.allow_at(ip, start));
        assert!(!limiter.allow_at(ip, start));
        assert!(limiter.allow_at(ip, start + Duration::from_secs(1)));
    }

    #[test]
    fn table_is_bounded() {
        let limiter = RateLimiter::new(RateLimitConfig {
            burst: 1,
            refill_per_sec: 1.0,
            max_entries: 1,
        })
        .expect("limiter");
        let start = Instant::now();
        assert!(limiter.allow_at("192.0.2.1".parse().expect("ip"), start));
        assert!(!limiter.allow_at("192.0.2.2".parse().expect("ip"), start));
    }
}
