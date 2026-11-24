//! Пул keep-alive соединений к одному upstream.
//!
//! Пул ленивый: соединение создаётся только когда все свободные слоты пусты,
//! поэтому последовательные запросы переиспользуют одно соединение, а
//! параллельные занимают до `size` соединений. Число слотов одновременно
//! является лимитом in-flight запросов: если все соединения заняты, новый
//! запрос ждёт свободный слот до общего дедлайна и получает
//! [`Error::Timeout`].
//!
//! Health-состояние ведётся по upstream: после неудачного подключения пул
//! уходит в cooldown с экспоненциальным backoff (от `reconnect_backoff` до
//! `max_reconnect_backoff`). Уже открытые idle-соединения при этом остаются
//! доступными; cooldown влияет только на создание новых.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::error::Error;

/// Размер пула по умолчанию.
pub const DEFAULT_POOL_SIZE: usize = 4;

/// Максимальный размер пула.
pub const MAX_POOL_SIZE: usize = 64;

/// Параметры пула соединений.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolConfig {
    /// Число keep-alive соединений (оно же лимит одновременных запросов).
    pub size: usize,
    /// Начальная задержка переподключения после ошибки.
    pub reconnect_backoff: Duration,
    /// Максимальная задержка переподключения.
    pub max_reconnect_backoff: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            size: DEFAULT_POOL_SIZE,
            reconnect_backoff: Duration::from_millis(100),
            max_reconnect_backoff: Duration::from_secs(5),
        }
    }
}

impl PoolConfig {
    /// Проверяет параметры пула.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] при размере вне `1..=64` или некорректном
    /// backoff.
    pub fn validate(self) -> Result<Self, Error> {
        if !(1..=MAX_POOL_SIZE).contains(&self.size) {
            return Err(Error::InvalidConfig("pool size must be in 1..=64"));
        }
        if self.reconnect_backoff.is_zero() || self.max_reconnect_backoff < self.reconnect_backoff {
            return Err(Error::InvalidConfig(
                "reconnect backoff must be positive and not exceed the maximum",
            ));
        }
        Ok(self)
    }

    fn backoff(self, failures: u32) -> Duration {
        let shift = failures.saturating_sub(1).min(16);
        let factor = 1_u32 << shift;
        self.reconnect_backoff
            .saturating_mul(factor)
            .min(self.max_reconnect_backoff)
    }
}

/// Снимок счётчиков пула.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PoolStats {
    /// Выдачи соединения вызывающему.
    pub acquires: u64,
    /// Из них переиспользовано уже открытых соединений.
    pub reuses: u64,
    /// Открытых новых соединений.
    pub opens: u64,
    /// Запросов, ждавших свободный слот.
    pub waits: u64,
    /// Соединений, выброшенных после ошибки.
    pub discards: u64,
    /// Неудачных попыток подключения.
    pub connect_failures: u64,
    /// Отказов из-за активного cooldown.
    pub cooldowns: u64,
}

#[derive(Debug, Default)]
struct Counters {
    acquires: AtomicU64,
    reuses: AtomicU64,
    opens: AtomicU64,
    waits: AtomicU64,
    discards: AtomicU64,
    connect_failures: AtomicU64,
    cooldowns: AtomicU64,
}

impl Counters {
    fn snapshot(&self) -> PoolStats {
        PoolStats {
            acquires: self.acquires.load(Ordering::Relaxed),
            reuses: self.reuses.load(Ordering::Relaxed),
            opens: self.opens.load(Ordering::Relaxed),
            waits: self.waits.load(Ordering::Relaxed),
            discards: self.discards.load(Ordering::Relaxed),
            connect_failures: self.connect_failures.load(Ordering::Relaxed),
            cooldowns: self.cooldowns.load(Ordering::Relaxed),
        }
    }
}

enum Slot<T> {
    Empty,
    Busy,
    Idle(T),
}

pub(crate) struct Pool<T> {
    config: PoolConfig,
    slots: Vec<Mutex<Slot<T>>>,
    cursor: AtomicUsize,
    failures: AtomicU64,
    cooldown_until: Mutex<Option<Instant>>,
    counters: Counters,
}

/// Занятый слот пула. Соединение возвращается в пул при `drop`; чтобы
/// выбросить сломанное соединение, вызовите [`Reservation::discard`].
pub(crate) struct Reservation<'a, T> {
    pool: &'a Pool<T>,
    index: usize,
    connection: Option<T>,
}

impl<T> Reservation<'_, T> {
    /// Соединение слота.
    ///
    /// # Errors
    ///
    /// [`Error::Shutdown`], если слот уже освобождён (внутренний инвариант).
    pub(crate) fn connection(&mut self) -> Result<&mut T, Error> {
        self.connection.as_mut().ok_or(Error::Shutdown)
    }

    /// Помечает соединение сломанным: слот станет пустым.
    pub(crate) fn discard(mut self) {
        self.connection = None;
    }
}

impl<T> Drop for Reservation<'_, T> {
    fn drop(&mut self) {
        match self.connection.take() {
            Some(connection) => self.pool.store_idle(self.index, connection),
            None => {
                self.pool.store_empty(self.index);
                self.pool.counters.discards.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

impl<T> std::fmt::Debug for Reservation<'_, T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Reservation")
            .field("index", &self.index)
            .field("occupied", &self.connection.is_some())
            .finish_non_exhaustive()
    }
}

impl<T> Pool<T> {
    pub(crate) fn new(config: PoolConfig) -> Result<Self, Error> {
        let config = config.validate()?;
        let mut slots = Vec::with_capacity(config.size);
        for _ in 0..config.size {
            slots.push(Mutex::new(Slot::Empty));
        }
        Ok(Self {
            config,
            slots,
            cursor: AtomicUsize::new(0),
            failures: AtomicU64::new(0),
            cooldown_until: Mutex::new(None),
            counters: Counters::default(),
        })
    }

    pub(crate) fn config(&self) -> PoolConfig {
        self.config
    }

    pub(crate) fn stats(&self) -> PoolStats {
        self.counters.snapshot()
    }

    /// Занимает слот: переиспользует idle-соединение или создаёт новое
    /// через `connect`.
    ///
    /// # Errors
    ///
    /// Ошибка `connect`, [`Error::Cooldown`] во время backoff или
    /// [`Error::Timeout`], если свободный слот не появился до `deadline`.
    pub(crate) fn checkout<F>(
        &self,
        deadline: Instant,
        connect: F,
    ) -> Result<Reservation<'_, T>, Error>
    where
        F: FnOnce(Instant) -> Result<T, Error>,
    {
        let mut waits = false;
        let mut connect = Some(connect);
        loop {
            let start = self.cursor.fetch_add(1, Ordering::Relaxed);
            // 1) Сначала ищем уже открытые idle-соединения: последовательные
            //    запросы должны переиспользовать одно соединение.
            for offset in 0..self.config.size {
                let index = start.wrapping_add(offset) % self.config.size;
                let Some(slot_mutex) = self.slots.get(index) else {
                    continue;
                };
                let mut slot = lock(slot_mutex);
                if matches!(&*slot, Slot::Idle(_)) {
                    let Slot::Idle(connection) = std::mem::replace(&mut *slot, Slot::Busy) else {
                        continue;
                    };
                    drop(slot);
                    self.counters.acquires.fetch_add(1, Ordering::Relaxed);
                    self.counters.reuses.fetch_add(1, Ordering::Relaxed);
                    return Ok(Reservation {
                        pool: self,
                        index,
                        connection: Some(connection),
                    });
                }
            }
            // 2) Свободных соединений нет — открываем новое в пустом слоте.
            for offset in 0..self.config.size {
                let index = start.wrapping_add(offset) % self.config.size;
                let Some(slot_mutex) = self.slots.get(index) else {
                    continue;
                };
                let mut slot = lock(slot_mutex);
                if !matches!(&*slot, Slot::Empty) {
                    continue;
                }
                if let Some(retry_after) = self.cooldown_remaining() {
                    drop(slot);
                    self.counters.cooldowns.fetch_add(1, Ordering::Relaxed);
                    return Err(Error::Cooldown { retry_after });
                }
                *slot = Slot::Busy;
                drop(slot);
                let Some(connector) = connect.take() else {
                    self.store_empty(index);
                    return Err(Error::Shutdown);
                };
                match connector(deadline) {
                    Ok(connection) => {
                        self.failures.store(0, Ordering::Relaxed);
                        *lock(&self.cooldown_until) = None;
                        self.counters.acquires.fetch_add(1, Ordering::Relaxed);
                        self.counters.opens.fetch_add(1, Ordering::Relaxed);
                        return Ok(Reservation {
                            pool: self,
                            index,
                            connection: Some(connection),
                        });
                    }
                    Err(error) => {
                        self.store_empty(index);
                        self.record_failure();
                        self.counters
                            .connect_failures
                            .fetch_add(1, Ordering::Relaxed);
                        return Err(error);
                    }
                }
            }
            if !waits {
                waits = true;
                self.counters.waits.fetch_add(1, Ordering::Relaxed);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(Error::Timeout);
            }
            let pause = deadline
                .saturating_duration_since(now)
                .min(Duration::from_millis(1));
            std::thread::sleep(pause);
        }
    }

    fn cooldown_remaining(&self) -> Option<Duration> {
        let until = (*lock(&self.cooldown_until))?;
        let now = Instant::now();
        (now < until).then(|| until.saturating_duration_since(now))
    }

    fn record_failure(&self) {
        let failures = self
            .failures
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        let failures = u32::try_from(failures).unwrap_or(u32::MAX);
        let delay = self.config.backoff(failures);
        *lock(&self.cooldown_until) = Instant::now().checked_add(delay);
    }

    fn store_idle(&self, index: usize, connection: T) {
        if let Some(slot) = self.slots.get(index) {
            *lock(slot) = Slot::Idle(connection);
        }
    }

    fn store_empty(&self, index: usize) {
        if let Some(slot) = self.slots.get(index) {
            *lock(slot) = Slot::Empty;
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Connection {
        id: u64,
    }

    fn pool(size: usize) -> Pool<Connection> {
        Pool::new(PoolConfig {
            size,
            reconnect_backoff: Duration::from_millis(10),
            max_reconnect_backoff: Duration::from_millis(50),
        })
        .expect("pool")
    }

    fn soon() -> Instant {
        Instant::now() + Duration::from_secs(1)
    }

    #[test]
    fn reuses_one_connection_sequentially() {
        let pool = pool(4);
        let mut opened = 0_u64;
        for _ in 0..4 {
            let mut reservation = pool
                .checkout(soon(), |_| {
                    opened += 1;
                    Ok(Connection { id: opened })
                })
                .expect("checkout");
            assert_eq!(reservation.connection().expect("connection").id, 1);
        }
        assert_eq!(opened, 1);
        let stats = pool.stats();
        assert_eq!(stats.opens, 1);
        assert_eq!(stats.reuses, 3);
        assert_eq!(stats.discards, 0);
    }

    #[test]
    fn discard_forces_new_connection() {
        let pool = pool(1);
        let mut opened = 0_u64;
        let mut first = pool
            .checkout(soon(), |_| {
                opened += 1;
                Ok(Connection { id: opened })
            })
            .expect("first");
        assert_eq!(first.connection().expect("connection").id, 1);
        first.discard();
        let mut second = pool
            .checkout(soon(), |_| {
                opened += 1;
                Ok(Connection { id: opened })
            })
            .expect("second");
        assert_eq!(second.connection().expect("connection").id, 2);
        assert_eq!(pool.stats().discards, 1);
    }

    #[test]
    fn parallel_checkouts_use_all_slots() {
        let pool = std::sync::Arc::new(pool(3));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut threads = Vec::new();
        for id in 0..3_u64 {
            let pool = std::sync::Arc::clone(&pool);
            let barrier = std::sync::Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                let mut reservation = pool
                    .checkout(soon(), |_| Ok(Connection { id }))
                    .expect("checkout");
                barrier.wait();
                assert_eq!(reservation.connection().expect("connection").id, id);
            }));
        }
        for thread in threads {
            thread.join().expect("thread");
        }
        assert_eq!(pool.stats().opens, 3);
    }

    #[test]
    fn failed_connect_sets_cooldown() {
        let pool = pool(1);
        let error = pool
            .checkout(soon(), |_| Err(Error::Timeout))
            .expect_err("connect failure");
        assert!(error.is_timeout());
        let error = pool
            .checkout(soon(), |_| Ok(Connection { id: 1 }))
            .expect_err("cooldown");
        assert!(matches!(error, Error::Cooldown { .. }));
        std::thread::sleep(Duration::from_millis(25));
        let mut reservation = pool
            .checkout(soon(), |_| Ok(Connection { id: 2 }))
            .expect("after cooldown");
        assert_eq!(reservation.connection().expect("connection").id, 2);
        assert_eq!(pool.stats().connect_failures, 1);
    }

    #[test]
    fn busy_pool_times_out() {
        let pool = pool(1);
        let mut reservation = pool
            .checkout(soon(), |_| Ok(Connection { id: 1 }))
            .expect("first");
        assert!(reservation.connection().is_ok());
        let deadline = Instant::now() + Duration::from_millis(10);
        let error = pool
            .checkout(deadline, |_| Ok(Connection { id: 2 }))
            .expect_err("pool exhausted");
        assert!(error.is_timeout());
        assert_eq!(pool.stats().waits, 1);
    }
}
