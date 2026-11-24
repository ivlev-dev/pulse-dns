//! Кэш клиентских nonce для anti-replay.
//!
//! Ключ — пара `(client-pk, client-nonce)`: именно для неё спецификация
//! требует уникальности nonce (§2). Запись живёт `ttl_secs`; при переполнении
//! вытесняется самая старая. Время передаётся снаружи, поэтому поведение
//! детерминировано и тестируемо.

use std::collections::{HashMap, VecDeque};

use crate::crypto::HALF_NONCE_LEN;
use crate::error::Error;
use crate::keys::KEY_LEN;

/// Ключ записи anti-replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct NonceKey {
    client_pk: [u8; KEY_LEN],
    client_nonce: [u8; HALF_NONCE_LEN],
}

/// Кэш использованных клиентских nonce с TTL.
#[derive(Debug)]
pub struct NonceCache {
    ttl_secs: u64,
    capacity: usize,
    expires: HashMap<NonceKey, u64>,
    order: VecDeque<(NonceKey, u64)>,
}

impl NonceCache {
    /// Создаёт кэш с заданным TTL и предельным числом записей.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`], если TTL или ёмкость равны нулю.
    pub fn new(ttl_secs: u64, capacity: usize) -> Result<Self, Error> {
        if ttl_secs == 0 {
            return Err(Error::InvalidConfig {
                field: "replay_ttl_secs",
            });
        }
        if capacity == 0 {
            return Err(Error::InvalidConfig {
                field: "replay_capacity",
            });
        }
        Ok(Self {
            ttl_secs,
            capacity,
            expires: HashMap::new(),
            order: VecDeque::new(),
        })
    }

    /// TTL записей в секундах.
    #[must_use]
    pub const fn ttl_secs(&self) -> u64 {
        self.ttl_secs
    }

    /// Текущее число записей.
    #[must_use]
    pub fn len(&self) -> usize {
        self.expires.len()
    }

    /// Кэш пуст.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.expires.is_empty()
    }

    /// Проверяет nonce и запоминает его.
    ///
    /// Возвращает [`Error::ReplayedNonce`], если пара уже встречалась и её TTL
    /// не истёк. Истёкшие записи удаляются лениво.
    ///
    /// # Errors
    ///
    /// [`Error::ReplayedNonce`].
    pub fn check_and_insert(
        &mut self,
        client_pk: [u8; KEY_LEN],
        client_nonce: [u8; HALF_NONCE_LEN],
        now_secs: u64,
    ) -> Result<(), Error> {
        self.prune(now_secs);
        let key = NonceKey {
            client_pk,
            client_nonce,
        };
        if self.expires.contains_key(&key) {
            return Err(Error::ReplayedNonce);
        }
        while self.expires.len() >= self.capacity {
            self.evict_oldest(now_secs);
        }
        let expiry = now_secs.saturating_add(self.ttl_secs);
        self.expires.insert(key, expiry);
        self.order.push_back((key, expiry));
        Ok(())
    }

    /// Удаляет истёкшие записи из головы очереди.
    fn prune(&mut self, now_secs: u64) {
        while let Some((key, expiry)) = self.order.front().copied() {
            if expiry > now_secs {
                break;
            }
            let _ = self.order.pop_front();
            if self.expires.get(&key).copied() == Some(expiry) {
                self.expires.remove(&key);
            }
        }
    }

    /// Вытесняет самую старую запись.
    fn evict_oldest(&mut self, now_secs: u64) {
        while let Some((key, expiry)) = self.order.pop_front() {
            if self.expires.get(&key).copied() != Some(expiry) {
                continue;
            }
            self.expires.remove(&key);
            if expiry > now_secs {
                break;
            }
        }
        // Если очередь опустела, а записи остались (не должно происходить),
        // очищаем карту, чтобы гарантировать прогресс.
        if self.order.is_empty() && self.expires.len() >= self.capacity {
            self.expires.clear();
        }
    }
}
