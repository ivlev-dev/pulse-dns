//! TTL: 31-битное значение (RFC 2181 §8, INV-3).

use std::fmt;

use thiserror::Error;

/// Максимальный TTL: `2^31 − 1` (RFC 2181 §8).
pub const TTL_MAX: u32 = 0x7FFF_FFFF;

/// Ошибка создания [`Ttl`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TtlError {
    /// Значение больше `2^31 − 1`.
    #[error("ttl {value} exceeds maximum {TTL_MAX}")]
    OutOfRange {
        /// Переданное значение.
        value: u32,
    },
}

/// Time-to-live DNS-записи.
///
/// Инвариант: `0..=2^31−1`. Значения из wire-формата и текстового импорта
/// clamp'ятся (с признаком нормализации), а не маскируются (INV-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Ttl(u32);

impl Ttl {
    /// Ноль секунд.
    pub const ZERO: Self = Self(0);

    /// Создаёт TTL, отклоняя значения вне диапазона.
    ///
    /// # Errors
    ///
    /// [`TtlError::OutOfRange`], если `value > 2^31−1`.
    pub const fn new(value: u32) -> Result<Self, TtlError> {
        if value > TTL_MAX {
            return Err(TtlError::OutOfRange { value });
        }
        Ok(Self(value))
    }

    /// Создаёт TTL из wire-значения с clamp к максимуму.
    #[must_use]
    pub const fn from_wire(value: u32) -> Self {
        if value > TTL_MAX {
            Self(TTL_MAX)
        } else {
            Self(value)
        }
    }

    /// Создаёт TTL из wire-значения, сообщая, был ли он clamp'нут.
    ///
    /// Возвращает `(ttl, normalized)`; `normalized == true` соответствует
    /// установке флага `TTL_NORMALIZED` в вызывающем слое.
    #[must_use]
    pub const fn from_wire_normalized(value: u32) -> (Self, bool) {
        (Self::from_wire(value), value > TTL_MAX)
    }

    /// Значение в секундах.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

impl fmt::Display for Ttl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Ttl> for u32 {
    fn from(value: Ttl) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamps_without_masking() {
        assert_eq!(Ttl::from_wire(0x8000_0001).as_u32(), TTL_MAX);
        assert_eq!(Ttl::from_wire(0xFFFF_FFFF).as_u32(), TTL_MAX);
        assert_eq!(Ttl::from_wire(42).as_u32(), 42);
    }

    #[test]
    fn normalization_flag() {
        assert_eq!(Ttl::from_wire_normalized(TTL_MAX), (Ttl(TTL_MAX), false));
        assert_eq!(Ttl::from_wire_normalized(TTL_MAX + 1), (Ttl(TTL_MAX), true));
    }

    #[test]
    fn new_rejects_out_of_range() {
        assert!(Ttl::new(TTL_MAX).is_ok());
        assert!(Ttl::new(TTL_MAX + 1).is_err());
    }
}
