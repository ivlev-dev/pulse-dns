//! Порядковый номер зоны SOA: арифметика RFC 1982 (`domain-model.md` §2.6).

use std::cmp::Ordering;
use std::fmt;

/// 32-битный serial зоны.
///
/// Не реализует [`Ord`]/[`PartialOrd`]: сравнение только через
/// [`Serial::cmp_rfc1982`] и [`Serial::is_newer_than`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Serial(u32);

impl Serial {
    /// Начальное значение новой зоны.
    pub const ZERO: Self = Self(0);

    /// Создаёт serial из полного 32-битного значения.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Синоним [`Serial::new`] для wire-декодера.
    #[must_use]
    pub const fn from_wire(value: u32) -> Self {
        Self(value)
    }

    /// Значение как `u32`.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Следующий serial: `(self + 1) mod 2^32`.
    #[must_use]
    pub const fn succ(self) -> Self {
        Self(self.0.wrapping_add(1))
    }

    /// Сравнение по RFC 1982 §3.2.
    ///
    /// Возвращает `None` при неопределённости (разность ровно `2^31`).
    #[must_use]
    pub const fn cmp_rfc1982(self, other: Self) -> Option<Ordering> {
        if self.0 == other.0 {
            return Some(Ordering::Equal);
        }
        let forward = other.0.wrapping_sub(self.0);
        if forward < 0x8000_0000 {
            return Some(Ordering::Less);
        }
        let backward = self.0.wrapping_sub(other.0);
        if backward < 0x8000_0000 {
            return Some(Ordering::Greater);
        }
        None
    }

    /// Является ли `self` строго новее `other`.
    ///
    /// `None` — неопределённость RFC 1982.
    #[must_use]
    pub const fn is_newer_than(self, other: Self) -> Option<bool> {
        match self.cmp_rfc1982(other) {
            Some(ordering) => Some(matches!(ordering, Ordering::Greater)),
            None => None,
        }
    }

    /// Разность `self − other mod 2^32`, если она меньше `2^31`.
    ///
    /// Используется IXFR: `None` означает, что дельта слишком велика
    /// (нужен AXFR).
    #[must_use]
    pub const fn diff(self, other: Self) -> Option<u32> {
        let delta = self.0.wrapping_sub(other.0);
        if delta < 0x8000_0000 {
            Some(delta)
        } else {
            None
        }
    }
}

impl fmt::Display for Serial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u32> for Serial {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<Serial> for u32 {
    fn from(value: Serial) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;

    use super::*;

    #[test]
    fn ordering_basic() {
        assert_eq!(
            Serial::new(1).cmp_rfc1982(Serial::new(2)),
            Some(Ordering::Less)
        );
        assert_eq!(
            Serial::new(2).cmp_rfc1982(Serial::new(1)),
            Some(Ordering::Greater)
        );
        assert_eq!(
            Serial::new(7).cmp_rfc1982(Serial::new(7)),
            Some(Ordering::Equal)
        );
    }

    #[test]
    fn wrap_around() {
        let max = Serial::new(0xFFFF_FFFF);
        assert_eq!(max.succ(), Serial::ZERO);
        assert_eq!(Serial::ZERO.is_newer_than(max), Some(true));
        assert_eq!(max.is_newer_than(Serial::ZERO), Some(false));
    }

    #[test]
    fn ambiguous_half_range() {
        let low = Serial::ZERO;
        let half = Serial::new(0x8000_0000);
        assert_eq!(low.cmp_rfc1982(half), None);
        assert_eq!(half.cmp_rfc1982(low), None);
        assert_eq!(low.is_newer_than(half), None);
    }

    #[test]
    fn diff_limits() {
        assert_eq!(Serial::new(5).diff(Serial::new(2)), Some(3));
        assert_eq!(Serial::new(2).diff(Serial::new(5)), None);
        assert_eq!(Serial::new(0x8000_0000).diff(Serial::ZERO), None);
        assert_eq!(
            Serial::new(0x7FFF_FFFF).diff(Serial::ZERO),
            Some(0x7FFF_FFFF)
        );
    }

    #[test]
    fn succ_round_trips() {
        let mut serial = Serial::new(0xFFFF_FFFE);
        serial = serial.succ();
        assert_eq!(serial, Serial::new(0xFFFF_FFFF));
        assert_eq!(serial.succ(), Serial::ZERO);
    }
}
