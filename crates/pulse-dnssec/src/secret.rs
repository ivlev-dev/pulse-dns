//! Обёртка секретного материала: zeroize при выгрузке, `Debug` без данных.
//!
//! Тип намеренно не реализует [`Clone`], [`PartialEq`], `Display` и
//! `Serialize`: случайное копирование и сравнение секретов запрещены
//! (ADR-0004 SEC-CR-003/005).

use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Секретный байтовый буфер (ключевой материал, PKCS#8, seed).
///
/// Содержимое обнуляется при `Drop`; `Debug` показывает только длину.
/// Для доступа к материалу используется явный [`SecretRef::expose`].
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretRef {
    bytes: Vec<u8>,
}

impl SecretRef {
    /// Оборачивает байты, принимая владение.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Копирует срез в секретный буфер.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
        }
    }

    /// Явный доступ к материалу. Вызывающий обязан не логировать результат.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }

    /// Длина материала в байтах.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Пуст ли буфер.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl fmt::Debug for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretRef")
            .field("bytes", &"<redacted>")
            .field("len", &self.bytes.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_leak_material() {
        let secret = SecretRef::from_slice(b"super-secret-key-material");
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("super"));
        assert!(rendered.contains("redacted"));
        assert!(rendered.contains("25"));
        assert_eq!(secret.len(), 25);
    }
}
