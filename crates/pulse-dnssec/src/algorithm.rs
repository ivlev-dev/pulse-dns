//! Политика DNSSEC-алгоритмов (RFC 8624, ADR-0004 SEC-CR-002).
//!
//! Матрица:
//!
//! | Alg | Подпись | Валидация |
//! |-----|---------|-----------|
//! | 1 RSAMD5 | запрещено | запрещено |
//! | 3 DSA/SHA-1 | запрещено | запрещено |
//! | 5 RSASHA1 | запрещено | только legacy opt-in |
//! | 6 DSA-NSEC3-SHA1 | запрещено | запрещено |
//! | 7 RSASHA1-NSEC3-SHA1 | запрещено | только legacy opt-in |
//! | 8 RSASHA256 | да | да |
//! | 10 RSASHA512 | нет | да |
//! | 13 ECDSAP256SHA256 | да | да |
//! | 14 ECDSAP384SHA384 | нет | да |
//! | 15 ED25519 | да | да |
//! | прочие | запрещено | запрещено |

use std::fmt;

/// Номер алгоритма DNSSEC (IANA).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Algorithm(u8);

impl Algorithm {
    /// RSA/MD5 (запрещён).
    pub const RSAMD5: Self = Self(1);
    /// DSA/SHA-1 (запрещён).
    pub const DSA: Self = Self(3);
    /// RSA/SHA-1 (только legacy-валидация).
    pub const RSASHA1: Self = Self(5);
    /// DSA-NSEC3-SHA1 (запрещён).
    pub const DSA_NSEC3_SHA1: Self = Self(6);
    /// RSA/SHA-1 NSEC3 (только legacy-валидация).
    pub const RSASHA1_NSEC3_SHA1: Self = Self(7);
    /// RSA/SHA-256.
    pub const RSASHA256: Self = Self(8);
    /// RSA/SHA-512.
    pub const RSASHA512: Self = Self(10);
    /// GOST R 34.10-2001 (не поддерживается).
    pub const ECC_GOST: Self = Self(12);
    /// ECDSA P-256 + SHA-256.
    pub const ECDSAP256SHA256: Self = Self(13);
    /// ECDSA P-384 + SHA-384.
    pub const ECDSAP384SHA384: Self = Self(14);
    /// Ed25519.
    pub const ED25519: Self = Self(15);
    /// Ed448 (не поддерживается в v1).
    pub const ED448: Self = Self(16);

    /// Создаёт алгоритм из номера.
    #[must_use]
    pub const fn from_u8(value: u8) -> Self {
        Self(value)
    }

    /// Номер алгоритма.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self.0
    }

    /// Поддерживается ли подпись этим алгоритмом.
    #[must_use]
    pub const fn is_sign_supported(self) -> bool {
        matches!(self.0, 8 | 13 | 15)
    }

    /// Поддерживается ли валидация (с учётом только не-legacy набора).
    #[must_use]
    pub const fn is_verify_supported(self) -> bool {
        matches!(self.0, 8 | 10 | 13 | 14 | 15)
    }

    /// Является ли алгоритм legacy SHA-1 (5/7).
    #[must_use]
    pub const fn is_legacy_sha1(self) -> bool {
        matches!(self.0, 5 | 7)
    }

    /// Компактное имя алгоритма.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self.0 {
            1 => "RSAMD5",
            3 => "DSA",
            5 => "RSASHA1",
            6 => "DSA-NSEC3-SHA1",
            7 => "RSASHA1-NSEC3-SHA1",
            8 => "RSASHA256",
            10 => "RSASHA512",
            12 => "ECC-GOST",
            13 => "ECDSAP256SHA256",
            14 => "ECDSAP384SHA384",
            15 => "ED25519",
            16 => "ED448",
            _ => "PRIVATE/UNKNOWN",
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.0, self.name())
    }
}

impl From<u8> for Algorithm {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl From<Algorithm> for u8 {
    fn from(value: Algorithm) -> Self {
        value.0
    }
}

/// Политика допустимых алгоритмов.
///
/// По умолчанию SHA-1 (alg 5/7) выключен; включение — явный opt-in
/// (`allow_legacy_sha1`), как требует ADR-0004 SEC-CR-002.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlgorithmPolicy {
    /// Разрешить legacy-валидацию RSA/SHA-1 (alg 5/7).
    pub allow_legacy_sha1: bool,
}

impl AlgorithmPolicy {
    /// Политика по умолчанию: SHA-1 запрещён.
    #[must_use]
    pub const fn strict() -> Self {
        Self {
            allow_legacy_sha1: false,
        }
    }

    /// Политика с включённой legacy-валидацией SHA-1.
    #[must_use]
    pub const fn with_legacy_sha1() -> Self {
        Self {
            allow_legacy_sha1: true,
        }
    }

    /// Проверяет допустимость алгоритма для подписи.
    ///
    /// # Errors
    ///
    /// [`crate::SignError::AlgorithmNotAllowed`] для запрещённых алгоритмов.
    pub fn check_sign(self, algorithm: Algorithm) -> Result<(), crate::SignError> {
        if algorithm.is_sign_supported() {
            Ok(())
        } else {
            Err(crate::SignError::AlgorithmNotAllowed { algorithm })
        }
    }

    /// Проверяет допустимость алгоритма для валидации.
    ///
    /// # Errors
    ///
    /// [`crate::VerifyError::LegacyDisabled`] для SHA-1 без opt-in;
    /// [`crate::VerifyError::AlgorithmNotAllowed`] для остальных запрещённых.
    pub fn check_verify(self, algorithm: Algorithm) -> Result<(), crate::VerifyError> {
        if algorithm.is_verify_supported() {
            return Ok(());
        }
        if algorithm.is_legacy_sha1() {
            if self.allow_legacy_sha1 {
                return Ok(());
            }
            return Err(crate::VerifyError::LegacyDisabled { algorithm });
        }
        Err(crate::VerifyError::AlgorithmNotAllowed { algorithm })
    }
}

impl Default for AlgorithmPolicy {
    fn default() -> Self {
        Self::strict()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_matrix() {
        assert!(Algorithm::RSASHA256.is_sign_supported());
        assert!(Algorithm::ECDSAP256SHA256.is_sign_supported());
        assert!(Algorithm::ED25519.is_sign_supported());
        assert!(!Algorithm::RSASHA512.is_sign_supported());
        assert!(!Algorithm::RSASHA1.is_sign_supported());
        assert!(!Algorithm::RSAMD5.is_sign_supported());
        assert_eq!(
            AlgorithmPolicy::strict()
                .check_sign(Algorithm::RSASHA1)
                .unwrap_err()
                .to_string(),
            "algorithm 5 (RSASHA1) is not allowed for signing"
        );
    }

    #[test]
    fn verify_matrix() {
        for value in [8_u8, 10, 13, 14, 15] {
            assert!(
                AlgorithmPolicy::strict()
                    .check_verify(Algorithm::from_u8(value))
                    .is_ok()
            );
        }
        assert!(matches!(
            AlgorithmPolicy::strict().check_verify(Algorithm::RSASHA1),
            Err(crate::VerifyError::LegacyDisabled { .. })
        ));
        assert!(
            AlgorithmPolicy::with_legacy_sha1()
                .check_verify(Algorithm::RSASHA1_NSEC3_SHA1)
                .is_ok()
        );
        for value in [1_u8, 3, 6, 12, 16, 253] {
            assert!(matches!(
                AlgorithmPolicy::strict().check_verify(Algorithm::from_u8(value)),
                Err(crate::VerifyError::AlgorithmNotAllowed { .. })
            ));
        }
    }
}
