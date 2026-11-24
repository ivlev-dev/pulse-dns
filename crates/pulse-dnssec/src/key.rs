//! Приватные DNSSEC-ключи: генерация, импорт/экспорт, DNSKEY.
//!
//! Поддерживаются алгоритмы 8 (RSA/SHA-256, 2048/4096), 13 (ECDSA P-256)
//! и 15 (Ed25519). Вся криптография выполняется `aws-lc-rs`; собственных
//! примитивов нет.
//!
//! # Секретность
//!
//! [`PrivateKey`] не реализует [`Clone`] и не печатает материал в `Debug`.
//! Экспортируемые PKCS#8-документы возвращаются в [`SecretRef`] и
//! обнуляются при выгрузке. Внутреннее представление ключа принадлежит
//! `aws-lc-rs` (EVP_PKEY) — оно освобождается библиотекой; промежуточные
//! буферы (DER, PEM) обнуляются через `zeroize`.

use std::fmt;

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::KeySize;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair as _, RSA_PKCS1_SHA256,
    RsaKeyPair,
};
use pulse_dns::DnskeyData;
use zeroize::{Zeroize, Zeroizing};

use crate::algorithm::Algorithm;
use crate::der;
use crate::error::KeyError;
use crate::rdata_util;
use crate::secret::SecretRef;

/// Бит «zone key» в DNSKEY flags (RFC 4034 §2.1.1).
pub const DNSKEY_FLAG_ZONE_KEY: u16 = 0x0100;
/// Бит «secure entry point» (KSK) в DNSKEY flags.
pub const DNSKEY_FLAG_SEP: u16 = 0x0001;

/// Минимальный размер RSA-ключа (ADR-0004).
pub const MIN_RSA_BITS: usize = 2048;

/// Размер RSA-ключа для генерации.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaKeySize {
    /// 2048 бит.
    Bits2048,
    /// 4096 бит.
    Bits4096,
}

impl RsaKeySize {
    const fn bits(self) -> usize {
        match self {
            Self::Bits2048 => 2048,
            Self::Bits4096 => 4096,
        }
    }
}

/// Приватный DNSSEC-ключ.
pub enum PrivateKey {
    /// RSA/SHA-256 (alg 8).
    Rsa(RsaKeyPair),
    /// ECDSA P-256 + SHA-256 (alg 13).
    EcdsaP256(EcdsaKeyPair),
    /// Ed25519 (alg 15).
    Ed25519(Ed25519KeyPair),
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("algorithm", &self.algorithm().name())
            .field("material", &"<redacted>")
            .finish()
    }
}

impl PrivateKey {
    /// Генерирует ключ для алгоритма 8 (2048 бит).
    ///
    /// # Errors
    ///
    /// [`KeyError::UnsupportedAlgorithm`] для algorithm != 8;
    /// [`KeyError::Random`] при отказе CSPRNG.
    pub fn generate(algorithm: Algorithm) -> Result<Self, KeyError> {
        Self::generate_with_rsa_size(algorithm, RsaKeySize::Bits2048)
    }

    /// Генерирует ключ с явным размером RSA (для 8) или дефолтным для 13/15.
    ///
    /// # Errors
    ///
    /// [`KeyError::UnsupportedAlgorithm`] для неподдерживаемых алгоритмов;
    /// [`KeyError::Random`] при отказе CSPRNG.
    pub fn generate_with_rsa_size(
        algorithm: Algorithm,
        rsa_size: RsaKeySize,
    ) -> Result<Self, KeyError> {
        match algorithm.as_u8() {
            8 => {
                let size = match rsa_size.bits() {
                    2048 => KeySize::Rsa2048,
                    4096 => KeySize::Rsa4096,
                    _ => {
                        return Err(KeyError::RsaKeySize {
                            bits: rsa_size.bits(),
                        });
                    }
                };
                let key = RsaKeyPair::generate(size).map_err(|error| KeyError::Crypto {
                    reason: error.to_string(),
                })?;
                Ok(Self::Rsa(key))
            }
            13 => {
                let key =
                    EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).map_err(|error| {
                        KeyError::Crypto {
                            reason: error.to_string(),
                        }
                    })?;
                Ok(Self::EcdsaP256(key))
            }
            15 => {
                let key = Ed25519KeyPair::generate().map_err(|error| KeyError::Crypto {
                    reason: error.to_string(),
                })?;
                Ok(Self::Ed25519(key))
            }
            _ => Err(KeyError::UnsupportedAlgorithm { algorithm }),
        }
    }

    /// Алгоритм ключа.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        match self {
            Self::Rsa(_) => Algorithm::RSASHA256,
            Self::EcdsaP256(_) => Algorithm::ECDSAP256SHA256,
            Self::Ed25519(_) => Algorithm::ED25519,
        }
    }

    /// Импортирует RSA-ключ из DER `RSAPrivateKey` (PKCS#1).
    ///
    /// # Errors
    ///
    /// [`KeyError::KeyRejected`] при отклонении материала библиотекой.
    pub fn from_rsa_der(der_bytes: &[u8]) -> Result<Self, KeyError> {
        let key = RsaKeyPair::from_der(der_bytes).map_err(|error| KeyError::KeyRejected {
            reason: error.to_string(),
        })?;
        ensure_rsa_strength(&key)?;
        Ok(Self::Rsa(key))
    }

    /// Импортирует ключ из PKCS#8 DER.
    ///
    /// # Errors
    ///
    /// [`KeyError::UnsupportedAlgorithm`] для неподдерживаемого алгоритма;
    /// [`KeyError::KeyRejected`] при некорректном материале.
    pub fn from_pkcs8_der(algorithm: Algorithm, der_bytes: &[u8]) -> Result<Self, KeyError> {
        match algorithm.as_u8() {
            8 => {
                let key =
                    RsaKeyPair::from_pkcs8(der_bytes).map_err(|error| KeyError::KeyRejected {
                        reason: error.to_string(),
                    })?;
                Ok(Self::Rsa(key))
            }
            13 => {
                let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der_bytes)
                    .map_err(|error| KeyError::KeyRejected {
                        reason: error.to_string(),
                    })?;
                Ok(Self::EcdsaP256(key))
            }
            15 => {
                let key = Ed25519KeyPair::from_pkcs8(der_bytes).map_err(|error| {
                    KeyError::KeyRejected {
                        reason: error.to_string(),
                    }
                })?;
                Ok(Self::Ed25519(key))
            }
            _ => Err(KeyError::UnsupportedAlgorithm { algorithm }),
        }
    }

    /// Импортирует ключ из PEM (`-----BEGIN PRIVATE KEY-----`).
    ///
    /// # Errors
    ///
    /// [`KeyError::BadPem`] при некорректном PEM;
    /// [`KeyError::KeyRejected`] при некорректном материале.
    pub fn from_pkcs8_pem(algorithm: Algorithm, pem_text: &str) -> Result<Self, KeyError> {
        let parsed = pem::parse(pem_text).map_err(|_| KeyError::BadPem {
            reason: "not a valid PEM document",
        })?;
        if parsed.tag() != "PRIVATE KEY" {
            return Err(KeyError::BadPem {
                reason: "unexpected PEM tag",
            });
        }
        let der_bytes = Zeroizing::new(parsed.contents().to_vec());
        let key = Self::from_pkcs8_der(algorithm, &der_bytes)?;
        let mut contents = parsed.into_contents();
        contents.zeroize();
        Ok(key)
    }

    /// Экспортирует ключ в PKCS#8 DER (обнуляется при выгрузке).
    ///
    /// # Errors
    ///
    /// [`KeyError::Crypto`] при ошибке сериализации.
    pub fn to_pkcs8_der(&self) -> Result<SecretRef, KeyError> {
        match self {
            Self::Rsa(key) => {
                let document = key.as_der().map_err(|error| KeyError::Crypto {
                    reason: error.to_string(),
                })?;
                Ok(SecretRef::from_slice(document.as_ref()))
            }
            Self::EcdsaP256(key) => {
                let document = key.to_pkcs8v1().map_err(|error| KeyError::Crypto {
                    reason: error.to_string(),
                })?;
                Ok(SecretRef::from_slice(document.as_ref()))
            }
            Self::Ed25519(key) => {
                let document = key.to_pkcs8v1().map_err(|error| KeyError::Crypto {
                    reason: error.to_string(),
                })?;
                Ok(SecretRef::from_slice(document.as_ref()))
            }
        }
    }

    /// Экспортирует ключ в PKCS#8 PEM (обнуляется при выгрузке).
    ///
    /// # Errors
    ///
    /// [`KeyError::Crypto`] при ошибке сериализации.
    pub fn to_pkcs8_pem(&self) -> Result<SecretRef, KeyError> {
        let der = self.to_pkcs8_der()?;
        let document = pem::Pem::new("PRIVATE KEY", der.expose().to_vec());
        let pem_text = pem::encode(&document);
        let mut contents = document.into_contents();
        contents.zeroize();
        Ok(SecretRef::new(pem_text.into_bytes()))
    }

    /// Публичный ключ в формате DNSKEY RDATA.
    ///
    /// `flags` — DNSKEY flags (например, `257` для KSK, `256` для ZSK).
    ///
    /// # Errors
    ///
    /// [`KeyError::InvalidPublicKey`] при неожиданной длине/структуре
    /// публичного ключа; [`KeyError::WeakKey`] для RSA < 2048 бит.
    pub fn dnskey(&self, flags: u16) -> Result<DnskeyData, KeyError> {
        let public_key = self.dnskey_public_key()?;
        DnskeyData::new(flags, 3, self.algorithm().as_u8(), public_key).map_err(|error| {
            KeyError::InvalidPublicKey {
                reason: match error {
                    pulse_dns::RdataError::Empty { .. } => "empty public key",
                    pulse_dns::RdataError::TooLong { .. } => "public key too long",
                    _ => "invalid DNSKEY data",
                },
            }
        })
    }

    /// Key tag для соответствующего DNSKEY (RFC 4034 Appendix B).
    ///
    /// # Errors
    ///
    /// Ошибки [`PrivateKey::dnskey`].
    pub fn key_tag(&self, flags: u16) -> Result<u16, KeyError> {
        Ok(rdata_util::key_tag(&self.dnskey(flags)?))
    }

    fn dnskey_public_key(&self) -> Result<Vec<u8>, KeyError> {
        match self {
            Self::Rsa(key) => {
                let der_bytes = key.public_key().as_ref();
                let (modulus, exponent) = der::parse_rsa_public_key(der_bytes)?;
                let bits = modulus.len().saturating_mul(8);
                if bits < MIN_RSA_BITS {
                    return Err(KeyError::WeakKey { bits });
                }
                Ok(rdata_util::encode_rsa_dnskey_key(exponent, modulus))
            }
            Self::EcdsaP256(key) => {
                let point = key.public_key().as_ref();
                let (prefix, coordinates) =
                    point.split_first().ok_or(KeyError::InvalidPublicKey {
                        reason: "empty EC point",
                    })?;
                if *prefix != 0x04 || coordinates.len() != 64 {
                    return Err(KeyError::InvalidPublicKey {
                        reason: "EC point is not an uncompressed P-256 point",
                    });
                }
                Ok(coordinates.to_vec())
            }
            Self::Ed25519(key) => {
                let public = key.public_key().as_ref();
                if public.len() != 32 {
                    return Err(KeyError::InvalidPublicKey {
                        reason: "Ed25519 public key is not 32 bytes",
                    });
                }
                Ok(public.to_vec())
            }
        }
    }

    /// Подписывает сообщение, возвращая «сырую» подпись алгоритма.
    ///
    /// Для alg 8 подпись — RSA PKCS#1 v1.5 с SHA-256; для 13 — fixed
    /// `r||s` (64 байта); для 15 — 64 байта Ed25519.
    ///
    /// # Errors
    ///
    /// [`KeyError::Crypto`] при ошибке подписи.
    pub fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>, KeyError> {
        match self {
            Self::Rsa(key) => {
                let rng = SystemRandom::new();
                let mut signature = vec![0_u8; key.public_modulus_len()];
                key.sign(&RSA_PKCS1_SHA256, &rng, message, &mut signature)
                    .map_err(|_| KeyError::Crypto {
                        reason: "RSA signing failed".to_owned(),
                    })?;
                Ok(signature)
            }
            Self::EcdsaP256(key) => {
                let rng = SystemRandom::new();
                let signature = key.sign(&rng, message).map_err(|error| KeyError::Crypto {
                    reason: error.to_string(),
                })?;
                Ok(signature.as_ref().to_vec())
            }
            Self::Ed25519(key) => {
                let signature = key.try_sign(message).map_err(|error| KeyError::Crypto {
                    reason: error.to_string(),
                })?;
                Ok(signature.as_ref().to_vec())
            }
        }
    }

    /// PKCS#8 DER во временном zeroizing-буфере (для BIND-экспорта).
    pub(crate) fn pkcs8_der_zeroizing(&self) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        let secret = self.to_pkcs8_der()?;
        Ok(Zeroizing::new(secret.expose().to_vec()))
    }
}

fn ensure_rsa_strength(key: &RsaKeyPair) -> Result<(), KeyError> {
    let der_bytes = key.public_key().as_ref();
    let (modulus, _) = der::parse_rsa_public_key(der_bytes)?;
    let bits = modulus.first().map_or(0, |first| {
        modulus
            .len()
            .saturating_mul(8)
            .saturating_sub(first.leading_zeros() as usize)
    });
    if bits < MIN_RSA_BITS {
        return Err(KeyError::WeakKey { bits });
    }
    Ok(())
}
