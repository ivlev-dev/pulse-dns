//! Delegation Signer: digest, key tag, сравнение (RFC 4034 §5, RFC 4509).

use aws_lc_rs::constant_time;
use aws_lc_rs::digest::{SHA1_FOR_LEGACY_USE_ONLY, SHA256, SHA384, digest};
use pulse_dns::{DnskeyData, DsData, Name};

use crate::error::DsError;
use crate::rdata_util::{dnskey_rdata, key_tag, parse_rsa_dnskey_key};

/// Digest type SHA-1 (legacy, RFC 3658).
pub const DIGEST_SHA1: u8 = 1;
/// Digest type SHA-256 (RFC 4509).
pub const DIGEST_SHA256: u8 = 2;
/// Digest type SHA-384 (RFC 6605).
pub const DIGEST_SHA384: u8 = 4;

/// Политика DS-digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DsPolicy {
    /// Разрешить SHA-1 (digest type 1) только для legacy-проверки.
    pub allow_legacy_sha1: bool,
    /// Минимальный размер RSA-ключа при сравнении DS.
    pub min_rsa_bits: usize,
}

impl DsPolicy {
    /// SHA-1 запрещён.
    #[must_use]
    pub const fn strict() -> Self {
        Self {
            allow_legacy_sha1: false,
            min_rsa_bits: 2048,
        }
    }

    /// SHA-1 разрешён (legacy-совместимость).
    #[must_use]
    pub const fn with_legacy_sha1() -> Self {
        Self {
            allow_legacy_sha1: true,
            min_rsa_bits: 2048,
        }
    }

    /// Понижает минимальный размер RSA (только для тестовых векторов).
    #[must_use]
    pub const fn with_min_rsa_bits(mut self, bits: usize) -> Self {
        self.min_rsa_bits = bits;
        self
    }

    fn digest_len(self, digest_type: u8) -> Result<usize, DsError> {
        match digest_type {
            DIGEST_SHA256 => Ok(32),
            DIGEST_SHA384 => Ok(48),
            DIGEST_SHA1 if self.allow_legacy_sha1 => Ok(20),
            DIGEST_SHA1 => Err(DsError::LegacyDigestDisabled { digest_type }),
            other => Err(DsError::UnsupportedDigestType { digest_type: other }),
        }
    }
}

impl Default for DsPolicy {
    fn default() -> Self {
        Self::strict()
    }
}

/// Строит DS из DNSKEY (RFC 4034 §5.1.4).
///
/// Digest считается по `canonical owner name | DNSKEY RDATA`.
///
/// # Errors
///
/// [`DsError::UnsupportedDigestType`], [`DsError::LegacyDigestDisabled`],
/// [`DsError::WeakKey`] для RSA < 2048 бит.
pub fn ds_from_dnskey(
    owner: &Name,
    dnskey: &DnskeyData,
    digest_type: u8,
    policy: DsPolicy,
) -> Result<DsData, DsError> {
    policy.digest_len(digest_type)?;
    let mut material = Vec::with_capacity(owner.wire_len() + dnskey.public_key().len() + 4);
    material.extend_from_slice(owner.as_wire());
    material.extend_from_slice(&dnskey_rdata(dnskey));
    let digest = match digest_type {
        DIGEST_SHA256 => digest(&SHA256, &material).as_ref().to_vec(),
        DIGEST_SHA384 => digest(&SHA384, &material).as_ref().to_vec(),
        DIGEST_SHA1 => digest(&SHA1_FOR_LEGACY_USE_ONLY, &material)
            .as_ref()
            .to_vec(),
        _ => {
            return Err(DsError::UnsupportedDigestType { digest_type });
        }
    };
    let tag = key_tag(dnskey);
    let expected = policy.digest_len(digest_type)?;
    DsData::new(tag, dnskey.algorithm(), digest_type, digest).map_err(|_| DsError::DigestLength {
        digest_type,
        expected,
        actual: expected,
    })
}

/// Сравнивает DNSKEY с DS (algorithm, key tag, digest constant-time).
///
/// `owner` — имя зоны (владелец DNSKEY RRset): оно входит в digest по
/// RFC 4034 §5.1.4, поэтому передаётся явно.
///
/// `Ok(false)` — DNSKEY не соответствует DS. Ошибка — если DS использует
/// неподдерживаемый/запрещённый digest type.
///
/// # Errors
///
/// [`DsError`] для неподдерживаемого digest type или слабого RSA-ключа.
pub fn ds_matches(
    owner: &Name,
    dnskey: &DnskeyData,
    ds: &DsData,
    policy: DsPolicy,
) -> Result<bool, DsError> {
    let expected_len = policy.digest_len(ds.digest_type())?;
    if ds.digest().len() != expected_len {
        return Err(DsError::DigestLength {
            digest_type: ds.digest_type(),
            expected: expected_len,
            actual: ds.digest().len(),
        });
    }
    if ds.algorithm() != dnskey.algorithm() {
        return Ok(false);
    }
    if ds.key_tag() != key_tag(dnskey) {
        return Ok(false);
    }
    check_rsa_strength(dnskey, policy)?;
    let mut material = Vec::with_capacity(owner.wire_len() + dnskey.public_key().len() + 4);
    material.extend_from_slice(owner.as_wire());
    material.extend_from_slice(&dnskey_rdata(dnskey));
    let computed = match ds.digest_type() {
        DIGEST_SHA256 => digest(&SHA256, &material),
        DIGEST_SHA384 => digest(&SHA384, &material),
        DIGEST_SHA1 => digest(&SHA1_FOR_LEGACY_USE_ONLY, &material),
        _ => {
            return Err(DsError::UnsupportedDigestType {
                digest_type: ds.digest_type(),
            });
        }
    };
    Ok(constant_time::verify_slices_are_equal(ds.digest(), computed.as_ref()).is_ok())
}

fn check_rsa_strength(dnskey: &DnskeyData, policy: DsPolicy) -> Result<(), DsError> {
    if matches!(dnskey.algorithm(), 5 | 7 | 8 | 10) {
        let (_, modulus) =
            parse_rsa_dnskey_key(dnskey.public_key()).map_err(|_| DsError::AlgorithmMismatch {
                ds: dnskey.algorithm(),
                dnskey: dnskey.algorithm(),
            })?;
        let bits = modulus.first().map_or(0, |first| {
            modulus.len() * 8 - first.leading_zeros() as usize
        });
        if bits < policy.min_rsa_bits {
            return Err(DsError::WeakKey { bits });
        }
    }
    Ok(())
}
