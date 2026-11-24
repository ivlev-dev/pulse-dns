//! Валидация RRSIG (RFC 4035 §5.3).
//!
//! Проверяются: класс/тип RRset, signer name, окно валидности (RFC 1982),
//! Original TTL, поле Labels (wildcard), алгоритм по политике, zone key
//! flag, key tag и сама подпись. Constant-time сравнение и проверку
//! подписи выполняет `aws-lc-rs`.

use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED, ECDSA_P384_SHA384_FIXED, ED25519,
    RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY, RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA512, UnparsedPublicKey,
};
use pulse_dns::{DnskeyData, Rclass, Rdata, Rrset, RrsigData, Serial};

use crate::algorithm::AlgorithmPolicy;
use crate::der;
use crate::error::VerifyError;
use crate::key::DNSKEY_FLAG_ZONE_KEY;
use crate::rdata_util::{key_tag, parse_rsa_dnskey_key, signed_data, signing_owner_name};

/// Параметры валидации.
#[derive(Debug, Clone, Copy)]
pub struct VerifyOptions {
    /// Текущее время (секунды UNIX).
    pub now: u32,
    /// Политика алгоритмов.
    pub policy: AlgorithmPolicy,
}

impl VerifyOptions {
    /// Параметры с политикой по умолчанию (SHA-1 выключен).
    #[must_use]
    pub const fn new(now: u32) -> Self {
        Self {
            now,
            policy: AlgorithmPolicy::strict(),
        }
    }

    /// Заменяет политику.
    #[must_use]
    pub const fn with_policy(mut self, policy: AlgorithmPolicy) -> Self {
        self.policy = policy;
        self
    }
}

/// Проверяет RRSIG для RRset одним DNSKEY.
///
/// # Errors
///
/// [`VerifyError`] с конкретной причиной: несовпадение типа/класса/ключа,
/// нарушение окна валидности, недопустимый алгоритм, ошибка подписи.
pub fn verify_rrsig(
    rrset: &Rrset,
    rrsig: &RrsigData,
    dnskey: &DnskeyData,
    options: &VerifyOptions,
) -> Result<(), VerifyError> {
    let algorithm = crate::algorithm::Algorithm::from_u8(rrsig.algorithm());
    options.policy.check_verify(algorithm)?;

    if rrset.class() != Rclass::IN {
        return Err(VerifyError::ClassNotIn {
            class: rrset.class(),
        });
    }
    if rrsig.type_covered() != rrset.rr_type() {
        return Err(VerifyError::TypeMismatch {
            covered: rrsig.type_covered(),
            rrset: rrset.rr_type(),
        });
    }
    if !rrset.owner().is_subdomain_of(rrsig.signer_name()) {
        return Err(VerifyError::SignerNotAncestor {
            owner: rrset.owner().to_string(),
            signer: rrsig.signer_name().to_string(),
        });
    }
    if dnskey.protocol() != 3 {
        return Err(VerifyError::DnskeyProtocol {
            protocol: dnskey.protocol(),
        });
    }
    if dnskey.flags() & DNSKEY_FLAG_ZONE_KEY == 0 {
        return Err(VerifyError::DnskeyNotZoneKey {
            flags: dnskey.flags(),
        });
    }
    if dnskey.algorithm() != rrsig.algorithm() {
        return Err(VerifyError::AlgorithmMismatch {
            rrsig: rrsig.algorithm(),
            dnskey: dnskey.algorithm(),
        });
    }
    let dnskey_tag = key_tag(dnskey);
    if dnskey_tag != rrsig.key_tag() {
        return Err(VerifyError::KeyTagMismatch {
            rrsig: rrsig.key_tag(),
            dnskey: dnskey_tag,
        });
    }

    check_validity_window(rrsig, options.now)?;

    let rrset_ttl = rrset.ttl().as_u32();
    if rrset_ttl > rrsig.original_ttl() {
        return Err(VerifyError::OriginalTtlBelowRrsetTtl {
            rrset_ttl,
            original_ttl: rrsig.original_ttl(),
        });
    }

    let owner_labels = rrset.owner().label_count();
    if usize::from(rrsig.labels()) > owner_labels {
        return Err(VerifyError::LabelsExceedOwner {
            labels: rrsig.labels(),
            owner_labels,
        });
    }
    if rrset.owner().is_wildcard_owner()
        && usize::from(rrsig.labels()).saturating_add(1) != owner_labels
    {
        return Err(VerifyError::WildcardLabelsMismatch {
            labels: rrsig.labels(),
            owner_labels,
        });
    }
    let signing_owner = signing_owner_name(rrset.owner(), rrsig.labels())?;
    if !signing_owner.is_subdomain_of(rrsig.signer_name()) {
        return Err(VerifyError::SignerNotAncestor {
            owner: signing_owner.to_string(),
            signer: rrsig.signer_name().to_string(),
        });
    }

    let rdatas: Vec<Rdata> = rrset.rdatas().iter().cloned().collect();
    let message = signed_data(
        &signing_owner,
        rrset.rr_type(),
        rrset.class(),
        &rdatas,
        rrsig,
    )?;

    verify_raw(algorithm, dnskey, &message, rrsig.signature())
}

/// Проверяет подпись одним из DNSKEY-наборов.
///
/// Кандидаты отбираются по algorithm + key tag. Успех — если подпись
/// прошла хотя бы одним ключом; иначе возвращается `Crypto` (если
/// кандидаты были) или `NoMatchingDnskey`.
///
/// # Errors
///
/// [`VerifyError::NoMatchingDnskey`] и ошибки [`verify_rrsig`].
pub fn verify_rrset_with_dnskeys(
    rrset: &Rrset,
    rrsig: &RrsigData,
    dnskeys: &[DnskeyData],
    options: &VerifyOptions,
) -> Result<(), VerifyError> {
    let mut candidate_seen = false;
    for dnskey in dnskeys {
        if dnskey.algorithm() != rrsig.algorithm() || key_tag(dnskey) != rrsig.key_tag() {
            continue;
        }
        candidate_seen = true;
        if verify_rrsig(rrset, rrsig, dnskey, options).is_ok() {
            return Ok(());
        }
    }
    if candidate_seen {
        Err(VerifyError::Crypto)
    } else {
        Err(VerifyError::NoMatchingDnskey)
    }
}

fn check_validity_window(rrsig: &RrsigData, now: u32) -> Result<(), VerifyError> {
    let now_serial = Serial::new(now);
    let inception = Serial::new(rrsig.signature_inception());
    let expiration = Serial::new(rrsig.signature_expiration());

    match now_serial.cmp_rfc1982(inception) {
        Some(std::cmp::Ordering::Less) => {
            return Err(VerifyError::NotYetValid {
                now,
                inception: rrsig.signature_inception(),
            });
        }
        None => return Err(VerifyError::AmbiguousTimeWindow),
        _ => {}
    }
    match now_serial.cmp_rfc1982(expiration) {
        Some(std::cmp::Ordering::Greater) => {
            return Err(VerifyError::Expired {
                now,
                expiration: rrsig.signature_expiration(),
            });
        }
        None => return Err(VerifyError::AmbiguousTimeWindow),
        _ => {}
    }
    Ok(())
}

fn verify_raw(
    algorithm: crate::algorithm::Algorithm,
    dnskey: &DnskeyData,
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerifyError> {
    match algorithm.as_u8() {
        8 | 10 | 5 | 7 => {
            let (exponent, modulus) = parse_rsa_dnskey_key(dnskey.public_key())?;
            let bits = rsa_bits(modulus);
            if bits < 2048 {
                return Err(VerifyError::WeakRsaKey { bits });
            }
            let der_key = der::encode_rsa_public_key(modulus, exponent);
            let verification_algorithm = match algorithm.as_u8() {
                8 => &RSA_PKCS1_2048_8192_SHA256,
                10 => &RSA_PKCS1_2048_8192_SHA512,
                _ => &RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
            };
            UnparsedPublicKey::new(verification_algorithm, der_key)
                .verify(message, signature)
                .map_err(|_| VerifyError::Crypto)
        }
        13 => {
            if signature.len() != 64 {
                return Err(VerifyError::BadSignatureLength {
                    expected: 64,
                    actual: signature.len(),
                });
            }
            if dnskey.public_key().len() != 64 {
                return Err(VerifyError::BadPublicKey {
                    reason: "P-256 public key must be 64 bytes (X||Y)",
                });
            }
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            point.extend_from_slice(dnskey.public_key());
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point)
                .verify(message, signature)
                .map_err(|_| VerifyError::Crypto)
        }
        14 => {
            if signature.len() != 96 {
                return Err(VerifyError::BadSignatureLength {
                    expected: 96,
                    actual: signature.len(),
                });
            }
            if dnskey.public_key().len() != 96 {
                return Err(VerifyError::BadPublicKey {
                    reason: "P-384 public key must be 96 bytes (X||Y)",
                });
            }
            let mut point = Vec::with_capacity(97);
            point.push(0x04);
            point.extend_from_slice(dnskey.public_key());
            UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, point)
                .verify(message, signature)
                .map_err(|_| VerifyError::Crypto)
        }
        15 => {
            if signature.len() != 64 {
                return Err(VerifyError::BadSignatureLength {
                    expected: 64,
                    actual: signature.len(),
                });
            }
            if dnskey.public_key().len() != 32 {
                return Err(VerifyError::BadPublicKey {
                    reason: "Ed25519 public key must be 32 bytes",
                });
            }
            UnparsedPublicKey::new(&ED25519, dnskey.public_key())
                .verify(message, signature)
                .map_err(|_| VerifyError::Crypto)
        }
        _ => Err(VerifyError::AlgorithmNotAllowed { algorithm }),
    }
}

fn rsa_bits(modulus: &[u8]) -> usize {
    let Some(&first) = modulus.first() else {
        return 0;
    };
    let leading = first.leading_zeros() as usize;
    modulus.len().saturating_mul(8).saturating_sub(leading)
}
