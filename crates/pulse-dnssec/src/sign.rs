//! Подпись RRset (RFC 4034 §3, RFC 4035 §5.3).
//!
//! Вход подписи — `RRSIG RDATA без signature | canonical RRset`, где TTL
//! RRset заменён на Original TTL. Wildcard-владелец (`*.example.com`)
//! подписывается с `Labels = labels(example.com)`.

use pulse_dns::{Name, Rdata, Rrset, RrsigData, TTL_MAX};

use crate::algorithm::AlgorithmPolicy;
use crate::error::SignError;
use crate::key::{DNSKEY_FLAG_ZONE_KEY, PrivateKey};
use crate::rdata_util::{rrsig_labels, rrsig_signed_prefix};

/// Параметры подписи RRset.
#[derive(Debug, Clone)]
pub struct SignOptions {
    /// Имя зоны (Signer's Name), которой принадлежит ключ.
    pub signer_name: Name,
    /// Текущее время (секунды UNIX).
    pub now: u32,
    /// Срок действия подписи от `now`, в секундах.
    pub validity: u32,
    /// Запас на расхождение часов: inception сдвигается назад,
    /// expiration — вперёд.
    pub inception_skew: u32,
    /// Original TTL; `None` — взять TTL RRset.
    pub original_ttl: Option<u32>,
    /// DNSKEY flags подписывающего ключа (влияют на key tag).
    pub dnskey_flags: u16,
}

impl SignOptions {
    /// Параметры по умолчанию: ZSK-флаги, skew 300 с.
    #[must_use]
    pub fn new(signer_name: Name, now: u32, validity: u32) -> Self {
        Self {
            signer_name,
            now,
            validity,
            inception_skew: 300,
            original_ttl: None,
            dnskey_flags: DNSKEY_FLAG_ZONE_KEY,
        }
    }

    /// Устанавливает размер запаса часов.
    #[must_use]
    pub const fn with_skew(mut self, skew: u32) -> Self {
        self.inception_skew = skew;
        self
    }

    /// Устанавливает Original TTL.
    #[must_use]
    pub const fn with_original_ttl(mut self, ttl: u32) -> Self {
        self.original_ttl = Some(ttl);
        self
    }

    /// Устанавливает DNSKEY flags (например, 257 для KSK).
    #[must_use]
    pub const fn with_dnskey_flags(mut self, flags: u16) -> Self {
        self.dnskey_flags = flags;
        self
    }
}

/// Подписывает RRset и возвращает RRSIG RDATA.
///
/// # Errors
///
/// - [`SignError::AlgorithmNotAllowed`] — ключ не годится для подписи;
/// - [`SignError::SignerNotAncestor`] — signer не является зоной RRset;
/// - [`SignError::InvalidValidity`] — окно не укладывается в RFC 1982;
/// - [`SignError::OriginalTtlBelowRrsetTtl`] / `OriginalTtlOutOfRange`;
/// - [`SignError::Key`] / [`SignError::Crypto`] — ошибки ключа/подписи.
pub fn sign_rrset(
    key: &PrivateKey,
    rrset: &Rrset,
    options: &SignOptions,
) -> Result<RrsigData, SignError> {
    AlgorithmPolicy::strict().check_sign(key.algorithm())?;

    let owner = rrset.owner();
    if !owner.is_subdomain_of(&options.signer_name) {
        return Err(SignError::SignerNotAncestor {
            owner: owner.to_string(),
            signer: options.signer_name.to_string(),
        });
    }

    let labels = rrsig_labels(owner);
    let Ok(labels_u8) = u8::try_from(labels) else {
        return Err(SignError::LabelsOverflow { labels });
    };

    let rrset_ttl = rrset.ttl().as_u32();
    let original_ttl = options.original_ttl.unwrap_or(rrset_ttl);
    if original_ttl > TTL_MAX {
        return Err(SignError::OriginalTtlOutOfRange { ttl: original_ttl });
    }
    if original_ttl < rrset_ttl {
        return Err(SignError::OriginalTtlBelowRrsetTtl {
            original_ttl,
            rrset_ttl,
        });
    }

    let skew = u64::from(options.inception_skew);
    let validity = u64::from(options.validity);
    if validity == 0 || validity.saturating_add(skew.saturating_mul(2)) >= (1_u64 << 31) {
        return Err(SignError::InvalidValidity);
    }

    let inception = options.now.wrapping_sub(options.inception_skew);
    let expiration = options
        .now
        .wrapping_add(options.validity)
        .wrapping_add(options.inception_skew);
    let key_tag = key.key_tag(options.dnskey_flags)?;

    let placeholder = RrsigData::new(
        rrset.rr_type(),
        key.algorithm().as_u8(),
        labels_u8,
        original_ttl,
        expiration,
        inception,
        key_tag,
        options.signer_name.clone(),
        vec![0_u8],
    )
    .map_err(|_| SignError::InvalidValidity)?;

    let rdatas: Vec<Rdata> = rrset.rdatas().iter().cloned().collect();
    let mut message = rrsig_signed_prefix(&placeholder);
    message.extend_from_slice(
        &crate::rdata_util::canonical_rrset_wire(
            owner,
            rrset.rr_type(),
            rrset.class(),
            original_ttl,
            &rdatas,
        )
        .map_err(|error| match error {
            crate::VerifyError::Rrset(rrset_error) => SignError::Rrset(rrset_error),
            _ => SignError::Crypto {
                reason: "canonical encoding failed".to_owned(),
            },
        })?,
    );

    let signature = key.sign_message(&message)?;
    RrsigData::new(
        rrset.rr_type(),
        key.algorithm().as_u8(),
        labels_u8,
        original_ttl,
        expiration,
        inception,
        key_tag,
        options.signer_name.clone(),
        signature,
    )
    .map_err(|_| SignError::InvalidValidity)
}
