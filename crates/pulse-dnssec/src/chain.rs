//! Цепочка доверия DNSSEC: DS → DNSKEY (KSK) → DNSKEY (ZSK) → RRSIG.
//!
//! Валидатор получает DS-набор ребёнка от родителя (или trust anchor для
//! корня), DNSKEY RRset зоны и его подписи. Шаги:
//!
//! 1. DS должен совпасть с одним из DNSKEY (KSK) — иначе `BOGUS`.
//! 2. DNSKEY RRset должен быть подписан этим KSK.
//! 3. Любой RRSIG данных проверяется любым ключом из валидированного
//!    DNSKEY RRset (обычно ZSK).

use pulse_dns::{DnskeyData, DsData, Name, Rdata, Rrset, RrsigData, Rtype};

use crate::ds::{DsPolicy, ds_matches};
use crate::error::ChainError;
use crate::verify::{VerifyOptions, verify_rrset_with_dnskeys, verify_rrsig};

/// DNSKEY-набор, прошедший проверку DS и self-signature.
#[derive(Debug, Clone)]
pub struct ValidatedDnskeySet {
    zone: Name,
    keys: Vec<DnskeyData>,
    ksk_tags: Vec<u16>,
}

impl ValidatedDnskeySet {
    /// Валидированная зона.
    #[must_use]
    pub const fn zone(&self) -> &Name {
        &self.zone
    }

    /// Все ключи зоны (KSK и ZSK).
    #[must_use]
    pub fn keys(&self) -> &[DnskeyData] {
        &self.keys
    }

    /// Key tags ключей, прошедших DS.
    #[must_use]
    pub fn ksk_tags(&self) -> &[u16] {
        &self.ksk_tags
    }

    /// Проверяет RRset подписями из этого набора ключей.
    ///
    /// # Errors
    ///
    /// [`ChainError::NoValidSignature`], если ни одна подпись не прошла.
    pub fn verify_rrset(
        &self,
        rrset: &Rrset,
        signatures: &[RrsigData],
        options: &VerifyOptions,
    ) -> Result<(), ChainError> {
        for signature in signatures {
            if verify_rrset_with_dnskeys(rrset, signature, &self.keys, options).is_ok() {
                return Ok(());
            }
        }
        Err(ChainError::NoValidSignature)
    }
}

/// Извлекает DNSKEY-значения из RRset.
fn dnskey_values(rrset: &Rrset) -> Result<Vec<DnskeyData>, ChainError> {
    if rrset.rr_type() != Rtype::DNSKEY {
        return Err(ChainError::NotDnskeyRrset {
            rr_type: rrset.rr_type(),
        });
    }
    let mut keys = Vec::with_capacity(rrset.len());
    for rdata in rrset.rdatas() {
        if let Rdata::Dnskey(key) = rdata {
            keys.push(key.clone());
        }
    }
    if keys.is_empty() {
        return Err(ChainError::EmptyDnskeyRrset);
    }
    Ok(keys)
}

/// Валидирует DNSKEY RRset по DS-набору родителя.
///
/// # Errors
///
/// [`ChainError::ZoneMismatch`] для чужого RRset,
/// [`ChainError::NoMatchingDs`] (BOGUS), [`ChainError::DnskeyNotSelfSigned`]
/// (BOGUS), ошибки DS/подписи.
pub fn validate_dnskey_rrset(
    zone: &Name,
    dnskeys: &Rrset,
    signatures: &[RrsigData],
    ds_set: &[DsData],
    verify_options: &VerifyOptions,
    ds_policy: DsPolicy,
) -> Result<ValidatedDnskeySet, ChainError> {
    if dnskeys.owner() != zone {
        return Err(ChainError::ZoneMismatch {
            expected: zone.to_string(),
            actual: dnskeys.owner().to_string(),
        });
    }
    let keys = dnskey_values(dnskeys)?;

    let mut matched_ksks: Vec<DnskeyData> = Vec::new();
    for ds in ds_set {
        for key in &keys {
            if ds_matches(zone, key, ds, ds_policy)? && !matched_ksks.contains(key) {
                matched_ksks.push(key.clone());
            }
        }
    }
    if matched_ksks.is_empty() {
        return Err(ChainError::NoMatchingDs);
    }

    let mut dnskeys_signed = false;
    for signature in signatures {
        if signature.type_covered() != Rtype::DNSKEY {
            continue;
        }
        for ksk in &matched_ksks {
            if verify_rrsig(dnskeys, signature, ksk, verify_options).is_ok() {
                dnskeys_signed = true;
                break;
            }
        }
        if dnskeys_signed {
            break;
        }
    }
    if !dnskeys_signed {
        return Err(ChainError::DnskeyNotSelfSigned);
    }

    let ksk_tags = matched_ksks
        .iter()
        .map(crate::rdata_util::key_tag)
        .collect();
    Ok(ValidatedDnskeySet {
        zone: zone.clone(),
        keys,
        ksk_tags,
    })
}

/// Полная проверка RRset в цепочке: DS → DNSKEY → RRSIG.
///
/// # Errors
///
/// Ошибки [`validate_dnskey_rrset`] и
/// [`ChainError::NoValidSignature`] (BOGUS).
#[allow(clippy::too_many_arguments)]
pub fn validate_rrset_in_chain(
    zone: &Name,
    dnskeys: &Rrset,
    dnskey_signatures: &[RrsigData],
    ds_set: &[DsData],
    rrset: &Rrset,
    signatures: &[RrsigData],
    verify_options: &VerifyOptions,
    ds_policy: DsPolicy,
) -> Result<ValidatedDnskeySet, ChainError> {
    let validated = validate_dnskey_rrset(
        zone,
        dnskeys,
        dnskey_signatures,
        ds_set,
        verify_options,
        ds_policy,
    )?;
    validated.verify_rrset(rrset, signatures, verify_options)?;
    Ok(validated)
}

/// Проверяет, что RRset подписан ключом, входящим в уже валидированный набор.
///
/// # Errors
///
/// Ошибки [`crate::VerifyError`] последней попытки или
/// [`ChainError::NoValidSignature`].
pub fn verify_with_validated_keys(
    validated: &ValidatedDnskeySet,
    rrset: &Rrset,
    signatures: &[RrsigData],
    options: &VerifyOptions,
) -> Result<(), ChainError> {
    validated.verify_rrset(rrset, signatures, options)
}
