//! NSEC3 denial-of-existence (RFC 5155).
//!
//! Поддерживается hash algorithm 1 (SHA-1), salt 0..=255, iterations ≤
//! лимита (по умолчанию 100; RFC 9276 рекомендует 0). Проверяются
//! closest encloser proof, next closer, wildcard, opt-out для DS-NODATA.

use pulse_dns::{Name, Nsec3Data, Nsec3ParamData, Rdata, Record, Rtype, TypeBitmap};

use crate::error::DenialError;
use crate::rdata_util::nsec3_hash;

use super::base32hex;
use super::{DenialLimits, DenialOutcome, DenialResult, check_record_limit};

/// Строит hashed-имя NSEC3 (`<base32hex(hash)>.zone`).
///
/// # Errors
///
/// [`DenialError::Nsec3OwnerHash`], если hash не помещается в DNS-метку или
/// имя не кодируется в wire-формат.
pub fn nsec3_owner_name(zone: &Name, hash: &[u8]) -> Result<Name, DenialError> {
    let label = base32hex::encode(hash);
    let length = u8::try_from(label.len()).map_err(|_| DenialError::Nsec3OwnerHash {
        reason: "hash label is too long",
    })?;
    let mut wire = Vec::with_capacity(1 + label.len() + zone.wire_len());
    wire.push(length);
    wire.extend_from_slice(label.as_bytes());
    wire.extend_from_slice(zone.as_wire());
    Name::from_wire(&wire).map_err(|_| DenialError::Nsec3OwnerHash {
        reason: "cannot build NSEC3 owner name",
    })
}

/// Генерирует случайную соль NSEC3 заданной длины.
///
/// # Errors
///
/// [`DenialError::Nsec3SaltRandom`] при отказе системного RNG.
pub fn random_salt(len: usize) -> Result<Vec<u8>, DenialError> {
    use aws_lc_rs::rand::{SecureRandom, SystemRandom};

    let mut salt = vec![0_u8; len];
    SystemRandom::new()
        .fill(&mut salt)
        .map_err(|_| DenialError::Nsec3SaltRandom)?;
    Ok(salt)
}

/// Параметры NSEC3-цепочки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nsec3Params {
    hash_algorithm: u8,
    iterations: u16,
    salt: Vec<u8>,
}

impl Nsec3Params {
    /// Hash algorithm SHA-1 (единственный поддерживаемый).
    pub const HASH_SHA1: u8 = 1;

    /// Создаёт параметры и проверяет их.
    ///
    /// # Errors
    ///
    /// [`DenialError::Nsec3HashUnsupported`],
    /// [`DenialError::Nsec3IterationsTooHigh`].
    pub fn new(
        hash_algorithm: u8,
        iterations: u16,
        salt: Vec<u8>,
        limits: DenialLimits,
    ) -> Result<Self, DenialError> {
        if hash_algorithm != Self::HASH_SHA1 {
            return Err(DenialError::Nsec3HashUnsupported {
                algorithm: hash_algorithm,
            });
        }
        if iterations > limits.max_nsec3_iterations {
            return Err(DenialError::Nsec3IterationsTooHigh {
                iterations,
                max: limits.max_nsec3_iterations,
            });
        }
        Ok(Self {
            hash_algorithm,
            iterations,
            salt,
        })
    }

    /// Параметры из NSEC3PARAM (flags обязаны быть нулевыми).
    ///
    /// # Errors
    ///
    /// [`DenialError::Nsec3Flags`] для ненулевых флагов и ошибки
    /// [`Nsec3Params::new`].
    pub fn from_nsec3param(
        param: &Nsec3ParamData,
        limits: DenialLimits,
    ) -> Result<Self, DenialError> {
        if param.flags() != 0 {
            return Err(DenialError::Nsec3Flags {
                flags: param.flags(),
            });
        }
        Self::new(
            param.hash_algorithm(),
            param.iterations(),
            param.salt().to_vec(),
            limits,
        )
    }

    /// Hash algorithm.
    #[must_use]
    pub const fn hash_algorithm(&self) -> u8 {
        self.hash_algorithm
    }

    /// Iterations.
    #[must_use]
    pub const fn iterations(&self) -> u16 {
        self.iterations
    }

    /// Salt.
    #[must_use]
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// Хеш имени в hashed-пространстве.
    #[must_use]
    pub fn hash(&self, name: &Name) -> Vec<u8> {
        nsec3_hash(name, &self.salt, self.iterations)
    }
}

/// NSEC3 proof: owner-hash, next hash, флаги, bitmap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nsec3Proof {
    owner: Name,
    params: Nsec3Params,
    flags: u8,
    next_hash: Vec<u8>,
    types: TypeBitmap,
    owner_hash: Vec<u8>,
}

impl Nsec3Proof {
    /// Извлекает NSEC3 из записи.
    ///
    /// # Errors
    ///
    /// [`DenialError::Nsec3OwnerHash`] при некорректной hash-метке,
    /// [`DenialError::Nsec3Flags`] для неизвестных флагов.
    pub fn from_record(record: &Record, limits: DenialLimits) -> Result<Self, DenialError> {
        let Rdata::Nsec3(data) = record.rdata() else {
            return Err(DenialError::Nsec3OwnerHash {
                reason: "record is not NSEC3",
            });
        };
        Self::from_parts(record.owner(), data, limits)
    }

    /// Собирает proof из владельца и RDATA.
    ///
    /// # Errors
    ///
    /// Ошибки валидации hash-метки/флагов/итераций.
    pub fn from_parts(
        owner: &Name,
        data: &Nsec3Data,
        limits: DenialLimits,
    ) -> Result<Self, DenialError> {
        if data.flags() & !1 != 0 {
            return Err(DenialError::Nsec3Flags {
                flags: data.flags(),
            });
        }
        let params = Nsec3Params::new(
            data.hash_algorithm(),
            data.iterations(),
            data.salt().to_vec(),
            limits,
        )?;
        let label = owner.first_label().ok_or(DenialError::Nsec3OwnerHash {
            reason: "owner has no hash label",
        })?;
        let owner_hash =
            base32hex::decode(label).map_err(|reason| DenialError::Nsec3OwnerHash { reason })?;
        if params.hash_algorithm() == Nsec3Params::HASH_SHA1 && owner_hash.len() != 20 {
            return Err(DenialError::Nsec3OwnerHash {
                reason: "SHA-1 hash must be 20 bytes",
            });
        }
        Ok(Self {
            owner: owner.clone(),
            params,
            flags: data.flags(),
            next_hash: data.next_hashed_owner().to_vec(),
            types: data.type_bitmap().clone(),
            owner_hash,
        })
    }

    /// Параметры цепочки.
    #[must_use]
    pub const fn params(&self) -> &Nsec3Params {
        &self.params
    }

    /// Владелец NSEC3.
    #[must_use]
    pub const fn owner(&self) -> &Name {
        &self.owner
    }

    /// Type bitmap оригинального владельца.
    #[must_use]
    pub const fn types(&self) -> &TypeBitmap {
        &self.types
    }

    /// Opt-Out установлен.
    #[must_use]
    pub const fn opt_out(&self) -> bool {
        self.flags & 1 != 0
    }

    fn matches_hash(&self, hash: &[u8]) -> bool {
        self.owner_hash == hash
    }

    fn covers_hash(&self, hash: &[u8]) -> bool {
        if hash == self.owner_hash.as_slice() {
            return false;
        }
        match self.owner_hash.as_slice().cmp(self.next_hash.as_slice()) {
            std::cmp::Ordering::Less => {
                hash > self.owner_hash.as_slice() && hash < self.next_hash.as_slice()
            }
            _ => hash > self.owner_hash.as_slice() || hash < self.next_hash.as_slice(),
        }
    }

    fn check_zone(&self, zone: &Name) -> Result<(), DenialError> {
        let expected_labels = zone.label_count().saturating_add(1);
        if !self.owner.is_subdomain_of(zone) || self.owner.label_count() != expected_labels {
            return Err(DenialError::Nsec3OwnerOutsideZone {
                name: self.owner.to_string(),
                zone: zone.to_string(),
            });
        }
        Ok(())
    }

    fn check_encloser_bits(&self) -> Result<(), DenialError> {
        if self.types.contains(Rtype::DNAME) {
            return Err(DenialError::DnamePresent);
        }
        if self.types.contains(Rtype::NS) && !self.types.contains(Rtype::SOA) {
            return Err(DenialError::DelegationWithoutSoa);
        }
        Ok(())
    }
}

fn check_consistency(
    proofs: &[Nsec3Proof],
    limits: DenialLimits,
) -> Result<Nsec3Params, DenialError> {
    check_record_limit(proofs.len(), limits)?;
    let first = proofs
        .first()
        .ok_or(DenialError::Nsec3InconsistentParams)?
        .params
        .clone();
    for proof in proofs {
        if proof.params != first {
            return Err(DenialError::Nsec3InconsistentParams);
        }
    }
    Ok(first)
}

fn find_match<'a>(proofs: &'a [Nsec3Proof], hash: &[u8]) -> Option<&'a Nsec3Proof> {
    proofs.iter().find(|proof| proof.matches_hash(hash))
}

fn find_cover<'a>(proofs: &'a [Nsec3Proof], hash: &[u8]) -> Option<&'a Nsec3Proof> {
    proofs.iter().find(|proof| proof.covers_hash(hash))
}

fn ancestors(qname: &Name, zone: &Name) -> Result<Vec<Name>, DenialError> {
    if !qname.is_subdomain_of(zone) {
        return Err(DenialError::ClosestEncloserNotFound {
            name: qname.to_string(),
        });
    }
    let mut result = vec![qname.clone()];
    let mut current = qname.clone();
    while current != *zone {
        let Some(parent) = current.parent() else {
            break;
        };
        result.push(parent.clone());
        current = parent;
    }
    Ok(result)
}

struct EncloserProof<'a> {
    encloser: Name,
    covering: &'a Nsec3Proof,
}

fn closest_encloser_proof<'a>(
    qname: &Name,
    zone: &Name,
    proofs: &'a [Nsec3Proof],
    params: &Nsec3Params,
) -> Result<EncloserProof<'a>, DenialError> {
    let names = ancestors(qname, zone)?;
    for (index, candidate) in names.iter().enumerate() {
        let hash = params.hash(candidate);
        let Some(matching) = find_match(proofs, &hash) else {
            continue;
        };
        if index == 0 {
            return Err(DenialError::NameExists {
                name: candidate.to_string(),
            });
        }
        matching.check_encloser_bits()?;
        let next_closer =
            names
                .get(index - 1)
                .ok_or_else(|| DenialError::ClosestEncloserNotFound {
                    name: qname.to_string(),
                })?;
        let next_hash = params.hash(next_closer);
        let covering =
            find_cover(proofs, &next_hash).ok_or_else(|| DenialError::NextCloserNotCovered {
                name: next_closer.to_string(),
            })?;
        return Ok(EncloserProof {
            encloser: candidate.clone(),
            covering,
        });
    }
    Err(DenialError::ClosestEncloserNotFound {
        name: qname.to_string(),
    })
}

fn wildcard_name(parent: &Name) -> Result<Name, DenialError> {
    let mut wire = Vec::with_capacity(parent.wire_len() + 2);
    wire.push(1);
    wire.push(b'*');
    wire.extend_from_slice(parent.as_wire());
    Name::from_wire(&wire).map_err(|_| DenialError::ClosestEncloserNotFound {
        name: parent.to_string(),
    })
}

/// NSEC3 NXDOMAIN: closest encloser proof + покрытие wildcard.
///
/// # Errors
///
/// [`DenialError`] при неполном/противоречивом proof.
pub fn nsec3_nxdomain(
    qname: &Name,
    zone: &Name,
    proofs: &[Nsec3Proof],
    limits: DenialLimits,
) -> Result<DenialResult, DenialError> {
    let params = check_consistency(proofs, limits)?;
    for proof in proofs {
        proof.check_zone(zone)?;
    }
    if find_match(proofs, &params.hash(qname)).is_some() {
        return Err(DenialError::NameExists {
            name: qname.to_string(),
        });
    }
    let encloser = closest_encloser_proof(qname, zone, proofs, &params)?;
    let wildcard = wildcard_name(&encloser.encloser)?;
    let wildcard_hash = params.hash(&wildcard);
    if find_match(proofs, &wildcard_hash).is_some() {
        return Err(DenialError::WildcardExists {
            name: wildcard.to_string(),
        });
    }
    if find_cover(proofs, &wildcard_hash).is_none() {
        return Err(DenialError::WildcardNotCovered {
            name: wildcard.to_string(),
        });
    }
    Ok(DenialResult::new(
        DenialOutcome::NxDomain,
        encloser.covering.opt_out(),
    ))
}

/// NSEC3 NODATA (QTYPE != DS): NSEC3 совпадает с QNAME, тип отсутствует.
///
/// # Errors
///
/// [`DenialError::Nsec3NoMatch`], [`DenialError::TypePresent`],
/// [`DenialError::CnamePresent`].
pub fn nsec3_nodata(
    qname: &Name,
    qtype: Rtype,
    zone: &Name,
    proofs: &[Nsec3Proof],
    limits: DenialLimits,
) -> Result<DenialResult, DenialError> {
    let params = check_consistency(proofs, limits)?;
    for proof in proofs {
        proof.check_zone(zone)?;
    }
    let matching =
        find_match(proofs, &params.hash(qname)).ok_or_else(|| DenialError::Nsec3NoMatch {
            name: qname.to_string(),
        })?;
    check_nodata_bitmap(matching, qtype)?;
    Ok(DenialResult::new(DenialOutcome::NoData, false))
}

/// NSEC3 CNAME/прочие типы отсутствуют в bitmap.
fn check_nodata_bitmap(proof: &Nsec3Proof, qtype: Rtype) -> Result<(), DenialError> {
    if proof.types.contains(qtype) {
        return Err(DenialError::TypePresent { rr_type: qtype });
    }
    if proof.types.contains(Rtype::CNAME) {
        return Err(DenialError::CnamePresent);
    }
    Ok(())
}

/// NSEC3 DS-NODATA / referral в неподписанную зону (opt-out).
///
/// # Errors
///
/// [`DenialError::OptOutRequired`], [`DenialError::DsPresent`],
/// [`DenialError::CnamePresent`].
pub fn nsec3_ds_nodata(
    qname: &Name,
    zone: &Name,
    proofs: &[Nsec3Proof],
    limits: DenialLimits,
) -> Result<DenialResult, DenialError> {
    let params = check_consistency(proofs, limits)?;
    for proof in proofs {
        proof.check_zone(zone)?;
    }
    if let Some(matching) = find_match(proofs, &params.hash(qname)) {
        if matching.types.contains(Rtype::DS) {
            return Err(DenialError::DsPresent);
        }
        if matching.types.contains(Rtype::CNAME) {
            return Err(DenialError::CnamePresent);
        }
        return Ok(DenialResult::new(DenialOutcome::NoData, false));
    }
    let encloser = closest_encloser_proof(qname, zone, proofs, &params)?;
    if !encloser.covering.opt_out() {
        return Err(DenialError::OptOutRequired);
    }
    Ok(DenialResult::new(DenialOutcome::NoData, true))
}

/// NSEC3 wildcard NODATA: CE proof + совпадение wildcard, тип отсутствует.
///
/// # Errors
///
/// [`DenialError::Nsec3NoMatch`], [`DenialError::TypePresent`].
pub fn nsec3_wildcard_nodata(
    qname: &Name,
    qtype: Rtype,
    zone: &Name,
    proofs: &[Nsec3Proof],
    limits: DenialLimits,
) -> Result<DenialResult, DenialError> {
    let params = check_consistency(proofs, limits)?;
    for proof in proofs {
        proof.check_zone(zone)?;
    }
    let encloser = closest_encloser_proof(qname, zone, proofs, &params)?;
    let wildcard = wildcard_name(&encloser.encloser)?;
    let matching =
        find_match(proofs, &params.hash(&wildcard)).ok_or_else(|| DenialError::Nsec3NoMatch {
            name: wildcard.to_string(),
        })?;
    check_nodata_bitmap(matching, qtype)?;
    Ok(DenialResult::new(DenialOutcome::WildcardNoData, false))
}

/// NSEC3 wildcard answer: next closer к известному CE покрыт.
///
/// # Errors
///
/// [`DenialError::NextCloserNotCovered`].
pub fn nsec3_wildcard_answer(
    qname: &Name,
    closest_encloser: &Name,
    zone: &Name,
    proofs: &[Nsec3Proof],
    limits: DenialLimits,
) -> Result<DenialResult, DenialError> {
    let params = check_consistency(proofs, limits)?;
    for proof in proofs {
        proof.check_zone(zone)?;
    }
    if !qname.is_subdomain_of(closest_encloser) || qname == closest_encloser {
        return Err(DenialError::NextCloserNotCovered {
            name: qname.to_string(),
        });
    }
    let mut current = qname.clone();
    let next_closer = loop {
        let Some(parent) = current.parent() else {
            return Err(DenialError::NextCloserNotCovered {
                name: qname.to_string(),
            });
        };
        if parent == *closest_encloser {
            break current;
        }
        current = parent;
    };
    let hash = params.hash(&next_closer);
    let Some(covering) = find_cover(proofs, &hash) else {
        return Err(DenialError::NextCloserNotCovered {
            name: next_closer.to_string(),
        });
    };
    // Opt-Out в покрытии next closer означает, что под ним может быть
    // insecure-делегирование; ответ нельзя считать полностью secure.
    Ok(DenialResult::new(
        DenialOutcome::WildcardExpansion,
        covering.opt_out(),
    ))
}
