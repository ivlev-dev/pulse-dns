//! NSEC denial-of-existence (RFC 4034 §4, RFC 4035 §5.4).

use pulse_dns::{Name, Rtype, TypeBitmap};

use crate::error::DenialError;
use crate::rdata_util::NsecEntry;

use super::{DenialLimits, DenialOutcome, DenialResult, check_record_limit};

/// NSEC proof: владелец, next domain и type bitmap.
pub type NsecProof = NsecEntry;

impl NsecProof {
    /// Проверяет, что NSEC относится к зоне.
    fn check_zone(&self, zone: &Name) -> Result<(), DenialError> {
        if !self.owner.is_subdomain_of(zone) {
            return Err(DenialError::NsecOwnerOutsideZone {
                name: self.owner.to_string(),
                zone: zone.to_string(),
            });
        }
        if !self.next.is_subdomain_of(zone) {
            return Err(DenialError::NsecNextOutsideZone {
                name: self.next.to_string(),
                zone: zone.to_string(),
            });
        }
        Ok(())
    }

    fn has_type(&self, rr_type: Rtype) -> bool {
        self.types.contains(rr_type)
    }
}

/// NSEC-доказательство NXDOMAIN: покрытие QNAME + покрытие wildcard.
///
/// # Errors
///
/// [`DenialError`] при отсутствии/несогласованности proof-записей.
pub fn nsec_nxdomain(
    qname: &Name,
    zone: &Name,
    proofs: &[NsecProof],
    limits: DenialLimits,
) -> Result<DenialResult, DenialError> {
    check_record_limit(proofs.len(), limits)?;
    for proof in proofs {
        proof.check_zone(zone)?;
    }
    if !qname.is_subdomain_of(zone) {
        return Err(DenialError::NsecDoesNotCover {
            name: qname.to_string(),
        });
    }
    if proofs.iter().any(|proof| proof.matches(qname)) {
        return Err(DenialError::NameExists {
            name: qname.to_string(),
        });
    }
    let covering = proofs
        .iter()
        .find(|proof| proof.covers(qname))
        .ok_or_else(|| DenialError::NsecDoesNotCover {
            name: qname.to_string(),
        })?;

    let closest = closest_encloser_from_nsec(qname, covering, zone);
    let wildcard = wildcard_name(&closest)?;
    if proofs.iter().any(|proof| proof.matches(&wildcard)) {
        return Err(DenialError::WildcardExists {
            name: wildcard.to_string(),
        });
    }
    if !proofs.iter().any(|proof| proof.covers(&wildcard)) {
        return Err(DenialError::WildcardNotCovered {
            name: wildcard.to_string(),
        });
    }
    Ok(DenialResult::new(DenialOutcome::NxDomain, false))
}

/// NSEC-доказательство NODATA: NSEC совпадает с QNAME и не содержит QTYPE.
///
/// # Errors
///
/// [`DenialError::NsecDoesNotMatch`], [`DenialError::TypePresent`],
/// [`DenialError::CnamePresent`], [`DenialError::DnamePresent`].
pub fn nsec_nodata(
    qname: &Name,
    qtype: Rtype,
    zone: &Name,
    proofs: &[NsecProof],
    limits: DenialLimits,
) -> Result<DenialResult, DenialError> {
    check_record_limit(proofs.len(), limits)?;
    for proof in proofs {
        proof.check_zone(zone)?;
    }
    let matching = proofs
        .iter()
        .find(|proof| proof.matches(qname))
        .ok_or_else(|| DenialError::NsecDoesNotMatch {
            name: qname.to_string(),
        })?;
    check_nodata_bitmap(matching, qtype)?;
    Ok(DenialResult::new(DenialOutcome::NoData, false))
}

/// NSEC-доказательство wildcard NODATA.
///
/// Wildcard-владелец существует (NSEC совпадает), QTYPE/CNAME в нём нет,
/// а QNAME покрыт отдельным NSEC (не существует).
///
/// # Errors
///
/// [`DenialError`] при отсутствии wildcard-NSEC или покрытия QNAME.
pub fn nsec_wildcard_nodata(
    qname: &Name,
    qtype: Rtype,
    zone: &Name,
    proofs: &[NsecProof],
    limits: DenialLimits,
) -> Result<DenialResult, DenialError> {
    check_record_limit(proofs.len(), limits)?;
    for proof in proofs {
        proof.check_zone(zone)?;
    }
    let mut wildcard_match = None;
    for ancestor in ancestors(qname, zone)? {
        let Some(name) = wildcard_name_opt(&ancestor) else {
            continue;
        };
        if let Some(proof) = proofs.iter().find(|proof| proof.matches(&name)) {
            wildcard_match = Some((name, proof));
            break;
        }
    }
    let Some((_wildcard, matching)) = wildcard_match else {
        return Err(DenialError::NsecDoesNotMatch {
            name: format!("*.{zone}"),
        });
    };
    check_nodata_bitmap(matching, qtype)?;
    if !proofs.iter().any(|proof| proof.covers(qname)) {
        return Err(DenialError::NsecDoesNotCover {
            name: qname.to_string(),
        });
    }
    Ok(DenialResult::new(DenialOutcome::WildcardNoData, false))
}

/// NSEC-доказательство wildcard answer: next closer покрыт NSEC.
///
/// `closest_encloser` — родитель сгенерировавшего wildcard (из RRSIG).
///
/// # Errors
///
/// [`DenialError::NextCloserNotCovered`].
pub fn nsec_wildcard_answer(
    qname: &Name,
    closest_encloser: &Name,
    zone: &Name,
    proofs: &[NsecProof],
    limits: DenialLimits,
) -> Result<DenialResult, DenialError> {
    check_record_limit(proofs.len(), limits)?;
    for proof in proofs {
        proof.check_zone(zone)?;
    }
    let next_closer = next_closer_name(qname, closest_encloser)?;
    if !proofs.iter().any(|proof| proof.covers(&next_closer)) {
        return Err(DenialError::NextCloserNotCovered {
            name: next_closer.to_string(),
        });
    }
    Ok(DenialResult::new(DenialOutcome::WildcardExpansion, false))
}

fn check_nodata_bitmap(proof: &NsecProof, qtype: Rtype) -> Result<(), DenialError> {
    if proof.has_type(qtype) {
        return Err(DenialError::TypePresent { rr_type: qtype });
    }
    if proof.has_type(Rtype::CNAME) {
        return Err(DenialError::CnamePresent);
    }
    if proof.has_type(Rtype::DNAME) {
        return Err(DenialError::DnamePresent);
    }
    Ok(())
}

/// Closest encloser из покрывающего NSEC.
///
/// NSEC owner — предшественник QNAME в каноническом порядке, поэтому
/// общий суффикс с owner не может быть глубже реального closest encloser
/// (иначе между ними существовал бы ещё один предок QNAME). Использовать
/// `next` нельзя: следующий владелец может делить с QNAME более длинный
/// суффикс, не являясь его предком.
fn closest_encloser_from_nsec(qname: &Name, covering: &NsecProof, zone: &Name) -> Name {
    let candidate = common_suffix(qname, &covering.owner);
    if candidate.is_subdomain_of(zone) {
        candidate
    } else {
        zone.clone()
    }
}

/// Список предков QNAME до зоны включительно, от самого QNAME.
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

fn wildcard_name(parent: &Name) -> Result<Name, DenialError> {
    wildcard_name_opt(parent).ok_or_else(|| DenialError::ClosestEncloserNotFound {
        name: parent.to_string(),
    })
}

fn wildcard_name_opt(parent: &Name) -> Option<Name> {
    let mut wire = Vec::with_capacity(parent.wire_len() + 2);
    wire.push(1);
    wire.push(b'*');
    wire.extend_from_slice(parent.as_wire());
    Name::from_wire(&wire).ok()
}

fn next_closer_name(qname: &Name, closest_encloser: &Name) -> Result<Name, DenialError> {
    if !qname.is_subdomain_of(closest_encloser) || qname == closest_encloser {
        return Err(DenialError::ClosestEncloserNotFound {
            name: qname.to_string(),
        });
    }
    let mut current = qname.clone();
    while let Some(parent) = current.parent() {
        if parent == *closest_encloser {
            return Ok(current);
        }
        current = parent;
    }
    Err(DenialError::ClosestEncloserNotFound {
        name: qname.to_string(),
    })
}

fn common_suffix(left: &Name, right: &Name) -> Name {
    let mut left_labels: Vec<&[u8]> = left.labels().collect();
    let mut right_labels: Vec<&[u8]> = right.labels().collect();
    let mut common: Vec<&[u8]> = Vec::new();
    while let (Some(left_label), Some(right_label)) = (left_labels.pop(), right_labels.pop()) {
        if left_label != right_label {
            break;
        }
        common.push(left_label);
    }
    let mut wire = Vec::new();
    for label in common.iter().rev() {
        let Ok(length) = u8::try_from(label.len()) else {
            return Name::root();
        };
        wire.push(length);
        wire.extend_from_slice(label);
    }
    wire.push(0);
    Name::from_wire(&wire).unwrap_or_else(|_| Name::root())
}

/// Проверка, что bitmap содержит тип (для тестов/вызывающего кода).
#[must_use]
pub fn bitmap_contains(types: &TypeBitmap, rr_type: Rtype) -> bool {
    types.contains(rr_type)
}
