//! Движок DNS UPDATE (RFC 2136 §3.2, §3.4) поверх транзакционного порта.
//!
//! Движок не знает про wire-формат и хранилище: он получает разобранный
//! [`UpdateRequest`] и реализацию [`UpdateTarget`]. Контракт порта:
//!
//! 1. **Prerequisites читаются до первой записи.** Все условия проверяются на
//!    одном снапшоте; при нарушении движок возвращает ошибку и не пишет.
//! 2. **Записи видны последующим операциям.** Add/delete компонуются в порядке
//!    секции Update (read-your-writes).
//! 3. **Ошибка/`Drop` без commit откатывает всё.** Реализация обязана
//!    применять правки в одной транзакции (`pulse-zonefile` — writer +
//!    единственный commit).
//!
//! # Семантика
//!
//! - Add: дубликаты RDATA игнорируются; существующий RRset сохраняет TTL;
//!   `CNAME` заменяет набор и не сосуществует с другими данными; `SOA`
//!   принимается только в apex и только с новым serial по RFC 1982.
//! - Delete RRset/name: в apex `SOA` и `NS` не удаляются (RFC 2136 §3.4.2.3).
//! - Delete RR: конкретные RDATA; единственная `NS` в apex не удаляется
//!   (RFC 2136 §3.4.2.4).
//! - После успешной транзакции serial растёт, даже если SOA не менялся
//!   (RFC 2136 §3.6, практика BIND); значение `0` при переполнении
//!   заменяется на `1` (RFC 2136 §7.11).
//! - DNSSEC-записи (`RRSIG`/`NSEC`/`NSEC3`/`NSEC3PARAM`/`DNSKEY`) управляются
//!   сигнатором; UPDATE их не добавляет и не удаляет (`REFUSED`), а при
//!   удалении всех RRset имени они сохраняются.

use pulse_dns::{Name, Rclass, Rdata, Rrset, Rtype, Serial, UpdateError, UpdateOp, UpdateRequest};

/// Результат успешной транзакции.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpdateOutcome {
    /// Итоговый SOA serial.
    pub serial: Serial,
    /// Были ли фактические изменения данных (без учёта автоинкремента SOA).
    pub changed: bool,
}

/// Транзакционный порт зоны для UPDATE.
///
/// `&mut self` у чтений нужен адаптерам с ленивым кешем владельцев; ошибки
/// хранилища возвращаются как [`UpdateError::ServFail`].
pub trait UpdateTarget {
    /// Origin зоны.
    fn origin(&self) -> &Name;

    /// Класс зоны (ZCLASS).
    fn zone_class(&self) -> Rclass;

    /// Текущий RRset или `None`.
    ///
    /// # Errors
    ///
    /// [`UpdateError::ServFail`] при ошибке чтения.
    fn rrset(&mut self, name: &Name, rr_type: Rtype) -> Result<Option<Rrset>, UpdateError>;

    /// Все типы, реально owning RRs у имени (без empty non-terminal).
    ///
    /// # Errors
    ///
    /// [`UpdateError::ServFail`] при ошибке чтения.
    fn types_at(&mut self, name: &Name) -> Result<Vec<Rtype>, UpdateError>;

    /// Записывает RRset (add/replace) в незакоммиченную транзакцию.
    ///
    /// # Errors
    ///
    /// [`UpdateError::ServFail`] при ошибке записи.
    fn put_rrset(&mut self, rrset: &Rrset) -> Result<(), UpdateError>;

    /// Удаляет RRset в незакоммиченной транзакции.
    ///
    /// # Errors
    ///
    /// [`UpdateError::ServFail`] при ошибке записи.
    fn delete_rrset(&mut self, name: &Name, rr_type: Rtype) -> Result<(), UpdateError>;
}

/// Применяет UPDATE к транзакционному порту.
///
/// # Errors
///
/// Коды RFC 2136 §3.8: prerequisites (`NXDOMAIN`/`YXDOMAIN`/`NXRRSET`/
/// `YXRRSET`), `NOTAUTH` при несовпадении зоны/класса, `REFUSED` для
/// управляемых записей, `SERVFAIL` при ошибке хранилища.
pub fn apply_update(
    target: &mut dyn UpdateTarget,
    request: &UpdateRequest,
) -> Result<UpdateOutcome, UpdateError> {
    if target.origin() != request.zone() {
        return Err(UpdateError::NotAuthoritative {
            zone: request.zone().to_string(),
        });
    }
    if target.zone_class() != request.zone_class() {
        return Err(UpdateError::NotAuthoritative {
            zone: request.zone().to_string(),
        });
    }
    check_names_in_zone(target.origin(), request)?;
    check_prerequisites(target, request)?;

    let mut changed = false;
    let mut soa_advanced = false;
    for op in request.updates() {
        match op {
            UpdateOp::Add {
                name,
                rr_type,
                ttl,
                rdatas,
            } => {
                if is_managed_type(*rr_type) {
                    return Err(UpdateError::Refused {
                        reason: "DNSSEC records are managed by the signer",
                    });
                }
                changed |= add_rrset(target, name, *rr_type, *ttl, rdatas, &mut soa_advanced)?;
            }
            UpdateOp::DeleteRrset { name, rr_type } => {
                if is_managed_type(*rr_type) {
                    return Err(UpdateError::Refused {
                        reason: "DNSSEC records are managed by the signer",
                    });
                }
                if name == target.origin() && matches!(*rr_type, Rtype::SOA | Rtype::NS) {
                    continue;
                }
                let existed = target.rrset(name, *rr_type)?.is_some();
                if existed {
                    target.delete_rrset(name, *rr_type)?;
                    changed = true;
                }
            }
            UpdateOp::DeleteName { name } => {
                let at_apex = name == target.origin();
                let types = target.types_at(name)?;
                for rr_type in types {
                    if is_managed_type(rr_type) {
                        continue;
                    }
                    if at_apex && matches!(rr_type, Rtype::SOA | Rtype::NS) {
                        continue;
                    }
                    let existed = target.rrset(name, rr_type)?.is_some();
                    if existed {
                        target.delete_rrset(name, rr_type)?;
                        changed = true;
                    }
                }
            }
            UpdateOp::DeleteRecord {
                name,
                rr_type,
                rdatas,
            } => {
                if is_managed_type(*rr_type) {
                    return Err(UpdateError::Refused {
                        reason: "DNSSEC records are managed by the signer",
                    });
                }
                changed |= delete_records(target, name, *rr_type, rdatas)?;
            }
        }
    }

    let serial = if soa_advanced {
        soa_serial(target)?.ok_or_else(missing_soa)?
    } else {
        bump_soa(target)?
    };
    Ok(UpdateOutcome { serial, changed })
}

fn check_names_in_zone(origin: &Name, request: &UpdateRequest) -> Result<(), UpdateError> {
    for prerequisite in request.prerequisites() {
        let name = match prerequisite {
            pulse_dns::Prerequisite::NameInUse { name }
            | pulse_dns::Prerequisite::NameNotInUse { name }
            | pulse_dns::Prerequisite::RrsetExists { name, .. }
            | pulse_dns::Prerequisite::RrsetDoesNotExist { name, .. }
            | pulse_dns::Prerequisite::RrsetEquals { name, .. } => name,
        };
        if !name.is_subdomain_of(origin) {
            return Err(UpdateError::NotZone {
                name: name.to_string(),
                zone: origin.to_string(),
            });
        }
    }
    for update in request.updates() {
        let name = match update {
            UpdateOp::Add { name, .. }
            | UpdateOp::DeleteRrset { name, .. }
            | UpdateOp::DeleteName { name }
            | UpdateOp::DeleteRecord { name, .. } => name,
        };
        if !name.is_subdomain_of(origin) {
            return Err(UpdateError::NotZone {
                name: name.to_string(),
                zone: origin.to_string(),
            });
        }
    }
    Ok(())
}

fn check_prerequisites(
    target: &mut dyn UpdateTarget,
    request: &UpdateRequest,
) -> Result<(), UpdateError> {
    for prerequisite in request.prerequisites() {
        match prerequisite {
            pulse_dns::Prerequisite::NameInUse { name } => {
                if target.types_at(name)?.is_empty() {
                    return Err(UpdateError::NameRequired {
                        name: name.to_string(),
                    });
                }
            }
            pulse_dns::Prerequisite::NameNotInUse { name } => {
                if !target.types_at(name)?.is_empty() {
                    return Err(UpdateError::NameExists {
                        name: name.to_string(),
                    });
                }
            }
            pulse_dns::Prerequisite::RrsetExists { name, rr_type } => {
                if target.rrset(name, *rr_type)?.is_none() {
                    return Err(UpdateError::RrsetRequired {
                        name: name.to_string(),
                        rr_type: *rr_type,
                    });
                }
            }
            pulse_dns::Prerequisite::RrsetDoesNotExist { name, rr_type } => {
                if target.rrset(name, *rr_type)?.is_some() {
                    return Err(UpdateError::RrsetExists {
                        name: name.to_string(),
                        rr_type: *rr_type,
                    });
                }
            }
            pulse_dns::Prerequisite::RrsetEquals {
                name,
                rr_type,
                rdatas,
            } => {
                let Some(current) = target.rrset(name, *rr_type)? else {
                    return Err(UpdateError::RrsetMismatch {
                        name: name.to_string(),
                        rr_type: *rr_type,
                    });
                };
                if !same_rdatas(&current, rdatas) {
                    return Err(UpdateError::RrsetMismatch {
                        name: name.to_string(),
                        rr_type: *rr_type,
                    });
                }
            }
        }
    }
    Ok(())
}

fn add_rrset(
    target: &mut dyn UpdateTarget,
    name: &Name,
    rr_type: Rtype,
    ttl: pulse_dns::Ttl,
    rdatas: &[Rdata],
    soa_advanced: &mut bool,
) -> Result<bool, UpdateError> {
    if rr_type == Rtype::CNAME {
        let types = target.types_at(name)?;
        if types
            .iter()
            .any(|kind| *kind != Rtype::CNAME && !is_dnssec_meta(*kind))
        {
            return Ok(false);
        }
    } else if target.rrset(name, Rtype::CNAME)?.is_some() {
        return Ok(false);
    }

    if rr_type == Rtype::SOA {
        if name != target.origin() {
            return Ok(false);
        }
        let Some(current) = target.rrset(name, Rtype::SOA)? else {
            return Ok(false);
        };
        let Some(new_serial) = rdatas.iter().find_map(|rdata| match rdata {
            Rdata::Soa(soa) => Some(soa.serial),
            _ => None,
        }) else {
            return Ok(false);
        };
        let Some(current_serial) = soa_serial_of(&current) else {
            return Ok(false);
        };
        if new_serial == Serial::ZERO || new_serial.is_newer_than(current_serial) != Some(true) {
            return Ok(false);
        }
        *soa_advanced = true;
        let rrset = build_rrset(name.clone(), rr_type, current.ttl(), rdatas)?;
        target.put_rrset(&rrset)?;
        return Ok(true);
    }

    if rr_type == Rtype::CNAME {
        // RFC 2136 §1.1.5: CNAME заменяет предыдущий CNAME, а не дополняет.
        let rrset = build_rrset(name.clone(), rr_type, ttl, rdatas)?;
        target.put_rrset(&rrset)?;
        return Ok(true);
    }

    let mut merged = rdatas.to_vec();
    let ttl = if let Some(current) = target.rrset(name, rr_type)? {
        for existing in current.rdatas() {
            merged.push(existing.clone());
        }
        current.ttl()
    } else {
        ttl
    };
    merged.sort();
    merged.dedup();
    let rrset = build_rrset(name.clone(), rr_type, ttl, &merged)?;
    target.put_rrset(&rrset)?;
    Ok(true)
}

fn delete_records(
    target: &mut dyn UpdateTarget,
    name: &Name,
    rr_type: Rtype,
    rdatas: &[Rdata],
) -> Result<bool, UpdateError> {
    if rr_type == Rtype::SOA {
        return Ok(false);
    }
    let Some(current) = target.rrset(name, rr_type)? else {
        return Ok(false);
    };
    if rr_type == Rtype::NS
        && name == target.origin()
        && current.len() == 1
        && let Some(rdata) = current.rdatas().first()
        && rdatas.contains(rdata)
    {
        return Ok(false);
    }
    if !rdatas.iter().any(|rdata| current.contains(rdata)) {
        return Ok(false);
    }
    let remaining: Vec<Rdata> = current
        .rdatas()
        .iter()
        .filter(|rdata| !rdatas.contains(rdata))
        .cloned()
        .collect();
    if remaining.is_empty() {
        target.delete_rrset(name, rr_type)?;
    } else {
        let rrset = build_rrset(name.clone(), rr_type, current.ttl(), &remaining)?;
        target.put_rrset(&rrset)?;
    }
    Ok(true)
}

fn bump_soa(target: &mut dyn UpdateTarget) -> Result<Serial, UpdateError> {
    let origin = target.origin().clone();
    let Some(current) = target.rrset(&origin, Rtype::SOA)? else {
        return Err(missing_soa());
    };
    let Some(current_serial) = soa_serial_of(&current) else {
        return Err(missing_soa());
    };
    let next = match current_serial.succ().as_u32() {
        0 => Serial::new(1),
        value => Serial::new(value),
    };
    let Some(Rdata::Soa(mut soa)) = current.rdatas().first().cloned() else {
        return Err(missing_soa());
    };
    soa.serial = next;
    let rrset = build_rrset(origin, Rtype::SOA, current.ttl(), &[Rdata::Soa(soa)])?;
    target.put_rrset(&rrset)?;
    Ok(next)
}

fn soa_serial(target: &mut dyn UpdateTarget) -> Result<Option<Serial>, UpdateError> {
    let origin = target.origin().clone();
    let Some(current) = target.rrset(&origin, Rtype::SOA)? else {
        return Ok(None);
    };
    Ok(soa_serial_of(&current))
}

fn soa_serial_of(rrset: &Rrset) -> Option<Serial> {
    rrset.rdatas().iter().find_map(|rdata| match rdata {
        Rdata::Soa(soa) => Some(soa.serial),
        _ => None,
    })
}

fn same_rdatas(rrset: &Rrset, rdatas: &[Rdata]) -> bool {
    if rrset.len() != rdatas.len() {
        return false;
    }
    rdatas.iter().all(|rdata| rrset.contains(rdata))
}

fn build_rrset(
    name: Name,
    rr_type: Rtype,
    ttl: pulse_dns::Ttl,
    rdatas: &[Rdata],
) -> Result<Rrset, UpdateError> {
    Rrset::new(name, rr_type, Rclass::IN, ttl, rdatas.iter().cloned()).map_err(|error| {
        UpdateError::ServFail {
            reason: error.to_string(),
        }
    })
}

fn missing_soa() -> UpdateError {
    UpdateError::ServFail {
        reason: "zone has no valid apex SOA".to_owned(),
    }
}

/// Записи DNSSEC, которыми управляет сигнатор, а не UPDATE.
#[must_use]
pub const fn is_managed_type(rr_type: Rtype) -> bool {
    is_dnssec_meta(rr_type) || matches!(rr_type, Rtype::DNSKEY)
}

const fn is_dnssec_meta(rr_type: Rtype) -> bool {
    matches!(
        rr_type.as_u16(),
        46 | 47 | 50 | 51 // RRSIG, NSEC, NSEC3, NSEC3PARAM
    )
}
