//! Вспомогательные операции над записями: группировка RRset, выбор RRSIG,
//! SOA/negative TTL, поиск делегирования и glue.

use std::collections::HashMap;

use pulse_dns::{Name, Rclass, Rdata, Record, Rrset, RrsigData, Rtype, Ttl};

/// Сгруппированный RRset до валидации.
pub(crate) struct RrsetGroup {
    pub(crate) owner: Name,
    pub(crate) rr_type: Rtype,
    pub(crate) ttl: Ttl,
    pub(crate) rdatas: Vec<Rdata>,
}

impl RrsetGroup {
    pub(crate) fn to_rrset(&self) -> Option<Rrset> {
        Rrset::new(
            self.owner.clone(),
            self.rr_type,
            Rclass::IN,
            self.ttl,
            self.rdatas.clone(),
        )
        .ok()
    }
}

/// Группирует записи по `(owner, type)` без RRSIG.
pub(crate) fn group_rrsets(records: &[Record]) -> Vec<RrsetGroup> {
    let mut groups: Vec<RrsetGroup> = Vec::new();
    let mut index: HashMap<(Name, Rtype), usize> = HashMap::new();
    for record in records {
        if record.rr_type() == Rtype::RRSIG || record.class() != Rclass::IN {
            continue;
        }
        let key = (record.owner().clone(), record.rr_type());
        if let Some(position) = index.get(&key) {
            if let Some(group) = groups.get_mut(*position)
                && !group.rdatas.contains(record.rdata())
            {
                group.rdatas.push(record.rdata().clone());
            }
            continue;
        }
        index.insert(key, groups.len());
        groups.push(RrsetGroup {
            owner: record.owner().clone(),
            rr_type: record.rr_type(),
            ttl: record.ttl(),
            rdatas: vec![record.rdata().clone()],
        });
    }
    groups
}

/// Возвращает RRSIG-значения, покрывающие `(owner, covered)`.
pub(crate) fn rrsigs_for(records: &[Record], owner: &Name, covered: Rtype) -> Vec<RrsigData> {
    records
        .iter()
        .filter(|record| record.owner() == owner)
        .filter_map(|record| match record.rdata() {
            Rdata::Rrsig(signature) if signature.type_covered() == covered => {
                Some(signature.clone())
            }
            _ => None,
        })
        .collect()
}

/// Возвращает RRSIG-записи, покрывающие `(owner, covered)`.
pub(crate) fn rrsig_records_for(records: &[Record], owner: &Name, covered: Rtype) -> Vec<Record> {
    records
        .iter()
        .filter(|record| record.owner() == owner)
        .filter(|record| match record.rdata() {
            Rdata::Rrsig(signature) => signature.type_covered() == covered,
            _ => false,
        })
        .cloned()
        .collect()
}

/// Копирует RRSIG-записи, относящиеся к собранным RRset.
pub(crate) fn related_rrsigs(source: &[Record], collected: &[Record]) -> Vec<Record> {
    let mut signatures = Vec::new();
    for record in collected {
        if record.rr_type() == Rtype::RRSIG {
            continue;
        }
        for signature in rrsig_records_for(source, record.owner(), record.rr_type()) {
            if !signatures.contains(&signature) {
                signatures.push(signature);
            }
        }
    }
    signatures
}

/// Возвращает SOA-запись из authority.
pub(crate) fn find_soa(authority: &[Record]) -> Option<&Record> {
    authority
        .iter()
        .find(|record| record.rr_type() == Rtype::SOA)
}

/// Negative TTL по RFC 2308: `min(SOA.ttl, SOA.minimum)`.
pub(crate) fn negative_ttl(authority: &[Record]) -> Option<u32> {
    let record = find_soa(authority)?;
    let Rdata::Soa(soa) = record.rdata() else {
        return None;
    };
    Some(record.ttl().as_u32().min(soa.minimum))
}

/// Переписывает TTL всех записей (для negative-ответов).
pub(crate) fn rewrite_ttl(records: &[Record], ttl: u32) -> Vec<Record> {
    let ttl = Ttl::from_wire(ttl);
    records
        .iter()
        .filter_map(|record| {
            Record::new(
                record.owner().clone(),
                record.rr_type(),
                record.class(),
                ttl,
                record.rdata().clone(),
            )
            .ok()
        })
        .collect()
}

/// Находит SOA-владельца (зону) в authority.
pub(crate) fn soa_zone(authority: &[Record]) -> Option<Name> {
    find_soa(authority).map(|record| record.owner().clone())
}

/// Делегирование из authority: наиболее специфичный NS-владелец внутри
/// `zone`, строго ниже текущей зоны и являющийся предком `qname`.
pub(crate) fn find_referral(
    authority: &[Record],
    zone: &Name,
    qname: &Name,
) -> Option<(Name, Vec<Name>)> {
    let mut candidates: HashMap<Name, Vec<Name>> = HashMap::new();
    for record in authority {
        if record.rr_type() != Rtype::NS || record.class() != Rclass::IN {
            continue;
        }
        let owner = record.owner();
        if owner == zone || !owner.is_subdomain_of(zone) || !qname.is_subdomain_of(owner) {
            continue;
        }
        let Rdata::Ns(target) = record.rdata() else {
            continue;
        };
        candidates
            .entry(owner.clone())
            .or_default()
            .push(target.clone());
    }
    let mut best: Option<(Name, Vec<Name>)> = None;
    for (owner, servers) in candidates {
        let replace = best
            .as_ref()
            .is_none_or(|(current, _)| owner.label_count() > current.label_count());
        if replace {
            best = Some((owner, servers));
        }
    }
    best
}

/// Glue-адреса из additional, находящиеся внутри делегированной зоны.
pub(crate) fn glue_for(additional: &[Record], child: &Name) -> Vec<Record> {
    additional
        .iter()
        .filter(|record| matches!(record.rr_type(), Rtype::A | Rtype::AAAA))
        .filter(|record| record.owner().is_subdomain_of(child))
        .cloned()
        .collect()
}

/// Фильтрует записи, оставляя только владельцев внутри `zone`.
pub(crate) fn within_bailiwick(records: &[Record], zone: &Name) -> Vec<Record> {
    records
        .iter()
        .filter(|record| record.owner().is_subdomain_of(zone))
        .cloned()
        .collect()
}

/// Достаёт адреса из A/AAAA-записей.
pub(crate) fn addresses(records: &[Record]) -> Vec<std::net::IpAddr> {
    let mut result = Vec::new();
    for record in records {
        let address = match record.rdata() {
            Rdata::A(address) => std::net::IpAddr::V4(*address),
            Rdata::Aaaa(address) => std::net::IpAddr::V6(*address),
            _ => continue,
        };
        if !result.contains(&address) {
            result.push(address);
        }
    }
    result
}

/// CNAME-цель из записей для указанного владельца.
pub(crate) fn cname_target(records: &[Record], owner: &Name) -> Option<Name> {
    records.iter().find_map(|record| {
        if record.owner() != owner {
            return None;
        }
        match record.rdata() {
            Rdata::Cname(target) => Some(target.clone()),
            _ => None,
        }
    })
}

/// Duplicate-free объединение записей.
pub(crate) fn merge_records(base: &mut Vec<Record>, extra: Vec<Record>) {
    for record in extra {
        if !base.contains(&record) {
            base.push(record);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    use pulse_dns::Serial;

    fn name(value: &str) -> Name {
        Name::parse(value).unwrap()
    }

    fn ns(owner: &str, target: &str) -> Record {
        Record::new(
            name(owner),
            Rtype::NS,
            Rclass::IN,
            Ttl::new(300).unwrap(),
            Rdata::Ns(name(target)),
        )
        .unwrap()
    }

    fn a(owner: &str, address: Ipv4Addr) -> Record {
        Record::new(
            name(owner),
            Rtype::A,
            Rclass::IN,
            Ttl::new(300).unwrap(),
            Rdata::A(address),
        )
        .unwrap()
    }

    #[test]
    fn referral_chooses_deepest_ns() {
        let authority = vec![
            ns("com", "a.gtld.net"),
            ns("example.com", "ns1.example.com"),
        ];
        let (zone, servers) =
            find_referral(&authority, &name("com"), &name("www.example.com")).unwrap();
        assert_eq!(zone, name("example.com"));
        assert_eq!(servers, vec![name("ns1.example.com")]);
    }

    #[test]
    fn negative_ttl_uses_soa_minimum() {
        let soa = Record::new(
            name("example.com"),
            Rtype::SOA,
            Rclass::IN,
            Ttl::new(300).unwrap(),
            Rdata::Soa(pulse_dns::SoaData::new(
                name("ns1.example.com"),
                name("hostmaster.example.com"),
                Serial::new(1),
                3600,
                600,
                86_400,
                60,
            )),
        )
        .unwrap();
        assert_eq!(negative_ttl(&[soa]), Some(60));
    }

    #[test]
    fn glue_outside_zone_is_ignored() {
        let additional = vec![
            a("ns1.example.com", Ipv4Addr::new(192, 0, 2, 1)),
            a("evil.other", Ipv4Addr::new(192, 0, 2, 2)),
        ];
        let glue = glue_for(&additional, &name("example.com"));
        assert_eq!(glue.len(), 1);
    }

    #[test]
    fn group_rrsets_deduplicates() {
        let records = vec![
            a("www.example.com", Ipv4Addr::new(192, 0, 2, 1)),
            a("www.example.com", Ipv4Addr::new(192, 0, 2, 1)),
        ];
        let groups = group_rrsets(&records);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].rdatas.len(), 1);
    }
}
