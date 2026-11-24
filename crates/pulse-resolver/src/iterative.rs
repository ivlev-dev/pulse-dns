//! Итеративная резолюция от корня: делегирования, glue, CNAME-цепочки.
//!
//! Bailiwick проверяется на каждом шаге: NS принимаются только внутри
//! текущей зоны и только если делегирование ведёт к QNAME; glue — только
//! внутри делегированной зоны и только для имён из NS-набора.

use std::net::{IpAddr, SocketAddr};

use pulse_dns::{Name, Question, Rclass, Rcode, Record, Rtype};

use crate::error::ResolverError;
use crate::resolver::{Resolution, ResolveContext, Resolver, check_context};
use crate::rrutil::{
    addresses, cname_target, find_referral, find_soa, glue_for, merge_records, related_rrsigs,
    within_bailiwick,
};

const MAX_NS_NAMES: usize = 8;
const MAX_NS_ADDRESSES: usize = 6;

pub(crate) fn resolve(
    resolver: &Resolver,
    qname: &Name,
    qtype: Rtype,
    dnssec_ok: bool,
    context: &ResolveContext,
) -> Result<Resolution, ResolverError> {
    let roots = resolver.root_hints();
    if roots.is_empty() {
        return Err(ResolverError::NoUpstream);
    }
    let mut engine = Engine {
        resolver,
        context,
        dnssec_ok,
        queries: 0,
    };
    engine.lookup(qname, qtype, 0, Name::root(), roots)
}

struct Engine<'a> {
    resolver: &'a Resolver,
    context: &'a ResolveContext,
    dnssec_ok: bool,
    queries: usize,
}

impl Engine<'_> {
    fn lookup(
        &mut self,
        qname: &Name,
        qtype: Rtype,
        depth: usize,
        zone: Name,
        servers: Vec<SocketAddr>,
    ) -> Result<Resolution, ResolverError> {
        let max_depth = self.resolver.inner.config.max_depth;
        if depth > max_depth {
            return Err(ResolverError::DepthExceeded { limit: max_depth });
        }
        let max_cname = self.resolver.inner.config.max_cname_chain;
        let mut zone = zone;
        let mut servers = servers;
        if self.resolver.inner.config.qname_minimization {
            let (next_zone, next_servers) = self.minimize(qname, &zone, &servers, depth)?;
            zone = next_zone;
            servers = next_servers;
        }

        let mut current = qname.clone();
        let mut cname_chain: Vec<Record> = Vec::new();
        let mut visited_cnames: Vec<Name> = vec![qname.clone()];
        let mut visited_referrals: Vec<Name> = Vec::new();

        for _ in 0..max_depth.saturating_add(1) {
            check_context(self.context)?;
            let response = self.query(&servers, &current, qtype)?;
            let message = response.message;
            let rcode = message.rcode();

            match rcode {
                Rcode::NOERROR => {}
                Rcode::NXDOMAIN => {
                    let authority = within_bailiwick(message.authority(), &zone);
                    return Ok(Resolution {
                        rcode,
                        answers: cname_chain,
                        authority,
                        additional: Vec::new(),
                        zone,
                    });
                }
                other => {
                    return Err(ResolverError::UpstreamRcode {
                        server: "authoritative".to_owned(),
                        rcode: other,
                    });
                }
            }

            if qtype != Rtype::CNAME
                && let Some(target) = cname_target(message.answers(), &current)
            {
                let cname_records: Vec<Record> = message
                    .answers()
                    .iter()
                    .filter(|record| record.owner() == &current && record.rr_type() == Rtype::CNAME)
                    .cloned()
                    .collect();
                let signatures = related_rrsigs(message.answers(), &cname_records);
                merge_records(&mut cname_chain, cname_records);
                merge_records(&mut cname_chain, signatures);
                let count = cname_chain
                    .iter()
                    .filter(|record| record.rr_type() == Rtype::CNAME)
                    .count();
                if count > max_cname {
                    return Err(ResolverError::CnameChainTooLong { limit: max_cname });
                }
                if visited_cnames.contains(&target) {
                    return Err(ResolverError::CnameLoop {
                        name: target.to_string(),
                    });
                }
                visited_cnames.push(target.clone());
                if visited_cnames.len() > max_cname.saturating_add(1) {
                    return Err(ResolverError::CnameChainTooLong { limit: max_cname });
                }
                if !target.is_subdomain_of(&zone) {
                    zone = Name::root();
                    servers = self.resolver.root_hints();
                    visited_referrals.clear();
                }
                current = target;
                continue;
            }

            let direct: Vec<Record> = message
                .answers()
                .iter()
                .filter(|record| record.owner() == &current && record.rr_type() == qtype)
                .cloned()
                .collect();
            if !direct.is_empty() {
                let signatures = related_rrsigs(message.answers(), &direct);
                let mut answers = cname_chain;
                merge_records(&mut answers, direct);
                merge_records(&mut answers, signatures);
                return Ok(Resolution {
                    rcode,
                    answers,
                    authority: Vec::new(),
                    additional: Vec::new(),
                    zone,
                });
            }

            if find_soa(message.authority()).is_some() {
                let mut authority = within_bailiwick(message.authority(), &zone);
                let signatures = related_rrsigs(message.authority(), &authority);
                merge_records(&mut authority, signatures);
                return Ok(Resolution {
                    rcode,
                    answers: cname_chain,
                    authority,
                    additional: Vec::new(),
                    zone,
                });
            }

            if let Some((child, ns_names)) = find_referral(message.authority(), &zone, &current) {
                if visited_referrals.contains(&child) {
                    return Err(ResolverError::DelegationLoop {
                        zone: child.to_string(),
                    });
                }
                visited_referrals.push(child.clone());
                if visited_referrals.len() > max_depth {
                    return Err(ResolverError::DepthExceeded { limit: max_depth });
                }
                let glue = glue_for(message.additional(), &child);
                let next_servers =
                    self.nameserver_addresses(&ns_names, &glue, depth.saturating_add(1))?;
                if next_servers.is_empty() {
                    return Err(ResolverError::NoNameserver {
                        zone: child.to_string(),
                    });
                }
                zone = child;
                servers = next_servers;
                continue;
            }

            return Err(ResolverError::NoProgress {
                zone: zone.to_string(),
            });
        }
        Err(ResolverError::DepthExceeded { limit: max_depth })
    }

    fn query(
        &mut self,
        servers: &[SocketAddr],
        qname: &Name,
        qtype: Rtype,
    ) -> Result<crate::upstream::UpstreamResponse, ResolverError> {
        let limit = self.resolver.inner.config.max_queries;
        self.queries = self.queries.saturating_add(1);
        if self.queries > limit {
            return Err(ResolverError::QueryBudgetExhausted { limit });
        }
        let question = Question::new(qname.clone(), qtype, Rclass::IN);
        self.resolver
            .query_any(servers, &question, false, self.dnssec_ok, self.context)
    }

    fn nameserver_addresses(
        &mut self,
        ns_names: &[Name],
        glue: &[Record],
        depth: usize,
    ) -> Result<Vec<SocketAddr>, ResolverError> {
        let mut found: Vec<IpAddr> = Vec::new();
        for record in glue {
            if !ns_names.iter().any(|name| name == record.owner()) {
                continue;
            }
            for address in addresses(std::slice::from_ref(record)) {
                if !found.contains(&address) {
                    found.push(address);
                }
            }
        }

        for name in ns_names.iter().take(MAX_NS_NAMES) {
            if found.len() >= MAX_NS_ADDRESSES {
                break;
            }
            if glue.iter().any(|record| record.owner() == name) {
                continue;
            }
            if let Some(cached) = self.resolver.cache_ref().lookup_exact(name, Rtype::A, true) {
                for address in addresses(&cached.records) {
                    if !found.contains(&address) {
                        found.push(address);
                    }
                }
                if found.len() >= MAX_NS_ADDRESSES {
                    break;
                }
            }
            if let Some(cached) = self
                .resolver
                .cache_ref()
                .lookup_exact(name, Rtype::AAAA, true)
            {
                for address in addresses(&cached.records) {
                    if !found.contains(&address) {
                        found.push(address);
                    }
                }
            }

            let roots = self.resolver.root_hints();
            for rr_type in [Rtype::A, Rtype::AAAA] {
                if found.len() >= MAX_NS_ADDRESSES {
                    break;
                }
                let result = self.lookup(name, rr_type, depth, Name::root(), roots.clone());
                match result {
                    Ok(resolution) => {
                        for address in addresses(&resolution.answers) {
                            if !found.contains(&address) {
                                found.push(address);
                            }
                        }
                    }
                    Err(error)
                        if matches!(
                            error,
                            ResolverError::Timeout
                                | ResolverError::Cancelled
                                | ResolverError::QueryBudgetExhausted { .. }
                        ) =>
                    {
                        return Err(error);
                    }
                    Err(_) => {}
                }
            }
        }

        let port = self.resolver.ns_port();
        let mut servers: Vec<SocketAddr> = found
            .into_iter()
            .take(MAX_NS_ADDRESSES)
            .map(|address| SocketAddr::new(address, port))
            .collect();
        servers.dedup();
        Ok(servers)
    }

    fn minimize(
        &mut self,
        qname: &Name,
        zone: &Name,
        servers: &[SocketAddr],
        depth: usize,
    ) -> Result<(Name, Vec<SocketAddr>), ResolverError> {
        let mut current_zone = zone.clone();
        let mut current_servers = servers.to_vec();
        let ancestors = ancestors_between(qname, zone);
        for ancestor in ancestors {
            check_context(self.context)?;
            let question = Question::new(ancestor.clone(), Rtype::NS, Rclass::IN);
            let limit = self.resolver.inner.config.max_queries;
            self.queries = self.queries.saturating_add(1);
            if self.queries > limit {
                return Err(ResolverError::QueryBudgetExhausted { limit });
            }
            let response = self.resolver.query_any(
                &current_servers,
                &question,
                false,
                self.dnssec_ok,
                self.context,
            )?;
            let message = response.message;
            if message.rcode() != Rcode::NOERROR {
                break;
            }
            if let Some((child, ns_names)) =
                find_referral(message.authority(), &current_zone, &ancestor)
            {
                let glue = glue_for(message.additional(), &child);
                let addresses =
                    self.nameserver_addresses(&ns_names, &glue, depth.saturating_add(1))?;
                if !addresses.is_empty() {
                    current_zone = child;
                    current_servers = addresses;
                }
            }
        }
        Ok((current_zone, current_servers))
    }
}

fn ancestors_between(qname: &Name, zone: &Name) -> Vec<Name> {
    if !qname.is_subdomain_of(zone) {
        return Vec::new();
    }
    let mut chain = Vec::new();
    let mut current = qname.clone();
    while &current != zone {
        chain.push(current.clone());
        let Some(parent) = current.parent() else {
            break;
        };
        current = parent;
    }
    chain.reverse();
    chain
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ancestors_exclude_zone_and_include_qname() {
        let zone = Name::parse("com").unwrap();
        let qname = Name::parse("www.example.com").unwrap();
        let chain = ancestors_between(&qname, &zone);
        assert_eq!(
            chain,
            vec![
                Name::parse("example.com").unwrap(),
                Name::parse("www.example.com").unwrap()
            ]
        );
    }

    #[test]
    fn ancestors_empty_for_outside_name() {
        let zone = Name::parse("example.com").unwrap();
        let qname = Name::parse("example.net").unwrap();
        assert_eq!(ancestors_between(&qname, &zone).len(), 0);
    }
}
