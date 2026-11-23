//! ETag зоны и RRset, разбор условных заголовков.

use pulse_dns::Rrset;
use sha2::{Digest, Sha256};

use crate::codec::hex_lower;

/// ETag зоны: `"z<id>-v<version>-t<txn>"`.
pub(crate) fn zone_etag(id: u32, version: u64, txn: u64) -> String {
    format!("\"z{id}-v{version}-t{txn}\"")
}

/// ETag RRset: хеш канонической формы набора `(owner, type, class, ttl, rdata)`.
pub(crate) fn rrset_etag(rrset: &Rrset) -> String {
    let mut hasher = Sha256::new();
    hasher.update(rrset.owner().as_wire());
    hasher.update(rrset.rr_type().as_u16().to_be_bytes());
    hasher.update(rrset.class().as_u16().to_be_bytes());
    hasher.update(rrset.ttl().as_u32().to_be_bytes());
    for rdata in rrset.rdatas() {
        hasher.update(rdata.to_canonical_wire());
    }
    let digest = hasher.finalize();
    let prefix = digest.get(..6).unwrap_or(&digest);
    format!("\"rr_{}\"", hex_lower(prefix))
}

/// Убирает кавычки и `W/`-префикс у ETag; `*` возвращается как есть.
pub(crate) fn normalize_tag(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed == "*" {
        return Some("*".to_owned());
    }
    let without_weak = trimmed.strip_prefix("W/").unwrap_or(trimmed);
    let without_quotes = without_weak
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(without_weak);
    if without_quotes.is_empty() || without_quotes.len() > 256 {
        return None;
    }
    Some(without_quotes.to_owned())
}

/// Совпадает ли текущий ETag с одним из значений заголовка.
///
/// Поддерживается список через запятую и `*`.
pub(crate) fn header_matches(current: &str, header_value: &str) -> bool {
    let current = normalize_tag(current).unwrap_or_default();
    header_value.split(',').any(|candidate| {
        normalize_tag(candidate).is_some_and(|candidate| candidate == "*" || candidate == current)
    })
}

#[cfg(test)]
mod tests {
    use pulse_dns::{Name, Rclass, Rdata, Rtype, Ttl};

    use super::*;

    fn sample() -> Rrset {
        Rrset::new(
            Name::parse("www.example.com.").unwrap(),
            Rtype::A,
            Rclass::IN,
            Ttl::new(300).unwrap(),
            [
                Rdata::A("192.0.2.10".parse().unwrap()),
                Rdata::A("192.0.2.11".parse().unwrap()),
            ],
        )
        .unwrap()
    }

    #[test]
    fn rrset_etag_stable_and_order_independent() {
        let first = sample();
        let second = Rrset::new(
            Name::parse("www.example.com.").unwrap(),
            Rtype::A,
            Rclass::IN,
            Ttl::new(300).unwrap(),
            [
                Rdata::A("192.0.2.11".parse().unwrap()),
                Rdata::A("192.0.2.10".parse().unwrap()),
            ],
        )
        .unwrap();
        assert_eq!(rrset_etag(&first), rrset_etag(&second));
    }

    #[test]
    fn conditional_matching() {
        assert!(header_matches("\"rr_abc\"", "\"rr_abc\""));
        assert!(header_matches("\"rr_abc\"", "W/\"rr_abc\""));
        assert!(header_matches("\"rr_abc\"", "\"x\", \"rr_abc\""));
        assert!(header_matches("\"rr_abc\"", "*"));
        assert!(!header_matches("\"rr_abc\"", "\"other\""));
    }
}
