//! Свойства суффиксного blocklist.

use proptest::prelude::*;
use pulse_dns::Name;
use pulse_resolver::blocklist::Blocklist;

fn join(labels: &[String]) -> String {
    labels.join(".")
}

proptest! {
    #[test]
    fn blocking_a_domain_blocks_all_subdomains(
        labels in prop::collection::vec("[a-z]{1,8}", 1..4),
        extra in prop::collection::vec("[a-z]{1,8}", 1..3),
    ) {
        let domain = join(&labels);
        let qname = format!("{}.{}", join(&extra), domain);
        let list = Blocklist::parse(&format!("{domain}\n"), &[]);
        prop_assert!(list.is_blocked(&Name::parse(&qname).unwrap()));
        prop_assert!(list.is_blocked(&Name::parse(&domain).unwrap()));
    }

    #[test]
    fn wildcard_blocks_strict_subdomains_only(
        labels in prop::collection::vec("[a-z]{1,8}", 1..4),
        extra in prop::collection::vec("[a-z]{1,8}", 1..3),
    ) {
        let domain = join(&labels);
        let qname = format!("{}.{}", join(&extra), domain);
        let list = Blocklist::parse(&format!("*.{domain}\n"), &[]);
        prop_assert!(list.is_blocked(&Name::parse(&qname).unwrap()));
        prop_assert!(!list.is_blocked(&Name::parse(&domain).unwrap()));
    }

    #[test]
    fn allowlist_overrides_blocklist(
        labels in prop::collection::vec("[a-z]{1,8}", 1..4),
        extra in prop::collection::vec("[a-z]{1,8}", 1..3),
    ) {
        let domain = join(&labels);
        let allowed = format!("allow.{domain}");
        let qname = format!("{}.{}", join(&extra), allowed);
        let list = Blocklist::parse(
            &format!("{domain}\n"),
            std::slice::from_ref(&allowed),
        );
        prop_assert!(!list.is_blocked(&Name::parse(&qname).unwrap()));
        prop_assert!(!list.is_blocked(&Name::parse(&allowed).unwrap()));
    }
}
