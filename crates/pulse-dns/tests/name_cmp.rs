//! Канонический порядок имён (RFC 4034 §6.1) и инварианты `Name`.

use std::cmp::Ordering;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use pulse_dns::{
    DecodeLimits, EncodeOptions, MAX_NAME_TEXT_LEN, Message, Name, NameError, Question, Rclass,
    Rtype, name_cmp,
};

fn parse(value: &str) -> Name {
    Name::parse(value).unwrap()
}

#[test]
fn rfc4034_canonical_order_vector() {
    let ordered = [
        "example",
        "a.example",
        "yljkjljk.a.example",
        "Z.a.example",
        "zABC.a.EXAMPLE",
        "z.example",
        "\\001.z.example",
        "*.z.example",
        "\\200.z.example",
    ];
    let names: Vec<Name> = ordered.iter().map(|value| parse(value)).collect();
    for pair in names.windows(2) {
        let (left, right) = (pair.first().unwrap(), pair.get(1).unwrap());
        assert_eq!(
            left.cmp_canonical(right),
            Ordering::Less,
            "{left} must sort before {right}"
        );
        assert_eq!(name_cmp(left, right), Ordering::Less);
        assert_eq!(right.cmp_canonical(left), Ordering::Greater);
    }
}

#[test]
fn ancestor_sorts_first() {
    assert_eq!(
        parse("example.com").cmp_canonical(&parse("a.example.com")),
        Ordering::Less
    );
    assert_eq!(
        parse("example.com").cmp_canonical(&parse("example.com")),
        Ordering::Equal
    );
    assert_eq!(
        parse("z.example.com").cmp_canonical(&parse("example.com")),
        Ordering::Greater
    );
}

#[test]
fn case_is_ignored() {
    let upper = parse("WwW.ExAmPlE.CoM");
    let lower = parse("www.example.com");
    assert_eq!(upper, lower);
    assert_eq!(upper.cmp_canonical(&lower), Ordering::Equal);

    let mut left = DefaultHasher::new();
    upper.hash(&mut left);
    let mut right = DefaultHasher::new();
    lower.hash(&mut right);
    assert_eq!(left.finish(), right.finish());
}

#[test]
fn escaped_uppercase_is_canonicalized() {
    assert_eq!(parse("\\065.example"), parse("a.example"));
    assert_eq!(parse("\\090.example"), parse("z.example"));
}

#[test]
fn subdomain_check_uses_label_boundaries() {
    assert!(parse("www.example.com").is_subdomain_of(&parse("example.com")));
    assert!(parse("example.com").is_subdomain_of(&parse("example.com")));
    assert!(!parse("example.com").is_subdomain_of(&parse("www.example.com")));
    // Содержимое метки не должно приниматься за суффикс.
    assert!(!parse("\\003com\\000").is_subdomain_of(&parse("com")));
}

#[test]
fn wire_wildcard_is_literal_label() {
    for value in [
        "*.example.com",
        "a.*.example.com",
        "*a.example.com",
        "*.*.example.com",
    ] {
        let expected = parse(value);
        let wire = expected.to_wire_uncompressed();
        assert_eq!(Name::from_wire(&wire).unwrap(), expected);

        let question = Question::new(expected.clone(), Rtype::A, Rclass::IN);
        let message = Message::query(0xBEEF, question);
        let bytes = message.encode(&EncodeOptions::default()).unwrap();
        let decoded = Message::decode(&bytes, &DecodeLimits::default()).unwrap();
        assert_eq!(decoded.questions().first().unwrap().qname(), &expected);
    }
}

#[test]
fn zone_owner_wildcard_validation() {
    let wildcard = parse("*.example.com");
    assert!(wildcard.is_wildcard_owner());
    assert!(wildcard.validate_zone_owner().is_ok());

    let middle = parse("a.*.example.com");
    assert!(!middle.is_wildcard_owner());
    assert_eq!(
        middle.validate_zone_owner(),
        Err(NameError::WildcardNotLeftmost)
    );

    let literal = parse("*a.example.com");
    assert!(!literal.is_wildcard_owner());
    assert!(literal.validate_zone_owner().is_ok());

    let double = parse("*.*.example.com");
    assert!(!double.is_wildcard_owner());
    assert_eq!(
        double.validate_zone_owner(),
        Err(NameError::WildcardNotLeftmost)
    );
}

#[test]
fn wildcard_and_underscore_ordering() {
    assert_eq!(
        parse("*.example.com").cmp_canonical(&parse("a.example.com")),
        Ordering::Less
    );
    assert_eq!(
        parse("_tcp.example.com").cmp_canonical(&parse("_sip._tcp.example.com")),
        Ordering::Less
    );
}

#[test]
fn display_roundtrip() {
    for value in [
        ".",
        "example.com.",
        "*.example.com.",
        "\\001.z.example.",
        "\\200.z.example.",
        "_sip._tcp.example.com.",
    ] {
        let parsed = parse(value);
        assert_eq!(parsed.to_string(), value);
        assert_eq!(Name::parse(&parsed.to_string()).unwrap(), parsed);
    }
}

#[test]
fn root_relations() {
    let root = Name::root();
    assert_eq!(root.label_count(), 0);
    assert_eq!(root.parent(), None);
    assert!(parse("example.com").is_subdomain_of(&root));
    assert_eq!(
        parse("www.example.com").parent(),
        Some(parse("example.com"))
    );
    assert_eq!(parse("example.com").parent(), Some(parse("com")));
    assert_eq!(parse("com").parent(), Some(root));
}

#[test]
fn text_and_wire_length_prechecks() {
    assert!(matches!(
        Name::from_wire(&[0_u8; 256]),
        Err(NameError::TooLong { len: 256 })
    ));
    assert!(matches!(
        Name::parse(&"a".repeat(MAX_NAME_TEXT_LEN + 1)),
        Err(NameError::TextTooLong { .. })
    ));
}

#[test]
fn length_limits() {
    let label_63 = "a".repeat(63);
    assert!(Name::parse(&label_63).is_ok());

    let label_64 = "a".repeat(64);
    assert!(matches!(
        Name::parse(&label_64),
        Err(NameError::LabelTooLong { len: 64 })
    ));

    let too_long = format!("{0}.{0}.{0}.{0}", "a".repeat(63));
    assert!(matches!(
        Name::parse(&too_long),
        Err(NameError::TooLong { .. })
    ));
}

#[test]
fn reject_bad_names() {
    assert!(matches!(Name::parse(""), Err(NameError::EmptyName)));
    assert!(matches!(Name::parse("a..b"), Err(NameError::EmptyLabel)));
    assert!(matches!(
        Name::parse("a b"),
        Err(NameError::BadCharacter { .. })
    ));
    assert!(matches!(
        Name::parse("a\\999"),
        Err(NameError::BadEscape { .. })
    ));

    let middle_wildcard = Name::parse("a.*.b").unwrap();
    assert!(middle_wildcard.validate_zone_owner().is_err());
}
