//! Ошибки разбора: синтаксис, семантика, инварианты зоны, лимиты.

use pulse_dns::{Name, TTL_MAX};
use pulse_master::{
    ErrorKind, ParseError, ParseOptions, WarningKind, parse_zone, parse_zone_with_options,
};

const HEADER: &str = "$TTL 60\n@ SOA ns hostmaster 1 1 1 10 1\n@ NS ns\n";

fn origin() -> Name {
    Name::parse("example.com.").expect("origin")
}

fn parse(text: &str) -> ParseError {
    parse_zone(origin(), text).expect_err("parse must fail")
}

fn zone_with(extra: &str) -> String {
    format!("{HEADER}{extra}")
}

#[test]
fn syntax_errors_have_location() {
    let cases = [
        ("x TXT \"unterminated\n", "unterminated quote"),
        ("x TXT ( a b\n", "unterminated group"),
        ("x TXT )\n", "stray close"),
        ("$TTL 12x\n", "bad ttl"),
        ("$BOGUS 1\n", "unknown directive"),
        ("$GENERATE 1-2 x A 192.0.2.1\n", "generate"),
        ("$INCLUDE /etc/passwd\n", "include disabled"),
    ];
    for (text, label) in cases {
        let error = parse(text);
        assert!(
            error.location.line >= 1,
            "{label}: line must be set, got {error:?}"
        );
        assert!(
            error.location.column >= 1,
            "{label}: column must be set, got {error:?}"
        );
        assert_eq!(error.location.source, "<input>", "{label}");
        assert!(!error.to_string().is_empty(), "{label}");
    }

    let error = parse("$GENERATE 1-2 x A 192.0.2.1\n");
    assert!(matches!(
        error.kind,
        ErrorKind::UnsupportedDirective(ref name) if name == "$GENERATE"
    ));
    let error = parse("$BOGUS 1\n");
    assert!(matches!(error.kind, ErrorKind::UnknownDirective(ref name) if name == "$BOGUS"));
    let error = parse("x TXT \"unterminated\n");
    assert!(matches!(error.kind, ErrorKind::UnterminatedQuote));
}

#[test]
fn ttl_errors_and_clamping() {
    let error = parse(&zone_with("x 1x A 192.0.2.1\n"));
    assert!(matches!(error.kind, ErrorKind::Ttl { .. }));

    let text = format!("{HEADER}$TTL 4294967295\nx A 192.0.2.1\n");
    let zone = parse_zone(origin(), &text).expect("clamped zone");
    assert_eq!(zone.default_ttl.map(pulse_dns::Ttl::as_u32), Some(TTL_MAX));
    assert!(zone.warnings.iter().any(|warning| matches!(
        warning.kind,
        WarningKind::TtlClamped {
            value: 4_294_967_295
        }
    )));

    // TTL больше u32 — это уже ошибка, а не clamp.
    let error = parse("$TTL 5000000000\n");
    assert!(matches!(error.kind, ErrorKind::Ttl { .. }));
}

#[test]
fn type_and_rdata_errors() {
    let error = parse(&zone_with("x FOO 1\n"));
    assert!(matches!(error.kind, ErrorKind::Type(ref name) if name == "FOO"));

    let error = parse(&zone_with("x TYPE65280 DEADBEEF\n"));
    assert!(matches!(error.kind, ErrorKind::Rdata { .. }));

    let error = parse(&zone_with("x TYPE65280 \\# 3 DEADBEEF\n"));
    assert!(matches!(
        error.kind,
        ErrorKind::Rdlength {
            declared: 3,
            actual: 4
        }
    ));

    let error = parse(&zone_with("x A 999.0.2.1\n"));
    assert!(matches!(error.kind, ErrorKind::Rdata { .. }));

    let error = parse(&zone_with("x MX notanumber mail\n"));
    assert!(matches!(
        error.kind,
        ErrorKind::Number {
            field: "preference",
            ..
        }
    ));

    let error = parse(&zone_with("x A\n"));
    assert!(matches!(error.kind, ErrorKind::Rdata { .. }));

    let error = parse(&zone_with("x A 192.0.2.1 extra\n"));
    assert!(matches!(error.kind, ErrorKind::Rdata { .. }));

    let error = parse(&zone_with("x DS 1 13 2 ABCD\n"));
    assert!(matches!(error.kind, ErrorKind::RdataValue(_)));

    let error = parse(&zone_with("x NSEC3 1 0 0 - NOTBASE32 A\n"));
    assert!(matches!(error.kind, ErrorKind::Rdata { .. }));

    let error = parse(&zone_with(
        "x RRSIG A 13 3 300 20261301000000 20260101000000 1 example.com. AA==\n",
    ));
    assert!(matches!(error.kind, ErrorKind::Timestamp { .. }));

    let long = "a".repeat(256);
    let error = parse(&zone_with(&format!("x TXT \"{long}\"\n")));
    assert!(matches!(error.kind, ErrorKind::RdataValue(_)));

    let error = parse(&zone_with("x SVCB 1 . alpn=h2 alpn=h3\n"));
    assert!(matches!(error.kind, ErrorKind::Rdata { .. }));

    let error = parse(&zone_with("x SVCB 1 . alpn=\n"));
    assert!(matches!(error.kind, ErrorKind::Rdata { .. }));

    let error = parse(&zone_with("x SVCB 1 . port=99999\n"));
    assert!(matches!(error.kind, ErrorKind::Rdata { .. }));

    let error = parse(&zone_with("x SVCB 1 . ech=\n"));
    assert!(matches!(error.kind, ErrorKind::Rdata { .. }));

    let error = parse(&zone_with("x SOA ns hostmaster 1 0 0 0 0\n"));
    assert!(matches!(error.kind, ErrorKind::Rdata { .. }));
}

#[test]
fn zone_invariants() {
    let error = parse("$TTL 60\n@ NS ns\nwww A 192.0.2.1\n");
    assert!(matches!(error.kind, ErrorKind::Validation(ref message) if message.contains("SOA")));

    let error = parse("$TTL 60\n@ SOA ns hostmaster 1 1 1 10 1\nwww A 192.0.2.1\n");
    assert!(matches!(error.kind, ErrorKind::Validation(ref message) if message.contains("NS")));

    let error = parse(&format!("{HEADER}@ SOA ns hostmaster 2 1 1 10 1\n"));
    assert!(
        matches!(error.kind, ErrorKind::Validation(ref message) if message.contains("more than one SOA"))
    );

    let error = parse("$TTL 60\nwww SOA ns hostmaster 1 1 1 10 1\n@ NS ns\n");
    assert!(matches!(error.kind, ErrorKind::Validation(ref message) if message.contains("apex")));

    let error = parse(&zone_with("@ CNAME www\n"));
    assert!(matches!(error.kind, ErrorKind::Validation(ref message) if message.contains("CNAME")));

    let error = parse(&zone_with("alias CNAME www\nalias A 192.0.2.1\n"));
    assert!(matches!(error.kind, ErrorKind::Validation(ref message) if message.contains("CNAME")));

    let error = parse(&zone_with("alias CNAME www\nalias DNAME target\n"));
    assert!(matches!(error.kind, ErrorKind::Validation(ref message) if message.contains("DNAME")));

    let error = parse(&zone_with("@ DNAME target\n"));
    assert!(matches!(error.kind, ErrorKind::Validation(ref message) if message.contains("DNAME")));

    // CNAME вместе с DNSSEC-метаданными допустим.
    let text = zone_with(
        "alias CNAME www\nalias RRSIG CNAME 13 3 60 20261231235959 20260101000000 1 example.com. AA==\n",
    );
    assert!(parse_zone(origin(), &text).is_ok());
}

#[test]
fn owner_and_class_errors() {
    let error = parse(&zone_with("other.net. A 192.0.2.1\n"));
    assert!(matches!(error.kind, ErrorKind::OutOfZone { .. }));

    let error = parse(&zone_with("a.*.example.com. A 192.0.2.1\n"));
    assert!(matches!(error.kind, ErrorKind::Name { .. }));

    let error = parse("  A 192.0.2.1\n");
    assert!(matches!(error.kind, ErrorKind::MissingOwner));

    let error = parse(&zone_with("x CH A 192.0.2.1\n"));
    assert!(matches!(error.kind, ErrorKind::UnsupportedClass(_)));

    let error = parse(&zone_with("x HS A 192.0.2.1\n"));
    assert!(matches!(error.kind, ErrorKind::UnsupportedClass(_)));

    let error = parse(&zone_with("x CLASS3 A 192.0.2.1\n"));
    assert!(matches!(error.kind, ErrorKind::UnsupportedClass(_)));

    let error = parse(&zone_with("x\n"));
    assert!(matches!(error.kind, ErrorKind::MissingType { .. }));

    let error = parse(&zone_with("x A 192.0.2.1\n  IN BOGUS\n"));
    assert!(matches!(error.kind, ErrorKind::Type(_)));
}

#[test]
fn limits_are_enforced() {
    let options = ParseOptions {
        limits: pulse_master::Limits {
            max_file_bytes: 16,
            ..pulse_master::Limits::default()
        },
        ..ParseOptions::default()
    };
    let error = parse_zone_with_options(origin(), HEADER, &options).expect_err("size limit");
    assert!(matches!(
        error.kind,
        ErrorKind::Limit {
            what: "file size",
            ..
        }
    ));

    let options = ParseOptions {
        limits: pulse_master::Limits {
            max_records: 1,
            ..pulse_master::Limits::default()
        },
        ..ParseOptions::default()
    };
    let error = parse_zone_with_options(origin(), HEADER, &options).expect_err("record limit");
    assert!(matches!(
        error.kind,
        ErrorKind::Limit {
            what: "records",
            ..
        }
    ));

    let options = ParseOptions {
        limits: pulse_master::Limits {
            max_line_tokens: 3,
            ..pulse_master::Limits::default()
        },
        ..ParseOptions::default()
    };
    let error = parse_zone_with_options(origin(), HEADER, &options).expect_err("token limit");
    assert!(matches!(
        error.kind,
        ErrorKind::Limit {
            what: "tokens in line",
            ..
        }
    ));
}

#[test]
fn fragment_mode_skips_zone_invariants() {
    let zone = pulse_master::parse_zone_fragment(origin(), "www 60 A 192.0.2.1\n")
        .expect("fragment without SOA");
    assert_eq!(zone.records.len(), 1);
    assert_eq!(zone.default_ttl, None);
}
