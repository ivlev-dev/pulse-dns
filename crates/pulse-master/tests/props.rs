//! Property-тесты: мусор не паникует, валидный вывод сериализатора разбирается.

use std::fmt::Write as _;

use proptest::prelude::*;
use pulse_dns::{Name, Rdata};
use pulse_master::{
    ParsedZone, TextOptions, parse_zone_fragment, parse_zone_fragment_with_options, to_text,
};

fn origin() -> Name {
    Name::parse("example.com.").expect("origin")
}

fn serialize(zone: &ParsedZone) -> String {
    to_text(&zone.records, &TextOptions::default())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn arbitrary_text_never_panics_and_serializes_stably(text in "\\PC{0,512}") {
        if let Ok(zone) = parse_zone_fragment(origin(), &text) {
            let exported = serialize(&zone);
            prop_assert_eq!(exported.is_empty(), zone.records.is_empty());
            let reparsed = parse_zone_fragment(origin(), &exported);
            prop_assert!(
                reparsed.is_ok(),
                "serialized text must parse: {:?}\n{}",
                reparsed.err(),
                exported
            );
            let reparsed = reparsed.expect("checked above");
            prop_assert_eq!(reparsed.records, zone.records);
        }
    }

    #[test]
    fn arbitrary_names_and_addresses_round_trip(
        labels in prop::collection::vec("[a-z0-9]{1,12}", 1..4),
        ttl in 0_u32..86_400,
        octets in prop::array::uniform4(any::<u8>()),
    ) {
        let owner = labels.join(".");
        let address = std::net::Ipv4Addr::from(octets);
        let text = format!("{owner} {ttl} A {address}\n");
        let options = pulse_master::ParseOptions {
            validate: false,
            ..pulse_master::ParseOptions::default()
        };
        let zone = parse_zone_fragment_with_options(origin(), &text, &options)
            .expect("generated record must parse");
        prop_assert_eq!(zone.records.len(), 1);
        let record = zone.records.first().expect("one record");
        prop_assert_eq!(record.ttl().as_u32(), ttl);
        prop_assert_eq!(record.rdata(), &Rdata::A(address));
        let reparsed = parse_zone_fragment(origin(), &serialize(&zone)).expect("reparse");
        prop_assert_eq!(reparsed.records, zone.records);
    }

    #[test]
    fn arbitrary_txt_segments_round_trip(
        segments in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..40), 1..5),
    ) {
        let mut text = String::from("$TTL 60\nx TXT");
        for segment in &segments {
            text.push_str(" \"");
            for byte in segment {
                let _ = write!(text, "\\{byte:03}");
            }
            text.push('"');
        }
        text.push('\n');
        let zone = parse_zone_fragment(origin(), &text).expect("txt record");
        let record = zone.records.first().expect("one record");
        let Rdata::Txt(txt) = record.rdata() else {
            prop_assert!(false, "TXT expected");
            return Ok(());
        };
        prop_assert_eq!(txt.segments(), segments.as_slice());
        let reparsed = parse_zone_fragment(origin(), &serialize(&zone)).expect("reparse");
        prop_assert_eq!(reparsed.records, zone.records);
    }

    #[test]
    fn arbitrary_unknown_rdata_round_trip(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
        let mut hex = String::with_capacity(bytes.len() * 2);
        for byte in &bytes {
            let _ = write!(hex, "{byte:02X}");
        }
        let text = format!("$TTL 60\nx TYPE65280 \\# {} {hex}\n", bytes.len());
        let zone = parse_zone_fragment(origin(), &text).expect("unknown record");
        let record = zone.records.first().expect("one record");
        prop_assert_eq!(
            record.rdata(),
            &Rdata::Unknown {
                rr_type: pulse_dns::Rtype::from_u16(65280),
                rdata: bytes.clone(),
            }
        );
        let reparsed = parse_zone_fragment(origin(), &serialize(&zone)).expect("reparse");
        prop_assert_eq!(reparsed.records, zone.records);
    }

    #[test]
    fn svcb_alpn_with_escaped_commas_round_trips(
        protocols in prop::collection::vec("[a-z0-9,]{1,8}", 1..4),
    ) {
        let joined = protocols
            .iter()
            .map(|protocol| protocol.replace(',', "\\,"))
            .collect::<Vec<_>>()
            .join(",");
        let text = format!("$TTL 60\nx SVCB 1 . alpn=\"{joined}\"\n");
        let zone = parse_zone_fragment(origin(), &text);
        let Ok(zone) = zone else {
            // Identifier length or escape shape can be rejected; the property
            // only requires accepted inputs to round-trip.
            return Ok(());
        };
        let reparsed = parse_zone_fragment(origin(), &serialize(&zone)).expect("reparse");
        prop_assert_eq!(reparsed.records, zone.records);
    }
}
