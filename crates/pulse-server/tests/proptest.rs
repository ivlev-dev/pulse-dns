//! Property-тесты: ответ всегда корректно кодируется и соблюдает транспортные лимиты.

#![cfg(feature = "testkit")]

mod common;

use common::{edns_query, example_engine, query};
use proptest::prelude::*;
use pulse_dns::{DecodeLimits, EncodeOptions, Message, Rcode, Rtype};
use pulse_server::application::Transport;

const QTYPE_MATRIX: [Rtype; 6] = [
    Rtype::A,
    Rtype::AAAA,
    Rtype::MX,
    Rtype::TXT,
    Rtype::ANY,
    Rtype::CNAME,
];

proptest! {
    #[test]
    fn responses_roundtrip_and_fit(
        labels in proptest::collection::vec("[a-z0-9]{1,8}", 0..4),
        type_index in 0usize..QTYPE_MATRIX.len(),
        tcp in any::<bool>(),
    ) {
        let qname = if labels.is_empty() {
            "example.com".to_string()
        } else {
            format!("{}.example.com", labels.join("."))
        };
        if qname.len() > 240 {
            return Ok(());
        }
        let qtype = QTYPE_MATRIX[type_index];
        let transport = if tcp { Transport::Tcp } else { Transport::Udp };
        let request = if tcp {
            query(&qname, qtype)
        } else {
            edns_query(&qname, qtype, 1232, false)
        };
        let response = example_engine().respond(&request, transport);

        prop_assert_eq!(response.id(), request.id());
        prop_assert!(response.flags().qr());
        prop_assert!(!response.flags().ra());
        prop_assert_eq!(response.questions().len(), 1);

        let bytes = response
            .encode(&EncodeOptions::compressed())
            .expect("response encodes");
        let decoded = Message::decode(&bytes, &DecodeLimits::default())
            .expect("response decodes");
        prop_assert_eq!(&decoded, &response);

        if tcp {
            prop_assert!(!response.flags().tc());
        } else {
            prop_assert!(bytes.len() <= 1232, "udp response is {} octets", bytes.len());
        }
        prop_assert!(matches!(
            response.rcode(),
            Rcode::NOERROR | Rcode::NXDOMAIN | Rcode::REFUSED | Rcode::SERVFAIL
        ));
    }

    #[test]
    fn responses_without_edns_fit_512_or_set_tc(
        labels in proptest::collection::vec("[a-z0-9]{1,8}", 0..4),
        type_index in 0usize..QTYPE_MATRIX.len(),
    ) {
        let qname = if labels.is_empty() {
            "example.com".to_string()
        } else {
            format!("{}.example.com", labels.join("."))
        };
        if qname.len() > 240 {
            return Ok(());
        }
        let request = query(&qname, QTYPE_MATRIX[type_index]);
        let response = example_engine().respond(&request, Transport::Udp);
        let bytes = response
            .encode(&EncodeOptions::compressed())
            .expect("response encodes");
        prop_assert!(
            bytes.len() <= 512,
            "non-truncated? tc={} len={}",
            response.flags().tc(),
            bytes.len()
        );
    }
}
