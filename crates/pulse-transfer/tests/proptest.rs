//! Property-тесты: случайные зоны AXFR и враждебный ввод.

mod common;

use common::*;
use proptest::prelude::*;
use pulse_dns::{DecodeLimits, EncodeOptions, Message, Question, Rclass, Rtype};
use pulse_transfer::{
    AxfrClient, IxfrClient, NotifyRequest, NotifyResponse, TransferConfig, TransferLimits,
    ZoneSnapshot, append_tsig, parse_tsig,
};

fn random_zone(labels: &[String], serial: u32) -> ZoneSnapshot {
    let origin = origin();
    let mut records = vec![soa_for(&origin, serial)];
    for (index, label) in labels.iter().enumerate() {
        records.push(a_record(label, u32::try_from(index).unwrap()));
    }
    ZoneSnapshot::new(origin, records).unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn axfr_roundtrip_random_zones(
        labels in prop::collection::vec("[a-z][a-z0-9]{0,7}", 0..40),
        serial in any::<u32>(),
        message_bytes in 256_usize..2048,
        every in 1_usize..6,
    ) {
        let zone = random_zone(&labels, serial);
        let config = TransferConfig {
            message_bytes,
            tsig_every: every,
            require_tsig: false,
            ..TransferConfig::default()
        };
        let received = axfr_roundtrip(&zone, config, None).unwrap();
        prop_assert_eq!(received, zone);
    }

    #[test]
    fn arbitrary_bytes_never_panic(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = parse_tsig(&data);
        let _ = NotifyRequest::decode(&data);
        let _ = Message::decode(&data, &DecodeLimits::default());
        let mut axfr = AxfrClient::with_limits(
            MemoryStream::client(data.clone()),
            TransferLimits::default(),
        );
        let _ = axfr.transfer(&origin(), 1, None, NOW);
        let mut ixfr = IxfrClient::with_limits(
            MemoryStream::client(data.clone()),
            TransferLimits::default(),
        );
        let _ = ixfr.transfer(&origin(), &soa_for(&origin(), 1), 1, None, NOW);
        let request = NotifyRequest::new(1, origin());
        let _ = NotifyResponse::decode(&data, &request, None, None, NOW);
    }

    #[test]
    fn any_tampered_tsig_byte_is_rejected(
        index in any::<prop::sample::Index>(),
        id in any::<u16>(),
    ) {
        let key = default_key();
        let query = Message::query(id, Question::new(origin(), Rtype::A, Rclass::IN));
        let base = query.encode(&EncodeOptions::default()).unwrap();
        let record = key.sign_request(&base, id, NOW).unwrap();
        let mut wire = append_tsig(base, &record).unwrap();
        let position = index.index(wire.len());
        wire[position] ^= 0x01;
        prop_assert!(key.verify_request(&wire, NOW).is_err());
    }
}
