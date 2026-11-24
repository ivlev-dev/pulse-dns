//! Тесты AXFR.

mod common;

use common::*;
use pulse_dns::{
    DecodeLimits, EncodeOptions, Flags, Message, Opcode, Question, Rclass, Rcode, Rtype,
};
use pulse_transfer::{
    AxfrClient, AxfrServer, LimitKind, TransferConfig, TransferError, TransferLimits, ZoneSnapshot,
    build_axfr_query, parse_tsig, write_message,
};

fn run_axfr(
    zone: &ZoneSnapshot,
    config: TransferConfig,
    key: Option<&pulse_transfer::TsigKey>,
) -> (Result<ZoneSnapshot, TransferError>, Vec<u8>) {
    let id = 0x4321;
    let query = {
        let base = build_axfr_query(id, &origin()).unwrap();
        match key {
            Some(key) => {
                let record = key.sign_request(&base, id, NOW).unwrap();
                pulse_transfer::append_tsig(base, &record).unwrap()
            }
            None => base,
        }
    };
    let mut framed_query = Vec::new();
    write_message(&mut framed_query, &query).unwrap();
    let mut server_stream = MemoryStream::server(framed_query);
    let server_result = AxfrServer::new(config).serve(&mut server_stream, zone, key, NOW);
    let output = server_stream.output;
    if let Err(error) = server_result {
        return (Err(error), output);
    }
    let mut client = AxfrClient::with_limits(MemoryStream::client(output.clone()), config.limits);
    (client.transfer(&origin(), id, key, NOW), output)
}

fn unsigned_config(message_bytes: usize) -> TransferConfig {
    TransferConfig {
        message_bytes,
        require_tsig: false,
        ..TransferConfig::default()
    }
}

fn response_wire(id: u16, answers: Vec<pulse_dns::Record>) -> Vec<u8> {
    let mut message = Message::new(
        id,
        Flags::new()
            .with_qr(true)
            .with_aa(true)
            .with_opcode(Opcode::QUERY),
    );
    message.add_question(Question::new(origin(), Rtype::AXFR, Rclass::IN));
    for record in answers {
        message.add_answer(record);
    }
    let body = message.encode(&EncodeOptions::default()).unwrap();
    let mut out = Vec::new();
    write_message(&mut out, &body).unwrap();
    out
}

#[test]
fn roundtrip_ten_thousand_records() {
    let zone = build_zone(42, 10_000);
    let (result, output) = run_axfr(&zone, unsigned_config(1024), None);
    let received = result.unwrap();
    assert_eq!(received, zone);
    let messages = split_messages(&output);
    assert!(messages.len() > 10);
    for (index, raw) in messages.iter().enumerate() {
        let message = Message::decode(raw, &DecodeLimits::default()).unwrap();
        assert_eq!(message.id(), 0x4321);
        assert_eq!(
            message.answers().len(),
            usize::from(message.header().answer_count())
        );
        let first = message.answers().first().unwrap();
        let last = message.answers().last().unwrap();
        if index == 0 {
            assert_eq!(first.rr_type(), Rtype::SOA);
            assert_eq!(message.questions().len(), 1);
        } else if index + 1 != messages.len() {
            assert!(
                !message
                    .answers()
                    .iter()
                    .any(|record| record.rr_type() == Rtype::SOA)
            );
        }
        if index + 1 == messages.len() {
            assert_eq!(last.rr_type(), Rtype::SOA);
            assert_eq!(last, zone.soa());
        }
    }
}

#[test]
fn roundtrip_with_tsig_every_third_message() {
    let zone = build_zone(7, 500);
    let key = default_key();
    let config = TransferConfig {
        message_bytes: 512,
        tsig_every: 3,
        require_tsig: true,
        ..TransferConfig::default()
    };
    let (result, output) = run_axfr(&zone, config, Some(&key));
    assert_eq!(result.unwrap(), zone);
    let messages = split_messages(&output);
    assert!(messages.len() > 3);
    for (index, raw) in messages.iter().enumerate() {
        let signed = parse_tsig(raw).unwrap().is_some();
        if index == 0 || index + 1 == messages.len() {
            assert!(signed, "first/last message must be signed");
        }
        if index % 3 == 0 && index + 1 != messages.len() {
            assert!(signed, "every third message must be signed");
        }
    }
}

#[test]
fn empty_zone_is_two_soa_records() {
    let zone = build_zone(1, 0);
    let (result, output) = run_axfr(&zone, unsigned_config(512), None);
    assert_eq!(result.unwrap(), zone);
    let messages = split_messages(&output);
    assert_eq!(messages.len(), 1);
    let message = Message::decode(&messages[0], &DecodeLimits::default()).unwrap();
    assert_eq!(message.answers().len(), 2);
    assert_eq!(message.answers()[0], *zone.soa());
    assert_eq!(message.answers()[1], *zone.soa());
}

#[test]
fn truncated_stream_is_rejected() {
    let zone = build_zone(1, 100);
    let (_, output) = run_axfr(&zone, unsigned_config(512), None);
    let half = output.len() / 2;
    let truncated = output[..half].to_vec();
    let mut client =
        AxfrClient::with_limits(MemoryStream::client(truncated), unsigned_config(512).limits);
    assert!(client.transfer(&origin(), 1, None, NOW).is_err());
}

#[test]
fn garbage_response_is_rejected() {
    for garbage in [
        vec![0u8, 0],
        vec![
            0u8, 12, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        ],
        vec![0u8, 4, 1, 2, 3, 4],
    ] {
        let mut client =
            AxfrClient::with_limits(MemoryStream::client(garbage), TransferLimits::default());
        assert!(client.transfer(&origin(), 1, None, NOW).is_err());
    }
}

#[test]
fn extra_soa_in_the_middle_is_rejected() {
    let soa = soa_for(&origin(), 1);
    let a = a_record("www", 1);
    let b = a_record("mail", 2);
    let wire = response_wire(9, vec![soa.clone(), a, soa, b]);
    let mut client = AxfrClient::with_limits(MemoryStream::client(wire), TransferLimits::default());
    let error = client.transfer(&origin(), 9, None, NOW).unwrap_err();
    assert!(matches!(error, TransferError::Protocol { .. }));
}

#[test]
fn response_not_starting_with_soa_is_rejected() {
    let wire = response_wire(9, vec![a_record("www", 1), soa_for(&origin(), 1)]);
    let mut client = AxfrClient::with_limits(MemoryStream::client(wire), TransferLimits::default());
    let error = client.transfer(&origin(), 9, None, NOW).unwrap_err();
    assert!(matches!(error, TransferError::Protocol { .. }));
}

#[test]
fn closing_soa_mismatch_is_rejected() {
    let wire = response_wire(
        9,
        vec![
            soa_for(&origin(), 1),
            a_record("www", 1),
            soa_for(&origin(), 2),
        ],
    );
    let mut client = AxfrClient::with_limits(MemoryStream::client(wire), TransferLimits::default());
    let error = client.transfer(&origin(), 9, None, NOW).unwrap_err();
    assert!(matches!(error, TransferError::Protocol { .. }));
}

#[test]
fn duplicate_records_are_ignored() {
    let soa = soa_for(&origin(), 1);
    let a = a_record("www", 1);
    let wire = response_wire(9, vec![soa.clone(), a.clone(), a, soa]);
    let mut client = AxfrClient::with_limits(MemoryStream::client(wire), TransferLimits::default());
    let zone = client.transfer(&origin(), 9, None, NOW).unwrap();
    assert_eq!(zone.records().len(), 1);
}

#[test]
fn record_limit_is_enforced() {
    let zone = build_zone(1, 100);
    let limits = TransferLimits {
        max_records: 10,
        ..TransferLimits::default()
    };
    let config = TransferConfig {
        limits,
        require_tsig: false,
        ..TransferConfig::default()
    };
    let (result, _) = run_axfr(&zone, config, None);
    assert!(matches!(
        result,
        Err(TransferError::Limit {
            kind: LimitKind::Records,
            ..
        })
    ));
}

#[test]
fn message_limit_is_enforced() {
    let zone = build_zone(1, 10_000);
    let limits = TransferLimits {
        max_messages: 1,
        ..TransferLimits::default()
    };
    let config = TransferConfig {
        limits,
        message_bytes: 1024,
        require_tsig: false,
        ..TransferConfig::default()
    };
    let (result, _) = run_axfr(&zone, config, None);
    assert!(matches!(
        result,
        Err(TransferError::Limit {
            kind: LimitKind::Messages,
            ..
        })
    ));
}

#[test]
fn byte_limit_is_enforced() {
    let zone = build_zone(1, 10_000);
    let limits = TransferLimits {
        max_bytes: 1024,
        ..TransferLimits::default()
    };
    let config = TransferConfig {
        limits,
        message_bytes: 512,
        require_tsig: false,
        ..TransferConfig::default()
    };
    let (result, _) = run_axfr(&zone, config, None);
    assert!(matches!(
        result,
        Err(TransferError::Limit {
            kind: LimitKind::Bytes,
            ..
        })
    ));
}

fn unsupported_algorithm_query(id: u16) -> Vec<u8> {
    let mut rdata = pulse_dns::Name::parse("hmac-sha999")
        .unwrap()
        .as_wire()
        .to_vec();
    rdata.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    rdata.extend_from_slice(&300_u16.to_be_bytes());
    rdata.extend_from_slice(&16_u16.to_be_bytes());
    rdata.extend_from_slice(&[0_u8; 16]);
    rdata.extend_from_slice(&id.to_be_bytes());
    rdata.extend_from_slice(&0_u16.to_be_bytes());
    rdata.extend_from_slice(&0_u16.to_be_bytes());
    let record = pulse_dns::Record::new(
        pulse_dns::Name::parse("transfer-key.example.com").unwrap(),
        Rtype::TSIG,
        Rclass::ANY,
        pulse_dns::Ttl::ZERO,
        pulse_dns::Rdata::unknown(Rtype::TSIG, rdata).unwrap(),
    )
    .unwrap();
    let mut message = Message::query(id, Question::new(origin(), Rtype::AXFR, Rclass::IN));
    message.add_additional(record);
    let body = message.encode(&EncodeOptions::default()).unwrap();
    let mut framed = Vec::new();
    write_message(&mut framed, &body).unwrap();
    framed
}

#[test]
fn server_rejects_unsupported_tsig_algorithm() {
    let zone = build_zone(1, 3);
    let mut stream = MemoryStream::server(unsupported_algorithm_query(1));
    let error = AxfrServer::new(TransferConfig {
        require_tsig: false,
        ..TransferConfig::default()
    })
    .serve(&mut stream, &zone, None, NOW)
    .unwrap_err();
    assert!(matches!(
        error,
        TransferError::Tsig(pulse_transfer::TsigError::UnsupportedAlgorithm { .. })
    ));
    let messages = split_messages(&stream.output);
    let response = Message::decode(&messages[0], &DecodeLimits::default()).unwrap();
    assert_eq!(response.rcode(), Rcode::NOTAUTH);
}

#[test]
fn server_rejects_unsigned_query_when_tsig_required() {
    let zone = build_zone(1, 3);
    let key = default_key();
    let query = build_axfr_query(1, &origin()).unwrap();
    let mut framed = Vec::new();
    write_message(&mut framed, &query).unwrap();
    let mut stream = MemoryStream::server(framed);
    let error = AxfrServer::new(TransferConfig::default())
        .serve(&mut stream, &zone, Some(&key), NOW)
        .unwrap_err();
    assert!(matches!(error, TransferError::Tsig(_)));
    let messages = split_messages(&stream.output);
    let response = Message::decode(&messages[0], &DecodeLimits::default()).unwrap();
    assert_eq!(response.rcode(), Rcode::NOTAUTH);
    assert_eq!(response.answers().len(), 0);
}

#[test]
fn client_surfaces_unsigned_badkey_error() {
    let zone = build_zone(1, 3);
    let server_key = default_key();
    let client_key = make_key(
        "wrong-key.example.com",
        pulse_transfer::TsigAlgorithm::HmacSha256,
    );
    let (query, _) =
        pulse_transfer::build_signed_axfr_query(1, &origin(), Some(&client_key), NOW).unwrap();
    let mut framed = Vec::new();
    write_message(&mut framed, &query).unwrap();
    let mut stream = MemoryStream::server(framed);
    assert!(
        AxfrServer::new(TransferConfig::default())
            .serve(&mut stream, &zone, Some(&server_key), NOW)
            .is_err()
    );
    let mut client = AxfrClient::with_limits(
        MemoryStream::client(stream.output),
        TransferConfig::default().limits,
    );
    let error = client
        .transfer(&origin(), 1, Some(&client_key), NOW)
        .unwrap_err();
    assert!(matches!(
        error,
        TransferError::Server {
            rcode: Rcode::NOTAUTH,
            tsig_error: Some(pulse_transfer::TsigErrorCode::BADKEY),
        }
    ));
}

#[test]
fn unsigned_is_allowed_when_not_required_even_with_key_configured() {
    let zone = build_zone(1, 3);
    let key = default_key();
    let config = TransferConfig {
        message_bytes: 512,
        require_tsig: false,
        ..TransferConfig::default()
    };
    let query = build_axfr_query(0x4321, &origin()).unwrap();
    let mut framed = Vec::new();
    write_message(&mut framed, &query).unwrap();
    let mut server_stream = MemoryStream::server(framed);
    AxfrServer::new(config)
        .serve(&mut server_stream, &zone, Some(&key), NOW)
        .unwrap();
    for raw in split_messages(&server_stream.output) {
        assert!(parse_tsig(&raw).unwrap().is_none());
    }
    let mut client =
        AxfrClient::with_limits(MemoryStream::client(server_stream.output), config.limits);
    let received = client.transfer(&origin(), 0x4321, None, NOW).unwrap();
    assert_eq!(received, zone);
}

#[test]
fn server_rejects_wrong_tsig_key() {
    let zone = build_zone(1, 3);
    let server_key = default_key();
    let client_key = make_key(
        "wrong-key.example.com",
        pulse_transfer::TsigAlgorithm::HmacSha256,
    );
    let (query, _) =
        pulse_transfer::build_signed_axfr_query(1, &origin(), Some(&client_key), NOW).unwrap();
    let mut framed = Vec::new();
    write_message(&mut framed, &query).unwrap();
    let mut stream = MemoryStream::server(framed);
    let error = AxfrServer::new(TransferConfig::default())
        .serve(&mut stream, &zone, Some(&server_key), NOW)
        .unwrap_err();
    assert!(matches!(error, TransferError::Tsig(_)));
    let messages = split_messages(&stream.output);
    let envelope = parse_tsig(&messages[0]).unwrap().unwrap();
    assert_eq!(
        envelope.record().error(),
        pulse_transfer::TsigErrorCode::BADKEY
    );
    assert!(envelope.is_unsigned());
}
