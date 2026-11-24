//! Тесты NOTIFY.

mod common;

use std::net::IpAddr;

use common::*;
use pulse_dns::{DecodeLimits, Message, Opcode, Rcode, Rtype};
use pulse_transfer::{
    NotifyIgnoreReason, NotifyOutcome, NotifyPolicy, NotifyRequest, NotifyResponse, NotifyServer,
    parse_tsig,
};

fn source() -> IpAddr {
    "192.0.2.10".parse().unwrap()
}

#[test]
fn request_roundtrip_and_shape() {
    let request = NotifyRequest::new(0x42, origin())
        .with_soa(soa_for(&origin(), 7))
        .unwrap();
    let encoded = request.encode(None, NOW).unwrap();
    assert!(encoded.request_mac.is_none());
    let (decoded, envelope) = NotifyRequest::decode(&encoded.bytes).unwrap();
    assert!(envelope.is_none());
    assert_eq!(decoded.id(), 0x42);
    assert_eq!(decoded.zone(), &origin());
    assert_eq!(decoded.serial(), Some(pulse_dns::Serial::new(7)));

    let message = Message::decode(&encoded.bytes, &DecodeLimits::default()).unwrap();
    assert_eq!(message.opcode(), Opcode::NOTIFY);
    assert!(!message.flags().qr());
    assert!(message.flags().aa());
    assert_eq!(message.questions().len(), 1);
    assert_eq!(message.questions()[0].qtype(), Rtype::SOA);
    assert_eq!(message.answers().len(), 1);
}

#[test]
fn unsigned_response_roundtrip() {
    let request = NotifyRequest::new(0x42, origin());
    let response = NotifyResponse::new(request.id(), Rcode::NOERROR);
    let wire = response.encode(&request, None, None, NOW).unwrap();
    let (decoded, envelope) = NotifyResponse::decode(&wire, &request, None, None, NOW).unwrap();
    assert!(envelope.is_none());
    assert_eq!(decoded.id(), 0x42);
    assert_eq!(decoded.rcode(), Rcode::NOERROR);
}

#[test]
fn policy_refuses_unknown_zone() {
    let server = NotifyServer::new(
        NotifyPolicy::new(
            vec![source()],
            vec![pulse_dns::Name::parse("other.test").unwrap()],
        ),
        None,
    )
    .require_tsig(false);
    let request = NotifyRequest::new(1, origin());
    let encoded = request.encode(None, NOW).unwrap();
    let outcome = server.handle(&encoded.bytes, source(), NOW).unwrap();
    let NotifyOutcome::Refused { response } = outcome else {
        panic!("expected refusal");
    };
    let (decoded, _) = NotifyResponse::decode(&response, &request, None, None, NOW).unwrap();
    assert_eq!(decoded.rcode(), Rcode::REFUSED);
}

#[test]
fn unknown_source_is_ignored() {
    let server = NotifyServer::new(
        NotifyPolicy::new(vec!["198.51.100.1".parse().unwrap()], vec![origin()]),
        None,
    )
    .require_tsig(false);
    let request = NotifyRequest::new(1, origin());
    let encoded = request.encode(None, NOW).unwrap();
    let outcome = server.handle(&encoded.bytes, source(), NOW).unwrap();
    assert!(matches!(
        outcome,
        NotifyOutcome::Ignored {
            reason: NotifyIgnoreReason::SourceNotAllowed
        }
    ));
}

#[test]
fn tsig_request_and_response() {
    let key = default_key();
    let server = NotifyServer::new(
        NotifyPolicy::new(vec![source()], vec![origin()]),
        Some(default_key()),
    );
    let request = NotifyRequest::new(9, origin());
    let encoded = request.encode(Some(&key), NOW).unwrap();
    let request_mac = encoded.request_mac.clone().unwrap();
    let outcome = server.handle(&encoded.bytes, source(), NOW).unwrap();
    let NotifyOutcome::Accepted { response, .. } = outcome else {
        panic!("expected acceptance");
    };
    let (decoded, envelope) =
        NotifyResponse::decode(&response, &request, Some(&request_mac), Some(&key), NOW).unwrap();
    assert_eq!(decoded.rcode(), Rcode::NOERROR);
    assert!(envelope.is_some());
}

#[test]
fn missing_tsig_is_refused() {
    let key = default_key();
    let server = NotifyServer::new(NotifyPolicy::new(vec![source()], vec![origin()]), Some(key));
    let request = NotifyRequest::new(1, origin());
    let encoded = request.encode(None, NOW).unwrap();
    let outcome = server.handle(&encoded.bytes, source(), NOW).unwrap();
    let NotifyOutcome::Refused { response } = outcome else {
        panic!("expected refusal");
    };
    let message = Message::decode(&response, &DecodeLimits::default()).unwrap();
    assert_eq!(message.rcode(), Rcode::NOTAUTH);
}

#[test]
fn wrong_tsig_key_is_refused() {
    let server_key = default_key();
    let client_key = make_key(
        "other-notify.example.com",
        pulse_transfer::TsigAlgorithm::HmacSha256,
    );
    let server = NotifyServer::new(
        NotifyPolicy::new(vec![source()], vec![origin()]),
        Some(server_key),
    );
    let request = NotifyRequest::new(1, origin());
    let encoded = request.encode(Some(&client_key), NOW).unwrap();
    let outcome = server.handle(&encoded.bytes, source(), NOW).unwrap();
    let NotifyOutcome::Refused { response } = outcome else {
        panic!("expected refusal");
    };
    let envelope = parse_tsig(&response).unwrap().unwrap();
    assert_eq!(
        envelope.record().error(),
        pulse_transfer::TsigErrorCode::BADKEY
    );
}

#[test]
fn malformed_notify_is_rejected() {
    let mut message = Message::new(
        1,
        pulse_dns::Flags::new()
            .with_opcode(Opcode::NOTIFY)
            .with_aa(true),
    );
    message.add_question(pulse_dns::Question::new(
        origin(),
        Rtype::A,
        pulse_dns::Rclass::IN,
    ));
    let wire = message
        .encode(&pulse_dns::EncodeOptions::default())
        .unwrap();
    assert!(NotifyRequest::decode(&wire).is_err());
}

#[test]
fn response_id_mismatch_is_rejected() {
    let request = NotifyRequest::new(1, origin());
    let response = NotifyResponse::new(2, Rcode::NOERROR);
    let wire = response.encode(&request, None, None, NOW).unwrap();
    assert!(NotifyResponse::decode(&wire, &request, None, None, NOW).is_err());
}
