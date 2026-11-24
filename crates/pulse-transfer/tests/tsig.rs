//! Тесты TSIG.

mod common;

use common::*;
use pulse_dns::{DecodeLimits, Message, Question, Rclass, Rcode, Rtype};
use pulse_transfer::{
    TsigAlgorithm, TsigError, TsigErrorCode, TsigSignParams, TsigStreamVerifier, append_tsig,
    build_tsig_error_response, parse_tsig,
};

fn request_bytes(key: &pulse_transfer::TsigKey, id: u16, now: u64) -> Vec<u8> {
    let query = Message::query(id, Question::new(origin(), Rtype::A, Rclass::IN));
    let base = query.encode(&pulse_dns::EncodeOptions::default()).unwrap();
    let record = key.sign_request(&base, id, now).unwrap();
    append_tsig(base, &record).unwrap()
}

#[test]
fn request_roundtrip() {
    let key = default_key();
    let wire = request_bytes(&key, 0x1234, NOW);
    let verified = key.verify_request(&wire, NOW).unwrap();
    assert_eq!(verified.record().original_id(), 0x1234);
    assert_eq!(verified.record().error(), TsigErrorCode::NONE);
    assert_ne!(verified.mac().len(), 0);
}

#[test]
fn tampered_message_fails_mac() {
    let key = default_key();
    let mut wire = request_bytes(&key, 0x1234, NOW);
    *wire.get_mut(13).unwrap() ^= 0x01;
    assert!(matches!(
        key.verify_request(&wire, NOW),
        Err(TsigError::BadSig)
    ));
}

#[test]
fn wrong_key_name_fails() {
    let key = default_key();
    let other = make_key("other-key.example.com", TsigAlgorithm::HmacSha256);
    let wire = request_bytes(&key, 0x1234, NOW);
    assert!(matches!(
        other.verify_request(&wire, NOW),
        Err(TsigError::KeyNameMismatch { .. })
    ));
}

#[test]
fn wrong_algorithm_fails() {
    let key = default_key();
    let other = make_key("transfer-key.example.com", TsigAlgorithm::HmacSha512);
    let wire = request_bytes(&key, 0x1234, NOW);
    assert!(matches!(
        other.verify_request(&wire, NOW),
        Err(TsigError::AlgorithmMismatch { .. })
    ));
}

#[test]
fn time_skew_fails() {
    let key = default_key();
    let wire = request_bytes(&key, 0x1234, NOW);
    assert!(matches!(
        key.verify_request(&wire, NOW + 301),
        Err(TsigError::TimeSkew { .. })
    ));
}

#[test]
fn original_id_mismatch_fails() {
    let key = default_key();
    let query = Message::query(0x1234, Question::new(origin(), Rtype::A, Rclass::IN));
    let base = query.encode(&pulse_dns::EncodeOptions::default()).unwrap();
    let record = key.sign_request(&base, 0x9999, NOW).unwrap();
    let wire = append_tsig(base, &record).unwrap();
    assert!(matches!(
        key.verify_request(&wire, NOW),
        Err(TsigError::OriginalIdMismatch { .. })
    ));
}

#[test]
fn replay_cache_integration() {
    let key = default_key();
    let wire = request_bytes(&key, 0x1234, NOW);
    let mut cache = pulse_transfer::TsigReplayCache::default();
    key.verify_request_with_replay(&wire, NOW, &mut cache)
        .unwrap();
    assert!(matches!(
        key.verify_request_with_replay(&wire, NOW, &mut cache),
        Err(TsigError::Replay { .. })
    ));
}

#[test]
fn truncated_mac_policy() {
    let key = default_key();
    let query = Message::query(0x1234, Question::new(origin(), Rtype::A, Rclass::IN));
    let base = query.encode(&pulse_dns::EncodeOptions::default()).unwrap();
    let params = TsigSignParams {
        truncate: Some(16),
        ..TsigSignParams::new(0x1234, NOW, 300)
    };
    let record = key.sign_response_with(&base, None, &params).unwrap();
    assert_eq!(record.mac().len(), 16);
    let wire = append_tsig(base.clone(), &record).unwrap();
    key.verify_request(&wire, NOW).unwrap();

    let params = TsigSignParams {
        truncate: Some(8),
        ..TsigSignParams::new(0x1234, NOW, 300)
    };
    assert!(matches!(
        key.sign_response_with(&base, None, &params),
        Err(TsigError::InvalidTruncation { .. })
    ));
}

#[test]
fn unsigned_badkey_error_response() {
    let key = default_key();
    let query = Message::query(0x1234, Question::new(origin(), Rtype::A, Rclass::IN));
    let base = query.encode(&pulse_dns::EncodeOptions::default()).unwrap();
    let record = key.sign_request(&base, 0x1234, NOW).unwrap();
    let wire = append_tsig(base, &record).unwrap();
    let envelope = parse_tsig(&wire).unwrap().unwrap();

    let response = build_tsig_error_response(
        &query,
        Some(envelope.record()),
        Some(&key),
        None,
        TsigErrorCode::BADKEY,
        NOW,
    )
    .unwrap();
    let message = Message::decode(&response, &DecodeLimits::default()).unwrap();
    assert_eq!(message.rcode(), Rcode::NOTAUTH);
    let response_tsig = parse_tsig(&response).unwrap().unwrap();
    assert_eq!(response_tsig.record().error(), TsigErrorCode::BADKEY);
    assert!(response_tsig.is_unsigned());
}

#[test]
fn badtime_response_is_signed_and_verifiable() {
    let key = default_key();
    let old = NOW - 10_000;
    let query = Message::query(0x1234, Question::new(origin(), Rtype::A, Rclass::IN));
    let base = query.encode(&pulse_dns::EncodeOptions::default()).unwrap();
    let record = key.sign_request(&base, 0x1234, old).unwrap();
    let wire = append_tsig(base, &record).unwrap();
    let envelope = parse_tsig(&wire).unwrap().unwrap();

    let response = build_tsig_error_response(
        &query,
        Some(envelope.record()),
        Some(&key),
        Some(envelope.record().mac()),
        TsigErrorCode::BADTIME,
        NOW,
    )
    .unwrap();
    let verified = key
        .verify_response(&response, envelope.record().mac(), 0x1234, NOW)
        .unwrap();
    assert_eq!(verified.record().error(), TsigErrorCode::BADTIME);
    assert_eq!(verified.record().other_data().len(), 6);
    assert_eq!(verified.record().time_signed(), old);
}

#[test]
fn multi_message_chain() {
    let key = default_key();
    let request = request_bytes(&key, 0x1234, NOW);
    let request_tsig = parse_tsig(&request).unwrap().unwrap();
    let request_mac = request_tsig.record().mac().to_vec();
    let id = 0x1234;
    let question = Question::new(origin(), Rtype::A, Rclass::IN);

    let base1 = Message::query(id, question.clone())
        .encode(&pulse_dns::EncodeOptions::default())
        .unwrap();
    let record1 = key.sign_response(&base1, &request_mac, id, NOW).unwrap();
    let wire1 = append_tsig(base1, &record1).unwrap();
    let mac1 = record1.mac().to_vec();

    let base2 = Message::query(id, question.clone())
        .encode(&pulse_dns::EncodeOptions::default())
        .unwrap();
    let record2 = key.sign_chain(&mac1, &[&base2], id, NOW + 1, 300).unwrap();
    let wire2 = append_tsig(base2, &record2).unwrap();
    let mac2 = record2.mac().to_vec();

    let base3 = Message::query(id, question.clone())
        .encode(&pulse_dns::EncodeOptions::default())
        .unwrap();
    let base4 = Message::query(id, question.clone())
        .encode(&pulse_dns::EncodeOptions::default())
        .unwrap();
    let record4 = key
        .sign_chain(&mac2, &[&base3, &base4], id, NOW + 2, 300)
        .unwrap();
    let wire4 = append_tsig(base4, &record4).unwrap();

    let mut verifier = TsigStreamVerifier::new(&key, request_mac, id);
    verifier.verify_message(&wire1, NOW).unwrap().unwrap();
    verifier.verify_message(&wire2, NOW + 1).unwrap().unwrap();
    assert!(verifier.verify_message(&base3, NOW + 1).unwrap().is_none());
    verifier.verify_message(&wire4, NOW + 2).unwrap().unwrap();
}

#[test]
fn chain_tampering_fails() {
    let key = default_key();
    let request = request_bytes(&key, 0x1234, NOW);
    let request_tsig = parse_tsig(&request).unwrap().unwrap();
    let request_mac = request_tsig.record().mac().to_vec();
    let id = 0x1234;
    let question = Question::new(origin(), Rtype::A, Rclass::IN);

    let base1 = Message::query(id, question.clone())
        .encode(&pulse_dns::EncodeOptions::default())
        .unwrap();
    let record1 = key.sign_response(&base1, &request_mac, id, NOW).unwrap();
    let wire1 = append_tsig(base1, &record1).unwrap();
    let mac1 = record1.mac().to_vec();

    let base2 = Message::query(id, question.clone())
        .encode(&pulse_dns::EncodeOptions::default())
        .unwrap();
    let mut tampered = base2.clone();
    *tampered.get_mut(13).unwrap() ^= 0x01;
    let record2 = key.sign_chain(&mac1, &[&base2], id, NOW + 1, 300).unwrap();
    let wire2 = append_tsig(tampered, &record2).unwrap();

    let mut verifier = TsigStreamVerifier::new(&key, request_mac, id);
    verifier.verify_message(&wire1, NOW).unwrap().unwrap();
    assert!(matches!(
        verifier.verify_message(&wire2, NOW + 1),
        Err(TsigError::BadSig)
    ));
}

#[test]
fn too_many_unsigned_messages_fail() {
    let key = default_key();
    let request = request_bytes(&key, 0x1234, NOW);
    let request_tsig = parse_tsig(&request).unwrap().unwrap();
    let request_mac = request_tsig.record().mac().to_vec();
    let id = 0x1234;
    let base = Message::query(id, Question::new(origin(), Rtype::A, Rclass::IN))
        .encode(&pulse_dns::EncodeOptions::default())
        .unwrap();
    let record = key.sign_response(&base, &request_mac, id, NOW).unwrap();
    let wire = append_tsig(base.clone(), &record).unwrap();

    let mut verifier = TsigStreamVerifier::new(&key, request_mac, id);
    verifier.verify_message(&wire, NOW).unwrap().unwrap();
    for index in 0..99 {
        assert!(
            verifier
                .verify_message(&base, NOW + index)
                .unwrap()
                .is_none()
        );
    }
    assert!(matches!(
        verifier.verify_message(&base, NOW + 100),
        Err(TsigError::Malformed { .. })
    ));
}

#[test]
fn unsupported_algorithm_is_rejected() {
    let mut rdata = pulse_dns::Name::parse("hmac-sha999")
        .unwrap()
        .as_wire()
        .to_vec();
    rdata.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    rdata.extend_from_slice(&300_u16.to_be_bytes());
    rdata.extend_from_slice(&16_u16.to_be_bytes());
    rdata.extend_from_slice(&[0_u8; 16]);
    rdata.extend_from_slice(&0x1234_u16.to_be_bytes());
    rdata.extend_from_slice(&0_u16.to_be_bytes());
    rdata.extend_from_slice(&0_u16.to_be_bytes());
    let record = pulse_dns::Record::new(
        pulse_dns::Name::parse("transfer-key.example.com").unwrap(),
        pulse_dns::Rtype::TSIG,
        pulse_dns::Rclass::ANY,
        pulse_dns::Ttl::ZERO,
        pulse_dns::Rdata::unknown(pulse_dns::Rtype::TSIG, rdata).unwrap(),
    )
    .unwrap();
    let mut message = Message::query(0x1234, Question::new(origin(), Rtype::A, Rclass::IN));
    message.add_additional(record);
    let wire = message
        .encode(&pulse_dns::EncodeOptions::default())
        .unwrap();
    assert!(matches!(
        parse_tsig(&wire),
        Err(TsigError::UnsupportedAlgorithm { .. })
    ));
}
