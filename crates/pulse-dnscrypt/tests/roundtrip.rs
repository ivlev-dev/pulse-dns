//! Round-trip клиент ↔ сервер, padding, anti-replay, TC и границы.

mod common;

use std::net::Ipv4Addr;
use std::sync::Arc;

use common::{
    CLIENT_MAGIC, Fixture, NOW, TS_END, certificate_for, dns_query, echo_handler, fixture,
};
use pulse_dns::{
    DecodeLimits, EncodeOptions, Message, Name, Question, Rclass, Rdata, Record, Rtype, Ttl,
};
use pulse_dnscrypt::{
    Certificate, DnscryptClient, DnscryptServer, Error, ManualClock, ProviderKeypair,
    ResolverKeypair, ServerConfig, Transport, decode_tcp_frame, encode_tcp_frame, pad_to_len,
    response_padded_len, round_up_block, tcp_pad_len, udp_query_padded_len, unpad,
};

fn build_large_response() -> Vec<u8> {
    let question = Question::new(Name::parse("example.com").unwrap(), Rtype::A, Rclass::IN);
    let request = Message::query(0x1234, question);
    let mut response = Message::response(&request);
    let ttl = Ttl::new(60).unwrap();
    for index in 0..80_u8 {
        let record = Record::new(
            Name::parse("example.com").unwrap(),
            Rtype::A,
            Rclass::IN,
            ttl,
            Rdata::A(Ipv4Addr::new(192, 0, 2, index)),
        )
        .unwrap();
        response.add_answer(record);
    }
    response.encode(&EncodeOptions::default()).unwrap()
}

#[test]
fn udp_roundtrip_echoes_query() {
    let fixture = fixture();
    let query = dns_query();
    let pending = fixture.client.build_query(&query, Transport::Udp).unwrap();
    assert!(pending.packet().len() >= 324);
    let response = fixture
        .server
        .handle_udp_at(pending.packet(), NOW, &echo_handler)
        .unwrap();
    let plaintext = fixture
        .client
        .decrypt_response(&pending, &response)
        .unwrap();
    assert_eq!(plaintext, query);
}

#[test]
fn tcp_roundtrip_is_length_prefixed() {
    let fixture = fixture();
    let query = dns_query();
    let pending = fixture.client.build_query(&query, Transport::Tcp).unwrap();
    let frame = pending.packet();
    let inner = decode_tcp_frame(frame).unwrap();
    assert_eq!(inner.len() + 2, frame.len());
    assert_eq!(
        (inner.len() - pulse_dnscrypt::QUERY_PACKET_OVERHEAD) % 64,
        0,
        "TCP query plaintext is block aligned"
    );

    let response_frame = fixture
        .server
        .handle_tcp_at(inner, NOW, &echo_handler)
        .unwrap();
    assert_eq!(
        response_frame.len(),
        usize::from(u16::from_be_bytes([response_frame[0], response_frame[1]])) + 2
    );
    let plaintext = fixture
        .client
        .decrypt_response(&pending, &response_frame)
        .unwrap();
    assert_eq!(plaintext, query);
}

#[test]
fn tcp_frame_helpers_roundtrip() {
    let payload = vec![0x5A; 1000];
    let frame = encode_tcp_frame(&payload).unwrap();
    assert_eq!(decode_tcp_frame(&frame).unwrap(), payload.as_slice());
    assert!(matches!(
        decode_tcp_frame(&[0x00]),
        Err(Error::InvalidTcpFrame)
    ));
    assert!(matches!(
        decode_tcp_frame(&[0x00, 0x10, 0x00]),
        Err(Error::InvalidTcpFrame)
    ));
    assert!(matches!(
        encode_tcp_frame(&vec![0; 70_000]),
        Err(Error::PacketTooLong { .. })
    ));
}

#[test]
fn replayed_nonce_is_rejected() {
    let fixture = fixture();
    let query = dns_query();
    let nonce = [0x42; 12];
    let pending = fixture
        .client
        .build_query_with_nonce(&query, Transport::Udp, nonce)
        .unwrap();
    let first = fixture
        .server
        .handle_udp_at(pending.packet(), NOW, &echo_handler)
        .unwrap();
    assert_ne!(first.as_slice(), b"" as &[u8]);
    let second = fixture
        .server
        .handle_udp_at(pending.packet(), NOW, &echo_handler);
    assert!(matches!(second, Err(Error::ReplayedNonce)));
}

#[test]
fn replay_entry_expires_with_ttl() {
    let provider = ProviderKeypair::from_seed([0x31; 32]);
    let resolver = ResolverKeypair::from_secret_bytes([0x32; 32]);
    let certificate = certificate_for(&provider, &resolver, 1, CLIENT_MAGIC);
    let clock = Arc::new(ManualClock::new(NOW));
    let config = ServerConfig {
        replay_ttl_secs: 10,
        ..ServerConfig::default()
    };
    let mut server =
        DnscryptServer::with_clock(provider.public_key(), config, clock.clone()).unwrap();
    server
        .add_certificate(certificate.clone(), resolver)
        .unwrap();
    let client = DnscryptClient::new(certificate, provider.public_key(), NOW).unwrap();
    let pending = client
        .build_query_with_nonce(&dns_query(), Transport::Udp, [7; 12])
        .unwrap();

    server.handle_udp(pending.packet(), &echo_handler).unwrap();
    assert!(matches!(
        server.handle_udp(pending.packet(), &echo_handler),
        Err(Error::ReplayedNonce)
    ));
    clock.advance(11);
    server
        .handle_udp(pending.packet(), &echo_handler)
        .expect("expired entry is accepted again");
}

#[test]
fn replay_protection_can_be_disabled_for_strict_spec_mode() {
    let provider = ProviderKeypair::from_seed([0x35; 32]);
    let resolver = ResolverKeypair::from_secret_bytes([0x36; 32]);
    let certificate = certificate_for(&provider, &resolver, 1, CLIENT_MAGIC);
    let config = ServerConfig {
        replay_protection: false,
        replay_ttl_secs: 0,
        replay_capacity: 0,
        ..ServerConfig::default()
    };
    let mut server = DnscryptServer::new(provider.public_key(), config).unwrap();
    server
        .add_certificate(certificate.clone(), resolver)
        .unwrap();
    let client = DnscryptClient::new(certificate, provider.public_key(), NOW).unwrap();
    let pending = client
        .build_query_with_nonce(&dns_query(), Transport::Udp, [9; 12])
        .unwrap();
    server
        .handle_udp_at(pending.packet(), NOW, &echo_handler)
        .unwrap();
    server
        .handle_udp_at(pending.packet(), NOW, &echo_handler)
        .expect("replay protection is disabled");
}

#[test]
fn different_resolver_key_fails_authentication() {
    let client_fixture = fixture();
    let query = dns_query();
    let pending = client_fixture
        .client
        .build_query(&query, Transport::Udp)
        .unwrap();

    let provider = ProviderKeypair::from_seed([0x41; 32]);
    let other_resolver = ResolverKeypair::from_secret_bytes([0x42; 32]);
    let other_cert = certificate_for(&provider, &other_resolver, 1, CLIENT_MAGIC);
    let mut other_server =
        DnscryptServer::new(provider.public_key(), ServerConfig::default()).unwrap();
    other_server
        .add_certificate(other_cert, other_resolver)
        .unwrap();

    let result = other_server.handle_udp_at(pending.packet(), NOW, &echo_handler);
    assert!(matches!(result, Err(Error::DecryptionFailed)));
}

#[test]
fn tampered_ciphertext_fails_authentication() {
    let fixture = fixture();
    let pending = fixture
        .client
        .build_query(&dns_query(), Transport::Udp)
        .unwrap();
    let mut packet = pending.packet().to_vec();
    let last = packet.len() - 1;
    packet[last] ^= 0x01;
    assert!(matches!(
        fixture.server.handle_udp_at(&packet, NOW, &echo_handler),
        Err(Error::DecryptionFailed)
    ));
}

#[test]
fn truncated_and_oversized_packets_are_errors() {
    let fixture = fixture();
    assert!(matches!(
        fixture.server.handle_udp_at(&[], NOW, &echo_handler),
        Err(Error::PacketTooShort { .. })
    ));
    let oversized = vec![0_u8; ServerConfig::default().max_udp_packet + 1];
    assert!(matches!(
        fixture.server.handle_udp_at(&oversized, NOW, &echo_handler),
        Err(Error::PacketTooLong { .. })
    ));
    assert!(matches!(
        fixture.client.decrypt_response(
            &fixture
                .client
                .build_query(&dns_query(), Transport::Udp)
                .unwrap(),
            &[0_u8; 4]
        ),
        Err(Error::PacketTooShort { .. })
    ));
}

#[test]
fn expired_certificate_rejects_query() {
    let fixture = fixture();
    let pending = fixture
        .client
        .build_query(&dns_query(), Transport::Udp)
        .unwrap();
    let result =
        fixture
            .server
            .handle_udp_at(pending.packet(), u64::from(TS_END) + 1, &echo_handler);
    assert!(matches!(result, Err(Error::CertificateExpired { .. })));
}

#[test]
fn expired_certificate_is_rejected_by_client() {
    let provider = ProviderKeypair::from_seed([0x51; 32]);
    let resolver = ResolverKeypair::from_secret_bytes([0x52; 32]);
    let certificate = certificate_for(&provider, &resolver, 1, CLIENT_MAGIC);
    assert!(matches!(
        DnscryptClient::new(certificate, provider.public_key(), u64::from(TS_END) + 1),
        Err(Error::CertificateExpired { .. })
    ));
}

#[test]
fn large_udp_response_is_truncated_with_tc() {
    let fixture = fixture();
    let query = dns_query();
    let pending = fixture.client.build_query(&query, Transport::Udp).unwrap();
    let large = build_large_response();
    let response = fixture
        .server
        .handle_udp_at(pending.packet(), NOW, &|_: &[u8]| {
            Ok::<_, std::io::Error>(large.clone())
        })
        .unwrap();
    assert!(
        response.len() <= pending.packet().len(),
        "response {} <= query {}",
        response.len(),
        pending.packet().len()
    );
    let plaintext = fixture
        .client
        .decrypt_response(&pending, &response)
        .unwrap();
    let message = Message::decode(&plaintext, &DecodeLimits::default()).unwrap();
    assert!(message.flags().tc());
    assert_eq!(message.answers(), &[] as &[pulse_dns::Record]);
    assert_eq!(
        message.questions(),
        Message::decode(&query, &DecodeLimits::default())
            .unwrap()
            .questions()
    );
}

#[test]
fn large_tcp_response_is_not_truncated() {
    let fixture = fixture();
    let pending = fixture
        .client
        .build_query(&dns_query(), Transport::Tcp)
        .unwrap();
    let large = build_large_response();
    let frame = fixture
        .server
        .handle_tcp_at(
            decode_tcp_frame(pending.packet()).unwrap(),
            NOW,
            &|_: &[u8]| Ok::<_, std::io::Error>(large.clone()),
        )
        .unwrap();
    let plaintext = fixture.client.decrypt_response(&pending, &frame).unwrap();
    assert_eq!(plaintext, large);
}

#[test]
fn empty_handler_response_is_rejected() {
    let fixture = fixture();
    let pending = fixture
        .client
        .build_query(&dns_query(), Transport::Udp)
        .unwrap();
    assert!(matches!(
        fixture
            .server
            .handle_udp_at(pending.packet(), NOW, &|_: &[u8]| {
                Ok::<_, std::io::Error>(Vec::new())
            }),
        Err(Error::EmptyResponse)
    ));
}

#[test]
fn handler_error_is_wrapped() {
    let fixture = fixture();
    let pending = fixture
        .client
        .build_query(&dns_query(), Transport::Udp)
        .unwrap();
    let result = fixture
        .server
        .handle_udp_at(pending.packet(), NOW, &|_: &[u8]| {
            Err::<Vec<u8>, _>(std::io::Error::other("boom"))
        });
    assert!(matches!(result, Err(Error::Handler(_))));
}

#[test]
fn padding_zero_and_max_boundaries() {
    let padded = pad_to_len(&[], 1).unwrap();
    assert_eq!(padded, vec![0x80]);
    assert_eq!(unpad(&padded).unwrap(), b"");

    let data = vec![0xAA; 200];
    let padded = pad_to_len(&data, 256).unwrap();
    assert_eq!(padded.len(), 256);
    assert_eq!(unpad(&padded).unwrap(), data.as_slice());

    let max_pad = pad_to_len(&[0x01], 257).unwrap();
    assert_eq!(max_pad.len(), 257);
    assert_eq!(unpad(&max_pad).unwrap(), &[0x01]);

    assert!(matches!(
        pad_to_len(&[0x01], 258),
        Err(Error::InvalidPadding)
    ));
    assert!(matches!(pad_to_len(&[0x01], 1), Err(Error::InvalidPadding)));
    assert!(matches!(unpad(&[]), Err(Error::InvalidPadding)));
    assert!(matches!(unpad(&[0, 0, 0]), Err(Error::InvalidPadding)));
    assert!(matches!(unpad(&[0x01, 0x00]), Err(Error::InvalidPadding)));
}

#[test]
fn response_padding_is_deterministic_and_block_aligned() {
    let nonce = [0x13, 0x37, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut previous = None;
    for len in 0..1500_usize {
        let target = response_padded_len(len, &nonce).unwrap();
        assert_eq!(target % 64, 0);
        let pad = target - len;
        assert!((1..=256).contains(&pad), "len {len} pad {pad}");
        if let Some((last_len, last_target)) = previous
            && last_len == len
        {
            assert_eq!(last_target, target);
        }
        previous = Some((len, target));
        assert_eq!(target, response_padded_len(len, &nonce).unwrap());
    }
}

#[test]
fn query_padding_helpers_respect_limits() {
    assert_eq!(udp_query_padded_len(12, 256, 2048).unwrap(), 256);
    assert_eq!(udp_query_padded_len(200, 256, 2048).unwrap(), 256);
    assert_eq!(udp_query_padded_len(300, 256, 2048).unwrap(), 320);
    assert!(matches!(
        udp_query_padded_len(12, 256, 128),
        Err(Error::InvalidPadding)
    ));
    for len in 0..600_usize {
        for selector in 0..=255_u8 {
            let pad = tcp_pad_len(len, selector);
            assert!((1..=256).contains(&pad));
            assert_eq!((len + pad) % 64, 0);
        }
    }
    assert_eq!(round_up_block(0), 0);
    assert_eq!(round_up_block(1), 64);
    assert_eq!(round_up_block(64), 64);
    assert_eq!(round_up_block(65), 128);
}

#[test]
fn certificate_rotation_accepts_old_and_new_magic() {
    let provider = ProviderKeypair::from_seed([0x61; 32]);
    let old_resolver = ResolverKeypair::from_secret_bytes([0x62; 32]);
    let new_resolver = ResolverKeypair::from_secret_bytes([0x63; 32]);
    let old_cert = certificate_for(&provider, &old_resolver, 1, [0x11; 8]);
    let new_cert = certificate_for(&provider, &new_resolver, 2, [0x22; 8]);

    let mut server = DnscryptServer::new(provider.public_key(), ServerConfig::default()).unwrap();
    server
        .add_certificate(old_cert.clone(), old_resolver)
        .unwrap();
    server
        .add_certificate(new_cert.clone(), new_resolver)
        .unwrap();

    let old_client = DnscryptClient::new(old_cert, provider.public_key(), NOW).unwrap();
    let new_client = DnscryptClient::new(new_cert, provider.public_key(), NOW).unwrap();
    for client in [&old_client, &new_client] {
        let pending = client.build_query(&dns_query(), Transport::Udp).unwrap();
        server
            .handle_udp_at(pending.packet(), NOW, &echo_handler)
            .unwrap();
    }
}

#[test]
fn duplicate_client_magic_is_rejected() {
    let provider = ProviderKeypair::from_seed([0x71; 32]);
    let resolver_a = ResolverKeypair::from_secret_bytes([0x72; 32]);
    let resolver_b = ResolverKeypair::from_secret_bytes([0x73; 32]);
    let cert_a = certificate_for(&provider, &resolver_a, 1, [0x33; 8]);
    let cert_b = certificate_for(&provider, &resolver_b, 2, [0x33; 8]);
    let mut server = DnscryptServer::new(provider.public_key(), ServerConfig::default()).unwrap();
    server.add_certificate(cert_a, resolver_a).unwrap();
    assert!(matches!(
        server.add_certificate(cert_b, resolver_b),
        Err(Error::DuplicateClientMagic)
    ));
}

#[test]
fn resolver_key_must_match_certificate() {
    let provider = ProviderKeypair::from_seed([0x81; 32]);
    let resolver = ResolverKeypair::from_secret_bytes([0x82; 32]);
    let other = ResolverKeypair::from_secret_bytes([0x83; 32]);
    let cert = certificate_for(&provider, &resolver, 1, [0x44; 8]);
    let mut server = DnscryptServer::new(provider.public_key(), ServerConfig::default()).unwrap();
    assert!(matches!(
        server.add_certificate(cert, other),
        Err(Error::ResolverKeyMismatch)
    ));
}

#[test]
fn debug_output_redacts_secrets() {
    let fixture: Fixture = fixture();
    let provider = format!("{:?}", fixture.provider);
    assert!(provider.contains("REDACTED"));
    assert!(!provider.contains("1111"));
    let resolver = format!("{:?}", fixture.resolver);
    assert!(resolver.contains("REDACTED"));
    assert!(!resolver.contains("2222"));
    let _ = (fixture.certificate, CLIENT_MAGIC);
}

#[test]
fn cert_parse_rejects_short_and_bad_magic() {
    assert!(matches!(
        Certificate::parse(&[0_u8; 10]),
        Err(Error::CertificateTooShort { .. })
    ));
    let mut bytes = fixture().certificate.to_bytes();
    bytes[0] = b'X';
    assert!(matches!(
        Certificate::parse(&bytes),
        Err(Error::CertificateMagicMismatch)
    ));
}
