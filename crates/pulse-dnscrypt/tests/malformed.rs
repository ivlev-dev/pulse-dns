//! Фаззинг мусорных пакетов: библиотека не паникует и возвращает типизированные
//! ошибки. Proptest гоняет произвольные байты через все публичные декодеры.

mod common;

use common::{NOW, echo_handler, fixture};
use proptest::prelude::*;
use pulse_dnscrypt::{
    Certificate, CertificateParams, DnscryptServer, Error, ProviderKeypair, ServerConfig,
    decode_tcp_frame, unpad,
};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn arbitrary_udp_packets_never_panic(packet in proptest::collection::vec(any::<u8>(), 0..5000)) {
        let fixture = fixture();
        let result = fixture.server.handle_udp_at(&packet, NOW, &echo_handler);
        if let Err(error) = result {
            // Любая ошибка допустима, кроме паники; проверяем Display.
            prop_assert!(!error.to_string().is_empty());
        }
    }

    #[test]
    fn arbitrary_certificate_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..2000)) {
        match Certificate::parse(&bytes) {
            Ok(certificate) => {
                let roundtrip = Certificate::parse(&certificate.to_bytes()).unwrap();
                prop_assert_eq!(roundtrip, certificate);
            }
            Err(error) => prop_assert!(!error.to_string().is_empty()),
        }
    }

    #[test]
    fn arbitrary_tcp_frames_never_panic(frame in proptest::collection::vec(any::<u8>(), 0..1000)) {
        let _ = decode_tcp_frame(&frame);
    }

    #[test]
    fn arbitrary_padding_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..1000)) {
        let _ = unpad(&bytes);
    }
}

#[test]
fn malformed_certificates_are_rejected() {
    let provider = ProviderKeypair::from_seed([0xD0; 32]);
    let resolver = pulse_dnscrypt::ResolverKeypair::from_secret_bytes([0xD1; 32]);
    let mut bytes = {
        let certificate = Certificate::sign(
            &provider,
            CertificateParams::new(resolver.public_key().to_bytes(), [0x01; 8], 1, 100, 200),
        )
        .unwrap();
        certificate.to_bytes()
    };
    // Расширение произвольной длины должно разбираться и проверяться.
    bytes.extend_from_slice(&[0xAA; 300]);
    let parsed = Certificate::parse(&bytes).unwrap();
    assert_eq!(parsed.extensions(), &[0xAA; 300]);
    assert!(matches!(
        parsed.verify(&provider.public_key()),
        Err(Error::InvalidCertificateSignature)
    ));
}

#[test]
fn invalid_server_config_is_rejected() {
    let provider = ProviderKeypair::from_seed([0xE0; 32]);
    let config = ServerConfig {
        min_query_len: 100,
        ..ServerConfig::default()
    };
    assert!(matches!(
        DnscryptServer::new(provider.public_key(), config),
        Err(Error::InvalidConfig { .. })
    ));
    let config = ServerConfig {
        replay_capacity: 0,
        ..ServerConfig::default()
    };
    assert!(matches!(
        DnscryptServer::new(provider.public_key(), config),
        Err(Error::InvalidConfig { .. })
    ));
    let config = ServerConfig {
        max_tcp_packet: usize::MAX,
        ..ServerConfig::default()
    };
    assert!(matches!(
        DnscryptServer::new(provider.public_key(), config),
        Err(Error::InvalidConfig { .. })
    ));
}
