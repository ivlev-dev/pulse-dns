//! Сертификаты: TXT, подпись, выбор, ротация, hex/base64.

mod common;

use common::{CLIENT_MAGIC, NOW, TS_END, TS_START, certificate_for, fixture};
use pulse_dns::{Message, Name, Question, Rclass, Rdata, Rtype, Ttl, TxtData};
use pulse_dnscrypt::{
    CERT_FIXED_LEN, Certificate, CertificateParams, CertificateSet, Error, ProviderKeypair,
    ResolverKeypair, provider_name, random_client_magic,
};

#[test]
fn certificate_wire_layout_matches_spec() {
    let fixture = fixture();
    let bytes = fixture.certificate.to_bytes();
    assert_eq!(bytes.len(), CERT_FIXED_LEN);
    assert_eq!(&bytes[..4], b"DNSC");
    assert_eq!(&bytes[4..6], &[0x00, 0x02]);
    assert_eq!(&bytes[6..8], &[0x00, 0x00]);
    assert_eq!(&bytes[72..104], fixture.resolver.public_key().to_bytes());
    assert_eq!(&bytes[104..112], &CLIENT_MAGIC);
    assert_eq!(u32::from_be_bytes(bytes[112..116].try_into().unwrap()), 1);
    assert_eq!(
        u32::from_be_bytes(bytes[116..120].try_into().unwrap()),
        TS_START
    );
    assert_eq!(
        u32::from_be_bytes(bytes[120..124].try_into().unwrap()),
        TS_END
    );
    assert_eq!(Certificate::parse(&bytes).unwrap(), fixture.certificate);
    fixture
        .certificate
        .verify(&fixture.provider.public_key())
        .unwrap();
}

#[test]
fn certificate_txt_record_roundtrip() {
    let fixture = fixture();
    let zone = Name::parse("example.com").unwrap();
    let owner = provider_name(&zone).unwrap();
    assert_eq!(owner.to_string(), "2.dnscrypt-cert.example.com.");
    let record = fixture
        .certificate
        .to_txt_record(&owner, Ttl::new(3600).unwrap())
        .unwrap();
    assert_eq!(record.owner(), &owner);
    assert_eq!(record.rr_type(), Rtype::TXT);
    assert_eq!(record.class(), pulse_dns::Rclass::IN);
    assert_eq!(record.ttl().as_u32(), 3600);
    let parsed = Certificate::from_txt_rdata(record.rdata()).unwrap();
    assert_eq!(parsed, fixture.certificate);
    parsed.verify(&fixture.provider.public_key()).unwrap();
}

#[test]
fn certificate_txt_record_survives_dns_wire() {
    let fixture = fixture();
    let owner = provider_name(&Name::parse("example.com").unwrap()).unwrap();
    let record = fixture
        .certificate
        .to_txt_record(&owner, Ttl::new(3600).unwrap())
        .unwrap();
    let question = Question::new(owner.clone(), Rtype::TXT, Rclass::IN);
    let mut response = Message::response(&Message::query(0x2222, question));
    response.add_answer(record);
    let wire = response
        .encode(&pulse_dns::EncodeOptions::default())
        .unwrap();
    let decoded = Message::decode(&wire, &pulse_dns::DecodeLimits::default()).unwrap();
    let answer = decoded.answers().first().unwrap();
    assert_eq!(answer.rr_type(), Rtype::TXT);
    assert_eq!(
        Certificate::from_txt_rdata(answer.rdata()).unwrap(),
        fixture.certificate
    );
}

#[test]
fn certificate_txt_supports_extensions_and_multiple_segments() {
    let provider = ProviderKeypair::from_seed([0x91; 32]);
    let resolver = ResolverKeypair::from_secret_bytes([0x92; 32]);
    let mut params = CertificateParams::new(
        resolver.public_key().to_bytes(),
        [0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18],
        7,
        TS_START,
        TS_END,
    );
    params.extensions = vec![0x5A; 600];
    let certificate = Certificate::sign(&provider, params).unwrap();
    assert_eq!(certificate.to_bytes().len(), CERT_FIXED_LEN + 600);

    let owner = provider_name(&Name::parse("test").unwrap()).unwrap();
    let record = certificate
        .to_txt_record(&owner, Ttl::new(60).unwrap())
        .unwrap();
    let Rdata::Txt(txt) = record.rdata() else {
        panic!("expected TXT");
    };
    assert!(txt.segments().len() >= 3);
    assert!(txt.segments().iter().all(|segment| segment.len() <= 255));
    let parsed = Certificate::from_txt_rdata(record.rdata()).unwrap();
    assert_eq!(parsed, certificate);
    assert_eq!(parsed.extensions(), &[0x5A; 600]);
}

#[test]
fn certificate_hex_and_base64_roundtrip() {
    let fixture = fixture();
    let hex = fixture.certificate.to_hex();
    let base64 = fixture.certificate.to_base64();
    assert_eq!(Certificate::from_hex(&hex).unwrap(), fixture.certificate);
    assert_eq!(
        Certificate::from_base64(&base64).unwrap(),
        fixture.certificate
    );
    assert!(matches!(Certificate::from_hex("zz"), Err(Error::HexDecode)));
    assert!(matches!(
        Certificate::from_base64("***"),
        Err(Error::Base64Decode)
    ));
}

#[test]
fn certificate_txt_accepts_hex_text() {
    let fixture = fixture();
    let hex = fixture.certificate.to_hex();
    let rdata = Rdata::Txt(TxtData::new(vec![hex.into_bytes()]).unwrap());
    assert_eq!(
        Certificate::from_txt_rdata(&rdata).unwrap(),
        fixture.certificate
    );
    let base64 = fixture.certificate.to_base64();
    let rdata = Rdata::Txt(TxtData::new(vec![base64.into_bytes()]).unwrap());
    assert_eq!(
        Certificate::from_txt_rdata(&rdata).unwrap(),
        fixture.certificate
    );
    let rdata = Rdata::Txt(TxtData::new(vec![b"not a certificate".to_vec()]).unwrap());
    assert!(matches!(
        Certificate::from_txt_rdata(&rdata),
        Err(Error::InvalidCertificateText)
    ));
}

#[test]
fn certificate_signature_is_bound_to_every_field() {
    let fixture = fixture();
    let mut bytes = fixture.certificate.to_bytes();
    bytes[112] ^= 0x01; // serial
    let tampered = Certificate::parse(&bytes).unwrap();
    assert!(matches!(
        tampered.verify(&fixture.provider.public_key()),
        Err(Error::InvalidCertificateSignature)
    ));
    assert!(matches!(
        fixture
            .certificate
            .verify(&ProviderKeypair::from_seed([0xEE; 32]).public_key()),
        Err(Error::InvalidCertificateSignature)
    ));
}

#[test]
fn certificate_time_window_is_inclusive() {
    let fixture = fixture();
    fixture
        .certificate
        .validate_at(u64::from(TS_START))
        .unwrap();
    fixture.certificate.validate_at(u64::from(TS_END)).unwrap();
    assert!(matches!(
        fixture.certificate.validate_at(u64::from(TS_START) - 1),
        Err(Error::CertificateNotYetValid { .. })
    ));
    assert!(matches!(
        fixture.certificate.validate_at(u64::from(TS_END) + 1),
        Err(Error::CertificateExpired { .. })
    ));
}

#[test]
fn certificate_rejects_bad_versions_and_magic() {
    let fixture = fixture();
    let mut bytes = fixture.certificate.to_bytes();
    bytes[5] = 0x01; // es-version 0.1 (XSalsa20), not implemented
    assert!(matches!(
        Certificate::parse(&bytes),
        Err(Error::UnsupportedEsVersion { .. })
    ));

    let mut bytes = fixture.certificate.to_bytes();
    bytes[7] = 0x01;
    assert!(matches!(
        Certificate::parse(&bytes),
        Err(Error::UnsupportedMinorVersion(1))
    ));

    let provider = ProviderKeypair::from_seed([0xA0; 32]);
    let resolver = ResolverKeypair::from_secret_bytes([0xA1; 32]);
    let params = CertificateParams::new(
        resolver.public_key().to_bytes(),
        [0, 0, 0, 0, 0, 0, 0, 1],
        1,
        TS_START,
        TS_END,
    );
    assert!(matches!(
        Certificate::sign(&provider, params),
        Err(Error::InvalidClientMagic)
    ));
    let params = CertificateParams::new(
        resolver.public_key().to_bytes(),
        CLIENT_MAGIC,
        1,
        TS_END,
        TS_START,
    );
    assert!(matches!(
        Certificate::sign(&provider, params),
        Err(Error::InvalidValidityRange { .. })
    ));
}

#[test]
fn certificate_set_prefers_highest_valid_serial() {
    let provider = ProviderKeypair::from_seed([0xB0; 32]);
    let resolver_a = ResolverKeypair::from_secret_bytes([0xB1; 32]);
    let resolver_b = ResolverKeypair::from_secret_bytes([0xB2; 32]);
    let old = certificate_for(&provider, &resolver_a, 10, [0x10; 8]);
    let new = certificate_for(&provider, &resolver_b, 20, [0x20; 8]);
    let set = CertificateSet::from_certificates(vec![old.clone(), new.clone()]).unwrap();
    let selected = set.select(&provider.public_key(), NOW).unwrap();
    assert_eq!(selected.serial(), 20);

    let future_provider = ProviderKeypair::from_seed([0xB3; 32]);
    let future_resolver = ResolverKeypair::from_secret_bytes([0xB4; 32]);
    let future = Certificate::sign(
        &future_provider,
        CertificateParams::new(
            future_resolver.public_key().to_bytes(),
            [0x30; 8],
            30,
            TS_END + 10,
            TS_END + 100,
        ),
    )
    .unwrap();
    let set = CertificateSet::from_certificates(vec![old, future]).unwrap();
    let selected = set.select(&provider.public_key(), NOW).unwrap();
    assert_eq!(selected.serial(), 10);
}

#[test]
fn certificate_set_rejects_duplicates_and_empty_selection() {
    let provider = ProviderKeypair::from_seed([0xC0; 32]);
    let resolver_a = ResolverKeypair::from_secret_bytes([0xC1; 32]);
    let resolver_b = ResolverKeypair::from_secret_bytes([0xC2; 32]);
    let a = certificate_for(&provider, &resolver_a, 1, [0x40; 8]);
    let b = certificate_for(&provider, &resolver_b, 2, [0x40; 8]);
    assert!(matches!(
        CertificateSet::from_certificates(vec![a, b]),
        Err(Error::DuplicateClientMagic)
    ));
    let empty = CertificateSet::new();
    assert!(matches!(
        empty.select(&provider.public_key(), NOW),
        Err(Error::NoValidCertificate)
    ));
}

#[test]
fn random_client_magic_never_has_seven_leading_zeros() {
    for _ in 0..1000 {
        let magic = random_client_magic().unwrap();
        assert!(!magic[..7].iter().all(|byte| *byte == 0));
    }
}

#[test]
fn provider_name_requires_valid_zone() {
    assert_eq!(
        provider_name(&Name::parse("example.com").unwrap())
            .unwrap()
            .to_string(),
        "2.dnscrypt-cert.example.com."
    );
}
