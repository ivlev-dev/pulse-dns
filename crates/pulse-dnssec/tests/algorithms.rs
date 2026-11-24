//! Подпись/валидация для алгоритмов 8, 13, 15; tamper-кейсы.

mod common;

use pulse_dns::{DecodeLimits, EncodeOptions, Message, Rclass, Rdata, Record, RrsigData, Rtype};
use pulse_dnssec::{
    Algorithm, AlgorithmPolicy, PrivateKey, RsaKeySize, SignOptions, VerifyError, VerifyOptions,
    sign_rrset, verify_rrset_with_dnskeys, verify_rrsig,
};

use common::{NOW, a_rrset, dnskey_of, name, rrsig_record, rrsig_with, sign, ttl};

#[test]
fn sign_verify_all_algorithms() {
    let cases = [
        (
            Algorithm::RSASHA256,
            RsaKeySize::Bits2048,
            "rsa.example.com",
        ),
        (
            Algorithm::ECDSAP256SHA256,
            RsaKeySize::Bits2048,
            "ecdsa.example.com",
        ),
        (Algorithm::ED25519, RsaKeySize::Bits2048, "ed.example.com"),
    ];

    for (algorithm, rsa_size, owner) in cases {
        let key = PrivateKey::generate_with_rsa_size(algorithm, rsa_size).unwrap();
        let dnskey = dnskey_of(&key, 256);
        let rrset = a_rrset(owner, &[[192, 0, 2, 1], [192, 0, 2, 2]], 300);
        let rrsig = sign(&key, &rrset, "example.com", 256, NOW, 86_400);

        let options = VerifyOptions::new(NOW + 100);
        verify_rrsig(&rrset, &rrsig, &dnskey, &options).unwrap();
        verify_rrset_with_dnskeys(&rrset, &rrsig, std::slice::from_ref(&dnskey), &options).unwrap();

        // Round-trip RRSIG через wire-формат пакета.
        let record = rrsig_record(owner, &rrsig, 300);
        let mut message = Message::response(&Message::query(
            0x1234,
            pulse_dns::Question::new(name(owner), Rtype::RRSIG, Rclass::IN),
        ));
        message.add_answer(record);
        let bytes = message.encode(&EncodeOptions::default()).unwrap();
        let decoded = Message::decode(&bytes, &DecodeLimits::default()).unwrap();
        let decoded_record = decoded.answers().first().unwrap();
        let Rdata::Rrsig(decoded_rrsig) = decoded_record.rdata() else {
            panic!("decoded record is not RRSIG");
        };
        assert_eq!(decoded_rrsig, &rrsig);
        verify_rrsig(&rrset, decoded_rrsig, &dnskey, &options).unwrap();
    }
}

#[test]
fn tampered_signature_is_rejected() {
    let key = PrivateKey::generate(Algorithm::ECDSAP256SHA256).unwrap();
    let dnskey = dnskey_of(&key, 256);
    let rrset = a_rrset("a.example.com", &[[192, 0, 2, 1]], 300);
    let rrsig = sign(&key, &rrset, "example.com", 256, NOW, 86_400);
    let options = VerifyOptions::new(NOW);

    let tampered = rrsig_with(&rrsig, |signature| {
        if let Some(byte) = signature.first_mut() {
            *byte ^= 0x01;
        }
    });
    assert!(matches!(
        verify_rrsig(&rrset, &tampered, &dnskey, &options),
        Err(VerifyError::Crypto)
    ));
}

#[test]
fn tampered_rrset_is_rejected() {
    let key = PrivateKey::generate(Algorithm::ED25519).unwrap();
    let dnskey = dnskey_of(&key, 256);
    let rrset = a_rrset("a.example.com", &[[192, 0, 2, 1]], 300);
    let rrsig = sign(&key, &rrset, "example.com", 256, NOW, 86_400);
    let options = VerifyOptions::new(NOW);

    let changed = a_rrset("a.example.com", &[[192, 0, 2, 99]], 300);
    assert!(matches!(
        verify_rrsig(&changed, &rrsig, &dnskey, &options),
        Err(VerifyError::Crypto)
    ));
}

#[test]
fn ttl_above_original_is_rejected() {
    let key = PrivateKey::generate(Algorithm::ED25519).unwrap();
    let dnskey = dnskey_of(&key, 256);
    let rrset = a_rrset("a.example.com", &[[192, 0, 2, 1]], 300);
    let rrsig = sign(&key, &rrset, "example.com", 256, NOW, 86_400);
    let options = VerifyOptions::new(NOW);

    let raised = a_rrset("a.example.com", &[[192, 0, 2, 1]], 301);
    assert!(matches!(
        verify_rrsig(&raised, &rrsig, &dnskey, &options),
        Err(VerifyError::OriginalTtlBelowRrsetTtl { .. })
    ));

    // TTL ниже Original TTL допустим (RRset кеширован).
    let lowered = a_rrset("a.example.com", &[[192, 0, 2, 1]], 100);
    verify_rrsig(&lowered, &rrsig, &dnskey, &options).unwrap();
}

fn rebuild(
    rrsig: &RrsigData,
    signer: pulse_dns::Name,
    key_tag: u16,
    algorithm: u8,
    labels: u8,
) -> RrsigData {
    RrsigData::new(
        rrsig.type_covered(),
        algorithm,
        labels,
        rrsig.original_ttl(),
        rrsig.signature_expiration(),
        rrsig.signature_inception(),
        key_tag,
        signer,
        rrsig.signature().to_vec(),
    )
    .unwrap()
}

#[test]
fn signer_and_key_tag_are_checked() {
    let key = PrivateKey::generate(Algorithm::ED25519).unwrap();
    let dnskey = dnskey_of(&key, 256);
    let rrset = a_rrset("a.example.com", &[[192, 0, 2, 1]], 300);
    let rrsig = sign(&key, &rrset, "example.com", 256, NOW, 86_400);
    let options = VerifyOptions::new(NOW);

    let wrong_signer = rebuild(&rrsig, name("other.net"), rrsig.key_tag(), 15, 2);
    assert!(matches!(
        verify_rrsig(&rrset, &wrong_signer, &dnskey, &options),
        Err(VerifyError::SignerNotAncestor { .. })
    ));

    let wrong_tag = rebuild(&rrsig, name("example.com"), 1, 15, 2);
    assert!(matches!(
        verify_rrsig(&rrset, &wrong_tag, &dnskey, &options),
        Err(VerifyError::KeyTagMismatch { .. })
    ));

    // Алгоритм изменён на запрещённый — политика отвергает до крипто.
    let wrong_alg = rebuild(&rrsig, name("example.com"), rrsig.key_tag(), 1, 2);
    assert!(matches!(
        verify_rrsig(&rrset, &wrong_alg, &dnskey, &options),
        Err(VerifyError::AlgorithmNotAllowed { .. })
    ));

    // SHA-1 (5) без opt-in — LegacyDisabled.
    let legacy = rebuild(&rrsig, name("example.com"), rrsig.key_tag(), 5, 2);
    assert!(matches!(
        verify_rrsig(&rrset, &legacy, &dnskey, &options),
        Err(VerifyError::LegacyDisabled { .. })
    ));
}

#[test]
fn legacy_policy_opt_in_is_still_bounded() {
    let options = VerifyOptions::new(NOW).with_policy(AlgorithmPolicy::with_legacy_sha1());
    let rrset = a_rrset("a.example.com", &[[192, 0, 2, 1]], 300);
    let rrsig = RrsigData::new(
        Rtype::A,
        5,
        2,
        300,
        NOW + 100,
        NOW - 100,
        1,
        name("example.com"),
        vec![0_u8; 128],
    )
    .unwrap();
    let key = PrivateKey::generate(Algorithm::ED25519).unwrap();
    let dnskey = dnskey_of(&key, 256);
    // Политика разрешила alg 5, но DNSKEY — alg 15: несовпадение.
    assert!(matches!(
        verify_rrsig(&rrset, &rrsig, &dnskey, &options),
        Err(VerifyError::AlgorithmMismatch { .. })
    ));
}

#[test]
fn wrong_zone_key_flags_are_rejected() {
    let key = PrivateKey::generate(Algorithm::ED25519).unwrap();
    let rrset = a_rrset("a.example.com", &[[192, 0, 2, 1]], 300);
    let rrsig = sign(&key, &rrset, "example.com", 256, NOW, 86_400);
    let options = VerifyOptions::new(NOW);
    let revoked = dnskey_of(&key, 0x0080); // без zone key bit
    assert!(matches!(
        verify_rrsig(&rrset, &rrsig, &revoked, &options),
        Err(VerifyError::DnskeyNotZoneKey { .. })
    ));
}

#[test]
fn wildcard_signature_verifies_on_expanded_owner() {
    let key = PrivateKey::generate(Algorithm::ECDSAP256SHA256).unwrap();
    let dnskey = dnskey_of(&key, 256);
    let wildcard = a_rrset("*.example.com", &[[192, 0, 2, 10]], 300);
    let rrsig = sign(&key, &wildcard, "example.com", 256, NOW, 86_400);
    assert_eq!(rrsig.labels(), 2);

    // Развёрнутое имя: owner изменён, TTL тот же.
    let expanded = a_rrset("a.b.example.com", &[[192, 0, 2, 10]], 300);
    let options = VerifyOptions::new(NOW);
    verify_rrsig(&expanded, &rrsig, &dnskey, &options).unwrap();
}

#[test]
fn weak_rsa_dnskey_is_rejected() {
    // Синтетический 1024-битный RSA DNSKEY: exponent 65537 + 128-байтный modulus.
    let mut public_key = vec![3_u8, 0x01, 0x00, 0x01];
    public_key.extend_from_slice(&[0xC1; 128]);
    let dnskey = pulse_dns::DnskeyData::new(256, 3, 8, public_key).unwrap();
    let rrset = a_rrset("a.example.com", &[[192, 0, 2, 1]], 300);
    let rrsig = RrsigData::new(
        Rtype::A,
        8,
        2,
        300,
        NOW + 100,
        NOW - 100,
        pulse_dnssec::key_tag(&dnskey),
        name("example.com"),
        vec![0_u8; 256],
    )
    .unwrap();
    assert!(matches!(
        verify_rrsig(&rrset, &rrsig, &dnskey, &VerifyOptions::new(NOW)),
        Err(VerifyError::WeakRsaKey { bits: 1024 })
    ));
}

#[test]
fn dnskeyset_helper_selects_by_tag() {
    let key = PrivateKey::generate(Algorithm::ED25519).unwrap();
    let other = PrivateKey::generate(Algorithm::ED25519).unwrap();
    let rrset = a_rrset("a.example.com", &[[192, 0, 2, 1]], 300);
    let rrsig = sign(&key, &rrset, "example.com", 256, NOW, 86_400);
    let options = VerifyOptions::new(NOW);
    let keys = [dnskey_of(&other, 256), dnskey_of(&key, 256)];
    verify_rrset_with_dnskeys(&rrset, &rrsig, &keys, &options).unwrap();

    let only_other = [dnskey_of(&other, 256)];
    assert!(matches!(
        verify_rrset_with_dnskeys(&rrset, &rrsig, &only_other, &options),
        Err(VerifyError::NoMatchingDnskey)
    ));
}

#[test]
fn signing_key_must_be_ancestor() {
    let key = PrivateKey::generate(Algorithm::ED25519).unwrap();
    let rrset = a_rrset("a.example.com", &[[192, 0, 2, 1]], 300);
    let options = SignOptions::new(name("other.net"), NOW, 86_400);
    assert!(matches!(
        sign_rrset(&key, &rrset, &options),
        Err(pulse_dnssec::SignError::SignerNotAncestor { .. })
    ));
}

#[test]
fn signing_rejects_small_original_ttl() {
    let key = PrivateKey::generate(Algorithm::ED25519).unwrap();
    let rrset = a_rrset("a.example.com", &[[192, 0, 2, 1]], 300);
    let options = SignOptions::new(name("example.com"), NOW, 86_400).with_original_ttl(299);
    assert!(matches!(
        sign_rrset(&key, &rrset, &options),
        Err(pulse_dnssec::SignError::OriginalTtlBelowRrsetTtl { .. })
    ));
}

#[test]
fn record_ttl_domain_is_untouched_by_wire_roundtrip() {
    let key = PrivateKey::generate(Algorithm::ED25519).unwrap();
    let rrsig = sign(
        &key,
        &a_rrset("a.example.com", &[[192, 0, 2, 1]], 300),
        "example.com",
        256,
        NOW,
        86_400,
    );
    let record = Record::new(
        name("a.example.com"),
        Rtype::RRSIG,
        Rclass::IN,
        ttl(300),
        Rdata::Rrsig(rrsig.clone()),
    )
    .unwrap();
    assert_eq!(record.ttl(), ttl(300));
}
