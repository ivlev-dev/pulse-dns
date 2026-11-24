//! Property-тесты: случайные RRset/ключи sign→verify; мусорные RRSIG → Err.

mod common;

use proptest::prelude::*;
use pulse_dns::{Name, Rclass, Rdata, Rrset, RrsigData, Rtype, Ttl};
use pulse_dnssec::{
    Algorithm, PrivateKey, SignOptions, VerifyError, VerifyOptions, key_tag, sign_rrset,
    verify_rrsig,
};

fn label_strategy() -> impl Strategy<Value = String> {
    "[a-z0-9]{1,8}"
}

fn owner_strategy() -> impl Strategy<Value = Name> {
    proptest::collection::vec(label_strategy(), 1..4)
        .prop_map(|labels| Name::parse(&labels.join(".")).unwrap())
}

fn rrset_strategy() -> impl Strategy<Value = (Rrset, Name)> {
    (
        owner_strategy(),
        proptest::collection::vec(any::<[u8; 4]>(), 1..5),
        0_u32..86_400,
    )
        .prop_map(|(owner, addresses, ttl_seconds)| {
            let rdatas: Vec<Rdata> = addresses
                .into_iter()
                .map(|address| Rdata::A(std::net::Ipv4Addr::from(address)))
                .collect();
            let rrset = Rrset::new(
                owner.clone(),
                Rtype::A,
                Rclass::IN,
                Ttl::new(ttl_seconds).unwrap(),
                rdatas,
            )
            .unwrap();
            (rrset, owner)
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn sign_then_verify_roundtrip((rrset, owner) in rrset_strategy(), now in 0_u32..4_000_000_000) {
        let key = PrivateKey::generate(Algorithm::ED25519).unwrap();
        let dnskey = key.dnskey(256).unwrap();
        let signer = Name::root();
        let options = SignOptions::new(signer, now, 3600).with_skew(120);
        let rrsig = sign_rrset(&key, &rrset, &options).unwrap();
        prop_assert_eq!(rrsig.type_covered(), Rtype::A);
        prop_assert_eq!(rrsig.key_tag(), key_tag(&dnskey));
        prop_assert_eq!(rrsig.labels() as usize, owner.label_count());
        verify_rrsig(&rrset, &rrsig, &dnskey, &VerifyOptions::new(now)).unwrap();
    }

    #[test]
    fn mutated_rrset_fails(
        (rrset, _owner) in rrset_strategy(),
        extra in any::<[u8; 4]>(),
        now in 0_u32..4_000_000_000,
    ) {
        let key = PrivateKey::generate(Algorithm::ED25519).unwrap();
        let dnskey = key.dnskey(256).unwrap();
        let signer = Name::root();
        let rrsig = sign_rrset(
            &key,
            &rrset,
            &SignOptions::new(signer, now, 3600),
        )
        .unwrap();

        let mut rdatas: Vec<Rdata> = rrset.rdatas().iter().cloned().collect();
        rdatas.push(Rdata::A(std::net::Ipv4Addr::from(extra)));
        let mutated = Rrset::new(
            rrset.owner().clone(),
            rrset.rr_type(),
            rrset.class(),
            rrset.ttl(),
            rdatas,
        ).unwrap();
        if mutated != rrset {
            prop_assert!(verify_rrsig(&mutated, &rrsig, &dnskey, &VerifyOptions::new(now)).is_err());
        }
    }

    #[test]
    fn garbage_signature_returns_error(
        (rrset, _owner) in rrset_strategy(),
        signature in proptest::collection::vec(any::<u8>(), 1..200),
        now in 0_u32..4_000_000_000,
    ) {
        let key = PrivateKey::generate(Algorithm::ED25519).unwrap();
        let dnskey = key.dnskey(256).unwrap();
        let rrsig = RrsigData::new(
            Rtype::A,
            15,
            u8::try_from(rrset.owner().label_count()).unwrap(),
            rrset.ttl().as_u32(),
            now.wrapping_add(3600),
            now.wrapping_sub(60),
            key_tag(&dnskey),
            Name::root(),
            signature,
        ).unwrap();
        let result = verify_rrsig(&rrset, &rrsig, &dnskey, &VerifyOptions::new(now));
        let expected_error = matches!(
            result,
            Err(VerifyError::Crypto | VerifyError::BadSignatureLength { .. })
        );
        prop_assert!(expected_error);
    }

    #[test]
    fn arbitrary_bytes_signature_never_panics(
        (rrset, _owner) in rrset_strategy(),
        garbage in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let key = PrivateKey::generate(Algorithm::ECDSAP256SHA256).unwrap();
        let dnskey = key.dnskey(256).unwrap();
        let result = RrsigData::new(
            Rtype::A,
            13,
            u8::try_from(rrset.owner().label_count()).unwrap(),
            rrset.ttl().as_u32(),
            1,
            0,
            0,
            Name::root(),
            garbage,
        );
        // Пустая подпись отвергается конструктором, остальные — валидатором.
        if let Ok(rrsig) = result {
            let _ = verify_rrsig(&rrset, &rrsig, &dnskey, &VerifyOptions::new(1_000));
        }
    }
}
