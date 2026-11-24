//! Цепочка доверия: DS → DNSKEY(KSK) → DNSKEY(ZSK) → RRSIG.

mod common;

use pulse_dns::{DnskeyData, DsData, Name, Rclass, Rdata, Rrset, Rtype, Ttl};
use pulse_dnssec::{
    Algorithm, ChainError, DsPolicy, PrivateKey, TrustAnchorSet, VerifyOptions,
    chain::validate_dnskey_rrset, ds_from_dnskey, key_tag, validate_rrset_in_chain,
};

use common::{NOW, a_rrset, dnskey_rrset, sign};

fn root_zone() -> Name {
    Name::root()
}

#[test]
fn root_ksk_to_zone_zsk_to_rrset() {
    let ksk = PrivateKey::generate(Algorithm::ED25519).unwrap();
    let zsk = PrivateKey::generate(Algorithm::ECDSAP256SHA256).unwrap();
    let zone = root_zone();

    let dnskeys = dnskey_rrset(".", &[(&ksk, 257), (&zsk, 256)]);
    let dnskeys_sig = sign(&ksk, &dnskeys, ".", 257, NOW, 86_400);
    let ksk_dnskey: DnskeyData = ksk.dnskey(257).unwrap();
    let ds = ds_from_dnskey(&zone, &ksk_dnskey, 2, DsPolicy::strict()).unwrap();

    let rrset = a_rrset("www.", &[[192, 0, 2, 80]], 300);
    let rrsig = sign(&zsk, &rrset, ".", 256, NOW, 86_400);

    let options = VerifyOptions::new(NOW);
    let validated = validate_rrset_in_chain(
        &zone,
        &dnskeys,
        &[dnskeys_sig],
        &[ds],
        &rrset,
        &[rrsig],
        &options,
        DsPolicy::strict(),
    )
    .unwrap();

    assert_eq!(validated.zone(), &zone);
    assert_eq!(validated.keys().len(), 2);
    assert_eq!(validated.ksk_tags(), &[key_tag(&ksk_dnskey)]);
}

#[test]
fn wrong_ds_is_bogus() {
    let ksk = PrivateKey::generate(Algorithm::ED25519).unwrap();
    let zone = root_zone();
    let dnskeys = dnskey_rrset(".", &[(&ksk, 257)]);
    let dnskeys_sig = sign(&ksk, &dnskeys, ".", 257, NOW, 86_400);
    let ksk_dnskey = ksk.dnskey(257).unwrap();
    let ds = ds_from_dnskey(&zone, &ksk_dnskey, 2, DsPolicy::strict()).unwrap();

    let mut wrong_digest = ds.digest().to_vec();
    wrong_digest[0] ^= 0x80;
    let wrong_ds = DsData::new(ds.key_tag(), ds.algorithm(), 2, wrong_digest).unwrap();

    let options = VerifyOptions::new(NOW);
    assert!(matches!(
        validate_dnskey_rrset(
            &zone,
            &dnskeys,
            &[dnskeys_sig],
            &[wrong_ds],
            &options,
            DsPolicy::strict(),
        ),
        Err(ChainError::NoMatchingDs)
    ));
}

#[test]
fn dnskey_rrset_must_be_signed_by_ds_matched_ksk() {
    let ksk = PrivateKey::generate(Algorithm::ED25519).unwrap();
    let zsk = PrivateKey::generate(Algorithm::ED25519).unwrap();
    let zone = root_zone();
    let dnskeys = dnskey_rrset(".", &[(&ksk, 257), (&zsk, 256)]);
    // Подпись только ZSK: DS матчит KSK, self-signature не проходит.
    let zsk_sig = sign(&zsk, &dnskeys, ".", 256, NOW, 86_400);
    let ksk_dnskey = ksk.dnskey(257).unwrap();
    let ds = ds_from_dnskey(&zone, &ksk_dnskey, 2, DsPolicy::strict()).unwrap();

    assert!(matches!(
        validate_dnskey_rrset(
            &zone,
            &dnskeys,
            &[zsk_sig],
            &[ds],
            &VerifyOptions::new(NOW),
            DsPolicy::strict(),
        ),
        Err(ChainError::DnskeyNotSelfSigned)
    ));
}

#[test]
fn rrset_signed_by_foreign_key_is_bogus() {
    let ksk = PrivateKey::generate(Algorithm::ED25519).unwrap();
    let zsk = PrivateKey::generate(Algorithm::ED25519).unwrap();
    let foreign = PrivateKey::generate(Algorithm::ED25519).unwrap();
    let zone = root_zone();
    let dnskeys = dnskey_rrset(".", &[(&ksk, 257), (&zsk, 256)]);
    let dnskeys_sig = sign(&ksk, &dnskeys, ".", 257, NOW, 86_400);
    let ds = ds_from_dnskey(&zone, &ksk.dnskey(257).unwrap(), 2, DsPolicy::strict()).unwrap();

    let rrset = a_rrset("www.", &[[192, 0, 2, 80]], 300);
    let foreign_sig = sign(&foreign, &rrset, ".", 256, NOW, 86_400);

    assert!(matches!(
        validate_rrset_in_chain(
            &zone,
            &dnskeys,
            &[dnskeys_sig],
            &[ds],
            &rrset,
            &[foreign_sig],
            &VerifyOptions::new(NOW),
            DsPolicy::strict(),
        ),
        Err(ChainError::NoValidSignature)
    ));
}

#[test]
fn builtin_trust_anchor_matches_iana_root_ksk() {
    let public_key = base64_decode(concat!(
        "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixH",
        "lFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9W",
        "Ge2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3",
        "eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHd",
        "Y6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
    ));
    let dnskey = DnskeyData::new(257, 3, 8, public_key).unwrap();
    let anchors = TrustAnchorSet::iana_root();
    let now = NOW;
    assert!(
        anchors
            .matches_dnskey(&root_zone(), &dnskey, now, DsPolicy::strict())
            .unwrap()
    );
    let ds_set = anchors.to_ds_set(now, DsPolicy::strict()).unwrap();
    assert!(ds_set.iter().any(|ds| ds.key_tag() == 20326));
}

#[test]
fn zone_mismatch_is_rejected() {
    let ksk = PrivateKey::generate(Algorithm::ED25519).unwrap();
    let zone = Name::parse("example.com").unwrap();
    let dnskeys = dnskey_rrset("other.com", &[(&ksk, 257)]);
    let sig = sign(&ksk, &dnskeys, "other.com", 257, NOW, 86_400);
    assert!(matches!(
        validate_dnskey_rrset(
            &zone,
            &dnskeys,
            &[sig],
            &[],
            &VerifyOptions::new(NOW),
            DsPolicy::strict(),
        ),
        Err(ChainError::ZoneMismatch { .. })
    ));
}

#[test]
fn dnskey_rrset_type_is_checked() {
    let key = PrivateKey::generate(Algorithm::ED25519).unwrap();
    let zone = Name::parse("example.com").unwrap();
    let not_dnskey = Rrset::new(
        zone.clone(),
        Rtype::TXT,
        Rclass::IN,
        Ttl::new(300).unwrap(),
        vec![Rdata::Txt(
            pulse_dns::TxtData::new(vec![b"x".to_vec()]).unwrap(),
        )],
    )
    .unwrap();
    assert!(matches!(
        validate_dnskey_rrset(
            &zone,
            &not_dnskey,
            &[],
            &[],
            &VerifyOptions::new(NOW),
            DsPolicy::strict(),
        ),
        Err(ChainError::NotDnskeyRrset { .. })
    ));
    // ключ нужен только для типа подписи; подавляем предупреждение.
    let _ = key;
}

fn base64_decode(value: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .unwrap()
}
