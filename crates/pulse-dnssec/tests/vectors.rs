//! Известные векторы: root KSK, DS, key tag, NSEC3 hash.

use pulse_dns::{DnskeyData, Name, Nsec3ParamData};
use pulse_dnssec::denial::{Nsec3Params, base32hex};
use pulse_dnssec::{DenialLimits, DsPolicy, ds_from_dnskey, ds_matches, key_tag};

const ROOT_KSK_20326: &str = "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=";
const ROOT_KSK_38696: &str = "AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=";

fn decode_base64(value: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .unwrap()
}

fn root_dnskey(public_key: &str) -> DnskeyData {
    DnskeyData::new(257, 3, 8, decode_base64(public_key)).unwrap()
}

#[test]
fn iana_root_ksk_key_tags_and_ds_match() {
    let root = Name::root();
    let cases = [
        (
            root_dnskey(ROOT_KSK_20326),
            20326_u16,
            "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
        ),
        (
            root_dnskey(ROOT_KSK_38696),
            38696_u16,
            "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
        ),
    ];
    for (dnskey, expected_tag, expected_digest) in cases {
        assert_eq!(key_tag(&dnskey), expected_tag);
        let ds = ds_from_dnskey(&root, &dnskey, 2, DsPolicy::strict()).unwrap();
        assert_eq!(ds.key_tag(), expected_tag);
        assert_eq!(ds.algorithm(), 8);
        assert_eq!(hex::encode_upper(ds.digest()), expected_digest);
        assert!(ds_matches(&root, &dnskey, &ds, DsPolicy::strict()).unwrap());
    }
}

#[test]
fn rfc4034_key_tag_and_sha1_ds_vector() {
    let public_key = decode_base64(
        "AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZ\
         DRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9Xzc\
         nOf+EPbtG9DMBmADjFDc2w/rljwvFw==",
    );
    let dnskey = DnskeyData::new(256, 3, 5, public_key).unwrap();
    assert_eq!(key_tag(&dnskey), 60485);

    let owner = Name::parse("dskey.example.com").unwrap();
    let policy = DsPolicy::with_legacy_sha1().with_min_rsa_bits(1024);
    let ds = ds_from_dnskey(&owner, &dnskey, 1, policy).unwrap();
    assert_eq!(ds.key_tag(), 60485);
    assert_eq!(ds.digest_type(), 1);
    assert_eq!(
        hex::encode_upper(ds.digest()),
        "2BB183AF5F22588179A53B0A98631FAD1A292118"
    );
    assert!(ds_matches(&owner, &dnskey, &ds, policy).unwrap());

    // SHA-1 digest type запрещён без opt-in.
    assert!(matches!(
        ds_from_dnskey(&owner, &dnskey, 1, DsPolicy::strict()),
        Err(pulse_dnssec::DsError::LegacyDigestDisabled { .. })
    ));
    // MD5 (digest type 3) не поддерживается.
    assert!(matches!(
        ds_from_dnskey(&owner, &dnskey, 3, DsPolicy::strict()),
        Err(pulse_dnssec::DsError::UnsupportedDigestType { .. })
    ));
}

#[test]
fn generated_key_ds_sha256_is_stable() {
    use pulse_dnssec::Algorithm;
    use pulse_dnssec::PrivateKey;

    let key = PrivateKey::generate(Algorithm::ED25519).unwrap();
    let dnskey = key.dnskey(257).unwrap();
    let owner = Name::parse("example.com").unwrap();
    let ds = ds_from_dnskey(&owner, &dnskey, 2, DsPolicy::strict()).unwrap();
    assert_eq!(ds.digest().len(), 32);
    assert_eq!(ds.key_tag(), key_tag(&dnskey));
    assert!(ds_matches(&owner, &dnskey, &ds, DsPolicy::strict()).unwrap());

    let mut wrong = ds.digest().to_vec();
    wrong[0] ^= 0xFF;
    let tampered = pulse_dns::DsData::new(ds.key_tag(), ds.algorithm(), 2, wrong).unwrap();
    assert!(!ds_matches(&owner, &dnskey, &tampered, DsPolicy::strict()).unwrap());
}

#[test]
fn rfc5155_nsec3_hash_vectors() {
    let salt = hex::decode("aabbccdd").unwrap();
    let cases = [
        ("example", "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"),
        ("a.example", "35mthgpgcu1qg68fab165klnsnk3dpvl"),
        ("ai.example", "gjeqe526plbf1g8mklp59enfd789njgi"),
        ("ns1.example", "2t7b4g4vsa5smi47k61mv5bv1a22bojr"),
        ("ns2.example", "q04jkcevqvmu85r014c7dkba38o0ji5r"),
        ("w.example", "k8udemvp1j2f7eg6jebps17vp3n8i58h"),
        ("*.w.example", "r53bq7cc2uvmubfu5ocmm6pers9tk9en"),
        ("x.w.example", "b4um86eghhds6nea196smvmlo4ors995"),
        ("y.w.example", "ji6neoaepv8b5o6k4ev33abha8ht9fgc"),
        ("x.y.w.example", "2vptu5timamqttgl4luu9kg21e0aor3s"),
        ("xx.example", "t644ebqk9bibcna874givr6joj62mlhv"),
    ];
    for (name_text, expected) in cases {
        let target = Name::parse(name_text).unwrap();
        let hash = pulse_dnssec::rdata_util::nsec3_hash(&target, &salt, 12);
        assert_eq!(
            base32hex::encode(&hash).to_lowercase(),
            expected,
            "hash of {name_text}"
        );
    }
}

#[test]
fn nsec3param_limits() {
    let limits = DenialLimits::new().with_max_iterations(10);
    let param = Nsec3ParamData::new(1, 0, 11, vec![0xAA; 4]).unwrap();
    assert!(matches!(
        Nsec3Params::from_nsec3param(&param, limits),
        Err(pulse_dnssec::DenialError::Nsec3IterationsTooHigh { .. })
    ));
    let param = Nsec3ParamData::new(2, 0, 0, vec![]).unwrap();
    assert!(matches!(
        Nsec3Params::from_nsec3param(&param, limits),
        Err(pulse_dnssec::DenialError::Nsec3HashUnsupported { .. })
    ));
    let param = Nsec3ParamData::new(1, 1, 0, vec![]).unwrap();
    assert!(matches!(
        Nsec3Params::from_nsec3param(&param, limits),
        Err(pulse_dnssec::DenialError::Nsec3Flags { .. })
    ));
}
