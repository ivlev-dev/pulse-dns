//! Время: expired / not-yet-valid / skew / RFC 1982 wrap.

mod common;

use pulse_dns::RrsigData;
use pulse_dnssec::{
    Algorithm, PrivateKey, SignError, SignOptions, VerifyError, VerifyOptions, sign_rrset,
    verify_rrsig,
};

use common::{NOW, a_rrset, dnskey_of, name};

#[test]
fn inception_skew_allows_slightly_past_clock() {
    let key = PrivateKey::generate(Algorithm::ED25519).unwrap();
    let dnskey = dnskey_of(&key, 256);
    let rrset = a_rrset("a.example.com", &[[192, 0, 2, 1]], 300);
    let options = SignOptions::new(name("example.com"), NOW, 86_400).with_skew(300);
    let rrsig = sign_rrset(&key, &rrset, &options).unwrap();

    // В пределах skew — валидно.
    verify_rrsig(&rrset, &rrsig, &dnskey, &VerifyOptions::new(NOW - 299)).unwrap();
    // Раньше inception — not yet valid.
    assert!(matches!(
        verify_rrsig(&rrset, &rrsig, &dnskey, &VerifyOptions::new(NOW - 301)),
        Err(VerifyError::NotYetValid { .. })
    ));
}

#[test]
fn expired_and_future_signatures_are_rejected() {
    let key = PrivateKey::generate(Algorithm::ECDSAP256SHA256).unwrap();
    let dnskey = dnskey_of(&key, 256);
    let rrset = a_rrset("a.example.com", &[[192, 0, 2, 1]], 300);
    let options = SignOptions::new(name("example.com"), NOW, 3600).with_skew(0);
    let rrsig = sign_rrset(&key, &rrset, &options).unwrap();

    assert_eq!(rrsig.signature_inception(), NOW);
    assert_eq!(rrsig.signature_expiration(), NOW + 3600);

    verify_rrsig(&rrset, &rrsig, &dnskey, &VerifyOptions::new(NOW + 3599)).unwrap();
    assert!(matches!(
        verify_rrsig(&rrset, &rrsig, &dnskey, &VerifyOptions::new(NOW + 3601)),
        Err(VerifyError::Expired { .. })
    ));
    assert!(matches!(
        verify_rrsig(&rrset, &rrsig, &dnskey, &VerifyOptions::new(NOW - 1)),
        Err(VerifyError::NotYetValid { .. })
    ));
}

#[test]
fn future_inception_is_not_yet_valid() {
    let key = PrivateKey::generate(Algorithm::ED25519).unwrap();
    let dnskey = dnskey_of(&key, 256);
    let rrset = a_rrset("a.example.com", &[[192, 0, 2, 1]], 300);
    let rrsig = RrsigData::new(
        rrset.rr_type(),
        15,
        2,
        300,
        NOW + 10_000,
        NOW + 5_000,
        pulse_dnssec::key_tag(&dnskey),
        name("example.com"),
        vec![1_u8; 64],
    )
    .unwrap();
    assert!(matches!(
        verify_rrsig(&rrset, &rrsig, &dnskey, &VerifyOptions::new(NOW)),
        Err(VerifyError::NotYetValid { .. })
    ));
}

#[test]
fn signature_window_wraps_around_serial_space() {
    let key = PrivateKey::generate(Algorithm::ED25519).unwrap();
    let dnskey = dnskey_of(&key, 256);
    let rrset = a_rrset("a.example.com", &[[192, 0, 2, 1]], 300);
    let now = u32::MAX - 10;
    let options = SignOptions::new(name("example.com"), now, 86_400).with_skew(60);
    let rrsig = sign_rrset(&key, &rrset, &options).unwrap();

    verify_rrsig(&rrset, &rrsig, &dnskey, &VerifyOptions::new(now)).unwrap();
    // Через 100 секунд после wrap.
    verify_rrsig(
        &rrset,
        &rrsig,
        &dnskey,
        &VerifyOptions::new(now.wrapping_add(100)),
    )
    .unwrap();
    // После expiration (wrap + 86460).
    assert!(matches!(
        verify_rrsig(
            &rrset,
            &rrsig,
            &dnskey,
            &VerifyOptions::new(now.wrapping_add(86_461)),
        ),
        Err(VerifyError::Expired { .. })
    ));
}

#[test]
fn skew_and_validity_bounds() {
    let key = PrivateKey::generate(Algorithm::ED25519).unwrap();
    let rrset = a_rrset("a.example.com", &[[192, 0, 2, 1]], 300);
    assert!(matches!(
        sign_rrset(&key, &rrset, &SignOptions::new(name("example.com"), NOW, 0)),
        Err(SignError::InvalidValidity)
    ));
    assert!(matches!(
        sign_rrset(
            &key,
            &rrset,
            &SignOptions::new(name("example.com"), NOW, 0x8000_0000)
        ),
        Err(SignError::InvalidValidity)
    ));
    assert!(
        sign_rrset(
            &key,
            &rrset,
            &SignOptions::new(name("example.com"), NOW, 0x7FFF_FF00).with_skew(0)
        )
        .is_ok()
    );
}
