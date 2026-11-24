//! Файлы ключей: права 0600/0700, zeroize-путь, отсутствие секретов в Debug,
//! BIND/PKCS#8 round-trip.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use pulse_dnssec::bind::{format_private_key, parse_dnskey_file, parse_private_key};
use pulse_dnssec::keyfile::{
    KeyAuditEvent, KeyOperation, ensure_private_directory, write_key_pair,
};
use pulse_dnssec::{
    Algorithm, KeyError, KeyFileError, PrivateKey, RsaKeySize, SecretRef, VerifyOptions,
    read_private_key_file, sign_rrset, verify_rrsig,
};
use zeroize::ZeroizeOnDrop;

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn assert_zeroizing<T: ZeroizeOnDrop>() {}

#[test]
fn secret_ref_zeroizes_and_hides_debug() {
    assert_zeroizing::<SecretRef>();
    let secret = SecretRef::from_slice(b"top-secret-material");
    assert_eq!(secret.len(), 19);
    assert!(format!("{secret:?}").contains("redacted"));
    assert!(!format!("{secret:?}").contains("top-secret"));
}

#[test]
fn private_key_debug_hides_material() {
    let key = PrivateKey::generate(Algorithm::ED25519).unwrap();
    let pem = key.to_pkcs8_pem().unwrap();
    let pem_text = String::from_utf8(pem.expose().to_vec()).unwrap();
    let body: String = pem_text
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let rendered = format!("{key:?}");
    assert!(rendered.contains("ED25519"));
    assert!(rendered.contains("redacted"));
    assert!(!rendered.contains(&body));
    assert!(!rendered.contains("PRIVATE KEY"));
}

#[test]
fn pkcs8_der_pem_roundtrip_all_algorithms() {
    let cases = [
        (
            Algorithm::RSASHA256,
            RsaKeySize::Bits2048,
            "rsa.example.com.",
        ),
        (
            Algorithm::ECDSAP256SHA256,
            RsaKeySize::Bits2048,
            "ecdsa.example.com.",
        ),
        (Algorithm::ED25519, RsaKeySize::Bits2048, "ed.example.com."),
    ];
    for (algorithm, size, owner) in cases {
        let key = PrivateKey::generate_with_rsa_size(algorithm, size).unwrap();
        let dnskey = key.dnskey(257).unwrap();
        let tag = key.key_tag(257).unwrap();

        let der = key.to_pkcs8_der().unwrap();
        let from_der = PrivateKey::from_pkcs8_der(algorithm, der.expose()).unwrap();
        assert_eq!(from_der.dnskey(257).unwrap(), dnskey);
        assert_eq!(from_der.key_tag(257).unwrap(), tag);

        let pem = key.to_pkcs8_pem().unwrap();
        let pem_text = std::str::from_utf8(pem.expose()).unwrap();
        assert!(pem_text.starts_with("-----BEGIN PRIVATE KEY-----"));
        let from_pem = PrivateKey::from_pkcs8_pem(algorithm, pem_text).unwrap();
        assert_eq!(from_pem.dnskey(257).unwrap(), dnskey);
        let _ = owner;
    }
}

#[test]
fn bind_private_roundtrip_all_algorithms() {
    let cases = [
        Algorithm::RSASHA256,
        Algorithm::ECDSAP256SHA256,
        Algorithm::ED25519,
    ];
    for algorithm in cases {
        let key = PrivateKey::generate(algorithm).unwrap();
        let dnskey = key.dnskey(256).unwrap();
        let text = format_private_key(&key).unwrap();
        let text = std::str::from_utf8(text.expose()).unwrap();
        assert!(text.starts_with("Private-key-format:"));
        assert!(!text.contains("PRIVATE KEY"));

        let parsed = parse_private_key(text).unwrap();
        assert_eq!(parsed.algorithm(), algorithm);
        assert_eq!(parsed.dnskey(256).unwrap(), dnskey);
        assert_eq!(parsed.key_tag(256).unwrap(), key.key_tag(256).unwrap());
    }
}

#[test]
fn bind_key_file_roundtrip() {
    let key = PrivateKey::generate(Algorithm::ECDSAP256SHA256).unwrap();
    let dnskey = key.dnskey(257).unwrap();
    let line = pulse_dnssec::bind::format_dnskey_line(
        &pulse_dns::Name::parse("example.com").unwrap(),
        3600,
        &dnskey,
    );
    let parsed = parse_dnskey_file(&line).unwrap();
    assert_eq!(parsed.owner.to_string(), "example.com.");
    assert_eq!(parsed.ttl, Some(3600));
    assert_eq!(parsed.dnskey, dnskey);
}

#[test]
fn key_files_are_private_and_atomic() {
    let directory = tempfile::tempdir().unwrap();
    let keys_dir = directory.path().join("keys");
    ensure_private_directory(&keys_dir).unwrap();
    assert_eq!(mode(&keys_dir) & 0o077, 0);

    let key = PrivateKey::generate(Algorithm::ED25519).unwrap();
    let audit_log = std::sync::Mutex::new(Vec::new());
    let audit = |event: &KeyAuditEvent| {
        audit_log.lock().unwrap().push(event.clone());
    };
    let paths = write_key_pair(
        &keys_dir,
        &pulse_dns::Name::parse("example.com").unwrap(),
        &key,
        257,
        &audit,
    )
    .unwrap();

    assert_eq!(mode(&paths.private), 0o600);
    assert_eq!(mode(&paths.public), 0o600);
    assert!(paths.private.to_string_lossy().contains("+015+"));
    assert!(paths.private.to_string_lossy().ends_with(".private"));

    let loaded = read_private_key_file(&paths.private).unwrap();
    assert_eq!(loaded.dnskey(257).unwrap(), key.dnskey(257).unwrap());

    let public_text = fs::read_to_string(&paths.public).unwrap();
    let parsed_public = parse_dnskey_file(&public_text).unwrap();
    assert_eq!(parsed_public.dnskey, key.dnskey(257).unwrap());

    // Аудит: только операции/пути/алгоритм, без материала.
    let events = audit_log.into_inner().unwrap();
    let write_events: Vec<&KeyAuditEvent> = events
        .iter()
        .filter(|event| event.operation == KeyOperation::Write)
        .collect();
    assert_eq!(write_events.len(), 2);
    for event in write_events {
        assert_eq!(event.algorithm, Algorithm::ED25519);
        assert!(event.key_tag.is_some());
        assert!(event.path.is_some());
    }
}

#[test]
fn insecure_directory_is_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let keys_dir = directory.path().join("public-keys");
    fs::create_dir(&keys_dir).unwrap();
    fs::set_permissions(&keys_dir, fs::Permissions::from_mode(0o755)).unwrap();
    let key = PrivateKey::generate(Algorithm::ED25519).unwrap();
    let error = write_key_pair(
        &keys_dir,
        &pulse_dns::Name::parse("example.com").unwrap(),
        &key,
        257,
        &pulse_dnssec::NoopAudit,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        KeyFileError::Permissions { mode: 0o755, .. }
    ));
}

#[test]
fn read_private_key_file_rejects_pkcs8_pem() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("key.pem");
    let key = PrivateKey::generate(Algorithm::ED25519).unwrap();
    let pem = key.to_pkcs8_pem().unwrap();
    fs::write(&path, pem.expose()).unwrap();
    assert!(matches!(
        read_private_key_file(&path),
        Err(KeyFileError::Key(KeyError::BadBindPrivate { .. }))
    ));
}

#[test]
fn malformed_bind_files_are_typed_errors() {
    assert!(matches!(
        parse_private_key("Private-key-format: v9.9\n"),
        Err(KeyError::MissingField { .. })
    ));
    assert!(matches!(
        parse_private_key("Algorithm: 13 (ECDSAP256SHA256)\nPrivateKey: AA==\n"),
        Err(KeyError::BadBindPrivate { .. })
    ));
    assert!(matches!(
        parse_dnskey_file("example.com IN DNSKEY 257 3 8 !!!\n"),
        Err(KeyError::InvalidBase64 { .. })
    ));
    assert!(matches!(
        parse_dnskey_file(""),
        Err(KeyError::BadDnskeyFile { .. })
    ));
}

#[test]
fn rsa_4096_generation_and_signing() {
    let key =
        PrivateKey::generate_with_rsa_size(Algorithm::RSASHA256, RsaKeySize::Bits4096).unwrap();
    let dnskey = key.dnskey(256).unwrap();
    assert!(dnskey.public_key().len() >= 512);
    assert!(key.key_tag(256).is_ok());

    let owner = pulse_dns::Name::parse("example.com").unwrap();
    let rrset = pulse_dns::Rrset::new(
        owner.clone(),
        pulse_dns::Rtype::A,
        pulse_dns::Rclass::IN,
        pulse_dns::Ttl::new(300).unwrap(),
        vec![pulse_dns::Rdata::A(std::net::Ipv4Addr::new(192, 0, 2, 1))],
    )
    .unwrap();
    let options =
        pulse_dnssec::SignOptions::new(owner, 1_700_000_000, 86_400).with_dnskey_flags(256);
    let rrsig = sign_rrset(&key, &rrset, &options).unwrap();
    verify_rrsig(&rrset, &rrsig, &dnskey, &VerifyOptions::new(1_700_000_100)).unwrap();
}
