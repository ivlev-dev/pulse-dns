//! Валидация конфигурации защищённых транспортов: TLS-пара, ключи DNSCrypt,
//! права `0600`, лимиты и TOML-пример.

#![allow(clippy::doc_markdown)]

use std::path::Path;

use pulseresolved::config::{Config, DnscryptSetting, SecureSetting};

fn base() -> Config {
    Config::from_toml_str(
        r#"
listen_udp = "127.0.0.1:0"
mode = "forward"
forwarders = ["127.0.0.1:53"]
"#,
    )
    .expect("base config")
}

fn secure_example() -> Config {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/resolver-secure-transports.toml");
    Config::from_path(path).expect("secure transports example")
}

#[test]
fn secure_transports_example_parses_and_validates() {
    let config = secure_example();
    config.validate().expect("example is valid");
    assert_eq!(config.dot_listen, Some("0.0.0.0:853".parse().unwrap()));
    assert_eq!(config.doh_listen, Some("0.0.0.0:443".parse().unwrap()));
    assert_eq!(config.doh2_listen, Some("0.0.0.0:8443".parse().unwrap()));
    assert_eq!(config.doq_listen, Some("0.0.0.0:8853".parse().unwrap()));
    assert_eq!(
        config.dnscrypt_listen,
        Some("0.0.0.0:5443".parse().unwrap())
    );
    assert_eq!(
        config.dnscrypt_tcp_listen,
        Some("0.0.0.0:5443".parse().unwrap())
    );
    assert!(config.has_tls_transport());
    assert!(config.has_dnscrypt_transport());
    assert_eq!(config.secure.max_connections, 1024);
    assert_eq!(config.dnscrypt.max_udp_packet, 4096);
    assert_eq!(
        config.tls_cert.as_deref(),
        Some(Path::new("/etc/pulse/tls/fullchain.pem"))
    );
    let acl = config.build_tls_acl().expect("tls acl").expect("explicit");
    assert!(acl.allows("192.168.1.1".parse().unwrap()));
}

#[test]
fn toml_round_trip_preserves_secure_fields() {
    let config = secure_example();
    let rendered = config.to_toml_string().expect("serialize");
    let reparsed = Config::from_toml_str(&rendered).expect("reparse");
    reparsed.validate().expect("valid");
    assert_eq!(
        serde_json::to_value(&config).expect("json"),
        serde_json::to_value(&reparsed).expect("json")
    );
    assert_eq!(reparsed.dnscrypt_cert, config.dnscrypt_cert);
    assert_eq!(reparsed.tls_allow_from, config.tls_allow_from);
}

#[test]
fn tls_pair_is_required_for_tls_transports() {
    let mut config = base();
    config.dot_listen = Some("127.0.0.1:0".parse().unwrap());
    let error = config.validate().expect_err("tls_cert required");
    assert!(error.to_string().contains("tls_cert"), "{error}");

    config.tls_cert = Some("cert.pem".into());
    let error = config.validate().expect_err("tls_key required");
    assert!(error.to_string().contains("tls_key"), "{error}");

    config.tls_key = Some("key.pem".into());
    config.validate().expect("tls pair present");
}

#[test]
fn dnscrypt_material_is_required() {
    let mut config = base();
    config.dnscrypt_listen = Some("127.0.0.1:0".parse().unwrap());
    for field in [
        "dnscrypt_provider_key",
        "dnscrypt_resolver_key",
        "dnscrypt_cert",
    ] {
        let error = config.validate().expect_err(field);
        assert!(error.to_string().contains(field), "{error}");
        match field {
            "dnscrypt_provider_key" => config.dnscrypt_provider_key = Some("p.key".into()),
            "dnscrypt_resolver_key" => config.dnscrypt_resolver_key = Some("r.key".into()),
            _ => config.dnscrypt_cert = Some("d.cert".into()),
        }
    }
    config.validate().expect("all dnscrypt files present");
}

#[cfg(unix)]
#[test]
fn insecure_key_permissions_are_rejected() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    std::fs::write(&cert, b"cert").expect("cert");
    std::fs::write(&key, b"key").expect("key");
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).expect("chmod");

    let mut config = base();
    config.dot_listen = Some("127.0.0.1:0".parse().unwrap());
    config.tls_cert = Some(cert);
    config.tls_key = Some(key.clone());
    let error = config.validate().expect_err("0644 key must be rejected");
    assert!(
        error.to_string().contains("insecure permissions"),
        "{error}"
    );

    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).expect("chmod 0600");
    config.validate().expect("0600 key accepted");
}

#[test]
fn secure_and_dnscrypt_limits_are_validated() {
    let mut config = base();
    config.secure = SecureSetting {
        max_connections: 0,
        ..SecureSetting::default()
    };
    assert!(config.validate().is_err());

    config.secure = SecureSetting {
        max_streams: 0,
        ..SecureSetting::default()
    };
    assert!(config.validate().is_err());

    config.secure = SecureSetting {
        worker_threads: 0,
        ..SecureSetting::default()
    };
    assert!(config.validate().is_err());

    config.secure = SecureSetting {
        max_message_size: 70_000,
        ..SecureSetting::default()
    };
    assert!(config.validate().is_err());

    config.secure = SecureSetting::default();
    config.dnscrypt = DnscryptSetting {
        min_query_len: 100,
        ..DnscryptSetting::default()
    };
    assert!(config.validate().is_err());

    config.dnscrypt = DnscryptSetting {
        max_udp_packet: 10,
        ..DnscryptSetting::default()
    };
    assert!(config.validate().is_err());

    config.dnscrypt = DnscryptSetting::default();
    config.validate().expect("defaults are valid");
}

#[test]
fn json_supports_secure_fields() {
    let text = r#"{
        "dot_listen": "127.0.0.1:8853",
        "tls_cert": "/tmp/cert.pem",
        "tls_key": "/tmp/key.pem",
        "tls_allow_from": ["10.0.0.0/8"],
        "secure": { "max_streams": 50, "cache_control": false },
        "dnscrypt": { "max_udp_packet": 2048 },
        "mode": "forward",
        "forwarders": ["127.0.0.1:53"]
    }"#;
    let config = Config::from_json_str(text).expect("json config");
    assert_eq!(config.secure.max_streams, 50);
    assert!(!config.secure.cache_control);
    assert_eq!(config.dnscrypt.max_udp_packet, 2048);
    assert_eq!(config.tls_allow_from, vec!["10.0.0.0/8".to_owned()]);
}

#[test]
fn empty_config_still_requires_a_transport() {
    let config = Config::from_toml_str("mode = \"forward\"\nforwarders = [\"127.0.0.1:53\"]\n")
        .expect("parse");
    let error = config.validate().expect_err("no transport");
    assert!(
        error.to_string().contains("at least one transport"),
        "{error}"
    );
}
