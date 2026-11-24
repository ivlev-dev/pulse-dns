//! Интеграция RFC 5011 в `pulseresolved`: конфигурация managed-набора,
//! seed из DS-файла и персистентное состояние `0600`.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use pulse_dns::Name;
use pulseresolved::config::{Config, Overrides, TrustAnchorSetting};

const ROOT_DS: &str =
    ". 172800 IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D";

fn now() -> u32 {
    u32::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs(),
    )
    .expect("timestamp")
}

#[test]
fn managed_anchor_state_is_seeded_and_persisted() {
    let directory = tempfile::tempdir().expect("dir");
    let ds_path = directory.path().join("root.ds");
    std::fs::write(&ds_path, format!("{ROOT_DS}\n")).expect("write DS");
    let state_path = directory.path().join("state/anchors.json");
    let toml = format!(
        r#"listen_udp = "127.0.0.1:5399"
forwarders = ["127.0.0.1:5300"]
dnssec_validate = true

[trust_anchor]
path = "{}"
state = "{}"
add_hold_down = 5
revoke_hold_down = 7
"#,
        ds_path.display(),
        state_path.display()
    );
    let config = Config::from_toml_str(&toml).expect("parse toml");
    config.validate().expect("validate");
    assert_eq!(
        config.trust_anchor,
        Some(TrustAnchorSetting::Managed {
            path: ds_path,
            state: state_path.clone(),
            add_hold_down: 5,
            revoke_hold_down: 7,
        })
    );

    let resolver = config.resolver_config().expect("resolver config");
    let provider = resolver
        .trust_anchor_provider
        .as_ref()
        .expect("RFC 5011 provider");
    let anchors = provider.anchors(&Name::root(), now());
    assert_eq!(anchors.len(), 1, "seeded root anchor");
    assert_eq!(anchors[0].key_tag(), 20326);
    assert!(
        provider
            .anchors(&Name::parse("example.com").expect("name"), now())
            .is_empty(),
        "managed store is root-only"
    );

    let mode = std::fs::metadata(&state_path)
        .expect("state metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "state file must be 0600");
    let text = std::fs::read_to_string(&state_path).expect("state");
    let state = pulse_dnssec::TrustAnchorStore::from_json(&text).expect("state json");
    assert_eq!(state.anchors().len(), 1);
    assert_eq!(state.policy().add_hold_down, 5);
    assert_eq!(state.policy().revoke_hold_down, 7);
}

#[test]
fn cli_overrides_enable_managed_updates() {
    let mut config = Config::default();
    config.apply_overrides(&Overrides {
        trust_anchor: Some(PathBuf::from("root.ds")),
        trust_anchor_state: Some(PathBuf::from("anchors.json")),
        trust_anchor_hold_down: Some(90),
        ..Overrides::default()
    });
    assert!(config.dnssec_validate);
    assert_eq!(
        config.trust_anchor,
        Some(TrustAnchorSetting::Managed {
            path: PathBuf::from("root.ds"),
            state: PathBuf::from("anchors.json"),
            add_hold_down: 90,
            revoke_hold_down: 90,
        })
    );
}
