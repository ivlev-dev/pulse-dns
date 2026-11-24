//! Форматы конфигурации `pulsed`: TOML (основной) и JSON (legacy).

use std::path::{Path, PathBuf};

use pulsed::config::Config;

fn examples_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples")
}

fn example_names() -> [&'static str; 8] {
    [
        "pulsed",
        "persistent",
        "empty",
        "transports",
        "pair-primary",
        "pair-secondary",
        "dnssec-rotation",
        "transfer",
    ]
}

#[test]
fn toml_and_json_examples_are_equivalent() {
    for name in example_names() {
        let root = examples_dir();
        let toml = Config::from_path(root.join(format!("{name}.toml")))
            .unwrap_or_else(|error| panic!("{name}.toml: {error}"));
        let json = Config::from_path(root.join(format!("{name}.json")))
            .unwrap_or_else(|error| panic!("{name}.json: {error}"));
        assert_eq!(
            serde_json::to_value(&toml).expect("serialize toml"),
            serde_json::to_value(&json).expect("serialize json"),
            "{name}: TOML и JSON должны совпадать"
        );
        toml.validate()
            .unwrap_or_else(|error| panic!("{name}: {error}"));
    }
}

#[test]
fn toml_round_trip_preserves_configuration() {
    for name in example_names() {
        let path = examples_dir().join(format!("{name}.toml"));
        let config = Config::from_path(&path).unwrap_or_else(|error| panic!("{name}: {error}"));
        let rendered = config.to_toml_string().expect("serialize toml");
        let reparsed = Config::from_toml_str(&rendered).expect("reparse rendered toml");
        assert_eq!(
            serde_json::to_value(&config).expect("serialize original"),
            serde_json::to_value(&reparsed).expect("serialize reparsed"),
            "{name}: round-trip через TOML должен сохранять конфигурацию"
        );
    }
}

#[test]
fn extension_selects_format_and_unknown_extension_hints() {
    let directory = tempfile::tempdir().expect("tempdir");
    let toml_path = directory.path().join("pulsed.TOML");
    std::fs::write(&toml_path, "listen_udp = \"127.0.0.1:0\"\n").expect("write toml");
    let config = Config::from_path(&toml_path).expect("uppercase .TOML");
    assert!(config.listen_udp.is_some());

    let json_path = directory.path().join("pulsed.json");
    std::fs::write(&json_path, r#"{"listen_udp": "127.0.0.1:0"}"#).expect("write json");
    let config = Config::from_path(&json_path).expect("legacy json");
    assert!(config.listen_udp.is_some());

    let unknown = directory.path().join("pulsed.conf");
    std::fs::write(&unknown, "listen_udp = \"127.0.0.1:0\"\n").expect("write conf");
    let message = Config::from_path(&unknown)
        .expect_err("unknown extension must be rejected")
        .to_string();
    assert!(message.contains("pulsed.conf"), "{message}");
    assert!(message.contains("a .toml file (recommended)"), "{message}");
    assert!(
        message.contains("a .json file (legacy compatibility)"),
        "{message}"
    );
}

#[test]
fn toml_errors_report_path_line_and_column() {
    let directory = tempfile::tempdir().expect("tempdir");

    let unknown = directory.path().join("unknown.toml");
    std::fs::write(&unknown, "listen_udp = \"127.0.0.1:0\"\nwat = true\n").expect("write");
    let message = Config::from_path(&unknown)
        .expect_err("unknown field")
        .to_string();
    assert!(
        message.contains(unknown.to_str().expect("utf8")),
        "{message}"
    );
    assert!(message.contains("unknown field `wat`"), "{message}");
    assert!(message.contains("line 2"), "{message}");
    assert!(message.contains("column 1"), "{message}");

    let wrong_type = directory.path().join("type.toml");
    std::fs::write(
        &wrong_type,
        "listen_udp = \"127.0.0.1:0\"\nworkers = \"many\"\n",
    )
    .expect("write");
    let message = Config::from_path(&wrong_type)
        .expect_err("bad type")
        .to_string();
    assert!(message.contains("invalid type"), "{message}");
    assert!(message.contains("line 2"), "{message}");
    assert!(message.contains("column"), "{message}");

    let syntax = directory.path().join("syntax.toml");
    std::fs::write(&syntax, "listen_udp = \"127.0.0.1:0\n").expect("write");
    let message = Config::from_path(&syntax)
        .expect_err("bad syntax")
        .to_string();
    assert!(message.contains("TOML parse error"), "{message}");
    assert!(message.contains("line 1"), "{message}");
    assert!(message.contains("column"), "{message}");
}

#[test]
fn json_errors_keep_path_and_position() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("pulsed.json");
    std::fs::write(&path, r#"{"listen_udp": "127.0.0.1:0", "wat": 1}"#).expect("write");
    let message = Config::from_path(&path)
        .expect_err("unknown field")
        .to_string();
    assert!(message.contains(path.to_str().expect("utf8")), "{message}");
    assert!(message.contains("unknown field `wat`"), "{message}");
    assert!(message.contains("line 1"), "{message}");
    assert!(message.contains("column"), "{message}");
}
