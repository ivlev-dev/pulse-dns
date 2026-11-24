//! `$INCLUDE`: глубина, циклы, выход за каталог, лимиты.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use pulse_dns::Name;
use pulse_master::{ErrorKind, Limits, ParseOptions, parse_zone_with_options};

fn origin() -> Name {
    Name::parse("example.com.").expect("origin")
}

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "pulse-master-test-{}-{counter}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("temp dir");
        Self { path }
    }

    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.path.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("parent dir");
        }
        std::fs::write(&path, contents).expect("write file");
        path
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn options(root: &Path) -> ParseOptions {
    ParseOptions {
        include_root: Some(root.to_path_buf()),
        ..ParseOptions::default()
    }
}

const HEADER: &str = "$TTL 60\n@ SOA ns hostmaster 1 1 1 10 1\n@ NS ns\n";

#[test]
fn include_loads_file_with_origin_and_restores_scope() {
    let dir = TempDir::new();
    dir.write("part.zone", "www 300 A 192.0.2.10\ndeep IN A 192.0.2.11\n");
    let text = format!("{HEADER}$INCLUDE part.zone sub\nafter A 192.0.2.12\n");
    let zone = parse_zone_with_options(origin(), &text, &options(dir.path())).expect("include");
    let names: Vec<String> = zone
        .records
        .iter()
        .map(|record| record.owner().to_string())
        .collect();
    assert!(
        names.iter().any(|name| name == "www.sub.example.com."),
        "{names:?}"
    );
    assert!(
        names.iter().any(|name| name == "deep.sub.example.com."),
        "{names:?}"
    );
    assert!(
        names.iter().any(|name| name == "after.example.com."),
        "{names:?}"
    );
    assert_eq!(zone.records.len(), 5);
}

#[test]
fn include_accepts_absolute_path_and_nested_origin() {
    let dir = TempDir::new();
    let path = dir.write(
        "nested/part.zone",
        "$ORIGIN sub.example.com.\nwww A 192.0.2.20\n",
    );
    let text = format!("{HEADER}$INCLUDE {}\n", path.display());
    let zone = parse_zone_with_options(origin(), &text, &options(dir.path())).expect("include");
    assert!(
        zone.records
            .iter()
            .any(|record| record.owner() == &Name::parse("www.sub.example.com.").expect("name"))
    );
}

#[test]
fn include_outside_root_is_rejected() {
    let dir = TempDir::new();
    let root = dir.path().join("root");
    std::fs::create_dir_all(&root).expect("root");
    std::fs::write(dir.path().join("outside.zone"), "x A 192.0.2.1\n").expect("outside");
    let text = format!("{HEADER}$INCLUDE ../outside.zone\n");
    let error = parse_zone_with_options(origin(), &text, &options(&root)).expect_err("escape");
    assert!(
        matches!(error.kind, ErrorKind::Include(ref message) if message.contains("escapes")),
        "{error:?}"
    );
}

#[test]
fn include_cycle_is_rejected() {
    let dir = TempDir::new();
    dir.write("a.zone", "$INCLUDE b.zone\n");
    dir.write("b.zone", "$INCLUDE a.zone\n");
    let text = format!("{HEADER}$INCLUDE a.zone\n");
    let error = parse_zone_with_options(origin(), &text, &options(dir.path())).expect_err("cycle");
    assert!(
        matches!(error.kind, ErrorKind::Include(ref message) if message.contains("cycle")),
        "{error:?}"
    );
}

#[test]
fn include_depth_limit_is_enforced() {
    let dir = TempDir::new();
    dir.write("a.zone", "$INCLUDE b.zone\n");
    dir.write("b.zone", "x A 192.0.2.1\n");
    let text = format!("{HEADER}$INCLUDE a.zone\n");
    let mut options = options(dir.path());
    options.limits = Limits {
        max_include_depth: 1,
        ..Limits::default()
    };
    let error = parse_zone_with_options(origin(), &text, &options).expect_err("depth");
    assert!(
        matches!(error.kind, ErrorKind::Include(ref message) if message.contains("depth")),
        "{error:?}"
    );
}

#[test]
fn include_count_limit_is_enforced() {
    let dir = TempDir::new();
    dir.write("a.zone", "a A 192.0.2.1\n");
    dir.write("b.zone", "b A 192.0.2.2\n");
    let text = format!("{HEADER}$INCLUDE a.zone\n$INCLUDE b.zone\n");
    let mut options = options(dir.path());
    options.limits = Limits {
        max_include_files: 1,
        ..Limits::default()
    };
    let error = parse_zone_with_options(origin(), &text, &options).expect_err("count");
    assert!(
        matches!(
            error.kind,
            ErrorKind::Limit {
                what: "include files",
                ..
            }
        ),
        "{error:?}"
    );
}

#[test]
fn include_size_limit_is_enforced() {
    let dir = TempDir::new();
    dir.write("big.zone", &"x A 192.0.2.1\n".repeat(100));
    let text = format!("{HEADER}$INCLUDE big.zone\n");
    let mut options = options(dir.path());
    options.limits = Limits {
        max_file_bytes: 64,
        ..Limits::default()
    };
    let error = parse_zone_with_options(origin(), &text, &options).expect_err("size");
    assert!(
        matches!(
            error.kind,
            ErrorKind::Limit {
                what: "file size",
                ..
            }
        ),
        "{error:?}"
    );
}

#[test]
fn include_is_disabled_by_default() {
    let text = format!("{HEADER}$INCLUDE part.zone\n");
    let error =
        parse_zone_with_options(origin(), &text, &ParseOptions::default()).expect_err("disabled");
    assert!(
        matches!(error.kind, ErrorKind::Include(ref message) if message.contains("disabled")),
        "{error:?}"
    );
}
