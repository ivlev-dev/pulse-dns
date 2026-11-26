//! HTTPS-загрузчик blocklist: кэш, 304, лимиты, редиректы и SSRF-guard.

mod support;

use std::time::{Duration, Instant};

use pulse_dns::Name;
use pulse_resolver::{
    Blocklist, RemoteBlocklist, RemoteBlocklistConfig, RemoteError, RemoteSource, SourceFormat,
};
use support::https_source::MockHttpsSource;

fn remote_config(source: &MockHttpsSource, cache: &std::path::Path) -> RemoteBlocklistConfig {
    RemoteBlocklistConfig {
        sources: vec![RemoteSource::new(source.url("/hosts"))],
        refresh_secs: 3600,
        cache_dir: cache.to_path_buf(),
        max_bytes: 1024 * 1024,
        allow_redirects: false,
        allow_hosts: vec!["127.0.0.1".to_owned()],
        timeout: Duration::from_secs(5),
        retries: 0,
        backoff: Duration::from_millis(20),
        ca_file: Some(source.write_ca(cache)),
    }
}

fn blocklist(remote: &RemoteBlocklist, allowlist: &[String]) -> Blocklist {
    let texts = remote.texts();
    Blocklist::load_combined(&[], &texts, allowlist).expect("combined blocklist")
}

fn name(value: &str) -> Name {
    Name::parse(value).expect("name")
}

#[test]
fn fetch_hosts_and_plain_domains_blocks_subdomains() {
    let directory = tempfile::tempdir().expect("tempdir");
    let server = MockHttpsSource::start(
        "# comment\n0.0.0.0 ads.test\n127.0.0.1 tracker.test\nplain.test\n*.wild.test\n",
    );
    let mut remote =
        RemoteBlocklist::new(remote_config(&server, directory.path())).expect("remote");
    assert!(!remote.has_snapshot());

    let report = remote.refresh_due();
    assert_eq!(report.updated, 1, "{report:?}");
    assert!(report.changed);
    assert!(report.bytes > 0);
    let list = blocklist(&remote, &["safe.ads.test".to_owned()]);
    assert!(list.is_blocked(&name("ads.test")));
    assert!(list.is_blocked(&name("sub.ads.test")));
    assert!(list.is_blocked(&name("tracker.test")));
    assert!(list.is_blocked(&name("plain.test")));
    assert!(!list.is_blocked(&name("safe.ads.test")));
    assert!(list.is_blocked(&name("a.wild.test")));
    assert!(!list.is_blocked(&name("wild.test")));
    assert_eq!(server.hits(), 1);
}

#[test]
fn chunked_body_is_supported() {
    let directory = tempfile::tempdir().expect("tempdir");
    let server = MockHttpsSource::start("0.0.0.0 chunked.test\n");
    server.update(|state| state.chunked = true);
    let mut remote =
        RemoteBlocklist::new(remote_config(&server, directory.path())).expect("remote");
    let report = remote.refresh_due();
    assert_eq!(report.updated, 1, "{report:?}");
    assert!(blocklist(&remote, &[]).is_blocked(&name("chunked.test")));
}

#[test]
fn conditional_requests_explain_304() {
    let directory = tempfile::tempdir().expect("tempdir");
    let server = MockHttpsSource::start("0.0.0.0 etag.test\n");
    server.update(|state| state.etag = Some("\"v1\"".to_owned()));
    let mut remote =
        RemoteBlocklist::new(remote_config(&server, directory.path())).expect("remote");
    assert_eq!(remote.refresh_due().updated, 1);
    assert!(server.last_request().if_none_match.is_none());

    let report = remote.refresh_all();
    assert_eq!(report.updated, 0);
    assert_eq!(report.not_modified, 1, "{report:?}");
    assert_eq!(
        server.last_request().if_none_match.as_deref(),
        Some("\"v1\"")
    );
    assert!(blocklist(&remote, &[]).is_blocked(&name("etag.test")));
    assert_eq!(server.hits(), 2);
}

#[test]
fn if_modified_since_is_used_without_etag() {
    let directory = tempfile::tempdir().expect("tempdir");
    let server = MockHttpsSource::start("0.0.0.0 modified.test\n");
    server.update(|state| {
        state.last_modified = Some("Wed, 21 Oct 2015 07:28:00 GMT".to_owned());
    });
    let mut remote =
        RemoteBlocklist::new(remote_config(&server, directory.path())).expect("remote");
    assert_eq!(remote.refresh_due().updated, 1);
    let report = remote.refresh_all();
    assert_eq!(report.not_modified, 1, "{report:?}");
    assert_eq!(
        server.last_request().if_modified_since.as_deref(),
        Some("Wed, 21 Oct 2015 07:28:00 GMT")
    );
}

#[test]
fn cache_survives_restart_and_is_private() {
    let directory = tempfile::tempdir().expect("tempdir");
    let server = MockHttpsSource::start("0.0.0.0 cached.test\n");
    server.update(|state| state.etag = Some("\"cache\"".to_owned()));
    let mut remote =
        RemoteBlocklist::new(remote_config(&server, directory.path())).expect("remote");
    assert_eq!(remote.refresh_due().updated, 1);
    drop(remote);

    let mut restarted =
        RemoteBlocklist::new(remote_config(&server, directory.path())).expect("restart");
    assert!(restarted.has_snapshot(), "cache must be loaded at startup");
    assert!(blocklist(&restarted, &[]).is_blocked(&name("cached.test")));
    assert_eq!(server.hits(), 1, "startup must not hit the network");

    let report = restarted.refresh_all();
    assert_eq!(report.not_modified, 1, "{report:?}");
    assert_eq!(
        server.last_request().if_none_match.as_deref(),
        Some("\"cache\"")
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let entries = std::fs::read_dir(directory.path()).expect("read cache dir");
        let mut files = 0_usize;
        for entry in entries {
            let entry = entry.expect("entry");
            let path = entry.path();
            if !path
                .extension()
                .is_some_and(|extension| extension == "list" || extension == "meta")
            {
                continue;
            }
            let mode = entry.metadata().expect("metadata").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "cache file {path:?} must be 0600");
            files = files.saturating_add(1);
        }
        assert!(files >= 2, "list and meta files expected");
    }
}

#[test]
fn fetch_error_keeps_previous_snapshot() {
    let directory = tempfile::tempdir().expect("tempdir");
    let server = MockHttpsSource::start("0.0.0.0 keep.test\n");
    let mut remote =
        RemoteBlocklist::new(remote_config(&server, directory.path())).expect("remote");
    assert_eq!(remote.refresh_due().updated, 1);
    server.update(|state| state.status = 500);

    let report = remote.refresh_all();
    assert_eq!(report.updated, 0);
    assert_eq!(report.failed, 1, "{report:?}");
    assert!(report.errors[0].error.contains("500"));
    assert!(remote.has_snapshot());
    assert!(blocklist(&remote, &[]).is_blocked(&name("keep.test")));
}

#[test]
fn size_limit_fails_without_snapshot() {
    let directory = tempfile::tempdir().expect("tempdir");
    let server = MockHttpsSource::start("0.0.0.0 huge.test\n".repeat(1024));
    let mut config = remote_config(&server, directory.path());
    config.max_bytes = 100;
    let mut remote = RemoteBlocklist::new(config).expect("remote");
    let report = remote.refresh_due();
    assert_eq!(report.failed, 1, "{report:?}");
    assert!(!remote.has_snapshot());
    assert!(report.errors[0].error.contains("exceeds"));
    assert_eq!(remote.texts(), Vec::new());
}

#[test]
fn redirects_are_disabled_by_default_and_restricted_when_enabled() {
    let directory = tempfile::tempdir().expect("tempdir");
    let server = MockHttpsSource::start("0.0.0.0 redirected.test\n");
    let target = server.url("/mirror");
    server.update(|state| {
        state.redirect = Some(target.clone());
        state.redirect_from = Some("/hosts".to_owned());
    });
    let mut config = remote_config(&server, directory.path());
    let mut remote = RemoteBlocklist::new(config.clone()).expect("remote");
    let report = remote.refresh_due();
    assert_eq!(report.failed, 1, "{report:?}");
    assert!(report.errors[0].error.contains("redirect"));

    config.allow_redirects = true;
    let mut remote = RemoteBlocklist::new(config).expect("remote");
    let report = remote.refresh_due();
    assert_eq!(report.updated, 1, "{report:?}");
    assert!(blocklist(&remote, &[]).is_blocked(&name("redirected.test")));
    assert_eq!(server.hits(), 3, "first request failed, redirect adds one");

    let directory = tempfile::tempdir().expect("tempdir");
    let server = MockHttpsSource::start("0.0.0.0 cross.test\n");
    server.update(|state| {
        state.redirect = Some("https://example.com/hosts".to_owned());
        state.redirect_from = Some("/hosts".to_owned());
    });
    let mut config = remote_config(&server, directory.path());
    config.allow_redirects = true;
    let mut remote = RemoteBlocklist::new(config).expect("remote");
    let report = remote.refresh_due();
    assert_eq!(report.failed, 1, "{report:?}");
    assert!(report.errors[0].error.contains("cross-host"));
}

#[test]
fn redirect_error_keeps_previous_snapshot() {
    let directory = tempfile::tempdir().expect("tempdir");
    let server = MockHttpsSource::start("0.0.0.0 before-redirect.test\n");
    let mut remote =
        RemoteBlocklist::new(remote_config(&server, directory.path())).expect("remote");
    assert_eq!(remote.refresh_due().updated, 1);
    server.update(|state| {
        state.redirect = Some(server.url("/mirror"));
        state.redirect_from = Some("/hosts".to_owned());
    });
    let report = remote.refresh_all();
    assert_eq!(report.failed, 1, "{report:?}");
    assert!(remote.has_snapshot());
    assert!(blocklist(&remote, &[]).is_blocked(&name("before-redirect.test")));
}

#[test]
fn https_only_and_private_host_guard() {
    let directory = tempfile::tempdir().expect("tempdir");
    let server = MockHttpsSource::start("0.0.0.0 guard.test\n");
    let mut config = remote_config(&server, directory.path());
    config.sources = vec![RemoteSource::new(format!(
        "http://127.0.0.1:{}/hosts",
        server.address().port()
    ))];
    assert!(matches!(
        RemoteBlocklist::new(config),
        Err(RemoteError::NotHttps(_))
    ));

    let mut config = remote_config(&server, directory.path());
    config.allow_hosts.clear();
    let mut remote = RemoteBlocklist::new(config).expect("remote");
    let report = remote.refresh_due();
    assert_eq!(report.failed, 1, "{report:?}");
    assert!(report.errors[0].error.contains("non-public"));
    assert_eq!(server.hits(), 0);

    let mut config = remote_config(&server, directory.path());
    config.allow_hosts = vec!["other.test".to_owned()];
    let mut remote = RemoteBlocklist::new(config).expect("remote");
    let report = remote.refresh_due();
    assert_eq!(report.failed, 1, "{report:?}");
    assert!(report.errors[0].error.contains("not allowed"));
}

#[test]
fn refresh_interval_gates_automatic_fetch() {
    let directory = tempfile::tempdir().expect("tempdir");
    let server = MockHttpsSource::start("0.0.0.0 interval.test\n");
    let mut config = remote_config(&server, directory.path());
    config.refresh_secs = 1;
    let mut remote = RemoteBlocklist::new(config).expect("remote");
    assert_eq!(remote.refresh_due().updated, 1);
    assert_eq!(remote.refresh_due().updated, 0, "not due yet");
    assert_eq!(server.hits(), 1);

    std::thread::sleep(Duration::from_millis(1_100));
    assert_eq!(remote.refresh_due().not_modified, 0);
    assert_eq!(server.hits(), 2, "second fetch after the interval");
    let status = remote.statuses().into_iter().next().expect("status");
    assert!(status.active);
    assert_eq!(status.refresh_secs, 1);
    assert!(status.next_refresh_in_secs.is_some());
}

#[test]
fn source_format_hosts_can_be_enforced_by_caller() {
    // Формат применяется при объединении: hosts-источник не добавляет
    // plain-домены, если вызывающий объявил `Hosts`.
    let directory = tempfile::tempdir().expect("tempdir");
    let server = MockHttpsSource::start("0.0.0.0 hosts.test\nplain.test\n");
    let mut remote =
        RemoteBlocklist::new(remote_config(&server, directory.path())).expect("remote");
    assert_eq!(remote.refresh_due().updated, 1);
    let texts = remote.texts();
    let list =
        Blocklist::load_combined(&[], &[(SourceFormat::Hosts, texts[0].1)], &[]).expect("combined");
    assert!(list.is_blocked(&name("hosts.test")));
    assert!(!list.is_blocked(&name("plain.test")));
}

#[test]
fn multiple_sources_are_merged() {
    let directory = tempfile::tempdir().expect("tempdir");
    let first = MockHttpsSource::start("0.0.0.0 first.test\n");
    let second = MockHttpsSource::start("0.0.0.0 second.test\n");
    let ca_path = directory.path().join("both-ca.pem");
    std::fs::write(
        &ca_path,
        format!("{}{}", first.cert_pem(), second.cert_pem()),
    )
    .expect("combined CA");
    let config = RemoteBlocklistConfig {
        sources: vec![
            RemoteSource::new(first.url("/hosts")),
            RemoteSource::new(second.url("/hosts")).with_format(SourceFormat::Hosts),
        ],
        refresh_secs: 3600,
        cache_dir: directory.path().join("cache"),
        max_bytes: 1024 * 1024,
        allow_redirects: false,
        allow_hosts: vec!["127.0.0.1".to_owned()],
        timeout: Duration::from_secs(5),
        retries: 0,
        backoff: Duration::from_millis(20),
        ca_file: Some(ca_path),
    };
    let mut remote = RemoteBlocklist::new(config).expect("remote");
    let report = remote.refresh_due();
    assert_eq!(report.updated, 2, "{report:?}");
    assert_eq!(remote.len(), 2);
    let list = blocklist(&remote, &[]);
    assert!(list.is_blocked(&name("first.test")));
    assert!(list.is_blocked(&name("second.test")));
    assert_eq!(first.hits() + second.hits(), 2);
}

#[test]
fn deadline_is_exposed_for_worker() {
    let directory = tempfile::tempdir().expect("tempdir");
    let server = MockHttpsSource::start("0.0.0.0 deadline.test\n");
    let config = remote_config(&server, directory.path());
    let remote = RemoteBlocklist::new(config).expect("remote");
    let deadline = remote.next_deadline().expect("deadline");
    assert!(deadline <= Instant::now() + Duration::from_secs(1));
}
