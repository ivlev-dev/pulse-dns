//! E2E: удалённый blocklist по HTTPS → NXDOMAIN через реальный UDP.

mod support;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};

use pulse_dns::{Name, Rcode, Rtype};
use pulseresolved::config::{BlocklistSourceSetting, Config, ControlToken, SourceFormatSetting};
use pulseresolved::server::Server;
use support::e2e::{SOCKET_TIMEOUT, wait_until};
use support::https_source::MockHttpsSource;
use support::{MockUpstream, base_config, make_query, positive_response, udp_query_retry};

const TOKEN: &str = "remote-blocklist-token";

fn positive_upstream() -> MockUpstream {
    MockUpstream::start(|request| {
        let name = request
            .questions()
            .first()
            .map(|question| question.qname().to_string())
            .unwrap_or_default();
        Some(positive_response(
            request,
            support::a_record(&name, [203, 0, 113, 9], 60),
        ))
    })
}

fn remote_config(upstream: SocketAddr, url: String, ca_file: &Path, cache_dir: &Path) -> Config {
    let mut config = base_config(upstream);
    config.blocklist.sources = vec![BlocklistSourceSetting {
        url,
        refresh_secs: Some(3600),
        format: SourceFormatSetting::Auto,
    }];
    config.blocklist.cache_dir = Some(cache_dir.to_path_buf());
    config.blocklist.allow_hosts = vec!["127.0.0.1".to_owned()];
    config.blocklist.ca_file = Some(ca_file.to_path_buf());
    config.blocklist.timeout_ms = 3_000;
    config.blocklist.retries = 0;
    config.blocklist.refresh_secs = 3600;
    config
}

fn wait_blocked(server: &Server, value: &str) {
    wait_until(
        "remote blocklist snapshot",
        || {
            format!(
                "entries={} statuses={:?}",
                server.resolver().blocklist().len(),
                server.blocklist_remote_statuses()
            )
        },
        || {
            server
                .resolver()
                .blocklist()
                .is_blocked(&Name::parse(value).expect("name"))
        },
    );
}

fn query(server: &Server, name: &str) -> pulse_dns::Message {
    udp_query_retry(
        server.udp_addr().expect("udp"),
        &make_query(name, Rtype::A, None),
        "remote blocklist UDP",
    )
}

fn http_get(addr: SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect metrics");
    stream
        .set_read_timeout(Some(SOCKET_TIMEOUT))
        .expect("read timeout");
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).expect("write request");
    stream.flush().expect("flush");
    let mut body = Vec::new();
    stream.read_to_end(&mut body).expect("read metrics");
    String::from_utf8_lossy(&body).into_owned()
}

fn control_request(addr: SocketAddr, method: &str, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect control");
    stream
        .set_read_timeout(Some(SOCKET_TIMEOUT))
        .expect("read timeout");
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {TOKEN}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).expect("write control");
    stream.flush().expect("flush");
    let mut body = Vec::new();
    stream.read_to_end(&mut body).expect("read control");
    String::from_utf8_lossy(&body).into_owned()
}

#[test]
fn remote_blocklist_blocks_hosts_and_subdomains_via_udp() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mock = MockHttpsSource::start("# hosts\n0.0.0.0 ads.test\n0.0.0.0 *.wild.test\n");
    let ca = mock.write_ca(directory.path());
    let cache: PathBuf = directory.path().join("cache");
    let upstream = positive_upstream();
    let mut config = remote_config(upstream.address(), mock.url("/hosts"), &ca, &cache);
    let local = directory.path().join("local-blocklist.txt");
    std::fs::write(&local, "local-only.test\n").expect("local blocklist");
    config.blocklist.paths = vec![local];
    config.blocklist.allowlist = vec!["safe.ads.test".to_owned()];
    config.metrics_listen = Some("127.0.0.1:0".parse().expect("metrics"));
    let server = Server::start(&config).expect("server");
    wait_blocked(&server, "ads.test");
    wait_blocked(&server, "local-only.test");

    assert_eq!(query(&server, "ads.test").rcode(), Rcode::NXDOMAIN);
    assert_eq!(query(&server, "local-only.test").rcode(), Rcode::NXDOMAIN);
    assert_eq!(query(&server, "deep.sub.ads.test").rcode(), Rcode::NXDOMAIN);
    assert_eq!(query(&server, "x.wild.test").rcode(), Rcode::NXDOMAIN);
    assert_eq!(upstream.hits(), 0, "blocked names must not reach upstream");
    assert!(
        !server
            .resolver()
            .blocklist()
            .is_blocked(&Name::parse("wild.test").expect("name"))
    );

    let allowed = query(&server, "safe.ads.test");
    assert_eq!(allowed.rcode(), Rcode::NOERROR);
    assert_eq!(upstream.hits(), 1, "allowlist must win over blocklist");

    let metrics = http_get(server.metrics_addr().expect("metrics enabled"), "/metrics");
    assert!(metrics.contains("pulseresolved_blocklist_fetch_total{result=\"updated\"}"));
    assert!(metrics.contains("pulseresolved_blocklist_last_success_ts"));
    let entries = metrics
        .lines()
        .find_map(|line| line.strip_prefix("pulseresolved_blocklist_entries "))
        .and_then(|value| value.parse::<u64>().ok())
        .expect("entries metric");
    assert!(entries >= 3, "entries={entries}");
    assert!(server.stats().blocklist_fetch_updated >= 1);
    assert!(server.stats().blocklist_last_success_ts > 0);
}

#[test]
fn periodic_refresh_applies_new_hosts() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mock = MockHttpsSource::start("0.0.0.0 old.test\n");
    let ca = mock.write_ca(directory.path());
    let cache = directory.path().join("cache");
    let upstream = positive_upstream();
    let mut config = remote_config(upstream.address(), mock.url("/hosts"), &ca, &cache);
    config.blocklist.sources[0].refresh_secs = Some(1);
    config.blocklist.refresh_secs = 1;
    let server = Server::start(&config).expect("server");
    wait_blocked(&server, "old.test");

    mock.update(|state| state.body = b"0.0.0.0 periodic.test\n".to_vec());
    wait_blocked(&server, "periodic.test");
    assert_eq!(query(&server, "periodic.test").rcode(), Rcode::NXDOMAIN);
    assert!(
        !server
            .resolver()
            .blocklist()
            .is_blocked(&Name::parse("old.test").expect("name"))
    );
}

#[test]
fn sighup_reload_path_fetches_immediately() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mock = MockHttpsSource::start("0.0.0.0 before.test\n");
    let ca = mock.write_ca(directory.path());
    let cache = directory.path().join("cache");
    let upstream = positive_upstream();
    let config = remote_config(upstream.address(), mock.url("/hosts"), &ca, &cache);
    let server = Server::start(&config).expect("server");
    wait_blocked(&server, "before.test");

    mock.update(|state| state.body = b"0.0.0.0 after.test\n".to_vec());
    let outcome = server.reload();
    outcome.blocklist.expect("blocklist reload");
    assert!(
        server
            .resolver()
            .blocklist()
            .is_blocked(&Name::parse("after.test").expect("name"))
    );
    assert!(
        !server
            .resolver()
            .blocklist()
            .is_blocked(&Name::parse("before.test").expect("name"))
    );
    assert_eq!(query(&server, "after.test").rcode(), Rcode::NXDOMAIN);
}

#[test]
fn control_api_reloads_remote_source() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mock = MockHttpsSource::start("0.0.0.0 api-before.test\n");
    let ca = mock.write_ca(directory.path());
    let cache = directory.path().join("cache");
    let upstream = positive_upstream();
    let mut config = remote_config(upstream.address(), mock.url("/hosts"), &ca, &cache);
    config.control_listen = Some("127.0.0.1:0".parse().expect("control"));
    config.control_token = Some(ControlToken::new(TOKEN));
    let server = Server::start(&config).expect("server");
    wait_blocked(&server, "api-before.test");
    let control = server.control_addr().expect("control enabled");

    mock.update(|state| state.body = b"0.0.0.0 api-after.test\n".to_vec());
    let response = control_request(control, "POST", "/api/v1/blocklist/reload");
    assert!(response.contains("200 OK"), "{response}");
    assert!(
        server
            .resolver()
            .blocklist()
            .is_blocked(&Name::parse("api-after.test").expect("name"))
    );
    let listing = control_request(control, "GET", "/api/v1/blocklist");
    assert!(listing.contains("\"remote\""), "{listing}");
}

#[test]
fn restart_uses_cache_before_network() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mock = MockHttpsSource::start("0.0.0.0 cached-remote.test\n");
    let ca = mock.write_ca(directory.path());
    let cache = directory.path().join("cache");
    let url = mock.url("/hosts");
    let upstream = positive_upstream();
    let config = remote_config(upstream.address(), url.clone(), &ca, &cache);
    let mut first = Server::start(&config).expect("first server");
    wait_blocked(&first, "cached-remote.test");
    first.shutdown().expect("shutdown first");

    drop(mock);
    let config = remote_config(upstream.address(), url, &ca, &cache);
    let second = Server::start(&config).expect("second server");
    assert!(
        second
            .resolver()
            .blocklist()
            .is_blocked(&Name::parse("cached-remote.test").expect("name")),
        "cache must be applied synchronously at startup"
    );
    let statuses = second.blocklist_remote_statuses();
    assert_eq!(statuses.len(), 1);
    assert!(statuses[0].active);
    assert_eq!(
        query(&second, "cached-remote.test").rcode(),
        Rcode::NXDOMAIN
    );
    assert_eq!(upstream.hits(), 0);
}
