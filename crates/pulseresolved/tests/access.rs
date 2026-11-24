//! ACL клиентов и per-source rate limit (RRL-подобное ограничение).

mod support;

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use pulse_dns::{DecodeLimits, EncodeOptions, Message, Rcode};
use pulseresolved::config::{Config, RateLimitAction, RateLimitSetting};
use pulseresolved::server::Server;
use pulseresolved::stats::StatsSnapshot;

use support::e2e::{self, SOCKET_TIMEOUT};
use support::{MockUpstream, a_record, base_config, make_query, positive_response};

fn upstream() -> MockUpstream {
    MockUpstream::start(|request| {
        let record = a_record("example.com", [192, 0, 2, 1], 60);
        Some(positive_response(request, record))
    })
}

fn udp_from(
    source: &str,
    server: SocketAddr,
    request: &Message,
    timeout: Duration,
) -> Option<Message> {
    let socket = UdpSocket::bind(source).expect("bind source");
    socket
        .set_read_timeout(Some(timeout))
        .expect("read timeout");
    let bytes = request.encode(&EncodeOptions::default()).expect("encode");
    e2e::send_to(&socket, &bytes, server).expect("send");
    let mut buffer = [0_u8; 4096];
    let (length, _) = e2e::recv_from(&socket, &mut buffer).ok()?;
    Message::decode(buffer.get(..length)?, &DecodeLimits::default()).ok()
}

fn access_config(upstream: SocketAddr) -> Config {
    let mut config = base_config(upstream);
    config.listen_tcp = None;
    config.allow_from = vec!["127.0.0.0/8".to_owned()];
    config
}

#[test]
fn acl_refuses_non_allowed_client_and_counts_metric() {
    let upstream = upstream();
    let mut config = access_config(upstream.address());
    config.allow_from = vec!["127.0.0.1".to_owned()];
    let server = Server::start(&config).expect("server");
    let address = server.udp_addr().expect("udp");
    let request = make_query("example.com", pulse_dns::Rtype::A, None);

    let allowed =
        udp_from("127.0.0.1:0", address, &request, SOCKET_TIMEOUT).expect("allowed response");
    assert_eq!(allowed.rcode(), Rcode::NOERROR);
    assert_eq!(allowed.answers().len(), 1);

    let refused =
        udp_from("127.0.0.2:0", address, &request, SOCKET_TIMEOUT).expect("refused response");
    assert_eq!(refused.rcode(), Rcode::REFUSED);

    let stats: StatsSnapshot = server.stats();
    assert!(stats.refused_acl >= 1, "refused_acl counter");
    assert!(stats.refused >= 1, "generic refused counter");
    drop(server);
}

#[test]
fn default_acl_is_loopback_only() {
    let acl = Config::default().build_acl().expect("default acl");
    assert!(acl.allows("127.0.0.1".parse().expect("ip")));
    assert!(acl.allows("127.0.0.2".parse().expect("ip")));
    assert!(acl.allows("::1".parse().expect("ip")));
    assert!(!acl.allows("192.0.2.1".parse().expect("ip")));
    assert!(!acl.allows("2001:db8::1".parse().expect("ip")));
}

#[test]
fn rate_limit_isolated_per_source_ip() {
    let upstream = upstream();
    let mut config = access_config(upstream.address());
    config.rate_limit = Some(RateLimitSetting {
        enabled: true,
        qps: 0.001,
        burst: 2,
        max_entries: 64,
        action: RateLimitAction::Refused,
    });
    let server = Server::start(&config).expect("server");
    let address = server.udp_addr().expect("udp");
    let request = make_query("flood.example.com", pulse_dns::Rtype::A, None);

    let first = udp_from("127.0.0.2:0", address, &request, SOCKET_TIMEOUT).expect("first");
    let second = udp_from("127.0.0.2:0", address, &request, SOCKET_TIMEOUT).expect("second");
    assert_eq!(first.rcode(), Rcode::NOERROR);
    assert_eq!(second.rcode(), Rcode::NOERROR, "burst must pass");

    let mut limited = 0_usize;
    for _ in 0..4 {
        let response =
            udp_from("127.0.0.2:0", address, &request, SOCKET_TIMEOUT).expect("limited response");
        if response.rcode() == Rcode::REFUSED {
            limited += 1;
        }
    }
    assert_eq!(limited, 4, "flood from one source must be limited");

    let other = udp_from("127.0.0.3:0", address, &request, SOCKET_TIMEOUT).expect("other source");
    assert_eq!(
        other.rcode(),
        Rcode::NOERROR,
        "another source IP must not be affected"
    );

    let stats = server.stats();
    assert!(stats.rate_limited >= 4);
    assert!(stats.rate_limit_refused >= 4);
    drop(server);
}

#[test]
fn rate_limit_drop_policy_sends_nothing() {
    let upstream = upstream();
    let mut config = access_config(upstream.address());
    config.rate_limit = Some(RateLimitSetting {
        enabled: true,
        qps: 0.001,
        burst: 1,
        max_entries: 32,
        action: RateLimitAction::Drop,
    });
    let server = Server::start(&config).expect("server");
    let address = server.udp_addr().expect("udp");
    let request = make_query("drop.example.com", pulse_dns::Rtype::A, None);

    assert!(
        udp_from("127.0.0.4:0", address, &request, SOCKET_TIMEOUT).is_some(),
        "burst token is available"
    );
    assert!(
        udp_from("127.0.0.4:0", address, &request, Duration::from_millis(200)).is_none(),
        "drop policy must not answer"
    );
    assert!(server.stats().rate_limit_dropped >= 1);
    drop(server);
}

#[test]
fn rate_limit_truncate_policy_sets_tc() {
    let upstream = upstream();
    let mut config = access_config(upstream.address());
    config.rate_limit = Some(RateLimitSetting {
        enabled: true,
        qps: 0.001,
        burst: 1,
        max_entries: 32,
        action: RateLimitAction::Truncate,
    });
    let server = Server::start(&config).expect("server");
    let address = server.udp_addr().expect("udp");
    let request = make_query("trace.example.com", pulse_dns::Rtype::A, None);

    let first = udp_from("127.0.0.5:0", address, &request, SOCKET_TIMEOUT).expect("first");
    assert!(!first.flags().tc());
    let limited = udp_from("127.0.0.5:0", address, &request, SOCKET_TIMEOUT).expect("limited");
    assert!(limited.flags().tc(), "truncate policy must set TC");
    assert_eq!(limited.answers().len(), 0);
    assert!(server.stats().rate_limit_truncated >= 1);
    drop(server);
}
