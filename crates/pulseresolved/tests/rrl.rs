//! E2E RRL: флуд NXDOMAIN/referral ограничивается по классам, легитимный
//! трафик не страдает, slip/truncate работают, метрики видны в `/metrics`.

mod support;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use pulse_dns::{Message, Rcode};
use pulseresolved::config::{
    Config, RateLimitAction, RrlRateSetting, RrlSetting, UpstreamPoolSetting,
};
use pulseresolved::server::Server;

use support::{
    MockUpstream, a_record, make_query, nxdomain_response, positive_response, udp_query,
};

const SHORT: Duration = Duration::from_millis(180);

fn nxdomain_upstream() -> MockUpstream {
    MockUpstream::start(|request| Some(nxdomain_response(request, "example.test")))
}

fn referral_upstream() -> MockUpstream {
    MockUpstream::start(|request| {
        let mut response = support::referral_response(request);
        response.add_authority(support::ns("example.test", 300, "ns1.example.test"));
        Some(response)
    })
}

fn strict_nxdomain_rrl(slip: u32, action: RateLimitAction) -> RrlSetting {
    RrlSetting {
        enabled: true,
        slip,
        max_entries: 1_000,
        action,
        nxdomain: RrlRateSetting {
            qps: 0.001,
            burst: 2,
        },
        ..RrlSetting::default()
    }
}

fn server_config(upstream: SocketAddr, rrl: RrlSetting) -> Config {
    let mut config = support::base_config(upstream);
    config.rate_limit = None;
    config.rrl = Some(rrl);
    config.upstream_pool = UpstreamPoolSetting::default();
    config
}

fn query(server: &Server, name: &str) -> Option<Message> {
    let address = server.udp_addr().expect("udp");
    let request = make_query(name, pulse_dns::Rtype::A, None);
    udp_query(address, &request, SHORT)
}

#[test]
fn nxdomain_flood_is_limited_and_legit_names_pass() {
    let upstream = nxdomain_upstream();
    let config = server_config(
        upstream.address(),
        strict_nxdomain_rrl(1, RateLimitAction::Truncate),
    );
    let mut server = Server::start(&config).expect("server");

    for index in 0..2 {
        let response = query(&server, "flood.example.test").expect("allowed");
        assert_eq!(response.rcode(), Rcode::NXDOMAIN, "query {index}");
        assert!(!response.flags().tc());
    }
    for index in 0..4 {
        let response = query(&server, "flood.example.test").expect("slipped");
        assert!(response.flags().tc(), "query {index} must be truncated");
        assert_eq!(response.answers().len(), 0);
    }

    // Другая зона — отдельный бакет, ответ не ограничен.
    let legit = query(&server, "legit.other.test").expect("legit response");
    assert_eq!(legit.rcode(), Rcode::NXDOMAIN);
    assert!(!legit.flags().tc());

    let stats = server.rrl_stats().expect("rrl enabled");
    assert_eq!(stats.nxdomain.limited, 4);
    assert_eq!(stats.nxdomain.slipped, 4);
    assert_eq!(stats.noerror.limited, 0);
    server.shutdown().expect("shutdown");
}

#[test]
fn slip_sends_only_every_nth_limited_response() {
    let upstream = nxdomain_upstream();
    let config = server_config(
        upstream.address(),
        strict_nxdomain_rrl(2, RateLimitAction::Truncate),
    );
    let mut server = Server::start(&config).expect("server");

    for _ in 0..2 {
        let response = query(&server, "slip.example.test").expect("allowed");
        assert_eq!(response.rcode(), Rcode::NXDOMAIN);
    }
    assert!(query(&server, "slip.example.test").is_none(), "first drop");
    let slipped = query(&server, "slip.example.test").expect("second slip");
    assert!(slipped.flags().tc());
    assert!(query(&server, "slip.example.test").is_none(), "third drop");
    let slipped = query(&server, "slip.example.test").expect("fourth slip");
    assert!(slipped.flags().tc());

    let stats = server.rrl_stats().expect("rrl");
    assert_eq!(stats.nxdomain.limited, 4);
    assert_eq!(stats.nxdomain.slipped, 2);
    assert_eq!(stats.nxdomain.dropped, 2);
    server.shutdown().expect("shutdown");
}

#[test]
fn referral_flood_is_limited_and_refused() {
    let upstream = referral_upstream();
    let mut setting = RrlSetting {
        slip: 1,
        action: RateLimitAction::Refused,
        ..RrlSetting::default()
    };
    setting.referral = RrlRateSetting {
        qps: 0.001,
        burst: 1,
    };
    let config = server_config(upstream.address(), setting);
    let mut server = Server::start(&config).expect("server");

    let first = query(&server, "referral.example.test").expect("first referral");
    assert_eq!(first.rcode(), Rcode::NOERROR);
    assert!(!first.flags().tc());
    assert_eq!(first.answers().len(), 0);
    for _ in 0..3 {
        let response = query(&server, "referral.example.test").expect("refused");
        assert_eq!(response.rcode(), Rcode::REFUSED);
    }

    let stats = server.rrl_stats().expect("rrl");
    assert_eq!(stats.referral.limited, 3);
    assert_eq!(stats.referral.slipped, 3);
    assert_eq!(stats.nxdomain.limited, 0);
    server.shutdown().expect("shutdown");
}

#[test]
fn positive_answers_are_not_limited_by_nxdomain_bucket() {
    let upstream = MockUpstream::start(|request| {
        Some(positive_response(
            request,
            a_record("positive.example.test", [192, 0, 2, 1], 300),
        ))
    });
    let config = server_config(
        upstream.address(),
        strict_nxdomain_rrl(1, RateLimitAction::Truncate),
    );
    let mut server = Server::start(&config).expect("server");
    for index in 0..6 {
        let name = format!("positive-{index}.example.test");
        let response = query(&server, &name).expect("positive");
        assert_eq!(response.rcode(), Rcode::NOERROR, "query {index}");
        assert!(!response.flags().tc(), "query {index}");
        assert_eq!(response.answers().len(), 1);
    }
    assert_eq!(server.rrl_stats().expect("rrl").noerror.limited, 0);
    server.shutdown().expect("shutdown");
}

#[test]
fn metrics_expose_rrl_classes() {
    let upstream = nxdomain_upstream();
    let mut config = server_config(
        upstream.address(),
        strict_nxdomain_rrl(1, RateLimitAction::Truncate),
    );
    config.metrics_listen = Some("127.0.0.1:0".parse().expect("metrics addr"));
    let mut server = Server::start(&config).expect("server");

    for _ in 0..4 {
        let _ = query(&server, "metrics.example.test");
    }
    let metrics_addr = server.metrics_addr().expect("metrics");
    let text = http_get(metrics_addr, "/metrics");
    assert!(text.contains("200 OK"));
    assert!(
        text.contains("pulseresolved_rrl_limited_total{class=\"nxdomain\"} 2"),
        "{text}"
    );
    assert!(text.contains("pulseresolved_rrl_slipped_total{class=\"nxdomain\"}"));
    assert!(text.contains("pulseresolved_rrl_dropped_total{class=\"nxdomain\"}"));
    assert!(text.contains("pulseresolved_rrl_entries"));
    assert!(text.contains("pulseresolved_upstream_pool_opens_total"));
    server.shutdown().expect("shutdown");
}

fn http_get(addr: SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect metrics");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    write!(stream, "GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").expect("request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("response");
    response
}

#[test]
fn server_keeps_rrl_disabled_by_default() {
    let upstream = nxdomain_upstream();
    let mut config = support::base_config(upstream.address());
    config.rate_limit = None;
    let mut server = Server::start(&config).expect("server");
    assert!(server.rrl_stats().is_none());
    for _ in 0..5 {
        let response = query(&server, "plain.example.test").expect("response");
        assert_eq!(response.rcode(), Rcode::NXDOMAIN);
    }
    server.shutdown().expect("shutdown");
}
