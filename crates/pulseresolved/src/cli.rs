//! CLI и жизненный цикл процесса.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use pulse_resolver::UpstreamConfig;
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
use signal_hook::iterator::Signals;

use crate::config::{Config, LogLevel, Overrides};
use crate::error::ServerError;
use crate::logging;
use crate::server::Server;

pub(crate) fn run() -> ExitCode {
    logging::init(LogLevel::Info);
    let matches = command().get_matches();
    let overrides = overrides(&matches);
    let config_path = matches
        .get_one::<PathBuf>("config")
        .cloned()
        .unwrap_or_else(|| PathBuf::from("examples/resolver.toml"));
    let mut config = match Config::from_path(&config_path) {
        Ok(config) => config,
        Err(error) => {
            logging::error("config", &error.to_string());
            return ExitCode::from(2);
        }
    };
    config.apply_overrides(&overrides);
    logging::init(config.log_level);
    if let Err(error) = config.validate() {
        logging::error("config", &error.to_string());
        return ExitCode::from(2);
    }

    let mut server = match Server::start(&config) {
        Ok(server) => server,
        Err(error) => {
            logging::error("startup", &error.to_string());
            return server_exit_code(&error);
        }
    };
    logging::info(
        "startup",
        &format!(
            "pulseresolved {} listening: udp={:?} tcp={:?} dot={:?} doh={:?} doh2={:?} doq={:?} dnscrypt_udp={:?} dnscrypt_tcp={:?} metrics={:?} control={:?} workers={:?} backend={:?}",
            env!("CARGO_PKG_VERSION"),
            server.udp_addr(),
            server.tcp_addr(),
            server.dot_addr(),
            server.doh_addr(),
            server.doh2_addr(),
            server.doq_addr(),
            server.dnscrypt_udp_addr(),
            server.dnscrypt_tcp_addr(),
            server.metrics_addr(),
            server.control_addr(),
            server.udp_workers(),
            server.udp_backend()
        ),
    );

    let mut signals = match Signals::new([SIGINT, SIGTERM, SIGHUP]) {
        Ok(signals) => signals,
        Err(error) => {
            logging::error(
                "signal",
                &format!("cannot install signal handlers: {error}"),
            );
            let _ = server.shutdown();
            return ExitCode::from(1);
        }
    };
    for signal in signals.forever() {
        match signal {
            SIGHUP => {
                logging::warn(
                    "signal",
                    "received SIGHUP, reloading blocklist and TLS certificate",
                );
                let outcome = server.reload();
                if let Err(error) = &outcome.blocklist {
                    logging::error("blocklist", &error.to_string());
                }
                match &outcome.tls {
                    Ok(()) => logging::info("tls", "certificate reloaded"),
                    Err(message) => logging::error("tls", message),
                }
            }
            SIGINT | SIGTERM => {
                logging::warn(
                    "signal",
                    &format!("received signal {signal}, starting graceful shutdown"),
                );
                break;
            }
            _ => {}
        }
    }

    let udp_stats = server.udp_stats();
    let shutdown_result = server.shutdown();
    let stats = server.stats();
    let resolver_stats = server.resolver_stats();
    logging::info(
        "stats",
        &format!(
            "queries(udp={},tcp={},dot={},doh={},doh2={},doq={},dnscrypt_udp={},dnscrypt_tcp={}) responses(udp={},tcp={},dot={},doh={},doh2={},doq={},dnscrypt_udp={},dnscrypt_tcp={}) decode_errors={} encode_errors={} formerr={} refused={} refused_acl={} rate_limited={} truncated={} dropped={}",
            stats.udp_queries,
            stats.tcp_queries,
            stats.dot_queries,
            stats.doh_queries,
            stats.doh_http2_queries,
            stats.doq_queries,
            stats.dnscrypt_udp_queries,
            stats.dnscrypt_tcp_queries,
            stats.udp_responses,
            stats.tcp_responses,
            stats.dot_responses,
            stats.doh_responses,
            stats.doh_http2_responses,
            stats.doq_responses,
            stats.dnscrypt_udp_responses,
            stats.dnscrypt_tcp_responses,
            stats.decode_errors,
            stats.encode_errors,
            stats.formerr,
            stats.refused,
            stats.refused_acl,
            stats.rate_limited,
            stats.truncated,
            stats.dropped
        ),
    );
    logging::info(
        "resolver_stats",
        &format!(
            "queries={} servfail={} blocked={} overridden={} dnssec(secure={},insecure={},bogus={}) cache(hits={},misses={},entries={})",
            resolver_stats.queries,
            resolver_stats.servfail,
            resolver_stats.blocked,
            resolver_stats.overridden,
            resolver_stats.dnssec_secure,
            resolver_stats.dnssec_insecure,
            resolver_stats.dnssec_bogus,
            resolver_stats.cache.hits,
            resolver_stats.cache.misses,
            resolver_stats.cache.entries
        ),
    );
    if let Some(udp_stats) = udp_stats {
        logging::info(
            "udp_stats",
            &format!(
                "received={} sent={} recv_errors={} send_errors={} dropped={} oversize={} panics={}",
                udp_stats.total.packets_received,
                udp_stats.total.packets_sent,
                udp_stats.total.recv_errors,
                udp_stats.total.send_errors,
                udp_stats.total.responses_dropped,
                udp_stats.total.oversize_received,
                udp_stats.total.handler_panics
            ),
        );
    }
    match shutdown_result {
        Ok(()) => {
            logging::info("shutdown", "stopped cleanly");
            ExitCode::SUCCESS
        }
        Err(error) => {
            logging::error("shutdown", &error.to_string());
            ExitCode::from(1)
        }
    }
}

fn overrides(matches: &ArgMatches) -> Overrides {
    Overrides {
        listen_udp: matches.get_one::<SocketAddr>("listen-udp").copied(),
        listen_tcp: matches.get_one::<SocketAddr>("listen-tcp").copied(),
        dot_listen: matches.get_one::<SocketAddr>("dot-listen").copied(),
        doh_listen: matches.get_one::<SocketAddr>("doh-listen").copied(),
        doh2_listen: matches.get_one::<SocketAddr>("doh2-listen").copied(),
        doq_listen: matches.get_one::<SocketAddr>("doq-listen").copied(),
        dnscrypt_listen: matches.get_one::<SocketAddr>("dnscrypt-listen").copied(),
        dnscrypt_tcp_listen: matches
            .get_one::<SocketAddr>("dnscrypt-tcp-listen")
            .copied(),
        tls_cert: matches.get_one::<PathBuf>("tls-cert").cloned(),
        tls_key: matches.get_one::<PathBuf>("tls-key").cloned(),
        metrics_listen: matches.get_one::<SocketAddr>("metrics-listen").copied(),
        workers: matches.get_one::<usize>("workers").copied(),
        control_cpu_affinity: matches
            .get_one::<Vec<usize>>("control-cpu-affinity")
            .cloned(),
        forwarders: matches
            .get_many::<SocketAddr>("forward")
            .map(|values| values.copied().collect())
            .unwrap_or_default(),
        upstreams: matches
            .get_many::<UpstreamConfig>("upstream")
            .map(|values| values.cloned().collect())
            .unwrap_or_default(),
        blocklists: matches
            .get_many::<PathBuf>("blocklist")
            .map(|values| values.cloned().collect())
            .unwrap_or_default(),
        trust_anchor: matches.get_one::<PathBuf>("trust-anchor").cloned(),
        trust_anchor_state: matches.get_one::<PathBuf>("trust-anchor-state").cloned(),
        trust_anchor_hold_down: matches.get_one::<u32>("trust-anchor-hold-down").copied(),
        no_dnssec: matches.get_flag("no-dnssec"),
        log_level: matches.get_one::<LogLevel>("log-level").copied(),
    }
}

fn server_exit_code(error: &ServerError) -> ExitCode {
    match error {
        ServerError::Config(_)
        | ServerError::Resolver(_)
        | ServerError::Affinity(_)
        | ServerError::BlocklistRemote(_) => ExitCode::from(2),
        ServerError::Udp(_)
        | ServerError::TcpStart { .. }
        | ServerError::Tcp(_)
        | ServerError::MetricsStart { .. }
        | ServerError::ControlStart { .. }
        | ServerError::Reload(_)
        | ServerError::SecureStart { .. }
        | ServerError::Secure { .. }
        | ServerError::Dnscrypt(_) => ExitCode::from(1),
    }
}

fn parse_upstream(value: &str) -> Result<UpstreamConfig, String> {
    UpstreamConfig::parse(value).map_err(|error| error.to_string())
}

fn parse_forwarder(value: &str) -> Result<SocketAddr, String> {
    let trimmed = value.trim();
    if let Ok(addr) = trimmed.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }
    Err(format!("expected an IP address or IP:port, got {value:?}"))
}

/// Разобрать список CPU для clap (`"0,2,4-7"`).
fn parse_cpu_list(value: &str) -> Result<Vec<usize>, String> {
    pulse_runtime::affinity::parse_list(value)
}

fn command() -> Command {
    Command::new("pulseresolved")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Caching DNS resolver: UDP/TCP/DoT/DoH/DoQ/DNSCrypt, blocklist, overrides")
        .arg(
            Arg::new("config")
                .long("config")
                .value_name("PATH")
                .default_value("examples/resolver.toml")
                .value_parser(value_parser!(PathBuf))
                .help("Path to the TOML (or legacy JSON) configuration file"),
        )
        .arg(
            Arg::new("listen-udp")
                .long("listen-udp")
                .value_name("ADDR")
                .value_parser(value_parser!(SocketAddr))
                .help("Override UDP listen address, e.g. 127.0.0.1:5353"),
        )
        .arg(
            Arg::new("listen-tcp")
                .long("listen-tcp")
                .value_name("ADDR")
                .value_parser(value_parser!(SocketAddr))
                .help("Override TCP listen address, e.g. 127.0.0.1:5353"),
        )
        .arg(
            Arg::new("dot-listen")
                .long("dot-listen")
                .value_name("ADDR")
                .value_parser(value_parser!(SocketAddr))
                .help("Enable DNS over TLS on ADDR, e.g. 0.0.0.0:853"),
        )
        .arg(
            Arg::new("doh-listen")
                .long("doh-listen")
                .value_name("ADDR")
                .value_parser(value_parser!(SocketAddr))
                .help("Enable DNS over HTTPS/1.1 on ADDR, e.g. 0.0.0.0:443"),
        )
        .arg(
            Arg::new("doh2-listen")
                .long("doh2-listen")
                .value_name("ADDR")
                .value_parser(value_parser!(SocketAddr))
                .help("Enable DNS over HTTPS/2 on ADDR, e.g. 0.0.0.0:8443"),
        )
        .arg(
            Arg::new("doq-listen")
                .long("doq-listen")
                .value_name("ADDR")
                .value_parser(value_parser!(SocketAddr))
                .help("Enable DNS over QUIC on ADDR, e.g. 0.0.0.0:8853"),
        )
        .arg(
            Arg::new("dnscrypt-listen")
                .long("dnscrypt-listen")
                .value_name("ADDR")
                .value_parser(value_parser!(SocketAddr))
                .help("Enable DNSCrypt v2 over UDP on ADDR"),
        )
        .arg(
            Arg::new("dnscrypt-tcp-listen")
                .long("dnscrypt-tcp-listen")
                .value_name("ADDR")
                .value_parser(value_parser!(SocketAddr))
                .help("Enable DNSCrypt v2 over TCP on ADDR"),
        )
        .arg(
            Arg::new("tls-cert")
                .long("tls-cert")
                .value_name("PATH")
                .value_parser(value_parser!(PathBuf))
                .help("PEM certificate chain for DoT/DoH/DoQ"),
        )
        .arg(
            Arg::new("tls-key")
                .long("tls-key")
                .value_name("PATH")
                .value_parser(value_parser!(PathBuf))
                .help("PEM private key for DoT/DoH/DoQ (mode 0600)"),
        )
        .arg(
            Arg::new("metrics-listen")
                .long("metrics-listen")
                .value_name("ADDR")
                .value_parser(value_parser!(SocketAddr))
                .help("Enable GET /metrics and GET /healthz on a loopback address"),
        )
        .arg(
            Arg::new("forward")
                .long("forward")
                .value_name("ADDR")
                .action(ArgAction::Append)
                .value_parser(parse_forwarder)
                .help("Forwarder address (repeatable); switches to forward mode"),
        )
        .arg(
            Arg::new("upstream")
                .long("upstream")
                .value_name("URL")
                .action(ArgAction::Append)
                .value_parser(parse_upstream)
                .help("Upstream URL: udp://addr, tcp://addr, tls://host:853#name or https://host/dns-query (repeatable)"),
        )
        .arg(
            Arg::new("workers")
                .long("workers")
                .value_name("N")
                .value_parser(value_parser!(usize))
                .help("Override the number of UDP workers (0 = available parallelism)"),
        )
        .arg(
            Arg::new("control-cpu-affinity")
                .long("control-cpu-affinity")
                .value_name("LIST")
                .value_parser(parse_cpu_list)
                .help("Pin resolver workers to CPUs: \"0,2,4-7\" (intersected with the process mask)"),
        )
        .arg(
            Arg::new("log-level")
                .long("log-level")
                .value_name("LEVEL")
                .value_parser(value_parser!(LogLevel))
                .help("Override log level: error, warn, info, debug or trace"),
        )
        .arg(
            Arg::new("blocklist")
                .long("blocklist")
                .value_name("PATH")
                .action(ArgAction::Append)
                .value_parser(value_parser!(PathBuf))
                .help("Add a blocklist file; repeatable"),
        )
        .arg(
            Arg::new("no-dnssec")
                .long("no-dnssec")
                .action(ArgAction::SetTrue)
                .help("Disable DNSSEC validation"),
        )
        .arg(
            Arg::new("trust-anchor")
                .long("trust-anchor")
                .value_name("PATH")
                .value_parser(value_parser!(PathBuf))
                .help("DS file with explicit trust anchors; enables DNSSEC validation"),
        )
        .arg(
            Arg::new("trust-anchor-state")
                .long("trust-anchor-state")
                .value_name("PATH")
                .value_parser(value_parser!(PathBuf))
                .help("RFC 5011 state file; enables automatic trust anchor updates"),
        )
        .arg(
            Arg::new("trust-anchor-hold-down")
                .long("trust-anchor-hold-down")
                .value_name("SECS")
                .value_parser(value_parser!(u32))
                .help("RFC 5011 add/revoke hold-down in seconds (default 30 days)"),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwarder_parser_accepts_ip_and_socket() {
        assert_eq!(
            parse_forwarder("1.1.1.1").unwrap(),
            "1.1.1.1:53".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_forwarder("9.9.9.9:5353").unwrap(),
            "9.9.9.9:5353".parse::<SocketAddr>().unwrap()
        );
        assert!(parse_forwarder("not-an-ip").is_err());
    }

    #[test]
    fn cli_parses_repeatable_forward_and_blocklist() {
        let matches = command()
            .try_get_matches_from([
                "pulseresolved",
                "--forward",
                "1.1.1.1",
                "--forward",
                "8.8.8.8:53",
                "--blocklist",
                "a.txt",
                "--blocklist",
                "b.txt",
                "--no-dnssec",
                "--workers",
                "2",
            ])
            .unwrap();
        let overrides = overrides(&matches);
        assert_eq!(overrides.forwarders.len(), 2);
        assert_eq!(overrides.blocklists.len(), 2);
        assert!(overrides.no_dnssec);
        assert_eq!(overrides.workers, Some(2));
    }

    #[test]
    fn cli_parses_control_cpu_affinity() {
        let matches = command()
            .try_get_matches_from(["pulseresolved", "--control-cpu-affinity", "0,2-3"])
            .unwrap();
        let overrides = overrides(&matches);
        assert_eq!(overrides.control_cpu_affinity, Some(vec![0, 2, 3]));
    }

    #[test]
    fn cli_parses_secure_upstreams() {
        let matches = command()
            .try_get_matches_from([
                "pulseresolved",
                "--config",
                "examples/resolver.toml",
                "--upstream",
                "tls://dns.example:853#dns.example",
                "--upstream",
                "https://dns.example/dns-query",
            ])
            .unwrap();
        let overrides = overrides(&matches);
        assert_eq!(overrides.upstreams.len(), 2);
        assert_eq!(overrides.upstreams[0].kind(), "tls");
        assert_eq!(overrides.upstreams[1].kind(), "https");
        assert!(parse_upstream("http://dns.example/dns-query").is_err());
    }

    #[test]
    fn cli_default_config_is_toml() {
        let matches = command().try_get_matches_from(["pulseresolved"]).unwrap();
        assert_eq!(
            matches.get_one::<PathBuf>("config"),
            Some(&PathBuf::from("examples/resolver.toml"))
        );
    }

    #[test]
    fn cli_accepts_toml_config_path() {
        let matches = command()
            .try_get_matches_from(["pulseresolved", "--config", "/etc/pulse/resolver.toml"])
            .unwrap();
        assert_eq!(
            matches.get_one::<PathBuf>("config"),
            Some(&PathBuf::from("/etc/pulse/resolver.toml"))
        );
    }
}
