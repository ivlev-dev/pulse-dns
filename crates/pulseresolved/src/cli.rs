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
        .unwrap_or_else(|| PathBuf::from("examples/resolver.json"));
    let mut config = match Config::load(&config_path) {
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
            "pulseresolved {} listening: udp={:?} tcp={:?} metrics={:?} workers={:?} backend={:?}",
            env!("CARGO_PKG_VERSION"),
            server.udp_addr(),
            server.tcp_addr(),
            server.metrics_addr(),
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
                logging::warn("signal", "received SIGHUP, reloading blocklist");
                let _ = server.reload_blocklist();
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
            "queries(udp={},tcp={}) responses(udp={},tcp={}) decode_errors={} encode_errors={} formerr={} refused={} refused_acl={} rate_limited={} truncated={} dropped={}",
            stats.udp_queries,
            stats.tcp_queries,
            stats.udp_responses,
            stats.tcp_responses,
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
        metrics_listen: matches.get_one::<SocketAddr>("metrics-listen").copied(),
        workers: matches.get_one::<usize>("workers").copied(),
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
        no_dnssec: matches.get_flag("no-dnssec"),
        log_level: matches.get_one::<LogLevel>("log-level").copied(),
    }
}

fn server_exit_code(error: &ServerError) -> ExitCode {
    match error {
        ServerError::Config(_) | ServerError::Resolver(_) => ExitCode::from(2),
        ServerError::Udp(_)
        | ServerError::TcpStart { .. }
        | ServerError::Tcp(_)
        | ServerError::MetricsStart { .. }
        | ServerError::Reload(_) => ExitCode::from(1),
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

fn command() -> Command {
    Command::new("pulseresolved")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Caching DNS resolver: forward/iterative, UDP/TCP, blocklist, overrides")
        .arg(
            Arg::new("config")
                .long("config")
                .value_name("PATH")
                .default_value("examples/resolver.json")
                .value_parser(value_parser!(PathBuf))
                .help("Path to the JSON configuration file"),
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
    fn cli_parses_secure_upstreams() {
        let matches = command()
            .try_get_matches_from([
                "pulseresolved",
                "--config",
                "examples/resolver.json",
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
}
