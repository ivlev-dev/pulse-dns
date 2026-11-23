//! CLI и жизненный цикл процесса.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Arg, Command, value_parser};
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;

use crate::config::{Config, LogLevel, Overrides};
use crate::logging;
use crate::server::{Server, ServerError};

#[allow(clippy::too_many_lines)] // Жизненный цикл процесса линеен и читается сверху вниз.
pub(crate) fn run() -> ExitCode {
    logging::init(LogLevel::Info);
    let matches = command().get_matches();
    let config_path = matches
        .get_one::<PathBuf>("config")
        .cloned()
        .unwrap_or_else(|| PathBuf::from("pulsed.json"));
    let overrides = Overrides {
        listen_udp: matches.get_one::<SocketAddr>("listen-udp").copied(),
        listen_tcp: matches.get_one::<SocketAddr>("listen-tcp").copied(),
        workers: matches.get_one::<usize>("workers").copied(),
        log_level: matches.get_one::<LogLevel>("log-level").copied(),
    };

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
            "pulsed {} listening: udp={:?} tcp={:?} workers={:?} backend={:?}",
            env!("CARGO_PKG_VERSION"),
            server.udp_addr(),
            server.tcp_addr(),
            server.udp_workers(),
            server.udp_backend()
        ),
    );

    let mut signals = match Signals::new([SIGINT, SIGTERM]) {
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
    match signals.forever().next() {
        Some(signal) => logging::warn(
            "signal",
            &format!("received signal {signal}, starting graceful shutdown"),
        ),
        None => logging::warn("signal", "signal iterator ended, shutting down"),
    }

    let udp_stats = server.udp_stats();
    let shutdown_result = server.shutdown();
    let stats = server.stats();
    let query_stats = server.query_stats();
    logging::info(
        "stats",
        &format!(
            "queries(udp={},tcp={}) responses={} decode_errors={} encode_errors={} dropped={} tcp_connections={} tcp_rejected={} tcp_io_errors={}",
            stats.udp_queries,
            stats.tcp_queries,
            stats.responses,
            stats.decode_errors,
            stats.encode_errors,
            stats.dropped,
            stats.tcp_connections,
            stats.tcp_rejected,
            stats.tcp_io_errors
        ),
    );
    logging::info(
        "query_stats",
        &format!(
            "queries={} nxdomain={} nodata={} refused={} truncated={} notimp={} badvers={} formerr={} servfail={}",
            query_stats.queries,
            query_stats.nxdomain,
            query_stats.nodata,
            query_stats.refused,
            query_stats.truncated,
            query_stats.notimp,
            query_stats.badvers,
            query_stats.formerr,
            query_stats.servfail
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

fn server_exit_code(error: &ServerError) -> ExitCode {
    match error {
        ServerError::Config(_) | ServerError::Zone(_) => ExitCode::from(2),
        ServerError::TcpStart { .. } | ServerError::Tcp(_) | ServerError::Udp(_) => {
            ExitCode::from(1)
        }
    }
}

fn command() -> Command {
    Command::new("pulsed")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Authoritative DNS server (MVP): JSON zones, UDP/TCP")
        .arg(
            Arg::new("config")
                .long("config")
                .value_name("PATH")
                .default_value("examples/zones.json")
                .value_parser(value_parser!(PathBuf))
                .help("Path to the JSON configuration file"),
        )
        .arg(
            Arg::new("listen-udp")
                .long("listen-udp")
                .value_name("ADDR")
                .value_parser(value_parser!(SocketAddr))
                .help("Override UDP listen address, e.g. 0.0.0.0:53"),
        )
        .arg(
            Arg::new("listen-tcp")
                .long("listen-tcp")
                .value_name("ADDR")
                .value_parser(value_parser!(SocketAddr))
                .help("Override TCP listen address, e.g. 0.0.0.0:53"),
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
}
