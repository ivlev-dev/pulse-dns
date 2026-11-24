//! CLI и жизненный цикл процесса.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use pulse_api::server::ApiServerError;
use pulse_dns::Name;
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;

use crate::config::{Config, DnssecKeyRole, Durability, LogLevel, Overrides};
use crate::logging;
use crate::server::{ApiOptions, Server, ServerError};

#[allow(clippy::too_many_lines)] // Жизненный цикл процесса линеен и читается сверху вниз.
pub(crate) fn run() -> ExitCode {
    logging::init(LogLevel::Info);
    let matches = command().get_matches();
    if let Some(("import", matches)) = matches.subcommand() {
        return import_zone(matches);
    }
    let config_path = matches
        .get_one::<PathBuf>("config")
        .cloned()
        .unwrap_or_else(|| PathBuf::from("pulsed.json"));
    let overrides = Overrides {
        listen_udp: matches.get_one::<SocketAddr>("listen-udp").copied(),
        listen_tcp: matches.get_one::<SocketAddr>("listen-tcp").copied(),
        workers: matches.get_one::<usize>("workers").copied(),
        log_level: matches.get_one::<LogLevel>("log-level").copied(),
        zonefile: matches.get_one::<PathBuf>("data").cloned(),
        durability: matches.get_one::<Durability>("durability").copied(),
        map_size: matches.get_one::<u64>("map-size").copied(),
    };

    let mut config = match Config::load(&config_path) {
        Ok(config) => config,
        Err(error) => {
            logging::error("config", &error.to_string());
            return ExitCode::from(2);
        }
    };
    config.apply_overrides(&overrides);
    match dnssec_keys(&matches) {
        Ok(keys) => {
            for (origin, role, path) in keys {
                config.add_dnssec_key(&origin, role, path);
            }
        }
        Err(error) => {
            logging::error("config", &error);
            return ExitCode::from(2);
        }
    }
    match tsig_keys(&matches) {
        Ok(keys) => {
            for (name, algorithm, secret) in keys {
                config.add_tsig_key(name, algorithm, secret);
            }
        }
        Err(error) => {
            logging::error("config", &error);
            return ExitCode::from(2);
        }
    }
    logging::init(config.log_level);
    if let Err(error) = config.validate() {
        logging::error("config", &error.to_string());
        return ExitCode::from(2);
    }

    let api = match api_options(&matches) {
        Ok(api) => api,
        Err(error) => {
            logging::error("api", &error);
            return ExitCode::from(2);
        }
    };
    let mut server = match Server::start_with_api(&config, api) {
        Ok(server) => server,
        Err(error) => {
            logging::error("startup", &error.to_string());
            return server_exit_code(&error);
        }
    };
    logging::info(
        "startup",
        &format!(
            "pulsed {} listening: udp={:?} tcp={:?} api={:?} workers={:?} backend={:?}",
            env!("CARGO_PKG_VERSION"),
            server.udp_addr(),
            server.tcp_addr(),
            server.api_addr(),
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

#[allow(clippy::too_many_lines)]
fn import_zone(matches: &ArgMatches) -> ExitCode {
    logging::init(LogLevel::Info);
    let Some(data) = matches.get_one::<PathBuf>("data").cloned() else {
        logging::error("import", "--data is required");
        return ExitCode::from(2);
    };
    let Some(origin) = matches.get_one::<String>("origin").cloned() else {
        logging::error("import", "--origin is required");
        return ExitCode::from(2);
    };
    let Some(zone_file) = matches.get_one::<PathBuf>("zone-file").cloned() else {
        logging::error("import", "zone file is required");
        return ExitCode::from(2);
    };
    let replace = matches.get_flag("replace");
    let sign = matches.get_flag("sign");
    let durability = matches
        .get_one::<Durability>("durability")
        .copied()
        .unwrap_or_default();
    let map_size = matches
        .get_one::<u64>("map-size")
        .copied()
        .unwrap_or(crate::config::DEFAULT_MAP_SIZE);
    let mut config = Config {
        zonefile: Some(data.clone()),
        durability,
        map_size,
        ..Config::default()
    };
    if let Err(error) = dnssec_keys(matches) {
        logging::error("import", &error);
        return ExitCode::from(2);
    }
    if let Ok(keys) = dnssec_keys(matches) {
        for (origin, role, path) in keys {
            config.add_dnssec_key(&origin, role, path);
        }
    }
    if sign && config.dnssec.is_empty() {
        logging::error(
            "import",
            "--sign requires at least one --dnssec-key <origin>=<path>",
        );
        return ExitCode::from(2);
    }
    let dnssec = match crate::dnssec::load(&config) {
        Ok(dnssec) => dnssec,
        Err(error) => {
            logging::error("import", &error.to_string());
            return ExitCode::from(2);
        }
    };
    let loaded = match crate::master::load_zone_file(&origin, &zone_file) {
        Ok(loaded) => loaded,
        Err(error) => {
            logging::error("import", &error);
            return ExitCode::from(2);
        }
    };
    let store =
        match crate::zonefile::ZoneStore::open_or_create(&data, map_size, durability.sync_mode()) {
            Ok(store) => store,
            Err(error) => {
                logging::error("import", &error.to_string());
                return ExitCode::from(1);
            }
        };
    match crate::store::import_loaded_zone(&store, &loaded, replace, &dnssec) {
        Ok(()) => {
            logging::info(
                "import",
                &format!(
                    "imported zone {} from {} into {} ({} RRset(s))",
                    loaded.origin,
                    zone_file.display(),
                    data.display(),
                    loaded.rrsets.len()
                ),
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            logging::error("import", &error);
            ExitCode::from(1)
        }
    }
}

fn dnssec_keys(
    matches: &ArgMatches,
) -> Result<Vec<(String, Option<DnssecKeyRole>, PathBuf)>, String> {
    let mut keys = Vec::new();
    let Some(values) = matches.get_many::<String>("dnssec-key") else {
        return Ok(keys);
    };
    for value in values {
        let (origin, rest) = value
            .split_once('=')
            .ok_or_else(|| format!("--dnssec-key expects <zone>=<key-path>, got {value:?}"))?;
        let origin = origin.trim();
        let rest = rest.trim();
        if origin.is_empty() || rest.is_empty() {
            return Err(format!(
                "--dnssec-key expects <zone>=<key-path>, got {value:?}"
            ));
        }
        let name = Name::parse(origin)
            .map_err(|error| format!("invalid --dnssec-key origin {origin:?}: {error}"))?;
        if name == Name::root() || name.labels().any(|label| label == b"*") {
            return Err(format!(
                "--dnssec-key origin {origin:?} must be a non-root name without wildcards"
            ));
        }
        let (role, path) = match rest.split_once(':') {
            Some((role, path)) if DnssecKeyRole::parse(role).is_some() => {
                (DnssecKeyRole::parse(role), path.trim())
            }
            _ => (None, rest),
        };
        if path.is_empty() {
            return Err(format!("--dnssec-key path is empty in {value:?}"));
        }
        keys.push((name.to_string(), role, PathBuf::from(path)));
    }
    Ok(keys)
}

fn tsig_keys(matches: &ArgMatches) -> Result<Vec<(String, String, String)>, String> {
    let mut keys = Vec::new();
    let Some(values) = matches.get_many::<String>("tsig-key") else {
        return Ok(keys);
    };
    for value in values {
        let mut parts = value.splitn(3, ':');
        let name = parts.next().unwrap_or_default().trim();
        let algorithm = parts.next().unwrap_or_default().trim();
        let secret = parts.next().unwrap_or_default().trim();
        if name.is_empty() || algorithm.is_empty() || secret.is_empty() {
            return Err(format!(
                "--tsig-key expects <name>:<algorithm>:<base64-secret>, got {value:?}"
            ));
        }
        let name = Name::parse(name)
            .map_err(|error| format!("invalid --tsig-key name {name:?}: {error}"))?;
        if name == Name::root() || name.labels().any(|label| label == b"*") {
            return Err(format!(
                "--tsig-key name {name} must be a non-root name without wildcards"
            ));
        }
        keys.push((
            name.to_string(),
            algorithm.to_ascii_lowercase(),
            secret.to_owned(),
        ));
    }
    Ok(keys)
}

fn api_options(matches: &ArgMatches) -> Result<Option<ApiOptions>, String> {
    let listen = matches.get_one::<SocketAddr>("api-listen").copied();
    let token = matches
        .get_one::<String>("api-token")
        .cloned()
        .or_else(|| std::env::var("PULSED_API_TOKEN").ok())
        .map(|token| token.trim().to_owned())
        .filter(|token| !token.is_empty());
    let scopes: Vec<String> = matches
        .get_many::<String>("api-scope")
        .map(|values| {
            values
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
                .collect()
        })
        .unwrap_or_default();
    match (listen, token) {
        (Some(listen), Some(token)) => Ok(Some(ApiOptions {
            listen,
            token,
            scopes,
        })),
        (Some(_), None) => Err(
            "--api-listen requires --api-token or the PULSED_API_TOKEN environment variable"
                .to_owned(),
        ),
        (None, Some(_)) => {
            logging::warn(
                "api",
                "API token is set but --api-listen is missing; API stays disabled",
            );
            Ok(None)
        }
        (None, None) => Ok(None),
    }
}

fn server_exit_code(error: &ServerError) -> ExitCode {
    match error {
        ServerError::Config(_) | ServerError::Store(_) | ServerError::Dnssec(_) => {
            ExitCode::from(2)
        }
        ServerError::Api(error) => match error {
            ApiServerError::Config(_) => ExitCode::from(2),
            _ => ExitCode::from(1),
        },
        ServerError::TcpStart { .. }
        | ServerError::Tcp(_)
        | ServerError::Udp(_)
        | ServerError::Notify(_)
        | ServerError::Secondary(_) => ExitCode::from(1),
    }
}

#[allow(clippy::too_many_lines)]
fn command() -> Command {
    Command::new("pulsed")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Authoritative DNS server (MVP): pulse-zonefile, UDP/TCP")
        .arg(
            Arg::new("config")
                .long("config")
                .value_name("PATH")
                .default_value("pulsed.json")
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
        .arg(
            Arg::new("data")
                .long("data")
                .value_name("PATH")
                .value_parser(value_parser!(PathBuf))
                .help("Enable pulse-zonefile persistence at PATH"),
        )
        .arg(
            Arg::new("durability")
                .long("durability")
                .value_name("MODE")
                .value_parser(value_parser!(Durability))
                .help("Zonefile durability: sync, flush (default) or memory"),
        )
        .arg(
            Arg::new("map-size")
                .long("map-size")
                .value_name("BYTES")
                .value_parser(value_parser!(u64))
                .help("Zonefile map size in bytes (default 4 GiB, sparse)"),
        )
        .arg(
            Arg::new("dnssec-key")
                .long("dnssec-key")
                .value_name("ZONE=PATH")
                .action(ArgAction::Append)
                .help("Sign a zone with a BIND/PKCS#8 private key; repeatable, optional role: ZONE=[ksk|zsk|csk:]PATH"),
        )
        .arg(
            Arg::new("tsig-key")
                .long("tsig-key")
                .value_name("NAME:ALG:SECRET")
                .action(ArgAction::Append)
                .help("Add a TSIG key for AXFR/IXFR/NOTIFY; secret is base64; repeatable"),
        )
        .arg(
            Arg::new("api-listen")
                .long("api-listen")
                .value_name("ADDR")
                .value_parser(value_parser!(SocketAddr))
                .help("Enable the REST API on a loopback address, e.g. 127.0.0.1:8080"),
        )
        .arg(
            Arg::new("api-token")
                .long("api-token")
                .value_name("TOKEN")
                .help("API bearer token (prefer the PULSED_API_TOKEN environment variable)"),
        )
        .arg(
            Arg::new("api-scope")
                .long("api-scope")
                .value_name("ORIGIN")
                .action(ArgAction::Append)
                .help("Per-zone API allowlist (exact origin or *.suffix.); repeatable"),
        )
        .subcommand(
            Command::new("import")
                .about("Import an RFC 1035 master file into the binary zonefile")
                .arg(
                    Arg::new("data")
                        .long("data")
                        .value_name("PATH")
                        .required(true)
                        .value_parser(value_parser!(PathBuf))
                        .help("Zonefile to create or update"),
                )
                .arg(
                    Arg::new("origin")
                        .long("origin")
                        .value_name("ORIGIN")
                        .required(true)
                        .help("Zone origin, e.g. example.com."),
                )
                .arg(
                    Arg::new("replace")
                        .long("replace")
                        .action(ArgAction::SetTrue)
                        .help("Replace an existing zone"),
                )
                .arg(
                    Arg::new("sign")
                        .long("sign")
                        .action(ArgAction::SetTrue)
                        .help("Sign the imported zone with configured DNSSEC keys"),
                )
                .arg(
                    Arg::new("dnssec-key")
                        .long("dnssec-key")
                        .value_name("ZONE=PATH")
                        .action(ArgAction::Append)
                        .help("Signing key for --sign; repeatable"),
                )
                .arg(
                    Arg::new("durability")
                        .long("durability")
                        .value_name("MODE")
                        .value_parser(value_parser!(Durability))
                        .help("Zonefile durability: sync, flush (default) or memory"),
                )
                .arg(
                    Arg::new("map-size")
                        .long("map-size")
                        .value_name("BYTES")
                        .value_parser(value_parser!(u64))
                        .help("Zonefile map size in bytes (default 4 GiB, sparse)"),
                )
                .arg(
                    Arg::new("zone-file")
                        .value_name("ZONE-FILE")
                        .required(true)
                        .value_parser(value_parser!(PathBuf))
                        .help("RFC 1035 master file to import"),
                ),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(args: &[&str]) -> ArgMatches {
        command()
            .try_get_matches_from(std::iter::once("pulsed").chain(args.iter().copied()))
            .expect("arguments parse")
    }

    #[test]
    fn dnssec_key_parses_plain_and_role_forms() {
        let arguments = matches(&[
            "--dnssec-key",
            "example.com.=keys/Kexample.com.+015+12345.private",
            "--dnssec-key",
            "example.com.=ksk:keys/ksk.private",
            "--dnssec-key",
            "example.com.=zsk:keys/zsk.private",
        ]);
        let keys = dnssec_keys(&arguments).expect("keys parse");
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0].0, "example.com.");
        assert_eq!(keys[0].1, None);
        assert_eq!(keys[1].1, Some(DnssecKeyRole::Ksk));
        assert_eq!(keys[2].1, Some(DnssecKeyRole::Zsk));
    }

    #[test]
    fn dnssec_key_rejects_bad_input() {
        assert!(dnssec_keys(&matches(&["--dnssec-key", "example.com."])).is_err());
        assert!(dnssec_keys(&matches(&["--dnssec-key", ".=keys/key.private"])).is_err());
        assert!(dnssec_keys(&matches(&["--dnssec-key", "bad..name=keys/key.private"])).is_err());
    }

    #[test]
    fn tsig_key_parses_name_algorithm_and_secret() {
        let keys = tsig_keys(&matches(&[
            "--tsig-key",
            "xfr-key.test.:hmac-sha512:c2VjcmV0",
        ]))
        .expect("keys parse");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].0, "xfr-key.test.");
        assert_eq!(keys[0].1, "hmac-sha512");
        assert_eq!(keys[0].2, "c2VjcmV0");
    }

    #[test]
    fn tsig_key_rejects_bad_input() {
        assert!(tsig_keys(&matches(&["--tsig-key", "xfr-key.test.:c2VjcmV0"])).is_err());
        assert!(tsig_keys(&matches(&["--tsig-key", ".:hmac-sha256:c2VjcmV0"])).is_err());
        assert!(tsig_keys(&matches(&["--tsig-key", "xfr-key.test.:hmac-sha256:"])).is_err());
    }
}
