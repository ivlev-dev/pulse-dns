//! CLI и жизненный цикл процесса.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use pulse_api::server::ApiServerError;
use pulse_dns::Name;
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
use signal_hook::iterator::Signals;

use crate::config::{CommitMode, Config, DnssecKeyRole, Durability, LogLevel, Overrides};
use crate::dnscrypt::{GenCertOptions, generate_certificate};
use crate::logging;
use crate::server::{ApiOptions, Server, ServerError};

#[allow(clippy::too_many_lines)]
// Жизненный цикл процесса линеен и читается сверху вниз.
#[allow(clippy::similar_names)] // dot/doh — имена протоколов, не опечатка.
pub(crate) fn run() -> ExitCode {
    logging::init(LogLevel::Info);
    let matches = command().get_matches();
    match matches.subcommand() {
        Some(("import", matches)) => return import_zone(matches),
        Some(("convert", matches)) => return convert_zonefile(matches),
        Some(("fsck", matches)) => return fsck_zonefile(matches),
        Some(("dnscrypt-gencert", matches)) => return dnscrypt_gencert(matches),
        _ => {}
    }
    let config_path = matches
        .get_one::<PathBuf>("config")
        .cloned()
        .unwrap_or_else(|| PathBuf::from("pulsed.json"));
    let overrides = Overrides {
        listen_udp: matches.get_one::<SocketAddr>("listen-udp").copied(),
        listen_tcp: matches.get_one::<SocketAddr>("listen-tcp").copied(),
        dot_listen: matches.get_one::<SocketAddr>("dot-listen").copied(),
        doh_listen: matches.get_one::<SocketAddr>("doh-listen").copied(),
        tls_cert: matches.get_one::<PathBuf>("tls-cert").cloned(),
        tls_key: matches.get_one::<PathBuf>("tls-key").cloned(),
        tls_reload_secs: matches.get_one::<u64>("tls-reload-secs").copied(),
        tls_allow_from: matches
            .get_many::<String>("tls-allow-from")
            .map(|values| values.cloned().collect())
            .unwrap_or_default(),
        dnscrypt_listen: matches.get_one::<SocketAddr>("dnscrypt-listen").copied(),
        dnscrypt_tcp_listen: matches
            .get_one::<SocketAddr>("dnscrypt-tcp-listen")
            .copied(),
        dnscrypt_provider_key: matches.get_one::<PathBuf>("dnscrypt-provider-key").cloned(),
        dnscrypt_resolver_key: matches.get_one::<PathBuf>("dnscrypt-resolver-key").cloned(),
        dnscrypt_cert: matches.get_one::<PathBuf>("dnscrypt-cert").cloned(),
        dnscrypt_provider_name: matches.get_one::<String>("dnscrypt-provider-name").cloned(),
        workers: matches.get_one::<usize>("workers").copied(),
        log_level: matches.get_one::<LogLevel>("log-level").copied(),
        zonefile: matches.get_one::<PathBuf>("data").cloned(),
        durability: matches.get_one::<Durability>("durability").copied(),
        commit_mode: matches.get_one::<CommitMode>("commit-mode").copied(),
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
            "pulsed {} listening: udp={:?} tcp={:?} dot={:?} doh={:?} dnscrypt={:?} api={:?} workers={:?} backend={:?}",
            env!("CARGO_PKG_VERSION"),
            server.udp_addr(),
            server.tcp_addr(),
            server.dot_addr(),
            server.doh_addr(),
            server.dnscrypt_addr(),
            server.api_addr(),
            server.udp_workers(),
            server.udp_backend()
        ),
    );
    if let Some(stats) = server.dot_stats() {
        logging::info(
            "dot",
            &format!(
                "DoT enabled (ALPN dot, TLS 1.2/1.3): connections={} active={}",
                stats.connections, stats.active_connections
            ),
        );
    }
    if let Some(stats) = server.doh_stats() {
        logging::info(
            "doh",
            &format!(
                "DoH enabled (HTTP/1.1 only, ALPN http/1.1): connections={} active={}",
                stats.connections, stats.active_connections
            ),
        );
    }
    if let Some(addr) = server.dnscrypt_addr() {
        logging::info(
            "dnscrypt",
            &format!(
                "DNSCrypt enabled on {addr} (UDP v2, workers={:?}, provider={:?}, serial={:?}, valid_until={:?})",
                server.dnscrypt_workers(),
                server.dnscrypt_provider_name(),
                server.dnscrypt_serial(),
                server.dnscrypt_valid_until()
            ),
        );
    }

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
    let reload_every = config.tls_reload_secs.map(Duration::from_secs);
    let mut last_reload = Instant::now();
    loop {
        let mut terminate = false;
        for signal in signals.pending() {
            match signal {
                SIGHUP => reload_tls(&server, "SIGHUP"),
                SIGINT | SIGTERM => {
                    logging::warn(
                        "signal",
                        &format!("received signal {signal}, starting graceful shutdown"),
                    );
                    terminate = true;
                }
                _ => {}
            }
        }
        if terminate {
            break;
        }
        if let Some(period) = reload_every
            && last_reload.elapsed() >= period
        {
            reload_tls(&server, "tls_reload_secs");
            last_reload = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    let udp_stats = server.udp_stats();
    let dot_snapshot = server.dot_stats();
    let doh_snapshot = server.doh_stats();
    let dnscrypt_snapshot = server.dnscrypt_stats();
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
    if let Some(dot) = dot_snapshot {
        logging::info(
            "dot_stats",
            &format!(
                "connections={} handshakes={} queries={} responses={} errors={}",
                dot.connections, dot.handshakes, dot.queries, dot.responses, dot.errors
            ),
        );
    }
    if let Some(doh) = doh_snapshot {
        logging::info(
            "doh_stats",
            &format!(
                "connections={} handshakes={} http_requests={} queries={} responses={} errors={}",
                doh.connections,
                doh.handshakes,
                doh.http_requests,
                doh.queries,
                doh.responses,
                doh.errors
            ),
        );
    }
    if let Some(dnscrypt) = dnscrypt_snapshot {
        logging::info(
            "dnscrypt_stats",
            &format!(
                "received={} sent={} dropped={}",
                dnscrypt.total.packets_received,
                dnscrypt.total.packets_sent,
                dnscrypt.total.responses_dropped
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

fn reload_tls(server: &Server, source: &str) {
    if server.dot_addr().is_none() && server.doh_addr().is_none() {
        logging::warn(
            "tls",
            &format!("{source}: TLS is not configured; reload skipped"),
        );
        return;
    }
    match server.reload_tls() {
        Ok(()) => logging::info(
            "tls",
            &format!("{source}: certificate reloaded for new connections"),
        ),
        Err(error) => logging::error(
            "tls",
            &format!("{source}: certificate reload failed: {error}"),
        ),
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
    let store = match crate::zonefile::ZoneStore::open_or_create(
        &data,
        map_size,
        durability.sync_mode_v2(),
        CommitMode::PerZone,
    ) {
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

#[allow(clippy::too_many_lines)]
fn convert_zonefile(matches: &ArgMatches) -> ExitCode {
    logging::init(LogLevel::Info);
    let Some(from) = matches.get_one::<PathBuf>("from").cloned() else {
        logging::error("convert", "--from is required");
        return ExitCode::from(2);
    };
    let Some(to) = matches.get_one::<PathBuf>("to").cloned() else {
        logging::error("convert", "--to is required");
        return ExitCode::from(2);
    };
    if from == to {
        logging::error("convert", "--from and --to must differ");
        return ExitCode::from(2);
    }
    let durability = matches
        .get_one::<Durability>("durability")
        .copied()
        .unwrap_or_default();
    let map_size = matches
        .get_one::<u64>("map-size")
        .copied()
        .unwrap_or(crate::config::DEFAULT_MAP_SIZE);
    match crate::zonefile::ZoneStore::convert_from_v1(
        &from,
        &to,
        map_size,
        durability.sync_mode_v2(),
    ) {
        Ok((zones, records)) => {
            logging::info(
                "convert",
                &format!(
                    "converted {} zone(s), {} RRset(s) from {} to {}",
                    zones,
                    records,
                    from.display(),
                    to.display()
                ),
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            logging::error("convert", &error.to_string());
            ExitCode::from(1)
        }
    }
}

/// Offline `fsck --verify` / `fsck --repair` для v2-файла.
#[allow(clippy::too_many_lines)]
fn fsck_zonefile(matches: &ArgMatches) -> ExitCode {
    logging::init(LogLevel::Info);
    let Some(data) = matches.get_one::<PathBuf>("data").cloned() else {
        logging::error("fsck", "--data is required");
        return ExitCode::from(2);
    };
    if matches.get_flag("repair") {
        return match pulse_zonefile::parallel::fsck_repair(&data) {
            Ok(report) => {
                println!(
                    "fsck --repair {}: repaired={} remaining={} deferred={} quarantined={:?} ok={}",
                    data.display(),
                    report.repaired_pages,
                    report.remaining_leaks,
                    report.deferred_leaks,
                    report.quarantined_zones,
                    report.ok
                );
                for issue in &report.issues {
                    println!("  issue: {issue}");
                }
                if report.ok {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(1)
                }
            }
            Err(error) => {
                logging::error("fsck", &format!("{}: {error}", data.display()));
                ExitCode::from(1)
            }
        };
    }
    let store = match pulse_zonefile::parallel::open_read_only(&data) {
        Ok(store) => store,
        Err(error) => {
            logging::error("fsck", &format!("{}: {error}", data.display()));
            return ExitCode::from(1);
        }
    };
    let lite = match store.fsck_lite() {
        Ok(report) => report,
        Err(error) => {
            logging::error("fsck", &format!("{}: {error}", data.display()));
            return ExitCode::from(1);
        }
    };
    let graph = match store.fsck_graph() {
        Ok(report) => report,
        Err(error) => {
            logging::error("fsck", &format!("{}: {error}", data.display()));
            return ExitCode::from(1);
        }
    };
    let ratio = if graph.durable_pages == 0 {
        0.0
    } else {
        #[allow(clippy::cast_precision_loss)]
        {
            graph.leaked_pages as f64 / graph.durable_pages as f64
        }
    };
    println!(
        "fsck {}: ok={} fatal={:?} durable_pages={} reachable={} chain={} buckets={} free={} leaked={} ratio={:.4} damaged={:?}",
        data.display(),
        lite.ok && graph.ok,
        graph.fatal.or(lite.fatal),
        graph.durable_pages,
        graph.reachable_pages,
        graph.chain_pages,
        graph.bucket_pages,
        graph.free_pages,
        graph.leaked_pages,
        ratio,
        graph.damaged_zones
    );
    println!(
        "  alloc: DP={} DT={} max_root_page_limit={} max_root_version={} zones={} page.txn_max={}",
        lite.durable_page_limit,
        lite.durable_txn_limit,
        lite.max_root_page_limit,
        lite.max_root_version,
        lite.zones,
        graph.max_page_txn
    );
    for issue in lite.issues.iter().chain(graph.issues.iter()) {
        println!("  issue: {issue}");
    }
    if lite.ok && graph.ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn dnscrypt_gencert(matches: &ArgMatches) -> ExitCode {
    let Some(out_dir) = matches.get_one::<PathBuf>("out").cloned() else {
        logging::error("dnscrypt-gencert", "--out is required");
        return ExitCode::from(2);
    };
    let Some(provider_name) = matches.get_one::<String>("provider-name").cloned() else {
        logging::error("dnscrypt-gencert", "--provider-name is required");
        return ExitCode::from(2);
    };
    let options = GenCertOptions {
        out_dir,
        provider_name,
        serial: matches.get_one::<u32>("serial").copied().unwrap_or(1),
        validity_days: matches
            .get_one::<u32>("validity-days")
            .copied()
            .unwrap_or(365),
        force: matches.get_flag("force"),
    };
    match generate_certificate(&options) {
        Ok(generated) => {
            println!("provider: {}", generated.provider_name);
            println!("provider_public_key: {}", generated.provider_public_key);
            println!("provider_key: {}", generated.provider_key.display());
            println!("resolver_key: {}", generated.resolver_key.display());
            println!("certificate: {}", generated.cert.display());
            println!("txt_file: {}", generated.txt.display());
            println!();
            print!("{}", generated.txt_records);
            ExitCode::SUCCESS
        }
        Err(error) => {
            logging::error("dnscrypt-gencert", &error.to_string());
            ExitCode::from(2)
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
        | ServerError::Secondary(_)
        | ServerError::Tls(_)
        | ServerError::Dnscrypt(_) => ExitCode::from(1),
    }
}

#[allow(clippy::too_many_lines)]
fn command() -> Command {
    Command::new("pulsed")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Authoritative DNS server: UDP/TCP, DoT, DoH/1.1, DNSCrypt, pulse-zonefile")
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
            Arg::new("dot-listen")
                .long("dot-listen")
                .value_name("ADDR")
                .value_parser(value_parser!(SocketAddr))
                .help("Enable DNS-over-TLS (RFC 7858), e.g. 0.0.0.0:853"),
        )
        .arg(
            Arg::new("doh-listen")
                .long("doh-listen")
                .value_name("ADDR")
                .value_parser(value_parser!(SocketAddr))
                .help("Enable DNS-over-HTTPS/1.1 (RFC 8484), e.g. 0.0.0.0:443"),
        )
        .arg(
            Arg::new("tls-cert")
                .long("tls-cert")
                .value_name("PATH")
                .value_parser(value_parser!(PathBuf))
                .help("PEM certificate chain for DoT/DoH"),
        )
        .arg(
            Arg::new("tls-key")
                .long("tls-key")
                .value_name("PATH")
                .value_parser(value_parser!(PathBuf))
                .help("PEM private key for DoT/DoH (mode 0600)"),
        )
        .arg(
            Arg::new("tls-reload-secs")
                .long("tls-reload-secs")
                .value_name("SECONDS")
                .value_parser(value_parser!(u64))
                .help("Reload the TLS certificate every N seconds (SIGHUP always works)"),
        )
        .arg(
            Arg::new("tls-allow-from")
                .long("tls-allow-from")
                .value_name("CIDR")
                .action(ArgAction::Append)
                .help("Allow DoT/DoH only from this IP/CIDR; repeatable"),
        )
        .arg(
            Arg::new("dnscrypt-listen")
                .long("dnscrypt-listen")
                .value_name("ADDR")
                .value_parser(value_parser!(SocketAddr))
                .help("Enable DNSCrypt v2 over UDP, e.g. 0.0.0.0:443"),
        )
        .arg(
            Arg::new("dnscrypt-tcp-listen")
                .long("dnscrypt-tcp-listen")
                .value_name("ADDR")
                .value_parser(value_parser!(SocketAddr))
                .help("Enable DNSCrypt v2 over TCP, e.g. 0.0.0.0:443"),
        )
        .arg(
            Arg::new("dnscrypt-provider-key")
                .long("dnscrypt-provider-key")
                .value_name("PATH")
                .value_parser(value_parser!(PathBuf))
                .help("Ed25519 provider seed file (hex, mode 0600)"),
        )
        .arg(
            Arg::new("dnscrypt-resolver-key")
                .long("dnscrypt-resolver-key")
                .value_name("PATH")
                .value_parser(value_parser!(PathBuf))
                .help("X25519 resolver secret file (hex, mode 0600)"),
        )
        .arg(
            Arg::new("dnscrypt-cert")
                .long("dnscrypt-cert")
                .value_name("PATH")
                .value_parser(value_parser!(PathBuf))
                .help("Signed DNSCrypt certificate JSON from dnscrypt-gencert"),
        )
        .arg(
            Arg::new("dnscrypt-provider-name")
                .long("dnscrypt-provider-name")
                .value_name("NAME")
                .help("Full DNSCrypt provider name, e.g. 2.dnscrypt-cert.example.com."),
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
            Arg::new("commit-mode")
                .long("commit-mode")
                .value_name("MODE")
                .value_parser(value_parser!(CommitMode))
                .help("Commit mode for zone writes: per-zone (default) or group"),
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
            Command::new("convert")
                .about("Convert a pulse-zonefile v1 file into the v2 format")
                .arg(
                    Arg::new("from")
                        .long("from")
                        .value_name("PATH")
                        .required(true)
                        .value_parser(value_parser!(PathBuf))
                        .help("Source pulse-zonefile v1 file"),
                )
                .arg(
                    Arg::new("to")
                        .long("to")
                        .value_name("PATH")
                        .required(true)
                        .value_parser(value_parser!(PathBuf))
                        .help("Destination v2 file (must not exist or be empty)"),
                )
                .arg(
                    Arg::new("durability")
                        .long("durability")
                        .value_name("MODE")
                        .value_parser(value_parser!(Durability))
                        .help("Durability of the destination file: sync, flush (default) or memory"),
                )
                .arg(
                    Arg::new("map-size")
                        .long("map-size")
                        .value_name("BYTES")
                        .value_parser(value_parser!(u64))
                        .help("Destination map size in bytes (default 4 GiB, sparse)"),
                ),
        )
        .subcommand(
            Command::new("fsck")
                .about("Verify (and optionally repair) a pulse-zonefile v2 file offline")
                .arg(
                    Arg::new("data")
                        .long("data")
                        .value_name("PATH")
                        .required(true)
                        .value_parser(value_parser!(PathBuf))
                        .help("Zonefile v2 to check"),
                )
                .arg(
                    Arg::new("repair")
                        .long("repair")
                        .action(ArgAction::SetTrue)
                        .help("Return safe leaked pages to the free pool and quarantine damaged zones"),
                ),
        )
        .subcommand(
            Command::new("dnscrypt-gencert")
                .about("Generate DNSCrypt provider/resolver keys and a signed certificate")
                .arg(
                    Arg::new("out")
                        .long("out")
                        .short('o')
                        .value_name("DIR")
                        .required(true)
                        .value_parser(value_parser!(PathBuf))
                        .help("Output directory for keys and certificate (created with 0700)"),
                )
                .arg(
                    Arg::new("provider-name")
                        .long("provider-name")
                        .value_name("NAME")
                        .required(true)
                        .help("Full provider name, e.g. 2.dnscrypt-cert.example.com."),
                )
                .arg(
                    Arg::new("serial")
                        .long("serial")
                        .value_name("N")
                        .value_parser(value_parser!(u32))
                        .help("Certificate serial number (default 1)"),
                )
                .arg(
                    Arg::new("validity-days")
                        .long("validity-days")
                        .value_name("DAYS")
                        .value_parser(value_parser!(u32))
                        .help("Certificate validity in days (default 365)"),
                )
                .arg(
                    Arg::new("force")
                        .long("force")
                        .action(ArgAction::SetTrue)
                        .help("Overwrite existing key/certificate files"),
                ),
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
