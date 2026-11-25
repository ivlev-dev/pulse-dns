//! CPU-affinity и huge pages на уровне `pulsed`: маска worker-потока,
//! ошибка старта на чужом CPU, THP-политика для RX-арены.

use std::fs;
use std::net::SocketAddr;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use pulsed::config::{Config, HugePagesSetting};
use pulsed::server::Server;

/// Worker-потоки тестов живут в одном процессе и называются одинаково.
static SERIAL: Mutex<()> = Mutex::new(());

fn parse_cpu_list(text: &str) -> Vec<usize> {
    let mut out = Vec::new();
    for part in text.trim().split(',') {
        match part.split_once('-') {
            Some((start, end)) => {
                let start: usize = start.parse().expect("range start");
                let end: usize = end.parse().expect("range end");
                out.extend(start..=end);
            }
            None => out.push(part.parse().expect("cpu")),
        }
    }
    out
}

fn thread_mask(name: &str) -> Option<Vec<usize>> {
    for task in fs::read_dir("/proc/self/task").ok()?.flatten() {
        let status = fs::read_to_string(task.path().join("status")).ok()?;
        let mut thread = String::new();
        let mut mask = Vec::new();
        for line in status.lines() {
            if let Some(value) = line.strip_prefix("Name:") {
                value.trim().clone_into(&mut thread);
            } else if let Some(value) = line.strip_prefix("Cpus_allowed_list:") {
                mask = parse_cpu_list(value);
            }
        }
        if thread == name {
            return Some(mask);
        }
    }
    None
}

fn wait_for_mask(name: &str) -> Vec<usize> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Some(mask) = thread_mask(name) {
            return mask;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("thread {name} did not appear");
}

fn dns_config() -> Config {
    Config {
        listen_udp: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
        listen_tcp: None,
        workers: 1,
        dns_workers: Some(1),
        journal: false,
        zonefile: None,
        ..Config::default()
    }
}

#[test]
fn dns_worker_uses_the_configured_cpu() {
    let _guard = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let allowed = pulse_runtime::affinity::current_cpus();
    let target = *allowed.last().expect("allowed CPUs");
    let mut server = Server::start(&Config {
        dns_cpu_affinity: vec![target],
        ..dns_config()
    })
    .expect("start");
    assert_eq!(wait_for_mask("pulse-udp-0"), vec![target]);
    server.shutdown().expect("shutdown");
}

#[test]
fn foreign_cpu_is_a_startup_error() {
    let _guard = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let allowed = pulse_runtime::affinity::current_cpus();
    let Some(foreign) = (0..pulse_runtime::affinity::MAX_CPU).find(|cpu| !allowed.contains(cpu))
    else {
        return;
    };
    let Err(error) = Server::start(&Config {
        dns_cpu_affinity: vec![foreign],
        ..dns_config()
    }) else {
        panic!("start must fail on a foreign CPU");
    };
    assert!(
        error.to_string().contains("dns_cpu_affinity"),
        "unexpected error: {error}"
    );
}

#[test]
fn huge_pages_policies_start_the_server() {
    let _guard = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    for policy in [
        HugePagesSetting::Never,
        HugePagesSetting::Auto,
        HugePagesSetting::Always,
    ] {
        let mut server = Server::start(&Config {
            huge_pages: policy,
            ..dns_config()
        })
        .unwrap_or_else(|error| panic!("huge_pages={policy}: {error}"));
        server.shutdown().expect("shutdown");
    }
}
