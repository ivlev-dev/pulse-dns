//! CPU-affinity `pulseresolved`: фактическая маска UDP worker'а и ошибка
//! старта при пересечении с маской процесса, равном пустому множеству.

mod support;

use std::fs;
use std::time::{Duration, Instant};

use pulseresolved::server::Server;
use support::base_config;

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
        if thread == name && !mask.is_empty() {
            return Some(mask);
        }
    }
    None
}

#[test]
fn udp_worker_uses_the_configured_cpu() {
    let allowed = pulse_runtime::affinity::current_cpus();
    let target = *allowed.last().expect("allowed CPUs");
    let mut config = base_config("127.0.0.1:9".parse().expect("addr"));
    config.control_cpu_affinity = vec![target];
    let mut server = Server::start(&config).expect("start");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if thread_mask("pulse-udp-0") == Some(vec![target]) {
            break;
        }
        assert!(Instant::now() < deadline, "UDP worker is not pinned");
        std::thread::sleep(Duration::from_millis(10));
    }
    server.shutdown().expect("shutdown");
}

#[test]
fn foreign_cpu_is_a_startup_error() {
    let allowed = pulse_runtime::affinity::current_cpus();
    let Some(foreign) = (0..pulse_runtime::affinity::MAX_CPU).find(|cpu| !allowed.contains(cpu))
    else {
        return;
    };
    let mut config = base_config("127.0.0.1:9".parse().expect("addr"));
    config.control_cpu_affinity = vec![foreign];
    let Err(error) = Server::start(&config) else {
        panic!("start must fail on a foreign CPU");
    };
    assert!(
        error.to_string().contains("control_cpu_affinity"),
        "unexpected error: {error}"
    );
}
