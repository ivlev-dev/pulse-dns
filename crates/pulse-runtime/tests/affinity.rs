//! Фактические маски CPU worker-потоков (`sched_getaffinity` через
//! `/proc/self/task`), проверка ошибки старта на чужой CPU и отсутствие
//! регрессии без явной affinity.

use std::fs;
use std::net::SocketAddr;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use pulse_runtime::{Reply, RuntimeConfig, UdpServer, affinity};

/// Worker-потоки всех тестов живут в одном процессе и называются одинаково,
/// поэтому тесты, читающие `/proc/self/task`, выполняются последовательно.
static SERIAL: Mutex<()> = Mutex::new(());

fn echo(request: &[u8], _peer: SocketAddr, out: &mut [u8]) -> Reply {
    let len = request.len().min(out.len());
    out[..len].copy_from_slice(&request[..len]);
    Reply::Send(len)
}

/// Разобрать `Cpus_allowed_list: 0-3,5`.
fn parse_cpu_list(text: &str) -> Vec<usize> {
    let mut out = Vec::new();
    for part in text.trim().split(',') {
        match part.split_once('-') {
            Some((start, end)) => {
                let start: usize = start.parse().expect("cpu range start");
                let end: usize = end.parse().expect("cpu range end");
                out.extend(start..=end);
            }
            None => out.push(part.parse().expect("cpu id")),
        }
    }
    out
}

/// `(имя, маска)` всех потоков процесса.
fn thread_masks() -> Vec<(String, Vec<usize>)> {
    let mut out = Vec::new();
    let Ok(tasks) = fs::read_dir("/proc/self/task") else {
        return out;
    };
    for task in tasks.flatten() {
        let Ok(status) = fs::read_to_string(task.path().join("status")) else {
            continue;
        };
        let mut name = String::new();
        let mut mask = Vec::new();
        for line in status.lines() {
            if let Some(value) = line.strip_prefix("Name:") {
                value.trim().clone_into(&mut name);
            } else if let Some(value) = line.strip_prefix("Cpus_allowed_list:") {
                mask = parse_cpu_list(value);
            }
        }
        out.push((name, mask));
    }
    out
}

fn wait_for_worker_mask(name: &str) -> Vec<usize> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Some((_, mask)) = thread_masks()
            .into_iter()
            .find(|(thread, _)| thread == name)
        {
            return mask;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("worker thread {name} did not appear");
}

#[test]
fn worker_is_pinned_to_the_requested_cpu() {
    let _guard = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let allowed = affinity::current_cpus();
    assert!(!allowed.is_empty(), "test process must have allowed CPUs");
    // Берём последний разрешённый CPU: так тест ловит случай, когда маска
    // процесса шире одного ядра.
    let target = *allowed.last().expect("allowed CPUs");

    let server = UdpServer::bind_with(
        "127.0.0.1:0".parse().expect("static address"),
        echo,
        RuntimeConfig::default()
            .with_workers(1)
            .with_cpu_affinity(vec![target]),
    )
    .expect("bind");
    server.start().expect("start");
    assert_eq!(wait_for_worker_mask("pulse-udp-0"), vec![target]);
    server.shutdown().expect("shutdown");
}

#[test]
fn empty_affinity_keeps_the_process_mask() {
    let _guard = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let process_mask = affinity::current_cpus();
    let server = UdpServer::bind_with(
        "127.0.0.1:0".parse().expect("static address"),
        echo,
        RuntimeConfig::default().with_workers(1),
    )
    .expect("bind");
    server.start().expect("start");
    // Без явного списка worker наследует маску процесса (регрессии нет).
    assert_eq!(wait_for_worker_mask("pulse-udp-0"), process_mask);
    server.shutdown().expect("shutdown");
}

#[test]
fn foreign_cpu_fails_at_start() {
    let _guard = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let allowed = affinity::current_cpus();
    let Some(foreign) = (0..affinity::MAX_CPU).find(|cpu| !allowed.contains(cpu)) else {
        // Процесс владеет всеми CPU — «чужого» ядра не существует.
        return;
    };
    let server = UdpServer::bind_with(
        "127.0.0.1:0".parse().expect("static address"),
        echo,
        RuntimeConfig::default()
            .with_workers(1)
            .with_cpu_affinity(vec![foreign]),
    )
    .expect("bind");
    let error = server
        .start()
        .expect_err("start must fail on a foreign CPU");
    let message = error.to_string();
    assert!(
        message.contains("cpu_affinity"),
        "unexpected error: {message}"
    );
}
