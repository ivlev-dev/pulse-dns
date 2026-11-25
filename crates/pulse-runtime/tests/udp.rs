//! Интеграционные тесты на реальных UDP-сокетах (localhost).

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use pulse_runtime::{
    BackendKind, BackendPreference, Reply, Runtime, RuntimeConfig, RuntimeError, RxMode, UdpServer,
    owned,
};

const CLIENT_TIMEOUT: Duration = Duration::from_millis(200);
const DEADLINE: Duration = Duration::from_secs(5);

fn echo(request: &[u8], _peer: SocketAddr, out: &mut [u8]) -> Reply {
    let len = request.len().min(out.len());
    out[..len].copy_from_slice(&request[..len]);
    Reply::Send(len)
}

fn client(addr: SocketAddr) -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("client bind");
    socket.connect(addr).expect("client connect");
    socket
        .set_read_timeout(Some(CLIENT_TIMEOUT))
        .expect("read timeout");
    socket
}

/// Ждать датаграмму до общего дедлайна; `None` — таймаут.
fn recv_until(socket: &UdpSocket, deadline: Instant) -> Option<Vec<u8>> {
    let mut buffer = vec![0_u8; 8192];
    loop {
        match socket.recv(&mut buffer) {
            Ok(len) => return Some(buffer[..len].to_vec()),
            Err(err)
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut =>
            {
                if Instant::now() >= deadline {
                    return None;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => panic!("recv failed: {err}"),
        }
    }
}

fn wait_for(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + DEADLINE;
    while !predicate() {
        assert!(
            Instant::now() < deadline,
            "condition not met before deadline"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn echo_single_worker() {
    let server = UdpServer::bind("127.0.0.1:0".parse().unwrap(), echo, 1).unwrap();
    assert_eq!(server.workers(), 1);
    assert!(matches!(server.backend(), BackendKind::IoUring { .. }));
    server.start().unwrap();

    let addr = server.local_addr();
    let socket = client(addr);
    for seq in 0..64_u16 {
        let payload = seq.to_be_bytes();
        socket.send(&payload).unwrap();
        let reply = recv_until(&socket, Instant::now() + DEADLINE).expect("echo reply");
        assert_eq!(reply, payload);
    }

    wait_for(|| server.stats().total.packets_sent == 64);
    let stats = server.stats();
    assert_eq!(stats.total.packets_received, 64);
    assert_eq!(stats.total.packets_sent, 64);
    assert_eq!(stats.total.bytes_received, 64 * 2);
    assert_eq!(stats.total.recv_errors, 0);
    assert_eq!(stats.total.send_errors, 0);
    assert_eq!(stats.per_worker.len(), 1);

    server.shutdown().unwrap();
}

#[test]
fn multiple_workers_share_reuseport() {
    let workers = 4;
    let server = UdpServer::bind("127.0.0.1:0".parse().unwrap(), echo, workers).unwrap();
    server.start().unwrap();

    let addr = server.local_addr();
    // SO_REUSEPORT хеширует 4-tuple, поэтому один клиентский сокет всегда
    // попадает в одну очередь; для распределения нужны разные source-порты.
    let clients: Vec<UdpSocket> = (0..16).map(|_| client(addr)).collect();
    let per_client = 32_u32;
    let total = per_client * u32::try_from(clients.len()).unwrap();
    for client in &clients {
        for seq in 0..per_client {
            let payload = seq.to_be_bytes();
            client.send(&payload).unwrap();
            let reply = recv_until(client, Instant::now() + DEADLINE).expect("echo reply");
            assert_eq!(reply, payload);
        }
    }

    wait_for(|| server.stats().total.packets_sent == u64::from(total));
    let stats = server.stats();
    assert_eq!(stats.per_worker.len(), workers);
    assert_eq!(stats.total.packets_sent, u64::from(total));
    // SO_REUSEPORT должен был распределить нагрузку хотя бы по двум очередям.
    let busy = stats
        .per_worker
        .iter()
        .filter(|worker| worker.packets_received > 0)
        .count();
    assert!(busy >= 2, "reuseport distributed only to {busy} worker(s)");

    server.shutdown().unwrap();
}

#[test]
fn empty_datagram_is_delivered() {
    let server = UdpServer::bind("127.0.0.1:0".parse().unwrap(), echo, 1).unwrap();
    server.start().unwrap();
    let socket = client(server.local_addr());

    socket.send(&[]).unwrap();
    let reply = recv_until(&socket, Instant::now() + DEADLINE).expect("empty reply");
    assert_eq!(reply.len(), 0);

    let stats = server.stats();
    assert_eq!(stats.total.packets_received, 1);
    assert_eq!(stats.total.oversize_received, 0);
    server.shutdown().unwrap();
}

#[test]
fn oversized_datagram_is_counted_and_dropped() {
    let cfg = RuntimeConfig::default()
        .with_workers(1)
        .with_rx_buffer_size(512)
        .with_tx(64, 2048)
        .with_socket_buffers(256 * 1024, 256 * 1024);
    let server = UdpServer::bind_with("127.0.0.1:0".parse().unwrap(), echo, cfg).unwrap();
    server.start().unwrap();
    let socket = client(server.local_addr());

    let oversized = vec![0xAB_u8; 2000];
    socket.send(&oversized).unwrap();
    // Ответа быть не должно: усечённый запрос не передаётся обработчику.
    assert!(
        recv_until(&socket, Instant::now() + Duration::from_millis(400)).is_none(),
        "truncated datagram must not produce a response"
    );
    let stats = server.stats();
    assert_eq!(stats.total.oversize_received, 1);
    assert_eq!(stats.total.packets_received, 1);

    // Worker жив и продолжает обслуживать нормальные запросы.
    socket.send(b"ok").unwrap();
    let reply = recv_until(&socket, Instant::now() + DEADLINE).expect("reply after oversize");
    assert_eq!(reply, b"ok");
    server.shutdown().unwrap();
}

#[test]
fn burst_overload_keeps_server_alive() {
    let cfg = RuntimeConfig::default()
        .with_workers(1)
        .with_rx_buffers(std::num::NonZeroU16::new(64).unwrap())
        .with_tx(8, 4096)
        .with_rx_buffer_size(512)
        .with_socket_buffers(64 * 1024, 64 * 1024);
    let server = UdpServer::bind_with("127.0.0.1:0".parse().unwrap(), echo, cfg).unwrap();
    server.start().unwrap();

    let socket = client(server.local_addr());
    let payload = [0x55_u8; 64];
    for _ in 0..5000 {
        // Ядро вправе дропнуть датаграмму — для UDP это штатный backpressure.
        let _ = socket.send(&payload);
    }
    thread::sleep(Duration::from_millis(300));

    // Новый клиент проверяет, что worker не умер и очередь разгребена.
    let probe = client(server.local_addr());
    probe.send(b"alive").unwrap();
    let reply = recv_until(&probe, Instant::now() + DEADLINE).expect("server alive after burst");
    assert_eq!(reply, b"alive");

    let stats = server.stats();
    assert!(stats.total.packets_received > 0);
    assert_eq!(stats.total.handler_panics, 0);
    server.shutdown().unwrap();
}

#[test]
fn handler_panic_flood_is_isolated() {
    let server = UdpServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        |request: &[u8], _peer: SocketAddr, out: &mut [u8]| {
            assert_ne!(request, b"boom", "handler panic (expected by test)");
            let len = request.len().min(out.len());
            out[..len].copy_from_slice(&request[..len]);
            Reply::Send(len)
        },
        1,
    )
    .unwrap();
    server.start().unwrap();
    let socket = client(server.local_addr());

    // 100 паник подряд: hook подавляет вывод, worker остаётся жив.
    for _ in 0..100 {
        socket.send(b"boom").unwrap();
    }
    wait_for(|| server.stats().total.handler_panics == 100);
    assert_eq!(server.stats().total.packets_sent, 0);

    socket.send(b"ok").unwrap();
    let reply = recv_until(&socket, Instant::now() + DEADLINE).expect("reply after panic flood");
    assert_eq!(reply, b"ok");
    server.shutdown().unwrap();
}

#[test]
fn oversized_reply_len_is_dropped() {
    let server = UdpServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        |request: &[u8], _peer: SocketAddr, out: &mut [u8]| {
            if request == b"big" {
                return Reply::Send(usize::MAX);
            }
            let len = request.len().min(out.len());
            out[..len].copy_from_slice(&request[..len]);
            Reply::Send(len)
        },
        1,
    )
    .unwrap();
    server.start().unwrap();
    let socket = client(server.local_addr());

    socket.send(b"big").unwrap();
    assert!(
        recv_until(&socket, Instant::now() + Duration::from_millis(400)).is_none(),
        "invalid Reply::Send(len) must not be sent"
    );
    wait_for(|| server.stats().total.responses_dropped >= 1);

    socket.send(b"ok").unwrap();
    assert_eq!(
        recv_until(&socket, Instant::now() + DEADLINE).expect("reply after invalid len"),
        b"ok"
    );
    server.shutdown().unwrap();
}

fn wildcard_serves_127_0_0_2(backend: BackendPreference, mode: RxMode) {
    let cfg = RuntimeConfig::default()
        .with_workers(2)
        .with_backend(backend)
        .with_rx_mode(mode);
    let server = UdpServer::bind_with("0.0.0.0:0".parse().unwrap(), echo, cfg).unwrap();
    server.start().unwrap();
    let port = server.local_addr().port();
    let target: SocketAddr = SocketAddr::from(([127, 0, 0, 2], port));

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(target).unwrap();
    socket
        .set_read_timeout(Some(CLIENT_TIMEOUT))
        .expect("read timeout");
    socket.send(b"pktinfo").unwrap();
    let mut buf = [0_u8; 64];
    let deadline = Instant::now() + DEADLINE;
    let (len, source) = loop {
        match socket.recv_from(&mut buf) {
            Ok(reply) => break reply,
            Err(err)
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut =>
            {
                assert!(Instant::now() < deadline, "no reply from 127.0.0.2");
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => panic!("recv failed: {err}"),
        }
    };
    assert_eq!(&buf[..len], b"pktinfo");
    assert_eq!(source.ip(), std::net::Ipv4Addr::new(127, 0, 0, 2));
    assert_eq!(source.port(), port);
    server.shutdown().unwrap();
}

#[test]
fn wildcard_bind_replies_from_requested_address() {
    wildcard_serves_127_0_0_2(BackendPreference::Uring, RxMode::Multishot);
}

#[test]
fn wildcard_bind_replies_in_recv_batch_mode() {
    wildcard_serves_127_0_0_2(BackendPreference::Uring, RxMode::RecvBatch);
}

#[cfg(feature = "epoll-fallback")]
#[test]
fn wildcard_bind_replies_from_requested_address_epoll() {
    wildcard_serves_127_0_0_2(BackendPreference::Epoll, RxMode::Auto);
}

fn flood_then_shutdown(backend: BackendPreference) {
    let cfg = RuntimeConfig::default()
        .with_workers(1)
        .with_backend(backend);
    let server = Arc::new(UdpServer::bind_with("127.0.0.1:0".parse().unwrap(), echo, cfg).unwrap());
    server.start().unwrap();
    let addr = server.local_addr();

    let stop = Arc::new(AtomicBool::new(false));
    let mut senders = Vec::new();
    for _ in 0..4 {
        let stop = Arc::clone(&stop);
        senders.push(thread::spawn(move || {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            socket.set_nonblocking(true).unwrap();
            socket.connect(addr).unwrap();
            let payload = [0x5A_u8; 64];
            while !stop.load(Ordering::Relaxed) {
                match socket.send(&payload) {
                    Ok(_) => {}
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        std::hint::spin_loop();
                    }
                    Err(_) => break,
                }
            }
        }));
    }

    thread::sleep(Duration::from_millis(200));
    let started = Instant::now();
    server.shutdown().unwrap();
    let elapsed = started.elapsed();
    stop.store(true, Ordering::Relaxed);
    for sender in senders {
        sender.join().unwrap();
    }
    assert!(
        elapsed < Duration::from_millis(500),
        "shutdown under flood took {elapsed:?}"
    );
}

#[test]
fn shutdown_under_flood_is_fast_uring() {
    flood_then_shutdown(BackendPreference::Uring);
}

#[cfg(feature = "epoll-fallback")]
#[test]
fn shutdown_under_flood_is_fast_epoll() {
    flood_then_shutdown(BackendPreference::Epoll);
}

#[test]
fn partial_start_stops_started_servers() {
    let runtime = Arc::new(Runtime::new(RuntimeConfig::default().with_workers(1)).unwrap());
    let first = runtime
        .udp_bind("127.0.0.1:0".parse().unwrap(), echo)
        .unwrap();
    let second = runtime
        .udp_bind("127.0.0.1:0".parse().unwrap(), echo)
        .unwrap();
    second.force_start_failure();

    let started = Instant::now();
    let error = runtime
        .run()
        .expect_err("forced start failure must propagate");
    assert!(
        error.to_string().contains("forced start failure"),
        "unexpected error: {error}"
    );
    assert!(started.elapsed() < Duration::from_secs(5));

    // Первый сервер уже был запущен и должен быть остановлен, а shutdown —
    // завершиться без WorkerTimeout.
    assert!(runtime.shutdown().is_ok());
    assert!(matches!(first.wait(), Ok(())));
}

#[test]
fn owned_handler_and_peer_address() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let handler = owned(move |request: &[u8], peer: SocketAddr| {
        sink.lock().unwrap().push(peer);
        let mut reply = request.to_vec();
        reply.extend_from_slice(b"-owned");
        Some(reply)
    });
    let server = UdpServer::bind("127.0.0.1:0".parse().unwrap(), handler, 1).unwrap();
    server.start().unwrap();

    let socket = client(server.local_addr());
    let local = socket.local_addr().unwrap();
    socket.send(b"hello").unwrap();
    let reply = recv_until(&socket, Instant::now() + DEADLINE).expect("owned reply");
    assert_eq!(reply, b"hello-owned");

    wait_for(|| seen.lock().unwrap().len() == 1);
    assert_eq!(seen.lock().unwrap()[0], local);
    server.shutdown().unwrap();
}

#[test]
fn shutdown_is_graceful_and_fast() {
    let server = Arc::new(UdpServer::bind("127.0.0.1:0".parse().unwrap(), echo, 2).unwrap());
    let runner = {
        let server = Arc::clone(&server);
        thread::spawn(move || server.run())
    };
    let socket = client(server.local_addr());
    socket.send(b"warmup").unwrap();
    assert_eq!(
        recv_until(&socket, Instant::now() + DEADLINE).expect("warmup reply"),
        b"warmup"
    );

    let started = Instant::now();
    server.shutdown().unwrap();
    let (done, timeout) = mpsc::channel();
    thread::spawn(move || {
        let _ = done.send(runner.join().is_ok());
    });
    assert!(
        timeout.recv_timeout(Duration::from_secs(3)).is_ok(),
        "run() did not return after shutdown"
    );
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[test]
fn recv_batch_mode_works() {
    let cfg = RuntimeConfig::default()
        .with_workers(2)
        .with_rx_mode(RxMode::RecvBatch);
    let server = UdpServer::bind_with("127.0.0.1:0".parse().unwrap(), echo, cfg).unwrap();
    server.start().unwrap();
    let socket = client(server.local_addr());
    for seq in 0..32_u16 {
        let payload = seq.to_be_bytes();
        socket.send(&payload).unwrap();
        let reply = recv_until(&socket, Instant::now() + DEADLINE).expect("batch reply");
        assert_eq!(reply, payload);
    }
    wait_for(|| server.stats().total.packets_sent == 32);
    server.shutdown().unwrap();
}

#[test]
fn multishot_mode_is_selected_by_default() {
    let server = UdpServer::bind("127.0.0.1:0".parse().unwrap(), echo, 1).unwrap();
    let caps = server.capabilities();
    if matches!(caps.backend, BackendKind::IoUring { level } if level >= 2) {
        assert!(caps.multishot_recv);
        assert!(caps.provided_buffers);
    }
    server.shutdown().unwrap();
}

#[test]
fn runtime_serves_two_servers_and_shuts_down() {
    let runtime = Arc::new(Runtime::new(RuntimeConfig::default().with_workers(2)).unwrap());
    let first = runtime
        .udp_bind("127.0.0.1:0".parse().unwrap(), echo)
        .unwrap();
    let second = runtime
        .udp_bind("127.0.0.1:0".parse().unwrap(), echo)
        .unwrap();
    let first_addr = first.local_addr();
    let second_addr = second.local_addr();
    assert_ne!(first_addr, second_addr);

    let runner = {
        let runtime = Arc::clone(&runtime);
        thread::spawn(move || runtime.run())
    };

    for addr in [first_addr, second_addr] {
        let socket = client(addr);
        socket.send(b"multi").unwrap();
        assert_eq!(
            recv_until(&socket, Instant::now() + DEADLINE).expect("reply"),
            b"multi"
        );
    }

    runtime.shutdown().unwrap();
    let (done, timeout) = mpsc::channel();
    thread::spawn(move || {
        let _ = done.send(runner.join().is_ok());
    });
    assert!(timeout.recv_timeout(Duration::from_secs(3)).is_ok());
}

#[test]
fn reuseport_allows_second_bind_on_same_port() {
    let server = UdpServer::bind("127.0.0.1:0".parse().unwrap(), echo, 1).unwrap();
    let addr = server.local_addr();
    let cfg = RuntimeConfig::default().with_workers(1);
    // Оба сокета выставляют SO_REUSEPORT, поэтому повторный bind разрешён —
    // это и есть механизм нескольких worker'ов на одном порту.
    let second = UdpServer::bind_with(addr, echo, cfg).expect("reuseport bind");
    assert_eq!(second.local_addr(), addr);
    server.shutdown().unwrap();
    second.shutdown().unwrap();
}

#[test]
fn stats_are_monotonic_and_aggregated() {
    let server = UdpServer::bind("127.0.0.1:0".parse().unwrap(), echo, 2).unwrap();
    server.start().unwrap();
    let socket = client(server.local_addr());
    for _ in 0..40 {
        socket.send(b"x").unwrap();
        recv_until(&socket, Instant::now() + DEADLINE).expect("reply");
    }
    wait_for(|| server.stats().total.packets_sent == 40);
    let stats = server.stats();
    let sum: u64 = stats.per_worker.iter().map(|w| w.packets_sent).sum();
    assert_eq!(sum, stats.total.packets_sent);
    assert_eq!(sum, 40);
    server.shutdown().unwrap();
}

#[cfg(feature = "epoll-fallback")]
#[test]
fn epoll_backend_echo_and_shutdown() {
    use pulse_runtime::BackendPreference;

    let cfg = RuntimeConfig::default()
        .with_workers(2)
        .with_backend(BackendPreference::Epoll)
        .with_rx_buffer_size(512)
        .with_tx(64, 2048);
    let server = UdpServer::bind_with("127.0.0.1:0".parse().unwrap(), echo, cfg).unwrap();
    assert_eq!(server.backend(), BackendKind::Epoll);
    server.start().unwrap();
    let addr = server.local_addr();

    let clients: Vec<UdpSocket> = (0..4).map(|_| client(addr)).collect();
    for socket in &clients {
        for seq in 0..32_u16 {
            let payload = seq.to_be_bytes();
            socket.send(&payload).unwrap();
            let reply = recv_until(socket, Instant::now() + DEADLINE).expect("epoll reply");
            assert_eq!(reply, payload);
        }
    }
    // Усечение и пустая датаграмма на epoll-бэкенде.
    let socket = client(addr);
    socket.send(&[]).unwrap();
    assert_eq!(
        recv_until(&socket, Instant::now() + DEADLINE)
            .expect("empty datagram")
            .len(),
        0
    );
    socket.send(&vec![0xAB_u8; 2000]).unwrap();
    assert!(
        recv_until(&socket, Instant::now() + Duration::from_millis(400)).is_none(),
        "oversize must be dropped"
    );

    wait_for(|| server.stats().total.packets_sent == 129);
    let stats = server.stats();
    assert_eq!(stats.total.oversize_received, 1);
    server.shutdown().unwrap();
}

#[test]
fn ipv6_loopback_echo() {
    // В окружении без IPv6 loopback тест не применим.
    let Ok(server) = UdpServer::bind("[::1]:0".parse().unwrap(), echo, 1) else {
        return;
    };
    server.start().unwrap();
    let socket = UdpSocket::bind("[::1]:0").unwrap();
    socket.connect(server.local_addr()).unwrap();
    socket
        .set_read_timeout(Some(CLIENT_TIMEOUT))
        .expect("read timeout");
    socket.send(b"v6").unwrap();
    let reply = recv_until(&socket, Instant::now() + DEADLINE).expect("ipv6 reply");
    assert_eq!(reply, b"v6");
    server.shutdown().unwrap();
}

#[test]
fn optional_kernel_features_degrade_without_breaking_echo() {
    let cfg = RuntimeConfig::default()
        .with_workers(1)
        .with_rx_buffer_size(512)
        .with_tx(32, 1024)
        .with_rx_buffers(std::num::NonZeroU16::new(64).unwrap())
        .with_cqe_batch(32)
        .with_thread_stack(128 * 1024)
        .with_busy_poll(50)
        .with_prefer_busy_poll(true)
        .with_register_files(false)
        .with_coop_taskrun(false);
    let server = UdpServer::bind_with("127.0.0.1:0".parse().unwrap(), echo, cfg).unwrap();
    // busy-poll/COOP не обязаны быть доступны (EPERM/EINVAL) — bind не падает.
    assert!(!server.capabilities().registered_files);
    server.start().unwrap();
    let socket = client(server.local_addr());
    socket.send(b"degrade").unwrap();
    assert_eq!(
        recv_until(&socket, Instant::now() + DEADLINE).expect("reply"),
        b"degrade"
    );
    server.shutdown().unwrap();
}

#[test]
fn sqpoll_request_degrades_gracefully() {
    let cfg = RuntimeConfig::default()
        .with_workers(1)
        .with_sqpoll(Some(1000))
        .with_sqpoll_cpu(None);
    let server = UdpServer::bind_with("127.0.0.1:0".parse().unwrap(), echo, cfg).unwrap();
    let caps = server.capabilities();
    server.start().unwrap();
    let socket = client(server.local_addr());
    socket.send(b"sqpoll").unwrap();
    assert_eq!(
        recv_until(&socket, Instant::now() + DEADLINE).expect("reply"),
        b"sqpoll"
    );
    // Флаг в capabilities отражает фактическое состояние: без прав SQPOLL
    // просто выключен, а echo продолжает работать.
    assert!(matches!(caps.backend, BackendKind::IoUring { .. }));
    if !caps.sqpoll {
        eprintln!("sqpoll unavailable in this environment; degradation path exercised");
    }
    server.shutdown().unwrap();
}

#[test]
fn cpu_affinity_outside_process_set_is_rejected_on_start() {
    let cfg = RuntimeConfig::default()
        .with_workers(1)
        .with_cpu_affinity(vec![usize::MAX - 1]);
    let server = UdpServer::bind_with("127.0.0.1:0".parse().unwrap(), echo, cfg).unwrap();
    let error = server.start().expect_err("foreign CPU must be rejected");
    assert!(
        error.to_string().contains("cpu_affinity"),
        "unexpected error: {error}"
    );
}

#[test]
fn wait_before_start_is_rejected() {
    let server = UdpServer::bind("127.0.0.1:0".parse().unwrap(), echo, 1).unwrap();
    assert!(matches!(server.wait(), Err(RuntimeError::NotStarted)));
    server.shutdown().unwrap();
}

#[test]
fn bind_error_carries_address_context() {
    let addr: SocketAddr = "192.0.2.1:0".parse().unwrap();
    match UdpServer::bind(addr, echo, 1) {
        Ok(server) => {
            // Адрес не должен быть локальным, но если среда так настроена —
            // просто корректно останавливаем сервер.
            server.shutdown().unwrap();
        }
        Err(err) => {
            let message = err.to_string();
            assert!(message.contains("192.0.2.1"), "unexpected error: {message}");
        }
    }
}
