//! Concurrency: 100 потоков на одном Resolver.

mod support;

use std::sync::{Arc, Barrier};
use std::time::Duration;

use pulse_dns::{Message, Name, Question, Rclass, Rcode, Rtype};
use pulse_resolver::{Resolver, ResolverConfig, TimeoutConfig};
use support::{MockServer, RawHandler, a, encode, response};

#[test]
fn hundred_threads_share_one_resolver() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Resolver>();

    let handler: RawHandler = Arc::new(|request, _tcp| {
        let mut reply = response(request, Rcode::NOERROR);
        reply.add_answer(a("example.com", 60, [192, 0, 2, 1]));
        Some(encode(&reply))
    });
    let server = MockServer::spawn(handler);
    let mut config = ResolverConfig::forward(vec![server.address()]);
    config.timeouts = TimeoutConfig {
        per_query: Duration::from_millis(500),
        tcp: Duration::from_millis(700),
        total: Duration::from_secs(3),
    };
    config.retries = 1;
    config.use_0x20 = false;
    let resolver = Arc::new(Resolver::new(config).unwrap());
    let warmup = resolver.resolve_qname(&Name::parse("example.com").unwrap(), Rtype::A);
    assert_eq!(warmup.rcode(), Rcode::NOERROR);
    let barrier = Arc::new(Barrier::new(100));
    let mut threads = Vec::new();
    for _ in 0..100 {
        let resolver = Arc::clone(&resolver);
        let barrier = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            let name = Name::parse("example.com").unwrap();
            let reply = resolver.resolve_qname(&name, Rtype::A);
            assert_eq!(reply.rcode(), Rcode::NOERROR);
            assert_eq!(reply.answers().len(), 1);
        }));
    }
    for thread in threads {
        thread.join().unwrap();
    }
    let stats = resolver.stats();
    assert_eq!(stats.queries, 101);
    assert_eq!(stats.servfail, 0);
    assert!(stats.cache.hits >= 99, "cache hits: {}", stats.cache.hits);
}

#[test]
fn hundred_threads_use_wire_fast_path() {
    let handler: RawHandler = Arc::new(|request, _tcp| {
        let mut reply = response(request, Rcode::NOERROR);
        reply.add_answer(a("fast.example", 60, [192, 0, 2, 2]));
        Some(encode(&reply))
    });
    let server = MockServer::spawn(handler);
    let mut config = ResolverConfig::forward(vec![server.address()]);
    config.timeouts = TimeoutConfig {
        per_query: Duration::from_millis(500),
        tcp: Duration::from_millis(700),
        total: Duration::from_secs(3),
    };
    config.retries = 1;
    config.use_0x20 = false;
    let resolver = Arc::new(Resolver::new(config).unwrap());
    let query = Message::query(
        0x77,
        Question::new(Name::parse("fast.example").unwrap(), Rtype::A, Rclass::IN),
    );
    assert_eq!(resolver.resolve(&query).rcode(), Rcode::NOERROR);

    let barrier = Arc::new(Barrier::new(100));
    let mut threads = Vec::new();
    for _ in 0..100 {
        let resolver = Arc::clone(&resolver);
        let barrier = Arc::clone(&barrier);
        let query = query.clone();
        threads.push(std::thread::spawn(move || {
            let mut out = [0_u8; 512];
            barrier.wait();
            for _ in 0..64 {
                let length = resolver
                    .resolve_into(&query, &mut out)
                    .expect("wire response");
                assert!(length > 12);
            }
        }));
    }
    for thread in threads {
        thread.join().unwrap();
    }
    let stats = resolver.stats();
    assert_eq!(stats.servfail, 0);
    assert!(
        stats.cache.hits >= 100 * 64,
        "wire cache hits: {}",
        stats.cache.hits
    );
}
