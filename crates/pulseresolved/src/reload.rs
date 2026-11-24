//! Перечитывание blocklist по SIGHUP и по расписанию.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use pulse_resolver::{BlocklistStats, Resolver, ResolverError};

use crate::logging;
use crate::stats::Stats;

/// Фоновый перезагрузчик blocklist.
pub(crate) struct Reloader {
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Reloader {
    pub(crate) fn start(
        resolver: Resolver,
        stats: Arc<Stats>,
        interval: Duration,
    ) -> std::io::Result<Self> {
        let shutdown = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&shutdown);
        let handle = thread::Builder::new()
            .name("pulseresolved-reload".to_owned())
            .spawn(move || {
                while !wait_for(&flag, interval) {
                    let _ = reload_now(&resolver, &stats);
                }
            })?;
        Ok(Self {
            shutdown,
            handle: Some(handle),
        })
    }

    pub(crate) fn stop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for Reloader {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Возвращает `true`, если пришло время остановиться.
fn wait_for(shutdown: &AtomicBool, interval: Duration) -> bool {
    let deadline = Instant::now() + interval;
    loop {
        if shutdown.load(Ordering::Acquire) {
            return true;
        }
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        thread::sleep((deadline - now).min(Duration::from_millis(100)));
    }
}

/// Перечитывает все файлы blocklist и логирует результат.
pub(crate) fn reload_now(
    resolver: &Resolver,
    stats: &Stats,
) -> Result<BlocklistStats, ResolverError> {
    match resolver.reload_blocklists() {
        Ok(stats_loaded) => {
            stats.reload_ok();
            logging::info(
                "blocklist",
                &format!(
                    "reloaded: blocked={} allowed={} skipped={}",
                    stats_loaded.blocked, stats_loaded.allowed, stats_loaded.skipped
                ),
            );
            Ok(stats_loaded)
        }
        Err(error) => {
            stats.reload_failed();
            logging::error("blocklist", &format!("reload failed: {error}"));
            Err(error)
        }
    }
}
