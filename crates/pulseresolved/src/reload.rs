//! Фоновый worker blocklist: локальные файлы и удалённые HTTPS-источники.
//!
//! Интервал пробуждения вычисляется сервисом: ближайший из `reload_secs`
//! локальных файлов и `refresh_secs` удалённых источников. Для удалённых
//! источников сроки дополнительно размываются jitter'ом внутри
//! `pulse-resolver`, чтобы не бить по серверу синхронно.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::blocklist::BlocklistService;

const MAX_IDLE_WAIT: Duration = Duration::from_secs(3600);

/// Фоновый перезагрузчик blocklist.
pub(crate) struct Reloader {
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Reloader {
    pub(crate) fn start(service: Arc<BlocklistService>) -> std::io::Result<Self> {
        let shutdown = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&shutdown);
        let handle = thread::Builder::new()
            .name("pulseresolved-blocklist".to_owned())
            .spawn(move || {
                loop {
                    let delay = service.next_delay().unwrap_or(MAX_IDLE_WAIT);
                    if wait_for(&flag, delay) {
                        break;
                    }
                    service.tick();
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
