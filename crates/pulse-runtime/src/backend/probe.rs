//! Проба возможностей io_uring и создание ring'а.

use std::io;

use io_uring::{IoUring, cqueue, squeue};

use super::pbuf::ProvidedBufRing;
use crate::config::{BackendKind, Capabilities, RuntimeConfig};
use crate::error::RuntimeError;

/// `bgid`, используемый только для пробы регистрации provided buffers.
const PROBE_BGID: u16 = 4095;

/// Создать ring с предпочтительными флагами; при отказе ядра — с базовыми.
///
/// Возвращает ring и признак «приняты L3-флаги (`SINGLE_ISSUER | DEFER_TASKRUN`)».
pub(crate) fn build_ring(cfg: &RuntimeConfig) -> io::Result<(IoUring, bool)> {
    match try_ring(cfg, true) {
        Ok(ring) => Ok((ring, true)),
        Err(_) => {
            // Если базовый вариант тоже не работает, отдаём его ошибку: она
            // описывает фундаментальную причину (ENOSYS/EACCES), а не EINVAL
            // от неподдержанного флага.
            try_ring(cfg, false).map(|ring| (ring, false))
        }
    }
}

fn try_ring(cfg: &RuntimeConfig, fast: bool) -> io::Result<IoUring> {
    let mut builder = IoUring::<squeue::Entry, cqueue::Entry>::builder();
    builder.setup_cqsize(cfg.cq_entries);
    if let Some(idle) = cfg.sqpoll_idle {
        builder.setup_sqpoll(idle);
    }
    if fast {
        builder.setup_single_issuer();
        builder.setup_defer_taskrun();
    }
    builder.build(cfg.sq_entries)
}

/// Проверить доступность io_uring и определить уровень возможностей.
///
/// Проба создаёт ring, пытается зарегистрировать крошечный ring provided
/// buffers (L2) и сообщает, приняты ли L3-флаги.
pub(crate) fn probe(cfg: &RuntimeConfig) -> Result<Capabilities, RuntimeError> {
    let (ring, fast_flags) =
        build_ring(cfg).map_err(|source| RuntimeError::IoUringUnavailable { source })?;

    let mut provided_buffers = false;
    if let Ok(pbuf) = ProvidedBufRing::new(16, PROBE_BGID) {
        // SAFETY: pbuf живёт дольше регистрации и снимается до `Drop`;
        // ring переживает pbuf в этой области видимости.
        if unsafe { pbuf.register(&ring.submitter()) }.is_ok() {
            provided_buffers = true;
            let _ = pbuf.unregister(&ring.submitter());
        }
    }

    let nodrop = ring.params().is_feature_nodrop();
    // L3 требует и флагов, и NODROP: без NODROP переполнение CQ теряет CQE.
    let level = if provided_buffers {
        if fast_flags && nodrop { 3 } else { 2 }
    } else {
        1
    };
    Ok(Capabilities {
        backend: BackendKind::IoUring { level },
        multishot_recv: provided_buffers,
        provided_buffers,
        defer_taskrun: fast_flags,
        sqpoll: ring.params().is_setup_sqpoll(),
        nodrop,
    })
}
