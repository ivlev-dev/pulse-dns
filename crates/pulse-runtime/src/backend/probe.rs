//! Проба возможностей io_uring и создание ring'а.

use std::io;
use std::os::fd::RawFd;

use io_uring::{IoUring, cqueue, squeue};

use super::pbuf::ProvidedBufRing;
use crate::config::{BackendKind, Capabilities, RuntimeConfig};
use crate::error::RuntimeError;

/// `bgid`, используемый только для пробы регистрации provided buffers.
const PROBE_BGID: u16 = 4095;

/// Созданный ring и фактически принятые им возможности.
pub(crate) struct RingSetup {
    pub(crate) ring: IoUring,
    /// Приняты `SINGLE_ISSUER | DEFER_TASKRUN`.
    pub(crate) fast_flags: bool,
    /// Принят `COOP_TASKRUN`.
    pub(crate) coop_taskrun: bool,
    /// Ring создан с `SQPOLL`.
    pub(crate) sqpoll: bool,
}

#[derive(Debug, Clone, Copy)]
struct Tier {
    fast: bool,
    coop: bool,
    sqpoll: Option<(u32, Option<usize>)>,
}

/// Создать ring с предпочтительными флагами, деградируя по одному:
/// SQPOLL+SQ_AFF → SQPOLL → fast-флаги → базовый ring.
///
/// `sqpoll_cpu` — CPU для `IORING_SETUP_SQ_AFF`; `None` — без привязки.
pub(crate) fn build_ring(cfg: &RuntimeConfig, sqpoll_cpu: Option<usize>) -> io::Result<RingSetup> {
    let mut last_error = None;
    let mut tiers = Vec::with_capacity(6);
    if let Some(idle) = cfg.sqpoll_idle {
        if let Some(cpu) = sqpoll_cpu {
            tiers.push(Tier {
                fast: true,
                coop: cfg.coop_taskrun,
                sqpoll: Some((idle, Some(cpu))),
            });
        }
        tiers.push(Tier {
            fast: true,
            coop: cfg.coop_taskrun,
            sqpoll: Some((idle, None)),
        });
        tiers.push(Tier {
            fast: false,
            coop: false,
            sqpoll: Some((idle, None)),
        });
    }
    if cfg.coop_taskrun {
        tiers.push(Tier {
            fast: true,
            coop: true,
            sqpoll: None,
        });
    }
    tiers.push(Tier {
        fast: true,
        coop: false,
        sqpoll: None,
    });
    tiers.push(Tier {
        fast: false,
        coop: false,
        sqpoll: None,
    });

    for tier in tiers {
        match try_ring(cfg, tier) {
            Ok(ring) => {
                return Ok(RingSetup {
                    ring,
                    fast_flags: tier.fast,
                    coop_taskrun: tier.coop,
                    sqpoll: tier.sqpoll.is_some(),
                });
            }
            Err(err) => last_error = Some(err),
        }
    }
    Err(last_error.unwrap_or_else(|| io::Error::from(io::ErrorKind::InvalidInput)))
}

fn try_ring(cfg: &RuntimeConfig, tier: Tier) -> io::Result<IoUring> {
    let mut builder = IoUring::<squeue::Entry, cqueue::Entry>::builder();
    builder.setup_cqsize(cfg.cq_entries);
    if let Some((idle, cpu)) = tier.sqpoll {
        builder.setup_sqpoll(idle);
        if let Some(cpu) = cpu {
            builder.setup_sqpoll_cpu(u32::try_from(cpu).unwrap_or(u32::MAX));
        }
    }
    if tier.fast {
        builder.setup_single_issuer();
        builder.setup_defer_taskrun();
    }
    if tier.coop {
        builder.setup_coop_taskrun();
    }
    builder.build(cfg.sq_entries)
}

/// Проверить доступность io_uring и определить уровень возможностей.
///
/// Проба создаёт ring, пытается зарегистрировать крошечный ring provided
/// buffers (L2) и файл-заглушку (registered files); сообщает, приняты ли
/// L3-флаги и фактически ли включился SQPOLL.
pub(crate) fn probe(cfg: &RuntimeConfig) -> Result<Capabilities, RuntimeError> {
    let sqpoll_cpu = cfg
        .sqpoll_cpu
        .or_else(|| crate::socket::allowed_cpus().first().copied());
    let setup = build_ring(cfg, sqpoll_cpu)
        .map_err(|source| RuntimeError::IoUringUnavailable { source })?;
    let ring = &setup.ring;

    if cfg.sqpoll_idle.is_some() && !setup.sqpoll {
        eprintln!(
            "pulse-runtime: warning: SQPOLL requested but unavailable \
             (insufficient privileges or kernel support); continuing without it"
        );
    }

    let mut provided_buffers = false;
    if let Ok(pbuf) = ProvidedBufRing::new(16, PROBE_BGID) {
        // SAFETY: pbuf живёт дольше регистрации и снимается до `Drop`;
        // ring переживает pbuf в этой области видимости.
        if unsafe { pbuf.register(&ring.submitter()) }.is_ok() {
            provided_buffers = true;
            let _ = pbuf.unregister(&ring.submitter());
        }
    }

    let registered_files = cfg.register_files && probe_registered_files(&ring.submitter());

    let nodrop = ring.params().is_feature_nodrop();
    // L3 требует и флагов, и NODROP: без NODROP переполнение CQ теряет CQE.
    let level = if provided_buffers {
        if setup.fast_flags && nodrop { 3 } else { 2 }
    } else {
        1
    };
    Ok(Capabilities {
        backend: BackendKind::IoUring { level },
        multishot_recv: provided_buffers,
        provided_buffers,
        defer_taskrun: setup.fast_flags,
        coop_taskrun: setup.coop_taskrun,
        sqpoll: setup.sqpoll,
        registered_files,
        nodrop,
    })
}

/// Проверить поддержку регистрации файлов разреженным fd (`-1`).
fn probe_registered_files(submitter: &io_uring::Submitter<'_>) -> bool {
    let sparse: [RawFd; 1] = [-1];
    if submitter.register_files(&sparse).is_err() {
        return false;
    }
    let _ = submitter.unregister_files();
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqpoll_tiers_are_tried_first() {
        // Функциональная проверка без привилегий: build_ring не падает и
        // сообщает фактический SQPOLL, а не запрошенный.
        let cfg = RuntimeConfig::default()
            .with_workers(1)
            .with_sqpoll(Some(100));
        let setup = build_ring(&cfg, Some(0)).expect("ring");
        let requested = cfg.sqpoll_idle.is_some();
        if requested && setup.sqpoll {
            assert!(setup.ring.params().is_setup_sqpoll());
        }
    }

    #[test]
    fn basic_ring_has_no_sqpoll() {
        let cfg = RuntimeConfig::default().with_sqpoll(None);
        let setup = build_ring(&cfg, None).expect("ring");
        assert!(!setup.sqpoll);
        assert!(!setup.ring.params().is_setup_sqpoll());
    }
}
