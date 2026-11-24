//! Group commit v2.0 (B2b, §7.1): координатор батчит готовые коммиты зон и
//! выполняет **ровно два** `fdatasync` на группу (`Sync`).
//!
//! Архитектура:
//!
//! * писатель зоны готовит коммит ([`ParallelZone::commit_via`]): dirty-страницы
//!   уже записаны, версия/chain/bucket-образы спланированы (`prepare_publish`);
//! * запрос уходит в ограниченную очередь [`GroupCommitter`] (backpressure по
//!   числу и байтам, §7.3);
//! * координатор набирает группу по числу зон, байтам и задержке
//!   `MAX_BATCH_DELAY` (bulk-коммит > `256 КиБ` идёт отдельной группой);
//! * фаза 1 — `ALLOC_RECORD` + chain/bucket всех зон → `fdatasync`;
//! * фаза 2 — две копии `RootEntry` всех зон → `fdatasync` → публикация голов →
//!   ack писателям.
//!
//! Ошибка ввода-вывода переводит файл в `CommitUncertain` (`write_locked`) и не
//! публикует ни одной головы группы; `ReaderContended` — per-zone retryable.
//!
//! [`ParallelZone::commit_via`]: crate::parallel::zone::ParallelZone::commit_via

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::parallel::consts::{
    BULK_COMMIT_BYTES, MAX_BATCH_BYTES, MAX_BATCH_DELAY, MAX_BATCH_ZONES, QUEUE_BYTES, QUEUE_ZONES,
};
use crate::parallel::error::ParallelError;
use crate::parallel::layout::SyncModeV2;
use crate::parallel::root::RootEntry;
use crate::parallel::store::{ParallelStore, PublishOutcome};

/// Окно «дозора» после первой пары запросов: собирает одновременную волну
/// писателей, не добавляя полный `MAX_BATCH_DELAY` к каждой группе.
const BATCH_SETTLE: Duration = Duration::from_micros(250);

/// Параметры координатора group commit (§7.1 п. 8, §7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupCommitConfig {
    /// Максимум зон в группе.
    pub max_batch_zones: u32,
    /// Максимум суммы веса запросов группы (байты).
    pub max_batch_bytes: u64,
    /// Максимальная задержка набора группы.
    pub max_batch_delay: Duration,
    /// Ёмкость очереди (число запросов) — backpressure.
    pub queue_zones: usize,
    /// Бюджет байтов очереди — backpressure.
    pub queue_bytes: u64,
    /// Запрос больше этого размера выполняется отдельной группой.
    pub bulk_bytes: u64,
}

impl Default for GroupCommitConfig {
    fn default() -> Self {
        Self {
            max_batch_zones: MAX_BATCH_ZONES,
            max_batch_bytes: MAX_BATCH_BYTES,
            max_batch_delay: MAX_BATCH_DELAY,
            queue_zones: QUEUE_ZONES,
            queue_bytes: QUEUE_BYTES,
            bulk_bytes: BULK_COMMIT_BYTES,
        }
    }
}

impl GroupCommitConfig {
    /// Компактная конфигурация для тестов (меньше задержка/очередь).
    #[must_use]
    pub fn small() -> Self {
        Self {
            max_batch_zones: 64,
            max_batch_bytes: 256 << 10,
            max_batch_delay: Duration::from_micros(500),
            queue_zones: 256,
            queue_bytes: 16 << 20,
            bulk_bytes: 128 << 10,
        }
    }
}

/// Счётчики координатора (собственные, не пересекаются с одиночными
/// публикациями).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GroupStats {
    /// Выполненных групп.
    pub groups: u64,
    /// Зона-коммитов в группах (включая отменённые).
    pub members: u64,
    /// `fdatasync` в группах.
    pub fsyncs: u64,
    /// Максимальный размер группы.
    pub max_members: u64,
    /// Отменённых зон (`ReaderContended`).
    pub aborted: u64,
    /// Успешно опубликованных зон (ack отправлен).
    pub commits: u64,
}

#[derive(Default)]
struct GroupStatsCounters {
    groups: u64,
    members: u64,
    fsyncs: u64,
    max_members: u64,
    aborted: u64,
    commits: u64,
}

impl GroupStatsCounters {
    fn snapshot(&self) -> GroupStats {
        GroupStats {
            groups: self.groups,
            members: self.members,
            fsyncs: self.fsyncs,
            max_members: self.max_members,
            aborted: self.aborted,
            commits: self.commits,
        }
    }
}

/// Байтовый шлюз backpressure (`QUEUE_BYTES`).
#[derive(Debug)]
struct ByteGate {
    used: Mutex<u64>,
    free: Condvar,
    limit: u64,
    closed: AtomicBool,
}

impl ByteGate {
    fn new(limit: u64) -> Self {
        Self {
            used: Mutex::new(0),
            free: Condvar::new(),
            limit,
            closed: AtomicBool::new(false),
        }
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.free.notify_all();
    }

    /// `false` — координатор остановлен, ждать бессмысленно.
    fn acquire(&self, bytes: u64) -> bool {
        if bytes == 0 || self.limit == 0 {
            return !self.closed.load(Ordering::Acquire);
        }
        let mut used = lock(&self.used);
        while used.saturating_add(bytes) > self.limit {
            if self.closed.load(Ordering::Acquire) {
                return false;
            }
            used = match self.free.wait(used) {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
        if self.closed.load(Ordering::Acquire) {
            return false;
        }
        *used = used.saturating_add(bytes);
        true
    }

    fn release(&self, bytes: u64) {
        if bytes == 0 || self.limit == 0 {
            return;
        }
        let mut used = lock(&self.used);
        *used = used.saturating_sub(bytes);
        self.free.notify_all();
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

struct GroupRequest {
    prepared: crate::parallel::store::PreparedPublish,
    mode: SyncModeV2,
    weight: u64,
    reply: SyncSender<Result<PublishOutcome, ParallelError>>,
}

/// Координатор group commit с каналом и фоновым потоком.
///
/// Создаётся на `Arc<ParallelStore>`; писатели вызывают
/// [`ParallelZone::commit_via`](crate::parallel::zone::ParallelZone::commit_via).
/// `Drop` останавливает координатора после обработки уже принятых запросов.
pub struct GroupCommitter {
    store: Arc<ParallelStore>,
    tx: Option<SyncSender<GroupRequest>>,
    gate: Arc<ByteGate>,
    stats: Arc<Mutex<GroupStatsCounters>>,
    handle: Option<JoinHandle<()>>,
    config: GroupCommitConfig,
}

impl std::fmt::Debug for GroupCommitter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupCommitter")
            .field("config", &self.config)
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

impl GroupCommitter {
    /// Запускает координатора с конфигурацией по умолчанию.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` — нулевые лимиты группы/очереди.
    pub fn new(store: Arc<ParallelStore>) -> Result<Self, ParallelError> {
        Self::with_config(store, GroupCommitConfig::default())
    }

    /// Запускает координатора с явной конфигурацией.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` — нулевые `max_batch_zones`/`queue_zones`.
    pub fn with_config(
        store: Arc<ParallelStore>,
        config: GroupCommitConfig,
    ) -> Result<Self, ParallelError> {
        if config.max_batch_zones == 0 || config.queue_zones == 0 {
            return Err(ParallelError::InvalidArgument {
                field: "group config",
            });
        }
        let (tx, rx) = sync_channel(config.queue_zones);
        let gate = Arc::new(ByteGate::new(config.queue_bytes));
        let stats = Arc::new(Mutex::new(GroupStatsCounters::default()));
        let worker_store = Arc::clone(&store);
        let worker_gate = Arc::clone(&gate);
        let worker_stats = Arc::clone(&stats);
        let worker_config = config;
        let handle = std::thread::Builder::new()
            .name("pulse-zonefile-group-commit".into())
            .spawn(move || {
                run_coordinator(
                    &worker_store,
                    &rx,
                    &worker_gate,
                    &worker_stats,
                    &worker_config,
                );
            })
            .map_err(ParallelError::Io)?;
        Ok(Self {
            store,
            tx: Some(tx),
            gate,
            stats,
            handle: Some(handle),
            config,
        })
    }

    /// Конфигурация координатора.
    #[must_use]
    pub const fn config(&self) -> GroupCommitConfig {
        self.config
    }

    /// Счётчики координатора.
    #[must_use]
    pub fn stats(&self) -> GroupStats {
        lock(&self.stats).snapshot()
    }

    /// Стор координатора.
    #[must_use]
    pub fn store(&self) -> &Arc<ParallelStore> {
        &self.store
    }

    /// Готовит и отправляет коммит зоны в группу (`Sync`).
    ///
    /// # Errors
    ///
    /// `DurabilityBelowFileMode`, `GroupClosed`, `MapFull`, `Corrupt`,
    /// `ZoneWriterStalled`, `InvalidArgument`.
    pub fn commit(
        &self,
        entry: RootEntry,
        drops: &[u32],
        weight: u64,
    ) -> Result<PublishOutcome, ParallelError> {
        self.commit_with(entry, drops, weight, SyncModeV2::Sync)
    }

    /// Готовит и отправляет коммит зоны в группу с явным режимом.
    ///
    /// # Errors
    ///
    /// См. [`GroupCommitter::commit`].
    pub fn commit_with(
        &self,
        entry: RootEntry,
        drops: &[u32],
        weight: u64,
        mode: SyncModeV2,
    ) -> Result<PublishOutcome, ParallelError> {
        // Режим проверяется до блокировки на очереди, чтобы не занимать слот.
        self.store.check_durability(mode)?;
        let prepared = self.store.prepare_publish(entry, drops, weight)?;
        let bytes = prepared.weight();
        if !self.gate.acquire(bytes) {
            return Err(ParallelError::GroupClosed);
        }
        let (reply_tx, reply_rx) = sync_channel(1);
        let request = GroupRequest {
            prepared,
            mode,
            weight: bytes,
            reply: reply_tx,
        };
        let sent = match self.tx.as_ref() {
            Some(tx) => tx.send(request).is_ok(),
            None => false,
        };
        if !sent {
            self.gate.release(bytes);
            return Err(ParallelError::GroupClosed);
        }
        match reply_rx.recv() {
            Ok(outcome) => outcome,
            Err(_) => Err(ParallelError::GroupClosed),
        }
    }

    /// Останавливает координатора, дожидаясь обработки принятых запросов.
    pub fn shutdown(mut self) {
        self.stop();
    }

    fn stop(&mut self) {
        self.tx.take();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for GroupCommitter {
    fn drop(&mut self) {
        self.stop();
    }
}

#[allow(clippy::too_many_lines)]
fn run_coordinator(
    store: &ParallelStore,
    rx: &Receiver<GroupRequest>,
    gate: &ByteGate,
    stats: &Mutex<GroupStatsCounters>,
    config: &GroupCommitConfig,
) {
    let mut pending: Option<GroupRequest> = None;
    loop {
        let first = match pending.take() {
            Some(request) => request,
            None => match rx.recv() {
                Ok(request) => request,
                Err(_) => break,
            },
        };
        let mode = first.mode;
        let first_weight = first.weight;
        let mut batch = vec![first];
        let mut bytes = first_weight;
        let deadline = Instant::now() + config.max_batch_delay;
        let mut disconnected = false;
        let mut settled = false;
        while u32::try_from(batch.len()).unwrap_or(u32::MAX) < config.max_batch_zones
            && bytes < config.max_batch_bytes
        {
            if batch.len() == 1 && bytes > config.bulk_bytes {
                break;
            }
            if batch.len() >= 2 {
                // Группа уже собрана: добираем то, что в очереди. Если очередь
                // пуста — короткое окно «дозора» под волну одновременных
                // писателей (не `MAX_BATCH_DELAY` на каждую группу).
                match rx.try_recv() {
                    Ok(request) => {
                        if request.mode != mode {
                            pending = Some(request);
                            break;
                        }
                        bytes = bytes.saturating_add(request.weight);
                        batch.push(request);
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => {
                        if settled {
                            break;
                        }
                        settled = true;
                        let remaining = deadline.saturating_duration_since(Instant::now());
                        let settle = remaining.min(BATCH_SETTLE);
                        if settle.is_zero() {
                            break;
                        }
                        match rx.recv_timeout(settle) {
                            Ok(request) => {
                                if request.mode != mode {
                                    pending = Some(request);
                                    break;
                                }
                                bytes = bytes.saturating_add(request.weight);
                                batch.push(request);
                            }
                            Err(RecvTimeoutError::Timeout) => break,
                            Err(RecvTimeoutError::Disconnected) => {
                                disconnected = true;
                                break;
                            }
                        }
                    }
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        disconnected = true;
                        break;
                    }
                }
                continue;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match rx.recv_timeout(remaining) {
                Ok(request) => {
                    if request.mode != mode {
                        pending = Some(request);
                        break;
                    }
                    bytes = bytes.saturating_add(request.weight);
                    batch.push(request);
                }
                Err(RecvTimeoutError::Timeout) => break,
                Err(RecvTimeoutError::Disconnected) => {
                    disconnected = true;
                    break;
                }
            }
        }
        let count = batch.len();
        let mut members = Vec::with_capacity(count);
        let mut meta = Vec::with_capacity(count);
        for request in batch {
            members.push(request.prepared);
            meta.push((request.reply, request.weight, request.mode));
        }
        let outcomes = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            store.execute_group(members, mode)
        }));
        let Ok(outcomes) = outcomes else {
            for (reply, weight, _) in meta {
                let _ = reply.send(Err(ParallelError::GroupClosed));
                gate.release(weight);
            }
            break;
        };
        let mut counters = lock(stats);
        counters.groups = counters.groups.saturating_add(1);
        counters.members = counters
            .members
            .saturating_add(u64::try_from(count).unwrap_or(0));
        counters.fsyncs = counters.fsyncs.saturating_add(match mode {
            SyncModeV2::Sync => 2,
            SyncModeV2::Flush => 1,
            SyncModeV2::Memory => 0,
        });
        counters.max_members = counters.max_members.max(u64::try_from(count).unwrap_or(0));
        let mut aborted = 0_u64;
        let mut committed = 0_u64;
        for ((reply, weight, _mode), outcome) in meta.into_iter().zip(outcomes) {
            match &outcome {
                Ok(_) => committed = committed.saturating_add(1),
                Err(ParallelError::ReaderContended) => aborted = aborted.saturating_add(1),
                Err(_) => {}
            }
            let _ = reply.send(outcome);
            gate.release(weight);
        }
        counters.aborted = counters.aborted.saturating_add(aborted);
        counters.commits = counters.commits.saturating_add(committed);
        drop(counters);
        if disconnected {
            break;
        }
    }
    gate.close();
}
