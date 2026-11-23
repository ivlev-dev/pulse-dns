//! Обработчик UDP-датаграмм.

use std::net::SocketAddr;

/// Решение обработчика по одной датаграмме.
#[derive(Debug)]
pub enum Reply {
    /// Ответ лежит в предоставленном буфере, длина — в байтах.
    Send(usize),
    /// Ответ во владеющем буфере: ядро скопирует его в TX-слот.
    Owned(Vec<u8>),
    /// Ответа нет (например, запрос отброшен политикой).
    Drop,
}

impl Reply {
    /// Преобразовать `Option<Vec<u8>>` в [`Reply`] (удобно для `owned`-адаптера).
    #[must_use]
    pub fn from_owned(reply: Option<Vec<u8>>) -> Self {
        match reply {
            Some(bytes) => Self::Owned(bytes),
            None => Self::Drop,
        }
    }
}

/// Синхронный обработчик датаграммы.
///
/// Вызывается в контексте worker-потока, без `await` и без доступа к сети.
/// `response` — буфер размером [`RuntimeConfig::tx_slot_size`](crate::RuntimeConfig::tx_slot_size);
/// обработчик может писать в него и вернуть [`Reply::Send`] с длиной, чтобы избежать аллокации.
///
/// Паника обработчика изолируется (`catch_unwind`) и не роняет worker: датаграмма
/// отбрасывается, счётчик `handler_panics` растёт.
pub trait Handler: Send + Sync + 'static {
    /// Обработать запрос.
    fn handle(&self, request: &[u8], peer: SocketAddr, response: &mut [u8]) -> Reply;
}

impl<F> Handler for F
where
    F: Fn(&[u8], SocketAddr, &mut [u8]) -> Reply + Send + Sync + 'static,
{
    fn handle(&self, request: &[u8], peer: SocketAddr, response: &mut [u8]) -> Reply {
        self(request, peer, response)
    }
}

/// Адаптер для обработчиков, возвращающих `Option<Vec<u8>>`.
///
/// Такая форма аллоцирует `Vec` на каждый ответ; на горячем пути предпочтителен
/// вариант с записью в `response`.
///
/// ```
/// use std::net::SocketAddr;
/// use pulse_runtime::{Handler, Reply, owned};
///
/// let echo = owned(|request: &[u8], _peer: SocketAddr| Some(request.to_vec()));
/// let mut out = [0_u8; 512];
/// let reply = echo.handle(b"ping", "127.0.0.1:9".parse().unwrap(), &mut out);
/// assert!(matches!(reply, Reply::Owned(bytes) if bytes == b"ping"));
/// ```
pub struct OwnedFn<F>(F);

impl<F> OwnedFn<F>
where
    F: Fn(&[u8], SocketAddr) -> Option<Vec<u8>> + Send + Sync + 'static,
{
    /// Создать адаптер.
    pub fn new(handler: F) -> Self {
        Self(handler)
    }
}

/// Создать [`OwnedFn`] из замыкания `Fn(&[u8], SocketAddr) -> Option<Vec<u8>>`.
pub fn owned<F>(handler: F) -> OwnedFn<F>
where
    F: Fn(&[u8], SocketAddr) -> Option<Vec<u8>> + Send + Sync + 'static,
{
    OwnedFn::new(handler)
}

impl<F> Handler for OwnedFn<F>
where
    F: Fn(&[u8], SocketAddr) -> Option<Vec<u8>> + Send + Sync + 'static,
{
    fn handle(&self, request: &[u8], peer: SocketAddr, _response: &mut [u8]) -> Reply {
        Reply::from_owned(self.0(request, peer))
    }
}
