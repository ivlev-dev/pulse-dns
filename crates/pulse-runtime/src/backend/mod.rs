//! Бэкенды ввода-вывода.

pub(crate) mod pbuf;
pub(crate) mod probe;
pub(crate) mod uring;

#[cfg(feature = "epoll-fallback")]
pub(crate) mod epoll;
