//! Создание UDP-сокетов и преобразование адресов.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, OwnedFd};

use rustix::net::addr::{SocketAddrArg, SocketAddrStorage};
use rustix::net::sockopt;
use rustix::net::{AddressFamily, SocketType, ipproto};

use crate::config::RuntimeConfig;

/// Создать неблокирующий UDP-сокет с `SO_REUSEPORT`, привязанный к `addr`.
///
/// Несколько сокетов с одинаковым адресом образуют reuseport-группу; ядро
/// распределяет между ними входящие датаграммы по хешу 4-tuple.
///
/// Включает `IP_PKTINFO`/`IPV6_RECVPKTINFO`, чтобы wildcard-bind отвечал с того
/// же локального адреса, на который пришёл запрос.
///
/// `SO_REUSEPORT` разрешает другому процессу того же uid (и с той же группой)
/// занять тот же порт и перехватывать часть трафика — это осознанное свойство
/// механизма, а не изоляция.
pub(crate) fn bind_udp(addr: SocketAddr, cfg: &RuntimeConfig) -> io::Result<OwnedFd> {
    let family = match addr {
        SocketAddr::V4(_) => AddressFamily::INET,
        SocketAddr::V6(_) => AddressFamily::INET6,
    };
    let fd = rustix::net::socket(family, SocketType::DGRAM, Some(ipproto::UDP)).map_err(io_err)?;

    sockopt::set_socket_reuseport(&fd, true).map_err(io_err)?;
    // Размеры буферов — оптимизация: ядро вправе урезать значение по sysctl.
    sockopt::set_socket_recv_buffer_size(&fd, cfg.socket_recv_buffer).map_err(io_err)?;
    sockopt::set_socket_send_buffer_size(&fd, cfg.socket_send_buffer).map_err(io_err)?;
    if let SocketAddr::V6(_) = addr {
        // Не полагаемся на dual-stack: у каждого семейства своя reuseport-группа.
        sockopt::set_ipv6_v6only(&fd, true).map_err(io_err)?;
    }
    enable_pktinfo(&fd, family)?;
    configure_busy_poll(&fd, cfg);
    rustix::io::ioctl_fionbio(&fd, true).map_err(io_err)?;
    rustix::net::bind(&fd, &addr).map_err(io_err)?;

    // Ядро вправе урезать SO_RCVBUF/SO_SNDBUF по sysctl (и удваивает значение).
    // Предупреждаем, если фактический буфер меньше запрошенного.
    if let Ok(actual) = sockopt::socket_recv_buffer_size(&fd)
        && actual < cfg.socket_recv_buffer
    {
        eprintln!(
            "pulse-runtime: warning: SO_RCVBUF={actual} < requested {}              (check net.core.rmem_max)",
            cfg.socket_recv_buffer
        );
    }
    if let Ok(actual) = sockopt::socket_send_buffer_size(&fd)
        && actual < cfg.socket_send_buffer
    {
        eprintln!(
            "pulse-runtime: warning: SO_SNDBUF={actual} < requested {}              (check net.core.wmem_max)",
            cfg.socket_send_buffer
        );
    }
    Ok(fd)
}

/// `SO_BUSY_POLL`/`SO_PREFER_BUSY_POLL`/`SO_BUSY_POLL_BUDGET`.
///
/// Это оптимизация латентности, а не корректности: недоступность (EPERM для
/// `SO_PREFER_BUSY_POLL`, отсутствие опции в ядре) не должна ломать bind.
fn configure_busy_poll(fd: &OwnedFd, cfg: &RuntimeConfig) {
    let Some(microseconds) = cfg.busy_poll_us.filter(|value| *value > 0) else {
        return;
    };
    set_int_sockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_BUSY_POLL,
        i32::from(microseconds),
    );
    if let Some(budget) = cfg.busy_poll_budget {
        set_int_sockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BUSY_POLL_BUDGET,
            i32::from(budget),
        );
    }
    if cfg.prefer_busy_poll {
        set_int_sockopt(fd, libc::SOL_SOCKET, libc::SO_PREFER_BUSY_POLL, 1);
    }
}

fn set_int_sockopt(fd: &OwnedFd, level: libc::c_int, name: libc::c_int, value: i32) {
    // SAFETY: `fd` валиден, `value` — инициализированный c_int нужного размера.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            name,
            (&raw const value).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    // Ошибки (EPERM/ENOPROTOOPT) игнорируются: busy-poll — необязательная
    // оптимизация. Отдельное предупреждение не печатаем, чтобы не шуметь на
    // каждом worker'е.
    let _ = rc;
}

fn enable_pktinfo(fd: &OwnedFd, family: AddressFamily) -> io::Result<()> {
    let value: libc::c_int = 1;
    let (level, name) = match family {
        AddressFamily::INET => (libc::IPPROTO_IP, libc::IP_PKTINFO),
        AddressFamily::INET6 => (libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO),
        _ => return Ok(()),
    };
    // SAFETY: `fd` валиден, `value` — инициализированный c_int нужного размера.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            name,
            (&raw const value).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Получить локальный адрес сокета.
pub(crate) fn local_addr(fd: &OwnedFd) -> io::Result<SocketAddr> {
    let any = rustix::net::getsockname(fd).map_err(io_err)?;
    SocketAddr::try_from(any).map_err(|errno| io::Error::from_raw_os_error(errno.raw_os_error()))
}

fn io_err(errno: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(errno.raw_os_error())
}

/// Разобрать сырой `sockaddr` из `recvmsg`.
///
/// Работает без `unsafe`: поля читаются из байтового среза по RFC-раскладке
/// `sockaddr_in`/`sockaddr_in6` (все многобайтовые поля — сетевой порядок).
pub(crate) fn sockaddr_from_bytes(bytes: &[u8]) -> Option<SocketAddr> {
    if bytes.len() < 2 {
        return None;
    }
    // На Linux `sa_family_t` — u16 в native order.
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
    match i32::from(family) {
        libc::AF_INET => {
            if bytes.len() < 8 {
                return None;
            }
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let addr = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
            Some(SocketAddr::V4(SocketAddrV4::new(addr, port)))
        }
        libc::AF_INET6 => {
            if bytes.len() < 24 {
                return None;
            }
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let flowinfo = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&bytes[8..24]);
            let scope_id = if bytes.len() >= 28 {
                u32::from_ne_bytes([bytes[24], bytes[25], bytes[26], bytes[27]])
            } else {
                0
            };
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(octets),
                port,
                flowinfo,
                scope_id,
            )))
        }
        _ => None,
    }
}

/// Закодировать адрес в `sockaddr_storage` для `sendmsg`.
///
/// Возвращает длину закодированного адреса.
///
/// # Safety
///
/// `storage` должен указывать на валидную, выровненную по `SocketAddrStorage`
/// память, которую можно перезаписать. Вызывается только из TX-слота worker'а.
pub(crate) unsafe fn write_sockaddr(addr: SocketAddr, storage: *mut SocketAddrStorage) -> u32 {
    let any = rustix::net::SocketAddrAny::from(addr);
    // SAFETY: контракт функции (см. выше) гарантирует валидный указатель.
    unsafe { any.write_sockaddr(storage) }
}

/// CPUs, разрешённые процессу (`sched_getaffinity`).
pub(crate) fn allowed_cpus() -> Vec<usize> {
    crate::affinity::current_cpus()
}

/// CPU-список для worker'ов: пересечение `sched_getaffinity`/cpuset и
/// явного `cpu_affinity`.
///
/// Пустой явный список — все разрешённые CPU. Если явный список не пересекается
/// с разрешёнными, возвращается `EINVAL`: пинить на чужие CPU нельзя.
pub(crate) fn worker_cpus(explicit: &[usize]) -> io::Result<Vec<usize>> {
    crate::affinity::resolve(explicit)
}

/// Выбрать CPU для kernel-потока SQPOLL (`IORING_SETUP_SQ_AFF`).
///
/// Явно заданный CPU используется только если он разрешён процессу. Иначе,
/// при наличии свободных CPU, SQPOLL-поток уводится на отдельное ядро; если
/// свободных нет — делит ядро с worker'ом.
pub(crate) fn select_sqpoll_cpu(
    allowed: &[usize],
    configured: Option<usize>,
    worker_index: usize,
    workers: usize,
    worker_cpu: Option<usize>,
) -> Option<usize> {
    if let Some(cpu) = configured {
        return (allowed.is_empty() || allowed.contains(&cpu)).then_some(cpu);
    }
    if allowed.is_empty() {
        return None;
    }
    if allowed.len() > workers {
        return Some(allowed[(worker_index + workers) % allowed.len()]);
    }
    worker_cpu.or_else(|| Some(allowed[worker_index % allowed.len()]))
}

/// Прибить текущий поток к ядру `cpu`. Ошибки не критичны (например, EPERM в cgroup).
pub(crate) fn pin_current_thread(cpu: usize) -> io::Result<()> {
    crate::affinity::pin_current(cpu)
}

#[cfg(test)]
mod tests {
    use std::mem::MaybeUninit;

    use super::*;

    #[test]
    fn parses_ipv4_and_ipv6_sockaddrs() {
        let v4: SocketAddr = "127.0.0.1:5353".parse().unwrap();
        let any = rustix::net::SocketAddrAny::from(v4);
        let mut storage = MaybeUninit::<SocketAddrStorage>::uninit();
        // SAFETY: `storage` валиден и достаточно велик для любого sockaddr.
        let len = unsafe { any.write_sockaddr(storage.as_mut_ptr()) };
        // SAFETY: `write_sockaddr` записал `len` инициализированных байт.
        let bytes =
            unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), len as usize) };
        assert_eq!(sockaddr_from_bytes(bytes), Some(v4));

        let v6: SocketAddr = "[::1]:5353".parse().unwrap();
        let any = rustix::net::SocketAddrAny::from(v6);
        let mut storage = MaybeUninit::<SocketAddrStorage>::uninit();
        // SAFETY: `storage` валиден и достаточно велик для любого sockaddr.
        let len = unsafe { any.write_sockaddr(storage.as_mut_ptr()) };
        // SAFETY: `write_sockaddr` записал `len` инициализированных байт.
        let bytes =
            unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), len as usize) };
        assert_eq!(sockaddr_from_bytes(bytes), Some(v6));
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(sockaddr_from_bytes(&[]), None);
        assert_eq!(sockaddr_from_bytes(&[0xff, 0xff]), None);
        assert_eq!(sockaddr_from_bytes(&[2, 0, 0]), None);
    }

    #[test]
    fn cpu_selection_respects_affinity() {
        assert_eq!(
            crate::affinity::intersection(&[0, 1, 2, 3], &[]),
            Vec::<usize>::new()
        );
        // Явный CPU вне разрешённого множества не пинится.
        assert_eq!(
            crate::affinity::intersection(&[0, 1, 2, 3], &[2, 7]),
            vec![2]
        );
        assert_eq!(
            crate::affinity::intersection(&[0, 1], &[5]),
            Vec::<usize>::new()
        );
    }

    #[test]
    fn sqpoll_cpu_avoids_worker_core_when_possible() {
        let allowed = [0, 1, 2, 3];
        // 2 worker'а, 4 CPU: SQPOLL уходит на отдельные ядра.
        assert_eq!(select_sqpoll_cpu(&allowed, None, 0, 2, Some(0)), Some(2));
        assert_eq!(select_sqpoll_cpu(&allowed, None, 1, 2, Some(1)), Some(3));
        // CPU не разрешён — без SQ_AFF.
        assert_eq!(select_sqpoll_cpu(&allowed, Some(9), 0, 2, Some(0)), None);
        // Свободных CPU нет — делим с worker'ом.
        assert_eq!(select_sqpoll_cpu(&[0, 1], None, 0, 2, Some(1)), Some(1));
        assert_eq!(select_sqpoll_cpu(&[], Some(2), 0, 1, None), Some(2));
    }
}
