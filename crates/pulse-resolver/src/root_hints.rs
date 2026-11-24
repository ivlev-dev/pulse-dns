//! Встроенные root hints (IANA, 13 корневых серверов).
//!
//! Адреса заданы статически, чтобы cold-start не зависел от сети. IPv4 и
//! IPv6 возвращаются отдельными списками: клиент выбирает семью по адресу
//! upstream-сокета.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// IPv4-адреса корневых серверов.
pub const ROOT_HINTS_V4: [Ipv4Addr; 13] = [
    Ipv4Addr::new(198, 41, 0, 4),
    Ipv4Addr::new(170, 247, 170, 2),
    Ipv4Addr::new(192, 33, 4, 12),
    Ipv4Addr::new(199, 7, 91, 13),
    Ipv4Addr::new(192, 203, 230, 10),
    Ipv4Addr::new(192, 5, 5, 241),
    Ipv4Addr::new(192, 112, 36, 4),
    Ipv4Addr::new(198, 97, 190, 53),
    Ipv4Addr::new(192, 36, 148, 17),
    Ipv4Addr::new(192, 58, 128, 30),
    Ipv4Addr::new(193, 0, 14, 129),
    Ipv4Addr::new(199, 7, 83, 42),
    Ipv4Addr::new(202, 12, 27, 33),
];

/// IPv6-адреса корневых серверов.
pub const ROOT_HINTS_V6: [Ipv6Addr; 13] = [
    Ipv6Addr::new(0x2001, 0x0503, 0xba3e, 0, 0, 0, 0x0002, 0x0030),
    Ipv6Addr::new(0x2801, 0x01b8, 0x0010, 0, 0, 0, 0, 0x000b),
    Ipv6Addr::new(0x2001, 0x0500, 0x0002, 0, 0, 0, 0, 0x000c),
    Ipv6Addr::new(0x2001, 0x0500, 0x002d, 0, 0, 0, 0, 0x000d),
    Ipv6Addr::new(0x2001, 0x0500, 0x00a8, 0, 0, 0, 0, 0x000e),
    Ipv6Addr::new(0x2001, 0x0500, 0x002f, 0, 0, 0, 0, 0x000f),
    Ipv6Addr::new(0x2001, 0x0500, 0x0012, 0, 0, 0, 0, 0x0d0d),
    Ipv6Addr::new(0x2001, 0x0500, 0x0001, 0, 0, 0, 0, 0x0053),
    Ipv6Addr::new(0x2001, 0x07fe, 0, 0, 0, 0, 0, 0x0053),
    Ipv6Addr::new(0x2001, 0x0503, 0x0c27, 0, 0, 0, 0x0002, 0x0030),
    Ipv6Addr::new(0x2001, 0x07fd, 0, 0, 0, 0, 0, 0x0001),
    Ipv6Addr::new(0x2001, 0x0500, 0x009f, 0, 0, 0, 0, 0x0042),
    Ipv6Addr::new(0x2001, 0x0dc3, 0, 0, 0, 0, 0, 0x0035),
];

/// Возвращает root hints как сокеты порта 53 (IPv4, затем IPv6).
#[must_use]
pub fn root_hints() -> Vec<SocketAddr> {
    let mut hints = Vec::with_capacity(ROOT_HINTS_V4.len() + ROOT_HINTS_V6.len());
    hints.extend(
        ROOT_HINTS_V4
            .iter()
            .map(|address| SocketAddr::new(IpAddr::V4(*address), 53)),
    );
    hints.extend(
        ROOT_HINTS_V6
            .iter()
            .map(|address| SocketAddr::new(IpAddr::V6(*address), 53)),
    );
    hints
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hints_have_13_v4_and_v6() {
        assert_eq!(ROOT_HINTS_V4.len(), 13);
        assert_eq!(ROOT_HINTS_V6.len(), 13);
        assert_eq!(root_hints().len(), 26);
        assert!(root_hints().iter().all(|addr| addr.port() == 53));
        assert_eq!(ROOT_HINTS_V4[11], Ipv4Addr::new(199, 7, 83, 42));
        assert_eq!(ROOT_HINTS_V4[12], Ipv4Addr::new(202, 12, 27, 33));
    }
}
