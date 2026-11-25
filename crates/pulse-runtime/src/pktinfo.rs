//! `IP_PKTINFO`/`IPV6_RECVPKTINFO`: адрес назначения принятой датаграммы,
//! чтобы ответ с wildcard-bind уходил с того же локального адреса.
//!
//! Разбор и сборка `cmsghdr` сделаны по байтам, без `unsafe`: раскладка
//! (`size_t cmsg_len`, `int cmsg_level`, `int cmsg_type`, данные с выравниванием
//! на `size_t`) фиксирована для Linux.

use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr};

const ALIGN: usize = size_of::<usize>();
const LEN_SIZE: usize = size_of::<usize>();
/// Заголовок `cmsghdr` с выравниванием: 16 байт на 64-битных, 12 на 32-битных.
const HEADER: usize = align_up(LEN_SIZE + 2 * size_of::<i32>(), ALIGN);

/// Размер буфера под control message: хватает и `in_pktinfo` (12), и
/// `in6_pktinfo` (20), с запасом.
pub(crate) const CMSG_BUF_LEN: usize = 64;

const CMSG_SIZE_V4: usize = 12;
const CMSG_SIZE_V6: usize = 20;

/// Адрес назначения входящей датаграммы.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum DstInfo {
    /// cmsg отсутствует: используется поведение по умолчанию (маршрут ядра).
    #[default]
    None,
    /// `in_pktinfo` (IPv4).
    V4 {
        /// `ipi_spec_dst`.
        dst: Ipv4Addr,
        /// `ipi_ifindex`.
        ifindex: i32,
    },
    /// `in6_pktinfo` (IPv6).
    V6 {
        /// `ipi6_addr`.
        dst: Ipv6Addr,
        /// `ipi6_ifindex`.
        ifindex: u32,
    },
}

impl DstInfo {
    /// Разобрать первые подходящие control message из `recvmsg`.
    pub(crate) fn parse(control: &[u8]) -> Self {
        let mut offset = 0_usize;
        while offset + HEADER <= control.len() {
            let Some(len) = read_usize(&control[offset..]) else {
                break;
            };
            if len < HEADER || offset + len > control.len() {
                break;
            }
            let level = read_i32(&control[offset + LEN_SIZE..]);
            let kind = read_i32(&control[offset + LEN_SIZE + 4..]);
            let data = &control[offset + HEADER..offset + len];

            match (level, kind) {
                (libc::IPPROTO_IP, libc::IP_PKTINFO) if data.len() >= CMSG_SIZE_V4 => {
                    let ifindex = i32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
                    let spec_dst = [data[4], data[5], data[6], data[7]];
                    let addr = [data[8], data[9], data[10], data[11]];
                    let dst = if spec_dst == [0, 0, 0, 0] {
                        Ipv4Addr::from(addr)
                    } else {
                        Ipv4Addr::from(spec_dst)
                    };
                    if !dst.is_unspecified() {
                        return Self::V4 { dst, ifindex };
                    }
                }
                (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) if data.len() >= CMSG_SIZE_V6 => {
                    let mut octets = [0_u8; 16];
                    octets.copy_from_slice(&data[..16]);
                    let ifindex = u32::from_ne_bytes([data[16], data[17], data[18], data[19]]);
                    let dst = Ipv6Addr::from(octets);
                    if !dst.is_unspecified() {
                        return Self::V6 { dst, ifindex };
                    }
                }
                _ => {}
            }

            offset += align_up(len, ALIGN);
        }
        Self::None
    }

    /// Записать control message в буфер слота; вернуть длину для
    /// `msg_controllen` (0 — control не нужен).
    pub(crate) fn write(self, buf: &mut [u8; CMSG_BUF_LEN]) -> usize {
        let (level, kind, data_len) = match self {
            Self::None => return 0,
            Self::V4 { .. } => (libc::IPPROTO_IP, libc::IP_PKTINFO, CMSG_SIZE_V4),
            Self::V6 { .. } => (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, CMSG_SIZE_V6),
        };
        let total = HEADER + data_len;
        if total > buf.len() {
            return 0;
        }
        buf[..LEN_SIZE].copy_from_slice(&total.to_ne_bytes());
        buf[LEN_SIZE..LEN_SIZE + 4].copy_from_slice(&level.to_ne_bytes());
        buf[LEN_SIZE + 4..LEN_SIZE + 8].copy_from_slice(&kind.to_ne_bytes());
        let data = &mut buf[HEADER..total];
        match self {
            Self::V4 { dst, ifindex } => {
                data[..4].copy_from_slice(&ifindex.to_ne_bytes());
                data[4..8].copy_from_slice(&dst.octets());
                data[8..12].fill(0);
            }
            Self::V6 { dst, ifindex } => {
                data[..16].copy_from_slice(&dst.octets());
                data[16..20].copy_from_slice(&ifindex.to_ne_bytes());
            }
            Self::None => {}
        }
        align_up(total, ALIGN)
    }
}

const fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

fn read_usize(bytes: &[u8]) -> Option<usize> {
    let raw: [u8; size_of::<usize>()] = bytes.get(..size_of::<usize>())?.try_into().ok()?;
    Some(usize::from_ne_bytes(raw))
}

fn read_i32(bytes: &[u8]) -> i32 {
    let raw: [u8; 4] = match bytes.get(..4) {
        Some(raw) => match raw.try_into() {
            Ok(raw) => raw,
            Err(_) => return -1,
        },
        None => return -1,
    };
    i32::from_ne_bytes(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_roundtrip() {
        let info = DstInfo::V4 {
            dst: Ipv4Addr::new(127, 0, 0, 2),
            ifindex: 7,
        };
        let mut buf = [0_u8; CMSG_BUF_LEN];
        let len = info.write(&mut buf);
        assert!(len >= HEADER + CMSG_SIZE_V4);
        assert_eq!(DstInfo::parse(&buf[..len]), info);
    }

    #[test]
    fn v6_roundtrip() {
        let info = DstInfo::V6 {
            dst: "2001:db8::1".parse().unwrap(),
            ifindex: 3,
        };
        let mut buf = [0_u8; CMSG_BUF_LEN];
        let len = info.write(&mut buf);
        assert!(len >= HEADER + CMSG_SIZE_V6);
        assert_eq!(DstInfo::parse(&buf[..len]), info);
    }

    #[test]
    fn none_and_garbage() {
        let mut buf = [0_u8; CMSG_BUF_LEN];
        assert_eq!(DstInfo::None.write(&mut buf), 0);
        assert_eq!(DstInfo::parse(&buf), DstInfo::None);
        assert_eq!(DstInfo::parse(&[]), DstInfo::None);
        assert_eq!(DstInfo::parse(&[0xff; 8]), DstInfo::None);
        // cmsg_len больше буфера — не паникуем.
        let mut bad = [0_u8; 32];
        bad[..LEN_SIZE].copy_from_slice(&usize::MAX.to_ne_bytes());
        assert_eq!(DstInfo::parse(&bad), DstInfo::None);
    }
}
