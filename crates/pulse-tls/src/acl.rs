//! Простой IP/CIDR ACL для входящих соединений.

use std::net::IpAddr;

use crate::error::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rule {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

impl Rule {
    fn matches(self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Self::V4 { network, prefix }, IpAddr::V4(address)) => {
                let value = u32::from(address);
                value & mask_v4(prefix) == network
            }
            (Self::V6 { network, prefix }, IpAddr::V6(address)) => {
                let value = u128::from(address);
                value & mask_v6(prefix) == network
            }
            _ => false,
        }
    }
}

fn mask_v4(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    }
}

fn mask_v6(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    }
}

/// Список разрешённых сетей.
///
/// `Acl::from_cidrs` создаёт список с политикой «запрещено всё, кроме
/// перечисленного». `Acl::allow_all` разрешает любой адрес. Одиночный адрес
/// без `/` трактуется как `/32` (IPv4) или `/128` (IPv6).
#[derive(Debug, Clone, Default)]
pub struct Acl {
    rules: Vec<Rule>,
    default_allow: bool,
}

impl Acl {
    /// ACL, разрешающий любые адреса.
    #[must_use]
    pub fn allow_all() -> Self {
        Self {
            rules: Vec::new(),
            default_allow: true,
        }
    }

    /// ACL, запрещающий любые адреса.
    #[must_use]
    pub fn deny_all() -> Self {
        Self::default()
    }

    /// Создаёт ACL из списка CIDR/адресов.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidCidr`] при синтаксической ошибке или префиксе вне
    /// диапазона.
    pub fn from_cidrs<I, S>(cidrs: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut acl = Self::deny_all();
        for cidr in cidrs {
            acl.add_cidr(cidr.as_ref())?;
        }
        Ok(acl)
    }

    /// Добавляет сеть в список разрешённых.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidCidr`] при синтаксической ошибке.
    pub fn add_cidr(&mut self, cidr: &str) -> Result<(), Error> {
        let (address, prefix) = match cidr.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (cidr, None),
        };
        let ip: IpAddr = address
            .parse()
            .map_err(|_| Error::InvalidCidr(cidr.to_owned()))?;
        match ip {
            IpAddr::V4(address) => {
                let prefix = parse_prefix(prefix, 32, cidr)?;
                let network = u32::from(address) & mask_v4(prefix);
                self.rules.push(Rule::V4 { network, prefix });
            }
            IpAddr::V6(address) => {
                let prefix = parse_prefix(prefix, 128, cidr)?;
                let network = u128::from(address) & mask_v6(prefix);
                self.rules.push(Rule::V6 { network, prefix });
            }
        }
        Ok(())
    }

    /// Проверяет адрес.
    #[must_use]
    pub fn allows(&self, ip: IpAddr) -> bool {
        self.default_allow || self.rules.iter().any(|rule| rule.matches(ip))
    }

    /// Число явных правил.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Нет ли явных правил (политика по умолчанию всё равно действует).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

fn parse_prefix(prefix: Option<&str>, max: u8, cidr: &str) -> Result<u8, Error> {
    match prefix {
        None => Ok(max),
        Some(value) => {
            let parsed: u8 = value
                .parse()
                .map_err(|_| Error::InvalidCidr(cidr.to_owned()))?;
            if parsed > max {
                return Err(Error::InvalidCidr(cidr.to_owned()));
            }
            Ok(parsed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("ip")
    }

    #[test]
    fn ipv4_cidr_and_single_address() {
        let acl = Acl::from_cidrs(["192.0.2.0/24", "198.51.100.7"]).expect("acl");
        assert!(acl.allows(ip("192.0.2.1")));
        assert!(acl.allows(ip("192.0.2.255")));
        assert!(acl.allows(ip("198.51.100.7")));
        assert!(!acl.allows(ip("198.51.100.8")));
        assert!(!acl.allows(ip("2001:db8::1")));
    }

    #[test]
    fn ipv6_cidr() {
        let acl = Acl::from_cidrs(["2001:db8::/32"]).expect("acl");
        assert!(acl.allows(ip("2001:db8::1")));
        assert!(!acl.allows(ip("2001:db9::1")));
        assert!(!acl.allows(ip("192.0.2.1")));
    }

    #[test]
    fn allow_all_and_invalid() {
        assert!(Acl::allow_all().allows(ip("203.0.113.1")));
        assert!(!Acl::deny_all().allows(ip("203.0.113.1")));
        assert!(Acl::from_cidrs(["192.0.2.0/33"]).is_err());
        assert!(Acl::from_cidrs(["not-an-ip"]).is_err());
    }
}
