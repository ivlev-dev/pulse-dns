//! Newtype'ы протокола: тип записи, класс, код ответа, opcode.

use std::fmt;

/// Тип DNS-записи (RFC 1035 и реестр IANA).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Rtype(u16);

impl Rtype {
    /// IPv4-адрес.
    pub const A: Self = Self(1);
    /// Authoritative name server.
    pub const NS: Self = Self(2);
    /// Canonical name.
    pub const CNAME: Self = Self(5);
    /// Start of authority.
    pub const SOA: Self = Self(6);
    /// Pointer.
    pub const PTR: Self = Self(12);
    /// Mail exchange.
    pub const MX: Self = Self(15);
    /// Text.
    pub const TXT: Self = Self(16);
    /// IPv6-адрес.
    pub const AAAA: Self = Self(28);
    /// Service locator.
    pub const SRV: Self = Self(33);
    /// Delegation name.
    pub const DNAME: Self = Self(39);
    /// EDNS0 pseudo-record.
    pub const OPT: Self = Self(41);
    /// Delegation signer.
    pub const DS: Self = Self(43);
    /// DNSSEC signature.
    pub const RRSIG: Self = Self(46);
    /// Authenticated denial of existence.
    pub const NSEC: Self = Self(47);
    /// DNSSEC public key.
    pub const DNSKEY: Self = Self(48);
    /// Hashed authenticated denial of existence.
    pub const NSEC3: Self = Self(50);
    /// NSEC3 parameters.
    pub const NSEC3PARAM: Self = Self(51);
    /// TLS certificate association.
    pub const TLSA: Self = Self(52);
    /// Service binding.
    pub const SVCB: Self = Self(64);
    /// HTTPS service binding.
    pub const HTTPS: Self = Self(65);
    /// Zone transfer (query type).
    pub const AXFR: Self = Self(252);
    /// Incremental zone transfer (query type).
    pub const IXFR: Self = Self(251);
    /// Transfer key (meta).
    pub const TKEY: Self = Self(249);
    /// Transaction signature (meta).
    pub const TSIG: Self = Self(250);
    /// Any type (query type).
    pub const ANY: Self = Self(255);
    /// Certification authority authorization.
    pub const CAA: Self = Self(257);

    /// Создаёт тип из wire-значения.
    #[must_use]
    pub const fn from_u16(value: u16) -> Self {
        Self(value)
    }

    /// Wire-значение типа.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Известен ли тип этому крейту (для RFC 3597 passthrough).
    #[must_use]
    pub const fn is_known(self) -> bool {
        matches!(
            self.0,
            1 | 2
                | 5
                | 6
                | 12
                | 15
                | 16
                | 28
                | 33
                | 39
                | 41
                | 43
                | 46
                | 47
                | 48
                | 50
                | 51
                | 52
                | 64
                | 65
                | 257
        )
    }
}

impl fmt::Display for Rtype {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mnemonic = match self.0 {
            1 => "A",
            2 => "NS",
            5 => "CNAME",
            6 => "SOA",
            12 => "PTR",
            15 => "MX",
            16 => "TXT",
            28 => "AAAA",
            33 => "SRV",
            39 => "DNAME",
            41 => "OPT",
            43 => "DS",
            46 => "RRSIG",
            47 => "NSEC",
            48 => "DNSKEY",
            50 => "NSEC3",
            51 => "NSEC3PARAM",
            52 => "TLSA",
            64 => "SVCB",
            65 => "HTTPS",
            249 => "TKEY",
            250 => "TSIG",
            251 => "IXFR",
            252 => "AXFR",
            255 => "ANY",
            257 => "CAA",
            other => return write!(f, "TYPE{other}"),
        };
        f.write_str(mnemonic)
    }
}

impl From<u16> for Rtype {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<Rtype> for u16 {
    fn from(value: Rtype) -> Self {
        value.0
    }
}

/// Класс DNS-записи.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Rclass(u16);

impl Rclass {
    /// Internet.
    pub const IN: Self = Self(1);
    /// CSNET (obsolete).
    pub const CS: Self = Self(2);
    /// CHAOS.
    pub const CH: Self = Self(3);
    /// Hesiod.
    pub const HS: Self = Self(4);
    /// None (dynamic update).
    pub const NONE: Self = Self(254);
    /// Any class (query only).
    pub const ANY: Self = Self(255);

    /// Создаёт класс из wire-значения.
    #[must_use]
    pub const fn from_u16(value: u16) -> Self {
        Self(value)
    }

    /// Wire-значение класса.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

impl fmt::Display for Rclass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mnemonic = match self.0 {
            1 => "IN",
            2 => "CS",
            3 => "CH",
            4 => "HS",
            254 => "NONE",
            255 => "ANY",
            other => return write!(f, "CLASS{other}"),
        };
        f.write_str(mnemonic)
    }
}

impl From<u16> for Rclass {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<Rclass> for u16 {
    fn from(value: Rclass) -> Self {
        value.0
    }
}

/// Код ответа (включая расширенные значения EDNS0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Rcode(u16);

impl Rcode {
    /// Успех.
    pub const NOERROR: Self = Self(0);
    /// Ошибка формата запроса.
    pub const FORMERR: Self = Self(1);
    /// Внутренняя ошибка сервера.
    pub const SERVFAIL: Self = Self(2);
    /// Имя не существует.
    pub const NXDOMAIN: Self = Self(3);
    /// Операция не поддерживается.
    pub const NOTIMP: Self = Self(4);
    /// Отказ.
    pub const REFUSED: Self = Self(5);
    /// Имя существует, но не для этого типа.
    pub const YXDOMAIN: Self = Self(6);
    /// RRset существует.
    pub const YXRRSET: Self = Self(7);
    /// RRset не существует.
    pub const NXRRSET: Self = Self(8);
    /// Не авторитативен для зоны.
    pub const NOTAUTH: Self = Self(9);
    /// Не в зоне.
    pub const NOTZONE: Self = Self(10);
    /// Неподдерживаемая версия EDNS.
    pub const BADVERS: Self = Self(16);

    /// Создаёт код из значения.
    #[must_use]
    pub const fn from_u16(value: u16) -> Self {
        Self(value)
    }

    /// Числовое значение.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Младшие 4 бита для заголовка.
    #[must_use]
    pub const fn header_bits(self) -> u8 {
        let [low, _] = self.0.to_le_bytes();
        low & 0x0F
    }

    /// Старшие биты для расширенного RCODE EDNS0.
    #[must_use]
    pub const fn extended_bits(self) -> u8 {
        let [low, high] = self.0.to_le_bytes();
        (low >> 4) | (high << 4)
    }
}

impl fmt::Display for Rcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mnemonic = match self.0 {
            0 => "NOERROR",
            1 => "FORMERR",
            2 => "SERVFAIL",
            3 => "NXDOMAIN",
            4 => "NOTIMP",
            5 => "REFUSED",
            6 => "YXDOMAIN",
            7 => "YXRRSET",
            8 => "NXRRSET",
            9 => "NOTAUTH",
            10 => "NOTZONE",
            16 => "BADVERS",
            other => return write!(f, "RCODE{other}"),
        };
        f.write_str(mnemonic)
    }
}

impl From<u16> for Rcode {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

/// Opcode DNS-сообщения.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Opcode(u8);

impl Opcode {
    /// Обычный запрос.
    pub const QUERY: Self = Self(0);
    /// Inverse query (obsolete).
    pub const IQUERY: Self = Self(1);
    /// Server status.
    pub const STATUS: Self = Self(2);
    /// Zone change notification.
    pub const NOTIFY: Self = Self(4);
    /// Dynamic update.
    pub const UPDATE: Self = Self(5);

    /// Создаёт opcode из значения.
    #[must_use]
    pub const fn from_u8(value: u8) -> Self {
        Self(value)
    }

    /// Числовое значение.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self.0
    }
}

impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mnemonic = match self.0 {
            0 => "QUERY",
            1 => "IQUERY",
            2 => "STATUS",
            4 => "NOTIFY",
            5 => "UPDATE",
            other => return write!(f, "OPCODE{other}"),
        };
        f.write_str(mnemonic)
    }
}

impl From<u8> for Opcode {
    fn from(value: u8) -> Self {
        Self(value)
    }
}
