//! Транспорт DNSCrypt v2.

/// Транспорт, влияющий на дополнение и TCP-фрейминг (§3–§10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    /// UDP: запрос дополняется минимум до `min-query-len` (§3).
    Udp,
    /// TCP: запрос дополняется до кратного 64 со случайной длиной (§5).
    Tcp,
}

impl Transport {
    /// Это UDP?
    #[must_use]
    pub const fn is_udp(self) -> bool {
        matches!(self, Self::Udp)
    }

    /// Это TCP?
    #[must_use]
    pub const fn is_tcp(self) -> bool {
        matches!(self, Self::Tcp)
    }
}
