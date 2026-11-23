//! Вопрос DNS-запроса.

use super::name::Name;
use super::rr::{Rclass, Rtype};

/// Вопрос секции QUESTION (RFC 1035 §4.1.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Question {
    qname: Name,
    qtype: Rtype,
    qclass: Rclass,
}

impl Question {
    /// Создаёт вопрос.
    #[must_use]
    pub const fn new(qname: Name, qtype: Rtype, qclass: Rclass) -> Self {
        Self {
            qname,
            qtype,
            qclass,
        }
    }

    /// Имя запроса.
    #[must_use]
    pub const fn qname(&self) -> &Name {
        &self.qname
    }

    /// Тип запроса.
    #[must_use]
    pub const fn qtype(&self) -> Rtype {
        self.qtype
    }

    /// Класс запроса.
    #[must_use]
    pub const fn qclass(&self) -> Rclass {
        self.qclass
    }
}
