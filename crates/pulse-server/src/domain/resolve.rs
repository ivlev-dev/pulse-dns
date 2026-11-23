//! Результат примитивного поиска в зоне и состояние зоны.

use pulse_dns::{Name, Rrset};

/// Состояние зоны в модели обслуживания.
///
/// Значения соответствуют `ZoneState` из `domain-model.md` §2.7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ZoneState {
    /// Зона создана, но ещё не имеет `SOA`/`NS`; DNS-ответ — `REFUSED`.
    Initializing,
    /// Зона авторитативна и обслуживается.
    Serving,
    /// Зона удалена; из каталога она уже исчезла, но тип оставлен для полноты
    /// модели состояний. DNS-ответ — `REFUSED`.
    Tombstone,
}

/// Результат точного поиска `(name, rtype)` в зоне.
///
/// Порт [`crate::ZoneView::lookup`] отдаёт **примитив**, а не готовый
/// DNS-ответ: композицию `CNAME`/`DNAME`/wildcard/referral выполняет
/// [`crate::QueryEngine`] (`domain-model.md` §5.1).
///
/// Инвариант: `Referral` возвращается только для имени **строго ниже**
/// zone cut; в точке cut (`name` — сама делегированная зона) — `Delegation`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupOutcome {
    /// Точное совпадение `(name, rtype)`.
    Answer(Rrset),
    /// У имени есть `CNAME` (а запрошен не `CNAME`); содержит набор `CNAME`
    /// и каноническую цель.
    Cname(Rrset, Name),
    /// Имя существует (включая empty non-terminal), но записей этого типа нет.
    NoData,
    /// Имени в зоне нет (и wildcard-совпадение проверяет движок).
    NxDomain,
    /// Имя — точка делегирования (zone cut): `NS` без `SOA`.
    ///
    /// `ds` присутствует, если в зоне есть `DS` для этой точки. Движок
    /// включает `DS` в authority только при установленном `DO`-бите.
    Delegation {
        /// `NS`-набор делегированной зоны.
        ns: Rrset,
        /// `DS`-набор точки делегирования, если опубликован.
        ds: Option<Rrset>,
    },
    /// Имя находится ниже zone cut; авторитетных данных для него нет —
    /// движок формирует referral.
    Referral,
    /// Имя не принадлежит зоне (защитная проверка порта).
    ZoneNotFound,
}
