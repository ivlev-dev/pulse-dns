//! Порт чтения зоны для авторитетного ответа.

use pulse_dns::{Name, Rclass, Rrset, Rtype};

use crate::domain::{LookupOutcome, ZoneState};

/// Синхронный порт зоны (driven port авторитетного сервиса).
///
/// Порт отдаёт **примитивы** — точный RRset, признак делегирования, glue.
/// Композиция ответа (wildcard, CNAME/DNAME-цепочка, referral, NXDOMAIN/NODATA,
/// additional/glue) выполняется [`crate::QueryEngine`] поверх этих операций;
/// адаптер не имеет права возвращать «готовый DNS-ответ»
/// (`domain-model.md` §5.1).
///
/// Реализация обязана быть детерминированной: два вызова с одним именем и
/// типом дают идентичный результат.
pub trait ZoneView: Send + Sync {
    /// Канонический origin зоны (абсолютное имя, нижний регистр).
    fn origin(&self) -> &Name;

    /// Apex зоны. В v1 совпадает с [`ZoneView::origin`].
    fn apex(&self) -> &Name;

    /// `SOA`-набор apex, если зона его имеет.
    ///
    /// Для `Serving`-зоны обязан присутствовать (INV-4); движок использует
    /// `min(SOA.ttl, SOA.minimum)` как TTL негативного ответа.
    fn soa(&self) -> Option<&Rrset>;

    /// `NS`-набор apex, если зона его имеет.
    fn ns(&self) -> Option<&Rrset>;

    /// Класс зоны. В v1 — только [`Rclass::IN`].
    fn class(&self) -> Rclass;

    /// Состояние зоны. Для `Initializing`/`Tombstone` движок отвечает `REFUSED`.
    fn state(&self) -> ZoneState;

    /// Точный поиск `(name, rtype)` без композиции.
    ///
    /// Возвращает [`LookupOutcome::Delegation`] в точке zone cut (кроме
    /// `rtype == DS`, для которого отдаётся авторитетный `DS`/`NoData`) и
    /// [`LookupOutcome::Referral`] для имени строго ниже cut.
    fn lookup(&self, name: &Name, rtype: Rtype) -> LookupOutcome;

    /// Все `RRSIG`-наборы имени, покрывающие `covered` (`type covered`).
    ///
    /// Движок прикладывает их к ответу при `DO = 1`. Пустой результат —
    /// подписей нет (неподписанная зона или отсутствующий RRset).
    fn lookup_all_rrsig(&self, name: &Name, covered: Rtype) -> Vec<Rrset>;

    /// Подписана ли зона: есть apex `DNSKEY` и его `RRSIG`.
    ///
    /// Реализация по умолчанию проверяет это через [`ZoneView::lookup`] и
    /// [`ZoneView::lookup_all_rrsig`], поэтому адаптерам достаточно хранить
    /// DNSSEC-записи как обычные RRset. Неподписанная зона не получает
    /// `RRSIG`/NSEC-доказательств в ответах.
    fn signed(&self) -> bool {
        matches!(
            self.lookup(self.origin(), Rtype::DNSKEY),
            LookupOutcome::Answer(_)
        ) && !self
            .lookup_all_rrsig(self.origin(), Rtype::DNSKEY)
            .is_empty()
    }

    /// `NSEC`-набор, владелец которого совпадает с `name`.
    ///
    /// Нужен для NODATA-доказательства (RFC 4035 §5.4). `None` — зона не
    /// публикует NSEC или имя не является владельцем NSEC.
    fn nsec_at(&self, name: &Name) -> Option<Rrset> {
        let _ = name;
        None
    }

    /// `NSEC`-набор, интервал которого покрывает `name` в каноническом
    /// порядке (RFC 4034 §4.1.2).
    ///
    /// Нужен для NXDOMAIN (покрытие QNAME и wildcard) и positive wildcard
    /// proof. `None` — покрывающей записи нет.
    fn nsec_cover(&self, name: &Name) -> Option<Rrset> {
        let _ = name;
        None
    }

    /// Является ли имя точкой делегирования (`NS` без `SOA`, не apex).
    fn is_delegation(&self, name: &Name) -> bool;

    /// `A`/`AAAA`-наборы имени для additional/glue.
    ///
    /// Возвращаются только реально существующие наборы в порядке `A`, `AAAA`;
    /// отсутствующие опускаются.
    fn glue(&self, name: &Name) -> Vec<Rrset>;

    /// Существует ли узел имени в зоне (включая empty non-terminal).
    ///
    /// Нужен для доказательства closest encloser при wildcard-разборе
    /// (RFC 4592 §2.2.1): без него нельзя отличить существующий предок от
    /// отсутствующего. Для имени вне зоны — `false`.
    fn node_exists(&self, name: &Name) -> bool;
}
