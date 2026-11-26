//! Порт чтения зоны для авторитетного ответа.

use pulse_dns::{MAX_NAME_WIRE_LEN, Name, NameRef, Rclass, Rrset, Rtype};

use super::cache::ZoneIdentity;
use crate::domain::{DenialKind, LookupOutcome, LookupOutcomeRef, RefLookup, RrsetRef, ZoneState};

/// Заимствованный снимок зоны, живущий не дольше пина читателя.
///
/// Снимок отдаётся через [`ZoneView::with_snapshot`] на время одного ответа:
/// все [`RrsetRef`] валидны, пока callback не вернулся. Это позволяет v2-адаптеру
/// держать один `ZoneReader`/`PageCache`-пин на запрос и не материализовать
/// RRset на каждый lookup.
pub trait ZoneSnapshot {
    /// Origin зоны.
    fn origin_ref(&self) -> NameRef<'_>;

    /// Класс зоны.
    fn class_ref(&self) -> Rclass;

    /// Точный поиск без композиции.
    fn lookup_ref<'a>(&'a self, name: NameRef<'a>, rtype: Rtype) -> LookupOutcomeRef<'a>;

    /// `SOA` apex.
    fn soa_ref(&self) -> Option<RrsetRef<'_>>;

    /// `NS` apex.
    fn ns_ref(&self) -> Option<RrsetRef<'_>>;

    /// Все RRset имени (все типы).
    fn records_ref<'a>(&'a self, name: NameRef<'a>) -> Vec<RrsetRef<'a>>;

    /// Все RRset `(name, rtype)` с подтипами (например, `RRSIG`).
    fn lookup_all_ref<'b, 's: 'b>(&'s self, name: NameRef<'b>, rtype: Rtype) -> Vec<RrsetRef<'b>>;

    /// `A`/`AAAA` для additional.
    fn glue_ref<'a>(&'a self, name: NameRef<'a>) -> Vec<RrsetRef<'a>>;

    /// Один `A`/`AAAA`-набор для additional без учёта zone cut.
    ///
    /// В отличие от [`ZoneSnapshot::lookup_ref`] возвращает glue и для имён
    /// ниже delegation (bailiwick referral-ответа). По умолчанию строится из
    /// [`ZoneSnapshot::glue_ref`].
    fn glue_at_ref<'b, 's: 'b>(&'s self, name: NameRef<'b>, rtype: Rtype) -> RefLookup<'b> {
        for rrset in self.glue_ref(name) {
            if rrset.rr_type() == rtype {
                return RefLookup::Found(rrset);
            }
        }
        RefLookup::Absent
    }

    /// Заимствованный `RRSIG`-набор имени, покрывающий `covered`.
    ///
    /// По умолчанию строится из [`ZoneSnapshot::lookup_all_ref`]; адаптеры
    /// хранящие подписи по подтипу (`type covered`) переопределяют метод,
    /// чтобы не собирать `Vec`.
    fn rrsig_ref<'b, 's: 'b>(&'s self, name: NameRef<'b>, covered: Rtype) -> RefLookup<'b> {
        for rrset in self.lookup_all_ref(name, Rtype::RRSIG) {
            if rrset.covers(covered) {
                return RefLookup::Found(rrset);
            }
        }
        RefLookup::Absent
    }

    /// Заимствованный `NSEC`-набор точного владельца.
    fn nsec_at_ref<'b, 's: 'b>(&'s self, name: NameRef<'b>) -> RefLookup<'b> {
        let _ = name;
        RefLookup::Absent
    }

    /// Заимствованный `NSEC`, интервал которого покрывает `name`.
    ///
    /// Владелец найденного набора копируется в `owner_wire` адаптерами,
    /// которые ищут predecessor по индексу.
    fn nsec_cover_ref<'b, 's: 'b>(
        &'s self,
        name: NameRef<'_>,
        owner_wire: &'b mut [u8; MAX_NAME_WIRE_LEN],
    ) -> RefLookup<'b> {
        let _ = (name, owner_wire);
        RefLookup::Absent
    }

    /// Заимствованный `NSEC3PARAM`-набор apex.
    fn nsec3_param_ref(&self) -> RefLookup<'_> {
        RefLookup::Absent
    }

    /// Заимствованный `NSEC3` по hash имени.
    ///
    /// Владелец hashed-имени строится в `owner_wire` вызывающего: это
    /// позволяет вернуть [`RrsetRef`] без аллокации `Name`.
    fn nsec3_at_ref<'b, 's: 'b>(
        &'s self,
        hash: &[u8],
        owner_wire: &'b mut [u8; MAX_NAME_WIRE_LEN],
    ) -> RefLookup<'b> {
        let _ = (hash, owner_wire);
        RefLookup::Absent
    }

    /// Заимствованный `NSEC3`, hash-интервал которого покрывает `hash`.
    fn nsec3_cover_ref<'b, 's: 'b>(
        &'s self,
        hash: &[u8],
        owner_wire: &'b mut [u8; MAX_NAME_WIRE_LEN],
    ) -> RefLookup<'b> {
        let _ = (hash, owner_wire);
        RefLookup::Absent
    }

    /// Существует ли узел (включая empty non-terminal).
    fn node_exists_ref(&self, name: NameRef<'_>) -> bool;

    /// Точка делегирования.
    fn is_delegation_ref(&self, name: NameRef<'_>) -> bool;

    /// Подписана ли зона.
    ///
    /// По умолчанию повторяет [`ZoneView::signed`] поверх заимствованных
    /// lookup'ов: apex `DNSKEY` и покрывающий его `RRSIG`.
    fn signed_ref(&self) -> bool {
        let origin = self.origin_ref();
        matches!(
            self.lookup_ref(origin, Rtype::DNSKEY),
            LookupOutcomeRef::Answer(_)
        ) && !matches!(self.rrsig_ref(origin, Rtype::DNSKEY), RefLookup::Absent)
    }

    /// Механизм denial-of-existence.
    fn denial_ref(&self) -> DenialKind {
        DenialKind::Nsec
    }
}

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

    /// Идентичность версии зоны для кеша готовых ответов.
    ///
    /// `None` — адаптер не поддерживает кеширование (например, отвечает на
    /// запросы из нестабильного источника). Значение обязано меняться при
    /// каждом изменении данных зоны; смена версии немедленно делает старые
    /// записи кеша недостижимыми.
    fn cache_identity(&self) -> Option<ZoneIdentity> {
        None
    }

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

    /// Механизм denial-of-existence зоны (по умолчанию NSEC).
    fn denial(&self) -> DenialKind {
        DenialKind::Nsec
    }

    /// `NSEC3PARAM`-набор apex, если зона подписана через NSEC3.
    ///
    /// Параметры (hash algorithm, iterations, salt) задают hash-пространство
    /// для поиска NSEC3-доказательств.
    fn nsec3_param(&self) -> Option<Rrset> {
        None
    }

    /// `NSEC3`-набор, owner которого — hashed-имя для `hash`.
    ///
    /// Нужен для NODATA/DS-NODATA (exact match) и closest encloser proof.
    fn nsec3_at(&self, hash: &[u8]) -> Option<Rrset> {
        let _ = hash;
        None
    }

    /// `NSEC3`-набор, hash-интервал которого покрывает `hash` (RFC 5155 §7.2).
    ///
    /// Нужен для next closer и wildcard-покрытия в NXDOMAIN и wildcard
    /// ответах.
    fn nsec3_cover(&self, hash: &[u8]) -> Option<Rrset> {
        let _ = hash;
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

    /// Выполняет `f` под снимком зоны с заимствованными lookup'ами.
    ///
    /// Возвращает `false`, если адаптер не поддерживает заимствованный путь;
    /// тогда вызывающий использует владеющие методы [`ZoneView::lookup`].
    /// Для v2 снимок держит `ZoneReader`/пин до конца callback'а.
    fn with_snapshot(&self, f: &mut dyn FnMut(&dyn ZoneSnapshot)) -> bool {
        let _ = f;
        false
    }

    /// Заимствованный точный поиск.
    ///
    /// По умолчанию не поддерживается: адаптер должен переопределить метод
    /// вместе с [`ZoneView::with_snapshot`]. Значение по умолчанию —
    /// [`LookupOutcomeRef::ZoneNotFound`] — никогда не используется движком,
    /// потому что он сначала проверяет `with_snapshot`.
    fn lookup_ref<'a>(&'a self, name: NameRef<'a>, rtype: Rtype) -> LookupOutcomeRef<'a> {
        let _ = (name, rtype);
        LookupOutcomeRef::ZoneNotFound
    }

    /// Заимствованный `SOA` apex; `None` по умолчанию.
    fn soa_ref(&self) -> Option<RrsetRef<'_>> {
        None
    }

    /// Заимствованный `NS` apex; `None` по умолчанию.
    fn ns_ref(&self) -> Option<RrsetRef<'_>> {
        None
    }

    /// Заимствованные RRset имени; по умолчанию пусто.
    fn records_ref<'a>(&'a self, name: NameRef<'a>) -> Vec<RrsetRef<'a>> {
        let _ = name;
        Vec::new()
    }

    /// Заимствованные RRset `(name, rtype)`; по умолчанию пусто.
    fn lookup_all_ref<'a>(&'a self, name: NameRef<'a>, rtype: Rtype) -> Vec<RrsetRef<'a>> {
        let _ = (name, rtype);
        Vec::new()
    }
}
