//! B+tree зоны и абстракция страничного I/O (`zonefile-v1.md` §10, §13.2–13.3).
//!
//! Дерево — набор страниц [`PageIo`]; запись идёт по COW: изменённый узел
//! пишется в новую страницу, старые страницы остаются для живых снапшотов
//! (освобождение — фаза 3, `free_page` пока no-op).
//!
//! [`BTree`] — общее B+tree над ключами [`Key`]; [`ZoneTree`] добавляет
//! семантику зоны: apex, `T_NODE`/ENT-материализацию (§13.3 шаг 9),
//! `node()` и `next_name()`.
//!
//! In-memory реализация [`PageIo`] — [`MemoryStore`]; она используется тестами
//! и бенчмарками и не является частью публикации/коммита.

use std::cmp::Ordering;

use crate::cache::PageCache;
use crate::consts::{
    INLINE_VALUE_MAX, MAX_CUT_SUBTREE_RECORDS, MAX_FILE_PAGES, MAX_RDLENGTH, MAX_RRSET_PAYLOAD,
    MAX_TREE_DEPTH, MAX_TTL,
};
use crate::errors::{CorruptDetail, CorruptKind, InvariantId, ZoneFileError};
use crate::key::{
    CLASS_IN, ChildrenProbe, Key, LABELS_MAX, NameRle, T_NODE, T_RRSIG, T_ZONE_ENTRY,
    compare_validated, name_cmp,
};
use crate::node::{
    self, BranchItem, BranchNode, DecodedBranch, DecodedLeaf, DecodedValue, EncodeContext,
    ItemValue, LeafItem, LeafNode, LeafValue, NodeRef, RR_FLAG_APEX, RR_FLAG_CHILDREN_MAY_EXIST,
    RR_FLAG_CUT_BELOW, RR_FLAG_DELEGATION, RR_FLAG_EMPTY_NON_TERMINAL, RR_FLAG_GLUE, RR_FLAG_NSEC3,
    RR_FLAG_OCCLUDED, RR_FLAG_RESERVED, RR_FLAG_SECURE_DELEGATION, RR_FLAG_WILDCARD, ValueKind,
};
use crate::overflow::{self, OverflowRrset};

/// Абстракция страничного ввода-вывода для дерева.
///
/// Реализация владеет страницами (в тестах — [`MemoryStore`], в фазе 3 —
/// pager). `read_page` возвращает срез в страницу, поэтому чтение zero-copy.
pub trait PageIo {
    /// Размер страницы в байтах.
    fn page_size(&self) -> u32;

    /// Выделяет новую страницу и возвращает её номер (`0` не выдаётся).
    ///
    /// # Errors
    ///
    /// `MapFull` — адресное пространство исчерпано.
    fn alloc_page(&mut self) -> Result<u32, ZoneFileError>;

    /// Читает страницу.
    ///
    /// # Errors
    ///
    /// `Corrupt(Bounds)` — страница не выделена или номер вне диапазона.
    fn read_page(&self, page_no: u32) -> Result<&[u8], ZoneFileError>;

    /// Перезаписывает страницу целиком.
    ///
    /// # Errors
    ///
    /// `Corrupt(Bounds)` — длина не равна `page_size`.
    fn write_page(&mut self, page_no: u32, page: &[u8]) -> Result<(), ZoneFileError>;

    /// Освобождает страницу. В фазе 2 — no-op (freelist появится в фазе 3).
    ///
    /// # Errors
    ///
    /// Ошибки реализации; текущая in-memory реализация не ошибается.
    fn free_page(&mut self, page_no: u32) -> Result<(), ZoneFileError>;

    /// COW-копия страницы: выделяет новую страницу и копирует содержимое.
    ///
    /// # Errors
    ///
    /// Ошибки [`PageIo::alloc_page`]/[`PageIo::read_page`]/[`PageIo::write_page`].
    fn cow_page(&mut self, page_no: u32) -> Result<u32, ZoneFileError> {
        let destination = self.alloc_page()?;
        let page = self.read_page(page_no)?.to_vec();
        self.write_page(destination, &page)?;
        Ok(destination)
    }
}

fn bounds(page: Option<u32>, detail: CorruptDetail) -> ZoneFileError {
    ZoneFileError::corrupt(CorruptKind::Bounds, page, detail)
}

fn tree_order(page: Option<u32>, detail: CorruptDetail) -> ZoneFileError {
    ZoneFileError::corrupt(CorruptKind::TreeOrder, page, detail)
}

fn invariant(id: InvariantId) -> ZoneFileError {
    ZoneFileError::InvariantViolation(id)
}

fn page_size_usize(page_size: u32) -> Result<usize, ZoneFileError> {
    usize::try_from(page_size).map_err(|_| bounds(None, CorruptDetail::OffsetOutOfRange))
}

pub(crate) fn is_descendant(owner: &NameRle, ancestor: &NameRle) -> bool {
    let prefix = ancestor.without_terminal();
    let bytes = owner.as_rle();
    bytes.len() > prefix.len()
        && bytes.starts_with(prefix)
        && bytes
            .get(prefix.len())
            .is_some_and(|&label_len| (1..=0x3F).contains(&label_len))
}

/// In-memory хранилище страниц для тестов и бенчмарков.
///
/// Страница `0` зарезервирована; аллокация начинается с `1`. `free_page` —
/// no-op: COW-страницы живут до конца теста (в реальном файле их освободит
/// коммит/фаза 3).
#[derive(Debug, Clone)]
pub struct MemoryStore {
    page_size: u32,
    pages: Vec<Option<Vec<u8>>>,
    next_page: u32,
}

impl MemoryStore {
    /// Создаёт пустое хранилище заданного размера страницы.
    ///
    /// # Errors
    ///
    /// `Corrupt(Bounds)` — размер меньше заголовков или не кратен 8.
    pub fn new(page_size: u32) -> Result<Self, ZoneFileError> {
        if page_size < 512 || !page_size.is_multiple_of(8) {
            return Err(bounds(None, CorruptDetail::OffsetOutOfRange));
        }
        Ok(Self {
            page_size,
            pages: vec![None],
            next_page: 1,
        })
    }

    /// Число выделенных страниц (без страницы 0).
    #[must_use]
    pub fn allocated_pages(&self) -> u32 {
        self.next_page.saturating_sub(1)
    }

    /// Содержимое страницы, если она записана.
    #[must_use]
    pub fn page(&self, page_no: u32) -> Option<&[u8]> {
        self.pages.get(usize::try_from(page_no).ok()?)?.as_deref()
    }

    fn ensure_slot(&mut self, page_no: u32) -> Result<usize, ZoneFileError> {
        let index =
            usize::try_from(page_no).map_err(|_| bounds(Some(page_no), CorruptDetail::PageNo))?;
        if index >= self.pages.len() {
            self.pages.resize_with(index + 1, || None);
        }
        Ok(index)
    }
}

impl PageIo for MemoryStore {
    fn page_size(&self) -> u32 {
        self.page_size
    }

    fn alloc_page(&mut self) -> Result<u32, ZoneFileError> {
        if self.next_page >= MAX_FILE_PAGES {
            return Err(ZoneFileError::MapFull {
                high_water: self.next_page,
                page_count_max: MAX_FILE_PAGES,
            });
        }
        let page_no = self.next_page;
        self.next_page += 1;
        let index = self.ensure_slot(page_no)?;
        if let Some(slot) = self.pages.get_mut(index) {
            *slot = None;
        }
        Ok(page_no)
    }

    fn read_page(&self, page_no: u32) -> Result<&[u8], ZoneFileError> {
        if page_no == 0 {
            return Err(bounds(Some(page_no), CorruptDetail::PageNo));
        }
        self.page(page_no)
            .ok_or_else(|| bounds(Some(page_no), CorruptDetail::PageNo))
    }

    fn write_page(&mut self, page_no: u32, page: &[u8]) -> Result<(), ZoneFileError> {
        if page_no == 0 || page.len() != usize::try_from(self.page_size).unwrap_or(0) {
            return Err(bounds(Some(page_no), CorruptDetail::OffsetOutOfRange));
        }
        let index = self.ensure_slot(page_no)?;
        let slot = self
            .pages
            .get_mut(index)
            .ok_or_else(|| bounds(Some(page_no), CorruptDetail::PageNo))?;
        *slot = Some(page.to_vec());
        Ok(())
    }

    fn free_page(&mut self, _page_no: u32) -> Result<(), ZoneFileError> {
        Ok(())
    }
}

/// Результат вставки/замены ключа.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InsertOutcome {
    /// Ключ был вставлен (не существовал).
    pub inserted: bool,
    /// Старое значение, если ключ заменён.
    pub old: Option<ItemValue>,
}

/// Запись листа, прочитанная из дерева (zero-copy).
#[derive(Debug, Clone, Copy)]
pub struct StoredEntry<'a> {
    /// Полный ключ.
    pub key: Key,
    /// Значение.
    pub value: DecodedValue<'a>,
}

/// Общее B+tree над [`Key`].
///
/// `root == 0` — пустое дерево; `level == 0` только для пустого. `level == 1`
/// означает, что корень — лист (`ZoneEntry.tree_level`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BTree {
    root: u32,
    level: u16,
}

impl BTree {
    /// Пустое дерево.
    #[must_use]
    pub const fn empty() -> Self {
        Self { root: 0, level: 0 }
    }

    /// Дерево с заданным корнем.
    ///
    /// # Errors
    ///
    /// `Corrupt(Bounds)` — `root == 0` при `level != 0`, `level == 0` при
    /// ненулевом корне или `level > MAX_TREE_DEPTH`.
    pub fn new(root: u32, level: u16) -> Result<Self, ZoneFileError> {
        if (root == 0) != (level == 0) || level > MAX_TREE_DEPTH {
            return Err(bounds(None, CorruptDetail::DepthExceeded));
        }
        Ok(Self { root, level })
    }

    /// Номер корневой страницы (`0` — пусто).
    #[must_use]
    pub const fn root(self) -> u32 {
        self.root
    }

    /// Уровень дерева: 0 — пусто, 1 — корень-лист.
    #[must_use]
    pub const fn level(self) -> u16 {
        self.level
    }

    /// Истина для пустого дерева.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.root == 0
    }

    fn find_leaf<'a, P: PageIo + ?Sized>(
        self,
        io: &'a P,
        txn: u64,
        target: &Key,
    ) -> Result<Option<DecodedLeaf<'a>>, ZoneFileError> {
        if self.root == 0 {
            return Ok(None);
        }
        let page_size = io.page_size();
        let mut page_no = self.root;
        let mut node_level = self
            .level
            .checked_sub(1)
            .ok_or_else(|| bounds(None, CorruptDetail::DepthExceeded))?;
        for _depth in 0..=MAX_TREE_DEPTH {
            let page = io.read_page(page_no)?;
            if node_level == 0 {
                return Ok(Some(DecodedLeaf::decode(page, page_no, txn, page_size)?));
            }
            let branch = DecodedBranch::decode(page, page_no, txn, page_size)?;
            if branch.level() != node_level {
                return Err(bounds(Some(page_no), CorruptDetail::PageType));
            }
            let index = branch.predecessor(target)?.unwrap_or(0);
            page_no = branch.child(index)?;
            node_level -= 1;
        }
        Err(bounds(Some(page_no), CorruptDetail::DepthExceeded))
    }

    /// Точный поиск ключа.
    ///
    /// # Errors
    ///
    /// `Corrupt` — страница повреждена.
    pub fn lookup<'a, P: PageIo + ?Sized>(
        &self,
        io: &'a P,
        txn: u64,
        target: &Key,
    ) -> Result<Option<StoredEntry<'a>>, ZoneFileError> {
        let Some(leaf) = self.find_leaf(io, txn, target)? else {
            return Ok(None);
        };
        let position = leaf.lower_bound(target)?;
        if position >= leaf.len() {
            return Ok(None);
        }
        let key = leaf.key(position)?;
        if compare_validated(&key, target) != Ordering::Equal {
            return Ok(None);
        }
        Ok(Some(StoredEntry {
            key,
            value: leaf.value(position)?,
        }))
    }

    fn find_leaf_cached<'a, P: PageIo + ?Sized>(
        self,
        io: &'a P,
        cache: &PageCache,
        txn: u64,
        target: &Key,
    ) -> Result<Option<NodeRef<'a>>, ZoneFileError> {
        if self.root == 0 {
            return Ok(None);
        }
        let mut page_no = self.root;
        let mut node_level = self
            .level
            .checked_sub(1)
            .ok_or_else(|| bounds(None, CorruptDetail::DepthExceeded))?;
        for _depth in 0..=MAX_TREE_DEPTH {
            if node_level == 0 {
                return cache.leaf(io, page_no, txn).map(Some);
            }
            let branch = cache.branch(io, page_no, txn, node_level)?;
            if branch.level() != node_level {
                return Err(bounds(Some(page_no), CorruptDetail::PageType));
            }
            let index = branch.predecessor(target)?.unwrap_or(0);
            page_no = branch.child(index)?;
            node_level -= 1;
        }
        Err(bounds(Some(page_no), CorruptDetail::DepthExceeded))
    }

    /// Точный поиск ключа через `PageCache` (zero-alloc горячий путь).
    ///
    /// # Errors
    ///
    /// `Corrupt` — страница повреждена; ошибки [`PageIo`].
    pub fn lookup_cached<'a, P: PageIo + ?Sized>(
        &self,
        io: &'a P,
        cache: &PageCache,
        txn: u64,
        target: &Key,
    ) -> Result<Option<StoredEntry<'a>>, ZoneFileError> {
        let Some(leaf) = self.find_leaf_cached(io, cache, txn, target)? else {
            return Ok(None);
        };
        let (position, captured) = leaf.lower_bound_capture(target)?;
        if position >= leaf.len() {
            return Ok(None);
        }
        let Some(key) = captured else {
            return Ok(None);
        };
        if compare_validated(&key, target) != Ordering::Equal {
            return Ok(None);
        }
        Ok(Some(StoredEntry {
            key,
            value: leaf.value(position)?,
        }))
    }

    /// Вставка или замена ключа с COW-путём до корня.
    ///
    /// # Errors
    ///
    /// `InvariantViolation(KeyOrder)` — ключ/значение не согласованы;
    /// `InvariantViolation(EncodedSize)` — item не помещается в пустую страницу;
    /// `InvariantViolation(DepthExceeded)` — превышена глубина;
    /// ошибки [`PageIo`].
    pub fn insert_or_replace<P: PageIo + ?Sized>(
        &mut self,
        io: &mut P,
        txn: u64,
        item: &LeafItem,
    ) -> Result<InsertOutcome, ZoneFileError> {
        self.insert_impl(io, None, txn, item)
    }

    /// Вставка/замена с кешем валидированных страниц (горячий путь записи).
    ///
    /// # Errors
    ///
    /// См. [`BTree::insert_or_replace`].
    pub fn insert_or_replace_cached<P: PageIo + ?Sized>(
        &mut self,
        io: &mut P,
        cache: &PageCache,
        txn: u64,
        item: &LeafItem,
    ) -> Result<InsertOutcome, ZoneFileError> {
        self.insert_impl(io, Some(cache), txn, item)
    }

    fn insert_impl<P: PageIo + ?Sized>(
        &mut self,
        io: &mut P,
        cache: Option<&PageCache>,
        txn: u64,
        item: &LeafItem,
    ) -> Result<InsertOutcome, ZoneFileError> {
        if self.root == 0 {
            let (page_no, _) = write_leaf_page(io, cache, txn, std::slice::from_ref(item))?;
            self.root = page_no;
            self.level = 1;
            return Ok(InsertOutcome {
                inserted: true,
                old: None,
            });
        }
        let inserted = insert_rec(io, cache, txn, self.root, self.level - 1, item, 0)?;
        self.root = inserted.page;
        if let Some((separator, right)) = inserted.split {
            let new_level = self
                .level
                .checked_add(1)
                .filter(|&level| level <= MAX_TREE_DEPTH)
                .ok_or_else(|| invariant(InvariantId::DepthExceeded))?;
            let branch_items = vec![
                BranchItem::new(inserted.first_key, inserted.page),
                BranchItem::new(separator, right),
            ];
            let (root_page, _) = write_branch_page(io, cache, txn, new_level - 1, &branch_items)?;
            self.root = root_page;
            self.level = new_level;
        }
        Ok(InsertOutcome {
            inserted: inserted.is_new,
            old: inserted.old,
        })
    }

    /// Удаляет ключ с COW-путём и перебалансировкой (§13.4).
    ///
    /// Возвращает старое значение, если ключ существовал. Старые страницы
    /// пути и overflow-цепочка значения уходят в набор освобождённых
    /// текущей транзакции; корень схлопывается, пустое дерево даёт `root = 0`.
    ///
    /// # Errors
    ///
    /// `Corrupt` — повреждённая страница; ошибки [`PageIo`].
    pub fn delete<P: PageIo + ?Sized>(
        &mut self,
        io: &mut P,
        txn: u64,
        target: &Key,
    ) -> Result<Option<ItemValue>, ZoneFileError> {
        if self.root == 0 {
            return Ok(None);
        }
        if self.lookup(io, txn, target)?.is_none() {
            return Ok(None);
        }
        let step = delete_rec(io, None, txn, self.root, self.level - 1, target, 0)?;
        if step.empty {
            io.free_page(step.page)?;
            *self = Self::empty();
            return Ok(step.old);
        }
        self.root = step.page;
        if let Some((separator, right)) = step.split {
            let new_level = self
                .level
                .checked_add(1)
                .filter(|&level| level <= MAX_TREE_DEPTH)
                .ok_or_else(|| invariant(InvariantId::DepthExceeded))?;
            let items = [
                BranchItem::new(step.first_key, self.root),
                BranchItem::new(separator, right),
            ];
            let (root_page, _) = write_branch_page(io, None, txn, new_level - 1, &items)?;
            self.root = root_page;
            self.level = new_level;
        }
        loop {
            if self.level <= 1 {
                break;
            }
            let branch = {
                let decoded =
                    load_branch(io, None, txn, self.root, self.level - 1, io.page_size())?;
                decoded.to_branch()?
            };
            if branch.items.is_empty() {
                io.free_page(self.root)?;
                *self = Self::empty();
                break;
            }
            if branch.items.len() != 1 {
                break;
            }
            let child = branch
                .items
                .first()
                .ok_or_else(|| bounds(Some(self.root), CorruptDetail::ChildRange))?
                .child;
            io.free_page(self.root)?;
            self.root = child;
            self.level = self
                .level
                .checked_sub(1)
                .ok_or_else(|| bounds(None, CorruptDetail::DepthExceeded))?;
        }
        Ok(step.old)
    }

    /// Строит дерево из отсортированных item'ов (bulk load).
    ///
    /// Листья и ветвления пакуются последовательно; каждый узел пишется один
    /// раз. Ключи обязаны быть строго возрастающими.
    ///
    /// # Errors
    ///
    /// `InvariantViolation(KeyOrder)` — вход не отсортирован;
    /// `InvariantViolation(EncodedSize)` — item не помещается в страницу;
    /// `InvariantViolation(DepthExceeded)` — превышена глубина; ошибки [`PageIo`].
    pub fn bulk_load<P, I>(io: &mut P, txn: u64, items: I) -> Result<Self, ZoneFileError>
    where
        P: PageIo + ?Sized,
        I: IntoIterator<Item = LeafItem>,
    {
        let mut items = items.into_iter();
        Self::bulk_load_with(io, txn, |_io| Ok(items.next()))
    }

    /// То же, что [`BTree::bulk_load`], но следующий item выдаёт замыкание.
    ///
    /// Замыкание получает `&mut P`, поэтому может писать вспомогательные
    /// страницы (overflow-цепочки) прямо во время построения дерева. Память
    /// ограничена текущим листом/ветвлением и одним item'ом.
    ///
    /// # Errors
    ///
    /// См. [`BTree::bulk_load`]; ошибки замыкания пробрасываются как есть.
    pub fn bulk_load_with<P, F>(io: &mut P, txn: u64, mut next: F) -> Result<Self, ZoneFileError>
    where
        P: PageIo + ?Sized,
        F: FnMut(&mut P) -> Result<Option<LeafItem>, ZoneFileError>,
    {
        let page_size = io.page_size();
        let mut current: Vec<LeafItem> = Vec::new();
        let mut item_bytes = 0_usize;
        let mut previous_in_chunk: Option<Key> = None;
        let mut children: Vec<(Key, u32)> = Vec::new();
        let mut last: Option<Key> = None;
        while let Some(item) = next(io)? {
            if let Some(previous) = last
                && compare_validated(&previous, &item.key) != Ordering::Less
            {
                return Err(invariant(InvariantId::KeyOrder));
            }
            last = Some(item.key);
            let index = current.len();
            let mut length = node::leaf_item_len(previous_in_chunk.as_ref(), index, &item)?;
            let mut size = leaf_chunk_size(index + 1, item_bytes + length)?;
            if size > page_size && !current.is_empty() {
                flush_leaf(io, None, txn, &current, &mut children)?;
                current.clear();
                item_bytes = 0;
                length = node::leaf_item_len(None, 0, &item)?;
                size = leaf_chunk_size(1, length)?;
                if size > page_size {
                    return Err(invariant(InvariantId::EncodedSize));
                }
            }
            current.push(item);
            item_bytes += length;
            previous_in_chunk = Some(
                current
                    .last()
                    .ok_or_else(|| invariant(InvariantId::EncodedSize))?
                    .key,
            );
        }
        if !current.is_empty() {
            flush_leaf(io, None, txn, &current, &mut children)?;
        }
        if children.is_empty() {
            return Ok(Self::empty());
        }
        let mut branch_level = 1_u16;
        loop {
            if children.len() == 1 {
                let (_, root) = children
                    .first()
                    .copied()
                    .ok_or_else(|| invariant(InvariantId::EncodedSize))?;
                return Ok(Self {
                    root,
                    level: branch_level,
                });
            }
            if branch_level > MAX_TREE_DEPTH {
                return Err(invariant(InvariantId::DepthExceeded));
            }
            let mut next: Vec<(Key, u32)> = Vec::new();
            let mut branch_items: Vec<BranchItem> = Vec::new();
            let mut branch_bytes = 0_usize;
            let mut previous_separator: Option<Key> = None;
            for (key, child) in children.drain(..) {
                let index = branch_items.len();
                let entry = BranchItem::new(key, child);
                let mut length = node::branch_item_len(previous_separator.as_ref(), index, &entry)?;
                let mut size = branch_chunk_size(index + 1, branch_bytes + length)?;
                if size > page_size && !branch_items.is_empty() {
                    flush_branch(io, None, txn, branch_level, &branch_items, &mut next)?;
                    branch_items.clear();
                    branch_bytes = 0;
                    length = node::branch_item_len(None, 0, &entry)?;
                    size = branch_chunk_size(1, length)?;
                    if size > page_size {
                        return Err(invariant(InvariantId::EncodedSize));
                    }
                }
                branch_items.push(entry);
                branch_bytes += length;
                previous_separator = branch_items.last().map(|entry| entry.key);
            }
            if !branch_items.is_empty() {
                flush_branch(io, None, txn, branch_level, &branch_items, &mut next)?;
            }
            children = next;
            branch_level = branch_level
                .checked_add(1)
                .filter(|&level| level <= MAX_TREE_DEPTH)
                .ok_or_else(|| invariant(InvariantId::DepthExceeded))?;
        }
    }

    /// Курсор для последовательного обхода (zero-copy по страницам).
    #[must_use]
    pub fn cursor<'a, P: PageIo + ?Sized>(&self, io: &'a P, txn: u64) -> Cursor<'a, P> {
        Cursor {
            io,
            txn,
            root: self.root,
            level: self.level,
            path: Vec::new(),
            leaf: None,
            index: 0,
        }
    }
}

struct Inserted {
    page: u32,
    first_key: Key,
    split: Option<(Key, u32)>,
    is_new: bool,
    old: Option<ItemValue>,
}

fn write_leaf_page<P: PageIo + ?Sized>(
    io: &mut P,
    cache: Option<&PageCache>,
    txn: u64,
    items: &[LeafItem],
) -> Result<(u32, Key), ZoneFileError> {
    let first = items
        .first()
        .map(|item| item.key)
        .ok_or_else(|| invariant(InvariantId::EncodedSize))?;
    let page_size = io.page_size();
    let mut page = vec![0_u8; page_size_usize(page_size)?];
    let page_no = io.alloc_page()?;
    let ctx = EncodeContext {
        page_no,
        page_size,
        txn,
        lsn: 0,
    };
    node::encode_leaf_trusted(&mut page, ctx, items)?;
    io.write_page(page_no, &page)?;
    if let Some(cache) = cache {
        cache.put_encoded_leaf(page_no, txn, &page, items);
    }
    Ok((page_no, first))
}

fn write_branch_page<P: PageIo + ?Sized>(
    io: &mut P,
    cache: Option<&PageCache>,
    txn: u64,
    level: u16,
    items: &[BranchItem],
) -> Result<(u32, Key), ZoneFileError> {
    let first = items
        .first()
        .map(|item| item.key)
        .ok_or_else(|| invariant(InvariantId::EncodedSize))?;
    let page_size = io.page_size();
    let mut page = vec![0_u8; page_size_usize(page_size)?];
    let page_no = io.alloc_page()?;
    let ctx = EncodeContext {
        page_no,
        page_size,
        txn,
        lsn: 0,
    };
    node::encode_branch_trusted(&mut page, ctx, level, items)?;
    io.write_page(page_no, &page)?;
    if let Some(cache) = cache {
        cache.put_encoded_branch(page_no, txn, &page, items);
    }
    Ok((page_no, first))
}

fn leaf_lower_bound(items: &[LeafItem], target: &Key) -> Result<usize, ZoneFileError> {
    let mut low = 0_usize;
    let mut high = items.len();
    while low < high {
        let middle = low + (high - low) / 2;
        let key = items
            .get(middle)
            .ok_or_else(|| bounds(None, CorruptDetail::OffsetOutOfRange))?
            .key;
        if compare_validated(&key, target) == Ordering::Less {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    Ok(low)
}

fn branch_predecessor(items: &[BranchItem], target: &Key) -> Result<Option<usize>, ZoneFileError> {
    let bound = {
        let mut low = 0_usize;
        let mut high = items.len();
        while low < high {
            let middle = low + (high - low) / 2;
            let key = items
                .get(middle)
                .ok_or_else(|| bounds(None, CorruptDetail::OffsetOutOfRange))?
                .key;
            if compare_validated(&key, target) == Ordering::Greater {
                high = middle;
            } else {
                low = middle + 1;
            }
        }
        low
    };
    Ok(bound.checked_sub(1))
}

fn split_leaf(
    items: &[LeafItem],
    page_size: u32,
) -> Result<(Vec<LeafItem>, Vec<LeafItem>), ZoneFileError> {
    let mut best: Option<(usize, u32)> = None;
    for split in 1..items.len() {
        let left = items
            .get(..split)
            .ok_or_else(|| invariant(InvariantId::EncodedSize))?;
        let right = items
            .get(split..)
            .ok_or_else(|| invariant(InvariantId::EncodedSize))?;
        let left_size = node::leaf_encoded_size_fast(left)?;
        let right_size = node::leaf_encoded_size_fast(right)?;
        if left_size <= page_size && right_size <= page_size {
            let difference = left_size.abs_diff(right_size);
            if best.is_none_or(|(_, previous)| difference < previous) {
                best = Some((split, difference));
            }
        }
    }
    let split = best
        .map(|(split, _)| split)
        .ok_or_else(|| invariant(InvariantId::EncodedSize))?;
    let mut left = items.to_vec();
    let right = left.split_off(split);
    Ok((left, right))
}

fn split_branch(
    items: &[BranchItem],
    page_size: u32,
) -> Result<(Vec<BranchItem>, Vec<BranchItem>), ZoneFileError> {
    let mut best: Option<(usize, u32)> = None;
    for split in 1..items.len() {
        let left = items
            .get(..split)
            .ok_or_else(|| invariant(InvariantId::EncodedSize))?;
        let right = items
            .get(split..)
            .ok_or_else(|| invariant(InvariantId::EncodedSize))?;
        let left_size = node::branch_encoded_size_fast(left)?;
        let right_size = node::branch_encoded_size_fast(right)?;
        if left_size <= page_size && right_size <= page_size {
            let difference = left_size.abs_diff(right_size);
            if best.is_none_or(|(_, previous)| difference < previous) {
                best = Some((split, difference));
            }
        }
    }
    let split = best
        .map(|(split, _)| split)
        .ok_or_else(|| invariant(InvariantId::EncodedSize))?;
    let mut left = items.to_vec();
    let right = left.split_off(split);
    Ok((left, right))
}

fn load_leaf<'a, P: PageIo + ?Sized>(
    io: &'a P,
    cache: Option<&PageCache>,
    txn: u64,
    page_no: u32,
    page_size: u32,
) -> Result<NodeRef<'a>, ZoneFileError> {
    match cache {
        Some(cache) => cache.leaf(io, page_no, txn),
        None => NodeRef::validate_leaf(io.read_page(page_no)?, page_no, txn, page_size),
    }
}

fn load_branch<'a, P: PageIo + ?Sized>(
    io: &'a P,
    cache: Option<&PageCache>,
    txn: u64,
    page_no: u32,
    level: u16,
    page_size: u32,
) -> Result<NodeRef<'a>, ZoneFileError> {
    match cache {
        Some(cache) => cache.branch(io, page_no, txn, level),
        None => NodeRef::validate_branch(io.read_page(page_no)?, page_no, txn, page_size),
    }
}

#[allow(clippy::too_many_lines)]
fn insert_rec<P: PageIo + ?Sized>(
    io: &mut P,
    cache: Option<&PageCache>,
    txn: u64,
    page_no: u32,
    node_level: u16,
    item: &LeafItem,
    depth: u16,
) -> Result<Inserted, ZoneFileError> {
    if depth > MAX_TREE_DEPTH || node_level > MAX_TREE_DEPTH {
        return Err(invariant(InvariantId::DepthExceeded));
    }
    let page_size = io.page_size();
    if node_level == 0 {
        let mut node = load_leaf(io, cache, txn, page_no, page_size)?.to_leaf()?;
        let position = leaf_lower_bound(&node.items, &item.key)?;
        let equal = position < node.items.len()
            && compare_validated(
                &node
                    .items
                    .get(position)
                    .ok_or_else(|| bounds(Some(page_no), CorruptDetail::OffsetOutOfRange))?
                    .key,
                &item.key,
            ) == Ordering::Equal;
        let old = if equal {
            let entry = node
                .items
                .get_mut(position)
                .ok_or_else(|| bounds(Some(page_no), CorruptDetail::OffsetOutOfRange))?;
            Some(std::mem::replace(&mut entry.value, item.value.clone()))
        } else {
            node.items.insert(position, item.clone());
            None
        };
        let first_key = node
            .items
            .first()
            .map(|entry| entry.key)
            .ok_or_else(|| invariant(InvariantId::EncodedSize))?;
        if node::leaf_encoded_size_fast(&node.items)? <= page_size {
            let (new_page, _) = write_leaf_page(io, cache, txn, &node.items)?;
            io.free_page(page_no)?;
            return Ok(Inserted {
                page: new_page,
                first_key,
                split: None,
                is_new: !equal,
                old,
            });
        }
        let (left, right) = split_leaf(&node.items, page_size)?;
        let (left_page, left_first) = write_leaf_page(io, cache, txn, &left)?;
        let (right_page, right_first) = write_leaf_page(io, cache, txn, &right)?;
        io.free_page(page_no)?;
        return Ok(Inserted {
            page: left_page,
            first_key: left_first,
            split: Some((right_first, right_page)),
            is_new: !equal,
            old,
        });
    }

    let mut branch = {
        let decoded = load_branch(io, cache, txn, page_no, node_level, page_size)?;
        if decoded.level() != node_level {
            return Err(bounds(Some(page_no), CorruptDetail::PageType));
        }
        decoded.to_branch()?
    };
    let position = branch_predecessor(&branch.items, &item.key)?.unwrap_or(0);
    let child = branch
        .items
        .get(position)
        .ok_or_else(|| bounds(Some(page_no), CorruptDetail::ChildRange))?
        .child;
    let child_result = insert_rec(io, cache, txn, child, node_level - 1, item, depth + 1)?;
    {
        let entry = branch
            .items
            .get_mut(position)
            .ok_or_else(|| bounds(Some(page_no), CorruptDetail::ChildRange))?;
        entry.child = child_result.page;
        entry.key = child_result.first_key;
    }
    if let Some((separator, right)) = child_result.split {
        branch
            .items
            .insert(position + 1, BranchItem::new(separator, right));
    }
    let first_key = branch
        .items
        .first()
        .map(|entry| entry.key)
        .ok_or_else(|| invariant(InvariantId::EncodedSize))?;
    if node::branch_encoded_size_fast(&branch.items)? <= page_size {
        let (new_page, _) = write_branch_page(io, cache, txn, node_level, &branch.items)?;
        io.free_page(page_no)?;
        return Ok(Inserted {
            page: new_page,
            first_key,
            split: None,
            is_new: child_result.is_new,
            old: child_result.old,
        });
    }
    let (left, right) = split_branch(&branch.items, page_size)?;
    let (left_page, left_first) = write_branch_page(io, cache, txn, node_level, &left)?;
    let (right_page, right_first) = write_branch_page(io, cache, txn, node_level, &right)?;
    io.free_page(page_no)?;
    Ok(Inserted {
        page: left_page,
        first_key: left_first,
        split: Some((right_first, right_page)),
        is_new: child_result.is_new,
        old: child_result.old,
    })
}

struct DeleteStep {
    page: u32,
    first_key: Key,
    old: Option<ItemValue>,
    empty: bool,
    underflow: bool,
    /// Новый правый сосед, если узел после удаления перестал помещаться в
    /// страницу (front-coding зависит от позиций restart'ов, поэтому узел с
    /// меньшим числом item'ов может кодироваться длиннее). Родитель вставляет
    /// сепаратор `(Key, u32)` сразу за текущим item'ом.
    split: Option<(Key, u32)>,
}

#[derive(Debug, Clone)]
enum NodeData {
    Leaf(LeafNode),
    Branch(BranchNode),
}

fn free_item_overflow<P: PageIo + ?Sized>(
    io: &mut P,
    value: &ItemValue,
) -> Result<(), ZoneFileError> {
    if let ItemValue::Leaf { value, .. } = value
        && value.kind == ValueKind::Overflow
        && value.val_u32 != 0
    {
        overflow::free_chain(io, value.val_u32)?;
    }
    Ok(())
}

fn load_node<P: PageIo + ?Sized>(
    io: &P,
    cache: Option<&PageCache>,
    txn: u64,
    page_no: u32,
    node_level: u16,
    page_size: u32,
) -> Result<NodeData, ZoneFileError> {
    if node_level == 0 {
        Ok(NodeData::Leaf(
            load_leaf(io, cache, txn, page_no, page_size)?.to_leaf()?,
        ))
    } else {
        Ok(NodeData::Branch(
            load_branch(io, cache, txn, page_no, node_level, page_size)?.to_branch()?,
        ))
    }
}

fn node_first(node: &NodeData) -> Result<Key, ZoneFileError> {
    match node {
        NodeData::Leaf(leaf) => leaf
            .items
            .first()
            .map(|item| item.key)
            .ok_or_else(|| bounds(None, CorruptDetail::ChildRange)),
        NodeData::Branch(branch) => branch
            .items
            .first()
            .map(|item| item.key)
            .ok_or_else(|| bounds(None, CorruptDetail::ChildRange)),
    }
}

fn node_is_empty(node: &NodeData) -> bool {
    match node {
        NodeData::Leaf(leaf) => leaf.items.is_empty(),
        NodeData::Branch(branch) => branch.items.is_empty(),
    }
}

fn node_encoded_size(node: &NodeData) -> Result<u32, ZoneFileError> {
    match node {
        NodeData::Leaf(leaf) => node::leaf_encoded_size_fast(&leaf.items),
        NodeData::Branch(branch) => node::branch_encoded_size_fast(&branch.items),
    }
}

fn node_content(node: &NodeData) -> Result<u32, ZoneFileError> {
    let size = node_encoded_size(node)?;
    Ok(size.saturating_sub(u32::try_from(node::NODE_HEADER_BYTES).unwrap_or(0)))
}

fn append_node(left: &mut NodeData, right: NodeData) -> Result<(), ZoneFileError> {
    match (left, right) {
        (NodeData::Leaf(left), NodeData::Leaf(right)) => left.items.extend(right.items),
        (NodeData::Branch(left), NodeData::Branch(right)) => left.items.extend(right.items),
        // Смешение типов на одном уровне — повреждение дерева: merge вызывается
        // только для узлов одного уровня, поэтому это защитная проверка.
        _ => return Err(bounds(None, CorruptDetail::PageType)),
    }
    Ok(())
}

fn write_node<P: PageIo + ?Sized>(
    io: &mut P,
    cache: Option<&PageCache>,
    txn: u64,
    node_level: u16,
    node: &NodeData,
) -> Result<u32, ZoneFileError> {
    match node {
        NodeData::Leaf(leaf) => Ok(write_leaf_page(io, cache, txn, &leaf.items)?.0),
        NodeData::Branch(branch) => {
            Ok(write_branch_page(io, cache, txn, node_level, &branch.items)?.0)
        }
    }
}

fn node_underflow(node: &NodeData, page_size: u32) -> Result<bool, ZoneFileError> {
    let usable = page_size.saturating_sub(u32::try_from(node::NODE_HEADER_BYTES).unwrap_or(0));
    if usable == 0 {
        return Ok(false);
    }
    // fill < 25%: content * 4 < usable. checked через u64, чтобы не переполнить.
    Ok(u64::from(node_content(node)?) * 4 < u64::from(usable))
}

#[allow(clippy::too_many_lines)]
fn delete_rec<P: PageIo + ?Sized>(
    io: &mut P,
    cache: Option<&PageCache>,
    txn: u64,
    page_no: u32,
    node_level: u16,
    target: &Key,
    depth: u16,
) -> Result<DeleteStep, ZoneFileError> {
    if depth > MAX_TREE_DEPTH || node_level > MAX_TREE_DEPTH {
        return Err(invariant(InvariantId::DepthExceeded));
    }
    let page_size = io.page_size();
    if node_level == 0 {
        let mut node = load_leaf(io, cache, txn, page_no, page_size)?.to_leaf()?;
        let position = leaf_lower_bound(&node.items, target)?;
        let equal = position < node.items.len()
            && compare_validated(
                &node
                    .items
                    .get(position)
                    .ok_or_else(|| bounds(Some(page_no), CorruptDetail::OffsetOutOfRange))?
                    .key,
                target,
            ) == Ordering::Equal;
        if !equal {
            let first_key = node
                .items
                .first()
                .map_or_else(Key::placeholder, |item| item.key);
            return Ok(DeleteStep {
                page: page_no,
                first_key,
                old: None,
                empty: node.items.is_empty(),
                underflow: false,
                split: None,
            });
        }
        let removed = node.items.remove(position);
        free_item_overflow(io, &removed.value)?;
        if node.items.is_empty() {
            return Ok(DeleteStep {
                page: page_no,
                first_key: Key::placeholder(),
                old: Some(removed.value),
                empty: true,
                underflow: true,
                split: None,
            });
        }
        let first_key = node
            .items
            .first()
            .map(|item| item.key)
            .ok_or_else(|| invariant(InvariantId::EncodedSize))?;
        if node::leaf_encoded_size_fast(&node.items)? <= page_size {
            let underflow = node_underflow(&NodeData::Leaf(node.clone()), page_size)?;
            let (new_page, _) = write_leaf_page(io, cache, txn, &node.items)?;
            io.free_page(page_no)?;
            return Ok(DeleteStep {
                page: new_page,
                first_key,
                old: Some(removed.value),
                empty: false,
                underflow,
                split: None,
            });
        }
        // Удаление сдвинуло restart-разметку: узел с меньшим числом item'ов
        // кодируется длиннее и перестал помещаться. Делим его и сообщаем
        // родителю о новом правом соседе.
        let (left, right) = split_leaf(&node.items, page_size)?;
        let (left_page, left_first) = write_leaf_page(io, cache, txn, &left)?;
        let (right_page, right_first) = write_leaf_page(io, cache, txn, &right)?;
        io.free_page(page_no)?;
        Ok(DeleteStep {
            page: left_page,
            first_key: left_first,
            old: Some(removed.value),
            empty: false,
            underflow: false,
            split: Some((right_first, right_page)),
        })
    } else {
        let mut branch = {
            let decoded = load_branch(io, cache, txn, page_no, node_level, page_size)?;
            if decoded.level() != node_level {
                return Err(bounds(Some(page_no), CorruptDetail::PageType));
            }
            decoded.to_branch()?
        };
        let position = branch_predecessor(&branch.items, target)?.unwrap_or(0);
        let child = branch
            .items
            .get(position)
            .ok_or_else(|| bounds(Some(page_no), CorruptDetail::ChildRange))?
            .child;
        let mut step = delete_rec(io, cache, txn, child, node_level - 1, target, depth + 1)?;
        let child_split = step.split.take();
        if step.empty {
            io.free_page(step.page)?;
            branch.items.remove(position);
        } else {
            {
                let entry = branch
                    .items
                    .get_mut(position)
                    .ok_or_else(|| bounds(Some(page_no), CorruptDetail::ChildRange))?;
                entry.child = step.page;
                entry.key = step.first_key;
            }
            if let Some((separator, right)) = child_split {
                branch
                    .items
                    .insert(position + 1, BranchItem::new(separator, right));
            } else if step.underflow {
                rebalance(io, cache, txn, node_level, &mut branch.items, position)?;
            }
        }
        if branch.items.is_empty() {
            return Ok(DeleteStep {
                page: page_no,
                first_key: Key::placeholder(),
                old: step.old,
                empty: true,
                underflow: true,
                split: None,
            });
        }
        let first_key = branch
            .items
            .first()
            .map(|entry| entry.key)
            .ok_or_else(|| invariant(InvariantId::EncodedSize))?;
        if node::branch_encoded_size_fast(&branch.items)? <= page_size {
            let underflow = node_underflow(&NodeData::Branch(branch.clone()), page_size)?;
            let (new_page, _) = write_branch_page(io, cache, txn, node_level, &branch.items)?;
            io.free_page(page_no)?;
            step.page = new_page;
            step.first_key = first_key;
            // Ветвление выжило: `empty` от удалённого ребёнка не наследуется,
            // иначе родитель удалил бы всё поддерево.
            step.empty = false;
            step.underflow = underflow;
            step.split = None;
            return Ok(step);
        }
        // Та же restart-разметка, но на уровне ветвления.
        let (left, right) = split_branch(&branch.items, page_size)?;
        let (left_page, left_first) = write_branch_page(io, cache, txn, node_level, &left)?;
        let (right_page, right_first) = write_branch_page(io, cache, txn, node_level, &right)?;
        io.free_page(page_no)?;
        step.page = left_page;
        step.first_key = left_first;
        step.empty = false;
        step.underflow = false;
        step.split = Some((right_first, right_page));
        Ok(step)
    }
}

#[allow(clippy::too_many_lines)]
fn rebalance<P: PageIo + ?Sized>(
    io: &mut P,
    cache: Option<&PageCache>,
    txn: u64,
    parent_level: u16,
    items: &mut Vec<BranchItem>,
    index: usize,
) -> Result<(), ZoneFileError> {
    if items.len() < 2 {
        return Ok(());
    }
    let child_level = parent_level.saturating_sub(1);
    let page_size = io.page_size();
    let usable = page_size.saturating_sub(u32::try_from(node::NODE_HEADER_BYTES).unwrap_or(0));
    let child_page = items
        .get(index)
        .ok_or_else(|| bounds(None, CorruptDetail::ChildRange))?
        .child;
    let child_node = load_node(io, cache, txn, child_page, child_level, page_size)?;
    let child_content = node_content(&child_node)?;
    if node_is_empty(&child_node) {
        if items.len() < 2 {
            return Ok(());
        }
        // Пустой ребёнок: его item и страница удаляются, сосед не переписывается.
        io.free_page(child_page)?;
        items.remove(index);
        return Ok(());
    }
    let right = index + 1 < items.len();
    let sibling_index = if right { index + 1 } else { index - 1 };
    let sibling_page = items
        .get(sibling_index)
        .ok_or_else(|| bounds(None, CorruptDetail::ChildRange))?
        .child;
    let sibling_node = load_node(io, cache, txn, sibling_page, child_level, page_size)?;
    let sibling_content = node_content(&sibling_node)?;
    let combined = u64::from(child_content).saturating_add(u64::from(sibling_content));

    // Слияние: суммарное содержимое <= 75% usable и результат реально
    // помещается в страницу. Оценка по `node_content` игнорирует сдвиг
    // restart-разметки, поэтому размер проверяется повторным планированием.
    if combined * 4 <= u64::from(usable) * 3 {
        let (left_index, right_index) = if right {
            (index, sibling_index)
        } else {
            (sibling_index, index)
        };
        let left_node = if right {
            child_node.clone()
        } else {
            sibling_node.clone()
        };
        let right_node = if right {
            sibling_node.clone()
        } else {
            child_node.clone()
        };
        let mut merged = left_node;
        append_node(&mut merged, right_node)?;
        let (left_page, right_page) = (
            items
                .get(left_index)
                .ok_or_else(|| bounds(None, CorruptDetail::ChildRange))?
                .child,
            items
                .get(right_index)
                .ok_or_else(|| bounds(None, CorruptDetail::ChildRange))?
                .child,
        );
        if node_is_empty(&merged) {
            io.free_page(left_page)?;
            io.free_page(right_page)?;
            items.remove(right_index);
            items.remove(left_index);
            return Ok(());
        }
        if node_encoded_size(&merged)? <= page_size {
            let first_key = node_first(&merged)?;
            let merged_page = write_node(io, cache, txn, child_level, &merged)?;
            io.free_page(left_page)?;
            io.free_page(right_page)?;
            if let Some(entry) = items.get_mut(left_index) {
                entry.key = first_key;
                entry.child = merged_page;
            }
            items.remove(right_index);
            return Ok(());
        }
        // Не помещается: пробуем заимствование ниже, иначе узел остаётся
        // недозаполненным (это корректное состояние дерева).
    }

    // Заимствование: у соседа >= 40% usable. Переносим item'ы, пока это
    // помогает (не опустошая соседа).
    let sibling_fraction_ok = u64::from(sibling_content) * 10 >= u64::from(usable) * 4;
    if !sibling_fraction_ok {
        return Ok(());
    }
    if right {
        let (new_child, new_right) = match (child_node, sibling_node) {
            (NodeData::Leaf(mut child), NodeData::Leaf(mut right)) => {
                if right.items.len() <= 1 {
                    return Ok(());
                }
                let mut moved = false;
                while node_underflow(&NodeData::Leaf(child.clone()), page_size)?
                    && right.items.len() > 1
                {
                    let Some(item) = right.items.first().cloned() else {
                        break;
                    };
                    right.items.remove(0);
                    child.items.push(item);
                    moved = true;
                }
                if !moved {
                    return Ok(());
                }
                (NodeData::Leaf(child), NodeData::Leaf(right))
            }
            (NodeData::Branch(mut child), NodeData::Branch(mut right)) => {
                if right.items.len() <= 1 {
                    return Ok(());
                }
                let mut moved = false;
                while node_underflow(&NodeData::Branch(child.clone()), page_size)?
                    && right.items.len() > 1
                {
                    let Some(item) = right.items.first().cloned() else {
                        break;
                    };
                    right.items.remove(0);
                    child.items.push(item);
                    moved = true;
                }
                if !moved {
                    return Ok(());
                }
                (NodeData::Branch(child), NodeData::Branch(right))
            }
            _ => return Ok(()),
        };
        let child_first = node_first(&new_child)?;
        let right_first = node_first(&new_right)?;
        if node_encoded_size(&new_child)? > page_size || node_encoded_size(&new_right)? > page_size
        {
            return Ok(());
        }
        let new_child_page = write_node(io, cache, txn, child_level, &new_child)?;
        let new_right_page = write_node(io, cache, txn, child_level, &new_right)?;
        io.free_page(child_page)?;
        io.free_page(sibling_page)?;
        if let Some(entry) = items.get_mut(index) {
            entry.key = child_first;
            entry.child = new_child_page;
        }
        if let Some(entry) = items.get_mut(sibling_index) {
            entry.key = right_first;
            entry.child = new_right_page;
        }
        return Ok(());
    }

    let (new_left, new_child) = match (sibling_node, child_node) {
        (NodeData::Leaf(mut left), NodeData::Leaf(mut child)) => {
            if left.items.len() <= 1 {
                return Ok(());
            }
            let mut moved = false;
            while node_underflow(&NodeData::Leaf(child.clone()), page_size)? && left.items.len() > 1
            {
                let Some(item) = left.items.pop() else {
                    break;
                };
                child.items.insert(0, item);
                moved = true;
            }
            if !moved {
                return Ok(());
            }
            (NodeData::Leaf(left), NodeData::Leaf(child))
        }
        (NodeData::Branch(mut left), NodeData::Branch(mut child)) => {
            if left.items.len() <= 1 {
                return Ok(());
            }
            let mut moved = false;
            while node_underflow(&NodeData::Branch(child.clone()), page_size)?
                && left.items.len() > 1
            {
                let Some(item) = left.items.pop() else {
                    break;
                };
                child.items.insert(0, item);
                moved = true;
            }
            if !moved {
                return Ok(());
            }
            (NodeData::Branch(left), NodeData::Branch(child))
        }
        _ => return Ok(()),
    };
    let left_first = node_first(&new_left)?;
    let child_first = node_first(&new_child)?;
    if node_encoded_size(&new_left)? > page_size || node_encoded_size(&new_child)? > page_size {
        return Ok(());
    }
    let new_left_page = write_node(io, cache, txn, child_level, &new_left)?;
    let new_child_page = write_node(io, cache, txn, child_level, &new_child)?;
    io.free_page(sibling_page)?;
    io.free_page(child_page)?;
    if let Some(entry) = items.get_mut(sibling_index) {
        entry.key = left_first;
        entry.child = new_left_page;
    }
    if let Some(entry) = items.get_mut(index) {
        entry.key = child_first;
        entry.child = new_child_page;
    }
    Ok(())
}

fn leaf_chunk_size(n_items: usize, item_bytes: usize) -> Result<u32, ZoneFileError> {
    let restarts = n_items.div_ceil(node::LEAF_INTERVAL);
    let arrays = node::NODE_HEADER_BYTES
        .checked_add(2 * (n_items + restarts))
        .ok_or_else(|| invariant(InvariantId::EncodedSize))?;
    u32::try_from(arrays + item_bytes).map_err(|_| invariant(InvariantId::EncodedSize))
}

fn branch_chunk_size(n_items: usize, item_bytes: usize) -> Result<u32, ZoneFileError> {
    let restarts = n_items.div_ceil(node::BRANCH_INTERVAL);
    let arrays = node::NODE_HEADER_BYTES
        .checked_add(2 * (n_items + restarts))
        .ok_or_else(|| invariant(InvariantId::EncodedSize))?;
    u32::try_from(arrays + item_bytes).map_err(|_| invariant(InvariantId::EncodedSize))
}

fn flush_leaf<P: PageIo + ?Sized>(
    io: &mut P,
    cache: Option<&PageCache>,
    txn: u64,
    items: &[LeafItem],
    children: &mut Vec<(Key, u32)>,
) -> Result<(), ZoneFileError> {
    let (page_no, first) = write_leaf_page(io, cache, txn, items)?;
    children.push((first, page_no));
    Ok(())
}

fn flush_branch<P: PageIo + ?Sized>(
    io: &mut P,
    cache: Option<&PageCache>,
    txn: u64,
    level: u16,
    items: &[BranchItem],
    children: &mut Vec<(Key, u32)>,
) -> Result<(), ZoneFileError> {
    let (page_no, first) = write_branch_page(io, cache, txn, level, items)?;
    children.push((first, page_no));
    Ok(())
}

/// Курсор по дереву: спуск до листа и последовательный проход.
pub struct Cursor<'a, P: PageIo + ?Sized> {
    io: &'a P,
    txn: u64,
    root: u32,
    level: u16,
    path: Vec<(u32, usize, u16)>,
    leaf: Option<DecodedLeaf<'a>>,
    index: usize,
}

#[allow(clippy::elidable_lifetime_names)]
impl<'a, P: PageIo + ?Sized> Cursor<'a, P> {
    /// Позиционируется на первый ключ `>= target`.
    ///
    /// # Errors
    ///
    /// `Corrupt` — повреждённая страница.
    pub fn seek(&mut self, target: &Key) -> Result<bool, ZoneFileError> {
        self.seek_by(|key| Ok(compare_validated(key, target)))
    }

    /// Позиционируется на первый ключ, для которого `compare` даёт `>= Equal`.
    ///
    /// # Errors
    ///
    /// `Corrupt` — повреждённая страница; ошибка компаратора.
    pub fn seek_by<F>(&mut self, mut compare: F) -> Result<bool, ZoneFileError>
    where
        F: FnMut(&Key) -> Result<Ordering, ZoneFileError>,
    {
        self.path.clear();
        self.leaf = None;
        self.index = 0;
        if self.root == 0 {
            return Ok(false);
        }
        let page_size = self.io.page_size();
        let mut page_no = self.root;
        let mut node_level = self
            .level
            .checked_sub(1)
            .ok_or_else(|| bounds(None, CorruptDetail::DepthExceeded))?;
        for _depth in 0..=MAX_TREE_DEPTH {
            let page = self.io.read_page(page_no)?;
            if node_level == 0 {
                let leaf = DecodedLeaf::decode(page, page_no, self.txn, page_size)?;
                let position = leaf.lower_bound_by(&mut compare)?;
                let exhausted = position >= leaf.len();
                self.leaf = Some(leaf);
                self.index = position;
                if exhausted {
                    return self.advance();
                }
                return Ok(true);
            }
            let branch = DecodedBranch::decode(page, page_no, self.txn, page_size)?;
            if branch.level() != node_level {
                return Err(bounds(Some(page_no), CorruptDetail::PageType));
            }
            let index = branch.predecessor_by(&mut compare)?.unwrap_or(0);
            self.path.push((page_no, index, node_level));
            page_no = branch.child(index)?;
            node_level -= 1;
        }
        Err(bounds(Some(page_no), CorruptDetail::DepthExceeded))
    }

    /// Позиционируется на последний ключ, для которого `compare` даёт
    /// `< Equal` (строгий предшественник).
    ///
    /// Возвращает `false`, если в дереве нет ключа строго меньше `target`.
    ///
    /// # Errors
    ///
    /// `Corrupt` — повреждённая страница; ошибка компаратора.
    pub fn seek_prev_by<F>(&mut self, mut compare: F) -> Result<bool, ZoneFileError>
    where
        F: FnMut(&Key) -> Result<Ordering, ZoneFileError>,
    {
        // `seek_by` встаёт на первый ключ `>= target`. Ключи одного владельца
        // могут пересекать границу листа, поэтому шагаем назад до первого
        // ключа, который компаратор действительно считает меньшим.
        let _ = self.seek_by(&mut compare)?;
        loop {
            if !self.retreat()? {
                return Ok(false);
            }
            let Some(key) = self.key()? else {
                return Ok(false);
            };
            if compare(&key)? == Ordering::Less {
                return Ok(true);
            }
        }
    }

    /// Позиционируется на первый ключ дерева.
    ///
    /// # Errors
    ///
    /// `Corrupt` — повреждённая страница.
    pub fn seek_first(&mut self) -> Result<bool, ZoneFileError> {
        self.path.clear();
        self.leaf = None;
        self.index = 0;
        if self.root == 0 {
            return Ok(false);
        }
        let node_level = self
            .level
            .checked_sub(1)
            .ok_or_else(|| bounds(None, CorruptDetail::DepthExceeded))?;
        self.descend_leftmost(self.root, node_level)?;
        Ok(self
            .leaf
            .as_ref()
            .is_some_and(|leaf| self.index < leaf.len()))
    }

    /// Позиционируется на последний ключ дерева.
    ///
    /// # Errors
    ///
    /// `Corrupt` — повреждённая страница.
    pub fn seek_last(&mut self) -> Result<bool, ZoneFileError> {
        self.path.clear();
        self.leaf = None;
        self.index = 0;
        if self.root == 0 {
            return Ok(false);
        }
        let node_level = self
            .level
            .checked_sub(1)
            .ok_or_else(|| bounds(None, CorruptDetail::DepthExceeded))?;
        self.descend_rightmost(self.root, node_level)?;
        Ok(self.leaf.as_ref().is_some_and(|leaf| !leaf.is_empty()))
    }

    fn descend_leftmost(
        &mut self,
        mut page_no: u32,
        mut node_level: u16,
    ) -> Result<(), ZoneFileError> {
        let page_size = self.io.page_size();
        loop {
            let page = self.io.read_page(page_no)?;
            if node_level == 0 {
                let leaf = DecodedLeaf::decode(page, page_no, self.txn, page_size)?;
                self.leaf = Some(leaf);
                self.index = 0;
                return Ok(());
            }
            let branch = DecodedBranch::decode(page, page_no, self.txn, page_size)?;
            if branch.level() != node_level {
                return Err(bounds(Some(page_no), CorruptDetail::PageType));
            }
            self.path.push((page_no, 0, node_level));
            page_no = branch.child(0)?;
            node_level -= 1;
        }
    }

    fn descend_rightmost(
        &mut self,
        mut page_no: u32,
        mut node_level: u16,
    ) -> Result<(), ZoneFileError> {
        let page_size = self.io.page_size();
        loop {
            let page = self.io.read_page(page_no)?;
            if node_level == 0 {
                let leaf = DecodedLeaf::decode(page, page_no, self.txn, page_size)?;
                self.index = leaf.len().saturating_sub(1);
                self.leaf = Some(leaf);
                return Ok(());
            }
            let branch = DecodedBranch::decode(page, page_no, self.txn, page_size)?;
            if branch.level() != node_level {
                return Err(bounds(Some(page_no), CorruptDetail::PageType));
            }
            let index = branch.len().saturating_sub(1);
            self.path.push((page_no, index, node_level));
            page_no = branch.child(index)?;
            node_level -= 1;
        }
    }

    /// Шаг назад к предыдущему item'у дерева.
    ///
    /// `false` — курсор уже на первом item'е (или дерево пусто).
    fn retreat(&mut self) -> Result<bool, ZoneFileError> {
        loop {
            if self.leaf.is_some() && self.index > 0 {
                self.index -= 1;
                return Ok(true);
            }
            let page_size = self.io.page_size();
            let Some(&(page_no, index, node_level)) = self.path.last() else {
                return Ok(false);
            };
            if index == 0 {
                self.path.pop();
                continue;
            }
            let page = self.io.read_page(page_no)?;
            let branch = DecodedBranch::decode(page, page_no, self.txn, page_size)?;
            let previous = index - 1;
            let child = branch.child(previous)?;
            if let Some(entry) = self.path.last_mut() {
                *entry = (page_no, previous, node_level);
            }
            self.descend_rightmost(child, node_level - 1)?;
            return Ok(self.leaf.as_ref().is_some_and(|leaf| !leaf.is_empty()));
        }
    }

    /// Текущий ключ.
    ///
    /// # Errors
    ///
    /// `Corrupt` — страница повреждена (недостижимо после `decode`).
    pub fn key(&self) -> Result<Option<Key>, ZoneFileError> {
        match &self.leaf {
            Some(leaf) if self.index < leaf.len() => leaf.key(self.index).map(Some),
            _ => Ok(None),
        }
    }

    /// Текущее значение.
    ///
    /// # Errors
    ///
    /// `Corrupt` — страница повреждена (недостижимо после `decode`).
    pub fn value(&self) -> Result<Option<DecodedValue<'a>>, ZoneFileError> {
        match &self.leaf {
            Some(leaf) if self.index < leaf.len() => leaf.value(self.index).map(Some),
            _ => Ok(None),
        }
    }

    /// Материализует текущий item.
    ///
    /// # Errors
    ///
    /// `Corrupt` — страница повреждена (недостижимо после `decode`).
    pub fn item(&self) -> Result<Option<LeafItem>, ZoneFileError> {
        let Some(key) = self.key()? else {
            return Ok(None);
        };
        let Some(value) = self.value()? else {
            return Ok(None);
        };
        let value = match value {
            DecodedValue::ZoneEntry(bytes) => ItemValue::zone_entry(bytes)?,
            DecodedValue::Rrset { value, payload } => {
                if value.kind == ValueKind::Inline {
                    ItemValue::inline(value, payload.to_vec())?
                } else {
                    ItemValue::Leaf {
                        value,
                        payload: Vec::new(),
                    }
                }
            }
        };
        Ok(Some(LeafItem::new(key, value)))
    }

    /// Переход к следующему item'у дерева.
    ///
    /// # Errors
    ///
    /// `Corrupt` — повреждённая страница.
    pub fn advance(&mut self) -> Result<bool, ZoneFileError> {
        if self
            .leaf
            .as_ref()
            .is_some_and(|leaf| self.index + 1 < leaf.len())
        {
            self.index += 1;
            return Ok(true);
        }
        let page_size = self.io.page_size();
        loop {
            let Some(&(page_no, index, node_level)) = self.path.last() else {
                self.index = self.leaf.as_ref().map_or(0, DecodedLeaf::len);
                return Ok(false);
            };
            let page = self.io.read_page(page_no)?;
            let branch = DecodedBranch::decode(page, page_no, self.txn, page_size)?;
            if index + 1 < branch.len() {
                let next = index + 1;
                let child = branch.child(next)?;
                if let Some(entry) = self.path.last_mut() {
                    *entry = (page_no, next, node_level);
                }
                self.descend_leftmost(child, node_level - 1)?;
                return Ok(self.leaf.as_ref().is_some_and(|leaf| !leaf.is_empty()));
            }
            self.path.pop();
        }
    }
}

/// Информация об имени (`NodeRef`, §20.3).
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeInfo {
    /// Имя.
    pub name: NameRle,
    /// Есть ли `T_NODE` (имя существует, в том числе как ENT).
    pub exists: bool,
    /// Имя — apex зоны.
    pub is_apex: bool,
    /// Имя существует только как предок (ENT).
    pub is_empty_non_terminal: bool,
    /// Имя — cut (NS без SOA, с DS или без).
    pub is_zone_cut: bool,
    /// Есть ли потомки.
    pub has_children: bool,
    /// Флаги `T_NODE`.
    pub flags: u16,
}

/// Итог upsert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpsertOutcome {
    /// Ключ `RRset` был вставлен (не существовал).
    pub inserted: bool,
    /// Ключ `RRset` заменил существующий.
    pub replaced: bool,
    /// Были ли фактические записи (повторный идемпотентный upsert — `false`).
    pub changed: bool,
}

/// Данные `RRset` для записи: TTL, флаги и RDATA каждого RR.
///
/// RDATA сортируются по каноническому порядку (лексикографически по байтам,
/// RFC 4034 §6.3) — инвариант W-3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrsetData {
    ttl: u32,
    flags: u16,
    rdata: Vec<Vec<u8>>,
}

impl RrsetData {
    /// Создаёт набор из RDATA-байтов и сортирует их.
    ///
    /// # Errors
    ///
    /// `Corrupt(BadTtl)` — TTL > `2^31−1`; `RdataTooLarge` — RDATA одного RR
    /// > 65535; `RrsetTooLarge` — сумма `rdlength` > 65535 или payload
    /// > [`MAX_RRSET_PAYLOAD`]; `Corrupt(Bounds)` — зарезервированные флаги.
    pub fn new(ttl: u32, flags: u16, mut rdata: Vec<Vec<u8>>) -> Result<Self, ZoneFileError> {
        if ttl > MAX_TTL {
            return Err(ZoneFileError::TtlOutOfRange { ttl, max: MAX_TTL });
        }
        if flags & RR_FLAG_RESERVED != 0 {
            return Err(bounds(None, CorruptDetail::OffsetOutOfRange));
        }
        if rdata.len() > usize::from(u16::MAX) {
            return Err(ZoneFileError::RrsetTooLarge);
        }
        let max_rdlength = usize::try_from(MAX_RDLENGTH).unwrap_or(usize::MAX);
        let mut sum = 0_usize;
        for rr in &rdata {
            if rr.len() > max_rdlength {
                return Err(ZoneFileError::RdataTooLarge);
            }
            sum = sum
                .checked_add(rr.len())
                .filter(|&sum| u16::try_from(sum).is_ok())
                .ok_or(ZoneFileError::RrsetTooLarge)?;
        }
        let rr_count = u32::try_from(rdata.len()).map_err(|_| ZoneFileError::RrsetTooLarge)?;
        let rdlen = u32::try_from(sum).map_err(|_| ZoneFileError::RrsetTooLarge)?;
        rdlen
            .checked_add(
                rr_count
                    .checked_mul(2)
                    .ok_or(ZoneFileError::RrsetTooLarge)?,
            )
            .filter(|&total| total <= MAX_RRSET_PAYLOAD)
            .ok_or(ZoneFileError::RrsetTooLarge)?;
        rdata.sort();
        Ok(Self { ttl, flags, rdata })
    }

    /// Создаёт набор из срезов RDATA.
    ///
    /// # Errors
    ///
    /// См. [`RrsetData::new`].
    pub fn from_slices(ttl: u32, flags: u16, rdata: &[&[u8]]) -> Result<Self, ZoneFileError> {
        Self::new(
            ttl,
            flags,
            rdata.iter().map(|rdata| (*rdata).to_vec()).collect(),
        )
    }

    /// TTL набора.
    #[must_use]
    pub const fn ttl(&self) -> u32 {
        self.ttl
    }

    /// Флаги набора.
    #[must_use]
    pub const fn flags(&self) -> u16 {
        self.flags
    }

    /// Число RR.
    ///
    /// # Errors
    ///
    /// `RrsetTooLarge` — больше `u16::MAX` RR.
    pub fn rr_count(&self) -> Result<u16, ZoneFileError> {
        u16::try_from(self.rdata.len()).map_err(|_| ZoneFileError::RrsetTooLarge)
    }

    /// Сумма `rdlength`.
    ///
    /// # Errors
    ///
    /// `RrsetTooLarge` — сумма больше `u16::MAX`.
    pub fn rdlen(&self) -> Result<u16, ZoneFileError> {
        let sum = self
            .rdata
            .iter()
            .try_fold(0_usize, |sum, rr| sum.checked_add(rr.len()))
            .ok_or(ZoneFileError::RrsetTooLarge)?;
        u16::try_from(sum).map_err(|_| ZoneFileError::RrsetTooLarge)
    }

    /// Длина payload (`rdlen + 2*rr_count`).
    ///
    /// # Errors
    ///
    /// `RrsetTooLarge`.
    pub fn payload_len(&self) -> Result<u32, ZoneFileError> {
        u32::from(self.rdlen()?)
            .checked_add(u32::from(self.rr_count()?).saturating_mul(2))
            .ok_or(ZoneFileError::RrsetTooLarge)
    }

    /// RDATA всех RR в каноническом порядке.
    #[must_use]
    pub fn rdata(&self) -> &[Vec<u8>] {
        &self.rdata
    }

    /// Кодирует payload `{u16 rdlength; rdata}*rr_count` с big-endian
    /// префиксами длин (DNS wire).
    ///
    /// # Errors
    ///
    /// `RrsetTooLarge` — длина RR > 65535.
    pub fn payload(&self) -> Result<Vec<u8>, ZoneFileError> {
        let mut out = Vec::with_capacity(
            usize::try_from(self.payload_len()?).map_err(|_| ZoneFileError::RrsetTooLarge)?,
        );
        for rr in &self.rdata {
            let length = u16::try_from(rr.len()).map_err(|_| ZoneFileError::RdataTooLarge)?;
            out.extend_from_slice(&length.to_be_bytes());
            out.extend_from_slice(rr);
        }
        Ok(out)
    }
}

/// Дерево одной зоны: apex + [`BTree`] с `T_NODE`/ENT-семантикой.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneTree {
    apex: NameRle,
    tree: BTree,
}

impl ZoneTree {
    /// Пустая зона (корень создаётся первой вставкой).
    #[must_use]
    pub const fn empty(apex: NameRle) -> Self {
        Self {
            apex,
            tree: BTree::empty(),
        }
    }

    /// Зона с восстановленным деревом (`ZoneEntry.tree_root`/`tree_level`).
    ///
    /// # Errors
    ///
    /// `Corrupt(Bounds)` — несогласованные `root`/`level`.
    pub fn new(apex: NameRle, root: u32, level: u16) -> Result<Self, ZoneFileError> {
        Ok(Self {
            apex,
            tree: BTree::new(root, level)?,
        })
    }

    /// Apex зоны.
    #[must_use]
    pub const fn apex(&self) -> &NameRle {
        &self.apex
    }

    /// Корень дерева.
    #[must_use]
    pub const fn root(&self) -> u32 {
        self.tree.root()
    }

    /// Уровень дерева.
    #[must_use]
    pub const fn level(&self) -> u16 {
        self.tree.level()
    }

    /// Нижнее B+tree (для каталога/диагностики).
    #[must_use]
    pub const fn btree(&self) -> &BTree {
        &self.tree
    }

    /// Нижнее B+tree для записи (низкоуровневые операции).
    pub fn btree_mut(&mut self) -> &mut BTree {
        &mut self.tree
    }

    fn ancestor_chain(&self, name: &NameRle) -> Result<Vec<NameRle>, ZoneFileError> {
        let mut chain = vec![*name];
        let mut current = *name;
        while current != self.apex {
            let Some(parent) = current.parent() else {
                return Err(ZoneFileError::NameOutsideZone);
            };
            chain.push(parent);
            current = parent;
            if chain.len() > LABELS_MAX + 1 {
                return Err(ZoneFileError::NameOutsideZone);
            }
        }
        Ok(chain)
    }

    fn node_flags<P: PageIo + ?Sized>(
        &self,
        io: &P,
        txn: u64,
        name: &NameRle,
    ) -> Result<Option<u16>, ZoneFileError> {
        let key = Key::new(name, T_NODE, 0, 0)?;
        match self.tree.lookup(io, txn, &key)? {
            None => Ok(None),
            Some(entry) => match entry.value {
                DecodedValue::Rrset { value, .. } if value.kind == ValueKind::Node => {
                    Ok(Some(value.flags))
                }
                _ => Err(tree_order(None, CorruptDetail::KeyOrder)),
            },
        }
    }

    /// Точный поиск `RRset` `(name, type, subtype)`.
    ///
    /// # Errors
    ///
    /// `WrongAccessor` — `RRSIG` с `subtype = 0` (§12.5);
    /// `Corrupt` — повреждённое дерево.
    pub fn lookup<'a, P: PageIo + ?Sized>(
        &self,
        io: &'a P,
        txn: u64,
        name: &NameRle,
        rr_type: u16,
        subtype: u16,
    ) -> Result<Option<StoredEntry<'a>>, ZoneFileError> {
        if rr_type == T_RRSIG && subtype == 0 {
            return Err(ZoneFileError::WrongAccessor);
        }
        let key = Key::new(name, rr_type, CLASS_IN, subtype)?;
        self.tree.lookup(io, txn, &key)
    }

    /// Точный поиск `RRset` через `PageCache` (zero-alloc горячий путь).
    ///
    /// # Errors
    ///
    /// `WrongAccessor` — `RRSIG` с `subtype = 0`; `Corrupt` — повреждённое
    /// дерево; ошибки [`PageIo`].
    pub fn lookup_cached<'a, P: PageIo + ?Sized>(
        &self,
        io: &'a P,
        cache: &PageCache,
        txn: u64,
        name: &NameRle,
        rr_type: u16,
        subtype: u16,
    ) -> Result<Option<StoredEntry<'a>>, ZoneFileError> {
        if rr_type == T_RRSIG && subtype == 0 {
            return Err(ZoneFileError::WrongAccessor);
        }
        let key = Key::new(name, rr_type, CLASS_IN, subtype)?;
        self.tree.lookup_cached(io, cache, txn, &key)
    }

    /// Все `RRset`'ы `(name, type)` по возрастанию `subtype` (§12.5).
    ///
    /// # Errors
    ///
    /// `Corrupt` — повреждённое дерево.
    pub fn lookup_all<P: PageIo + ?Sized>(
        &self,
        io: &P,
        txn: u64,
        name: &NameRle,
        rr_type: u16,
    ) -> Result<Vec<LeafItem>, ZoneFileError> {
        let start = Key::new(name, rr_type, CLASS_IN, 0)?;
        let mut cursor = self.tree.cursor(io, txn);
        if !cursor.seek(&start)? {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        while let Some(item) = cursor.item()? {
            if item.key.owner_bytes() != name.as_rle()
                || item.key.rr_type() != rr_type
                || item.key.class() != CLASS_IN
            {
                break;
            }
            out.push(item);
            if !cursor.advance()? {
                break;
            }
        }
        Ok(out)
    }

    /// Предикат `has_children` (§13.3): `lower_bound(RLE(name) без терминатора
    /// || 0x01)` и проверка байта длины метки.
    ///
    /// # Errors
    ///
    /// `Corrupt` — повреждённое дерево.
    pub fn has_children<P: PageIo + ?Sized>(
        &self,
        io: &P,
        txn: u64,
        name: &NameRle,
    ) -> Result<bool, ZoneFileError> {
        if self.tree.is_empty() {
            return Ok(false);
        }
        let probe = ChildrenProbe::new(name);
        let mut cursor = self.tree.cursor(io, txn);
        if !cursor.seek_by(|key| probe.compare_key(key))? {
            return Ok(false);
        }
        match cursor.key()? {
            Some(key) => probe.matches(&key),
            None => Ok(false),
        }
    }

    /// Состояние имени: `T_NODE`, ENT/APEX, cut (флаги материализованы).
    ///
    /// # Errors
    ///
    /// `Corrupt` — повреждённое дерево.
    pub fn node<P: PageIo + ?Sized>(
        &self,
        io: &P,
        txn: u64,
        name: &NameRle,
    ) -> Result<NodeInfo, ZoneFileError> {
        let flags = self.node_flags(io, txn, name)?;
        let is_apex = name == &self.apex || flags.is_some_and(|flags| flags & RR_FLAG_APEX != 0);
        let has_children = match flags {
            Some(flags) => flags & RR_FLAG_CHILDREN_MAY_EXIST != 0,
            None => self.has_children(io, txn, name)?,
        };
        Ok(NodeInfo {
            name: *name,
            exists: flags.is_some(),
            is_apex,
            is_empty_non_terminal: flags
                .is_some_and(|flags| flags & RR_FLAG_EMPTY_NON_TERMINAL != 0),
            is_zone_cut: flags
                .is_some_and(|flags| flags & (RR_FLAG_DELEGATION | RR_FLAG_SECURE_DELEGATION) != 0),
            has_children,
            flags: flags.unwrap_or(0),
        })
    }

    /// Следующее имя в каноническом порядке после `after` (`None` — первое).
    ///
    /// # Errors
    ///
    /// `Corrupt` — повреждённое дерево.
    pub fn next_name<P: PageIo + ?Sized>(
        &self,
        io: &P,
        txn: u64,
        after: Option<&NameRle>,
    ) -> Result<Option<NameRle>, ZoneFileError> {
        let mut cursor = self.tree.cursor(io, txn);
        let found = match after {
            Some(after) => cursor.seek_by(|key| {
                let owner = key.owner()?;
                name_cmp(owner.as_rle(), after.as_rle())
            })?,
            None => cursor.seek_first()?,
        };
        if !found {
            return Ok(None);
        }
        loop {
            let Some(key) = cursor.key()? else {
                return Ok(None);
            };
            let owner = key.owner()?;
            let greater = match after {
                Some(after) => name_cmp(owner.as_rle(), after.as_rle())? == Ordering::Greater,
                None => true,
            };
            if greater {
                return Ok(Some(owner));
            }
            if !cursor.advance()? {
                return Ok(None);
            }
        }
    }

    /// Предыдущее имя в каноническом порядке до `before` (`None` — последнее).
    ///
    /// Возвращает наибольшее имя строго меньше `before`. Предшественник
    /// ищется спуском по B+tree (O(log n)), без обхода зоны.
    ///
    /// # Errors
    ///
    /// `Corrupt` — повреждённое дерево.
    pub fn prev_name<P: PageIo + ?Sized>(
        &self,
        io: &P,
        txn: u64,
        before: Option<&NameRle>,
    ) -> Result<Option<NameRle>, ZoneFileError> {
        let mut cursor = self.tree.cursor(io, txn);
        let found = match before {
            Some(before) => cursor.seek_prev_by(|key| {
                let owner = key.owner()?;
                name_cmp(owner.as_rle(), before.as_rle())
            })?,
            None => cursor.seek_last()?,
        };
        if !found {
            return Ok(None);
        }
        let Some(key) = cursor.key()? else {
            return Ok(None);
        };
        Ok(Some(key.owner()?))
    }

    /// Обходит владельцев ключей заданного типа в каноническом порядке.
    ///
    /// Читаются только ключи листьев (RDATA/overflow не материализуются).
    ///
    /// # Errors
    ///
    /// `Corrupt` — повреждённое дерево.
    pub fn for_each_owner<P: PageIo + ?Sized>(
        &self,
        io: &P,
        txn: u64,
        rr_type: u16,
        mut visit: impl FnMut(&NameRle),
    ) -> Result<(), ZoneFileError> {
        let mut cursor = self.tree.cursor(io, txn);
        let mut found = cursor.seek_first()?;
        while found {
            if let Some(key) = cursor.key()?
                && key.rr_type() == rr_type
                && let Ok(owner) = key.owner()
            {
                visit(&owner);
            }
            found = cursor.advance()?;
        }
        Ok(())
    }

    fn desired_flags<P: PageIo + ?Sized>(
        &self,
        io: &P,
        txn: u64,
        name: &NameRle,
        is_owner: bool,
        existing: Option<u16>,
    ) -> Result<u16, ZoneFileError> {
        let preserved = existing.unwrap_or(0)
            & (RR_FLAG_DELEGATION
                | RR_FLAG_SECURE_DELEGATION
                | RR_FLAG_GLUE
                | RR_FLAG_OCCLUDED
                | RR_FLAG_NSEC3
                | RR_FLAG_CUT_BELOW);
        let mut flags = preserved;
        if name == &self.apex {
            flags |= RR_FLAG_APEX;
            flags &= !RR_FLAG_EMPTY_NON_TERMINAL;
        } else if is_owner {
            flags &= !RR_FLAG_EMPTY_NON_TERMINAL;
        } else if existing.is_none_or(|flags| flags & RR_FLAG_EMPTY_NON_TERMINAL != 0) {
            // Новый предок без данных — ENT; существующий ENT сохраняется.
            // Существующий владелец RRset (без ENT) ENT не получает
            // (удаления в фазе 2 нет).
            flags |= RR_FLAG_EMPTY_NON_TERMINAL;
        }
        if name.is_wildcard() {
            flags |= RR_FLAG_WILDCARD;
        } else {
            flags &= !RR_FLAG_WILDCARD;
        }
        let has_children = if is_owner {
            self.has_children(io, txn, name)?
        } else {
            // Предок в цепочке всегда имеет как минимум одного потомка.
            true
        };
        if has_children {
            flags |= RR_FLAG_CHILDREN_MAY_EXIST;
        } else {
            flags &= !RR_FLAG_CHILDREN_MAY_EXIST;
        }
        Ok(flags)
    }

    fn materialization_current<P: PageIo + ?Sized>(
        &self,
        io: &P,
        txn: u64,
        name: &NameRle,
    ) -> Result<bool, ZoneFileError> {
        for (index, node_name) in self.ancestor_chain(name)?.iter().enumerate() {
            let existing = self.node_flags(io, txn, node_name)?;
            let desired = self.desired_flags(io, txn, node_name, index == 0, existing)?;
            if existing != Some(desired) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn materialize<P: PageIo + ?Sized>(
        &mut self,
        io: &mut P,
        txn: u64,
        name: &NameRle,
    ) -> Result<(), ZoneFileError> {
        let chain = self.ancestor_chain(name)?;
        for (index, node_name) in chain.iter().enumerate() {
            let existing = self.node_flags(io, txn, node_name)?;
            let desired = self.desired_flags(io, txn, node_name, index == 0, existing)?;
            if existing == Some(desired) {
                continue;
            }
            let key = Key::new(node_name, T_NODE, 0, 0)?;
            self.tree
                .insert_or_replace(io, txn, &LeafItem::new(key, ItemValue::node(desired)))?;
        }
        Ok(())
    }

    /// Гарантирует существование `T_NODE` для имени, включая листовой empty node.
    ///
    /// Обычная ENT-материализация помечает `EMPTY_NON_TERMINAL` только при
    /// наличии потомков; для persistence нужно сохранить и листовой пустой узел
    /// после удаления последнего `RRset`.
    ///
    /// # Errors
    ///
    /// `NameOutsideZone`, `Corrupt`/`Io`.
    pub fn ensure_empty_node<P: PageIo + ?Sized>(
        &mut self,
        io: &mut P,
        txn: u64,
        name: &NameRle,
    ) -> Result<bool, ZoneFileError> {
        let _ = self.ancestor_chain(name)?;
        self.materialize(io, txn, name)?;
        let mut flags = if name == &self.apex {
            RR_FLAG_APEX
        } else {
            RR_FLAG_EMPTY_NON_TERMINAL
        };
        if self.has_children(io, txn, name)? {
            flags |= RR_FLAG_CHILDREN_MAY_EXIST;
        }
        if self.node_flags(io, txn, name)? == Some(flags) {
            return Ok(false);
        }
        let key = Key::new(name, T_NODE, 0, 0)?;
        self.tree
            .insert_or_replace(io, txn, &LeafItem::new(key, ItemValue::node(flags)))?;
        Ok(true)
    }

    /// Upsert `RRset`'а с COW и материализацией `T_NODE`/ENT (§13.3).
    ///
    /// Повторный upsert идентичного набора не пишет страницы:
    /// `UpsertOutcome.changed == false`.
    ///
    /// # Errors
    ///
    /// `WrongAccessor` — `RRSIG` с `subtype = 0`; `InvariantViolation(KeyOrder)` —
    /// имя вне apex или недопустимый тип; `RrsetTooLarge`/`RdataTooLarge` —
    /// лимиты; ошибки [`PageIo`].
    pub fn upsert_rrset<P: PageIo + ?Sized>(
        &mut self,
        io: &mut P,
        txn: u64,
        name: &NameRle,
        rr_type: u16,
        subtype: u16,
        data: &RrsetData,
    ) -> Result<UpsertOutcome, ZoneFileError> {
        if rr_type == T_NODE || rr_type == T_ZONE_ENTRY {
            return Err(invariant(InvariantId::KeyOrder));
        }
        if rr_type == T_RRSIG && subtype == 0 {
            return Err(ZoneFileError::WrongAccessor);
        }
        self.ancestor_chain(name)?;
        let key = Key::new(name, rr_type, CLASS_IN, subtype)?;
        let payload = data.payload()?;
        let expected_kind =
            if payload.len() <= usize::try_from(INLINE_VALUE_MAX).unwrap_or(usize::MAX) {
                ValueKind::Inline
            } else {
                ValueKind::Overflow
            };
        let rr_count = data.rr_count()?;
        let rdlen = data.rdlen()?;
        let expected = LeafValue {
            kind: expected_kind,
            flags: data.flags(),
            rr_count,
            ttl: data.ttl(),
            val_u32: u32::from(expected_kind == ValueKind::Overflow),
            rdlen,
        };
        let mut old_overflow = 0_u32;
        let mut value_matches = false;
        let mut replaced = false;
        if !self.tree.is_empty()
            && let Some(entry) = self.tree.lookup(io, txn, &key)?
        {
            replaced = true;
            value_matches = stored_value_matches(io, txn, &entry.value, &expected, &payload)?;
            if let DecodedValue::Rrset { value, .. } = entry.value
                && value.kind == ValueKind::Overflow
            {
                old_overflow = value.val_u32;
            }
        }
        if value_matches && self.materialization_current(io, txn, name)? {
            return Ok(UpsertOutcome {
                inserted: false,
                replaced,
                changed: false,
            });
        }
        if !value_matches {
            let value = match expected_kind {
                ValueKind::Inline => ItemValue::inline(expected, payload)?,
                ValueKind::Overflow => {
                    let first = overflow::write_chain(io, txn, &payload)?;
                    let value = LeafValue {
                        val_u32: first,
                        ..expected
                    };
                    ItemValue::overflow(value)?
                }
                ValueKind::Node => return Err(invariant(InvariantId::KeyOrder)),
            };
            let outcome = self
                .tree
                .insert_or_replace(io, txn, &LeafItem::new(key, value))?;
            if old_overflow != 0 {
                overflow::free_chain(io, old_overflow)?;
            }
            self.materialize(io, txn, name)?;
            return Ok(UpsertOutcome {
                inserted: outcome.inserted,
                replaced: outcome.old.is_some(),
                changed: true,
            });
        }
        self.materialize(io, txn, name)?;
        Ok(UpsertOutcome {
            inserted: false,
            replaced,
            changed: true,
        })
    }

    /// Число `RRset` имени (без `T_NODE`/`T_ZONE_ENTRY`).
    ///
    /// # Errors
    ///
    /// `Corrupt` — повреждённое дерево.
    pub fn owner_rrset_count<P: PageIo + ?Sized>(
        &self,
        io: &P,
        txn: u64,
        name: &NameRle,
    ) -> Result<u32, ZoneFileError> {
        let keys = self.collect_owner_keys(io, txn, name)?;
        let count = keys
            .iter()
            .filter(|key| key.rr_type() != T_NODE && key.rr_type() != T_ZONE_ENTRY)
            .count();
        u32::try_from(count).map_err(|_| bounds(None, CorruptDetail::OffsetOutOfRange))
    }

    /// Удаляет `RRset` и выполняет `T_NODE`/ENT-каскад (§13.4).
    ///
    /// Возвращает `true`, если ключ существовал. Overflow-цепочка значения
    /// освобождается в текущей транзакции.
    ///
    /// # Errors
    ///
    /// `Corrupt` — повреждённое дерево; ошибки [`PageIo`].
    pub fn delete_rrset<P: PageIo + ?Sized>(
        &mut self,
        io: &mut P,
        txn: u64,
        name: &NameRle,
        rr_type: u16,
        subtype: u16,
    ) -> Result<bool, ZoneFileError> {
        if rr_type == T_NODE || rr_type == T_ZONE_ENTRY {
            return Ok(false);
        }
        self.ancestor_chain(name)?;
        let key = Key::new(name, rr_type, CLASS_IN, subtype)?;
        if self.tree.delete(io, txn, &key)?.is_none() {
            return Ok(false);
        }
        self.after_delete(io, txn, name)?;
        Ok(true)
    }

    /// Удаляет все `RRset` имени (не поддерево) и обновляет `T_NODE`.
    ///
    /// # Errors
    ///
    /// `Corrupt` — повреждённое дерево; ошибки [`PageIo`].
    pub fn delete_name<P: PageIo + ?Sized>(
        &mut self,
        io: &mut P,
        txn: u64,
        name: &NameRle,
    ) -> Result<bool, ZoneFileError> {
        let keys = self.collect_owner_keys(io, txn, name)?;
        if keys.is_empty() {
            return Ok(false);
        }
        let had_records = keys
            .iter()
            .any(|key| key.rr_type() != T_NODE && key.rr_type() != T_ZONE_ENTRY);
        for key in keys {
            let _ = self.tree.delete(io, txn, &key)?;
        }
        self.after_delete(io, txn, name)?;
        Ok(had_records)
    }

    /// Удаляет имя со всем поддеревом (§13.4, каскад cut).
    ///
    /// # Errors
    ///
    /// `InvariantViolation(CutSubtreeTooLarge)` — поддерево больше
    /// [`MAX_CUT_SUBTREE_RECORDS`]; `Corrupt` — повреждённое дерево.
    pub fn delete_subtree<P: PageIo + ?Sized>(
        &mut self,
        io: &mut P,
        txn: u64,
        name: &NameRle,
    ) -> Result<bool, ZoneFileError> {
        let keys = self.collect_subtree_keys(io, txn, name)?;
        if keys.is_empty() {
            return Ok(false);
        }
        for key in keys {
            let _ = self.tree.delete(io, txn, &key)?;
        }
        self.after_delete(io, txn, name)?;
        Ok(true)
    }

    /// Все item'ы дерева (для компакции).
    ///
    /// # Errors
    ///
    /// `Corrupt` — повреждённое дерево.
    pub fn collect_items<P: PageIo + ?Sized>(
        &self,
        io: &P,
        txn: u64,
    ) -> Result<Vec<LeafItem>, ZoneFileError> {
        let mut cursor = self.tree.cursor(io, txn);
        let mut items = Vec::new();
        if !cursor.seek_first()? {
            return Ok(items);
        }
        loop {
            if let Some(item) = cursor.item()? {
                items.push(item);
            }
            if !cursor.advance()? {
                break;
            }
        }
        Ok(items)
    }

    fn collect_owner_keys<P: PageIo + ?Sized>(
        &self,
        io: &P,
        txn: u64,
        name: &NameRle,
    ) -> Result<Vec<Key>, ZoneFileError> {
        let start = Key::new(name, 0, 0, 0)?;
        let mut cursor = self.tree.cursor(io, txn);
        if !cursor.seek(&start)? {
            return Ok(Vec::new());
        }
        let mut keys = Vec::new();
        while let Some(key) = cursor.key()? {
            if key.owner_bytes() != name.as_rle() {
                break;
            }
            keys.push(key);
            if !cursor.advance()? {
                break;
            }
        }
        Ok(keys)
    }

    fn collect_subtree_keys<P: PageIo + ?Sized>(
        &self,
        io: &P,
        txn: u64,
        name: &NameRle,
    ) -> Result<Vec<Key>, ZoneFileError> {
        let start = Key::new(name, 0, 0, 0)?;
        let mut cursor = self.tree.cursor(io, txn);
        if !cursor.seek(&start)? {
            return Ok(Vec::new());
        }
        let mut keys = Vec::new();
        while let Some(key) = cursor.key()? {
            let owner = key.owner()?;
            if owner != *name && !is_descendant(&owner, name) {
                break;
            }
            if keys.len() as u64 >= MAX_CUT_SUBTREE_RECORDS {
                return Err(ZoneFileError::InvariantViolation(
                    InvariantId::CutSubtreeTooLarge,
                ));
            }
            keys.push(key);
            if !cursor.advance()? {
                break;
            }
        }
        Ok(keys)
    }

    fn owner_has_rrset<P: PageIo + ?Sized>(
        &self,
        io: &P,
        txn: u64,
        name: &NameRle,
    ) -> Result<bool, ZoneFileError> {
        let start = Key::new(name, 0, 0, 0)?;
        let mut cursor = self.tree.cursor(io, txn);
        if !cursor.seek(&start)? {
            return Ok(false);
        }
        while let Some(key) = cursor.key()? {
            if key.owner_bytes() != name.as_rle() {
                break;
            }
            if key.rr_type() != T_NODE && key.rr_type() != T_ZONE_ENTRY {
                return Ok(true);
            }
            if !cursor.advance()? {
                break;
            }
        }
        Ok(false)
    }

    fn after_delete<P: PageIo + ?Sized>(
        &mut self,
        io: &mut P,
        txn: u64,
        name: &NameRle,
    ) -> Result<(), ZoneFileError> {
        if self.owner_has_rrset(io, txn, name)? {
            // У имени остались RRset'ы: T_NODE не трогаем, флаги уже корректны.
            return Ok(());
        }
        let is_apex = name == &self.apex;
        let has_children = self.has_children(io, txn, name)?;
        if is_apex || has_children {
            let mut flags = 0_u16;
            if is_apex {
                flags |= RR_FLAG_APEX;
            } else {
                flags |= RR_FLAG_EMPTY_NON_TERMINAL;
            }
            if has_children {
                flags |= RR_FLAG_CHILDREN_MAY_EXIST;
            }
            let key = Key::new(name, T_NODE, 0, 0)?;
            self.tree
                .insert_or_replace(io, txn, &LeafItem::new(key, ItemValue::node(flags)))?;
        } else {
            let key = Key::new(name, T_NODE, 0, 0)?;
            let _ = self.tree.delete(io, txn, &key)?;
        }

        let mut current = name.parent();
        while let Some(parent) = current {
            let has_children = self.has_children(io, txn, &parent)?;
            let has_data = self.owner_has_rrset(io, txn, &parent)?;
            if parent == self.apex {
                let existing = self.node_flags(io, txn, &parent)?;
                let flags = self.desired_flags(io, txn, &parent, has_data, existing)?;
                let key = Key::new(&parent, T_NODE, 0, 0)?;
                self.tree.insert_or_replace(
                    io,
                    txn,
                    &LeafItem::new(key, ItemValue::node(flags)),
                )?;
                break;
            }
            if has_data || has_children {
                let existing = self.node_flags(io, txn, &parent)?;
                let flags = self.desired_flags(io, txn, &parent, has_data, existing)?;
                let key = Key::new(&parent, T_NODE, 0, 0)?;
                self.tree.insert_or_replace(
                    io,
                    txn,
                    &LeafItem::new(key, ItemValue::node(flags)),
                )?;
                break;
            }
            let key = Key::new(&parent, T_NODE, 0, 0)?;
            let _ = self.tree.delete(io, txn, &key)?;
            current = parent.parent();
        }
        Ok(())
    }

    /// Читает overflow-цепочку значения (если значение overflow).
    ///
    /// # Errors
    ///
    /// `Corrupt(BadRdata)` — цепочка повреждена; ошибки [`PageIo`].
    pub fn read_overflow<'a, P: PageIo + ?Sized>(
        &self,
        io: &'a P,
        txn: u64,
        value: &LeafValue,
    ) -> Result<Option<OverflowRrset<'a>>, ZoneFileError> {
        if value.kind != ValueKind::Overflow {
            return Ok(None);
        }
        Ok(Some(OverflowRrset::decode(
            io,
            txn,
            value.val_u32,
            value.rdlen,
            value.rr_count,
        )?))
    }
}

fn stored_value_matches<P: PageIo + ?Sized>(
    io: &P,
    txn: u64,
    stored: &DecodedValue<'_>,
    expected: &LeafValue,
    payload: &[u8],
) -> Result<bool, ZoneFileError> {
    let DecodedValue::Rrset {
        value,
        payload: inline,
    } = stored
    else {
        return Ok(false);
    };
    if value.kind != expected.kind
        || value.flags != expected.flags
        || value.ttl != expected.ttl
        || value.rr_count != expected.rr_count
        || value.rdlen != expected.rdlen
    {
        return Ok(false);
    }
    match value.kind {
        ValueKind::Inline => Ok(*inline == payload),
        ValueKind::Overflow => {
            if value.val_u32 == 0 {
                return Ok(false);
            }
            let chain = OverflowRrset::decode(io, txn, value.val_u32, value.rdlen, value.rr_count)?;
            Ok(chain.stream_matches(payload))
        }
        ValueKind::Node => Ok(false),
    }
}
