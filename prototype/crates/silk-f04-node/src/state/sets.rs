//! Immutable ordered ledger leaves, derived only through the checkpoint reducer.
//! Auxiliary pages carry no received-state constructor or persisted validity.
use crate::{
    Digest, Error, Result,
    budget::JobBudget,
    store::{ObjectReader, Store},
    wire::{u32le, u64le},
};
use std::sync::Arc;

const PAGE_KEYS: usize = 64;
const HEADER: usize = 52;
#[derive(Clone)]
struct PageRef {
    id: Digest,
    count: usize,
    source_ordinal: usize,
    edited: Option<Arc<[Digest]>>,
}
#[derive(Clone)]
struct Retained {
    pages: Arc<Vec<PageRef>>,
    reader: Arc<ObjectReader>,
    domain: Digest,
    magic: [u8; 8],
}

fn load_leaf(
    retained: &Retained,
    page: &PageRef,
    budget: Option<&JobBudget>,
) -> Result<Arc<[Digest]>> {
    if let Some(budget) = budget {
        budget.check()?;
    }
    if !(1..=PAGE_KEYS).contains(&page.count) {
        return Err(Error::Unavailable("retained ledger set page count"));
    }
    let keys = if let Some(keys) = &page.edited {
        if keys.len() != page.count {
            return Err(Error::Unavailable("edited ledger set page count"));
        }
        keys.clone()
    } else {
        if let Some(budget) = budget {
            budget.source()?;
        }
        let size = HEADER + page.count * 32;
        let bytes = retained.reader.object(page.id, size)?;
        if bytes.len() != size
            || bytes.get(..8) != Some(retained.magic.as_slice())
            || bytes[8..40] != retained.domain
            || u64le(&bytes, 40)? != page.source_ordinal as u64
            || u32le(&bytes, 48)? as usize != page.count
        {
            return Err(Error::Unavailable("retained ledger set page binding"));
        }
        Arc::from(
            bytes[HEADER..]
                .chunks_exact(32)
                .map(|key| {
                    key.try_into()
                        .map_err(|_| Error::Unavailable("retained ledger set key"))
                })
                .collect::<Result<Vec<Digest>>>()?,
        )
    };
    if keys.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(Error::Unavailable("retained ledger set order"));
    }
    Ok(keys)
}

#[derive(Clone)]
pub(super) struct PagedLedgerSet {
    pages: Vec<Arc<[Digest]>>,
    len: usize,
    limit: usize,
    retained: Option<Retained>,
}

// Operation-local merge cursor: one decoded leaf, no validity memoization.
struct DifferenceCursor<'a> {
    set: &'a PagedLedgerSet,
    ordinal: usize,
    page: Vec<Digest>,
    offset: usize,
    seen: usize,
    last: Option<Digest>,
}
impl<'a> DifferenceCursor<'a> {
    fn new(set: &'a PagedLedgerSet) -> Self {
        Self {
            set,
            ordinal: 0,
            page: Vec::new(),
            offset: 0,
            seen: 0,
            last: None,
        }
    }
    fn next(&mut self, budget: Option<&JobBudget>) -> Result<Option<Digest>> {
        let check = || budget.map_or(Ok(()), JobBudget::check);
        check()?;
        if self.set.len > self.set.limit {
            return Err(Error::Unavailable("retained ledger set horizon"));
        }
        if self.offset == self.page.len() {
            self.page.clear();
            self.offset = 0;
            if let Some(retained) = &self.set.retained {
                if let Some(page) = retained.pages.get(self.ordinal) {
                    self.page
                        .extend_from_slice(&load_leaf(retained, page, budget)?);
                }
            } else if let Some(page) = self.set.pages.get(self.ordinal) {
                if !(1..=PAGE_KEYS).contains(&page.len()) {
                    return Err(Error::Unavailable("derived ledger set page count"));
                }
                self.page.extend_from_slice(page);
            }
            if self.page.is_empty() {
                if self.seen != self.set.len {
                    return Err(Error::Unavailable("retained ledger set directory length"));
                }
                return Ok(None);
            }
            self.ordinal += 1;
        }
        let key = self.page[self.offset];
        if self.last.is_some_and(|last| last >= key) {
            return Err(Error::Unavailable("retained ledger set order"));
        }
        self.offset += 1;
        self.seen += 1;
        if self.seen > self.set.len {
            return Err(Error::Unavailable("retained ledger set directory length"));
        }
        self.last = Some(key);
        Ok(Some(key))
    }
}
impl PagedLedgerSet {
    pub(super) const fn new(limit: usize) -> Self {
        Self {
            pages: Vec::new(),
            len: 0,
            limit,
            retained: None,
        }
    }
    pub(super) const fn len(&self) -> usize {
        self.len
    }
    fn page_for(&self, key: &Digest) -> usize {
        self.pages
            .partition_point(|page| page.last().expect("nonempty derived leaf") < key)
    }
    pub(super) fn contains(&self, key: &Digest) -> bool {
        assert!(
            self.retained.is_none(),
            "borrowed membership requires materialized snapshot"
        );
        self.pages
            .get(self.page_for(key))
            .is_some_and(|page| page.binary_search(key).is_ok())
    }
    pub(super) fn insert(&mut self, key: Digest) -> Result<bool> {
        if self.retained.is_some() {
            return self.insert_checked(key, None);
        }
        if self.contains(&key) {
            return Ok(false);
        }
        if self.len >= self.limit {
            return Err(Error::Paused("paged ledger set reference horizon"));
        }
        let ordinal = self.page_for(&key);
        if self.pages.is_empty()
            || ordinal == self.pages.len()
                && self
                    .pages
                    .last()
                    .is_some_and(|page| page.len() == PAGE_KEYS)
        {
            self.pages.push(Arc::from([key]));
        } else {
            let ordinal = ordinal.min(self.pages.len() - 1);
            let page = &self.pages[ordinal];
            let position = page.binary_search(&key).expect_err("absent derived key");
            // Stage replacement leaves before publishing any directory change.
            // A full leaf splits into 32/33 keys; every other leaf stays shared.
            let mut changed = Vec::with_capacity(page.len() + 1);
            changed.extend_from_slice(page);
            changed.insert(position, key);
            if changed.len() > PAGE_KEYS {
                let left = Arc::from(&changed[..PAGE_KEYS / 2]);
                let right = Arc::from(&changed[PAGE_KEYS / 2..]);
                self.pages[ordinal] = left;
                self.pages.insert(ordinal + 1, right);
            } else {
                self.pages[ordinal] = Arc::from(changed);
            }
        }
        self.len += 1;
        Ok(true)
    }
    pub(super) fn iter(&self) -> impl Iterator<Item = &Digest> {
        assert!(
            self.retained.is_none(),
            "borrowed set iteration requires materialized snapshot"
        );
        self.pages.iter().flat_map(|page| page.iter())
    }
    // Membership observations remain provisional until complete reducer hashing.
    fn retained_position(&self, key: &Digest, budget: Option<&JobBudget>) -> Result<usize> {
        let retained = self
            .retained
            .as_ref()
            .ok_or(Error::Unavailable("retained ledger set mutation context"))?;
        let mut low = 0;
        let mut high = retained.pages.len();
        while low < high {
            let mid = low + (high - low) / 2;
            let page = load_leaf(retained, &retained.pages[mid], budget)?;
            if page.last().expect("checked nonempty leaf") < key {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        Ok(low)
    }
    pub(super) fn contains_checked(
        &self,
        key: &Digest,
        budget: Option<&JobBudget>,
    ) -> Result<bool> {
        if let Some(budget) = budget {
            budget.check()?;
        }
        let Some(retained) = &self.retained else {
            return Ok(self.contains(key));
        };
        let ordinal = self.retained_position(key, budget)?;
        let Some(page) = retained.pages.get(ordinal) else {
            return Ok(false);
        };
        Ok(load_leaf(retained, page, budget)?
            .binary_search(key)
            .is_ok())
    }
    pub(super) fn insert_checked(
        &mut self,
        key: Digest,
        budget: Option<&JobBudget>,
    ) -> Result<bool> {
        if let Some(budget) = budget {
            budget.check()?;
        }
        if self.retained.is_none() {
            return self.insert(key);
        }
        let ordinal = self.retained_position(&key, budget)?;
        let retained = self.retained.as_ref().expect("selected retained leaf");
        let length = retained.pages.len();
        let target = ordinal.min(length.saturating_sub(1));
        let old: Arc<[Digest]> = if length == 0 {
            Arc::from([])
        } else {
            load_leaf(retained, &retained.pages[target], budget)?
        };
        if old.binary_search(&key).is_ok() {
            return Ok(false);
        }
        if self.len >= self.limit {
            return Err(Error::Paused("paged ledger set reference horizon"));
        }
        let make = |keys: Arc<[Digest]>| PageRef {
            id: [0; 32],
            count: keys.len(),
            source_ordinal: 0,
            edited: Some(keys),
        };
        let mut staged = Vec::with_capacity(2);
        let append = length == 0 || ordinal == length && old.len() == PAGE_KEYS;
        if append {
            staged.push(make(Arc::from([key])));
        } else {
            let position = old.binary_search(&key).expect_err("absent derived key");
            let mut changed = Vec::with_capacity(old.len() + 1);
            changed.extend_from_slice(&old);
            changed.insert(position, key);
            if changed.len() > PAGE_KEYS {
                staged.push(make(Arc::from(&changed[..PAGE_KEYS / 2])));
                staged.push(make(Arc::from(&changed[PAGE_KEYS / 2..])));
            } else {
                staged.push(make(Arc::from(changed)));
            }
        }
        if let Some(budget) = budget {
            budget.check()?;
        }
        let pages = Arc::make_mut(
            &mut self
                .retained
                .as_mut()
                .expect("selected retained leaf")
                .pages,
        );
        if append {
            pages.extend(staged);
        } else {
            pages.splice(target..target + 1, staged);
        }
        self.len += 1;
        Ok(true)
    }
    /// Private staging visitor: observations are provisional until ALL sorted
    /// pages and the exact directory length pass. Owns one page and one key.
    pub(super) fn visit_encoded(
        &self,
        budget: Option<&JobBudget>,
        visit: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        let check = || budget.map_or(Ok(()), JobBudget::check);
        check()?;
        if self.len > self.limit {
            return Err(Error::Unavailable("retained ledger set horizon"));
        }
        let Some(retained) = &self.retained else {
            for (position, key) in self.iter().enumerate() {
                if position % PAGE_KEYS == 0 {
                    check()?;
                }
                visit(key)?;
            }
            return check();
        };
        let mut seen = 0;
        let mut last: Option<Digest> = None;
        for page in retained.pages.iter() {
            let keys = load_leaf(retained, page, budget)?;
            for key in keys.iter() {
                if last.is_some_and(|last| last >= *key) {
                    return Err(Error::Unavailable("retained ledger set order"));
                }
                last = Some(*key);
                seen += 1;
                if seen > self.len {
                    return Err(Error::Unavailable("retained ledger set directory length"));
                }
                visit(key)?;
            }
        }
        if seen != self.len {
            return Err(Error::Unavailable("retained ledger set directory length"));
        }
        check()
    }
    pub(super) fn materialize(&self, budget: Option<&JobBudget>) -> Result<Self> {
        let Some(retained) = &self.retained else {
            return Ok(self.clone());
        };
        let mut pages = Vec::with_capacity(retained.pages.len());
        let mut len = 0;
        let mut last = None;
        for page in retained.pages.iter() {
            let keys = load_leaf(retained, page, budget)?;
            if last.is_some_and(|last| last >= keys[0]) {
                return Err(Error::Unavailable("retained ledger set order"));
            }
            last = keys.last().copied();
            len += keys.len();
            if len > self.limit {
                return Err(Error::Unavailable("retained ledger set horizon"));
            }
            pages.push(keys);
        }
        if len != self.len {
            return Err(Error::Unavailable("retained ledger set directory length"));
        }
        if let Some(budget) = budget {
            budget.check()?;
        }
        Ok(Self {
            pages,
            len,
            limit: self.limit,
            retained: None,
        })
    }
    /// Sorted difference for private delta staging. BOTH streams must finish,
    /// including a previous suffix beyond the largest current key.
    pub(super) fn difference_visit(
        &self,
        prior: &Self,
        budget: Option<&JobBudget>,
        visit: &mut dyn FnMut(&Digest) -> Result<()>,
    ) -> Result<()> {
        let mut current = DifferenceCursor::new(self);
        let mut previous = DifferenceCursor::new(prior);
        let mut old = previous.next(budget)?;
        while let Some(key) = current.next(budget)? {
            while old.is_some_and(|old| old < key) {
                old = previous.next(budget)?;
            }
            if old != Some(key) {
                visit(&key)?;
            }
        }
        while old.is_some() {
            old = previous.next(budget)?;
        }
        budget.map_or(Ok(()), JobBudget::check)
    }
    pub(super) fn retain(
        &self,
        store: &mut Store,
        domain: Digest,
        magic: [u8; 8],
        budget: &JobBudget,
    ) -> Result<Self> {
        if let Some(retained) = &self.retained {
            if retained.domain != domain || retained.magic != magic {
                return Err(Error::Unavailable("retained ledger set context"));
            }
            if retained
                .pages
                .iter()
                .enumerate()
                .all(|(ordinal, page)| page.edited.is_none() && page.source_ordinal == ordinal)
            {
                return Ok(self.clone());
            }
        }
        if ![b"SNF04NP1", b"SNF04EP1"].contains(&&magic) {
            return Err(Error::Unavailable("retained ledger set kind"));
        }
        let length = self
            .retained
            .as_ref()
            .map_or(self.pages.len(), |rows| rows.pages.len());
        let mut pages = Vec::with_capacity(length);
        let mut seen = 0;
        let mut last: Option<Digest> = None;
        for ordinal in 0..length {
            budget.check()?;
            let page = if let Some(retained) = &self.retained {
                load_leaf(retained, &retained.pages[ordinal], Some(budget))?
            } else {
                self.pages[ordinal].clone()
            };
            if !(1..=PAGE_KEYS).contains(&page.len())
                || page.windows(2).any(|pair| pair[0] >= pair[1])
                || last.is_some_and(|last| last >= page[0])
            {
                return Err(Error::Unavailable("derived ledger set order/count"));
            }
            last = page.last().copied();
            seen += page.len();
            if seen > self.len || seen > self.limit {
                return Err(Error::Unavailable("retained ledger set horizon"));
            }
            let mut bytes = Vec::with_capacity(HEADER + page.len() * 32);
            bytes.extend_from_slice(&magic);
            bytes.extend_from_slice(&domain);
            bytes.extend_from_slice(&(ordinal as u64).to_le_bytes());
            bytes.extend_from_slice(&(page.len() as u32).to_le_bytes());
            for key in page.iter() {
                bytes.extend_from_slice(key);
            }
            budget.source()?;
            pages.push(PageRef {
                id: store.retain_ledger_set_page(&bytes)?,
                count: page.len(),
                source_ordinal: ordinal,
                edited: None,
            });
        }
        if seen != self.len {
            return Err(Error::Unavailable("retained ledger set directory length"));
        }
        budget.check()?;
        Ok(Self {
            pages: Vec::new(),
            len: self.len,
            limit: self.limit,
            retained: Some(Retained {
                pages: Arc::new(pages),
                reader: store.object_reader()?,
                domain,
                magic,
            }),
        })
    }
    #[cfg(test)]
    pub(super) fn retained_ids(&self) -> Vec<Digest> {
        self.retained.as_ref().map_or_else(Vec::new, |retained| {
            retained
                .pages
                .iter()
                .filter(|page| page.edited.is_none())
                .map(|page| page.id)
                .collect()
        })
    }
    #[cfg(test)]
    pub(super) fn staged_keys(&self) -> usize {
        self.retained.as_ref().map_or(self.len, |rows| {
            rows.pages
                .iter()
                .filter(|page| page.edited.is_some())
                .map(|page| page.count)
                .sum()
        })
    }
    #[cfg(test)]
    pub(super) fn has_retained_prefix(&self) -> bool {
        self.retained.is_some()
    }
    pub(super) fn difference<'a>(&'a self, other: &'a Self) -> impl Iterator<Item = &'a Digest> {
        let mut left = self.iter();
        let mut right = other.iter().peekable();
        // Linear ordered merge, not one membership lookup per historical key.
        std::iter::from_fn(move || {
            loop {
                let key = left.next()?;
                while right.peek().is_some_and(|candidate| *candidate < key) {
                    right.next();
                }
                if right.peek().is_none_or(|candidate| *candidate != key) {
                    return Some(key);
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retained_leaf_edits_match_literal_split_geometry_and_preserve_forks() {
        let (temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        store.begin_replay(b"synthetic staged leaf edits").unwrap();
        let mut literal = PagedLedgerSet::new(512);
        for index in 0..129 {
            literal.insert(key(index * 2)).unwrap();
        }
        let base = literal
            .retain(&mut store, [19; 32], *b"SNF04NP1", &budget)
            .unwrap();
        let mut staged = base.clone();
        for index in [1, 3, 63, 65, 127, 129, 191, 255, 259, 300, 301, 302] {
            assert_eq!(
                staged.insert_checked(key(index), Some(&budget)).unwrap(),
                literal.insert(key(index)).unwrap()
            );
            assert!(staged.contains_checked(&key(index), Some(&budget)).unwrap());
        }
        assert!(staged.pages.is_empty());
        assert_eq!(base.len(), 129);
        assert!(!staged.insert_checked(key(63), Some(&budget)).unwrap());
        assert!(
            staged
                .materialize(Some(&budget))
                .unwrap()
                .iter()
                .eq(literal.iter())
        );
        let stored = staged
            .retain(&mut store, [19; 32], *b"SNF04NP1", &budget)
            .unwrap();
        assert_eq!(
            stored.retained_ids(),
            literal
                .retain(&mut store, [19; 32], *b"SNF04NP1", &budget)
                .unwrap()
                .retained_ids()
        );
        let mut fork = base.clone();
        fork.insert_checked(key(311), Some(&budget)).unwrap();
        assert!(!staged.contains_checked(&key(311), Some(&budget)).unwrap());
        let path = temp
            .path()
            .join("store")
            .join(format!("{}.obj", hex::encode(base.retained_ids()[0])));
        let held = path.with_extension("held");
        std::fs::rename(&path, &held).unwrap();
        assert!(base.contains_checked(&key(0), Some(&budget)).is_err());
        assert!(base.clone().insert_checked(key(1), Some(&budget)).is_err());
        assert!(fork.materialize(Some(&budget)).is_err());
        std::fs::rename(&held, &path).unwrap();
        let expired = JobBudget::testing(std::time::Duration::ZERO).unwrap();
        assert!(
            base.clone()
                .insert_checked(key(17), Some(&expired))
                .is_err()
        );
        assert_eq!(base.len(), 129);
        assert_eq!(store.head(), None);
    }
    #[test]
    fn streamed_difference_drains_previous_suffix_and_refuses_bad_bindings() {
        let (temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        store.begin_replay(b"synthetic merge cursor").unwrap();
        let previous = fixture(129)
            .retain(&mut store, [19; 32], *b"SNF04NP1", &budget)
            .unwrap();
        let mut current = PagedLedgerSet::new(256);
        current.insert(key(0)).unwrap();
        current.insert(key(200)).unwrap();
        let stored = current
            .retain(&mut store, [19; 32], *b"SNF04NP1", &budget)
            .unwrap();
        let mut added = Vec::new();
        stored
            .difference_visit(&previous, Some(&budget), &mut |key| {
                added.push(*key);
                Ok(())
            })
            .unwrap();
        assert_eq!(added, [key(200)]);
        // No current rows: the entire previous stream must still qualify.
        let empty = PagedLedgerSet::new(256);
        let path = temp.path().join("store").join(format!(
            "{}.obj",
            hex::encode(previous.retained_ids().last().unwrap())
        ));
        let held = path.with_extension("held");
        std::fs::rename(&path, &held).unwrap();
        assert!(
            empty
                .difference_visit(&previous, Some(&budget), &mut |_| Ok(()))
                .is_err()
        );
        std::fs::rename(&held, &path).unwrap();
        empty
            .difference_visit(&previous, Some(&budget), &mut |_| {
                panic!("empty difference")
            })
            .unwrap();
        for kind in 0..4 {
            let mut wrong = previous.clone();
            match kind {
                0 => wrong.retained.as_mut().unwrap().domain = [20; 32],
                1 => wrong.retained.as_mut().unwrap().magic = *b"SNF04EP1",
                2 => Arc::make_mut(&mut wrong.retained.as_mut().unwrap().pages).swap(0, 1),
                _ => wrong.len -= 1,
            }
            assert!(
                empty
                    .difference_visit(&wrong, Some(&budget), &mut |_| Ok(()))
                    .is_err()
            );
        }
        let mut wrong = fixture(129);
        wrong.pages.swap(0, 1);
        assert!(
            empty
                .difference_visit(&wrong, Some(&budget), &mut |_| Ok(()))
                .is_err()
        );
        assert_eq!(store.head(), None);
    }
    use std::collections::BTreeSet;

    fn key(position: u16) -> Digest {
        let mut key = [0; 32];
        key[30..].copy_from_slice(&position.to_be_bytes());
        key
    }
    fn fixture(count: u16) -> PagedLedgerSet {
        // Synthetic storage keys only, not accepted transactions or spentness.
        let mut set = PagedLedgerSet::new(256);
        for position in 0..count {
            set.insert(key(position)).unwrap();
        }
        set
    }
    #[test]
    fn disk_sets_detach_keys_preserve_sorted_membership_and_held_directory() {
        let (_temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        store.begin_replay(b"synthetic ordered set pages").unwrap();
        let set = fixture(129);
        let weak = Arc::downgrade(&set.pages[1]);
        let expected = set.iter().copied().collect::<Vec<_>>();
        let retained = set
            .retain(&mut store, [19; 32], *b"SNF04NP1", &budget)
            .unwrap();
        assert_eq!(retained.retained_ids().len(), 3);
        assert!(retained.pages.is_empty());
        assert_eq!(store.head(), None);
        drop(set);
        assert!(weak.upgrade().is_none());
        drop(store);
        let restored = retained.materialize(Some(&budget)).unwrap();
        assert_eq!(restored.iter().copied().collect::<Vec<_>>(), expected);
        for i in 0..130 {
            assert_eq!(restored.contains(&key(i)), i < 129);
        }
        let mut fork = restored.clone();
        assert!(!fork.insert(key(64)).unwrap());
        fork.insert(key(129)).unwrap();
        assert_eq!(restored.len(), 129);
        assert_eq!(
            fork.difference(&restored).copied().collect::<Vec<_>>(),
            vec![key(129)]
        );
    }
    #[test]
    fn disk_sets_missing_tampered_or_hardlinked_page_refuses_all_or_nothing() {
        let (temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        store
            .begin_replay(b"synthetic ordered set refusal")
            .unwrap();
        let set = fixture(129);
        let retained = set
            .retain(&mut store, [19; 32], *b"SNF04NP1", &budget)
            .unwrap();
        let ids = retained.retained_ids();
        let path = temp
            .path()
            .join("store")
            .join(format!("{}.obj", hex::encode(ids[2])));
        let held = path.with_extension("held");
        let bytes = std::fs::read(&path).unwrap();
        std::fs::rename(&path, &held).unwrap();
        assert!(matches!(
            retained.materialize(Some(&budget)),
            Err(Error::Io(_))
        ));
        assert_eq!(retained.retained_ids(), ids);
        assert!(retained.pages.is_empty());
        assert_eq!(retained.len(), 129);
        std::fs::rename(&held, &path).unwrap();
        let mut changed = bytes.clone();
        *changed.last_mut().unwrap() ^= 1;
        std::fs::write(&path, changed).unwrap();
        assert!(retained.materialize(Some(&budget)).is_err());
        std::fs::write(&path, bytes).unwrap();
        std::fs::hard_link(&path, &held).unwrap();
        assert!(retained.materialize(Some(&budget)).is_err());
        std::fs::remove_file(&held).unwrap();
        assert_eq!(
            retained
                .materialize(Some(&budget))
                .unwrap()
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            set.iter().copied().collect::<Vec<_>>()
        );
        assert_eq!(store.head(), None);
    }
    #[test]
    fn disk_sets_forks_deduplicate_exact_pages_and_separate_kind_and_domain() {
        let (_temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        store.begin_replay(b"synthetic ordered set forks").unwrap();
        let base = fixture(129)
            .retain(&mut store, [19; 32], *b"SNF04NP1", &budget)
            .unwrap();
        let mut left = base.materialize(Some(&budget)).unwrap();
        let mut right = left.clone();
        left.insert(key(129)).unwrap();
        right.insert(key(130)).unwrap();
        let left = left
            .retain(&mut store, [19; 32], *b"SNF04NP1", &budget)
            .unwrap();
        let right = right
            .retain(&mut store, [19; 32], *b"SNF04NP1", &budget)
            .unwrap();
        assert_eq!(&base.retained_ids()[..2], &left.retained_ids()[..2]);
        assert_eq!(&base.retained_ids()[..2], &right.retained_ids()[..2]);
        assert_ne!(left.retained_ids()[2], right.retained_ids()[2]);
        let accounted = store.accounted_bytes();
        let resident = base.materialize(Some(&budget)).unwrap();
        assert_eq!(
            resident
                .retain(&mut store, [19; 32], *b"SNF04NP1", &budget)
                .unwrap()
                .retained_ids(),
            base.retained_ids()
        );
        assert_eq!(store.accounted_bytes(), accounted);
        assert!(
            base.retain(&mut store, [20; 32], *b"SNF04NP1", &budget)
                .is_err()
        );
        assert!(
            base.retain(&mut store, [19; 32], *b"SNF04EP1", &budget)
                .is_err()
        );
        assert_eq!(store.accounted_bytes(), accounted);
        let effects = resident
            .retain(&mut store, [19; 32], *b"SNF04EP1", &budget)
            .unwrap();
        assert_ne!(base.retained_ids(), effects.retained_ids());
        let mut wrong = base.clone();
        wrong.retained.as_mut().unwrap().domain = [20; 32];
        assert!(wrong.materialize(Some(&budget)).is_err());
        let mut wrong = base.clone();
        wrong.retained.as_mut().unwrap().magic = *b"SNF04EP1";
        assert!(wrong.materialize(Some(&budget)).is_err());
        assert_eq!(store.head(), None);
    }
    #[test]
    fn disk_sets_unfenced_or_uncertain_write_stops_without_state_or_head_credit() {
        use std::os::unix::fs::PermissionsExt;
        let (temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        let set = fixture(1);
        let accounted = store.accounted_bytes();
        assert!(
            set.retain(&mut store, [19; 32], *b"SNF04NP1", &budget)
                .is_err()
        );
        assert_eq!(store.accounted_bytes(), accounted);
        store
            .begin_replay(b"synthetic ordered set write refusal")
            .unwrap();
        let root = temp.path().join("store");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o500)).unwrap();
        assert!(matches!(
            set.retain(&mut store, [19; 32], *b"SNF04NP1", &budget),
            Err(Error::Unavailable(
                "retained ledger set page publication failed"
            ))
        ));
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            store.check_external_write(1),
            Err(Error::Unavailable(
                "store requires reopen after failed write"
            ))
        ));
        assert_eq!(store.head(), None);
        assert_eq!(set.len(), 1);
        assert!(set.retained_ids().is_empty());
    }
    fn assert_exact(set: &PagedLedgerSet, expected: &BTreeSet<Digest>) {
        assert_eq!(set.len(), expected.len());
        assert_eq!(
            set.iter().collect::<Vec<_>>(),
            expected.iter().collect::<Vec<_>>()
        );
        assert!(
            set.pages
                .iter()
                .all(|page| !page.is_empty() && page.len() <= PAGE_KEYS)
        );
        assert!(
            set.pages
                .iter()
                .take(set.pages.len().saturating_sub(1))
                .all(|page| page.len() >= PAGE_KEYS / 2)
        );
        assert!(set.pages.len() <= set.len().div_ceil(PAGE_KEYS / 2));
    }

    #[test]
    fn paged_ledger_set_unordered_insert_duplicate_and_membership_match_btree() {
        let mut set = PagedLedgerSet::new(193);
        let mut expected = BTreeSet::new();
        for i in 0..193_u16 {
            let key = key((i * 37) % 193);
            assert_eq!(set.insert(key).unwrap(), expected.insert(key));
            assert!(!set.insert(key).unwrap());
            assert_exact(&set, &expected);
        }
        for i in 0..195 {
            assert_eq!(set.contains(&key(i)), expected.contains(&key(i)));
        }
    }

    #[test]
    fn paged_ledger_set_difference_preserves_exact_sorted_delta_order() {
        let mut left = PagedLedgerSet::new(193);
        let mut right = PagedLedgerSet::new(193);
        let mut left_expected = BTreeSet::new();
        let mut right_expected = BTreeSet::new();
        for i in (0..193_u16).rev() {
            if i % 2 == 0 {
                left.insert(key(i)).unwrap();
                left_expected.insert(key(i));
            }
            if i % 3 == 0 {
                right.insert(key(i)).unwrap();
                right_expected.insert(key(i));
            }
        }
        assert_eq!(
            left.difference(&right).collect::<Vec<_>>(),
            left_expected
                .difference(&right_expected)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            right.difference(&left).collect::<Vec<_>>(),
            right_expected
                .difference(&left_expected)
                .collect::<Vec<_>>()
        );
        assert_eq!(left.difference(&left).count(), 0);
        assert_eq!(left.difference(&PagedLedgerSet::new(0)).count(), left.len());
    }

    #[test]
    fn paged_ledger_set_forks_share_unchanged_leaves_and_rollback_exactly() {
        let mut base = PagedLedgerSet::new(256);
        let mut expected = BTreeSet::new();
        for i in 0..128_u16 {
            base.insert(key(i * 2)).unwrap();
            expected.insert(key(i * 2));
        }
        let mut append = base.clone();
        append.insert(key(256)).unwrap();
        assert!(Arc::ptr_eq(&base.pages[0], &append.pages[0]));
        assert!(Arc::ptr_eq(&base.pages[1], &append.pages[1]));
        let mut fork = base.clone();
        fork.insert(key(31)).unwrap();
        assert_eq!(fork.pages.len(), 3);
        assert!(Arc::ptr_eq(&base.pages[1], &fork.pages[2]));
        assert!(!base.contains(&key(31)));
        assert!(!append.contains(&key(31)));
        assert!(!fork.contains(&key(256)));
        assert_exact(&base, &expected);
        let restored = base.clone();
        assert_exact(&restored, &expected);
        assert!(Arc::ptr_eq(&base.pages[0], &restored.pages[0]));
    }

    #[test]
    fn paged_ledger_set_capacity_stop_precedes_mutation_and_allows_duplicates() {
        let mut set = PagedLedgerSet::new(65);
        for i in 0..65 {
            set.insert(key(i)).unwrap();
        }
        let before = set.iter().copied().collect::<Vec<_>>();
        let pages = set.pages.clone();
        assert!(matches!(
            set.insert(key(66)),
            Err(Error::Paused("paged ledger set reference horizon"))
        ));
        assert!(!set.insert(key(64)).unwrap());
        assert_eq!(set.iter().copied().collect::<Vec<_>>(), before);
        assert!(set.pages.iter().zip(&pages).all(|(a, b)| Arc::ptr_eq(a, b)));
        assert!(PagedLedgerSet::new(0).insert(key(0)).is_err());
    }
}
