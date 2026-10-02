//! Immutable ordered ledger leaves, derived only through the checkpoint reducer.
//! No codec, received-state constructor, pruning or persisted validity authority.
use crate::{Digest, Error, Result};
use std::sync::Arc;

const PAGE_KEYS: usize = 64;

#[derive(Clone)]
pub(super) struct PagedLedgerSet {
    pages: Vec<Arc<[Digest]>>,
    len: usize,
    limit: usize,
}
impl PagedLedgerSet {
    pub(super) const fn new(limit: usize) -> Self {
        Self {
            pages: Vec::new(),
            len: 0,
            limit,
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
        self.pages
            .get(self.page_for(key))
            .is_some_and(|page| page.binary_search(key).is_ok())
    }
    pub(super) fn insert(&mut self, key: Digest) -> Result<bool> {
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
        self.pages.iter().flat_map(|page| page.iter())
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
    use std::collections::BTreeSet;

    fn key(position: u16) -> Digest {
        let mut key = [0; 32];
        key[30..].copy_from_slice(&position.to_be_bytes());
        key
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
