//! Receiver-derived append-only sequence; no received-state or persisted codec.
//! Full leaves are immutable/shared; only the incomplete tail is copied on fork.
use crate::{Error, Result};
use std::sync::{Arc, OnceLock};

const PAGE_ITEMS: usize = 64;

struct Page<T> {
    items: Vec<T>,
}
impl<T: Clone> Clone for Page<T> {
    fn clone(&self) -> Self {
        let mut items = Vec::with_capacity(PAGE_ITEMS);
        items.extend(self.items.iter().cloned());
        Self { items }
    }
}
pub(super) struct PagedSequence<T> {
    pages: Vec<Arc<Page<T>>>,
    len: usize,
    limit: usize,
    // Compatibility ONLY. Core hashing/reconciliation never requests this view.
    materialized: OnceLock<Vec<T>>,
}
impl<T: Clone> Clone for PagedSequence<T> {
    fn clone(&self) -> Self {
        Self {
            pages: self.pages.clone(),
            len: self.len,
            limit: self.limit,
            materialized: OnceLock::new(),
        }
    }
}
impl<T: Clone> PagedSequence<T> {
    pub(super) const fn new(limit: usize) -> Self {
        Self {
            pages: Vec::new(),
            len: 0,
            limit,
            materialized: OnceLock::new(),
        }
    }
    pub(super) const fn len(&self) -> usize {
        self.len
    }
    pub(super) const fn limit(&self) -> usize {
        self.limit
    }
    pub(super) fn get(&self, index: usize) -> Option<&T> {
        self.pages
            .get(index / PAGE_ITEMS)?
            .items
            .get(index % PAGE_ITEMS)
    }
    pub(super) fn last(&self) -> Option<&T> {
        self.pages.last()?.items.last()
    }
    pub(super) fn push(&mut self, value: T) -> Result<()> {
        if self.len >= self.limit {
            return Err(Error::Paused("paged ledger sequence reference horizon"));
        }
        if self
            .pages
            .last()
            .is_none_or(|page| page.items.len() == PAGE_ITEMS)
        {
            self.pages.push(Arc::new(Page {
                items: Vec::with_capacity(PAGE_ITEMS),
            }));
        }
        let page = self.pages.last_mut().expect("derived sequence tail");
        Arc::make_mut(page).items.push(value);
        self.len += 1;
        self.materialized.take();
        Ok(())
    }
    pub(super) fn iter(&self) -> impl Iterator<Item = &T> {
        self.pages.iter().flat_map(|page| page.items.iter())
    }
    pub(super) fn iter_from(&self, start: usize) -> Result<impl Iterator<Item = &T>> {
        if start > self.len {
            return Err(Error::Unavailable("ledger sequence suffix bounds"));
        }
        Ok(self
            .pages
            .iter()
            .skip(start / PAGE_ITEMS)
            .flat_map(|page| page.items.iter())
            .skip(start % PAGE_ITEMS))
    }
    pub(super) fn as_slice(&self) -> &[T] {
        self.materialized
            .get_or_init(|| {
                let mut flat = Vec::with_capacity(self.len);
                flat.extend(self.iter().cloned());
                flat
            })
            .as_slice()
    }
    pub(super) fn starts_with(&self, prior: &Self) -> bool
    where
        T: PartialEq,
    {
        self.len >= prior.len && self.iter().zip(prior.iter()).all(|(a, b)| a == b)
    }
    // Charge every leaf at full capacity, reference/directory/allocator slack,
    // AND the complete compatibility view even if never requested. Sharing can
    // only reduce actual use; cloning never clones the materialized view.
    pub(super) const fn cache_charge(&self) -> usize {
        self.pages.len() * (PAGE_ITEMS * std::mem::size_of::<T>() + 128)
            + self.len * std::mem::size_of::<T>()
    }
    #[cfg(test)]
    pub(super) fn is_materialized(&self) -> bool {
        self.materialized.get().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paged_recovery_history_indexed_reads_and_last_never_flatten() {
        let mut sequence = PagedSequence::new(130);
        assert!(sequence.get(0).is_none());
        assert!(sequence.last().is_none());
        let expected = (0..130_u16).map(Arc::new).collect::<Vec<_>>();
        for value in &expected {
            sequence.push(value.clone()).unwrap();
        }
        for position in [0, 1, 63, 64, 65, 127, 128, 129] {
            assert!(Arc::ptr_eq(
                sequence.get(position).unwrap(),
                &expected[position]
            ));
        }
        assert!(sequence.get(130).is_none());
        assert!(sequence.get(usize::MAX).is_none());
        assert!(Arc::ptr_eq(sequence.last().unwrap(), &expected[129]));
        assert!(!sequence.is_materialized());
        let cloned = sequence.clone();
        assert!(Arc::ptr_eq(&sequence.pages[0], &cloned.pages[0]));
        assert!(Arc::ptr_eq(&sequence.pages[1], &cloned.pages[1]));
        assert!(!cloned.is_materialized());
    }

    #[test]
    fn paged_ledger_sequence_order_suffix_and_compatibility_match_vec() {
        let mut sequence = PagedSequence::new(130);
        let mut expected = Vec::new();
        for value in 0..130_u64 {
            sequence.push(value).unwrap();
            expected.push(value);
        }
        assert_eq!(sequence.iter().copied().collect::<Vec<_>>(), expected);
        for start in [0, 1, 63, 64, 65, 127, 128, 130] {
            assert_eq!(
                sequence
                    .iter_from(start)
                    .unwrap()
                    .copied()
                    .collect::<Vec<_>>(),
                expected[start..]
            );
        }
        assert!(sequence.iter_from(131).is_err());
        assert!(sequence.iter_from(usize::MAX).is_err());
        assert!(sequence.materialized.get().is_none());
        assert_eq!(sequence.as_slice(), expected);
        let first = sequence.as_slice().as_ptr();
        assert_eq!(sequence.as_slice().as_ptr(), first);
        assert_eq!(sequence.cache_charge(), 3 * (64 * 8 + 128) + 130 * 8);
    }

    #[test]
    fn paged_ledger_sequence_fork_copies_only_tail_and_not_compatibility_view() {
        let mut base = PagedSequence::new(256);
        for value in 0..65_u64 {
            base.push(value).unwrap();
        }
        let original = base.as_slice().to_vec();
        let mut fork = base.clone();
        assert!(fork.materialized.get().is_none());
        fork.push(999).unwrap();
        assert!(Arc::ptr_eq(&base.pages[0], &fork.pages[0]));
        assert!(!Arc::ptr_eq(&base.pages[1], &fork.pages[1]));
        assert_eq!(base.as_slice(), original);
        assert!(fork.starts_with(&base));
        assert!(!base.starts_with(&fork));
        assert_eq!(fork.as_slice().last(), Some(&999));
        fork.push(1000).unwrap();
        assert!(fork.materialized.get().is_none());
        assert_eq!(fork.as_slice().last(), Some(&1000));
        let restored = base.clone();
        assert_eq!(restored.as_slice(), original);
        assert!(Arc::ptr_eq(&base.pages[0], &restored.pages[0]));
    }

    #[test]
    fn paged_ledger_sequence_capacity_stop_preserves_all_pages_and_flat_view() {
        let mut sequence = PagedSequence::new(64);
        for value in 0..64_u64 {
            sequence.push(value).unwrap();
        }
        let view = sequence.as_slice().as_ptr();
        let page = sequence.pages[0].clone();
        assert!(matches!(
            sequence.push(64),
            Err(Error::Paused("paged ledger sequence reference horizon"))
        ));
        assert_eq!(sequence.len(), 64);
        assert_eq!(sequence.as_slice().as_ptr(), view);
        assert!(Arc::ptr_eq(&page, &sequence.pages[0]));
        assert!(PagedSequence::new(0).push(0_u64).is_err());
    }
}
