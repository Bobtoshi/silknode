//! Receiver-derived ancestry only; no codec, disk cache or validity constructor.
//! Immutable 512-position leaves are shared across descendants and graph clones.
//! Changing a bit copies at most one 64-byte leaf, not the whole strict past.
use crate::sync::HISTORY_LIMIT_V1;
use silk_order::sg0_v1::Sg0Error;
use std::sync::Arc;

const WORDS_PER_PAGE: usize = 8;
const POSITIONS_PER_PAGE: usize = WORDS_PER_PAGE * 64;
const PAGES: usize = 8;
// Deliberately preserve the reference horizon. Raising it requires a separate
// graph/order/ledger/sync resource design, not silently widening this directory.
const _: () = assert!(PAGES * POSITIONS_PER_PAGE == HISTORY_LIMIT_V1);

#[derive(Clone, Default)]
pub(super) struct PagedAncestry {
    pages: [Option<Arc<[u64; WORDS_PER_PAGE]>>; PAGES],
}
impl PagedAncestry {
    pub(super) fn contains(&self, position: usize) -> Result<bool, Sg0Error> {
        let page = self
            .pages
            .get(position / POSITIONS_PER_PAGE)
            .ok_or(Sg0Error::Invariant)?;
        Ok(page.as_ref().is_some_and(|words| {
            words[position / 64 % WORDS_PER_PAGE] & (1_u64 << (position % 64)) != 0
        }))
    }

    pub(super) fn insert(&mut self, position: usize) -> Result<(), Sg0Error> {
        let page = self
            .pages
            .get_mut(position / POSITIONS_PER_PAGE)
            .ok_or(Sg0Error::Invariant)?;
        let word = position / 64 % WORDS_PER_PAGE;
        let bit = 1_u64 << (position % 64);
        if page.as_ref().is_some_and(|words| words[word] & bit != 0) {
            return Ok(());
        }
        let page = page.get_or_insert_with(|| Arc::new([0; WORDS_PER_PAGE]));
        Arc::make_mut(page)[word] |= bit;
        Ok(())
    }

    pub(super) fn union(&mut self, other: &Self) {
        for (target, source) in self.pages.iter_mut().zip(&other.pages) {
            let Some(source) = source else { continue };
            let Some(target) = target else {
                *target = Some(source.clone());
                continue;
            };
            // Identical or already included leaves need no copy. This also
            // keeps saturated prefix leaves shared when branches merge.
            if Arc::ptr_eq(target, source)
                || source.iter().zip(target.iter()).all(|(s, t)| s & !t == 0)
            {
                continue;
            }
            for (target, source) in Arc::make_mut(target).iter_mut().zip(source.iter()) {
                *target |= source;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_flat(bits: &PagedAncestry, flat: &[u64; 64]) {
        for position in 0..HISTORY_LIMIT_V1 {
            assert_eq!(
                bits.contains(position).unwrap(),
                flat[position / 64] & (1_u64 << (position % 64)) != 0
            );
        }
    }

    #[test]
    fn paged_ancestry_word_page_and_horizon_boundaries_match_flat_bits() {
        let mut bits = PagedAncestry::default();
        let mut flat = [0; 64];
        for position in [0, 63, 64, 511, 512, 1023, 1024, 4095] {
            bits.insert(position).unwrap();
            flat[position / 64] |= 1_u64 << (position % 64);
            assert_flat(&bits, &flat);
        }
    }

    #[test]
    fn paged_ancestry_fork_union_is_exact_and_does_not_mutate_sources() {
        let mut left = PagedAncestry::default();
        let mut right = PagedAncestry::default();
        let mut left_flat = [0; 64];
        let mut right_flat = [0; 64];
        for position in [0, 63, 64, 512, 1023] {
            left.insert(position).unwrap();
            left_flat[position / 64] |= 1_u64 << (position % 64);
        }
        for position in [1, 64, 511, 512, 1024, 4095] {
            right.insert(position).unwrap();
            right_flat[position / 64] |= 1_u64 << (position % 64);
        }
        let mut merged = left.clone();
        merged.union(&right);
        let flat = std::array::from_fn(|i| left_flat[i] | right_flat[i]);
        assert_flat(&merged, &flat);
        assert_flat(&left, &left_flat);
        assert_flat(&right, &right_flat);
        let mut reversed = right.clone();
        reversed.union(&left);
        assert_flat(&reversed, &flat);
    }

    #[test]
    fn paged_ancestry_shares_prefix_and_copies_only_changed_leaf() {
        let mut prefix = PagedAncestry::default();
        for position in 0..POSITIONS_PER_PAGE {
            prefix.insert(position).unwrap();
        }
        let mut child = prefix.clone();
        child.insert(POSITIONS_PER_PAGE).unwrap();
        assert!(Arc::ptr_eq(
            prefix.pages[0].as_ref().unwrap(),
            child.pages[0].as_ref().unwrap()
        ));
        assert!(prefix.pages[1].is_none());
        let mut fork = child.clone();
        fork.insert(POSITIONS_PER_PAGE + 1).unwrap();
        assert!(Arc::ptr_eq(
            child.pages[0].as_ref().unwrap(),
            fork.pages[0].as_ref().unwrap()
        ));
        assert!(!Arc::ptr_eq(
            child.pages[1].as_ref().unwrap(),
            fork.pages[1].as_ref().unwrap()
        ));
        assert!(!child.contains(POSITIONS_PER_PAGE + 1).unwrap());
        let before = fork.pages[1].as_ref().unwrap().clone();
        fork.insert(POSITIONS_PER_PAGE + 1).unwrap();
        fork.union(&child);
        assert!(Arc::ptr_eq(&before, fork.pages[1].as_ref().unwrap()));
        assert_eq!(
            std::mem::size_of::<PagedAncestry>(),
            PAGES * std::mem::size_of::<usize>()
        );
        assert_eq!(std::mem::size_of::<[u64; WORDS_PER_PAGE]>(), 64);
    }

    #[test]
    fn paged_ancestry_outside_horizon_refuses_without_mutation() {
        let mut bits = PagedAncestry::default();
        bits.insert(4095).unwrap();
        let retained = bits.pages[7].as_ref().unwrap().clone();
        for position in [HISTORY_LIMIT_V1, usize::MAX] {
            assert_eq!(bits.contains(position), Err(Sg0Error::Invariant));
            assert_eq!(bits.insert(position), Err(Sg0Error::Invariant));
            assert!(Arc::ptr_eq(&retained, bits.pages[7].as_ref().unwrap()));
        }
        assert!(bits.contains(4095).unwrap());
    }
}
