//! Receiver-derived ancestry; retained pages are auxiliary data, never validity.
//! Immutable 512-position leaves are shared across descendants and graph clones.
//! Changing a bit copies at most one 64-byte leaf, not the whole strict past.
use crate::{
    Digest,
    budget::JobBudget,
    store::{ObjectReader, Store},
    sync::HISTORY_LIMIT_V1,
};
use silk_order::sg0_v1::Sg0Error;
use std::sync::Arc;

const WORDS_PER_PAGE: usize = 8;
const POSITIONS_PER_PAGE: usize = WORDS_PER_PAGE * 64;
const PAGES: usize = 8;
// Deliberately preserve the reference horizon. Raising it requires a separate
// graph/order/ledger/sync resource design, not silently widening this directory.
const _: () = assert!(PAGES * POSITIONS_PER_PAGE == HISTORY_LIMIT_V1);

#[derive(Clone)]
enum Leaf {
    Resident([u64; WORDS_PER_PAGE]),
    Retained(Digest),
}
pub(super) struct RetainedContext {
    objects: Arc<ObjectReader>,
    domain: Digest,
}
impl RetainedContext {
    pub(super) fn objects(&self) -> &ObjectReader {
        &self.objects
    }
    pub(super) fn new(objects: Arc<ObjectReader>, domain: Digest) -> Arc<Self> {
        Arc::new(Self { objects, domain })
    }
}
#[derive(Clone, Default)]
pub(super) struct PagedAncestry {
    pages: [Option<Arc<Leaf>>; PAGES],
    reader: Option<Arc<RetainedContext>>,
}
impl PagedAncestry {
    fn words(&self, page: usize) -> Result<Option<[u64; WORDS_PER_PAGE]>, Sg0Error> {
        let Some(leaf) = self.pages.get(page).ok_or(Sg0Error::Invariant)? else {
            return Ok(None);
        };
        match leaf.as_ref() {
            Leaf::Resident(words) => Ok(Some(*words)),
            Leaf::Retained(id) => {
                let reader = self.reader.as_ref().ok_or(Sg0Error::Invariant)?;
                let bytes = reader
                    .objects
                    .object(*id, 112)
                    .map_err(|_| Sg0Error::Invariant)?;
                if bytes.len() != 112
                    || &bytes[..8] != b"SNF04AP1"
                    || bytes[8..40] != reader.domain
                    || bytes[40..48]
                        != u64::try_from(page)
                            .map_err(|_| Sg0Error::Invariant)?
                            .to_le_bytes()
                {
                    return Err(Sg0Error::Invariant);
                }
                let mut words = [0; WORDS_PER_PAGE];
                for (word, bytes) in words.iter_mut().zip(bytes[48..].chunks_exact(8)) {
                    *word = u64::from_le_bytes(bytes.try_into().map_err(|_| Sg0Error::Invariant)?);
                }
                Ok(Some(words))
            }
        }
    }
    /// At most eight leaves, local to one complete strict-past traversal. Every
    /// retained byte is read/checked; no persistent read/validity cache is used.
    pub(super) fn materialize(&self) -> Result<Self, Sg0Error> {
        let mut result = Self::default();
        for page in 0..PAGES {
            if let Some(words) = self.words(page)? {
                result.pages[page] = Some(Arc::new(Leaf::Resident(words)));
            }
        }
        Ok(result)
    }
    /// Addresses are receiver-local and never serialized in a head/snapshot.
    /// Cold reopen derives them again only AFTER original full admission checks.
    pub(super) fn retain(
        &mut self,
        store: &mut Store,
        reader: Arc<RetainedContext>,
        budget: &JobBudget,
    ) -> crate::Result<()> {
        if self
            .reader
            .as_ref()
            .is_some_and(|r| !Arc::ptr_eq(r, &reader))
        {
            return Err(crate::Error::Unavailable("ancestry reader context changed"));
        }
        let mut next = self.clone();
        for page in 0..PAGES {
            budget.check()?;
            let Some(leaf) = &self.pages[page] else {
                continue;
            };
            if matches!(leaf.as_ref(), Leaf::Retained(_)) {
                continue;
            }
            budget.source()?;
            let words = self
                .words(page)?
                .ok_or(crate::Error::Unavailable("ancestry leaf disappeared"))?;
            let mut bytes = Vec::with_capacity(112);
            bytes.extend_from_slice(b"SNF04AP1");
            bytes.extend_from_slice(&reader.domain);
            bytes.extend_from_slice(
                &u64::try_from(page)
                    .map_err(|_| crate::Error::Unavailable("ancestry page index"))?
                    .to_le_bytes(),
            );
            for word in words {
                bytes.extend_from_slice(&word.to_le_bytes());
            }
            let id = store.retain_ancestry_page(&bytes)?;
            next.pages[page] = Some(Arc::new(Leaf::Retained(id)));
            budget.check()?;
        }
        next.reader = Some(reader);
        *self = next;
        Ok(())
    }
    pub(super) fn contains(&self, position: usize) -> Result<bool, Sg0Error> {
        Ok(self
            .words(position / POSITIONS_PER_PAGE)?
            .is_some_and(|words| {
                words[position / 64 % WORDS_PER_PAGE] & (1_u64 << (position % 64)) != 0
            }))
    }
    #[cfg(test)]
    pub(super) fn retained_ids(&self) -> Vec<Digest> {
        self.pages
            .iter()
            .filter_map(|leaf| match leaf.as_deref() {
                Some(Leaf::Retained(id)) => Some(*id),
                _ => None,
            })
            .collect()
    }

    pub(super) fn insert(&mut self, position: usize) -> Result<(), Sg0Error> {
        let page = position / POSITIONS_PER_PAGE;
        let mut words = self.words(page)?.unwrap_or([0; WORDS_PER_PAGE]);
        let word = position / 64 % WORDS_PER_PAGE;
        let bit = 1_u64 << (position % 64);
        if words[word] & bit != 0 {
            return Ok(());
        }
        words[word] |= bit;
        let leaf = self.pages[page].get_or_insert_with(|| Arc::new(Leaf::Resident(words)));
        *Arc::make_mut(leaf) = Leaf::Resident(words);
        Ok(())
    }

    pub(super) fn union(&mut self, other: &Self) -> Result<(), Sg0Error> {
        if let (Some(a), Some(b)) = (&self.reader, &other.reader)
            && !Arc::ptr_eq(a, b)
        {
            return Err(Sg0Error::Invariant);
        }
        // Stage all fallible reads, so a failed union never installs half a past.
        let mut next = self.clone();
        if next.reader.is_none() {
            next.reader.clone_from(&other.reader);
        }
        for page in 0..PAGES {
            let source = &other.pages[page];
            let Some(source) = source else { continue };
            let target = &mut next.pages[page];
            let Some(target) = target else {
                *target = Some(source.clone());
                continue;
            };
            // Identical or already included leaves need no copy. This also
            // keeps saturated prefix leaves shared when branches merge.
            if Arc::ptr_eq(target, source) {
                continue;
            }
            let mut target_words = self.words(page)?.ok_or(Sg0Error::Invariant)?;
            let source_words = other.words(page)?.ok_or(Sg0Error::Invariant)?;
            if source_words
                .iter()
                .zip(&target_words)
                .all(|(s, t)| s & !t == 0)
            {
                continue;
            }
            for (target, source) in target_words.iter_mut().zip(source_words) {
                *target |= source;
            }
            *target = Arc::new(Leaf::Resident(target_words));
        }
        *self = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(store: &Store) -> Arc<RetainedContext> {
        RetainedContext::new(store.object_reader().unwrap(), [9; 32])
    }
    fn page_path(temp: &tempfile::TempDir, id: Digest) -> std::path::PathBuf {
        temp.path()
            .join("store")
            .join(format!("{}.obj", hex::encode(id)))
    }
    #[test]
    fn disk_ancestry_reads_actual_retained_pages_and_preserves_horizon() {
        let (temp, mut store) = crate::store::ancestry_test_store();
        let head = store.commit(&[], b"synthetic source head").unwrap();
        let job = store
            .begin_job(b"synthetic already-derived ancestry")
            .unwrap();
        let reader = context(&store);
        let budget = JobBudget::checkpoint().unwrap();
        let mut bits = PagedAncestry::default();
        for position in [0, 63, 64, 511, 512, 513, 4095] {
            bits.insert(position).unwrap();
        }
        let expected = bits.materialize().unwrap();
        bits.retain(&mut store, reader, &budget).unwrap();
        assert_eq!(bits.retained_ids().len(), 3);
        for id in bits.retained_ids() {
            assert_eq!(std::fs::metadata(page_path(&temp, id)).unwrap().len(), 112);
        }
        let loaded = bits.materialize().unwrap();
        for position in 0..HISTORY_LIMIT_V1 {
            assert_eq!(loaded.contains(position), expected.contains(position));
        }
        for position in [0, 63, 64, 511, 512, 513, 4095] {
            assert!(bits.contains(position).unwrap());
        }
        assert!(!bits.contains(514).unwrap());
        assert_eq!(bits.contains(HISTORY_LIMIT_V1), Err(Sg0Error::Invariant));
        assert_eq!(bits.insert(usize::MAX), Err(Sg0Error::Invariant));
        assert_eq!(store.head(), Some(head));
        store.finish_job(job, true).unwrap();
        drop(store);
        // Same live receiver-derived references, not cold validity adoption.
        assert!(bits.contains(4095).unwrap());
    }

    #[test]
    fn disk_ancestry_tampered_missing_and_wrong_context_pages_are_errors_not_absence() {
        let (temp, mut store) = crate::store::ancestry_test_store();
        store.begin_replay(b"synthetic fresh replay").unwrap();
        let reader = context(&store);
        let budget = JobBudget::checkpoint().unwrap();
        let mut bits = PagedAncestry::default();
        bits.insert(0).unwrap();
        bits.retain(&mut store, reader.clone(), &budget).unwrap();
        let id = bits.retained_ids()[0];
        let path = page_path(&temp, id);
        let original = std::fs::read(&path).unwrap();
        let mut changed = original.clone();
        changed[48] ^= 1;
        std::fs::write(&path, &changed).unwrap();
        assert_eq!(bits.contains(0), Err(Sg0Error::Invariant));
        assert_eq!(bits.contains(1), Err(Sg0Error::Invariant));
        std::fs::remove_file(&path).unwrap();
        assert_eq!(bits.contains(0), Err(Sg0Error::Invariant));
        for offset in [8, 40] {
            let mut foreign = original.clone();
            foreign[offset] ^= 1;
            let foreign_id = store.retain_ancestry_page(&foreign).unwrap();
            let mut wrong = bits.clone();
            wrong.pages[0] = Some(Arc::new(Leaf::Retained(foreign_id)));
            assert_eq!(wrong.contains(0), Err(Sg0Error::Invariant));
        }
        let other = RetainedContext::new(store.object_reader().unwrap(), [8; 32]);
        assert!(bits.retain(&mut store, other, &budget).is_err());
    }

    #[test]
    fn disk_ancestry_fork_retains_prior_and_failed_union_is_atomic() {
        let (temp, mut store) = crate::store::ancestry_test_store();
        store.begin_job(b"synthetic verified transition").unwrap();
        let reader = context(&store);
        let budget = JobBudget::checkpoint().unwrap();
        let mut left = PagedAncestry::default();
        left.insert(0).unwrap();
        left.insert(512).unwrap();
        left.retain(&mut store, reader.clone(), &budget).unwrap();
        let before = left.retained_ids();
        let mut child = left.clone();
        child.insert(513).unwrap();
        child.retain(&mut store, reader.clone(), &budget).unwrap();
        assert!(Arc::ptr_eq(
            left.pages[0].as_ref().unwrap(),
            child.pages[0].as_ref().unwrap()
        ));
        assert!(!left.contains(513).unwrap());
        assert!(child.contains(513).unwrap());
        let mut right = PagedAncestry::default();
        right.insert(1).unwrap();
        right.insert(514).unwrap();
        right.retain(&mut store, reader, &budget).unwrap();
        let bad = page_path(&temp, right.retained_ids()[1]);
        let mut bytes = std::fs::read(&bad).unwrap();
        bytes[48] ^= 1;
        std::fs::write(&bad, &bytes).unwrap();
        assert_eq!(left.union(&right), Err(Sg0Error::Invariant));
        assert_eq!(left.retained_ids(), before);
        assert!(!left.contains(1).unwrap());
        assert!(left.contains(512).unwrap());
    }

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
        merged.union(&right).unwrap();
        let flat = std::array::from_fn(|i| left_flat[i] | right_flat[i]);
        assert_flat(&merged, &flat);
        assert_flat(&left, &left_flat);
        assert_flat(&right, &right_flat);
        let mut reversed = right.clone();
        reversed.union(&left).unwrap();
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
        fork.union(&child).unwrap();
        assert!(Arc::ptr_eq(&before, fork.pages[1].as_ref().unwrap()));
        assert_eq!(
            std::mem::size_of::<PagedAncestry>(),
            (PAGES + 1) * std::mem::size_of::<usize>()
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
