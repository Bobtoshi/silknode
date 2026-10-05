//! Receiver-derived ancestry; retained pages are auxiliary data, never validity.
//! Immutable 512-position leaves are shared across descendants and graph clones.
//! Changing a bit copies at most one 64-byte leaf, not the whole strict past.
mod tree;
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
// Policy stays at the reference horizon; the address representation is no
// longer an eight-leaf array. Coupled graph/order/ledger/sync work must precede
// any node-wide horizon change.

/// One owned 64-byte leaf, scoped to an immutable receiver graph operation.
pub(super) struct AncestryOperation<'a> {
    reader: Option<&'a Arc<RetainedContext>>,
    leaf: Option<(Digest, usize, [u64; WORDS_PER_PAGE])>,
    leaf_directory: Option<tree::Pages>,
    #[cfg(test)]
    loads: usize,
}
impl<'a> AncestryOperation<'a> {
    pub(super) const fn new(reader: Option<&'a Arc<RetainedContext>>) -> Self {
        Self {
            reader,
            leaf: None,
            leaf_directory: None,
            #[cfg(test)]
            loads: 0,
        }
    }
    #[cfg(test)]
    pub(super) const fn loads(&self) -> usize {
        self.loads
    }
    pub(super) fn contains(
        &mut self,
        bits: &PagedAncestry,
        position: usize,
        budget: &JobBudget,
    ) -> Result<bool, Sg0Error> {
        let check = || budget.check().map_err(|_| Sg0Error::ResourceBudget);
        check()?;
        bits.check_position(position)?;
        let page = position / POSITIONS_PER_PAGE;
        if let Some((_, ordinal, words)) = &self.leaf
            && *ordinal == page
            && self
                .leaf_directory
                .as_ref()
                .is_some_and(|directory| directory.same_root(&bits.pages))
            && bits
                .reader
                .as_ref()
                .is_some_and(|reader| self.reader.is_some_and(|bound| Arc::ptr_eq(bound, reader)))
        {
            let present = words[position / 64 % WORDS_PER_PAGE] & (1_u64 << (position % 64)) != 0;
            check()?;
            return Ok(present);
        }
        let slot = bits
            .pages
            .get(page, bits.reader.as_ref(), Some(budget))
            .map_err(directory_error)?;
        let words = match slot.as_deref() {
            None => None,
            Some(Leaf::Resident(words)) => Some(*words),
            Some(Leaf::Retained(id)) => {
                let reader = bits.reader.as_ref().ok_or(Sg0Error::Invariant)?;
                if !self.reader.is_some_and(|bound| Arc::ptr_eq(bound, reader)) {
                    return Err(Sg0Error::Invariant);
                }
                if self
                    .leaf
                    .as_ref()
                    .is_none_or(|(cached, ordinal, _)| cached != id || *ordinal != page)
                {
                    budget.source().map_err(|_| Sg0Error::ResourceBudget)?;
                    let words = bits.leaf_words(page, slot.as_ref().ok_or(Sg0Error::Invariant)?)?;
                    check()?;
                    // Install only a complete hash/inode/domain/page-qualified
                    // positive leaf. Failures and missing objects are not bits.
                    self.leaf = Some((*id, page, words));
                    self.leaf_directory = Some(bits.pages.clone());
                    #[cfg(test)]
                    {
                        self.loads += 1;
                    }
                }
                Some(self.leaf.as_ref().ok_or(Sg0Error::Invariant)?.2)
            }
        };
        let present = words.is_some_and(|words| {
            words[position / 64 % WORDS_PER_PAGE] & (1_u64 << (position % 64)) != 0
        });
        check()?;
        Ok(present)
    }
}

#[derive(Clone)]
enum Leaf {
    Resident([u64; WORDS_PER_PAGE]),
    Retained(Digest),
}
// Shared with the crate-private entry adapter through its trait signature.
#[allow(clippy::redundant_pub_crate)]
pub(crate) struct RetainedContext {
    objects: Arc<ObjectReader>,
    domain: Digest,
}
impl RetainedContext {
    pub(super) const fn domain(&self) -> Digest {
        self.domain
    }
    pub(super) fn objects(&self) -> &ObjectReader {
        &self.objects
    }
    pub(super) fn new(objects: Arc<ObjectReader>, domain: Digest) -> Arc<Self> {
        Arc::new(Self { objects, domain })
    }
}
#[derive(Clone)]
pub(super) struct PagedAncestry {
    pages: tree::Pages,
    reader: Option<Arc<RetainedContext>>,
    horizon: usize,
}
impl Default for PagedAncestry {
    fn default() -> Self {
        Self {
            pages: tree::Pages::default(),
            reader: None,
            horizon: HISTORY_LIMIT_V1,
        }
    }
}
fn directory_error(error: crate::Error) -> Sg0Error {
    match error {
        crate::Error::Paused(_) => Sg0Error::ResourceBudget,
        _ => Sg0Error::Invariant,
    }
}
impl PagedAncestry {
    fn check_position(&self, position: usize) -> Result<(), Sg0Error> {
        if position >= self.horizon {
            Err(Sg0Error::Invariant)
        } else {
            Ok(())
        }
    }
    pub(super) fn directory_bytes(&self) -> crate::Result<Vec<u8>> {
        self.pages.directory_bytes()
    }
    /// Addresses from private receiver-minted, hash-bound live directory pages.
    pub(super) fn from_live_directory(
        bytes: &[u8],
        reader: Arc<RetainedContext>,
    ) -> crate::Result<Self> {
        Ok(Self {
            pages: tree::Pages::from_directory(
                bytes,
                HISTORY_LIMIT_V1.div_ceil(POSITIONS_PER_PAGE),
            )?,
            reader: Some(reader),
            ..Self::default()
        })
    }
    fn words(&self, page: usize) -> Result<Option<[u64; WORDS_PER_PAGE]>, Sg0Error> {
        if page >= self.horizon.div_ceil(POSITIONS_PER_PAGE) {
            return Err(Sg0Error::Invariant);
        }
        let Some(leaf) = self
            .pages
            .get(page, self.reader.as_ref(), None)
            .map_err(directory_error)?
        else {
            return Ok(None);
        };
        self.leaf_words(page, &leaf).map(Some)
    }
    fn leaf_words(&self, page: usize, leaf: &Arc<Leaf>) -> Result<[u64; WORDS_PER_PAGE], Sg0Error> {
        match leaf.as_ref() {
            Leaf::Resident(words) => Ok(*words),
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
                Ok(words)
            }
        }
    }
    /// At most eight leaves, local to one complete strict-past traversal. Every
    /// retained byte is read/checked; no persistent read/validity cache is used.
    #[cfg(test)]
    pub(super) fn materialize(&self) -> Result<Self, Sg0Error> {
        let mut result = Self {
            horizon: self.horizon,
            ..Self::default()
        };
        self.pages
            .visit(self.reader.as_ref(), None, &mut |page, leaf| {
                if page >= self.horizon.div_ceil(POSITIONS_PER_PAGE) {
                    return Err(crate::Error::Unavailable("ancestry leaf horizon"));
                }
                let words = self.leaf_words(page, &leaf).map_err(crate::Error::Order)?;
                result
                    .pages
                    .set(page, Arc::new(Leaf::Resident(words)), None)
            })
            .map_err(directory_error)?;
        Ok(result)
    }
    /// Own only the set positions, in the same increasing ordinal order. Every
    /// retained leaf is freshly qualified before this list can reach a visitor,
    /// including leaves outside the requested prefix; they are never skipped.
    pub(super) fn positions_before(
        &self,
        end: usize,
        budget: &JobBudget,
    ) -> Result<Vec<usize>, Sg0Error> {
        if end > self.horizon {
            return Err(Sg0Error::Invariant);
        }
        budget.check().map_err(|_| Sg0Error::ResourceBudget)?;
        let mut positions = Vec::new();
        self.pages
            .visit(self.reader.as_ref(), Some(budget), &mut |page, leaf| {
                if page >= self.horizon.div_ceil(POSITIONS_PER_PAGE) {
                    return Err(crate::Error::Unavailable("ancestry leaf horizon"));
                }
                if matches!(leaf.as_ref(), Leaf::Retained(_)) {
                    budget.source()?;
                }
                let words = self.leaf_words(page, &leaf).map_err(crate::Error::Order)?;
                for (word_index, mut word) in words.into_iter().enumerate() {
                    budget.graph_read()?;
                    while word != 0 {
                        let bit = word.trailing_zeros() as usize;
                        let position = page * POSITIONS_PER_PAGE + word_index * 64 + bit;
                        if position < end {
                            positions.push(position);
                        }
                        word &= word - 1;
                    }
                }
                Ok(())
            })
            .map_err(directory_error)?;
        budget.check().map_err(|_| Sg0Error::ResourceBudget)?;
        Ok(positions)
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
        let pages = self
            .pages
            .retain(store, &reader, budget, &mut |page, leaf, store| {
                budget.check()?;
                if let Leaf::Retained(id) = leaf.as_ref() {
                    return Ok(*id);
                }
                budget.source()?;
                let words = self.leaf_words(page, leaf).map_err(crate::Error::Order)?;
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
                budget.check()?;
                Ok(id)
            })?;
        let mut next = self.clone();
        next.pages = pages;
        next.reader = Some(reader);
        *self = next;
        Ok(())
    }
    pub(super) fn contains(&self, position: usize) -> Result<bool, Sg0Error> {
        self.check_position(position)?;
        Ok(self
            .words(position / POSITIONS_PER_PAGE)?
            .is_some_and(|words| {
                words[position / 64 % WORDS_PER_PAGE] & (1_u64 << (position % 64)) != 0
            }))
    }
    #[cfg(test)]
    pub(super) fn retained_ids(&self) -> Vec<Digest> {
        let mut ids = Vec::new();
        self.pages
            .visit(self.reader.as_ref(), None, &mut |_, leaf| {
                if let Leaf::Retained(id) = leaf.as_ref() {
                    ids.push(*id);
                }
                Ok(())
            })
            .unwrap();
        ids
    }

    pub(super) fn insert(&mut self, position: usize) -> Result<(), Sg0Error> {
        self.check_position(position)?;
        let page = position / POSITIONS_PER_PAGE;
        let mut words = self.words(page)?.unwrap_or([0; WORDS_PER_PAGE]);
        let word = position / 64 % WORDS_PER_PAGE;
        let bit = 1_u64 << (position % 64);
        if words[word] & bit != 0 {
            return Ok(());
        }
        words[word] |= bit;
        self.pages
            .set(page, Arc::new(Leaf::Resident(words)), self.reader.as_ref())
            .map_err(directory_error)
    }

    pub(super) fn union(&mut self, other: &Self) -> Result<(), Sg0Error> {
        if self.horizon != other.horizon {
            return Err(Sg0Error::Invariant);
        }
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
        other
            .pages
            .visit(other.reader.as_ref(), None, &mut |page, source| {
                if page >= self.horizon.div_ceil(POSITIONS_PER_PAGE) {
                    return Err(crate::Error::Unavailable("ancestry leaf horizon"));
                }
                let target = self.pages.get(page, self.reader.as_ref(), None)?;
                let Some(target) = target else {
                    next.pages.set(page, source, next.reader.as_ref())?;
                    return Ok(());
                };
                // Identical or already included leaves need no copy. This also
                // keeps saturated prefix leaves shared when branches merge.
                if Arc::ptr_eq(&target, &source) {
                    return Ok(());
                }
                let mut target_words = self
                    .leaf_words(page, &target)
                    .map_err(crate::Error::Order)?;
                let source_words = other
                    .leaf_words(page, &source)
                    .map_err(crate::Error::Order)?;
                if source_words
                    .iter()
                    .zip(&target_words)
                    .all(|(s, t)| s & !t == 0)
                {
                    return Ok(());
                }
                for (target, source) in target_words.iter_mut().zip(source_words) {
                    *target |= source;
                }
                next.pages.set(
                    page,
                    Arc::new(Leaf::Resident(target_words)),
                    next.reader.as_ref(),
                )
            })
            .map_err(directory_error)?;
        *self = next;
        Ok(())
    }
    #[cfg(test)]
    fn test_leaf(&self, page: usize) -> Option<Arc<Leaf>> {
        self.pages.get(page, self.reader.as_ref(), None).unwrap()
    }
    #[cfg(test)]
    fn test_set(&mut self, page: usize, leaf: Arc<Leaf>) {
        self.pages.set(page, leaf, self.reader.as_ref()).unwrap();
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
    fn sparse_ancestry_positions_match_flat_prefixes_and_qualify_all_leaves_first() {
        let (temp, mut store) = crate::store::ancestry_test_store();
        store
            .begin_replay(b"synthetic sparse ancestry fixture")
            .unwrap();
        let reader = context(&store);
        let budget = JobBudget::checkpoint().unwrap();
        let expected: std::collections::BTreeSet<_> = (0..HISTORY_LIMIT_V1)
            .step_by(37)
            .chain([0, 63, 64, 511, 512, 513, 4095])
            .collect();
        let mut bits = PagedAncestry::default();
        for position in &expected {
            bits.insert(*position).unwrap();
        }
        let resident = bits.clone();
        bits.retain(&mut store, reader, &budget).unwrap();
        for end in [0, 1, 64, 65, 511, 512, 513, 1024, HISTORY_LIMIT_V1] {
            let reference: Vec<_> = expected.range(..end).copied().collect();
            assert_eq!(resident.positions_before(end, &budget).unwrap(), reference);
            assert_eq!(bits.positions_before(end, &budget).unwrap(), reference);
        }
        let path = page_path(&temp, bits.retained_ids()[7]);
        let held = path.with_extension("held");
        let original = std::fs::read(&path).unwrap();
        std::fs::rename(&path, &held).unwrap();
        // Even an empty or tiny requested prefix must read the late leaf. A
        // partially built position list cannot become apparent empty ancestry.
        assert_eq!(bits.positions_before(0, &budget), Err(Sg0Error::Invariant));
        assert_eq!(bits.positions_before(1, &budget), Err(Sg0Error::Invariant));
        std::fs::rename(&held, &path).unwrap();
        let mut changed = original.clone();
        changed[48] ^= 1;
        std::fs::write(&path, changed).unwrap();
        assert_eq!(bits.positions_before(1, &budget), Err(Sg0Error::Invariant));
        std::fs::write(&path, &original).unwrap();
        assert_eq!(
            bits.positions_before(HISTORY_LIMIT_V1, &budget).unwrap(),
            expected.into_iter().collect::<Vec<_>>()
        );
        let expired = JobBudget::testing(std::time::Duration::ZERO).unwrap();
        assert_eq!(
            bits.positions_before(1, &expired),
            Err(Sg0Error::ResourceBudget)
        );
        assert_eq!(
            bits.positions_before(HISTORY_LIMIT_V1 + 1, &budget),
            Err(Sg0Error::Invariant)
        );
        let mut dense = PagedAncestry::default();
        for position in 0..HISTORY_LIMIT_V1 {
            dense.insert(position).unwrap();
        }
        let positions = dense.positions_before(HISTORY_LIMIT_V1, &budget).unwrap();
        assert_eq!(positions, (0..HISTORY_LIMIT_V1).collect::<Vec<_>>());
        assert!(positions.len() * std::mem::size_of::<usize>() <= 32 * 1024);
    }

    #[test]
    fn operation_ancestry_leaf_is_bounded_exact_and_cannot_hide_failed_fresh_reads() {
        let (temp, mut store) = crate::store::ancestry_test_store();
        store
            .begin_replay(b"synthetic operation ancestry fixture")
            .unwrap();
        let reader = context(&store);
        let bound = Some(reader.clone());
        let budget = JobBudget::checkpoint().unwrap();
        let mut bits = PagedAncestry::default();
        for position in [0, 63, 64, 511, 512, 4095] {
            bits.insert(position).unwrap();
        }
        bits.retain(&mut store, reader, &budget).unwrap();
        let path = page_path(&temp, bits.retained_ids()[0]);
        let original = std::fs::read(&path).unwrap();
        let held = path.with_extension("held");
        let mut operation = AncestryOperation::new(bound.as_ref());
        let source_before = budget.source_calls();
        for position in 0..POSITIONS_PER_PAGE {
            assert_eq!(
                operation.contains(&bits, position, &budget).unwrap(),
                [0, 63, 64, 511].contains(&position)
            );
        }
        assert_eq!(operation.loads(), 1);
        // One root-branch qualification plus one leaf, not a branch reopen for
        // every bit probe. The owned root key is scoped to this operation.
        assert_eq!(budget.source_calls() - source_before, 2);
        assert_eq!(
            std::mem::size_of_val(&operation.leaf.as_ref().unwrap().2),
            64
        );
        std::fs::rename(&path, &held).unwrap();
        assert!(operation.contains(&bits, 0, &budget).unwrap());
        let mut fresh = AncestryOperation::new(bound.as_ref());
        for position in [0, 1] {
            assert_eq!(
                fresh.contains(&bits, position, &budget),
                Err(Sg0Error::Invariant)
            );
        }
        assert_eq!(fresh.loads(), 0);
        assert!(operation.contains(&bits, 512, &budget).unwrap());
        assert_eq!(operation.loads(), 2);
        assert_eq!(
            operation.contains(&bits, 0, &budget),
            Err(Sg0Error::Invariant)
        );
        std::fs::rename(&held, &path).unwrap();
        let mut changed = original.clone();
        changed[48] ^= 1;
        std::fs::write(&path, changed).unwrap();
        assert_eq!(fresh.contains(&bits, 1, &budget), Err(Sg0Error::Invariant));
        std::fs::write(&path, &original).unwrap();
        std::fs::hard_link(&path, &held).unwrap();
        assert_eq!(fresh.contains(&bits, 0, &budget), Err(Sg0Error::Invariant));
        std::fs::remove_file(&held).unwrap();
        assert!(fresh.contains(&bits, 0, &budget).unwrap());
        assert_eq!(fresh.loads(), 1);
        for offset in [8, 40] {
            let mut foreign = original.clone();
            foreign[offset] ^= 1;
            let foreign_id = store.retain_ancestry_page(&foreign).unwrap();
            let mut wrong = bits.clone();
            wrong.test_set(0, Arc::new(Leaf::Retained(foreign_id)));
            assert_eq!(fresh.contains(&wrong, 0, &budget), Err(Sg0Error::Invariant));
            assert_eq!(fresh.loads(), 1);
        }
        let foreign_bound = Some(context(&store));
        let mut foreign = AncestryOperation::new(foreign_bound.as_ref());
        assert_eq!(
            foreign.contains(&bits, 0, &budget),
            Err(Sg0Error::Invariant)
        );
        let expired = JobBudget::testing(std::time::Duration::ZERO).unwrap();
        assert_eq!(
            fresh.contains(&bits, 0, &expired),
            Err(Sg0Error::ResourceBudget)
        );
        assert_eq!(
            fresh.contains(&bits, HISTORY_LIMIT_V1, &budget),
            Err(Sg0Error::Invariant)
        );
        assert_eq!(
            fresh.contains(&bits, usize::MAX, &budget),
            Err(Sg0Error::Invariant)
        );
        let resident = bits.materialize().unwrap();
        let mut resident_reads = AncestryOperation::new(None);
        assert!(resident_reads.contains(&resident, 4095, &budget).unwrap());
        assert!(!resident_reads.contains(&resident, 1024, &budget).unwrap());
        assert_eq!(resident_reads.loads(), 0);
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
            wrong.test_set(0, Arc::new(Leaf::Retained(foreign_id)));
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
        assert_eq!(left.retained_ids()[0], child.retained_ids()[0]);
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
            &prefix.test_leaf(0).unwrap(),
            &child.test_leaf(0).unwrap()
        ));
        assert!(prefix.test_leaf(1).is_none());
        let mut fork = child.clone();
        fork.insert(POSITIONS_PER_PAGE + 1).unwrap();
        assert!(Arc::ptr_eq(
            &child.test_leaf(0).unwrap(),
            &fork.test_leaf(0).unwrap()
        ));
        assert!(!Arc::ptr_eq(
            &child.test_leaf(1).unwrap(),
            &fork.test_leaf(1).unwrap()
        ));
        assert!(!child.contains(POSITIONS_PER_PAGE + 1).unwrap());
        let before = fork.test_leaf(1).unwrap();
        fork.insert(POSITIONS_PER_PAGE + 1).unwrap();
        fork.union(&child).unwrap();
        assert!(Arc::ptr_eq(&before, &fork.test_leaf(1).unwrap()));
        assert_eq!(
            std::mem::size_of::<PagedAncestry>(),
            4 * std::mem::size_of::<usize>()
        );
        assert_eq!(std::mem::size_of::<[u64; WORDS_PER_PAGE]>(), 64);
    }

    #[test]
    fn paged_ancestry_outside_horizon_refuses_without_mutation() {
        let mut bits = PagedAncestry::default();
        bits.insert(4095).unwrap();
        let retained = bits.test_leaf(7).unwrap();
        for position in [HISTORY_LIMIT_V1, usize::MAX] {
            assert_eq!(bits.contains(position), Err(Sg0Error::Invariant));
            assert_eq!(bits.insert(position), Err(Sg0Error::Invariant));
            assert!(Arc::ptr_eq(&retained, &bits.test_leaf(7).unwrap()));
        }
        assert!(bits.contains(4095).unwrap());
    }
    #[test]
    fn extensible_ancestry_root_crosses_old_geometry_and_rejects_deep_damage_atomically() {
        // Synthetic auxiliary positions only. The integrated node policy and
        // every consensus/crypto/graph/order/ledger/sync limit remain unchanged.
        let (temp, mut store) = crate::store::ancestry_test_store();
        store
            .begin_replay(b"synthetic extensible ancestry root")
            .unwrap();
        let reader = context(&store);
        let budget = JobBudget::checkpoint().unwrap();
        let horizon = 1_048_576;
        let positions = [
            0,
            511,
            512,
            4095,
            4096,
            32767,
            32768,
            65535,
            65536,
            horizon - 1,
        ];
        let mut bits = PagedAncestry {
            horizon,
            ..PagedAncestry::default()
        };
        for position in positions {
            bits.insert(position).unwrap();
        }
        let prior = bits.clone();
        let mut fork = bits.clone();
        fork.insert(4097).unwrap();
        assert!(Arc::ptr_eq(
            &prior.test_leaf(0).unwrap(),
            &fork.test_leaf(0).unwrap()
        ));
        assert!(!prior.contains(4097).unwrap());
        bits.union(&fork).unwrap();
        bits.retain(&mut store, reader.clone(), &budget).unwrap();
        let entry = bits.directory_bytes().unwrap();
        assert_eq!(entry.len(), 34);
        assert_eq!(entry[0], 4);
        // Higher-depth roots cannot be injected into the unchanged node policy.
        assert!(PagedAncestry::from_live_directory(&entry, reader.clone()).is_err());
        let restored = PagedAncestry {
            pages: tree::Pages::from_directory(&entry, horizon.div_ceil(POSITIONS_PER_PAGE))
                .unwrap(),
            reader: Some(reader.clone()),
            horizon,
        };
        let expected: Vec<_> = positions
            .into_iter()
            .chain([4097])
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        assert_eq!(
            restored.positions_before(horizon, &budget).unwrap(),
            expected
        );
        assert_eq!(
            restored.positions_before(4097, &budget).unwrap(),
            expected
                .iter()
                .copied()
                .filter(|p| *p < 4097)
                .collect::<Vec<_>>()
        );
        assert!(!restored.contains(12345).unwrap());
        let ids = restored.retained_ids();
        let tail = page_path(&temp, *ids.last().unwrap());
        let held = tail.with_extension("held");
        std::fs::rename(&tail, &held).unwrap();
        assert_eq!(
            restored.positions_before(0, &budget),
            Err(Sg0Error::Invariant)
        );
        let mut merged = prior.clone();
        let before = merged.positions_before(horizon, &budget).unwrap();
        assert_eq!(merged.union(&restored), Err(Sg0Error::Invariant));
        assert_eq!(merged.positions_before(horizon, &budget).unwrap(), before);
        std::fs::rename(&held, &tail).unwrap();
        let root: Digest = entry[2..].try_into().unwrap();
        let root_path = page_path(&temp, root);
        let bytes = std::fs::read(&root_path).unwrap();
        assert_eq!(bytes.len(), 320);
        assert_eq!(&bytes[..8], b"SNF04AD2");
        for offset in [8, 40, 48] {
            let mut foreign = bytes.clone();
            foreign[offset] ^= 1;
            // Keep a structurally writable depth while making the expected
            // root coordinate wrong. A valid content hash alone is not enough.
            let id = store.retain_ancestry_directory_page(&foreign).unwrap();
            let mut wrong_entry = entry.clone();
            wrong_entry[2..].copy_from_slice(&id);
            let wrong = PagedAncestry {
                pages: tree::Pages::from_directory(
                    &wrong_entry,
                    horizon.div_ceil(POSITIONS_PER_PAGE),
                )
                .unwrap(),
                reader: Some(reader.clone()),
                horizon,
            };
            assert_eq!(wrong.positions_before(0, &budget), Err(Sg0Error::Invariant));
        }
        std::fs::hard_link(&root_path, root_path.with_extension("linked")).unwrap();
        assert_eq!(restored.contains(0), Err(Sg0Error::Invariant));
        std::fs::remove_file(root_path.with_extension("linked")).unwrap();
        let expired = JobBudget::testing(std::time::Duration::ZERO).unwrap();
        assert_eq!(
            restored.positions_before(0, &expired),
            Err(Sg0Error::ResourceBudget)
        );
        assert_eq!(restored.contains(horizon), Err(Sg0Error::Invariant));
        assert_eq!(
            restored.positions_before(horizon, &budget).unwrap(),
            expected
        );
        assert_eq!(store.head(), None);
    }
}
