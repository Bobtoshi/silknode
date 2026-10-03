//! Receiver-derived ID/ordinal index pages, never imported validity or graph data.
use crate::{
    Digest, Error, Result,
    budget::JobBudget,
    store::{ObjectReader, Store},
    sync::HISTORY_LIMIT_V1,
    wire::{u32le, u64le},
};
use silk_types::VertexId;
use std::{collections::BTreeMap, sync::Arc};

const KEYS: usize = 64;
const HEADER: usize = 52;

/// One operation's owned leaf, tied to the immutable receiver-created index.
pub(super) struct IndexOperation<'a> {
    index: &'a VertexIndex,
    page: Option<(usize, Vec<(VertexId, usize)>)>,
    #[cfg(test)]
    loads: usize,
}
impl<'a> IndexOperation<'a> {
    #[cfg(test)]
    pub(super) const fn loads(&self) -> usize {
        self.loads
    }
    pub(super) const fn new(index: &'a VertexIndex) -> Self {
        Self {
            index,
            page: None,
            #[cfg(test)]
            loads: 0,
        }
    }
    pub(super) fn lookup(&mut self, id: &VertexId, budget: &JobBudget) -> Result<Option<usize>> {
        budget.check()?;
        let VertexIndex::Retained(rows) = self.index else {
            return self.index.lookup(id, Some(budget));
        };
        if rows.len > HISTORY_LIMIT_V1 {
            return Err(Error::Unavailable("operation vertex index horizon"));
        }
        let ordinal = rows.pages.partition_point(|page| page.last < *id);
        let Some(page) = rows.pages.get(ordinal) else {
            return Ok(None);
        };
        if *id < page.first {
            return Ok(None);
        }
        if self
            .page
            .as_ref()
            .is_none_or(|(cached, _)| *cached != ordinal)
        {
            let entries = VertexIndex::page(rows, ordinal, Some(budget))?;
            // No partial page, I/O error, or decoded error becomes cached data.
            self.page = Some((ordinal, entries));
            #[cfg(test)]
            {
                self.loads += 1;
            }
        }
        let entries = &self
            .page
            .as_ref()
            .ok_or(Error::Unavailable("operation index leaf absent"))?
            .1;
        let result = entries
            .binary_search_by_key(id, |(key, _)| *key)
            .ok()
            .map(|position| entries[position].1);
        budget.check()?;
        Ok(result)
    }
}
#[derive(Clone)]
struct Page {
    id: Digest,
    count: usize,
    first: VertexId,
    last: VertexId,
}
#[derive(Clone)]
pub(super) struct Retained {
    pages: Arc<Vec<Page>>,
    len: usize,
    domain: Digest,
    reader: Arc<ObjectReader>,
}
#[derive(Clone)]
pub(super) enum VertexIndex {
    Resident(Arc<BTreeMap<VertexId, usize>>),
    Retained(Retained),
}
impl Default for VertexIndex {
    fn default() -> Self {
        Self::Resident(Arc::new(BTreeMap::new()))
    }
}
impl VertexIndex {
    fn page(
        rows: &Retained,
        ordinal: usize,
        budget: Option<&JobBudget>,
    ) -> Result<Vec<(VertexId, usize)>> {
        let page = rows
            .pages
            .get(ordinal)
            .ok_or(Error::Unavailable("retained vertex index directory"))?;
        if !(1..=KEYS).contains(&page.count) || ordinal + 1 < rows.pages.len() && page.count != KEYS
        {
            return Err(Error::Unavailable("retained vertex index count"));
        }
        if let Some(budget) = budget {
            budget.check()?;
            budget.source()?;
        }
        let size = HEADER + page.count * 40;
        let bytes = rows.reader.object(page.id, size)?;
        if bytes.len() != size
            || bytes.get(..8) != Some(b"SNF04IP1")
            || bytes[8..40] != rows.domain
            || u64le(&bytes, 40)? != ordinal as u64
            || u32le(&bytes, 48)? as usize != page.count
        {
            return Err(Error::Unavailable("retained vertex index binding"));
        }
        let mut entries = Vec::with_capacity(page.count);
        for row in bytes[HEADER..].chunks_exact(40) {
            let id = VertexId::from_bytes(
                row[..32]
                    .try_into()
                    .map_err(|_| Error::Unavailable("retained vertex index key"))?,
            );
            let position = usize::try_from(u64le(row, 32)?)
                .map_err(|_| Error::Unavailable("retained vertex index ordinal"))?;
            if position >= rows.len || entries.last().is_some_and(|(last, _)| *last >= id) {
                return Err(Error::Unavailable("retained vertex index order"));
            }
            entries.push((id, position));
        }
        if entries.first().map(|(id, _)| *id) != Some(page.first)
            || entries.last().map(|(id, _)| *id) != Some(page.last)
        {
            return Err(Error::Unavailable("retained vertex index range"));
        }
        if let Some(budget) = budget {
            budget.check()?;
        }
        Ok(entries)
    }
    pub(super) fn lookup(
        &self,
        id: &VertexId,
        budget: Option<&JobBudget>,
    ) -> Result<Option<usize>> {
        if let Some(budget) = budget {
            budget.check()?;
        }
        match self {
            Self::Resident(rows) => Ok(rows.get(id).copied()),
            Self::Retained(rows) => {
                if rows.len > HISTORY_LIMIT_V1 {
                    return Err(Error::Unavailable("retained vertex index horizon"));
                }
                // These ranges are private live derivation, never disk metadata.
                let ordinal = rows.pages.partition_point(|page| page.last < *id);
                let Some(page) = rows.pages.get(ordinal) else {
                    return Ok(None);
                };
                if *id < page.first {
                    return Ok(None);
                }
                let entries = Self::page(rows, ordinal, budget)?;
                Ok(entries
                    .binary_search_by_key(id, |(key, _)| *key)
                    .ok()
                    .map(|position| entries[position].1))
            }
        }
    }
    pub(super) fn materialize(
        &self,
        budget: Option<&JobBudget>,
    ) -> Result<BTreeMap<VertexId, usize>> {
        if let Some(budget) = budget {
            budget.check()?;
        }
        let rows = match self {
            Self::Resident(rows) => return Ok(rows.as_ref().clone()),
            Self::Retained(rows) => rows,
        };
        if rows.len > HISTORY_LIMIT_V1 {
            return Err(Error::Unavailable("retained vertex index horizon"));
        }
        let mut result = BTreeMap::new();
        let mut seen = vec![false; rows.len];
        let mut last = None;
        for ordinal in 0..rows.pages.len() {
            for (id, position) in Self::page(rows, ordinal, budget)? {
                if last.is_some_and(|last| last >= id) || seen[position] {
                    return Err(Error::Unavailable("retained vertex index directory order"));
                }
                seen[position] = true;
                result.insert(id, position);
                last = Some(id);
            }
        }
        if result.len() != rows.len || seen.iter().any(|seen| !seen) {
            return Err(Error::Unavailable("retained vertex index directory length"));
        }
        if let Some(budget) = budget {
            budget.check()?;
        }
        Ok(result)
    }
    /// Complete owned ordinal vectors without constructing a second whole index.
    pub(super) fn inventory(&self, budget: &JobBudget) -> Result<super::OrdinalInventory> {
        budget.check()?;
        let len = match self {
            Self::Resident(rows) => rows.len(),
            Self::Retained(rows) => rows.len,
        };
        if len > HISTORY_LIMIT_V1 {
            return Err(Error::Unavailable("retained vertex index horizon"));
        }
        let mut ids = vec![VertexId::from_bytes([0; 32]); len];
        let mut sorted = Vec::with_capacity(len);
        let mut seen = vec![false; len];
        let mut last = None;
        let mut accept = |id: VertexId, position: usize| -> Result<()> {
            if position >= len || last.is_some_and(|last| last >= id) || seen[position] {
                return Err(Error::Unavailable("retained vertex index directory order"));
            }
            seen[position] = true;
            ids[position] = id;
            sorted.push(position);
            last = Some(id);
            Ok(())
        };
        match self {
            Self::Resident(rows) => {
                for (id, position) in rows.iter() {
                    accept(*id, *position)?;
                }
            }
            Self::Retained(rows) => {
                for ordinal in 0..rows.pages.len() {
                    for (id, position) in Self::page(rows, ordinal, Some(budget))? {
                        accept(id, position)?;
                    }
                }
            }
        }
        if sorted.len() != len || seen.iter().any(|seen| !seen) {
            return Err(Error::Unavailable("retained vertex index directory length"));
        }
        budget.check()?;
        Ok(super::OrdinalInventory { ids, sorted })
    }
    pub(super) fn retain(
        rows: &BTreeMap<VertexId, usize>,
        store: &mut Store,
        domain: Digest,
        budget: &JobBudget,
    ) -> Result<Self> {
        if rows.len() > HISTORY_LIMIT_V1 {
            return Err(Error::Paused("vertex index reference horizon"));
        }
        let mut seen = vec![false; rows.len()];
        for position in rows.values() {
            if *position >= rows.len() || seen[*position] {
                return Err(Error::Unavailable("derived vertex index ordinal"));
            }
            seen[*position] = true;
        }
        let mut pages = Vec::with_capacity(rows.len().div_ceil(KEYS));
        let mut entries = rows.iter().peekable();
        while let Some((first, _)) = entries.peek().copied() {
            budget.check()?;
            let count = (rows.len() - pages.len() * KEYS).min(KEYS);
            let mut bytes = Vec::with_capacity(HEADER + count * 40);
            bytes.extend_from_slice(b"SNF04IP1");
            bytes.extend_from_slice(&domain);
            bytes.extend_from_slice(&(pages.len() as u64).to_le_bytes());
            bytes.extend_from_slice(
                &u32::try_from(count)
                    .map_err(|_| Error::Unavailable("derived vertex index count"))?
                    .to_le_bytes(),
            );
            let mut last = *first;
            for _ in 0..count {
                let (id, position) = entries
                    .next()
                    .ok_or(Error::Unavailable("derived vertex index length"))?;
                bytes.extend_from_slice(id.as_bytes());
                bytes.extend_from_slice(&(*position as u64).to_le_bytes());
                last = *id;
            }
            budget.source()?;
            pages.push(Page {
                id: store.retain_vertex_index_page(&bytes)?,
                count,
                first: *first,
                last,
            });
        }
        budget.check()?;
        Ok(Self::Retained(Retained {
            pages: Arc::new(pages),
            len: rows.len(),
            domain,
            reader: store.object_reader()?,
        }))
    }
    #[cfg(test)]
    pub(super) fn retained_ids(&self) -> Vec<Digest> {
        match self {
            Self::Resident(_) => Vec::new(),
            Self::Retained(rows) => rows.pages.iter().map(|page| page.id).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    fn key(position: usize) -> VertexId {
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&(position as u64).to_be_bytes());
        VertexId::from_bytes(bytes)
    }
    fn rows(count: usize) -> BTreeMap<VertexId, usize> {
        (0..count)
            .map(|position| (key(position * 2), count - 1 - position))
            .collect()
    }
    #[test]
    fn inventory_vectors_match_complete_index_at_page_and_horizon_boundaries() {
        let (_temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        store.begin_replay(b"synthetic ordinal vectors").unwrap();
        for count in [0, 1, 63, 64, 65, 129, HISTORY_LIMIT_V1] {
            let source = rows(count);
            let resident = VertexIndex::Resident(Arc::new(source.clone()));
            let retained = VertexIndex::retain(&source, &mut store, [21; 32], &budget).unwrap();
            for index in [&resident, &retained] {
                let inventory = index.inventory(&budget).unwrap();
                assert_eq!(inventory.ids.len(), count);
                assert_eq!(
                    inventory.sorted,
                    source.values().copied().collect::<Vec<_>>()
                );
                for (id, position) in &source {
                    assert_eq!(inventory.ids[*position], *id);
                }
                assert_eq!(index.materialize(Some(&budget)).unwrap(), source);
            }
        }
        let expired = JobBudget::testing(std::time::Duration::ZERO).unwrap();
        assert!(matches!(
            VertexIndex::default().inventory(&expired),
            Err(Error::Paused(_))
        ));
        let oversize = VertexIndex::Resident(Arc::new(rows(HISTORY_LIMIT_V1 + 1)));
        assert!(oversize.inventory(&budget).is_err());
    }
    #[test]
    fn inventory_vectors_refuse_partial_corrupt_or_invalid_permutations() {
        let (temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        store
            .begin_replay(b"synthetic ordinal vector refusal")
            .unwrap();
        let source = rows(129);
        let retained = VertexIndex::retain(&source, &mut store, [21; 32], &budget).unwrap();
        let pages = retained.retained_ids();
        let last = temp
            .path()
            .join("store")
            .join(format!("{}.obj", hex::encode(pages[2])));
        let held = last.with_extension("held");
        let original = fs::read(&last).unwrap();
        fs::rename(&last, &held).unwrap();
        assert!(retained.inventory(&budget).is_err());
        fs::rename(&held, &last).unwrap();
        let mut damaged = original.clone();
        *damaged.last_mut().unwrap() ^= 1;
        fs::write(&last, damaged).unwrap();
        assert!(retained.inventory(&budget).is_err());
        fs::write(&last, &original).unwrap();
        fs::hard_link(&last, &held).unwrap();
        assert!(retained.inventory(&budget).is_err());
        fs::remove_file(&held).unwrap();
        assert_eq!(
            retained.inventory(&budget).unwrap().sorted.len(),
            source.len()
        );
        for mutation in 0..4 {
            let mut wrong = retained.clone();
            if let VertexIndex::Retained(rows) = &mut wrong {
                match mutation {
                    0 => rows.domain = [22; 32],
                    1 => Arc::make_mut(&mut rows.pages).swap(0, 1),
                    2 => rows.len -= 1,
                    _ => Arc::make_mut(&mut rows.pages)[0].first = key(1),
                }
            }
            assert!(wrong.inventory(&budget).is_err());
            assert!(wrong.materialize(Some(&budget)).is_err());
        }
        // A correctly retained/hash-bound leaf can still carry a bad permutation.
        let first = temp
            .path()
            .join("store")
            .join(format!("{}.obj", hex::encode(pages[0])));
        let mut bytes = fs::read(first).unwrap();
        bytes[HEADER + 32..HEADER + 40].copy_from_slice(&0_u64.to_le_bytes());
        let bad_id = store.retain_vertex_index_page(&bytes).unwrap();
        let mut wrong = retained.clone();
        if let VertexIndex::Retained(rows) = &mut wrong {
            Arc::make_mut(&mut rows.pages)[0].id = bad_id;
        }
        assert!(wrong.inventory(&budget).is_err());
        assert!(wrong.materialize(Some(&budget)).is_err());
        for position in [1, 129] {
            let mut wrong = source.clone();
            wrong.insert(key(0), position);
            assert!(
                VertexIndex::Resident(Arc::new(wrong))
                    .inventory(&budget)
                    .is_err()
            );
        }
    }
    #[test]
    fn operation_index_leaf_is_exact_bounded_and_does_not_hide_failed_target_reads() {
        let (temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        store.begin_replay(b"synthetic operation index").unwrap();
        let source = rows(129);
        let retained = VertexIndex::retain(&source, &mut store, [21; 32], &budget).unwrap();
        let mut operation = IndexOperation::new(&retained);
        for position in 0..64 {
            assert_eq!(
                operation.lookup(&key(position * 2), &budget).unwrap(),
                Some(128 - position)
            );
            assert_eq!(
                operation.lookup(&key(position * 2 + 1), &budget).unwrap(),
                None
            );
        }
        assert_eq!(operation.loads, 1);
        assert_eq!(operation.page.as_ref().unwrap().1.len(), 64);
        let pages = retained.retained_ids();
        let first = temp
            .path()
            .join("store")
            .join(format!("{}.obj", hex::encode(pages[0])));
        let first_held = first.with_extension("held");
        fs::rename(&first, &first_held).unwrap();
        // The old operation owns already checked bytes; no new operation or
        // publication inherits this positive snapshot after storage changes.
        assert_eq!(operation.lookup(&key(0), &budget).unwrap(), Some(128));
        assert!(
            IndexOperation::new(&retained)
                .lookup(&key(1), &budget)
                .is_err()
        );
        let second = temp
            .path()
            .join("store")
            .join(format!("{}.obj", hex::encode(pages[1])));
        let second_held = second.with_extension("held");
        let original = fs::read(&second).unwrap();
        fs::rename(&second, &second_held).unwrap();
        assert!(matches!(
            operation.lookup(&key(128), &budget),
            Err(Error::Io(_))
        ));
        assert!(operation.lookup(&key(129), &budget).is_err());
        assert_eq!(operation.loads, 1);
        fs::rename(&second_held, &second).unwrap();
        let mut damaged = original.clone();
        *damaged.last_mut().unwrap() ^= 1;
        fs::write(&second, damaged).unwrap();
        assert!(operation.lookup(&key(129), &budget).is_err());
        fs::write(&second, original).unwrap();
        fs::hard_link(&second, &second_held).unwrap();
        assert!(operation.lookup(&key(129), &budget).is_err());
        fs::remove_file(&second_held).unwrap();
        assert_eq!(operation.lookup(&key(128), &budget).unwrap(), Some(64));
        assert_eq!(operation.lookup(&key(129), &budget).unwrap(), None);
        assert_eq!(operation.loads, 2);
        assert!(operation.lookup(&key(0), &budget).is_err());
        fs::rename(&first_held, &first).unwrap();
        assert_eq!(operation.lookup(&key(0), &budget).unwrap(), Some(128));
        assert_eq!(operation.loads, 3);
        let expired = JobBudget::testing(std::time::Duration::ZERO).unwrap();
        assert!(matches!(
            operation.lookup(&key(0), &expired),
            Err(Error::Paused(_))
        ));
        assert_eq!(operation.loads, 3);
        assert_eq!(
            IndexOperation::new(&retained)
                .lookup(&key(260), &budget)
                .unwrap(),
            None
        );
        let resident = VertexIndex::Resident(Arc::new(source));
        let mut resident_read = IndexOperation::new(&resident);
        assert_eq!(resident_read.lookup(&key(128), &budget).unwrap(), Some(64));
        assert_eq!(resident_read.loads, 0);
    }
    #[test]
    fn disk_index_roundtrip_page_boundaries_horizon_detaches_and_anchors_directory() {
        let (temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        store.begin_replay(b"synthetic index storage rows").unwrap();
        let source = Arc::new(rows(HISTORY_LIMIT_V1));
        let weak = Arc::downgrade(&source);
        let resident = VertexIndex::Resident(source.clone());
        let retained = VertexIndex::retain(&source, &mut store, [21; 32], &budget).unwrap();
        assert_eq!(retained.retained_ids().len(), 64);
        assert_eq!(retained.materialize(Some(&budget)).unwrap(), *source);
        for position in [0, 63, 64, 127, 128, 4095] {
            assert_eq!(
                retained.lookup(&key(position * 2), Some(&budget)).unwrap(),
                Some(4095 - position)
            );
            assert_eq!(
                retained
                    .lookup(&key(position * 2 + 1), Some(&budget))
                    .unwrap(),
                None
            );
        }
        drop(resident);
        drop(source);
        assert!(weak.upgrade().is_none());
        fs::rename(temp.path().join("store"), temp.path().join("original")).unwrap();
        fs::create_dir(temp.path().join("store")).unwrap();
        assert_eq!(
            retained.lookup(&key(128), Some(&budget)).unwrap(),
            Some(4031)
        );
        assert!(VertexIndex::retain(&rows(4097), &mut store, [21; 32], &budget).is_err());
        let expired = JobBudget::testing(std::time::Duration::ZERO).unwrap();
        assert!(retained.lookup(&key(8193), Some(&expired)).is_err());
    }
    #[test]
    fn disk_index_missing_tampered_hardlinked_page_refuses_not_false_absence() {
        let (temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        store.begin_replay(b"synthetic index refusal").unwrap();
        let source = rows(129);
        let retained = VertexIndex::retain(&source, &mut store, [21; 32], &budget).unwrap();
        let pages = retained.retained_ids();
        let path = temp
            .path()
            .join("store")
            .join(format!("{}.obj", hex::encode(pages[1])));
        let held = path.with_extension("held");
        let original = fs::read(&path).unwrap();
        fs::rename(&path, &held).unwrap();
        assert!(matches!(
            retained.lookup(&key(128), Some(&budget)),
            Err(Error::Io(_))
        ));
        // An absent key INSIDE the damaged page's private range cannot be false.
        assert!(retained.lookup(&key(129), Some(&budget)).is_err());
        assert!(retained.materialize(Some(&budget)).is_err());
        // Unrelated page queries do not claim full-index integrity.
        assert_eq!(retained.lookup(&key(0), Some(&budget)).unwrap(), Some(128));
        fs::rename(&held, &path).unwrap();
        let mut changed = original.clone();
        *changed.last_mut().unwrap() ^= 1;
        fs::write(&path, changed).unwrap();
        assert!(retained.lookup(&key(128), Some(&budget)).is_err());
        fs::write(&path, original).unwrap();
        fs::hard_link(&path, &held).unwrap();
        assert!(retained.lookup(&key(129), Some(&budget)).is_err());
        fs::remove_file(&held).unwrap();
        assert_eq!(retained.materialize(Some(&budget)).unwrap(), source);
        assert_eq!(retained.retained_ids(), pages);
    }
    #[test]
    fn disk_index_forks_deduplicate_and_refuse_context_range_ordinal_or_permutation() {
        let (_temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        store.begin_replay(b"synthetic index forks").unwrap();
        let source = rows(129);
        let base = VertexIndex::retain(&source, &mut store, [21; 32], &budget).unwrap();
        let accounted = store.accounted_bytes();
        assert_eq!(
            VertexIndex::retain(&source, &mut store, [21; 32], &budget)
                .unwrap()
                .retained_ids(),
            base.retained_ids()
        );
        assert_eq!(store.accounted_bytes(), accounted);
        let mut left = source.clone();
        let mut right = source.clone();
        left.insert(key(258), 129);
        right.insert(key(260), 129);
        let left = VertexIndex::retain(&left, &mut store, [21; 32], &budget).unwrap();
        let right = VertexIndex::retain(&right, &mut store, [21; 32], &budget).unwrap();
        assert_eq!(&left.retained_ids()[..2], &base.retained_ids()[..2]);
        assert_eq!(&right.retained_ids()[..2], &base.retained_ids()[..2]);
        assert_ne!(left.retained_ids()[2], right.retained_ids()[2]);
        assert_eq!(base.materialize(Some(&budget)).unwrap(), source);
        for mutation in 0..4 {
            let mut wrong = base.clone();
            if let VertexIndex::Retained(rows) = &mut wrong {
                match mutation {
                    0 => rows.domain = [22; 32],
                    1 => Arc::make_mut(&mut rows.pages).swap(0, 1),
                    2 => rows.len -= 1,
                    _ => Arc::make_mut(&mut rows.pages)[0].first = key(1),
                }
            }
            assert!(wrong.materialize(Some(&budget)).is_err());
        }
        let mut wrong = source;
        wrong.insert(key(0), 1); // Duplicate ordinal, not a complete permutation.
        assert!(VertexIndex::retain(&wrong, &mut store, [21; 32], &budget).is_err());
    }
    #[test]
    fn disk_index_writer_requires_fence_and_damage_stops_without_head_fallback() {
        let (temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        store.commit(&[], b"synthetic previous head").unwrap();
        let head = store.commit(&[], b"synthetic current head").unwrap();
        let previous = fs::read(temp.path().join("store/PREVIOUS")).unwrap();
        assert!(VertexIndex::retain(&rows(1), &mut store, [21; 32], &budget).is_err());
        store.begin_job(b"synthetic verified transition").unwrap();
        let retained = VertexIndex::retain(&rows(1), &mut store, [21; 32], &budget).unwrap();
        let path = temp
            .path()
            .join("store")
            .join(format!("{}.obj", hex::encode(retained.retained_ids()[0])));
        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&path, bytes).unwrap();
        let error = VertexIndex::retain(&rows(1), &mut store, [21; 32], &budget)
            .err()
            .unwrap();
        assert!(matches!(
            error,
            Error::Unavailable("retained vertex index page damaged")
        ));
        assert!(!crate::node::storage_integrity_failure(&error));
        assert!(store.commit(&[], b"must not publish").is_err());
        assert_eq!(store.head(), Some(head));
        assert_eq!(
            fs::read(temp.path().join("store/PREVIOUS")).unwrap(),
            previous
        );
    }
}
