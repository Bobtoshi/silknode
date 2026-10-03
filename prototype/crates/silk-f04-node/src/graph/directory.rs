//! Receiver-minted directory pages. These are live auxiliary addresses, never
//! a persisted/importable validity source. Crypto capabilities stay live only.
use super::ancestry::RetainedContext;
use crate::{
    Digest, Error, Result,
    budget::JobBudget,
    store::Store,
    sync::HISTORY_LIMIT_V1,
    wire::{u32le, u64le},
};
use silk_sapling_f04::crypto::LiveRepresentationBinding;
use std::sync::Arc;

pub(super) const SLOT: usize = 561;
const ITEMS: usize = 64;
const HEADER: usize = 52;
type Bindings = Arc<Vec<LiveRepresentationBinding>>;
type Decoder<V> = fn(&[u8], &Arc<RetainedContext>, Bindings) -> Result<Arc<V>>;
type Encoder<V> = fn(&V) -> Result<Vec<u8>>;
type Capabilities<V> = fn(&V) -> Bindings;

/// A single operation's owned, already hash-checked page, not graph authority.
/// The immutable directory borrow prevents reuse across publication or reopen.
pub(super) struct DirectoryOperation<'a, V> {
    directory: &'a VertexDirectory<V>,
    page: Option<(usize, Vec<Arc<V>>)>,
    #[cfg(test)]
    loads: usize,
}
impl<'a, V> DirectoryOperation<'a, V> {
    #[cfg(test)]
    pub(super) const fn loads(&self) -> usize {
        self.loads
    }
    pub(super) const fn new(directory: &'a VertexDirectory<V>) -> Self {
        Self {
            directory,
            page: None,
            #[cfg(test)]
            loads: 0,
        }
    }
    pub(super) fn load(&mut self, ordinal: usize, budget: &JobBudget) -> Result<Arc<V>> {
        budget.check()?;
        let VertexDirectory::Retained(rows, decode) = self.directory else {
            return self.directory.load(ordinal, Some(budget));
        };
        if ordinal >= rows.len {
            return Err(Error::Unavailable("operation directory ordinal"));
        }
        let page_ordinal = ordinal / ITEMS;
        if self
            .page
            .as_ref()
            .is_none_or(|(cached, _)| *cached != page_ordinal)
        {
            let bytes = VertexDirectory::<V>::page(rows, page_ordinal, Some(budget))?;
            let mut entries = Vec::with_capacity(rows.pages[page_ordinal].count);
            for (position, slot) in bytes[HEADER..].chunks_exact(SLOT).enumerate() {
                entries.push(decode(
                    slot,
                    &rows.reader,
                    rows.bindings[page_ordinal * ITEMS + position].clone(),
                )?);
            }
            budget.check()?;
            // Never cache a partial decode, an absence, or a failed read.
            self.page = Some((page_ordinal, entries));
            #[cfg(test)]
            {
                self.loads += 1;
            }
        }
        let vertex = self
            .page
            .as_ref()
            .and_then(|(_, entries)| entries.get(ordinal % ITEMS))
            .cloned()
            .ok_or(Error::Unavailable("operation directory slot"))?;
        budget.check()?;
        Ok(vertex)
    }
}

#[derive(Clone)]
struct Page {
    id: Digest,
    count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn encode(value: &u64) -> Result<Vec<u8>> {
        let mut slot = vec![0; SLOT];
        slot[..8].copy_from_slice(&value.to_le_bytes());
        Ok(slot)
    }
    fn capabilities(_: &u64) -> Bindings {
        Arc::new(Vec::new())
    }
    fn decode(bytes: &[u8], _: &Arc<RetainedContext>, bindings: Bindings) -> Result<Arc<u64>> {
        if bytes.len() != SLOT || bytes[8..].iter().any(|byte| *byte != 0) || !bindings.is_empty() {
            return Err(Error::Unavailable("synthetic directory slot"));
        }
        Ok(Arc::new(u64le(bytes, 0)?))
    }
    #[test]
    fn operation_page_reader_is_bounded_exact_and_does_not_cache_read_failures() {
        let (temp, mut store) = crate::store::ancestry_test_store();
        let reader = RetainedContext::new(store.object_reader().unwrap(), [7; 32]);
        let budget = JobBudget::checkpoint().unwrap();
        store
            .begin_replay(b"synthetic operation directory pages")
            .unwrap();
        let rows: Vec<_> = (0..65_u64).map(Arc::new).collect();
        let directory = VertexDirectory::retain(
            &rows,
            &mut store,
            reader,
            &budget,
            encode,
            capabilities,
            decode,
        )
        .unwrap();
        let mut operation = DirectoryOperation::new(&directory);
        for ordinal in 0..64 {
            assert_eq!(operation.load(ordinal, &budget).unwrap(), rows[ordinal]);
        }
        assert_eq!(operation.loads, 1);
        assert_eq!(operation.page.as_ref().unwrap().1.len(), 64);
        let first = temp
            .path()
            .join("store")
            .join(format!("{}.obj", hex::encode(directory.retained_ids()[0])));
        let first_held = first.with_extension("held");
        std::fs::rename(&first, &first_held).unwrap();
        // This operation owns its previously checked immutable snapshot, not
        // a fresh-read promise. A fresh operation cannot inherit it.
        assert_eq!(operation.load(0, &budget).unwrap(), rows[0]);
        assert!(
            DirectoryOperation::new(&directory)
                .load(0, &budget)
                .is_err()
        );
        let second = temp
            .path()
            .join("store")
            .join(format!("{}.obj", hex::encode(directory.retained_ids()[1])));
        let second_held = second.with_extension("held");
        std::fs::rename(&second, &second_held).unwrap();
        assert!(matches!(operation.load(64, &budget), Err(Error::Io(_))));
        assert_eq!(operation.loads, 1);
        std::fs::rename(&second_held, &second).unwrap();
        assert_eq!(operation.load(64, &budget).unwrap(), rows[64]);
        assert_eq!(operation.loads, 2);
        assert_eq!(operation.page.as_ref().unwrap().1.len(), 1);
        assert!(operation.load(0, &budget).is_err());
        std::fs::rename(&first_held, &first).unwrap();
        assert_eq!(operation.load(0, &budget).unwrap(), rows[0]);
        assert_eq!(operation.loads, 3);
        assert!(operation.load(65, &budget).is_err());
        let expired = JobBudget::testing(std::time::Duration::ZERO).unwrap();
        assert!(matches!(operation.load(0, &expired), Err(Error::Paused(_))));
        assert_eq!(operation.loads, 3);
        let cached = Arc::downgrade(&operation.load(0, &budget).unwrap());
        drop(operation);
        assert!(cached.upgrade().is_none());
    }
    #[test]
    fn incremental_directory_tail_append_matches_full_bytes_and_preserves_immutable_prefix() {
        let (temp, mut store) = crate::store::ancestry_test_store();
        let reader = RetainedContext::new(store.object_reader().unwrap(), [7; 32]);
        let budget = JobBudget::checkpoint().unwrap();
        store
            .begin_replay(b"synthetic incremental directory append")
            .unwrap();
        let mut directory = VertexDirectory::default();
        let mut rows = Vec::new();
        let mut first_page = None;
        for ordinal in 0..66_u64 {
            let old = directory.clone();
            let row = Arc::new(ordinal);
            rows.push(row.clone());
            directory = directory
                .append(
                    row,
                    &mut store,
                    reader.clone(),
                    &budget,
                    encode,
                    capabilities,
                    decode,
                )
                .unwrap();
            let full = VertexDirectory::retain(
                &rows,
                &mut store,
                reader.clone(),
                &budget,
                encode,
                capabilities,
                decode,
            )
            .unwrap();
            assert_eq!(directory.retained_ids(), full.retained_ids());
            assert_eq!(directory.materialize(Some(&budget)).unwrap(), rows);
            assert_eq!(
                old.materialize(Some(&budget)).unwrap(),
                rows[..rows.len() - 1]
            );
            if ordinal == 63 {
                first_page = Some(directory.retained_ids()[0]);
            }
            if ordinal >= 64 {
                assert_eq!(Some(directory.retained_ids()[0]), first_page);
            }
        }
        let old_ids = directory.retained_ids();
        let path = temp
            .path()
            .join("store")
            .join(format!("{}.obj", hex::encode(old_ids[1])));
        let held = path.with_extension("held");
        std::fs::rename(&path, &held).unwrap();
        let used = store.accounted_bytes();
        assert!(matches!(
            directory.append(
                Arc::new(66),
                &mut store,
                reader.clone(),
                &budget,
                encode,
                capabilities,
                decode
            ),
            Err(Error::Io(_))
        ));
        assert_eq!(directory.retained_ids(), old_ids);
        assert_eq!(directory.len(), 66);
        assert_eq!(store.accounted_bytes(), used);
        std::fs::rename(&held, &path).unwrap();
        let wrong = RetainedContext::new(store.object_reader().unwrap(), [7; 32]);
        assert!(
            directory
                .append(
                    Arc::new(66),
                    &mut store,
                    wrong,
                    &budget,
                    encode,
                    capabilities,
                    decode
                )
                .is_err()
        );
        assert_eq!(store.accounted_bytes(), used);
        let max: Vec<_> = (0..HISTORY_LIMIT_V1).map(|n| Arc::new(n as u64)).collect();
        let max_directory = VertexDirectory::retain(
            &max,
            &mut store,
            reader.clone(),
            &budget,
            encode,
            capabilities,
            decode,
        )
        .unwrap();
        let used = store.accounted_bytes();
        assert!(matches!(
            max_directory.append(
                Arc::new(HISTORY_LIMIT_V1 as u64),
                &mut store,
                reader,
                &budget,
                encode,
                capabilities,
                decode
            ),
            Err(Error::Paused(_))
        ));
        assert_eq!(store.accounted_bytes(), used);
    }
    #[test]
    fn disk_directory_pages_boundaries_horizon_and_live_shape_are_exact() {
        let (_temp, mut store) = crate::store::ancestry_test_store();
        let reader = RetainedContext::new(store.object_reader().unwrap(), [7; 32]);
        let budget = JobBudget::checkpoint().unwrap();
        store
            .begin_replay(b"synthetic directory boundary test")
            .unwrap();
        for count in [0, 1, 63, 64, 65, HISTORY_LIMIT_V1] {
            let rows: Vec<_> = (0..count).map(|n| Arc::new(n as u64)).collect();
            let directory = VertexDirectory::retain(
                &rows,
                &mut store,
                reader.clone(),
                &budget,
                encode,
                capabilities,
                decode,
            )
            .unwrap();
            assert_eq!(directory.retained_ids().len(), count.div_ceil(ITEMS));
            assert_eq!(directory.materialize(Some(&budget)).unwrap(), rows);
            for ordinal in [0, 63, 64, count.saturating_sub(1)]
                .into_iter()
                .filter(|n| *n < count)
            {
                assert_eq!(
                    *directory.load(ordinal, Some(&budget)).unwrap(),
                    ordinal as u64
                );
            }
            assert!(directory.load(count, Some(&budget)).is_err());
            if count > 0 {
                let VertexDirectory::Retained(mut broken, decoder) = directory.clone() else {
                    panic!("retained directory");
                };
                Arc::make_mut(&mut broken.pages)[0].count = 0;
                assert!(
                    VertexDirectory::Retained(broken, decoder)
                        .materialize(Some(&budget))
                        .is_err()
                );
                let VertexDirectory::Retained(mut broken, decoder) = directory else {
                    panic!("retained directory");
                };
                Arc::make_mut(&mut broken.bindings).pop();
                assert!(
                    VertexDirectory::Retained(broken, decoder)
                        .load(0, Some(&budget))
                        .is_err()
                );
            }
        }
        let rows = vec![Arc::new(0); HISTORY_LIMIT_V1 + 1];
        assert!(matches!(
            VertexDirectory::retain(
                &rows,
                &mut store,
                reader,
                &budget,
                encode,
                capabilities,
                decode
            ),
            Err(Error::Paused(_))
        ));
    }
    #[test]
    fn disk_directory_owned_pages_refuse_tamper_links_missing_and_wrong_context() {
        let (temp, mut store) = crate::store::ancestry_test_store();
        let reader = RetainedContext::new(store.object_reader().unwrap(), [7; 32]);
        let budget = JobBudget::checkpoint().unwrap();
        store
            .begin_replay(b"synthetic directory refusal test")
            .unwrap();
        let rows = vec![Arc::new(12), Arc::new(19)];
        let directory = VertexDirectory::retain(
            &rows,
            &mut store,
            reader,
            &budget,
            encode,
            capabilities,
            decode,
        )
        .unwrap();
        let path = temp
            .path()
            .join("store")
            .join(format!("{}.obj", hex::encode(directory.retained_ids()[0])));
        let original = std::fs::read(&path).unwrap();
        let mut changed = original.clone();
        *changed.last_mut().unwrap() ^= 1;
        std::fs::write(&path, changed).unwrap();
        assert!(directory.load(0, Some(&budget)).is_err());
        assert!(directory.materialize(Some(&budget)).is_err());
        std::fs::write(&path, original).unwrap();
        let held = path.with_extension("held");
        std::fs::hard_link(&path, &held).unwrap();
        assert!(directory.load(1, Some(&budget)).is_err());
        std::fs::remove_file(&held).unwrap();
        std::fs::rename(&path, &held).unwrap();
        assert!(matches!(
            directory.load(0, Some(&budget)),
            Err(Error::Io(_))
        ));
        std::fs::rename(&held, &path).unwrap();
        let VertexDirectory::Retained(mut broken, decoder) = directory.clone() else {
            panic!("retained directory");
        };
        broken.reader = RetainedContext::new(store.object_reader().unwrap(), [8; 32]);
        assert!(
            VertexDirectory::Retained(broken, decoder)
                .load(0, Some(&budget))
                .is_err()
        );
        assert_eq!(directory.materialize(Some(&budget)).unwrap(), rows);
        let held_dir = temp.path().join("held-store");
        std::fs::rename(temp.path().join("store"), &held_dir).unwrap();
        // The owned directory descriptor stays anchored to the original inode,
        // not a substituted pathname. It may still read its immutable original.
        std::fs::create_dir(temp.path().join("store")).unwrap();
        let substitute = temp.path().join("store").join(path.file_name().unwrap());
        std::fs::write(&substitute, b"not the anchored object").unwrap();
        assert_eq!(directory.materialize(Some(&budget)).unwrap(), rows);
        std::fs::remove_file(substitute).unwrap();
        std::fs::remove_dir(temp.path().join("store")).unwrap();
        std::fs::rename(&held_dir, temp.path().join("store")).unwrap();
        assert_eq!(directory.materialize(Some(&budget)).unwrap(), rows);
    }
}
pub(super) enum VertexDirectory<V> {
    Resident(Vec<Arc<V>>),
    Retained(RetainedDirectory, Decoder<V>),
}
#[derive(Clone)]
pub(super) struct RetainedDirectory {
    pages: Arc<Vec<Page>>,
    len: usize,
    // These opaque verifier capabilities are NEVER encoded/decoded in a page.
    bindings: Arc<Vec<Bindings>>,
    reader: Arc<RetainedContext>,
}
impl<V> Default for VertexDirectory<V> {
    fn default() -> Self {
        Self::Resident(Vec::new())
    }
}
impl<V> Clone for VertexDirectory<V> {
    fn clone(&self) -> Self {
        match self {
            Self::Resident(rows) => Self::Resident(rows.clone()),
            Self::Retained(rows, decode) => Self::Retained(rows.clone(), *decode),
        }
    }
}
impl<V> VertexDirectory<V> {
    fn page(
        rows: &RetainedDirectory,
        ordinal: usize,
        budget: Option<&JobBudget>,
    ) -> Result<Vec<u8>> {
        if let Some(budget) = budget {
            budget.check()?;
        }
        if rows.len > HISTORY_LIMIT_V1
            || rows.bindings.len() != rows.len
            || rows.pages.len() != rows.len.div_ceil(ITEMS)
        {
            return Err(Error::Unavailable(
                "retained vertex directory horizon or shape",
            ));
        }
        let page = rows
            .pages
            .get(ordinal)
            .ok_or(Error::Unavailable("retained vertex directory page absent"))?;
        let expected = (rows.len - ordinal * ITEMS).min(ITEMS);
        if page.count != expected || !(1..=ITEMS).contains(&page.count) {
            return Err(Error::Unavailable("retained vertex directory count"));
        }
        if let Some(budget) = budget {
            budget.source()?;
        }
        let size = HEADER + page.count * SLOT;
        let bytes = rows.reader.objects().object(page.id, size)?;
        if bytes.len() != size
            || bytes.get(..8) != Some(b"SNF04DP1")
            || bytes[8..40] != rows.reader.domain()
            || u64le(&bytes, 40)? != ordinal as u64
            || u32le(&bytes, 48)? as usize != page.count
        {
            return Err(Error::Unavailable("retained vertex directory binding"));
        }
        Ok(bytes)
    }
    pub(super) const fn len(&self) -> usize {
        match self {
            Self::Resident(rows) => rows.len(),
            Self::Retained(rows, _) => rows.len,
        }
    }
    pub(super) const fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub(super) fn borrowed(&self, ordinal: usize) -> Result<&V> {
        match self {
            Self::Resident(rows) => rows
                .get(ordinal)
                .map(AsRef::as_ref)
                .ok_or(Error::Unavailable("missing resident vertex ordinal")),
            Self::Retained(..) => Err(Error::Unavailable("durable vertex requires owned lookup")),
        }
    }
    pub(super) fn borrowed_iter(&self) -> impl Iterator<Item = &Arc<V>> {
        let Self::Resident(rows) = self else {
            // The externally constructible Graph alias always owns resident rows.
            panic!("public borrowed graph iteration requires resident entries");
        };
        rows.iter()
    }
    pub(super) fn push_resident(&mut self, row: Arc<V>) -> Result<()> {
        let Self::Resident(rows) = self else {
            return Err(Error::Unavailable(
                "resident insertion into durable directory",
            ));
        };
        rows.push(row);
        Ok(())
    }
    pub(super) fn load(&self, ordinal: usize, budget: Option<&JobBudget>) -> Result<Arc<V>> {
        if let Some(budget) = budget {
            budget.check()?;
        }
        match self {
            Self::Resident(rows) => rows
                .get(ordinal)
                .cloned()
                .ok_or(Error::Unavailable("missing resident vertex ordinal")),
            Self::Retained(rows, decode) => {
                if ordinal >= rows.len {
                    return Err(Error::Unavailable(
                        "retained vertex directory horizon or ordinal",
                    ));
                }
                let page_ordinal = ordinal / ITEMS;
                let bytes = Self::page(rows, page_ordinal, budget)?;
                let position = ordinal % ITEMS;
                let start = HEADER + position * SLOT;
                let row = decode(
                    &bytes[start..start + SLOT],
                    &rows.reader,
                    rows.bindings[ordinal].clone(),
                )?;
                if let Some(budget) = budget {
                    budget.check()?;
                }
                Ok(row)
            }
        }
    }
    pub(super) fn materialize(&self, budget: Option<&JobBudget>) -> Result<Vec<Arc<V>>> {
        if let Some(budget) = budget {
            budget.check()?;
        }
        match self {
            Self::Resident(rows) => Ok(rows.clone()),
            Self::Retained(rows, decode) => {
                if rows.len > HISTORY_LIMIT_V1
                    || rows.bindings.len() != rows.len
                    || rows.pages.len() != rows.len.div_ceil(ITEMS)
                {
                    return Err(Error::Unavailable("retained vertex directory shape"));
                }
                let mut entries = Vec::with_capacity(rows.len);
                for ordinal in 0..rows.pages.len() {
                    let bytes = Self::page(rows, ordinal, budget)?;
                    for (position, slot) in bytes[HEADER..].chunks_exact(SLOT).enumerate() {
                        entries.push(decode(
                            slot,
                            &rows.reader,
                            rows.bindings[ordinal * ITEMS + position].clone(),
                        )?);
                    }
                    if let Some(budget) = budget {
                        budget.check()?;
                    }
                }
                Ok(entries)
            }
        }
    }
    /// Called only with fully receiver-derived typed rows under the original fence.
    // Keep the closed private codec callbacks out of the public GraphEntry API.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn append(
        &self,
        row: Arc<V>,
        store: &mut Store,
        reader: Arc<RetainedContext>,
        budget: &JobBudget,
        encode: Encoder<V>,
        capabilities: Capabilities<V>,
        decode: Decoder<V>,
    ) -> Result<Self> {
        budget.check()?;
        if self.len() >= HISTORY_LIMIT_V1 {
            return Err(Error::Paused("vertex directory reference horizon"));
        }
        let Self::Retained(old, _) = self else {
            if !self.is_empty() {
                return Err(Error::Unavailable("nonempty resident directory append"));
            }
            return Self::retain(&[row], store, reader, budget, encode, capabilities, decode);
        };
        if !Arc::ptr_eq(&old.reader, &reader)
            || old.bindings.len() != old.len
            || old.pages.len() != old.len.div_ceil(ITEMS)
        {
            return Err(Error::Unavailable("directory append live context or shape"));
        }
        let ordinal = old.len / ITEMS;
        let count = old.len % ITEMS;
        let mut bytes = Vec::with_capacity(HEADER + (count + 1) * SLOT);
        bytes.extend_from_slice(b"SNF04DP1");
        bytes.extend_from_slice(&reader.domain());
        bytes.extend_from_slice(&(ordinal as u64).to_le_bytes());
        bytes.extend_from_slice(
            &u32::try_from(count + 1)
                .map_err(|_| Error::Unavailable("directory append count"))?
                .to_le_bytes(),
        );
        if count != 0 {
            let tail = Self::page(old, ordinal, Some(budget))?;
            // Own and hash-check the complete tail once. The prefix is copied
            // byte-for-byte, never re-encoded from a new validity assertion.
            bytes.extend_from_slice(&tail[HEADER..]);
        }
        let slot = encode(&row)?;
        if slot.len() != SLOT {
            return Err(Error::Unavailable("directory append slot length"));
        }
        bytes.extend_from_slice(&slot);
        budget.source()?;
        let page = Page {
            id: store.retain_vertex_directory_page(&bytes)?,
            count: count + 1,
        };
        let mut pages = old.pages.as_ref().clone();
        if count == 0 {
            pages.push(page);
        } else {
            pages[ordinal] = page;
        }
        let mut bindings = old.bindings.as_ref().clone();
        bindings.push(capabilities(&row));
        budget.check()?;
        Ok(Self::Retained(
            RetainedDirectory {
                pages: Arc::new(pages),
                len: old.len + 1,
                bindings: Arc::new(bindings),
                reader,
            },
            decode,
        ))
    }
    /// Full receiver-derived construction used for initial publication and codec checks.
    pub(super) fn retain(
        rows: &[Arc<V>],
        store: &mut Store,
        reader: Arc<RetainedContext>,
        budget: &JobBudget,
        encode: Encoder<V>,
        capabilities: Capabilities<V>,
        decode: Decoder<V>,
    ) -> Result<Self> {
        if rows.len() > HISTORY_LIMIT_V1 {
            return Err(Error::Paused("vertex directory reference horizon"));
        }
        let mut pages = Vec::with_capacity(rows.len().div_ceil(ITEMS));
        let mut bindings = Vec::with_capacity(rows.len());
        for (ordinal, chunk) in rows.chunks(ITEMS).enumerate() {
            budget.check()?;
            let mut bytes = Vec::with_capacity(HEADER + chunk.len() * SLOT);
            bytes.extend_from_slice(b"SNF04DP1");
            bytes.extend_from_slice(&reader.domain());
            bytes.extend_from_slice(&(ordinal as u64).to_le_bytes());
            bytes.extend_from_slice(
                &u32::try_from(chunk.len())
                    .map_err(|_| Error::Unavailable("derived vertex directory count"))?
                    .to_le_bytes(),
            );
            for row in chunk {
                let slot = encode(row)?;
                if slot.len() != SLOT {
                    return Err(Error::Unavailable("derived vertex directory slot length"));
                }
                bytes.extend_from_slice(&slot);
                bindings.push(capabilities(row));
            }
            budget.source()?;
            pages.push(Page {
                id: store.retain_vertex_directory_page(&bytes)?,
                count: chunk.len(),
            });
        }
        budget.check()?;
        Ok(Self::Retained(
            RetainedDirectory {
                pages: Arc::new(pages),
                len: rows.len(),
                bindings: Arc::new(bindings),
                reader,
            },
            decode,
        ))
    }
    pub(super) fn into_retained(self) -> Result<RetainedDirectory> {
        match self {
            Self::Retained(rows, _) => Ok(rows),
            Self::Resident(_) => Err(Error::Unavailable("staged directory is resident")),
        }
    }
    pub(super) fn from_retained(rows: RetainedDirectory, decode: Decoder<V>) -> Self {
        Self::Retained(rows, decode)
    }
    #[cfg(test)]
    pub(super) fn retained_ids(&self) -> Vec<Digest> {
        match self {
            Self::Resident(_) => Vec::new(),
            Self::Retained(rows, _) => rows.pages.iter().map(|page| page.id).collect(),
        }
    }
}
