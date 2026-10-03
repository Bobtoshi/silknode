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
