//! Live receiver-derived recovery pages; never decoded as persisted validity.
use super::sequence::PagedSequence;
use crate::{
    Digest, Error, Result,
    budget::JobBudget,
    store::{ObjectReader, Store},
    wire::{u32le, u64le},
};
use silk_sapling_f04::codec::RECOVERY_BYTES;
use std::sync::Arc;

const ROWS: usize = 64;
const HEADER: usize = 52;
#[derive(Clone)]
struct Page {
    id: Digest,
    count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(count: usize) -> RecoveryHistory {
        // Synthetic encrypted-row storage model ONLY, not real admitted notes.
        let mut rows = RecoveryHistory::new(256);
        for position in 0..count {
            let mut row = [0; RECOVERY_BYTES];
            row[..8].copy_from_slice(&(position as u64).to_le_bytes());
            rows.push(Arc::new(row)).unwrap();
        }
        rows
    }
    #[test]
    fn disk_recovery_unfenced_or_uncertain_write_stops_without_directory_or_head_credit() {
        use std::os::unix::fs::PermissionsExt;
        let (temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        let rows = fixture(1);
        let accounted = store.accounted_bytes();
        assert!(rows.retain(&mut store, [19; 32], &budget).is_err());
        assert_eq!(store.accounted_bytes(), accounted);
        assert_eq!(store.head(), None);
        store
            .begin_replay(b"synthetic recovery write refusal")
            .unwrap();
        let root = temp.path().join("store");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o500)).unwrap();
        assert!(matches!(
            rows.retain(&mut store, [19; 32], &budget),
            Err(Error::Unavailable(
                "retained recovery page publication failed"
            ))
        ));
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(store.head(), None);
        assert!(matches!(
            store.check_external_write(1),
            Err(Error::Unavailable(
                "store requires reopen after failed write"
            ))
        ));
        assert_eq!(rows.len(), 1);
    }
    #[test]
    fn disk_recovery_detaches_rows_and_preserves_exact_positions_and_held_directory() {
        let (_temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        store
            .begin_replay(b"synthetic recovery page fixture")
            .unwrap();
        let rows = fixture(129);
        let weak = Arc::downgrade(rows.get(64).unwrap());
        let retained = rows.retain(&mut store, [19; 32], &budget).unwrap();
        let head = store.head();
        assert_eq!(retained.retained_ids().len(), 3);
        assert_eq!(retained.cache_charge(), rows.cache_charge());
        let expected = rows.iter().map(|row| **row).collect::<Vec<_>>();
        drop(rows);
        assert!(weak.upgrade().is_none());
        let restored = retained.materialize(Some(&budget)).unwrap();
        assert_eq!(
            restored.iter().map(|row| **row).collect::<Vec<_>>(),
            expected
        );
        assert!(restored.get(129).is_none());
        assert!(restored.get(usize::MAX).is_none());
        assert_eq!(store.head(), head);
        drop(store);
        assert_eq!(
            retained
                .materialize(Some(&budget))
                .unwrap()
                .iter()
                .map(|row| **row)
                .collect::<Vec<_>>(),
            expected
        );
    }
    #[test]
    fn disk_recovery_missing_tampered_or_hardlinked_page_refuses_complete_materialization() {
        let (temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        store
            .begin_replay(b"synthetic recovery refusal fixture")
            .unwrap();
        let rows = fixture(129);
        let retained = rows.retain(&mut store, [19; 32], &budget).unwrap();
        let ids = retained.retained_ids();
        let path = temp
            .path()
            .join("store")
            .join(format!("{}.obj", hex::encode(ids[2])));
        let held = path.with_extension("held");
        let bytes = std::fs::read(&path).unwrap();
        let head = store.head();
        std::fs::rename(&path, &held).unwrap();
        assert!(matches!(
            retained.materialize(Some(&budget)),
            Err(Error::Io(_))
        ));
        assert_eq!(retained.retained_ids(), ids);
        assert_eq!(retained.len(), 129);
        assert_eq!(store.head(), head);
        std::fs::rename(&held, &path).unwrap();
        let mut changed = bytes.clone();
        *changed.last_mut().unwrap() ^= 1;
        std::fs::write(&path, changed).unwrap();
        assert!(retained.materialize(Some(&budget)).is_err());
        std::fs::write(&path, &bytes).unwrap();
        std::fs::hard_link(&path, &held).unwrap();
        assert!(retained.materialize(Some(&budget)).is_err());
        std::fs::remove_file(&held).unwrap();
        assert_eq!(
            retained.materialize(Some(&budget)).unwrap().as_slice(),
            rows.as_slice()
        );
        assert_eq!(store.head(), head);
    }
    #[test]
    fn disk_recovery_fork_reuses_full_pages_and_keeps_distinct_tails_and_context() {
        let (_temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        store.begin_replay(b"synthetic recovery forks").unwrap();
        let base = fixture(129).retain(&mut store, [19; 32], &budget).unwrap();
        let mut left = base.materialize(Some(&budget)).unwrap();
        let mut right = base.materialize(Some(&budget)).unwrap();
        left.push(Arc::new([1; RECOVERY_BYTES])).unwrap();
        right.push(Arc::new([2; RECOVERY_BYTES])).unwrap();
        let left = left.retain(&mut store, [19; 32], &budget).unwrap();
        let right = right.retain(&mut store, [19; 32], &budget).unwrap();
        assert_eq!(&base.retained_ids()[..2], &left.retained_ids()[..2]);
        assert_eq!(&base.retained_ids()[..2], &right.retained_ids()[..2]);
        assert_ne!(left.retained_ids()[2], right.retained_ids()[2]);
        assert_ne!(base.retained_ids()[2], left.retained_ids()[2]);
        assert_eq!(base.len(), 129);
        let accounted = store.accounted_bytes();
        assert!(left.retain(&mut store, [20; 32], &budget).is_err());
        assert_eq!(store.accounted_bytes(), accounted);
        assert_eq!(
            left.materialize(Some(&budget))
                .unwrap()
                .get(129)
                .unwrap()
                .as_slice(),
            &[1; RECOVERY_BYTES]
        );
        assert_eq!(
            right
                .materialize(Some(&budget))
                .unwrap()
                .get(129)
                .unwrap()
                .as_slice(),
            &[2; RECOVERY_BYTES]
        );
    }
}
#[derive(Clone)]
pub(super) struct Retained {
    pages: Arc<Vec<Page>>,
    len: usize,
    limit: usize,
    domain: Digest,
    reader: Arc<ObjectReader>,
}
#[derive(Clone)]
pub(super) enum RecoveryHistory {
    Resident(PagedSequence<Arc<[u8; RECOVERY_BYTES]>>),
    Retained(Retained),
}
impl RecoveryHistory {
    pub(super) const fn new(limit: usize) -> Self {
        Self::Resident(PagedSequence::new(limit))
    }
    pub(super) const fn len(&self) -> usize {
        match self {
            Self::Resident(rows) => rows.len(),
            Self::Retained(rows) => rows.len,
        }
    }
    #[cfg(test)]
    pub(super) fn is_materialized(&self) -> bool {
        match self {
            Self::Resident(rows) => rows.is_materialized(),
            Self::Retained(_) => false,
        }
    }
    #[cfg(test)]
    pub(super) fn retained_ids(&self) -> Vec<Digest> {
        match self {
            Self::Resident(_) => Vec::new(),
            Self::Retained(rows) => rows.pages.iter().map(|page| page.id).collect(),
        }
    }
    pub(super) fn resident(&self) -> &PagedSequence<Arc<[u8; RECOVERY_BYTES]>> {
        match self {
            Self::Resident(rows) => rows,
            // Public BranchState values are genesis/materialized snapshots.
            // Internal retained state must use the explicit fallible loader.
            Self::Retained(_) => panic!("borrowed recovery access requires materialized snapshot"),
        }
    }
    pub(super) fn get(&self, index: usize) -> Option<&Arc<[u8; RECOVERY_BYTES]>> {
        self.resident().get(index)
    }
    pub(super) fn iter(&self) -> impl Iterator<Item = &Arc<[u8; RECOVERY_BYTES]>> {
        self.resident().iter()
    }
    pub(super) fn as_slice(&self) -> &[Arc<[u8; RECOVERY_BYTES]>] {
        self.resident().as_slice()
    }
    pub(super) fn push(&mut self, row: Arc<[u8; RECOVERY_BYTES]>) -> Result<()> {
        match self {
            Self::Resident(rows) => rows.push(row),
            Self::Retained(_) => Err(Error::Unavailable(
                "materialize recovery before reducer mutation",
            )),
        }
    }
    pub(super) const fn cache_charge(&self) -> usize {
        match self {
            Self::Resident(rows) => rows.cache_charge(),
            // Charge directory and the complete possible materialized view;
            // BranchState separately charges ciphertext bytes conservatively.
            Self::Retained(rows) => {
                rows.len.div_ceil(ROWS)
                    * (ROWS * std::mem::size_of::<Arc<[u8; RECOVERY_BYTES]>>() + 128)
                    + rows.len * std::mem::size_of::<Arc<[u8; RECOVERY_BYTES]>>()
            }
        }
    }
    pub(super) fn materialize(&self, budget: Option<&JobBudget>) -> Result<Self> {
        let Self::Retained(retained) = self else {
            return Ok(self.clone());
        };
        let mut rows = PagedSequence::new(retained.limit);
        for (ordinal, page) in retained.pages.iter().enumerate() {
            if let Some(budget) = budget {
                budget.check()?;
                budget.source()?;
            }
            let size = HEADER
                .checked_add(
                    page.count
                        .checked_mul(RECOVERY_BYTES)
                        .ok_or(Error::Unavailable("retained recovery page size"))?,
                )
                .ok_or(Error::Unavailable("retained recovery page size"))?;
            let bytes = retained.reader.object(page.id, size)?;
            if bytes.len() != size
                || bytes.get(..8) != Some(b"SNF04RP1")
                || bytes[8..40] != retained.domain
                || u64le(&bytes, 40)? != ordinal as u64
                || u32le(&bytes, 48)? as usize != page.count
                || !(1..=ROWS).contains(&page.count)
                || ordinal + 1 < retained.pages.len() && page.count != ROWS
            {
                return Err(Error::Unavailable("retained recovery page binding"));
            }
            for row in bytes[HEADER..].chunks_exact(RECOVERY_BYTES) {
                rows.push(Arc::new(
                    row.try_into()
                        .map_err(|_| Error::Unavailable("retained recovery row"))?,
                ))?;
            }
        }
        if rows.len() != retained.len {
            return Err(Error::Unavailable("retained recovery directory length"));
        }
        if let Some(budget) = budget {
            budget.check()?;
        }
        Ok(Self::Resident(rows))
    }
    /// Private hash staging only; no digest/result can escape before the final
    /// complete page/length check. At most one ciphertext page is owned here.
    pub(super) fn visit_encoded(
        &self,
        budget: Option<&JobBudget>,
        visit: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        let check = || budget.map_or(Ok(()), JobBudget::check);
        check()?;
        let Self::Retained(rows) = self else {
            for (position, row) in self.resident().iter().enumerate() {
                if position % ROWS == 0 {
                    check()?;
                }
                visit(row.as_slice())?;
            }
            return check();
        };
        if rows.len > rows.limit || rows.pages.len() != rows.len.div_ceil(ROWS) {
            return Err(Error::Unavailable("retained recovery directory length"));
        }
        for (ordinal, page) in rows.pages.iter().enumerate() {
            check()?;
            if page.count != (rows.len - ordinal * ROWS).min(ROWS) {
                return Err(Error::Unavailable("retained recovery page binding"));
            }
            if let Some(budget) = budget {
                budget.source()?;
            }
            let size = HEADER + page.count * RECOVERY_BYTES;
            let bytes = rows.reader.object(page.id, size)?;
            if bytes.len() != size
                || bytes.get(..8) != Some(b"SNF04RP1")
                || bytes[8..40] != rows.domain
                || u64le(&bytes, 40)? != ordinal as u64
                || u32le(&bytes, 48)? as usize != page.count
            {
                return Err(Error::Unavailable("retained recovery page binding"));
            }
            for row in bytes[HEADER..].chunks_exact(RECOVERY_BYTES) {
                visit(row)?;
            }
        }
        check()
    }
    pub(super) fn retain(
        &self,
        store: &mut Store,
        domain: Digest,
        budget: &JobBudget,
    ) -> Result<Self> {
        if let Self::Retained(retained) = self {
            if retained.domain != domain {
                return Err(Error::Unavailable("retained recovery context"));
            }
            return Ok(self.clone());
        }
        let rows = self.resident();
        let mut pages = Vec::with_capacity(rows.len().div_ceil(ROWS));
        let mut iter = rows.iter();
        loop {
            budget.check()?;
            let mut bytes = Vec::with_capacity(HEADER + ROWS * RECOVERY_BYTES);
            bytes.extend_from_slice(b"SNF04RP1");
            bytes.extend_from_slice(&domain);
            bytes.extend_from_slice(&(pages.len() as u64).to_le_bytes());
            bytes.extend_from_slice(&[0; 4]);
            let mut count = 0_u32;
            for row in iter.by_ref().take(ROWS) {
                bytes.extend_from_slice(row.as_slice());
                count += 1;
            }
            if count == 0 {
                break;
            }
            bytes[48..52].copy_from_slice(&count.to_le_bytes());
            budget.source()?;
            pages.push(Page {
                id: store.retain_recovery_page(&bytes)?,
                count: count as usize,
            });
        }
        // Install no directory until EVERY page is durably retained. This live
        // directory is derived from reducer bytes, never restored from a flag.
        Ok(Self::Retained(Retained {
            pages: Arc::new(pages),
            len: rows.len(),
            limit: rows.limit(),
            domain,
            reader: store.object_reader()?,
        }))
    }
}
