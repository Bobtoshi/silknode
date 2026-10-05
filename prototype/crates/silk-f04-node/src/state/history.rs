//! Receiver-derived disk histories; no received-state or persisted validity API.
use super::{AcceptedOutputs, sequence::PagedSequence};
use crate::{
    Digest, Error, Result,
    budget::JobBudget,
    store::{ObjectReader, Store},
    wire::{u32le, u64le},
};
use silk_types::VertexId;
use std::{marker::PhantomData, sync::Arc};

const ITEMS: usize = 64;
const HEADER: usize = 52;
// Private closed codecs. Only freshly derived live states retain page references.
pub(super) trait Item: Clone {
    const MAGIC: [u8; 8];
    const WIDTH: usize;
    fn encode(&self, bytes: &mut Vec<u8>);
    fn decode(bytes: &[u8]) -> Result<Self>;
    fn retain_page(store: &mut Store, bytes: &[u8]) -> Result<Digest> {
        store.retain_ledger_history_page(bytes)
    }
    fn validate_encoded(bytes: &[u8]) -> Result<()> {
        Self::decode(bytes).map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retained_appends_match_literal_pages_for_all_four_codecs_and_refuse_old_tail() {
        fn check<T: Item + PartialEq>(rows: Vec<T>) {
            let (temp, mut store) = crate::store::ancestry_test_store();
            let budget = JobBudget::checkpoint().unwrap();
            store.begin_replay(b"synthetic retained append").unwrap();
            let mut literal = LedgerHistory::new(256);
            for row in &rows[..129] {
                literal.push(row.clone()).unwrap();
            }
            let base = literal.retain(&mut store, [19; 32], &budget).unwrap();
            let ids = base.retained_ids();
            let mut staged = base.clone();
            for row in &rows[129..] {
                staged.push(row.clone()).unwrap();
                literal.push(row.clone()).unwrap();
            }
            assert_eq!(staged.retained_ids(), ids);
            assert_eq!(base.len(), 129);
            assert!(!staged.is_materialized());
            assert!(
                staged
                    .materialize(Some(&budget))
                    .unwrap()
                    .iter()
                    .eq(literal.iter())
            );
            let stored = staged.retain(&mut store, [19; 32], &budget).unwrap();
            let oracle = literal.retain(&mut store, [19; 32], &budget).unwrap();
            assert_eq!(stored.retained_ids(), oracle.retained_ids());
            assert_eq!(&stored.retained_ids()[..2], &ids[..2]);
            assert_ne!(stored.retained_ids()[2], ids[2]);
            let path = temp
                .path()
                .join("store")
                .join(format!("{}.obj", hex::encode(ids[2])));
            let held = path.with_extension("held");
            std::fs::rename(&path, &held).unwrap();
            assert!(staged.materialize(Some(&budget)).is_err());
            assert!(staged.retain(&mut store, [19; 32], &budget).is_err());
            std::fs::rename(&held, &path).unwrap();
            assert_eq!(
                staged
                    .retain(&mut store, [19; 32], &budget)
                    .unwrap()
                    .retained_ids(),
                oracle.retained_ids()
            );
            assert!(staged.retain(&mut store, [20; 32], &budget).is_err());
            assert_eq!(store.head(), None);
        }
        check(
            (0..193_u16)
                .map(|index| {
                    let mut id = [0; 32];
                    id[..2].copy_from_slice(&index.to_le_bytes());
                    VertexId::from_bytes(id)
                })
                .collect(),
        );
        check(
            (0..193_u16)
                .map(|index| {
                    let mut row = [0; 112];
                    row[..2].copy_from_slice(&index.to_le_bytes());
                    row
                })
                .collect(),
        );
        check(
            (0..193_u16)
                .map(|index| {
                    Arc::new(AcceptedOutputs {
                        effect: [index as u8; 32],
                        first_position: u64::from(index) * 2,
                        commitments: [[1; 32], [2; 32]],
                    })
                })
                .collect(),
        );
        check(
            (0..193_u16)
                .map(|index| {
                    let mut row = [0; silk_sapling_f04::codec::RECOVERY_BYTES];
                    row[..2].copy_from_slice(&index.to_le_bytes());
                    Arc::new(row)
                })
                .collect(),
        );
    }
    fn links(count: usize) -> LedgerHistory<Arc<AcceptedOutputs>> {
        // Synthetic storage rows ONLY, not accepted economic effects.
        let mut rows = LedgerHistory::new(256);
        for position in 0..count {
            rows.push(Arc::new(AcceptedOutputs {
                effect: [position as u8; 32],
                first_position: position as u64 * 2,
                commitments: [[1; 32], [2; 32]],
            }))
            .unwrap();
        }
        rows
    }
    #[test]
    fn disk_history_detaches_all_three_payload_kinds_and_preserves_exact_owned_views() {
        let (_temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        store.begin_replay(b"synthetic history roundtrip").unwrap();
        let rows = links(129);
        let weak = Arc::downgrade(rows.iter().nth(64).unwrap());
        let expected = rows
            .iter()
            .map(|row| row.as_ref().clone())
            .collect::<Vec<_>>();
        let retained = rows.retain(&mut store, [19; 32], &budget).unwrap();
        assert_eq!(retained.retained_ids().len(), 3);
        assert_eq!(retained.cache_charge(), rows.cache_charge());
        drop(rows);
        assert!(weak.upgrade().is_none());
        let mut executed = LedgerHistory::new(256);
        let mut rewards = LedgerHistory::new(256);
        for position in 0..129_u64 {
            let mut id = [0; 32];
            id[..8].copy_from_slice(&position.to_le_bytes());
            executed.push(VertexId::from_bytes(id)).unwrap();
            let mut row = [0; 112];
            row[..8].copy_from_slice(&position.to_le_bytes());
            rewards.push(row).unwrap();
        }
        let stored_executed = executed.retain(&mut store, [19; 32], &budget).unwrap();
        let stored_rewards = rewards.retain(&mut store, [19; 32], &budget).unwrap();
        assert_ne!(
            stored_executed.retained_ids(),
            stored_rewards.retained_ids()
        );
        assert_eq!(stored_executed.cache_charge(), executed.cache_charge());
        assert_eq!(stored_rewards.cache_charge(), rewards.cache_charge());
        assert_eq!(store.head(), None);
        drop(store);
        assert_eq!(
            retained
                .materialize(Some(&budget))
                .unwrap()
                .iter()
                .map(|row| row.as_ref().clone())
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(
            stored_executed
                .materialize(Some(&budget))
                .unwrap()
                .as_slice(),
            executed.as_slice()
        );
        assert_eq!(
            stored_rewards
                .materialize(Some(&budget))
                .unwrap()
                .as_slice(),
            rewards.as_slice()
        );
    }
    #[test]
    fn disk_history_missing_tampered_or_hardlinked_tail_refuses_without_partial_rows() {
        let (temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        store.begin_replay(b"synthetic history refusal").unwrap();
        let rows = links(129);
        let retained = rows.retain(&mut store, [19; 32], &budget).unwrap();
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
            retained.materialize(Some(&budget)).unwrap().as_slice(),
            rows.as_slice()
        );
        assert_eq!(store.head(), None);
    }
    #[test]
    fn disk_history_forks_share_full_pages_and_refuse_wrong_context_ordinal_or_length() {
        let (_temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        store.begin_replay(b"synthetic history forks").unwrap();
        let base = links(129).retain(&mut store, [19; 32], &budget).unwrap();
        let mut left = base.materialize(Some(&budget)).unwrap();
        let mut right = left.clone();
        left.push(Arc::new(AcceptedOutputs {
            effect: [3; 32],
            first_position: 258,
            commitments: [[4; 32], [5; 32]],
        }))
        .unwrap();
        right
            .push(Arc::new(AcceptedOutputs {
                effect: [6; 32],
                first_position: 258,
                commitments: [[4; 32], [5; 32]],
            }))
            .unwrap();
        let left = left.retain(&mut store, [19; 32], &budget).unwrap();
        let right = right.retain(&mut store, [19; 32], &budget).unwrap();
        assert_eq!(&base.retained_ids()[..2], &left.retained_ids()[..2]);
        assert_eq!(&base.retained_ids()[..2], &right.retained_ids()[..2]);
        assert_ne!(left.retained_ids()[2], right.retained_ids()[2]);
        let accounted = store.accounted_bytes();
        let resident = base.materialize(Some(&budget)).unwrap();
        assert_eq!(
            resident
                .retain(&mut store, [19; 32], &budget)
                .unwrap()
                .retained_ids(),
            base.retained_ids()
        );
        assert_eq!(store.accounted_bytes(), accounted);
        assert!(base.retain(&mut store, [20; 32], &budget).is_err());
        let mut wrong = base.clone();
        if let LedgerHistory::Retained(rows) = &mut wrong {
            rows.domain = [20; 32];
        }
        assert!(wrong.materialize(Some(&budget)).is_err());
        let mut wrong = base.clone();
        if let LedgerHistory::Retained(rows) = &mut wrong {
            Arc::make_mut(&mut rows.pages).swap(0, 1);
        }
        assert!(wrong.materialize(Some(&budget)).is_err());
        let mut wrong = base.clone();
        if let LedgerHistory::Retained(rows) = &mut wrong {
            rows.len -= 1;
        }
        assert!(wrong.materialize(Some(&budget)).is_err());
        assert_eq!(store.head(), None);
    }
    #[test]
    fn disk_history_unfenced_or_uncertain_write_stops_without_state_or_head_credit() {
        use std::os::unix::fs::PermissionsExt;
        let (temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        let rows = links(1);
        let accounted = store.accounted_bytes();
        assert!(rows.retain(&mut store, [19; 32], &budget).is_err());
        assert_eq!(store.accounted_bytes(), accounted);
        store
            .begin_replay(b"synthetic history write refusal")
            .unwrap();
        let root = temp.path().join("store");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o500)).unwrap();
        assert!(matches!(
            rows.retain(&mut store, [19; 32], &budget),
            Err(Error::Unavailable(
                "retained ledger history page publication failed"
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
        assert!(rows.retained_ids().is_empty());
    }
}
impl Item for VertexId {
    const MAGIC: [u8; 8] = *b"SNF04XP1";
    const WIDTH: usize = 32;
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(self.as_bytes());
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        Ok(Self::from_bytes(bytes.try_into().map_err(|_| {
            Error::Unavailable("executed history item")
        })?))
    }
}
impl Item for [u8; 112] {
    const MAGIC: [u8; 8] = *b"SNF04WP1";
    const WIDTH: usize = 112;
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(self);
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        bytes
            .try_into()
            .map_err(|_| Error::Unavailable("reward history item"))
    }
}
impl Item for Arc<AcceptedOutputs> {
    const MAGIC: [u8; 8] = *b"SNF04OP1";
    const WIDTH: usize = 104;
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.effect);
        bytes.extend_from_slice(&self.first_position.to_le_bytes());
        for commitment in &self.commitments {
            bytes.extend_from_slice(commitment);
        }
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::WIDTH {
            return Err(Error::Unavailable("output linkage history item"));
        }
        Ok(Self::new(AcceptedOutputs {
            effect: bytes[..32]
                .try_into()
                .map_err(|_| Error::Unavailable("output linkage effect"))?,
            first_position: u64le(bytes, 32)?,
            commitments: [
                bytes[40..72]
                    .try_into()
                    .map_err(|_| Error::Unavailable("output linkage commitment"))?,
                bytes[72..104]
                    .try_into()
                    .map_err(|_| Error::Unavailable("output linkage commitment"))?,
            ],
        }))
    }
}
#[derive(Clone)]
struct Page {
    id: Digest,
    count: usize,
}
#[derive(Clone)]
pub(super) struct Retained<T> {
    pages: Arc<Vec<Page>>,
    len: usize,
    limit: usize,
    domain: Digest,
    reader: Arc<ObjectReader>,
    item: PhantomData<T>,
    // Only newly derived rows live here; immutable historical payloads stay on disk.
    appended: PagedSequence<T>,
}
#[derive(Clone)]
pub(super) enum LedgerHistory<T: Item> {
    Resident(PagedSequence<T>),
    Retained(Retained<T>),
}
/// One immutable comparison, owning at most 64 decoded rows. Nothing is
/// returned as a comparison result until every ledger page has been qualified.
pub(super) struct PrefixComparison<'a, T: Item> {
    history: &'a LedgerHistory<T>,
    page: Option<(usize, Vec<T>)>,
    position: usize,
    common: usize,
}
impl<T: Item + PartialEq> PrefixComparison<'_, T> {
    fn load(&mut self, position: usize, budget: Option<&JobBudget>) -> Result<T> {
        if let Some(budget) = budget {
            budget.check()?;
        }
        match self.history {
            LedgerHistory::Resident(rows) => rows
                .get(position)
                .cloned()
                .ok_or(Error::Unavailable("ledger comparison ordinal")),
            LedgerHistory::Retained(rows) => {
                if position >= rows.len {
                    return rows
                        .appended
                        .get(position - rows.len)
                        .cloned()
                        .ok_or(Error::Unavailable("ledger comparison ordinal"));
                }
                let ordinal = position / ITEMS;
                if self
                    .page
                    .as_ref()
                    .is_none_or(|(cached, _)| *cached != ordinal)
                {
                    // Release the old payload BEFORE decoding the replacement:
                    // even the transient decoded-row ownership stays <=64.
                    self.page = None;
                    let page = rows
                        .pages
                        .get(ordinal)
                        .ok_or(Error::Unavailable("retained history directory length"))?;
                    if rows.len > rows.limit
                        || rows.pages.len() != rows.len.div_ceil(ITEMS)
                        || page.count != (rows.len - ordinal * ITEMS).min(ITEMS)
                    {
                        return Err(Error::Unavailable("retained history page count"));
                    }
                    if let Some(budget) = budget {
                        budget.source()?;
                    }
                    let size = HEADER + page.count * T::WIDTH;
                    let bytes = rows.reader.object(page.id, size)?;
                    if bytes.len() != size
                        || bytes.get(..8) != Some(T::MAGIC.as_slice())
                        || bytes[8..40] != rows.domain
                        || u64le(&bytes, 40)? != ordinal as u64
                        || u32le(&bytes, 48)? as usize != page.count
                    {
                        return Err(Error::Unavailable("retained history page binding"));
                    }
                    let decoded = bytes[HEADER..]
                        .chunks_exact(T::WIDTH)
                        .map(T::decode)
                        .collect::<Result<Vec<_>>>()?;
                    if let Some(budget) = budget {
                        budget.check()?;
                    }
                    self.page = Some((ordinal, decoded));
                }
                self.page
                    .as_ref()
                    .and_then(|(_, page)| page.get(position % ITEMS))
                    .cloned()
                    .ok_or(Error::Unavailable("ledger comparison ordinal"))
            }
        }
    }
    pub(super) fn advance(&mut self, value: &T, budget: Option<&JobBudget>) -> Result<()> {
        if let Some(budget) = budget {
            budget.check()?;
        }
        if self.position < self.history.len() {
            let executed = self.load(self.position, budget)?;
            if self.common == self.position && executed == *value {
                self.common += 1;
            }
        }
        self.position = self
            .position
            .checked_add(1)
            .ok_or(Error::Unavailable("ledger comparison overflow"))?;
        Ok(())
    }
    pub(super) fn finish(mut self, budget: Option<&JobBudget>) -> Result<usize> {
        // A short preferred order or an early divergence MUST NOT conceal a
        // missing/corrupt later ledger page. No early-success prefix return.
        for position in self.position.min(self.history.len())..self.history.len() {
            self.load(position, budget)?;
        }
        if let LedgerHistory::Retained(rows) = self.history
            && (self.history.len() > rows.limit || rows.pages.len() != rows.len.div_ceil(ITEMS))
        {
            return Err(Error::Unavailable("retained history directory length"));
        }
        if let Some(budget) = budget {
            budget.check()?;
        }
        Ok(self.common)
    }
}
impl<T: Item> LedgerHistory<T> {
    pub(super) const fn prefix_comparison(&self) -> PrefixComparison<'_, T> {
        PrefixComparison {
            history: self,
            page: None,
            position: 0,
            common: 0,
        }
    }
    pub(super) const fn new(limit: usize) -> Self {
        Self::Resident(PagedSequence::new(limit))
    }
    pub(super) const fn len(&self) -> usize {
        match self {
            Self::Resident(rows) => rows.len(),
            Self::Retained(rows) => rows.len + rows.appended.len(),
        }
    }
    pub(super) fn resident(&self) -> &PagedSequence<T> {
        match self {
            Self::Resident(rows) => rows,
            Self::Retained(_) => panic!("borrowed history access requires materialized snapshot"),
        }
    }
    pub(super) fn iter(&self) -> impl Iterator<Item = &T> {
        self.resident().iter()
    }
    pub(super) fn get(&self, index: usize) -> Option<&T> {
        self.resident().get(index)
    }
    pub(super) fn iter_from(&self, start: usize) -> Result<impl Iterator<Item = &T>> {
        self.resident().iter_from(start)
    }
    pub(super) fn last(&self) -> Option<&T> {
        self.resident().last()
    }
    pub(super) fn as_slice(&self) -> &[T] {
        self.resident().as_slice()
    }
    pub(super) fn starts_with(&self, prior: &Self) -> bool
    where
        T: PartialEq,
    {
        self.resident().starts_with(prior.resident())
    }
    pub(super) fn push(&mut self, value: T) -> Result<()> {
        match self {
            Self::Resident(rows) => rows.push(value),
            Self::Retained(rows) => rows.appended.push(value),
        }
    }
    pub(super) const fn cache_charge(&self) -> usize {
        match self {
            Self::Resident(rows) => rows.cache_charge(),
            // Keep the original full payload/view charge, not a larger cache cap.
            Self::Retained(rows) => {
                let len = rows.len + rows.appended.len();
                len.div_ceil(ITEMS) * (ITEMS * std::mem::size_of::<T>() + 128)
                    + len * std::mem::size_of::<T>()
            }
        }
    }
    pub(super) fn materialize(&self, budget: Option<&JobBudget>) -> Result<Self> {
        let Self::Retained(rows) = self else {
            return Ok(self.clone());
        };
        let mut result = PagedSequence::new(rows.limit);
        self.visit_encoded(budget, &mut |row| result.push(T::decode(row)?))?;
        if result.len() != self.len() {
            return Err(Error::Unavailable("retained history directory length"));
        }
        if let Some(budget) = budget {
            budget.check()?;
        }
        Ok(Self::Resident(result))
    }
    /// Private hash staging, owning one checked page plus at most one typed row.
    /// No caller may use observations as a successful result before completion.
    pub(super) fn visit_encoded(
        &self,
        budget: Option<&JobBudget>,
        visit: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        let check = || budget.map_or(Ok(()), JobBudget::check);
        check()?;
        let Self::Retained(rows) = self else {
            let mut encoded = Vec::with_capacity(T::WIDTH);
            for (position, row) in self.resident().iter().enumerate() {
                if position % ITEMS == 0 {
                    check()?;
                }
                encoded.clear();
                row.encode(&mut encoded);
                if encoded.len() != T::WIDTH {
                    return Err(Error::Unavailable("encoded history item width"));
                }
                visit(&encoded)?;
            }
            return check();
        };
        if self.len() > rows.limit || rows.pages.len() != rows.len.div_ceil(ITEMS) {
            return Err(Error::Unavailable("retained history directory length"));
        }
        for (ordinal, page) in rows.pages.iter().enumerate() {
            check()?;
            if page.count != (rows.len - ordinal * ITEMS).min(ITEMS) {
                return Err(Error::Unavailable("retained history page count"));
            }
            if let Some(budget) = budget {
                budget.source()?;
            }
            let size = HEADER + page.count * T::WIDTH;
            let bytes = rows.reader.object(page.id, size)?;
            if bytes.len() != size
                || bytes.get(..8) != Some(T::MAGIC.as_slice())
                || bytes[8..40] != rows.domain
                || u64le(&bytes, 40)? != ordinal as u64
                || u32le(&bytes, 48)? as usize != page.count
            {
                return Err(Error::Unavailable("retained history page binding"));
            }
            for row in bytes[HEADER..].chunks_exact(T::WIDTH) {
                T::validate_encoded(row)?;
                visit(row)?;
            }
        }
        let mut encoded = Vec::with_capacity(T::WIDTH);
        for (position, row) in rows.appended.iter().enumerate() {
            if position % ITEMS == 0 {
                check()?;
            }
            encoded.clear();
            row.encode(&mut encoded);
            if encoded.len() != T::WIDTH {
                return Err(Error::Unavailable("encoded history item width"));
            }
            visit(&encoded)?;
        }
        check()
    }
    pub(super) fn retain(
        &self,
        store: &mut Store,
        domain: Digest,
        budget: &JobBudget,
    ) -> Result<Self> {
        if let Self::Retained(rows) = self {
            if rows.domain != domain {
                return Err(Error::Unavailable("retained history context"));
            }
            if rows.appended.len() == 0 {
                return Ok(self.clone());
            }
        }
        let len = self.len();
        let limit = match self {
            Self::Resident(rows) => rows.limit(),
            Self::Retained(rows) => rows.limit,
        };
        let mut pages = Vec::with_capacity(len.div_ceil(ITEMS));
        let mut bytes = Vec::with_capacity(HEADER + ITEMS * T::WIDTH);
        let mut count = 0;
        self.visit_encoded(Some(budget), &mut |row| {
            if count == 0 {
                bytes.extend_from_slice(&T::MAGIC);
                bytes.extend_from_slice(&domain);
                bytes.extend_from_slice(&(pages.len() as u64).to_le_bytes());
                bytes.extend_from_slice(&0_u32.to_le_bytes());
            }
            bytes.extend_from_slice(row);
            count += 1;
            if count == ITEMS {
                bytes[48..52].copy_from_slice(&(count as u32).to_le_bytes());
                budget.source()?;
                pages.push(Page {
                    id: T::retain_page(store, &bytes)?,
                    count,
                });
                bytes.clear();
                count = 0;
            }
            Ok(())
        })?;
        if count > 0 {
            bytes[48..52].copy_from_slice(&(count as u32).to_le_bytes());
            budget.source()?;
            pages.push(Page {
                id: T::retain_page(store, &bytes)?,
                count,
            });
        }
        budget.check()?;
        Ok(Self::Retained(Retained {
            pages: Arc::new(pages),
            len,
            limit,
            domain,
            reader: store.object_reader()?,
            item: PhantomData,
            appended: PagedSequence::new(
                limit
                    .checked_sub(len)
                    .ok_or(Error::Unavailable("derived history horizon"))?,
            ),
        }))
    }
    #[cfg(test)]
    pub(super) fn is_materialized(&self) -> bool {
        match self {
            Self::Resident(rows) => rows.is_materialized(),
            Self::Retained(_) => false,
        }
    }
    #[cfg(test)]
    pub(super) fn staged_rows(&self) -> usize {
        match self {
            Self::Resident(rows) => rows.len(),
            Self::Retained(rows) => rows.appended.len(),
        }
    }
    #[cfg(test)]
    pub(super) fn has_retained_prefix(&self) -> bool {
        matches!(self, Self::Retained(_))
    }
    #[cfg(test)]
    pub(super) fn retained_ids(&self) -> Vec<Digest> {
        match self {
            Self::Resident(_) => Vec::new(),
            Self::Retained(rows) => rows.pages.iter().map(|page| page.id).collect(),
        }
    }
}
