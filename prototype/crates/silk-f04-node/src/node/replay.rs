//! Full-data generation traversal with one 64-address page resident at a time.
//! This is a local representation, not pruning, finality, a validity cache or
//! permission to exceed the existing graph, ledger, replay or runtime horizons.
use super::{GENERATION_LIMIT_V1, Record};
use crate::{
    Digest, Error, Result,
    store::Store,
    wire::{field, u64le},
};
use std::collections::VecDeque;

const PAGE_RECORDS: usize = 64;
const PAGE_HEADER: usize = 56;
const DIRECTORY_PAGES: usize = 313;
const _: () = assert!((DIRECTORY_PAGES * PAGE_RECORDS) as u64 >= GENERATION_LIMIT_V1);
const _: () = assert!((((DIRECTORY_PAGES - 1) * PAGE_RECORDS) as u64) < GENERATION_LIMIT_V1);

struct Page {
    domain: Digest,
    sequence: u64,
    ids: Vec<Digest>,
}
impl Page {
    fn encode(&self) -> Vec<u8> {
        debug_assert!((1..=PAGE_RECORDS).contains(&self.ids.len()));
        let mut bytes = Vec::with_capacity(PAGE_HEADER + self.ids.len() * 32);
        bytes.extend_from_slice(b"SNF04RP2");
        bytes.extend_from_slice(&self.domain);
        bytes.extend_from_slice(&self.sequence.to_le_bytes());
        let count = u16::try_from(self.ids.len()).expect("bounded page count");
        bytes.extend_from_slice(&count.to_le_bytes());
        bytes.extend_from_slice(&[0; 6]);
        for id in &self.ids {
            bytes.extend_from_slice(id);
        }
        bytes
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        if !(PAGE_HEADER + 32..=PAGE_HEADER + PAGE_RECORDS * 32).contains(&bytes.len())
            || &bytes[..8] != b"SNF04RP2"
            || bytes[50..56] != [0; 6]
        {
            return Err(Error::Unavailable("retained replay page encoding"));
        }
        let count = usize::from(u16::from_le_bytes(field(bytes, 48)?));
        if !(1..=PAGE_RECORDS).contains(&count) || bytes.len() != PAGE_HEADER + count * 32 {
            return Err(Error::Unavailable("retained replay page count"));
        }
        Ok(Self {
            domain: field(bytes, 8)?,
            sequence: u64le(bytes, 40)?,
            ids: bytes[PAGE_HEADER..]
                .chunks_exact(32)
                .map(|id| id.try_into().expect("fixed page address"))
                .collect(),
        })
    }
}

pub(super) struct ReplayPagesV1 {
    domain: Digest,
    source: Digest,
    total: u64,
    sequence: u64,
    pages: [Digest; DIRECTORY_PAGES],
    previous: Digest,
    ids: VecDeque<Digest>,
}
impl ReplayPagesV1 {
    /// Rebuild the index from the exact authenticated backward lineage on EVERY
    /// cold open. A saved root or cursor never resumes verification authority.
    pub(super) fn build(store: &mut Store, head: Digest, domain: Digest) -> Result<Self> {
        let terminal = Record::decode(&store.object(head)?)?;
        if terminal.sequence >= store.limits().generations() {
            return Err(Error::Paused("generation replay reference horizon"));
        }
        let total = terminal.sequence + 1;
        let mut sequence = terminal.sequence;
        let mut cursor = head;
        // Fresh, nonserialized directory: it cannot stand in for replay. Leaves
        // are aligned to sequence zero, so completed prefix pages deduplicate
        // across appended heads. At most 64 prefix variants per aligned group
        // on one append-only lineage: <=20,000 pages, not quadratic growth.
        let mut pages = [[0; 32]; DIRECTORY_PAGES];
        let mut ids = Vec::with_capacity(PAGE_RECORDS);
        loop {
            let record = Record::decode(&store.object(cursor)?)?;
            if record.domain != domain {
                return Err(Error::Unavailable("retained generation context"));
            }
            if record.sequence != sequence || (record.previous == [0; 32]) != (sequence == 0) {
                return Err(Error::Unavailable("generation lineage"));
            }
            ids.push(cursor);
            if sequence % PAGE_RECORDS as u64 == 0 {
                ids.reverse();
                let ordinal = usize::try_from(sequence / PAGE_RECORDS as u64)
                    .map_err(|_| Error::Unavailable("retained replay page ordinal"))?;
                pages[ordinal] = store.retain_replay_page(
                    &Page {
                        domain,
                        sequence,
                        ids,
                    }
                    .encode(),
                )?;
                ids = Vec::with_capacity(PAGE_RECORDS);
            }
            if sequence == 0 {
                break;
            }
            cursor = record.previous;
            sequence -= 1;
        }
        Ok(Self {
            domain,
            source: head,
            total,
            sequence: 0,
            pages,
            previous: [0; 32],
            ids: VecDeque::new(),
        })
    }

    /// Load at most one fixed page, then authenticate one original full record.
    /// Original context/lineage checks and ALL semantic replay still apply.
    pub(super) fn next(&mut self, store: &Store) -> Result<Option<Record>> {
        if self.sequence == self.total {
            if !self.ids.is_empty() || self.previous != self.source {
                return Err(Error::Unavailable("retained replay page terminal"));
            }
            return Ok(None);
        }
        if self.ids.is_empty() {
            let ordinal = usize::try_from(self.sequence / PAGE_RECORDS as u64)
                .map_err(|_| Error::Unavailable("retained replay page ordinal"))?;
            let page_id = self.pages[ordinal];
            if page_id == [0; 32] {
                return Err(Error::Unavailable("missing retained replay page"));
            }
            // Auxiliary index damage is a STOP, never authority to replace an
            // intact canonical HEAD with PREVIOUS. Original record reads below
            // retain the ordinary verified-previous recovery classification.
            let bytes = store
                .object(page_id)
                .map_err(|_| Error::Unavailable("retained replay page load failed"))?;
            let page = Page::decode(&bytes)?;
            let remaining = self.total - self.sequence;
            if page.domain != self.domain
                || page.sequence != self.sequence
                || page.ids.len() as u64 != remaining.min(PAGE_RECORDS as u64)
            {
                return Err(Error::Unavailable("retained replay page binding/lineage"));
            }
            self.ids = page.ids.into();
        }
        let id = *self.ids.front().expect("nonempty validated page");
        let record = Record::decode(&store.object(id)?)?;
        if record.domain != self.domain
            || record.sequence != self.sequence
            || record.previous != self.previous
            || (self.sequence + 1 == self.total && id != self.source)
        {
            return Err(Error::Unavailable("generation lineage"));
        }
        self.ids.pop_front();
        self.sequence += 1;
        self.previous = id;
        Ok(Some(record))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::raw_hash;
    use std::fs;

    const DOMAIN: Digest = [7; 32];

    // Synthetic local headers only: no vertices, PoW, proof generation or
    // cryptographic/state acceptance is claimed by these traversal checks.
    fn record(sequence: u64, previous: Digest) -> Record {
        Record {
            kind: if sequence == 0 { 0 } else { 4 },
            status: 0,
            sequence,
            previous,
            domain: DOMAIN,
            clock: sequence + 1,
            data: raw_hash(b"data"),
            state: [3; 32],
            order: [4; 32],
            checkpoint: [5; 32],
            vertices: 0,
        }
    }
    fn chain(store: &mut Store, count: u64) -> (Digest, Vec<Vec<u8>>) {
        let mut previous = [0; 32];
        let mut rows = Vec::new();
        for sequence in 0..count {
            let bytes = record(sequence, previous).encode();
            previous = store.commit(&[b"data"], &bytes).unwrap();
            rows.push(bytes);
        }
        (previous, rows)
    }
    fn fenced(store: &mut Store) {
        store.begin_replay(b"synthetic replay fence").unwrap();
    }

    #[test]
    fn paged_generation_traversal_is_exact_bounded_and_fresh() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("store");
        let mut store = Store::create(&root, temp.path()).unwrap();
        let (head, rows) = chain(&mut store, 130);
        let retained = fs::read_dir(&root)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect::<Vec<_>>();
        fenced(&mut store);
        let mut pages = ReplayPagesV1::build(&mut store, head, DOMAIN).unwrap();
        let directory = pages.pages;
        let mut output = Vec::new();
        while let Some(record) = pages.next(&store).unwrap() {
            assert!(pages.ids.len() < PAGE_RECORDS);
            output.push(record.encode());
        }
        assert_eq!(output, rows);
        assert_eq!(store.head(), Some(head));
        assert!(retained.into_iter().all(|name| root.join(name).is_file()));
        // This second fresh traversal rebuilds from HEAD; index bytes may
        // deduplicate, but the old completed cursor was not loaded or trusted.
        let fresh = ReplayPagesV1::build(&mut store, head, DOMAIN).unwrap();
        assert_eq!(fresh.sequence, 0);
        assert_eq!(fresh.pages, directory);
    }

    #[test]
    fn paged_generation_corruption_stops_without_advancing_or_switching_head() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("store");
        let mut store = Store::create(&root, temp.path()).unwrap();
        let (head, _) = chain(&mut store, 65);
        fenced(&mut store);
        let mut pages = ReplayPagesV1::build(&mut store, head, DOMAIN).unwrap();
        let path = root.join(format!("{}.obj", hex::encode(pages.pages[0])));
        let mut changed = fs::read(&path).unwrap();
        changed[8] ^= 1;
        fs::write(&path, changed).unwrap();
        let error = pages.next(&store).err().unwrap();
        assert!(matches!(
            error,
            Error::Unavailable("retained replay page load failed")
        ));
        assert!(!super::super::storage_integrity_failure(&error));
        // Missing auxiliary bytes have the same STOP classification, while
        // neither fault advances the cursor or mutates canonical selection.
        fs::remove_file(&path).unwrap();
        let error = pages.next(&store).err().unwrap();
        assert!(matches!(
            error,
            Error::Unavailable("retained replay page load failed")
        ));
        assert!(!super::super::storage_integrity_failure(&error));
        assert_eq!(pages.sequence, 0);
        assert!(pages.ids.is_empty());
        assert_eq!(store.head(), Some(head));
        assert!(store.active_replay().unwrap().is_some());
    }

    #[test]
    fn paged_generation_rejects_discontinuous_source_and_wrong_bindings() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("store");
        let mut store = Store::create(&root, temp.path()).unwrap();
        let (head, _) = chain(&mut store, 1);
        let bad = record(2, head).encode();
        let bad_head = store.commit(&[b"data"], &bad).unwrap();
        fenced(&mut store);
        assert!(matches!(
            ReplayPagesV1::build(&mut store, bad_head, DOMAIN),
            Err(Error::Unavailable("generation lineage"))
        ));
        assert!(ReplayPagesV1::build(&mut store, head, [8; 32]).is_err());
        let mut pages = ReplayPagesV1::build(&mut store, head, DOMAIN).unwrap();
        let forged = Page {
            domain: [9; 32],
            sequence: 0,
            ids: vec![head],
        };
        pages.pages[0] = store.retain_replay_page(&forged.encode()).unwrap();
        assert!(matches!(
            pages.next(&store),
            Err(Error::Unavailable("retained replay page binding/lineage"))
        ));
        assert_eq!(pages.sequence, 0);
        assert_eq!(store.head(), Some(bad_head));
    }

    #[test]
    fn paged_generation_page_encoding_is_closed_and_requires_a_fence() {
        let page = Page {
            domain: DOMAIN,
            sequence: 0,
            ids: vec![[2; 32]],
        };
        let bytes = page.encode();
        assert_eq!(Page::decode(&bytes).unwrap().encode(), bytes);
        for length in [0, 55, 56, 87, 89, PAGE_HEADER + PAGE_RECORDS * 32 + 1] {
            assert!(Page::decode(&vec![0; length]).is_err());
        }
        let mut reserved = bytes.clone();
        reserved[50] = 1;
        assert!(Page::decode(&reserved).is_err());
        let mut count = bytes.clone();
        count[48..50].copy_from_slice(&65_u16.to_le_bytes());
        assert!(Page::decode(&count).is_err());
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::create(&temp.path().join("store"), temp.path()).unwrap();
        assert!(store.retain_replay_page(&bytes).is_err());
        fenced(&mut store);
        assert!(store.retain_replay_page(&vec![0; 4097]).is_err());
        assert_eq!(store.head(), None);
    }

    #[test]
    fn paged_generation_stable_prefix_retention_is_linear() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("store");
        let mut store = Store::create(&root, temp.path()).unwrap();
        let (mut head, _) = chain(&mut store, 128);
        let mut stable = [[0; 32]; 2];
        // A short boundary-crossing fixture, not a maturity/network run.
        // Every first cold open adds just one distinct partial/full leaf;
        // reopening the identical head adds no retained objects.
        for sequence in 127..132 {
            if sequence > 127 {
                head = store
                    .commit(&[b"data"], &record(sequence, head).encode())
                    .unwrap();
            }
            fenced(&mut store);
            let before = fs::read_dir(&root).unwrap().count();
            let pages = ReplayPagesV1::build(&mut store, head, DOMAIN).unwrap();
            let after = fs::read_dir(&root).unwrap().count();
            if sequence == 127 {
                stable.copy_from_slice(&pages.pages[..2]);
                assert_eq!(after - before, 2); // first two full leaves
            } else {
                assert_eq!(pages.pages[..2], stable);
                assert_eq!(after - before, 1); // only the new leaf
            }
            let fresh = ReplayPagesV1::build(&mut store, head, DOMAIN).unwrap();
            assert_eq!(fresh.pages, pages.pages);
            assert_eq!(fs::read_dir(&root).unwrap().count(), after);
            store
                .finish_replay(store.active_replay().unwrap().unwrap().0)
                .unwrap();
            assert_eq!(store.head(), Some(head));
        }
        // Store inventory charges <=8 KiB per <=4096-byte page. One canonical
        // lineage has <=one distinct leaf per generation even when reopened
        // after EVERY append: <=156.25 MiB at the unchanged 20,000 horizon.
        assert!(PAGE_HEADER + PAGE_RECORDS * 32 <= 4096);
        assert_eq!(GENERATION_LIMIT_V1 * 8192, 163_840_000);
    }

    #[test]
    fn paged_generation_failed_page_write_is_not_previous_head_recovery() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("store");
        let mut store = Store::create(&root, temp.path()).unwrap();
        let (head, _) = chain(&mut store, 1);
        fenced(&mut store);
        let bytes = Page {
            domain: DOMAIN,
            sequence: 0,
            ids: vec![head],
        }
        .encode();
        // Owned synthetic fault: occupy the exact new page name with bad bytes.
        fs::write(
            root.join(format!("{}.obj", hex::encode(raw_hash(&bytes)))),
            b"damaged page",
        )
        .unwrap();
        let error = ReplayPagesV1::build(&mut store, head, DOMAIN)
            .err()
            .unwrap();
        assert!(matches!(
            error,
            Error::Unavailable("retained replay page publication failed")
        ));
        assert!(!super::super::storage_integrity_failure(&error));
        assert!(store.active_replay().unwrap().is_some());
        assert_eq!(store.head(), Some(head));
        assert!(store.commit(&[], b"not a permitted retry").is_err());
    }

    #[test]
    #[ignore = "requires canonical parameters and an explicitly isolated Linux empty-ledger store"]
    fn paged_generation_empty_ledger_cold_reopen_keeps_exact_head_and_state() {
        use super::super::Node;
        use crate::{genesis::public_testnet_v1, node::NodeStatus};
        use silk_sapling_f04::parameters::SaplingParameters;
        use std::path::PathBuf;
        assert_eq!(std::env::var("SILK_F04_ISOLATED_LAB").as_deref(), Ok("1"));
        let parameter_dir = PathBuf::from(std::env::var_os("SILK_F04_PARAMETER_DIR").unwrap());
        let store_parent = PathBuf::from(std::env::var_os("SILK_F04_LAB_STORE").unwrap());
        let margin = PathBuf::from(std::env::var_os("SILK_F04_HOST_MARGIN").unwrap());
        let parameters = SaplingParameters::load(
            &parameter_dir.join("sapling-spend.params"),
            &parameter_dir.join("sapling-output.params"),
        )
        .unwrap();
        let lab = tempfile::Builder::new()
            .prefix("paged-empty-ledger-")
            .tempdir_in(store_parent)
            .unwrap();
        let root = lab.path().join("store");
        let genesis = public_testnet_v1::genesis().unwrap();
        let mut node = Node::create(&root, &margin, genesis.clone()).unwrap();
        for _ in 0..64 {
            node.flush_clock().unwrap();
        }
        let pin = node.local_head().unwrap();
        let expected_checkpoint = node.state().unwrap().checkpoint_id();
        let expected_state = node.state().unwrap().digest();
        let retained = fs::read_dir(&root)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                (path.clone(), fs::read(path).unwrap())
            })
            .collect::<Vec<_>>();
        drop(node);
        let reopened =
            Node::open_retained_pinned(&root, &margin, genesis, &parameters, pin).unwrap();
        assert_eq!(reopened.local_head().unwrap(), pin);
        assert_eq!(reopened.status().unwrap(), NodeStatus::Ready);
        assert_eq!(reopened.vertex_count(), 0);
        assert_eq!(
            reopened.state().unwrap().checkpoint_id(),
            expected_checkpoint
        );
        assert_eq!(reopened.state().unwrap().digest(), expected_state);
        assert!(
            retained
                .into_iter()
                .all(|(path, bytes)| fs::read(path).unwrap() == bytes)
        );
        assert!(!root.join("ACTIVE_REPLAY").exists());
        assert!(!root.join("ACTIVE_JOB").exists());
        drop(reopened);
        // The existing unpinned, verified-previous recovery remains exact: a
        // damaged current object is retained, while the previous full lineage
        // must pass semantic replay before its head can be restored.
        let previous = fs::read_to_string(root.join("PREVIOUS")).unwrap();
        let damaged = root.join(format!("{}.obj", hex::encode(pin)));
        fs::write(&damaged, b"owned synthetic damaged generation").unwrap();
        let recovered = Node::open_retained(
            &root,
            &margin,
            public_testnet_v1::genesis().unwrap(),
            &parameters,
        )
        .unwrap();
        assert!(recovered.recovered_previous());
        assert_eq!(hex::encode(recovered.local_head().unwrap()), previous);
        assert_eq!(recovered.state().unwrap().digest(), expected_state);
        assert_eq!(
            fs::read(damaged).unwrap(),
            b"owned synthetic damaged generation"
        );
        drop(recovered);
        // A fresh process cannot adopt index pages or renew an interrupted
        // attempt. Refusal precedes every page write and preserves all bytes.
        let mut stopped = Store::open(&root, &margin).unwrap();
        fenced(&mut stopped);
        let stopped_pin = stopped.head().unwrap();
        drop(stopped);
        let before = fs::read_dir(&root)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                (path.clone(), fs::read(path).unwrap())
            })
            .collect::<Vec<_>>();
        assert!(matches!(
            Node::open_retained_pinned(
                &root,
                &margin,
                public_testnet_v1::genesis().unwrap(),
                &parameters,
                stopped_pin
            ),
            Err(Error::Paused(
                "interrupted retained replay requires explicit bounded authority"
            ))
        ));
        assert_eq!(fs::read_dir(&root).unwrap().count(), before.len());
        assert!(
            before
                .into_iter()
                .all(|(path, bytes)| fs::read(path).unwrap() == bytes)
        );
        println!(
            "empty_ledger_generation_replay=65;index_pages=2;head_and_state_unchanged=true;verified_previous_preserved=true;interrupted_replay_refused=true;no_work_or_proofs=true"
        );
    }
}
