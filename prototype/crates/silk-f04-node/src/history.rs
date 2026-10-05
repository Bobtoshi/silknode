//! Bounded file-backed public history distribution, never receiver validity.
//!
//! Every returned carrier must enter ordinary `Node::ingest`; a source manifest
//! or its claimed checkpoint cannot bootstrap a verified node or import a store.
use crate::{
    Digest, Error, Result,
    budget::JobBudget,
    carriage::{Candidate, MAX_VERTEX_BYTES},
    genesis::Genesis,
    node::Node,
    sync::{RANGE_LIMIT_V1, RangeBatchV1},
    wire::{field, raw_hash, u32le},
};
use std::{
    collections::BTreeSet,
    fs::{File, Metadata, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    sync::Arc,
};

const HEADER: usize = 176;
const ROW: usize = 68;
#[cfg(test)]
use crate::sync::HISTORY_LIMIT_V1;

struct Entry {
    vertex: Digest,
    carrier: Digest,
    size: usize,
}

/// An owning directory descriptor and bounded UNVERIFIED carrier inventory.
///
/// Rows have the same 4,096 reference horizon as graph/order/ledger/sync. Output
/// is at most one existing 32-carrier range, not a full-history allocation.
pub struct PublicHistoryV1 {
    directory: File,
    owner: u32,
    genesis: Arc<Genesis>,
    source_head: Digest,
    checkpoint: Digest,
    state: Digest,
    entries: Vec<Entry>,
    limits: crate::capacity::HistoryLimitsV1,
}
impl PublicHistoryV1 {
    /// Bind a bounded public manifest to an independently retained content hash
    /// and already admitted public genesis. Hash identity is NOT `PoW` validity.
    /// Only `history.manifest` and hash-derived `.vertex` names are read; no
    /// wallet, exposure journal, node HEAD/LOCK or private Git input is imported.
    ///
    /// # Errors
    /// Refuses directory aliases, changed/unowned/nonregular files, hash/context
    /// mismatch, framing/duplicate rows or the existing reference horizon.
    pub fn open(root: &Path, expected_manifest: Digest, genesis: Arc<Genesis>) -> Result<Self> {
        Self::open_with_limits(
            root,
            expected_manifest,
            genesis,
            crate::capacity::HistoryLimitsV1::REFERENCE,
        )
    }
    /// Explicit receiver-local inventory envelope; rows remain UNVERIFIED.
    pub fn open_with_limits(
        root: &Path,
        expected_manifest: Digest,
        genesis: Arc<Genesis>,
        limits: crate::capacity::HistoryLimitsV1,
    ) -> Result<Self> {
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(root)?;
        let owner = directory.metadata()?.uid();
        let bytes = read_checked(
            &directory,
            owner,
            "history.manifest",
            HEADER + limits.vertices() * ROW,
            expected_manifest,
        )?;
        if bytes.len() < HEADER || &bytes[..8] != b"SNF04HF1" || bytes[172..176] != [0; 4] {
            return Err(Error::Invalid("public history manifest framing"));
        }
        let count = usize::try_from(u32le(&bytes, 168)?)
            .map_err(|_| Error::Invalid("public history count"))?;
        if count > limits.vertices() || bytes.len() != HEADER + count * ROW {
            return Err(Error::Invalid("public history reference horizon or rows"));
        }
        if bytes[8..40] != genesis.domain() || bytes[40..72] != raw_hash(&genesis.local_bundle()) {
            return Err(Error::Invalid("public history genesis/context"));
        }
        let mut vertices = BTreeSet::new();
        let mut carriers = BTreeSet::new();
        let mut entries = Vec::with_capacity(count);
        for row in bytes[HEADER..].chunks_exact(ROW) {
            let vertex = field(row, 0)?;
            let carrier = field(row, 32)?;
            let size = usize::try_from(u32::from_be_bytes(field(row, 64)?))
                .map_err(|_| Error::Invalid("public history carrier size"))?;
            if !(720..=MAX_VERTEX_BYTES).contains(&size)
                || !vertices.insert(vertex)
                || !carriers.insert(carrier)
            {
                return Err(Error::Invalid("public history duplicate or size"));
            }
            entries.push(Entry {
                vertex,
                carrier,
                size,
            });
        }
        Ok(Self {
            directory,
            owner,
            genesis,
            source_head: field(&bytes, 72)?,
            checkpoint: field(&bytes, 104)?,
            state: field(&bytes, 136)?,
            entries,
            limits,
        })
    }
    /// Source-local advertised count only, not the receiver's admitted graph.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }
    /// Whether this public inventory advertises no carriers.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// Provenance claim only. Never use it as the receiving node's local pin.
    #[must_use]
    pub const fn source_head(&self) -> Digest {
        self.source_head
    }
    /// Claimed checkpoint, for comparison AFTER full ordinary receiver execution.
    #[must_use]
    pub const fn claimed_checkpoint(&self) -> Digest {
        self.checkpoint
    }
    /// Claimed original state-object hash, not an imported ledger snapshot.
    #[must_use]
    pub const fn claimed_state(&self) -> Digest {
        self.state
    }

    /// Bind a received response to this independently pinned manifest and the
    /// exact requested window before exposing any UNVERIFIED carrier bytes.
    /// A short final window is allowed only at this manifest's actual end.
    /// No cursor, node state, work validity or source checkpoint is adopted.
    /// Transports must still submit every carrier through ordinary `Node::ingest`.
    ///
    /// # Errors
    /// Refuses partial/malformed responses, wrong counts or positions, changed
    /// carrier bytes, and mismatched static ID/context/candidate framing.
    pub fn decode_range<'a>(
        &self,
        bytes: &'a [u8],
        start: usize,
        count: usize,
    ) -> Result<RangeBatchV1<'a>> {
        if start >= self.entries.len() || !(1..=RANGE_LIMIT_V1).contains(&count) {
            return Err(Error::Invalid("public history range bounds"));
        }
        let end = start + count.min(self.entries.len() - start);
        let batch =
            RangeBatchV1::decode_with_limits(bytes, start, self.entries.len(), self.limits)?;
        if batch.carriers().len() != end - start {
            return Err(Error::Invalid("public history response count"));
        }
        for (bytes, entry) in batch.carriers().iter().zip(&self.entries[start..end]) {
            if bytes.len() != entry.size || raw_hash(bytes) != entry.carrier {
                return Err(Error::Invalid("public history response carrier bytes"));
            }
            if Candidate::decode(bytes, &self.genesis)?.id != entry.vertex {
                return Err(Error::Invalid("public history response carrier ID"));
            }
        }
        Ok(batch)
    }

    /// Derive the first missing source position from this receiver's own freshly
    /// checked admitted IDs and exact original carrier bytes, not saved cursors,
    /// peer counts or source checkpoint claims. This is only a request-planning
    /// hint: it neither admits data nor proves source/ledger convergence.
    /// One unchanged checkpoint allowance covers the entire read-only scan.
    ///
    /// # Errors
    /// Refuses a non-ready/interrupted receiver, different genesis, damaged local
    /// evidence, an already-known ID with different source bytes, or exhaustion.
    pub fn admitted_prefix(&self, node: &Node) -> Result<usize> {
        let budget = JobBudget::checkpoint()?;
        self.admitted_prefix_budget(node, &budget)
    }
    fn admitted_prefix_budget(&self, node: &Node, budget: &JobBudget) -> Result<usize> {
        node.check_history_query_ready()?;
        if self.entries.len() > node.history_limits().vertices() {
            return Err(Error::Unavailable(
                "public history receiver resource profile",
            ));
        }
        if self.genesis.domain() != node.genesis().domain()
            || self.genesis.local_bundle() != node.genesis().local_bundle()
        {
            return Err(Error::Invalid("public history receiver genesis"));
        }
        for (position, entry) in self.entries.iter().enumerate() {
            budget.check()?;
            if !node.knows_history_carrier(entry.vertex, entry.carrier, entry.size, budget)? {
                budget.check()?;
                return Ok(position);
            }
        }
        budget.check()?;
        Ok(self.entries.len())
    }

    /// Read and freshly hash/type/context/frame-check one complete public range.
    /// Output uses the existing `RangeBatchV1` wire bytes, contains UNVERIFIED
    /// work/proofs, and is returned only after every requested member passes.
    /// Each call reopens every carrier; no prior successful read grants validity.
    ///
    /// # Errors
    /// Refuses out-of-range/excessive requests, any failed original read, changed
    /// content/ID/size/context, or noncanonical candidate/body framing. Nothing is
    /// admitted and no partial range is returned on a failed later member.
    pub fn read_range(&self, start: usize, count: usize) -> Result<Vec<u8>> {
        if start >= self.entries.len() || !(1..=RANGE_LIMIT_V1).contains(&count) {
            return Err(Error::Invalid("public history range bounds"));
        }
        let end = start + count.min(self.entries.len() - start);
        let rows = &self.entries[start..end];
        let size = rows.iter().map(|entry| 4 + entry.size).sum::<usize>() + 1;
        let mut range = Vec::with_capacity(size);
        range.push(u8::try_from(rows.len()).map_err(|_| Error::Invalid("range count"))?);
        for entry in rows {
            let name = format!("{}.vertex", hex::encode(entry.carrier));
            let bytes = read_checked(
                &self.directory,
                self.owner,
                &name,
                entry.size,
                entry.carrier,
            )?;
            if bytes.len() != entry.size {
                return Err(Error::Unavailable("public history carrier length"));
            }
            // Static framing only: this deliberately cannot create VerifiedVertex.
            if Candidate::decode(&bytes, &self.genesis)?.id != entry.vertex {
                return Err(Error::Invalid("public history carrier ID"));
            }
            range.extend_from_slice(
                &u32::try_from(entry.size)
                    .map_err(|_| Error::Invalid("range carrier size"))?
                    .to_be_bytes(),
            );
            range.extend_from_slice(&bytes);
        }
        debug_assert_eq!(range.len(), size);
        Ok(range)
    }
}

fn identity(meta: &Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        meta.dev(),
        meta.ino(),
        meta.len(),
        meta.mtime(),
        meta.mtime_nsec(),
        meta.ctime(),
        meta.ctime_nsec(),
    )
}
fn read_checked(
    directory: &File,
    owner: u32,
    name: &str,
    limit: usize,
    expected: Digest,
) -> Result<Vec<u8>> {
    let mut file: File = rustix::fs::openat(
        directory,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(std::io::Error::from)?
    .into();
    let before = file.metadata()?;
    if !before.is_file()
        || before.nlink() != 1
        || before.uid() != owner
        || before.len() > limit as u64
    {
        return Err(Error::Unavailable("public history file type/owner/length"));
    }
    let capacity = usize::try_from(before.len())
        .map_err(|_| Error::Unavailable("public history allocation bound"))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != before.len()
        || identity(&before) != identity(&file.metadata()?)
        || raw_hash(&bytes) != expected
    {
        return Err(Error::Unavailable("public history changed file or hash"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;
