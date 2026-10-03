//! Deterministic SG-0 ordering core for the persistent valueless DAG profile.
//!
//! This module is deliberately pure: it consumes a receiver-owned graph/read
//! boundary and derives ordering metadata. It does not decode peer work, verify
//! proof of work, mine, persist state, execute transactions, or authorize
//! rewards. The node adapter must expose only fully available, receiver-
//! verified vertices through [`ReceiverVerifiedSg0Graph`].
//!
//! Per-vertex metadata stores only its selected parent and newly blue merge
//! members. Full past and blue closures are reconstructed transiently through
//! graph queries, so a persistent adapter can keep graph records and metadata
//! on disk and bound its in-memory cache instead of retaining a quadratic set
//! for every vertex.

use sha2::{Digest, Sha256};
use silk_pow::Uint256;
use silk_types::{Hash32, VertexId};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Foreground resource accounting for receiver-owned indexed graph adapters.
#[path = "sg0_budgeted_v1.rs"]
pub mod budgeted;

/// Bounded replay-checked order and checkpoint capabilities.
#[path = "sg0_paged_v1.rs"]
pub mod paged;

/// Maximum ordinary parents in the persistent SG-0 test profile.
pub const SG0_V1_MAX_PARENTS: usize = 2;
/// Anticone bound in the persistent SG-0 test profile.
pub const SG0_V1_K: usize = 2;
/// Exact eligible vertices in one persistent-profile checkpoint batch.
pub const SG0_V1_CHECKPOINT_ELIGIBLE_SPAN: usize = 8;
/// Stable source-independent policy name bound by the profile manifest.
pub const SG0_V1_POLICY_NAME: &str = "silknode-private-persistent-sg0-v1";

const GRAPH_COMMITMENT_DOMAIN: &[u8] = b"Silk/SG0-v1/Graph";
const MERGE_COMMITMENT_DOMAIN: &[u8] = b"Silk/SG0-v1/MergeOrder";
const TOTAL_ORDER_COMMITMENT_DOMAIN: &[u8] = b"Silk/SG0-v1/TotalOrder";
const ELIGIBLE_ORDER_COMMITMENT_DOMAIN: &[u8] = b"Silk/SG0-v1/EligibleOrder";
const CHECKPOINT_BATCH_COMMITMENT_DOMAIN: &[u8] = b"Silk/SG0-v1/CheckpointBatch";
const VERTEX_DATA_CACHE_MAGIC: &[u8; 8] = b"SLKSG01\0";
const VERTEX_DATA_CACHE_VERSION: u16 = 1;
const VERTEX_DATA_CACHE_FIXED_BYTES: usize = 140;

/// Canonical shared unsigned 256-bit work type used by SG-0.
pub type Sg0Work = Uint256;

/// The canonical parent shape supplied by a receiver-verified graph adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Sg0ParentSetV1 {
    /// The typed authenticated first-child anchor.
    Anchor,
    /// One or two strictly sorted, unique ordinary parents.
    Vertices(Vec<VertexId>),
}

impl Sg0ParentSetV1 {
    /// Constructs the first-layer anchor parent shape.
    #[must_use]
    pub const fn anchor() -> Self {
        Self::Anchor
    }

    /// Constructs one or two sorted, unique ordinary parents.
    ///
    /// This validates representation only. It does not authenticate the
    /// parents or establish receiver-verified work.
    ///
    /// # Errors
    ///
    /// Rejects an empty, oversized, unsorted, or duplicate parent list.
    pub fn vertices(parents: Vec<VertexId>) -> Result<Self, Sg0Error> {
        if parents.is_empty()
            || parents.len() > SG0_V1_MAX_PARENTS
            || parents.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(Sg0Error::InvalidParents);
        }
        Ok(Self::Vertices(parents))
    }

    fn ordinary(&self) -> &[VertexId] {
        match self {
            Self::Anchor => &[],
            Self::Vertices(parents) => parents,
        }
    }

    /// Returns ordinary parent IDs, or an empty slice for the anchor variant.
    #[must_use]
    pub fn ordinary_parents(&self) -> &[VertexId] {
        self.ordinary()
    }
}

/// Receiver-owned random-access graph boundary used by the pure order core.
///
/// Implementations MUST expose only vertices whose complete body, proof,
/// recovery data, DAA context, and `PoW` have already been verified locally.
/// Implementing this trait for decoded peer claims does not create consensus
/// authority; the node's trusted adapter and checkpoint capability remain the
/// enforcement boundary.
pub trait ReceiverVerifiedSg0Graph {
    /// Visits every admitted ordinary vertex ID exactly once.
    ///
    /// Disk-backed implementations may stream IDs and retain a bounded cache.
    ///
    /// # Errors
    ///
    /// Propagates a local graph/index read or visitor failure.
    fn visit_vertex_ids(
        &self,
        visitor: &mut dyn FnMut(VertexId) -> Result<(), Sg0Error>,
    ) -> Result<(), Sg0Error>;

    /// Returns whether one ordinary vertex is present in the admitted graph.
    ///
    /// Persistent adapters SHOULD override this reference scan with their
    /// authenticated key index.
    ///
    /// # Errors
    ///
    /// Propagates a local graph/index read failure.
    fn receiver_verified_contains(&self, vertex: VertexId) -> Result<bool, Sg0Error> {
        let mut found = false;
        self.visit_vertex_ids(&mut |candidate| {
            found |= candidate == vertex;
            Ok(())
        })?;
        Ok(found)
    }

    /// Returns the already authenticated canonical parent shape for a vertex.
    ///
    /// # Errors
    ///
    /// Returns a local read or missing-vertex failure.
    fn parent_set(&self, vertex: VertexId) -> Result<Sg0ParentSetV1, Sg0Error>;

    /// Returns exact work bytes derived by receiver-side `PoW` verification.
    ///
    /// # Errors
    ///
    /// Returns a local read, missing-vertex, or work-evidence failure.
    fn receiver_verified_work_be(&self, vertex: VertexId) -> Result<[u8; 32], Sg0Error>;

    /// Loads previously derived metadata for an admitted vertex.
    ///
    /// A persistent implementation may read this from an authenticated index;
    /// it need not keep metadata for the full graph in memory.
    ///
    /// # Errors
    ///
    /// Returns a local read or metadata-decoding failure.
    fn vertex_data(&self, vertex: VertexId) -> Result<Option<Sg0VertexDataV1>, Sg0Error>;

    /// Visits every strict ancestor of `vertex` exactly once.
    ///
    /// The default is a bounded-memory reference walk over `parent_set`.
    /// Persistent adapters SHOULD override it with their authenticated
    /// disk-backed reachability index and stream results through the visitor.
    ///
    /// # Errors
    ///
    /// Propagates local index/read/visitor failures or reports a cycle.
    fn visit_strict_past_ids(
        &self,
        vertex: VertexId,
        visitor: &mut dyn FnMut(VertexId) -> Result<(), Sg0Error>,
    ) -> Result<(), Sg0Error>
    where
        Self: Sized,
    {
        reference_visit_strict_past(self, vertex, visitor)
    }

    /// Returns exact receiver-indexed strict ancestry.
    ///
    /// Persistent adapters SHOULD override the reference scan with their
    /// authenticated reachability query. Equality is deliberately false.
    ///
    /// # Errors
    ///
    /// Propagates local index/read failures or reports inconsistent ancestry.
    fn receiver_verified_is_ancestor(
        &self,
        ancestor: VertexId,
        descendant: VertexId,
    ) -> Result<bool, Sg0Error>
    where
        Self: Sized,
    {
        if ancestor == descendant {
            return Ok(false);
        }
        let mut found = false;
        self.visit_strict_past_ids(descendant, &mut |candidate| {
            found |= candidate == ancestor;
            Ok(())
        })?;
        Ok(found)
    }
}

/// Selected-parent reference in derived SG-0 metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Sg0SelectedParentV1 {
    /// The authenticated zero-work anchor for a first-layer vertex.
    Anchor,
    /// An ordinary selected parent.
    Vertex(VertexId),
}

/// Compact derived metadata for one admitted ordinary vertex.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sg0VertexDataV1 {
    selected_parent: Sg0SelectedParentV1,
    merge_blues: Vec<VertexId>,
    merge_red_count: u64,
    merge_order_commitment: Hash32,
    blue_score: u128,
    blue_work: Sg0Work,
}

impl Sg0VertexDataV1 {
    /// Returns the deterministic selected parent.
    #[must_use]
    pub const fn selected_parent(&self) -> Sg0SelectedParentV1 {
        self.selected_parent
    }

    /// Returns newly blue merge-set vertices in pinned merge order.
    #[must_use]
    pub fn merge_blues(&self) -> &[VertexId] {
        &self.merge_blues
    }

    /// Returns the number of newly red merge-set vertices.
    #[must_use]
    pub const fn merge_red_count(&self) -> u64 {
        self.merge_red_count
    }

    /// Returns the commitment to the complete blue/red merge order.
    #[must_use]
    pub const fn merge_order_commitment(&self) -> Hash32 {
        self.merge_order_commitment
    }

    /// Returns checked intrinsic blue score through this vertex.
    #[must_use]
    pub const fn blue_score(&self) -> u128 {
        self.blue_score
    }

    /// Returns checked cumulative blue work through this vertex.
    #[must_use]
    pub const fn blue_work(&self) -> Sg0Work {
        self.blue_work
    }

    /// Encodes strict compact receiver-cache bytes for durable local storage.
    ///
    /// These bytes contain no full past or blue closure. The archive adapter
    /// remains responsible for authenticating their origin and binding them to
    /// the exact canonical vertex record.
    ///
    /// # Errors
    ///
    /// Rejects an in-memory count that cannot fit the fixed `u32` cache field.
    pub fn canonical_cache_bytes_v1(&self) -> Result<Vec<u8>, Sg0Error> {
        let merge_blue_count =
            u32::try_from(self.merge_blues.len()).map_err(|_| Sg0Error::CountOverflow)?;
        let capacity = VERTEX_DATA_CACHE_FIXED_BYTES
            .checked_add(
                self.merge_blues
                    .len()
                    .checked_mul(Hash32::LENGTH)
                    .ok_or(Sg0Error::CountOverflow)?,
            )
            .ok_or(Sg0Error::CountOverflow)?;
        let mut bytes = Vec::with_capacity(capacity);
        bytes.extend_from_slice(VERTEX_DATA_CACHE_MAGIC);
        bytes.extend_from_slice(&VERTEX_DATA_CACHE_VERSION.to_be_bytes());
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        match self.selected_parent {
            Sg0SelectedParentV1::Anchor => {
                bytes.extend_from_slice(&[0, 0, 0, 0]);
                bytes.extend_from_slice(&[0; Hash32::LENGTH]);
            }
            Sg0SelectedParentV1::Vertex(parent) => {
                bytes.extend_from_slice(&[1, 0, 0, 0]);
                bytes.extend_from_slice(parent.as_bytes());
            }
        }
        bytes.extend_from_slice(&self.blue_score.to_be_bytes());
        bytes.extend_from_slice(&self.blue_work.to_be_bytes());
        bytes.extend_from_slice(&self.merge_red_count.to_be_bytes());
        bytes.extend_from_slice(self.merge_order_commitment.as_bytes());
        bytes.extend_from_slice(&merge_blue_count.to_be_bytes());
        for merge_blue in &self.merge_blues {
            bytes.extend_from_slice(merge_blue.as_bytes());
        }
        if bytes.len() != capacity {
            return Err(Sg0Error::Invariant);
        }
        Ok(bytes)
    }

    /// Strictly decodes compact cache bytes without granting graph authority.
    ///
    /// Only a receiver-owned adapter may expose the result through
    /// [`ReceiverVerifiedSg0Graph`]. Peer-provided bytes must never be treated
    /// as locally derived metadata merely because this structural decoder
    /// accepts them.
    ///
    /// # Errors
    ///
    /// Rejects malformed, cross-version, reserved, duplicate, truncated,
    /// trailing, or impossible ordinary-vertex cache fields.
    #[allow(clippy::too_many_lines)]
    pub fn decode_cache_untrusted_v1(bytes: &[u8]) -> Result<Self, Sg0Error> {
        if bytes.len() < VERTEX_DATA_CACHE_FIXED_BYTES
            || bytes.get(..8) != Some(VERTEX_DATA_CACHE_MAGIC)
            || bytes.get(8..10) != Some(VERTEX_DATA_CACHE_VERSION.to_be_bytes().as_slice())
            || bytes.get(10..12) != Some([0, 0].as_slice())
            || bytes.get(13..16) != Some([0, 0, 0].as_slice())
        {
            return Err(Sg0Error::CacheCodec);
        }
        let selected_bytes: [u8; Hash32::LENGTH] = bytes
            .get(16..48)
            .ok_or(Sg0Error::CacheCodec)?
            .try_into()
            .map_err(|_| Sg0Error::CacheCodec)?;
        let selected_parent = match bytes[12] {
            0 if selected_bytes == [0; Hash32::LENGTH] => Sg0SelectedParentV1::Anchor,
            1 => Sg0SelectedParentV1::Vertex(VertexId::from_bytes(selected_bytes)),
            _ => return Err(Sg0Error::CacheCodec),
        };
        let blue_score = u128::from_be_bytes(
            bytes
                .get(48..64)
                .ok_or(Sg0Error::CacheCodec)?
                .try_into()
                .map_err(|_| Sg0Error::CacheCodec)?,
        );
        let blue_work = Uint256::from_be_bytes(
            bytes
                .get(64..96)
                .ok_or(Sg0Error::CacheCodec)?
                .try_into()
                .map_err(|_| Sg0Error::CacheCodec)?,
        );
        let merge_red_count = u64::from_be_bytes(
            bytes
                .get(96..104)
                .ok_or(Sg0Error::CacheCodec)?
                .try_into()
                .map_err(|_| Sg0Error::CacheCodec)?,
        );
        let merge_order_commitment = Hash32::new(
            bytes
                .get(104..136)
                .ok_or(Sg0Error::CacheCodec)?
                .try_into()
                .map_err(|_| Sg0Error::CacheCodec)?,
        );
        let merge_blue_count = usize::try_from(u32::from_be_bytes(
            bytes
                .get(136..140)
                .ok_or(Sg0Error::CacheCodec)?
                .try_into()
                .map_err(|_| Sg0Error::CacheCodec)?,
        ))
        .map_err(|_| Sg0Error::CountOverflow)?;
        let expected = VERTEX_DATA_CACHE_FIXED_BYTES
            .checked_add(
                merge_blue_count
                    .checked_mul(Hash32::LENGTH)
                    .ok_or(Sg0Error::CountOverflow)?,
            )
            .ok_or(Sg0Error::CountOverflow)?;
        if bytes.len() != expected || blue_score == 0 || blue_work.is_zero() {
            return Err(Sg0Error::CacheCodec);
        }
        let mut merge_blues = Vec::new();
        merge_blues
            .try_reserve_exact(merge_blue_count)
            .map_err(|_| Sg0Error::CountOverflow)?;
        let mut unique = BTreeSet::new();
        for chunk in bytes[VERTEX_DATA_CACHE_FIXED_BYTES..].chunks_exact(Hash32::LENGTH) {
            let id = VertexId::from_slice(chunk).map_err(|_| Sg0Error::CacheCodec)?;
            if !unique.insert(id)
                || matches!(selected_parent, Sg0SelectedParentV1::Vertex(parent) if parent == id)
            {
                return Err(Sg0Error::CacheCodec);
            }
            merge_blues.push(id);
        }
        u64::try_from(merge_blues.len())
            .map_err(|_| Sg0Error::CountOverflow)?
            .checked_add(merge_red_count)
            .ok_or(Sg0Error::CountOverflow)?;
        let decoded = Self {
            selected_parent,
            merge_blues,
            merge_red_count,
            merge_order_commitment,
            blue_score,
            blue_work,
        };
        if matches!(decoded.selected_parent, Sg0SelectedParentV1::Anchor)
            && (decoded.blue_score != 1
                || !decoded.merge_blues.is_empty()
                || decoded.merge_red_count != 0
                || decoded.merge_order_commitment
                    != colored_commitment(MERGE_COMMITMENT_DOMAIN, &[])?)
        {
            return Err(Sg0Error::CacheCodec);
        }
        if decoded.canonical_cache_bytes_v1()?.as_slice() != bytes {
            return Err(Sg0Error::CacheCodec);
        }
        Ok(decoded)
    }
}

/// Color of one vertex in a complete virtual graph order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Sg0Color {
    /// The vertex is eligible under the virtual k-cluster.
    Blue,
    /// The vertex remains graph evidence but is not execution eligible.
    Red,
}

/// One colored vertex in deterministic total order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sg0OrderedVertexV1 {
    /// Ordinary vertex identifier.
    pub vertex_id: VertexId,
    /// Virtual-view color.
    pub color: Sg0Color,
}

/// Deterministic SG-0 snapshot for one complete receiver-local graph view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sg0OrderSnapshotV1 {
    graph_commitment: Hash32,
    selected_tip: Option<VertexId>,
    total_order: Vec<Sg0OrderedVertexV1>,
    eligible_order: Vec<VertexId>,
    eligible_work: Sg0Work,
    total_order_commitment: Hash32,
    eligible_order_commitment: Hash32,
}

impl Sg0OrderSnapshotV1 {
    /// Returns a commitment to sorted admitted graph records and metadata.
    #[must_use]
    pub const fn graph_commitment(&self) -> Hash32 {
        self.graph_commitment
    }

    /// Returns the virtual selected tip, or `None` for an empty graph.
    #[must_use]
    pub const fn selected_tip(&self) -> Option<VertexId> {
        self.selected_tip
    }

    /// Returns every admitted vertex once in total graph order.
    #[must_use]
    pub fn total_order(&self) -> &[Sg0OrderedVertexV1] {
        &self.total_order
    }

    /// Returns the blue execution/issuance order.
    #[must_use]
    pub fn eligible_order(&self) -> &[VertexId] {
        &self.eligible_order
    }

    /// Returns checked work of the virtual eligible set.
    #[must_use]
    pub const fn eligible_work(&self) -> Sg0Work {
        self.eligible_work
    }

    /// Returns the colored total-order commitment.
    #[must_use]
    pub const fn total_order_commitment(&self) -> Hash32 {
        self.total_order_commitment
    }

    /// Returns the eligible-order commitment.
    #[must_use]
    pub const fn eligible_order_commitment(&self) -> Hash32 {
        self.eligible_order_commitment
    }
}

/// Candidate-parent-local order view used by the DAG DAA.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedParentOrderViewV1 {
    parent_set: Sg0ParentSetV1,
    selected_parent: Sg0SelectedParentV1,
    eligible_order: Vec<VertexId>,
    eligible_work: Sg0Work,
    eligible_order_commitment: Hash32,
}

impl VerifiedParentOrderViewV1 {
    /// Returns the exact authenticated parent shape used for this view.
    #[must_use]
    pub const fn parent_set(&self) -> &Sg0ParentSetV1 {
        &self.parent_set
    }

    /// Returns the selected parent for the supplied parent subgraph.
    #[must_use]
    pub const fn selected_parent(&self) -> Sg0SelectedParentV1 {
        self.selected_parent
    }

    /// Returns the exact parent-subgraph eligible order.
    #[must_use]
    pub fn eligible_order(&self) -> &[VertexId] {
        &self.eligible_order
    }

    /// Returns its checked eligible work.
    #[must_use]
    pub const fn eligible_work(&self) -> Sg0Work {
        self.eligible_work
    }

    /// Returns its eligible-order commitment.
    #[must_use]
    pub const fn eligible_order_commitment(&self) -> Hash32 {
        self.eligible_order_commitment
    }
}

/// Longest-common-prefix delta between two eligible orders.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sg0OrderDeltaV1 {
    common_prefix_len: u64,
    removed: Vec<VertexId>,
    appended: Vec<VertexId>,
}

/// Opaque receiver-local proof of the next exact eligible-order checkpoint batch.
///
/// This type contains only order authority. The node/kernel adapter joins these
/// IDs with already verified bodies and reward receivers without reimplementing
/// SG-0 classification or its commitment algorithm.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSg0EligiblePrefixBatchV1 {
    base_cursor: u64,
    first_order_index: u64,
    base_prefix_commitment: Hash32,
    resulting_prefix_commitment: Hash32,
    graph_commitment: Hash32,
    total_order_commitment: Hash32,
    eligible_score_at_boundary: u128,
    eligible_work_at_boundary: Sg0Work,
    entries: [VertexId; SG0_V1_CHECKPOINT_ELIGIBLE_SPAN],
    batch_commitment: Hash32,
}

impl VerifiedSg0EligiblePrefixBatchV1 {
    /// Returns the base issuance/order cursor.
    #[must_use]
    pub const fn base_cursor(&self) -> u64 {
        self.base_cursor
    }

    /// Returns the one-based order index of the first entry.
    #[must_use]
    pub const fn first_order_index(&self) -> u64 {
        self.first_order_index
    }

    /// Returns the commitment to the eligible prefix before this batch.
    #[must_use]
    pub const fn base_prefix_commitment(&self) -> Hash32 {
        self.base_prefix_commitment
    }

    /// Returns the commitment to the eligible prefix through this batch.
    #[must_use]
    pub const fn resulting_prefix_commitment(&self) -> Hash32 {
        self.resulting_prefix_commitment
    }

    /// Returns the receiver-local admitted graph commitment.
    #[must_use]
    pub const fn graph_commitment(&self) -> Hash32 {
        self.graph_commitment
    }

    /// Returns the complete colored total-order commitment.
    #[must_use]
    pub const fn total_order_commitment(&self) -> Hash32 {
        self.total_order_commitment
    }

    /// Returns the eligible-prefix count at this batch boundary.
    #[must_use]
    pub const fn eligible_score_at_boundary(&self) -> u128 {
        self.eligible_score_at_boundary
    }

    /// Returns checked eligible-prefix work at this batch boundary.
    #[must_use]
    pub const fn eligible_work_at_boundary(&self) -> Sg0Work {
        self.eligible_work_at_boundary
    }

    /// Returns exactly eight eligible vertex IDs in canonical order.
    #[must_use]
    pub const fn entries(&self) -> &[VertexId; SG0_V1_CHECKPOINT_ELIGIBLE_SPAN] {
        &self.entries
    }

    /// Returns the sole SG-0 batch commitment for the kernel/node adapter.
    #[must_use]
    pub const fn batch_commitment(&self) -> Hash32 {
        self.batch_commitment
    }
}

impl Sg0OrderDeltaV1 {
    /// Returns the unchanged eligible prefix length.
    #[must_use]
    pub const fn common_prefix_len(&self) -> u64 {
        self.common_prefix_len
    }

    /// Returns old eligible vertices removed after the common prefix.
    #[must_use]
    pub fn removed(&self) -> &[VertexId] {
        &self.removed
    }

    /// Returns new eligible vertices appended after the common prefix.
    #[must_use]
    pub fn appended(&self) -> &[VertexId] {
        &self.appended
    }
}

/// Stable failures from the pure SG-0 core or its receiver-owned read adapter.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum Sg0Error {
    /// A requested vertex is absent from the admitted graph.
    #[error("sg0.missing_vertex")]
    MissingVertex,
    /// Parent representation is empty, oversized, unsorted, or duplicated.
    #[error("sg0.invalid_parents")]
    InvalidParents,
    /// Ordinary parents are comparable or a vertex reaches itself.
    #[error("sg0.redundant_or_cyclic_parent")]
    RedundantOrCyclicParent,
    /// Required selected-parent or merge metadata has not been derived.
    #[error("sg0.missing_metadata")]
    MissingMetadata,
    /// Receiver evidence exposed zero work for an ordinary vertex.
    #[error("sg0.zero_work")]
    ZeroWork,
    /// Checked blue score overflowed.
    #[error("sg0.score_overflow")]
    ScoreOverflow,
    /// Checked 256-bit work overflowed.
    #[error("sg0.work_overflow")]
    WorkOverflow,
    /// Graph traversal or Kahn ordering detected a cycle/incomplete emission.
    #[error("sg0.cycle")]
    Cycle,
    /// A count or index cannot be represented by the consensus integer type.
    #[error("sg0.count_overflow")]
    CountOverflow,
    /// Derived metadata contradicts the graph or SG-0 invariant.
    #[error("sg0.invariant")]
    Invariant,
    /// The supplied checkpoint base does not match the canonical eligible prefix.
    #[error("sg0.base_prefix_mismatch")]
    BasePrefixMismatch,
    /// Fewer than eight eligible vertices remain after the supplied base.
    #[error("sg0.incomplete_checkpoint_batch")]
    IncompleteCheckpointBatch,
    /// The receiver-owned graph adapter reported a local read failure.
    #[error("sg0.graph_read")]
    GraphRead,
    /// Compact receiver-cache bytes are malformed or internally impossible.
    #[error("sg0.cache_codec")]
    CacheCodec,
    /// An opaque parent view no longer matches receiver-derived graph facts.
    #[error("sg0.parent_view_mismatch")]
    ParentViewMismatch,
    /// A local foreground work allowance was exhausted; not a consensus rejection.
    #[error("sg0.resource_budget")]
    ResourceBudget,
}

impl Sg0Error {
    /// Returns the stable language-neutral diagnostic code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::MissingVertex => "sg0.missing_vertex",
            Self::InvalidParents => "sg0.invalid_parents",
            Self::RedundantOrCyclicParent => "sg0.redundant_or_cyclic_parent",
            Self::MissingMetadata => "sg0.missing_metadata",
            Self::ZeroWork => "sg0.zero_work",
            Self::ScoreOverflow => "sg0.score_overflow",
            Self::WorkOverflow => "sg0.work_overflow",
            Self::Cycle => "sg0.cycle",
            Self::CountOverflow => "sg0.count_overflow",
            Self::Invariant => "sg0.invariant",
            Self::BasePrefixMismatch => "sg0.base_prefix_mismatch",
            Self::IncompleteCheckpointBatch => "sg0.incomplete_checkpoint_batch",
            Self::GraphRead => "sg0.graph_read",
            Self::CacheCodec => "sg0.cache_codec",
            Self::ParentViewMismatch => "sg0.parent_view_mismatch",
            Self::ResourceBudget => "sg0.resource_budget",
        }
    }
}

/// Derives compact SG-0 metadata for one newly admitted vertex.
///
/// Parent metadata must already exist in the receiver-owned index. The function
/// transiently reconstructs only the closures needed for this derivation; it
/// does not retain a full past/blue set in the result.
///
/// # Errors
///
/// Rejects malformed/cyclic parents, missing receiver evidence or metadata,
/// zero work, count/work overflow, or a violated k-cluster invariant.
pub fn derive_vertex_data(
    graph: &impl ReceiverVerifiedSg0Graph,
    vertex: VertexId,
) -> Result<Sg0VertexDataV1, Sg0Error> {
    ensure_vertex_exists(graph, vertex)?;
    let parents = validated_parents(graph, vertex)?;
    let own_work = work(graph, vertex)?;

    let selected_parent = select_parent(graph, &parents)?;
    let selected_data = match selected_parent {
        Sg0SelectedParentV1::Anchor => None,
        Sg0SelectedParentV1::Vertex(parent) => Some(metadata(graph, parent)?),
    };
    let merge_order = merge_order_for(graph, &parents, selected_parent)?;
    let mut blue = match selected_parent {
        Sg0SelectedParentV1::Anchor => BTreeSet::new(),
        Sg0SelectedParentV1::Vertex(parent) => blue_closure(graph, parent)?,
    };
    if !is_k_cluster(graph, &blue)? {
        return Err(Sg0Error::Invariant);
    }

    let mut merge_blues = Vec::new();
    let mut red_count = 0_u64;
    let mut colors = Vec::with_capacity(merge_order.len());
    for candidate in &merge_order {
        let mut trial = blue.clone();
        trial.insert(*candidate);
        if is_k_cluster(graph, &trial)? {
            blue = trial;
            merge_blues.push(*candidate);
            colors.push((*candidate, Sg0Color::Blue));
        } else {
            red_count = red_count.checked_add(1).ok_or(Sg0Error::CountOverflow)?;
            colors.push((*candidate, Sg0Color::Red));
        }
    }

    let selected_score = selected_data
        .as_ref()
        .map_or(0, Sg0VertexDataV1::blue_score);
    let selected_work = selected_data
        .as_ref()
        .map_or(Uint256::ZERO, Sg0VertexDataV1::blue_work);
    let merge_blue_count =
        u128::try_from(merge_blues.len()).map_err(|_| Sg0Error::CountOverflow)?;
    let blue_score = selected_score
        .checked_add(1)
        .and_then(|score| score.checked_add(merge_blue_count))
        .ok_or(Sg0Error::ScoreOverflow)?;
    let mut blue_work = selected_work
        .checked_add(own_work)
        .ok_or(Sg0Error::WorkOverflow)?;
    for merge_blue in &merge_blues {
        blue_work = blue_work
            .checked_add(work(graph, *merge_blue)?)
            .ok_or(Sg0Error::WorkOverflow)?;
    }

    Ok(Sg0VertexDataV1 {
        selected_parent,
        merge_blues,
        merge_red_count: red_count,
        merge_order_commitment: colored_commitment(MERGE_COMMITMENT_DOMAIN, &colors)?,
        blue_score,
        blue_work,
    })
}

/// Derives the candidate-parent-local eligible view used by DAA validation.
///
/// # Errors
///
/// Returns [`Sg0Error`] for invalid parent shape, missing metadata/evidence,
/// traversal cycles, overflow, or inconsistent order state.
pub fn derive_parent_order_view(
    graph: &impl ReceiverVerifiedSg0Graph,
    parent_set: &Sg0ParentSetV1,
) -> Result<VerifiedParentOrderViewV1, Sg0Error> {
    let ordinary = validate_supplied_parents(graph, parent_set, None)?;
    if ordinary.is_empty() {
        return Ok(VerifiedParentOrderViewV1 {
            parent_set: parent_set.clone(),
            selected_parent: Sg0SelectedParentV1::Anchor,
            eligible_order: Vec::new(),
            eligible_work: Uint256::ZERO,
            eligible_order_commitment: ids_commitment(ELIGIBLE_ORDER_COMMITMENT_DOMAIN, &[])?,
        });
    }
    let virtual_view = derive_for_tips(graph, &ordinary)?;
    Ok(VerifiedParentOrderViewV1 {
        parent_set: parent_set.clone(),
        selected_parent: Sg0SelectedParentV1::Vertex(
            virtual_view.selected_tip.unwrap_or_else(|| unreachable!()),
        ),
        eligible_order: virtual_view.eligible_order,
        eligible_work: virtual_view.eligible_work,
        eligible_order_commitment: virtual_view.eligible_order_commitment,
    })
}

/// Derives a deterministic complete virtual SG-0 order for the admitted graph.
///
/// # Errors
///
/// Returns [`Sg0Error`] for missing/inconsistent receiver evidence, invalid
/// ancestry, missing metadata, arithmetic overflow, or ordering invariants.
pub fn derive_virtual_order(
    graph: &impl ReceiverVerifiedSg0Graph,
) -> Result<Sg0OrderSnapshotV1, Sg0Error> {
    let vertices = all_vertex_ids(graph)?;
    if vertices.is_empty() {
        return Ok(Sg0OrderSnapshotV1 {
            graph_commitment: graph_commitment(graph, &vertices)?,
            selected_tip: None,
            total_order: Vec::new(),
            eligible_order: Vec::new(),
            eligible_work: Uint256::ZERO,
            total_order_commitment: colored_commitment(TOTAL_ORDER_COMMITMENT_DOMAIN, &[])?,
            eligible_order_commitment: ids_commitment(ELIGIBLE_ORDER_COMMITMENT_DOMAIN, &[])?,
        });
    }
    let mut non_tips = BTreeSet::new();
    for vertex in &vertices {
        let parents = validated_parents(graph, *vertex)?;
        non_tips.extend(parents);
        metadata(graph, *vertex)?;
    }
    let tips: Vec<_> = vertices
        .iter()
        .copied()
        .filter(|vertex| !non_tips.contains(vertex))
        .collect();
    derive_for_tips(graph, &tips)
}

/// Computes the exact longest-common-prefix reorganisation delta.
///
/// # Errors
///
/// Rejects a common-prefix length that does not fit the consensus `u64` index.
pub fn diff_eligible_order(
    old: &[VertexId],
    new: &[VertexId],
) -> Result<Sg0OrderDeltaV1, Sg0Error> {
    let common = old
        .iter()
        .zip(new)
        .take_while(|(left, right)| left == right)
        .count();
    Ok(Sg0OrderDeltaV1 {
        common_prefix_len: u64::try_from(common).map_err(|_| Sg0Error::CountOverflow)?,
        removed: old[common..].to_vec(),
        appended: new[common..].to_vec(),
    })
}

/// Commits to an exact prefix of an already receiver-derived eligible order.
///
/// This helper does not classify vertices or grant ordering authority. It
/// exists so the delayed-key resolver and durable checkpoint adapter use the
/// exact same prefix domain and length encoding as SG-0.
///
/// # Errors
///
/// Rejects a prefix beyond the supplied order or a count that cannot be
/// represented by the consensus `u64` length.
pub fn eligible_prefix_commitment_v1(
    eligible_order: &[VertexId],
    prefix_len: u64,
) -> Result<Hash32, Sg0Error> {
    let prefix_len = usize::try_from(prefix_len).map_err(|_| Sg0Error::CountOverflow)?;
    let prefix = eligible_order
        .get(..prefix_len)
        .ok_or(Sg0Error::BasePrefixMismatch)?;
    ids_commitment(ELIGIBLE_ORDER_COMMITMENT_DOMAIN, prefix)
}

/// Derives the next exact eight-entry eligible-order checkpoint capability.
///
/// `base_cursor` is the number of already checkpointed eligible vertices. The
/// expected base commitment must equal the canonical prefix of exactly that
/// length. Returned record positions are one-based
/// `base_cursor + 1 ..= base_cursor + 8`.
///
/// # Errors
///
/// Rejects a stale graph snapshot, base cursor/commitment mismatch, an
/// incomplete eight-entry suffix, receiver-evidence failure, or checked
/// count/work overflow.
pub fn derive_checkpoint_order_batch(
    graph: &impl ReceiverVerifiedSg0Graph,
    snapshot: &Sg0OrderSnapshotV1,
    base_cursor: u64,
    expected_base_prefix_commitment: Hash32,
) -> Result<VerifiedSg0EligiblePrefixBatchV1, Sg0Error> {
    let vertices = all_vertex_ids(graph)?;
    if graph_commitment(graph, &vertices)? != snapshot.graph_commitment {
        return Err(Sg0Error::BasePrefixMismatch);
    }
    derive_checkpoint_batch_from_order(
        graph,
        snapshot.eligible_order(),
        snapshot.graph_commitment,
        snapshot.total_order_commitment,
        base_cursor,
        expected_base_prefix_commitment,
    )
}

/// Derives the next exact checkpoint batch on an opaque candidate-parent view.
///
/// This is the branch-local counterpart of [`derive_checkpoint_order_batch`].
/// It rederives the view from its private canonical parent set before granting
/// a batch, so callers cannot supply an arbitrary eligible order. Equal
/// eligible prefixes produce the same batch commitment as the whole-graph
/// helper even when graph or red-order diagnostics differ.
///
/// # Errors
///
/// Rejects a stale/mismatched parent view, invalid receiver graph facts, base
/// cursor/commitment mismatch, incomplete eight-entry suffix, or overflow.
pub fn derive_parent_checkpoint_order_batch(
    graph: &impl ReceiverVerifiedSg0Graph,
    parent_view: &VerifiedParentOrderViewV1,
    base_cursor: u64,
    expected_base_prefix_commitment: Hash32,
) -> Result<VerifiedSg0EligiblePrefixBatchV1, Sg0Error> {
    let rederived = derive_parent_order_view(graph, parent_view.parent_set())?;
    if rederived != *parent_view {
        return Err(Sg0Error::ParentViewMismatch);
    }
    let ordinary = parent_view.parent_set().ordinary_parents();
    let (graph_diagnostic, total_order_diagnostic) = if ordinary.is_empty() {
        let vertices = all_vertex_ids(graph)?;
        (
            graph_commitment(graph, &vertices)?,
            colored_commitment(TOTAL_ORDER_COMMITMENT_DOMAIN, &[])?,
        )
    } else {
        let snapshot = derive_for_tips(graph, ordinary)?;
        if snapshot.eligible_order() != parent_view.eligible_order()
            || snapshot.eligible_work() != parent_view.eligible_work()
            || snapshot.eligible_order_commitment() != parent_view.eligible_order_commitment()
        {
            return Err(Sg0Error::ParentViewMismatch);
        }
        (
            snapshot.graph_commitment(),
            snapshot.total_order_commitment(),
        )
    };
    derive_checkpoint_batch_from_order(
        graph,
        parent_view.eligible_order(),
        graph_diagnostic,
        total_order_diagnostic,
        base_cursor,
        expected_base_prefix_commitment,
    )
}

fn derive_checkpoint_batch_from_order(
    graph: &impl ReceiverVerifiedSg0Graph,
    eligible: &[VertexId],
    graph_commitment: Hash32,
    total_order_commitment: Hash32,
    base_cursor: u64,
    expected_base_prefix_commitment: Hash32,
) -> Result<VerifiedSg0EligiblePrefixBatchV1, Sg0Error> {
    let base = usize::try_from(base_cursor).map_err(|_| Sg0Error::CountOverflow)?;
    let end = base
        .checked_add(SG0_V1_CHECKPOINT_ELIGIBLE_SPAN)
        .ok_or(Sg0Error::CountOverflow)?;
    if base > eligible.len() {
        return Err(Sg0Error::BasePrefixMismatch);
    }
    let base_prefix_commitment = eligible_prefix_commitment_v1(eligible, base_cursor)?;
    if base_prefix_commitment != expected_base_prefix_commitment {
        return Err(Sg0Error::BasePrefixMismatch);
    }
    let entries: [VertexId; SG0_V1_CHECKPOINT_ELIGIBLE_SPAN] = eligible
        .get(base..end)
        .ok_or(Sg0Error::IncompleteCheckpointBatch)?
        .try_into()
        .map_err(|_| Sg0Error::Invariant)?;
    let resulting_prefix_commitment = ids_commitment(
        ELIGIBLE_ORDER_COMMITMENT_DOMAIN,
        eligible
            .get(..end)
            .ok_or(Sg0Error::IncompleteCheckpointBatch)?,
    )?;
    let first_order_index = base_cursor.checked_add(1).ok_or(Sg0Error::CountOverflow)?;
    let eligible_score_at_boundary = u128::try_from(end).map_err(|_| Sg0Error::CountOverflow)?;
    let mut eligible_work_at_boundary = Uint256::ZERO;
    for vertex in eligible
        .get(..end)
        .ok_or(Sg0Error::IncompleteCheckpointBatch)?
    {
        eligible_work_at_boundary = eligible_work_at_boundary
            .checked_add(work(graph, *vertex)?)
            .ok_or(Sg0Error::WorkOverflow)?;
    }
    let batch_commitment = checkpoint_batch_commitment(
        base_cursor,
        first_order_index,
        base_prefix_commitment,
        resulting_prefix_commitment,
        eligible_score_at_boundary,
        eligible_work_at_boundary,
        &entries,
    );
    Ok(VerifiedSg0EligiblePrefixBatchV1 {
        base_cursor,
        first_order_index,
        base_prefix_commitment,
        resulting_prefix_commitment,
        graph_commitment,
        total_order_commitment,
        eligible_score_at_boundary,
        eligible_work_at_boundary,
        entries,
        batch_commitment,
    })
}

fn derive_for_tips(
    graph: &impl ReceiverVerifiedSg0Graph,
    tips: &[VertexId],
) -> Result<Sg0OrderSnapshotV1, Sg0Error> {
    if tips.is_empty() {
        return Err(Sg0Error::InvalidParents);
    }
    let selected = tips
        .iter()
        .copied()
        .map(|tip| {
            ensure_vertex_exists(graph, tip)?;
            // Own the already qualified work field instead of reopening the
            // same metadata immediately after validating every tip.
            metadata(graph, tip).map(|data| (tip, data.blue_work()))
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .reduce(|left, right| {
            if right.1 > left.1 || (right.1 == left.1 && right.0 < left.0) {
                right
            } else {
                left
            }
        })
        .ok_or(Sg0Error::Invariant)?
        .0;

    let selected_parent = Sg0SelectedParentV1::Vertex(selected);
    let merge_order = merge_order_for(graph, tips, selected_parent)?;
    let mut blue = blue_closure(graph, selected)?;
    let mut virtual_colors = BTreeMap::new();
    for candidate in &merge_order {
        let mut trial = blue.clone();
        trial.insert(*candidate);
        if is_k_cluster(graph, &trial)? {
            blue = trial;
            virtual_colors.insert(*candidate, Sg0Color::Blue);
        } else {
            virtual_colors.insert(*candidate, Sg0Color::Red);
        }
    }

    let mut total_ids = order_through(graph, selected)?;
    total_ids.extend(merge_order.iter().copied());
    let expected = closure_for_tips(graph, tips)?;
    if total_ids.len() != expected.len()
        || total_ids.iter().copied().collect::<BTreeSet<_>>() != expected
    {
        return Err(Sg0Error::Invariant);
    }

    let mut total_order = Vec::with_capacity(total_ids.len());
    let mut eligible_order = Vec::new();
    let mut eligible_work = Uint256::ZERO;
    for id in total_ids {
        let color = if blue.contains(&id) {
            Sg0Color::Blue
        } else {
            Sg0Color::Red
        };
        if virtual_colors
            .get(&id)
            .is_some_and(|expected_color| *expected_color != color)
        {
            return Err(Sg0Error::Invariant);
        }
        total_order.push(Sg0OrderedVertexV1 {
            vertex_id: id,
            color,
        });
        if color == Sg0Color::Blue {
            eligible_order.push(id);
            eligible_work = eligible_work
                .checked_add(work(graph, id)?)
                .ok_or(Sg0Error::WorkOverflow)?;
        }
    }
    let vertices = all_vertex_ids(graph)?;
    let colored: Vec<_> = total_order
        .iter()
        .map(|entry| (entry.vertex_id, entry.color))
        .collect();
    Ok(Sg0OrderSnapshotV1 {
        graph_commitment: graph_commitment(graph, &vertices)?,
        selected_tip: Some(selected),
        total_order_commitment: colored_commitment(TOTAL_ORDER_COMMITMENT_DOMAIN, &colored)?,
        eligible_order_commitment: ids_commitment(
            ELIGIBLE_ORDER_COMMITMENT_DOMAIN,
            &eligible_order,
        )?,
        total_order,
        eligible_order,
        eligible_work,
    })
}

fn validated_parents(
    graph: &impl ReceiverVerifiedSg0Graph,
    vertex: VertexId,
) -> Result<Vec<VertexId>, Sg0Error> {
    let parent_set = graph.parent_set(vertex)?;
    validate_supplied_parents(graph, &parent_set, Some(vertex))
}

fn validate_supplied_parents(
    graph: &impl ReceiverVerifiedSg0Graph,
    parent_set: &Sg0ParentSetV1,
    child: Option<VertexId>,
) -> Result<Vec<VertexId>, Sg0Error> {
    let ordinary = parent_set.ordinary();
    match parent_set {
        Sg0ParentSetV1::Anchor => return Ok(Vec::new()),
        Sg0ParentSetV1::Vertices(_) => {
            if ordinary.is_empty()
                || ordinary.len() > SG0_V1_MAX_PARENTS
                || ordinary.windows(2).any(|pair| pair[0] >= pair[1])
            {
                return Err(Sg0Error::InvalidParents);
            }
        }
    }
    for parent in ordinary {
        ensure_vertex_exists(graph, *parent)?;
        if child == Some(*parent) {
            return Err(Sg0Error::RedundantOrCyclicParent);
        }
    }
    if ordinary.len() == 2
        && (is_ancestor(graph, ordinary[0], ordinary[1])?
            || is_ancestor(graph, ordinary[1], ordinary[0])?)
    {
        return Err(Sg0Error::RedundantOrCyclicParent);
    }
    if let Some(child) = child {
        for parent in ordinary {
            if is_ancestor(graph, child, *parent)? {
                return Err(Sg0Error::RedundantOrCyclicParent);
            }
        }
    }
    Ok(ordinary.to_vec())
}

fn select_parent(
    graph: &impl ReceiverVerifiedSg0Graph,
    parents: &[VertexId],
) -> Result<Sg0SelectedParentV1, Sg0Error> {
    if parents.is_empty() {
        return Ok(Sg0SelectedParentV1::Anchor);
    }
    let mut selected = parents[0];
    let mut selected_work = metadata(graph, selected)?.blue_work();
    for candidate in &parents[1..] {
        let candidate_work = metadata(graph, *candidate)?.blue_work();
        if candidate_work > selected_work
            || (candidate_work == selected_work && *candidate < selected)
        {
            selected = *candidate;
            selected_work = candidate_work;
        }
    }
    Ok(Sg0SelectedParentV1::Vertex(selected))
}

fn merge_order_for(
    graph: &impl ReceiverVerifiedSg0Graph,
    parents: &[VertexId],
    selected_parent: Sg0SelectedParentV1,
) -> Result<Vec<VertexId>, Sg0Error> {
    if parents.is_empty() {
        return Ok(Vec::new());
    }
    let mut past = BTreeSet::new();
    let mut selected_closure = None;
    for parent in parents {
        ensure_vertex_exists(graph, *parent)?;
        let mut closure = collect_past(graph, *parent)?;
        closure.insert(*parent);
        past.extend(closure.iter().copied());
        if selected_parent == Sg0SelectedParentV1::Vertex(*parent) {
            selected_closure = Some(closure);
        }
    }
    let selected_closure = match selected_parent {
        Sg0SelectedParentV1::Anchor => BTreeSet::new(),
        Sg0SelectedParentV1::Vertex(selected) => {
            if let Some(closure) = selected_closure {
                closure
            } else {
                let mut closure = collect_past(graph, selected)?;
                closure.insert(selected);
                closure
            }
        }
    };
    let merge: BTreeSet<_> = past.difference(&selected_closure).copied().collect();
    kahn_merge_order(graph, &merge)
}

fn kahn_merge_order(
    graph: &impl ReceiverVerifiedSg0Graph,
    merge: &BTreeSet<VertexId>,
) -> Result<Vec<VertexId>, Sg0Error> {
    let mut indegree = BTreeMap::new();
    let mut children: BTreeMap<VertexId, Vec<VertexId>> = BTreeMap::new();
    let mut work_cache = BTreeMap::new();
    for vertex in merge {
        let parents = validated_parents(graph, *vertex)?;
        let degree = parents
            .iter()
            .filter(|parent| merge.contains(parent))
            .count();
        indegree.insert(*vertex, degree);
        work_cache.insert(*vertex, metadata(graph, *vertex)?.blue_work());
        for parent in parents {
            if merge.contains(&parent) {
                children.entry(parent).or_default().push(*vertex);
            }
        }
    }
    let mut ready = BTreeSet::new();
    for (vertex, degree) in &indegree {
        if *degree == 0 {
            ready.insert((work_cache[vertex], *vertex));
        }
    }
    let mut ordered = Vec::with_capacity(merge.len());
    while let Some((candidate_work, candidate)) = ready.iter().next().copied() {
        ready.remove(&(candidate_work, candidate));
        ordered.push(candidate);
        if let Some(candidate_children) = children.get(&candidate) {
            for child in candidate_children {
                let degree = indegree.get_mut(child).ok_or(Sg0Error::Invariant)?;
                *degree = degree.checked_sub(1).ok_or(Sg0Error::Invariant)?;
                if *degree == 0 {
                    ready.insert((work_cache[child], *child));
                }
            }
        }
    }
    if ordered.len() != merge.len() {
        return Err(Sg0Error::Cycle);
    }
    Ok(ordered)
}

fn blue_closure(
    graph: &impl ReceiverVerifiedSg0Graph,
    tip: VertexId,
) -> Result<BTreeSet<VertexId>, Sg0Error> {
    let mut blue = BTreeSet::new();
    let mut seen_selected = BTreeSet::new();
    let mut cursor = Some(tip);
    while let Some(vertex) = cursor {
        if !seen_selected.insert(vertex) {
            return Err(Sg0Error::Cycle);
        }
        let data = metadata(graph, vertex)?;
        blue.insert(vertex);
        blue.extend(data.merge_blues().iter().copied());
        cursor = match data.selected_parent() {
            Sg0SelectedParentV1::Anchor => None,
            Sg0SelectedParentV1::Vertex(parent) => Some(parent),
        };
    }
    Ok(blue)
}

fn order_through(
    graph: &impl ReceiverVerifiedSg0Graph,
    tip: VertexId,
) -> Result<Vec<VertexId>, Sg0Error> {
    let mut selected_chain = Vec::new();
    let mut seen = BTreeSet::new();
    let mut cursor = Some(tip);
    while let Some(vertex) = cursor {
        if !seen.insert(vertex) {
            return Err(Sg0Error::Cycle);
        }
        let selected_parent = metadata(graph, vertex)?.selected_parent();
        // Only this immutable field is retained in the operation's existing
        // selected-chain list; no merge-list/metadata/validity cache is added.
        selected_chain.push((vertex, selected_parent));
        cursor = match selected_parent {
            Sg0SelectedParentV1::Anchor => None,
            Sg0SelectedParentV1::Vertex(parent) => Some(parent),
        };
    }
    selected_chain.reverse();
    let mut order = Vec::new();
    let mut emitted = BTreeSet::new();
    for (vertex, selected_parent) in selected_chain {
        let parents = validated_parents(graph, vertex)?;
        for merge_vertex in merge_order_for(graph, &parents, selected_parent)? {
            if !emitted.insert(merge_vertex) {
                return Err(Sg0Error::Invariant);
            }
            order.push(merge_vertex);
        }
        if !emitted.insert(vertex) {
            return Err(Sg0Error::Invariant);
        }
        order.push(vertex);
    }
    Ok(order)
}

fn is_k_cluster(
    graph: &impl ReceiverVerifiedSg0Graph,
    candidates: &BTreeSet<VertexId>,
) -> Result<bool, Sg0Error> {
    // Count each strict comparable pair once, from descendant to ancestor.
    // The pairwise implementation repeated a full ancestry traversal for
    // every pair (cubic work on a chain). Keep only one transient past set
    // plus one counter per candidate; no persistent closure cache is needed.
    let initial = candidates.len().saturating_sub(1);
    let mut anticone_counts: BTreeMap<_, _> = candidates.iter().map(|id| (*id, initial)).collect();
    for candidate in candidates {
        let past = collect_past(graph, *candidate)?;
        if past.contains(candidate) {
            return Err(Sg0Error::Cycle);
        }
        for ancestor in past.intersection(candidates) {
            for endpoint in [candidate, ancestor] {
                let count = anticone_counts
                    .get_mut(endpoint)
                    .ok_or(Sg0Error::Invariant)?;
                *count = count.checked_sub(1).ok_or(Sg0Error::Invariant)?;
            }
        }
    }
    Ok(anticone_counts.values().all(|count| *count <= SG0_V1_K))
}

fn is_ancestor(
    graph: &impl ReceiverVerifiedSg0Graph,
    ancestor: VertexId,
    descendant: VertexId,
) -> Result<bool, Sg0Error> {
    graph.receiver_verified_is_ancestor(ancestor, descendant)
}

fn collect_past(
    graph: &impl ReceiverVerifiedSg0Graph,
    vertex: VertexId,
) -> Result<BTreeSet<VertexId>, Sg0Error> {
    let mut result = BTreeSet::new();
    graph.visit_strict_past_ids(vertex, &mut |ancestor| {
        if !result.insert(ancestor) {
            return Err(Sg0Error::Invariant);
        }
        Ok(())
    })?;
    Ok(result)
}

fn reference_visit_strict_past(
    graph: &impl ReceiverVerifiedSg0Graph,
    vertex: VertexId,
    visitor: &mut dyn FnMut(VertexId) -> Result<(), Sg0Error>,
) -> Result<(), Sg0Error> {
    ensure_vertex_exists(graph, vertex)?;
    let mut result = BTreeSet::new();
    let mut active = BTreeSet::new();
    let mut stack = Vec::new();
    for parent in validated_parent_shape_only(graph, vertex)?
        .into_iter()
        .rev()
    {
        stack.push((parent, false));
    }
    while let Some((current, exiting)) = stack.pop() {
        if exiting {
            active.remove(&current);
            result.insert(current);
            continue;
        }
        if result.contains(&current) {
            continue;
        }
        if current == vertex || !active.insert(current) {
            return Err(Sg0Error::Cycle);
        }
        ensure_vertex_exists(graph, current)?;
        stack.push((current, true));
        for parent in validated_parent_shape_only(graph, current)?
            .into_iter()
            .rev()
        {
            stack.push((parent, false));
        }
    }
    for ancestor in result {
        visitor(ancestor)?;
    }
    Ok(())
}

fn closure_for_tips(
    graph: &impl ReceiverVerifiedSg0Graph,
    tips: &[VertexId],
) -> Result<BTreeSet<VertexId>, Sg0Error> {
    let mut closure = BTreeSet::new();
    for tip in tips {
        ensure_vertex_exists(graph, *tip)?;
        closure.extend(collect_past(graph, *tip)?);
        closure.insert(*tip);
    }
    Ok(closure)
}

fn validated_parent_shape_only(
    graph: &impl ReceiverVerifiedSg0Graph,
    vertex: VertexId,
) -> Result<Vec<VertexId>, Sg0Error> {
    match graph.parent_set(vertex)? {
        Sg0ParentSetV1::Anchor => Ok(Vec::new()),
        Sg0ParentSetV1::Vertices(parents)
            if !parents.is_empty()
                && parents.len() <= SG0_V1_MAX_PARENTS
                && parents.windows(2).all(|pair| pair[0] < pair[1]) =>
        {
            Ok(parents)
        }
        Sg0ParentSetV1::Vertices(_) => Err(Sg0Error::InvalidParents),
    }
}

fn all_vertex_ids(graph: &impl ReceiverVerifiedSg0Graph) -> Result<Vec<VertexId>, Sg0Error> {
    let mut ids = Vec::new();
    graph.visit_vertex_ids(&mut |id| {
        ids.push(id);
        Ok(())
    })?;
    ids.sort_unstable();
    if ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(Sg0Error::Invariant);
    }
    Ok(ids)
}

fn ensure_vertex_exists(
    graph: &impl ReceiverVerifiedSg0Graph,
    vertex: VertexId,
) -> Result<(), Sg0Error> {
    if graph.receiver_verified_contains(vertex)? {
        Ok(())
    } else {
        Err(Sg0Error::MissingVertex)
    }
}

fn metadata(
    graph: &impl ReceiverVerifiedSg0Graph,
    vertex: VertexId,
) -> Result<Sg0VertexDataV1, Sg0Error> {
    graph.vertex_data(vertex)?.ok_or(Sg0Error::MissingMetadata)
}

fn work(graph: &impl ReceiverVerifiedSg0Graph, vertex: VertexId) -> Result<Sg0Work, Sg0Error> {
    let value = Uint256::from_be_bytes(graph.receiver_verified_work_be(vertex)?);
    if value.is_zero() {
        return Err(Sg0Error::ZeroWork);
    }
    Ok(value)
}

fn graph_commitment(
    graph: &impl ReceiverVerifiedSg0Graph,
    vertices: &[VertexId],
) -> Result<Hash32, Sg0Error> {
    let mut hasher = Sha256::new();
    hasher.update(GRAPH_COMMITMENT_DOMAIN);
    update_len(&mut hasher, vertices.len())?;
    for vertex in vertices {
        hasher.update(vertex.as_bytes());
        match graph.parent_set(*vertex)? {
            Sg0ParentSetV1::Anchor => hasher.update([0]),
            Sg0ParentSetV1::Vertices(parents) => {
                hasher.update([1]);
                update_len(&mut hasher, parents.len())?;
                for parent in parents {
                    hasher.update(parent.as_bytes());
                }
            }
        }
        hasher.update(work(graph, *vertex)?.to_be_bytes());
        let data = metadata(graph, *vertex)?;
        match data.selected_parent() {
            Sg0SelectedParentV1::Anchor => hasher.update([0]),
            Sg0SelectedParentV1::Vertex(parent) => {
                hasher.update([1]);
                hasher.update(parent.as_bytes());
            }
        }
        hasher.update(data.merge_order_commitment().as_bytes());
        hasher.update(data.blue_score().to_le_bytes());
        hasher.update(data.blue_work().to_be_bytes());
    }
    Ok(Hash32::new(hasher.finalize().into()))
}

fn colored_commitment(domain: &[u8], ordered: &[(VertexId, Sg0Color)]) -> Result<Hash32, Sg0Error> {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    update_len(&mut hasher, ordered.len())?;
    for (vertex, color) in ordered {
        hasher.update(vertex.as_bytes());
        hasher.update([match color {
            Sg0Color::Blue => 1,
            Sg0Color::Red => 0,
        }]);
    }
    Ok(Hash32::new(hasher.finalize().into()))
}

fn ids_commitment(domain: &[u8], ordered: &[VertexId]) -> Result<Hash32, Sg0Error> {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    update_len(&mut hasher, ordered.len())?;
    for vertex in ordered {
        hasher.update(vertex.as_bytes());
    }
    Ok(Hash32::new(hasher.finalize().into()))
}

#[allow(clippy::too_many_arguments)]
fn checkpoint_batch_commitment(
    base_cursor: u64,
    first_order_index: u64,
    base_prefix_commitment: Hash32,
    resulting_prefix_commitment: Hash32,
    eligible_score_at_boundary: u128,
    eligible_work_at_boundary: Sg0Work,
    entries: &[VertexId; SG0_V1_CHECKPOINT_ELIGIBLE_SPAN],
) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(CHECKPOINT_BATCH_COMMITMENT_DOMAIN);
    hasher.update(base_cursor.to_le_bytes());
    hasher.update(first_order_index.to_le_bytes());
    hasher.update(base_prefix_commitment.as_bytes());
    hasher.update(resulting_prefix_commitment.as_bytes());
    hasher.update(eligible_score_at_boundary.to_le_bytes());
    hasher.update(eligible_work_at_boundary.to_be_bytes());
    for entry in entries {
        hasher.update(entry.as_bytes());
    }
    Hash32::new(hasher.finalize().into())
}

fn update_len(hasher: &mut Sha256, length: usize) -> Result<(), Sg0Error> {
    let length = u64::try_from(length).map_err(|_| Sg0Error::CountOverflow)?;
    hasher.update(length.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct TestVertex {
        parents: Sg0ParentSetV1,
        work: [u8; 32],
    }

    #[derive(Default)]
    struct TestGraph {
        vertices: BTreeMap<VertexId, TestVertex>,
        data: BTreeMap<VertexId, Sg0VertexDataV1>,
        past_visits: std::cell::Cell<usize>,
        metadata_reads: std::cell::Cell<usize>,
    }

    impl TestGraph {
        fn id(value: u8) -> VertexId {
            VertexId::from_bytes([value; 32])
        }

        fn work(value: u64) -> [u8; 32] {
            let mut bytes = [0_u8; 32];
            bytes[24..].copy_from_slice(&value.to_be_bytes());
            bytes
        }

        fn push(&mut self, value: u8, parents: Sg0ParentSetV1, work: u64) {
            let id = Self::id(value);
            self.vertices.insert(
                id,
                TestVertex {
                    parents,
                    work: Self::work(work),
                },
            );
            let data = derive_vertex_data(self, id).expect("valid test vertex");
            self.data.insert(id, data);
        }
    }

    impl ReceiverVerifiedSg0Graph for TestGraph {
        fn visit_vertex_ids(
            &self,
            visitor: &mut dyn FnMut(VertexId) -> Result<(), Sg0Error>,
        ) -> Result<(), Sg0Error> {
            for id in self.vertices.keys() {
                visitor(*id)?;
            }
            Ok(())
        }

        fn parent_set(&self, vertex: VertexId) -> Result<Sg0ParentSetV1, Sg0Error> {
            self.vertices
                .get(&vertex)
                .map(|entry| entry.parents.clone())
                .ok_or(Sg0Error::MissingVertex)
        }

        fn receiver_verified_work_be(&self, vertex: VertexId) -> Result<[u8; 32], Sg0Error> {
            self.vertices
                .get(&vertex)
                .map(|entry| entry.work)
                .ok_or(Sg0Error::MissingVertex)
        }

        fn vertex_data(&self, vertex: VertexId) -> Result<Option<Sg0VertexDataV1>, Sg0Error> {
            self.metadata_reads.set(self.metadata_reads.get() + 1);
            Ok(self.data.get(&vertex).cloned())
        }

        fn visit_strict_past_ids(
            &self,
            vertex: VertexId,
            visitor: &mut dyn FnMut(VertexId) -> Result<(), Sg0Error>,
        ) -> Result<(), Sg0Error> {
            self.past_visits.set(self.past_visits.get() + 1);
            reference_visit_strict_past(self, vertex, visitor)
        }
    }

    // Exact pre-change algorithms, frozen as local test-only byte/result oracles.
    fn reference_merge_walk(
        graph: &impl ReceiverVerifiedSg0Graph,
        parents: &[VertexId],
        selected_parent: Sg0SelectedParentV1,
    ) -> Result<Vec<VertexId>, Sg0Error> {
        if parents.is_empty() {
            return Ok(Vec::new());
        }
        let past = closure_for_tips(graph, parents)?;
        let selected_closure = match selected_parent {
            Sg0SelectedParentV1::Anchor => BTreeSet::new(),
            Sg0SelectedParentV1::Vertex(selected) => {
                let mut closure = collect_past(graph, selected)?;
                closure.insert(selected);
                closure
            }
        };
        let merge: BTreeSet<_> = past.difference(&selected_closure).copied().collect();
        kahn_merge_order(graph, &merge)
    }

    fn reference_selected_walk(
        graph: &impl ReceiverVerifiedSg0Graph,
        tip: VertexId,
    ) -> Result<Vec<VertexId>, Sg0Error> {
        let mut selected_chain = Vec::new();
        let mut seen = BTreeSet::new();
        let mut cursor = Some(tip);
        while let Some(vertex) = cursor {
            if !seen.insert(vertex) {
                return Err(Sg0Error::Cycle);
            }
            selected_chain.push(vertex);
            cursor = match metadata(graph, vertex)?.selected_parent() {
                Sg0SelectedParentV1::Anchor => None,
                Sg0SelectedParentV1::Vertex(parent) => Some(parent),
            };
        }
        selected_chain.reverse();
        let mut order = Vec::new();
        let mut emitted = BTreeSet::new();
        for vertex in selected_chain {
            let parents = validated_parents(graph, vertex)?;
            let selected_parent = metadata(graph, vertex)?.selected_parent();
            for merge_vertex in reference_merge_walk(graph, &parents, selected_parent)? {
                if !emitted.insert(merge_vertex) {
                    return Err(Sg0Error::Invariant);
                }
                order.push(merge_vertex);
            }
            if !emitted.insert(vertex) {
                return Err(Sg0Error::Invariant);
            }
            order.push(vertex);
        }
        Ok(order)
    }

    fn reference_selected_tips(
        graph: &impl ReceiverVerifiedSg0Graph,
        tips: &[VertexId],
    ) -> Result<Sg0OrderSnapshotV1, Sg0Error> {
        if tips.is_empty() {
            return Err(Sg0Error::InvalidParents);
        }
        for tip in tips {
            ensure_vertex_exists(graph, *tip)?;
            metadata(graph, *tip)?;
        }
        let selected = tips
            .iter()
            .copied()
            .map(|tip| metadata(graph, tip).map(|data| (tip, data.blue_work())))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .reduce(|left, right| {
                if right.1 > left.1 || (right.1 == left.1 && right.0 < left.0) {
                    right
                } else {
                    left
                }
            })
            .ok_or(Sg0Error::Invariant)?
            .0;

        let selected_parent = Sg0SelectedParentV1::Vertex(selected);
        let merge_order = reference_merge_walk(graph, tips, selected_parent)?;
        let mut blue = blue_closure(graph, selected)?;
        let mut virtual_colors = BTreeMap::new();
        for candidate in &merge_order {
            let mut trial = blue.clone();
            trial.insert(*candidate);
            if is_k_cluster(graph, &trial)? {
                blue = trial;
                virtual_colors.insert(*candidate, Sg0Color::Blue);
            } else {
                virtual_colors.insert(*candidate, Sg0Color::Red);
            }
        }

        let mut total_ids = reference_selected_walk(graph, selected)?;
        total_ids.extend(merge_order.iter().copied());
        let expected = closure_for_tips(graph, tips)?;
        if total_ids.len() != expected.len()
            || total_ids.iter().copied().collect::<BTreeSet<_>>() != expected
        {
            return Err(Sg0Error::Invariant);
        }

        let mut total_order = Vec::with_capacity(total_ids.len());
        let mut eligible_order = Vec::new();
        let mut eligible_work = Uint256::ZERO;
        for id in total_ids {
            let color = if blue.contains(&id) {
                Sg0Color::Blue
            } else {
                Sg0Color::Red
            };
            if virtual_colors
                .get(&id)
                .is_some_and(|expected_color| *expected_color != color)
            {
                return Err(Sg0Error::Invariant);
            }
            total_order.push(Sg0OrderedVertexV1 {
                vertex_id: id,
                color,
            });
            if color == Sg0Color::Blue {
                eligible_order.push(id);
                eligible_work = eligible_work
                    .checked_add(work(graph, id)?)
                    .ok_or(Sg0Error::WorkOverflow)?;
            }
        }
        let vertices = all_vertex_ids(graph)?;
        let colored: Vec<_> = total_order
            .iter()
            .map(|entry| (entry.vertex_id, entry.color))
            .collect();
        Ok(Sg0OrderSnapshotV1 {
            graph_commitment: graph_commitment(graph, &vertices)?,
            selected_tip: Some(selected),
            total_order_commitment: colored_commitment(TOTAL_ORDER_COMMITMENT_DOMAIN, &colored)?,
            eligible_order_commitment: ids_commitment(
                ELIGIBLE_ORDER_COMMITMENT_DOMAIN,
                &eligible_order,
            )?,
            total_order,
            eligible_order,
            eligible_work,
        })
    }

    #[test]
    fn selected_metadata_fields_preserve_all_snapshot_bytes_and_remove_exact_duplicate_reads() {
        let mut graph = TestGraph::default();
        graph.push(1, Sg0ParentSetV1::anchor(), 1);
        for value in 2..=5 {
            graph.push(
                value,
                Sg0ParentSetV1::vertices(vec![TestGraph::id(1)]).unwrap(),
                u64::from(value),
            );
        }
        graph.push(
            6,
            Sg0ParentSetV1::vertices(vec![TestGraph::id(2), TestGraph::id(3)]).unwrap(),
            1,
        );
        graph.push(
            7,
            Sg0ParentSetV1::vertices(vec![TestGraph::id(4), TestGraph::id(5)]).unwrap(),
            1,
        );
        graph.push(
            8,
            Sg0ParentSetV1::vertices(vec![TestGraph::id(6), TestGraph::id(7)]).unwrap(),
            1,
        );
        for tips in [vec![1], vec![2], vec![2, 3], vec![6, 7], vec![8]] {
            let tips: Vec<_> = tips.into_iter().map(TestGraph::id).collect();
            graph.metadata_reads.set(0);
            graph.past_visits.set(0);
            let reference = reference_selected_tips(&graph, &tips).unwrap();
            let prior_reads = graph.metadata_reads.get();
            let prior_walks = graph.past_visits.get();
            graph.metadata_reads.set(0);
            graph.past_visits.set(0);
            let actual = derive_for_tips(&graph, &tips).unwrap();
            let actual_reads = graph.metadata_reads.get();
            let actual_walks = graph.past_visits.get();
            assert_eq!(actual, reference); // every snapshot field and commitment
            let mut chain_len = 0;
            let mut cursor = reference.selected_tip;
            while let Some(vertex) = cursor {
                chain_len += 1;
                cursor = match graph.data[&vertex].selected_parent() {
                    Sg0SelectedParentV1::Anchor => None,
                    Sg0SelectedParentV1::Vertex(parent) => Some(parent),
                };
            }
            assert_eq!(prior_reads - actual_reads, tips.len() + chain_len);
            assert_eq!(prior_walks - actual_walks, chain_len);
        }
    }

    #[test]
    fn selected_merge_closure_reuses_only_an_already_read_parent_past() {
        let mut graph = TestGraph::default();
        graph.push(1, Sg0ParentSetV1::anchor(), 1);
        for value in 2..=4 {
            graph.push(
                value,
                Sg0ParentSetV1::vertices(vec![TestGraph::id(1)]).unwrap(),
                u64::from(value),
            );
        }
        for (parents, selected, saved_walks) in [
            (vec![2], Sg0SelectedParentV1::Vertex(TestGraph::id(2)), 1),
            (vec![2, 3], Sg0SelectedParentV1::Vertex(TestGraph::id(2)), 1),
            (vec![2, 3], Sg0SelectedParentV1::Vertex(TestGraph::id(3)), 1),
            (vec![2, 3], Sg0SelectedParentV1::Vertex(TestGraph::id(4)), 0),
            (vec![2, 3], Sg0SelectedParentV1::Anchor, 0),
            (vec![], Sg0SelectedParentV1::Vertex(TestGraph::id(99)), 0),
        ] {
            let parents: Vec<_> = parents.into_iter().map(TestGraph::id).collect();
            graph.past_visits.set(0);
            let reference = reference_merge_walk(&graph, &parents, selected).unwrap();
            let prior_walks = graph.past_visits.get();
            graph.past_visits.set(0);
            assert_eq!(
                merge_order_for(&graph, &parents, selected).unwrap(),
                reference
            );
            assert_eq!(prior_walks - graph.past_visits.get(), saved_walks);
        }
    }

    #[test]
    fn selected_merge_closure_still_reads_every_parent_and_refuses_bad_ancestry() {
        let mut graph = TestGraph::default();
        graph.push(1, Sg0ParentSetV1::anchor(), 1);
        graph.push(2, Sg0ParentSetV1::anchor(), 1);
        graph.push(
            3,
            Sg0ParentSetV1::vertices(vec![TestGraph::id(2)]).unwrap(),
            1,
        );
        let parents = [TestGraph::id(1), TestGraph::id(3)];
        let selected = Sg0SelectedParentV1::Vertex(parents[0]);
        graph.vertices.remove(&TestGraph::id(2));
        assert_eq!(
            merge_order_for(&graph, &parents, selected),
            reference_merge_walk(&graph, &parents, selected)
        );
        assert_eq!(
            merge_order_for(&graph, &parents, selected),
            Err(Sg0Error::MissingVertex)
        );
        graph.vertices.get_mut(&parents[1]).unwrap().parents =
            Sg0ParentSetV1::vertices(vec![parents[1]]).unwrap();
        assert_eq!(
            merge_order_for(&graph, &parents, selected),
            reference_merge_walk(&graph, &parents, selected)
        );
        assert!(merge_order_for(&graph, &parents, selected).is_err());
        let missing_selected = Sg0SelectedParentV1::Vertex(TestGraph::id(99));
        assert_eq!(
            merge_order_for(&graph, &[parents[0]], missing_selected),
            reference_merge_walk(&graph, &[parents[0]], missing_selected)
        );
        assert_eq!(
            merge_order_for(&graph, &[parents[0]], missing_selected),
            Err(Sg0Error::MissingVertex)
        );
    }

    #[test]
    fn selected_metadata_fields_keep_missing_metadata_vertex_and_cycle_refusal() {
        let mut graph = TestGraph::default();
        graph.push(1, Sg0ParentSetV1::anchor(), 1);
        graph.push(
            2,
            Sg0ParentSetV1::vertices(vec![TestGraph::id(1)]).unwrap(),
            1,
        );
        let tips = [TestGraph::id(2)];
        let metadata = graph.data.remove(&tips[0]).unwrap();
        assert_eq!(
            derive_for_tips(&graph, &tips),
            reference_selected_tips(&graph, &tips)
        );
        assert_eq!(
            derive_for_tips(&graph, &tips),
            Err(Sg0Error::MissingMetadata)
        );
        graph.data.insert(tips[0], metadata.clone());
        graph.data.get_mut(&tips[0]).unwrap().selected_parent =
            Sg0SelectedParentV1::Vertex(tips[0]);
        assert_eq!(
            derive_for_tips(&graph, &tips),
            reference_selected_tips(&graph, &tips)
        );
        assert_eq!(derive_for_tips(&graph, &tips), Err(Sg0Error::Cycle));
        graph.data.insert(tips[0], metadata);
        graph.vertices.remove(&TestGraph::id(1));
        assert_eq!(
            derive_for_tips(&graph, &tips),
            reference_selected_tips(&graph, &tips)
        );
        assert_eq!(derive_for_tips(&graph, &tips), Err(Sg0Error::MissingVertex));
    }

    #[test]
    fn cluster_check_walks_each_candidate_past_only_once() {
        let mut graph = TestGraph::default();
        for value in 1..=64 {
            let parents = if value == 1 {
                Sg0ParentSetV1::anchor()
            } else {
                Sg0ParentSetV1::vertices(vec![TestGraph::id(value - 1)]).unwrap()
            };
            graph.vertices.insert(
                TestGraph::id(value),
                TestVertex {
                    parents,
                    work: TestGraph::work(1),
                },
            );
        }
        let candidates = graph.vertices.keys().copied().collect();
        assert!(is_k_cluster(&graph, &candidates).unwrap());
        assert_eq!(graph.past_visits.get(), 64);
        graph.vertices.remove(&TestGraph::id(1));
        assert!(
            is_k_cluster(&graph, &candidates).is_err(),
            "missing ancestry still fails closed"
        );
    }

    #[test]
    fn cluster_pair_count_matches_reference_for_every_fork_merge_subset() {
        let mut graph = TestGraph::default();
        graph.push(1, Sg0ParentSetV1::anchor(), 1);
        for value in 2..=5 {
            graph.push(
                value,
                Sg0ParentSetV1::vertices(vec![TestGraph::id(1)]).unwrap(),
                1,
            );
        }
        graph.push(
            6,
            Sg0ParentSetV1::vertices(vec![TestGraph::id(2), TestGraph::id(3)]).unwrap(),
            1,
        );
        graph.push(
            7,
            Sg0ParentSetV1::vertices(vec![TestGraph::id(4), TestGraph::id(5)]).unwrap(),
            1,
        );
        graph.push(
            8,
            Sg0ParentSetV1::vertices(vec![TestGraph::id(6), TestGraph::id(7)]).unwrap(),
            1,
        );
        for mask in 0_u16..256 {
            let candidates: BTreeSet<_> = (1..=8)
                .filter(|value| mask & (1 << (value - 1)) != 0)
                .map(TestGraph::id)
                .collect();
            let mut reference = true;
            for candidate in &candidates {
                let mut incomparable = 0;
                for other in &candidates {
                    if candidate != other
                        && !is_ancestor(&graph, *candidate, *other).unwrap()
                        && !is_ancestor(&graph, *other, *candidate).unwrap()
                    {
                        incomparable += 1;
                    }
                }
                reference &= incomparable <= SG0_V1_K;
            }
            assert_eq!(
                is_k_cluster(&graph, &candidates).unwrap(),
                reference,
                "subset {mask}"
            );
        }
    }

    #[test]
    fn chain_is_blue_and_anchor_is_absent() {
        let mut graph = TestGraph::default();
        graph.push(1, Sg0ParentSetV1::anchor(), 1);
        graph.push(
            2,
            Sg0ParentSetV1::vertices(vec![TestGraph::id(1)]).unwrap(),
            2,
        );
        let snapshot = derive_virtual_order(&graph).unwrap();
        assert_eq!(
            snapshot.eligible_order(),
            &[TestGraph::id(1), TestGraph::id(2)]
        );
        assert_eq!(snapshot.eligible_work().to_be_bytes(), TestGraph::work(3));
        assert_eq!(snapshot.selected_tip(), Some(TestGraph::id(2)));
    }

    #[test]
    fn equal_blue_work_selects_smallest_id() {
        let mut graph = TestGraph::default();
        graph.push(1, Sg0ParentSetV1::anchor(), 1);
        graph.push(2, Sg0ParentSetV1::anchor(), 1);
        let snapshot = derive_virtual_order(&graph).unwrap();
        assert_eq!(snapshot.selected_tip(), Some(TestGraph::id(1)));
    }

    #[test]
    fn fourth_incomparable_sibling_is_red_at_k_two() {
        let mut graph = TestGraph::default();
        for value in 1..=4 {
            graph.push(value, Sg0ParentSetV1::anchor(), 1);
        }
        let snapshot = derive_virtual_order(&graph).unwrap();
        assert_eq!(snapshot.eligible_order().len(), 3);
        assert_eq!(snapshot.total_order().len(), 4);
        assert_eq!(
            snapshot
                .total_order()
                .iter()
                .filter(|entry| entry.color == Sg0Color::Red)
                .count(),
            1
        );
    }

    #[test]
    fn redundant_comparable_parents_reject() {
        let mut graph = TestGraph::default();
        graph.push(1, Sg0ParentSetV1::anchor(), 1);
        graph.push(
            2,
            Sg0ParentSetV1::vertices(vec![TestGraph::id(1)]).unwrap(),
            1,
        );
        let id = TestGraph::id(3);
        graph.vertices.insert(
            id,
            TestVertex {
                parents: Sg0ParentSetV1::vertices(vec![TestGraph::id(1), TestGraph::id(2)])
                    .unwrap(),
                work: TestGraph::work(1),
            },
        );
        assert_eq!(
            derive_vertex_data(&graph, id),
            Err(Sg0Error::RedundantOrCyclicParent)
        );
    }

    #[test]
    fn concurrent_fork_merge_is_insertion_order_independent() {
        fn graph_with_middle_order(middle: [u8; 2]) -> TestGraph {
            let mut graph = TestGraph::default();
            graph.push(1, Sg0ParentSetV1::anchor(), 1);
            for value in middle {
                graph.push(
                    value,
                    Sg0ParentSetV1::vertices(vec![TestGraph::id(1)]).unwrap(),
                    1,
                );
            }
            graph.push(
                4,
                Sg0ParentSetV1::vertices(vec![TestGraph::id(2), TestGraph::id(3)]).unwrap(),
                1,
            );
            graph
        }

        let left = derive_virtual_order(&graph_with_middle_order([2, 3])).unwrap();
        let right = derive_virtual_order(&graph_with_middle_order([3, 2])).unwrap();
        assert_eq!(left, right);
        assert_eq!(
            left.eligible_order(),
            &[
                TestGraph::id(1),
                TestGraph::id(2),
                TestGraph::id(3),
                TestGraph::id(4),
            ]
        );
    }

    #[test]
    fn eligible_delta_is_exact_longest_common_prefix() {
        let old = [TestGraph::id(1), TestGraph::id(2), TestGraph::id(3)];
        let new = [TestGraph::id(1), TestGraph::id(4), TestGraph::id(5)];
        let delta = diff_eligible_order(&old, &new).unwrap();
        assert_eq!(delta.common_prefix_len(), 1);
        assert_eq!(delta.removed(), &old[1..]);
        assert_eq!(delta.appended(), &new[1..]);
    }

    #[test]
    fn checkpoint_batch_is_exactly_eight_and_one_based() {
        let mut graph = TestGraph::default();
        for value in 1..=9 {
            let parents = if value == 1 {
                Sg0ParentSetV1::anchor()
            } else {
                Sg0ParentSetV1::vertices(vec![TestGraph::id(value - 1)]).unwrap()
            };
            graph.push(value, parents, 1);
        }
        let snapshot = derive_virtual_order(&graph).unwrap();
        let empty_prefix = ids_commitment(ELIGIBLE_ORDER_COMMITMENT_DOMAIN, &[]).unwrap();
        let batch = derive_checkpoint_order_batch(&graph, &snapshot, 0, empty_prefix).unwrap();
        assert_eq!(batch.first_order_index(), 1);
        assert_eq!(batch.entries().len(), 8);
        assert_eq!(batch.entries()[0], TestGraph::id(1));
        assert_eq!(batch.entries()[7], TestGraph::id(8));
        assert_eq!(batch.eligible_score_at_boundary(), 8);
        assert_eq!(batch.eligible_work_at_boundary(), Uint256::from_u64(8));
        assert_eq!(
            derive_checkpoint_order_batch(
                &graph,
                &snapshot,
                8,
                batch.resulting_prefix_commitment(),
            ),
            Err(Sg0Error::IncompleteCheckpointBatch)
        );
    }

    #[test]
    fn unrelated_red_evidence_does_not_change_eligible_batch_commitment() {
        let mut graph = TestGraph::default();
        for value in 1..=8 {
            let parents = if value == 1 {
                Sg0ParentSetV1::anchor()
            } else {
                Sg0ParentSetV1::vertices(vec![TestGraph::id(value - 1)]).unwrap()
            };
            graph.push(value, parents, 1);
        }
        let before = derive_virtual_order(&graph).unwrap();
        let empty = eligible_prefix_commitment_v1(before.eligible_order(), 0).unwrap();
        let before_batch = derive_checkpoint_order_batch(&graph, &before, 0, empty).unwrap();

        graph.push(250, Sg0ParentSetV1::anchor(), 1);
        let after = derive_virtual_order(&graph).unwrap();
        assert_eq!(after.eligible_order(), before.eligible_order());
        assert_ne!(after.graph_commitment(), before.graph_commitment());
        assert_ne!(
            after.total_order_commitment(),
            before.total_order_commitment()
        );
        let after_batch = derive_checkpoint_order_batch(&graph, &after, 0, empty).unwrap();
        assert_eq!(
            after_batch.batch_commitment(),
            before_batch.batch_commitment()
        );
    }

    #[test]
    fn parent_view_batch_matches_virtual_batch_for_equal_eligible_prefix() {
        let mut graph = TestGraph::default();
        for value in 1..=8 {
            let parents = if value == 1 {
                Sg0ParentSetV1::anchor()
            } else {
                Sg0ParentSetV1::vertices(vec![TestGraph::id(value - 1)]).unwrap()
            };
            graph.push(value, parents, 1);
        }
        graph.push(250, Sg0ParentSetV1::anchor(), 1);
        let parent_view = derive_parent_order_view(
            &graph,
            &Sg0ParentSetV1::vertices(vec![TestGraph::id(8)]).unwrap(),
        )
        .unwrap();
        let virtual_view = derive_virtual_order(&graph).unwrap();
        assert_eq!(parent_view.eligible_order(), virtual_view.eligible_order());
        let empty = eligible_prefix_commitment_v1(parent_view.eligible_order(), 0).unwrap();
        let parent_batch =
            derive_parent_checkpoint_order_batch(&graph, &parent_view, 0, empty).unwrap();
        let virtual_batch = derive_checkpoint_order_batch(&graph, &virtual_view, 0, empty).unwrap();
        assert_eq!(parent_batch.entries(), virtual_batch.entries());
        assert_eq!(
            parent_batch.resulting_prefix_commitment(),
            virtual_batch.resulting_prefix_commitment()
        );
        assert_eq!(
            parent_batch.eligible_work_at_boundary(),
            virtual_batch.eligible_work_at_boundary()
        );
        assert_eq!(
            parent_batch.batch_commitment(),
            virtual_batch.batch_commitment()
        );
        assert_ne!(
            parent_batch.total_order_commitment(),
            virtual_batch.total_order_commitment()
        );
    }

    #[test]
    fn parent_view_batch_rejects_stale_view_and_wrong_base() {
        let mut original = TestGraph::default();
        let mut changed = TestGraph::default();
        for value in 1..=8 {
            let parents = if value == 1 {
                Sg0ParentSetV1::anchor()
            } else {
                Sg0ParentSetV1::vertices(vec![TestGraph::id(value - 1)]).unwrap()
            };
            original.push(value, parents.clone(), 1);
            changed.push(value, parents, u64::from(value == 8) + 1);
        }
        let parent_set = Sg0ParentSetV1::vertices(vec![TestGraph::id(8)]).unwrap();
        let stale = derive_parent_order_view(&original, &parent_set).unwrap();
        let empty = eligible_prefix_commitment_v1(stale.eligible_order(), 0).unwrap();
        assert_eq!(
            derive_parent_checkpoint_order_batch(&changed, &stale, 0, empty),
            Err(Sg0Error::ParentViewMismatch)
        );
        let current = derive_parent_order_view(&changed, &parent_set).unwrap();
        assert_eq!(
            derive_parent_checkpoint_order_batch(&changed, &current, 0, Hash32::new([9; 32])),
            Err(Sg0Error::BasePrefixMismatch)
        );
    }
}
