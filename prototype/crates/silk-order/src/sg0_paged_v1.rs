//! Bounded replay verification of immutable receiver-local DAG transcripts.
//! Saved completion flags, hashes and cursors are never execution authority.
use super::*;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
#[path = "sg0_paged_v1/append.rs"]
mod append;
pub use append::{PagedAppendGraphV1, PagedAppendPassV1, PagedAppendRecoveryV1};
#[path = "sg0_paged_v1/parent_metadata.rs"]
mod parent_metadata;
pub use parent_metadata::{PagedParentMetadataV1, VerifiedPagedVertexTemplateV1};
type Result<T> = std::result::Result<T, Sg0Error>;
const MAX_FACT: usize = 1024 * 1024;
/// Number of freshly verified sole-tip appends sealed into one durable page.
pub const DURABLE_APPEND_PAGE_V1: u64 = 64;
/// Explicit local research bound, not a consensus or wire-format limit.
pub const DURABLE_APPEND_MAX_V1: u64 = 4096;
struct Source {
    total: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DagOrderEntryV1 {
    id: [u8; 32],
    blue: bool,
}

/// Receiver-admitted, immutable, bounded-read graph and parent-first inventory.
/// The binding must change whenever its complete admitted inventory changes.
pub trait PagedGraphV1: ReceiverVerifiedSg0Graph {
    /// Receiver-owned source binding, not a peer assertion.
    fn binding(&self) -> [u8; 32];
    /// Exact complete admitted inventory size.
    fn count(&self) -> u64;
    /// One parent-first ID and fixed-size continuation.
    fn next_id(
        &self,
        ordinal: u64,
        cursor: Option<[u64; 3]>,
    ) -> Result<(VertexId, Option<[u64; 3]>)>;
}
/// Immutable authenticated transcript/index view. Implementations must bind
/// exact local heads, authenticate every read, cap record size and never change
/// a binding's contents. Bytes returned here are still logically untrusted.
pub trait TranscriptV1 {
    /// Binding of both immutable archive heads and source context.
    fn binding(&self) -> [u8; 32];
    /// Authenticated record, bounded to 1 MiB.
    fn record(&self, key: [u8; 32]) -> Result<Option<Vec<u8>>>;
    /// Candidate sorted inventory ID; the verifier checks its sequence/membership.
    fn sorted_id(&self, ordinal: u64) -> Result<[u8; 32]>;
    /// Logically untrusted ancestry bits. The default reads the original local
    /// matrix; a shared sparse store can supply the same relation by vertex ID.
    /// Fresh replay always checks every cell against its defining recurrence.
    fn ancestry_flags(&self, descendant: u64, ancestor: u64) -> Result<u8> {
        let bytes = self
            .record(key(b'r', descendant, ancestor))?
            .ok_or(Sg0Error::Invariant)?;
        let value: u8 = serde_json::from_slice(&bytes).map_err(|_| Sg0Error::Invariant)?;
        if value > 7 || serde_json::to_vec(&value).map_err(|_| Sg0Error::Invariant)? != bytes {
            return Err(Sg0Error::Invariant);
        }
        Ok(value)
    }
    /// Binding of receiver-local sealed append pages. Live, unsealed receipts do
    /// not change this value and never survive process exit as authority.
    fn durable_append_binding(&self) -> [u8; 32] {
        [0; 32]
    }
    /// Number of chronological IDs covered by sealed append pages.
    fn durable_append_count(&self) -> u64 {
        0
    }
    /// One authenticated chronological append ID. Only ordinals below
    /// `durable_append_count` belong to the sealed prefix.
    fn durable_append_id(&self, _ordinal: u64) -> Result<VertexId> {
        Err(Sg0Error::Invariant)
    }
    /// Receiver-local ordinal for an authenticated append ID. Consumers must
    /// apply the sealed/live bound appropriate to their capability.
    fn durable_append_ordinal(&self, _id: VertexId) -> Result<Option<u64>> {
        Ok(None)
    }
    /// One ID from a sealed page's strictly sorted permutation.
    fn durable_append_sorted_id(&self, _page: u64, _offset: u64) -> Result<VertexId> {
        Err(Sg0Error::Invariant)
    }
    /// Number of atomically completed journal entries, including the current
    /// unsealed page. This is restart input to verify, never authority itself.
    fn append_journal_count(&self) -> u64 {
        self.durable_append_count()
    }
    /// One authenticated completed journal entry in admission order.
    fn append_journal_id(&self, ordinal: u64) -> Result<VertexId> {
        self.durable_append_id(ordinal)
    }
    /// Journal ordinal for one authenticated completed ID.
    fn append_journal_ordinal(&self, id: VertexId) -> Result<Option<u64>> {
        self.durable_append_ordinal(id)
    }
    /// Candidate from an interrupted two-phase local append, if present.
    fn pending_append_id(&self) -> Result<Option<VertexId>> {
        Ok(None)
    }
}
fn get<T: DeserializeOwned>(a: &impl TranscriptV1, key: [u8; 32]) -> Result<Option<T>> {
    let Some(bytes) = a.record(key)? else {
        return Ok(None);
    };
    if bytes.len() > MAX_FACT {
        return Err(Sg0Error::ResourceBudget);
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| Sg0Error::Invariant)
}
// Hide future emissions during replay. An early stored position is accepted
// only when its previously replay-checked output actually names this vertex.
fn emitted(a: &impl TranscriptV1, s: &State, v: u64) -> Result<Option<u64>> {
    let Some(position) = get::<u64>(a, key(b'e', v, 0))? else {
        return Ok(None);
    };
    if position >= s.ordered {
        return Ok(None);
    }
    let output: DagOrderEntryV1 = must(a, key(b'o', position, 0))?;
    if output.id != fact(a, v)?.id {
        return Err(Sg0Error::Invariant);
    }
    Ok(Some(position))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum VerifyPhase {
    Replay,
    Graph,
    Count,
    Order,
    Done,
}

/// Fresh, non-deserializable verifier continuation. Each call checks at most
/// 16 replay/hash units; no reference snapshot or history-sized vector exists.
#[derive(Clone)]
pub struct PagedOrderVerifierV1 {
    graph_binding: [u8; 32],
    transcript_binding: [u8; 32],
    total: u64,
    state: State,
    phase: VerifyPhase,
    cursor: u64,
    previous: Option<[u8; 32]>,
    eligible: u64,
    graph_hash: Sha256,
    total_hash: Sha256,
    eligible_hash: Sha256,
}
fn start_hash(domain: &[u8], count: u64) -> Sha256 {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(count.to_le_bytes());
    h
}
impl PagedOrderVerifierV1 {
    /// Begin from an empty verifier state, never a decoded saved cursor.
    pub fn new(g: &impl PagedGraphV1, t: &impl TranscriptV1) -> Self {
        Self {
            graph_binding: g.binding(),
            transcript_binding: t.binding(),
            total: g.count(),
            state: State::default(),
            phase: VerifyPhase::Replay,
            cursor: 0,
            previous: None,
            eligible: 0,
            graph_hash: start_hash(GRAPH_COMMITMENT_DOMAIN, g.count()),
            total_hash: start_hash(TOTAL_ORDER_COMMITMENT_DOMAIN, g.count()),
            eligible_hash: Sha256::new(),
        }
    }
    /// Rejects mismatches/corruption without advancing any in-memory state.
    pub fn advance(
        &mut self,
        g: &impl PagedGraphV1,
        t: &impl TranscriptV1,
    ) -> Result<Option<VerifiedPagedOrderV1>> {
        if self.graph_binding != g.binding()
            || self.total != g.count()
            || self.transcript_binding != t.binding()
        {
            return Err(Sg0Error::Invariant);
        }
        let mut next = self.clone();
        for _ in 0..16 {
            match next.phase {
                VerifyPhase::Replay => {
                    if next.state.phase == Phase::Done {
                        if next.state.ordered != next.total {
                            return Err(Sg0Error::Invariant);
                        }
                        next.phase = VerifyPhase::Graph;
                    } else {
                        let writes =
                            replay_step(t, &Source { total: next.total }, g, &mut next.state)?;
                        for (key, bytes) in writes {
                            if t.record(key)?.as_deref() != Some(bytes.as_slice()) {
                                return Err(Sg0Error::Invariant);
                            }
                        }
                    }
                }
                VerifyPhase::Graph => {
                    if next.cursor == next.total {
                        next.cursor = 0;
                        next.phase = VerifyPhase::Count;
                    } else {
                        let bytes = t.sorted_id(next.cursor)?;
                        if next.previous.is_some_and(|p| p >= bytes) {
                            return Err(Sg0Error::Invariant);
                        }
                        let ordinal: u64 = must(t, id_key(bytes))?;
                        if ordinal >= next.total || fact(t, ordinal)?.id != bytes {
                            return Err(Sg0Error::Invariant);
                        }
                        let id = VertexId::from_bytes(bytes);
                        next.graph_hash.update(bytes);
                        match g.parent_set(id)? {
                            Sg0ParentSetV1::Anchor => next.graph_hash.update([0]),
                            Sg0ParentSetV1::Vertices(parents) => {
                                if parents.is_empty()
                                    || parents.len() > 2
                                    || parents.windows(2).any(|p| p[0] >= p[1])
                                {
                                    return Err(Sg0Error::InvalidParents);
                                }
                                next.graph_hash.update([1]);
                                next.graph_hash.update((parents.len() as u64).to_le_bytes());
                                for p in parents {
                                    next.graph_hash.update(p.as_bytes());
                                }
                            }
                        }
                        next.graph_hash.update(work(g, id)?.to_be_bytes());
                        let data = metadata(g, id)?;
                        match data.selected_parent() {
                            Sg0SelectedParentV1::Anchor => next.graph_hash.update([0]),
                            Sg0SelectedParentV1::Vertex(p) => {
                                next.graph_hash.update([1]);
                                next.graph_hash.update(p.as_bytes());
                            }
                        }
                        next.graph_hash
                            .update(data.merge_order_commitment().as_bytes());
                        next.graph_hash.update(data.blue_score().to_le_bytes());
                        next.graph_hash.update(data.blue_work().to_be_bytes());
                        next.previous = Some(bytes);
                        next.cursor += 1;
                    }
                }
                VerifyPhase::Count => {
                    if next.cursor == next.total {
                        next.cursor = 0;
                        next.eligible_hash =
                            start_hash(ELIGIBLE_ORDER_COMMITMENT_DOMAIN, next.eligible);
                        next.phase = VerifyPhase::Order;
                    } else {
                        let e: DagOrderEntryV1 = must(t, key(b'o', next.cursor, 0))?;
                        next.eligible += u64::from(e.blue);
                        next.cursor += 1;
                    }
                }
                VerifyPhase::Order => {
                    if next.cursor == next.total {
                        next.phase = VerifyPhase::Done;
                    } else {
                        let e: DagOrderEntryV1 = must(t, key(b'o', next.cursor, 0))?;
                        next.total_hash.update(e.id);
                        next.total_hash.update([u8::from(e.blue)]);
                        if e.blue {
                            next.eligible_hash.update(e.id);
                        }
                        next.cursor += 1;
                    }
                }
                VerifyPhase::Done => break,
            }
        }
        let out = (next.phase == VerifyPhase::Done).then(|| VerifiedPagedOrderV1 {
            graph_binding: next.graph_binding,
            base_binding: next.graph_binding,
            base_total: next.total,
            durable_append_binding: [0; 32],
            durable_appended: 0,
            appended: Vec::new(),
            transcript_binding: next.transcript_binding,
            total: next.total,
            eligible: next.eligible,
            tip: next.state.tip,
            graph: Hash32::new(next.graph_hash.clone().finalize().into()),
            total_order: Hash32::new(next.total_hash.clone().finalize().into()),
            eligible_order: Hash32::new(next.eligible_hash.clone().finalize().into()),
        });
        *self = next;
        Ok(out)
    }
}

/// Opaque order from replay or a checked sole-tip append to replay authority.
/// No decoded records or claimed hashes can construct this capability. It is
/// valid only for its exact current graph and immutable base transcript.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPagedOrderV1 {
    graph_binding: [u8; 32],
    base_binding: [u8; 32],
    base_total: u64,
    durable_append_binding: [u8; 32],
    durable_appended: u64,
    appended: Vec<VertexId>,
    transcript_binding: [u8; 32],
    total: u64,
    eligible: u64,
    tip: Option<u64>,
    graph: Hash32,
    total_order: Hash32,
    eligible_order: Hash32,
}
impl VerifiedPagedOrderV1 {
    /// Immutable original transcript source, retained across checked appends.
    pub fn transcript_source(&self) -> ([u8; 32], u64) {
        (self.base_binding, self.base_total)
    }
    /// Receiver-verified suffix count, including sealed and live entries.
    pub fn append_count(&self) -> u64 {
        self.durable_appended + self.appended.len() as u64
    }
    /// Number of IDs held only in the current non-serialized live page.
    pub fn live_append_count(&self) -> u64 {
        self.appended.len() as u64
    }
    fn check_base_source(&self, g: &impl PagedGraphV1, t: &impl TranscriptV1) -> Result<()> {
        if self.append_count() != 0
            || g.binding() != self.base_binding
            || g.count() != self.base_total
            || t.binding() != self.transcript_binding
        {
            return Err(Sg0Error::Invariant);
        }
        Ok(())
    }
    fn base_selected_tip(
        &self,
        g: &impl PagedGraphV1,
        t: &impl TranscriptV1,
    ) -> Result<Option<VertexId>> {
        self.check_base_source(g, t)?;
        self.tip
            .map(|i| fact(t, i).map(|f| VertexId::from_bytes(f.id)))
            .transpose()
    }
    fn ordinal(&self, t: &impl TranscriptV1, id: VertexId) -> Result<u64> {
        if let Some(n) = self.appended.iter().position(|v| *v == id) {
            return self
                .base_total
                .checked_add(self.durable_appended)
                .and_then(|base| base.checked_add(n as u64))
                .ok_or(Sg0Error::CountOverflow);
        }
        if let Some(n) = t.durable_append_ordinal(id)? {
            if n >= self.durable_appended || t.durable_append_id(n)? != id {
                return Err(Sg0Error::Invariant);
            }
            return self
                .base_total
                .checked_add(n)
                .ok_or(Sg0Error::CountOverflow);
        }
        let n: u64 = must(t, id_key(id.into_bytes()))?;
        if n >= self.base_total || fact(t, n)?.id != id.into_bytes() {
            return Err(Sg0Error::Invariant);
        }
        Ok(n)
    }
    /// Authenticated ancestry from the replay-checked relation matrix.
    pub fn is_ancestor_or_equal(
        &self,
        g: &impl PagedGraphV1,
        t: &impl TranscriptV1,
        ancestor: VertexId,
        descendant: VertexId,
    ) -> Result<bool> {
        self.check(g, t)?;
        let a = self.ordinal(t, ancestor)?;
        let d = self.ordinal(t, descendant)?;
        if a >= self.total || d >= self.total {
            return Err(Sg0Error::Invariant);
        }
        if d >= self.base_total || a >= self.base_total {
            return Ok(a <= d);
        }
        Ok(flags(t, d, a)? & 1 != 0)
    }
    /// Prove that the supplied parents cover this entire verified graph. This
    /// restricted conversion must reject omitted branches; it never treats an
    /// arbitrary virtual order as candidate-parent authority.
    pub fn begin_parent_view(
        &self,
        g: &impl PagedGraphV1,
        t: &impl TranscriptV1,
        parents: Sg0ParentSetV1,
    ) -> Result<PagedParentPassV1> {
        self.check(g, t)?;
        let ids = parents.ordinary_parents();
        for parent in ids {
            self.is_ancestor_or_equal(g, t, *parent, *parent)?;
        }
        if ids.len() == 2
            && (self.is_ancestor_or_equal(g, t, ids[0], ids[1])?
                || self.is_ancestor_or_equal(g, t, ids[1], ids[0])?)
        {
            return Err(Sg0Error::Invariant);
        }
        let tip = self.selected_tip(g, t)?;
        if (self.total == 0) != ids.is_empty() || tip.is_some_and(|id| !ids.contains(&id)) {
            return Err(Sg0Error::Invariant);
        }
        Ok(PagedParentPassV1 {
            view: VerifiedPagedParentV1 {
                order: self.clone(),
                parents,
                selected: tip.map_or(Sg0SelectedParentV1::Anchor, Sg0SelectedParentV1::Vertex),
                tail: Vec::new(),
            },
            cursor: 0,
        })
    }
    /// Selected tip from replay-checked selection, never inferred from the last
    /// emitted entry (which may belong to a different merge branch).
    pub fn selected_tip(
        &self,
        g: &impl PagedGraphV1,
        t: &impl TranscriptV1,
    ) -> Result<Option<VertexId>> {
        self.check(g, t)?;
        if let Some(id) = self.appended.last() {
            return Ok(Some(*id));
        }
        if self.durable_appended != 0 {
            return t.durable_append_id(self.durable_appended - 1).map(Some);
        }
        self.tip
            .map(|i| fact(t, i).map(|f| VertexId::from_bytes(f.id)))
            .transpose()
    }
    /// Recheck immutable source/transcript ownership before using this token.
    pub fn check(&self, g: &impl PagedGraphV1, t: &impl TranscriptV1) -> Result<()> {
        if self.durable_appended % DURABLE_APPEND_PAGE_V1 != 0
            || self.durable_appended > DURABLE_APPEND_MAX_V1
            || self.appended.len() as u64 > DURABLE_APPEND_PAGE_V1
            || self.append_count() > DURABLE_APPEND_MAX_V1
            || self
                .base_total
                .checked_add(self.append_count())
                .ok_or(Sg0Error::CountOverflow)?
                != self.total
            || g.binding() != self.graph_binding
            || g.count() != self.total
            || t.binding() != self.transcript_binding
            || t.durable_append_binding() != self.durable_append_binding
            || t.durable_append_count() != self.durable_appended
        {
            Err(Sg0Error::Invariant)
        } else {
            Ok(())
        }
    }
    /// Complete admitted count.
    pub fn total_count(&self) -> u64 {
        self.total
    }
    /// Complete eligible count.
    pub fn eligible_count(&self) -> u64 {
        self.eligible
    }
    /// Exact existing graph commitment.
    pub fn graph_commitment(&self) -> Hash32 {
        self.graph
    }
    /// Exact existing total commitment.
    pub fn total_order_commitment(&self) -> Hash32 {
        self.total_order
    }
    /// Exact existing eligible commitment.
    pub fn eligible_order_commitment(&self) -> Hash32 {
        self.eligible_order
    }
    /// Read one already replay-checked entry through its bound transcript.
    pub fn entry(
        &self,
        g: &impl PagedGraphV1,
        t: &impl TranscriptV1,
        index: u64,
    ) -> Result<Sg0OrderedVertexV1> {
        self.check(g, t)?;
        if index >= self.total {
            return Err(Sg0Error::Invariant);
        }
        if index >= self.base_total {
            let suffix = index - self.base_total;
            if suffix < self.durable_appended {
                return Ok(Sg0OrderedVertexV1 {
                    vertex_id: t.durable_append_id(suffix)?,
                    color: Sg0Color::Blue,
                });
            }
            return Ok(Sg0OrderedVertexV1 {
                vertex_id: self.appended[(suffix - self.durable_appended) as usize],
                color: Sg0Color::Blue,
            });
        }
        let e: DagOrderEntryV1 = must(t, key(b'o', index, 0))?;
        Ok(Sg0OrderedVertexV1 {
            vertex_id: VertexId::from_bytes(e.id),
            color: if e.blue {
                Sg0Color::Blue
            } else {
                Sg0Color::Red
            },
        })
    }
    /// Begin bounded prefix calculation, including the empty prefix.
    pub fn begin_prefix(&self, count: u64) -> Result<PagedPrefixPassV1> {
        if count > self.eligible {
            return Err(Sg0Error::BasePrefixMismatch);
        }
        Ok(PagedPrefixPassV1 {
            order: self.clone(),
            target: count,
            seen: 0,
            cursor: 0,
            hash: start_hash(ELIGIBLE_ORDER_COMMITMENT_DOMAIN, count),
        })
    }
    /// Begin production of the existing typed eight-entry checkpoint capability.
    pub fn begin_checkpoint(&self, base: u64, expected: Hash32) -> Result<PagedCheckpointPassV1> {
        let end = base.checked_add(8).ok_or(Sg0Error::CountOverflow)?;
        if end > self.eligible {
            return Err(Sg0Error::IncompleteCheckpointBatch);
        }
        Ok(PagedCheckpointPassV1 {
            order: self.clone(),
            base,
            expected,
            cursor: 0,
            seen: 0,
            work: Uint256::ZERO,
            entries: [VertexId::from_bytes([0; 32]); 8],
            before: start_hash(ELIGIBLE_ORDER_COMMITMENT_DOMAIN, base),
            after: start_hash(ELIGIBLE_ORDER_COMMITMENT_DOMAIN, end),
        })
    }
}
/// Opaque complete-coverage parent view with only the final 43 eligible IDs.
#[derive(Clone)]
pub struct VerifiedPagedParentV1 {
    order: VerifiedPagedOrderV1,
    parents: Sg0ParentSetV1,
    selected: Sg0SelectedParentV1,
    tail: Vec<VertexId>,
}
impl VerifiedPagedParentV1 {
    /// The exact verified order from which this coverage was established.
    pub fn verified_order(&self) -> &VerifiedPagedOrderV1 {
        &self.order
    }
    /// Recheck the exact receiver graph and transcript.
    pub fn check(&self, g: &impl PagedGraphV1, t: &impl TranscriptV1) -> Result<()> {
        self.order.check(g, t)
    }
    /// Verified parent shape.
    pub fn parent_set(&self) -> &Sg0ParentSetV1 {
        &self.parents
    }
    /// Receiver-selected parent.
    pub fn selected_parent(&self) -> Sg0SelectedParentV1 {
        self.selected
    }
    /// Complete eligible count, not the tail length.
    pub fn eligible_count(&self) -> u64 {
        self.order.eligible_count()
    }
    /// Exact parent-order commitment.
    pub fn eligible_order_commitment(&self) -> Hash32 {
        self.order.eligible_order_commitment()
    }
    /// At most 43 oldest-first terminal eligible IDs for bounded DAA.
    pub fn eligible_tail(&self) -> &[VertexId] {
        &self.tail
    }
}
/// Bounded, non-deserializable parent coverage continuation.
#[derive(Clone)]
pub struct PagedParentPassV1 {
    view: VerifiedPagedParentV1,
    cursor: u64,
}
impl PagedParentPassV1 {
    /// Check at most 64 entries. Errors preserve the previous continuation.
    pub fn advance(
        &mut self,
        g: &impl PagedGraphV1,
        t: &impl TranscriptV1,
    ) -> Result<Option<VerifiedPagedParentV1>> {
        self.view.check(g, t)?;
        let mut next = self.clone();
        for _ in 0..64 {
            if next.cursor == next.view.order.total_count() {
                break;
            }
            let entry = next.view.order.entry(g, t, next.cursor)?;
            let mut covered = false;
            for parent in next.view.parents.ordinary_parents() {
                covered |= next
                    .view
                    .order
                    .is_ancestor_or_equal(g, t, entry.vertex_id, *parent)?;
            }
            if !covered {
                return Err(Sg0Error::Invariant);
            }
            if entry.color == Sg0Color::Blue {
                if next.view.tail.len() == 43 {
                    next.view.tail.remove(0);
                }
                next.view.tail.push(entry.vertex_id);
            }
            next.cursor += 1;
        }
        let result = (next.cursor == next.view.order.total_count()).then(|| next.view.clone());
        *self = next;
        Ok(result)
    }
}
/// Fixed-size in-memory prefix continuation; no serialized hash state accepted.
#[derive(Clone)]
pub struct PagedPrefixPassV1 {
    order: VerifiedPagedOrderV1,
    target: u64,
    seen: u64,
    cursor: u64,
    hash: Sha256,
}
impl PagedPrefixPassV1 {
    /// Process at most 64 total-order entries, preserving state on failure.
    pub fn advance(
        &mut self,
        g: &impl PagedGraphV1,
        t: &impl TranscriptV1,
    ) -> Result<Option<Hash32>> {
        self.order.check(g, t)?;
        // The complete prefix was already hashed by the verifier. Reuse that
        // authority only after checking both bindings, including empty graphs.
        if self.target == self.order.eligible_count() {
            return Ok(Some(self.order.eligible_order_commitment()));
        }
        let mut next = self.clone();
        for _ in 0..64 {
            if next.seen == next.target {
                break;
            }
            let e = next.order.entry(g, t, next.cursor)?;
            next.cursor += 1;
            if e.color == Sg0Color::Blue {
                next.hash.update(e.vertex_id.as_bytes());
                next.seen += 1;
            }
        }
        let out =
            (next.seen == next.target).then(|| Hash32::new(next.hash.clone().finalize().into()));
        *self = next;
        Ok(out)
    }
}
/// Bounded checkpoint derivation from opaque verified order, not claimed pages.
#[derive(Clone)]
pub struct PagedCheckpointPassV1 {
    order: VerifiedPagedOrderV1,
    base: u64,
    expected: Hash32,
    cursor: u64,
    seen: u64,
    work: Uint256,
    entries: [VertexId; 8],
    before: Sha256,
    after: Sha256,
}
impl PagedCheckpointPassV1 {
    /// Process at most 64 entries and verify prefix/work before minting authority.
    pub fn advance(
        &mut self,
        g: &impl PagedGraphV1,
        t: &impl TranscriptV1,
    ) -> Result<Option<VerifiedSg0EligiblePrefixBatchV1>> {
        self.order.check(g, t)?;
        let mut next = self.clone();
        let end = next.base + 8;
        for _ in 0..64 {
            if next.seen == end {
                break;
            }
            let e = next.order.entry(g, t, next.cursor)?;
            next.cursor += 1;
            if e.color == Sg0Color::Blue {
                if next.seen < next.base {
                    next.before.update(e.vertex_id.as_bytes());
                } else {
                    next.entries[(next.seen - next.base) as usize] = e.vertex_id;
                }
                next.after.update(e.vertex_id.as_bytes());
                next.work = next
                    .work
                    .checked_add(work(g, e.vertex_id)?)
                    .ok_or(Sg0Error::WorkOverflow)?;
                next.seen += 1;
            }
        }
        let out = if next.seen == end {
            let before = Hash32::new(next.before.clone().finalize().into());
            if before != next.expected {
                return Err(Sg0Error::BasePrefixMismatch);
            }
            let after = Hash32::new(next.after.clone().finalize().into());
            Some(VerifiedSg0EligiblePrefixBatchV1 {
                base_cursor: next.base,
                first_order_index: next.base + 1,
                base_prefix_commitment: before,
                resulting_prefix_commitment: after,
                graph_commitment: next.order.graph,
                total_order_commitment: next.order.total_order,
                eligible_score_at_boundary: u128::from(end),
                eligible_work_at_boundary: next.work,
                entries: next.entries,
                batch_commitment: checkpoint_batch_commitment(
                    next.base,
                    next.base + 1,
                    before,
                    after,
                    u128::from(end),
                    next.work,
                    &next.entries,
                ),
            })
        } else {
            None
        };
        *self = next;
        Ok(out)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fact {
    id: [u8; 32],
    parents: Vec<u64>,
    selected: Option<u64>,
    work: [u8; 32],
    blues: Vec<[u8; 32]>,
}
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
enum Phase {
    Load,
    Matrix,
    Validate,
    SeedCluster,
    Block,
    Scan,
    Trial,
    Done,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    phase: Phase,
    i: u64,
    j: u64,
    tip: Option<u64>,
    cursor: Option<[u64; 3]>,
    block: u64,
    scan: u64,
    best: Option<u64>,
    pending: bool,
    candidate: u64,
    anti: u64,
    // At most K=2 existing blue vertices can be incomparable with a candidate.
    incomparable: [Option<u64>; 2],
    checking_existing: bool,
    ordered: u64,
}
impl Default for State {
    fn default() -> Self {
        Self {
            phase: Phase::Load,
            i: 0,
            j: 0,
            tip: None,
            cursor: None,
            block: 0,
            scan: 0,
            best: None,
            pending: false,
            candidate: 0,
            anti: 0,
            incomparable: [None; 2],
            checking_existing: false,
            ordered: 0,
        }
    }
}
fn key(kind: u8, a: u64, b: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"Silk/DagJob/v1/Key");
    h.update([kind]);
    h.update(a.to_le_bytes());
    h.update(b.to_le_bytes());
    h.finalize().into()
}
fn id_key(id: [u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"Silk/DagJob/v1/Id");
    h.update(id);
    h.finalize().into()
}
fn must<T: DeserializeOwned>(a: &impl TranscriptV1, key: [u8; 32]) -> Result<T> {
    get(a, key)?.ok_or(Sg0Error::Invariant)
}
fn fact(a: &impl TranscriptV1, n: u64) -> Result<Fact> {
    let f: Fact = must(a, key(b'f', n, 0))?;
    if f.parents.len() > 2
        || f.blues.len() > 4096
        || f.parents.iter().any(|p| *p >= n)
        || f.selected.is_some_and(|p| !f.parents.contains(&p))
    {
        return Err(Sg0Error::Invariant);
    }
    Ok(f)
}
// Rows store self/past, selected-chain and blue-closure bits. Topological
// ordinals make all future-ancestor queries false without reading absent keys.
fn flags(a: &impl TranscriptV1, descendant: u64, ancestor: u64) -> Result<u8> {
    if ancestor > descendant {
        return Ok(0);
    }
    let f = a.ancestry_flags(descendant, ancestor)?;
    if f > 7 {
        return Err(Sg0Error::Invariant);
    }
    Ok(f)
}
type Writes = Vec<([u8; 32], Vec<u8>)>;
fn put<T: Serialize>(writes: &mut Writes, key: [u8; 32], value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| Sg0Error::Invariant)?;
    if bytes.len() > MAX_FACT {
        return Err(Sg0Error::Invariant);
    }
    writes.push((key, bytes));
    Ok(())
}
fn member(a: &impl TranscriptV1, s: &State, total: u64, v: u64) -> Result<bool> {
    let tip = s.tip.ok_or(Sg0Error::Invariant)?;
    if s.block == total {
        return Ok(flags(a, tip, v)? & 1 == 0);
    }
    if v == s.block || flags(a, s.block, v)? & 1 == 0 {
        return Ok(false);
    }
    Ok(match fact(a, s.block)?.selected {
        None => true,
        Some(p) => flags(a, p, v)? & 1 == 0,
    })
}
fn blue(a: &impl TranscriptV1, s: &State, v: u64) -> Result<bool> {
    Ok(flags(a, s.tip.ok_or(Sg0Error::Invariant)?, v)? & 4 != 0
        || (emitted(a, s, v)?.is_some() && get::<bool>(a, key(b'b', v, 0))?.unwrap_or(false)))
}
fn incomparable(a: &impl TranscriptV1, x: u64, y: u64) -> Result<bool> {
    Ok(x != y && flags(a, x, y)? & 1 == 0 && flags(a, y, x)? & 1 == 0)
}
fn reset_scan(s: &mut State) {
    s.phase = Phase::Scan;
    s.scan = 0;
    s.best = None;
    s.pending = false;
}
fn emit(a: &impl TranscriptV1, s: &mut State, w: &mut Writes, v: u64, color: bool) -> Result<()> {
    if emitted(a, s, v)?.is_some() {
        return Err(Sg0Error::Invariant);
    }
    put(
        w,
        key(b'o', s.ordered, 0),
        &DagOrderEntryV1 {
            id: fact(a, v)?.id,
            blue: color,
        },
    )?;
    put(w, key(b'e', v, 0), &s.ordered)?;
    s.ordered = s.ordered.checked_add(1).ok_or(Sg0Error::Invariant)?;
    Ok(())
}

fn replay_step(
    a: &impl TranscriptV1,
    source: &Source,
    input: &impl PagedGraphV1,
    s: &mut State,
) -> Result<Writes> {
    let mut w = Vec::new();
    let n = source.total;
    match s.phase {
        Phase::Load => {
            if s.i == n {
                s.phase = Phase::Matrix;
                s.i = 0;
                return Ok(w);
            }
            let (id, cursor) = input.next_id(s.i, s.cursor)?;
            if !input.receiver_verified_contains(id)? {
                return Err(Sg0Error::MissingVertex.into());
            }
            let parents = input.parent_set(id)?;
            let ids = parents.ordinary_parents();
            if ids.len() > 2
                || (!matches!(parents, Sg0ParentSetV1::Anchor) && ids.is_empty())
                || ids.windows(2).any(|p| p[0] >= p[1])
            {
                return Err(Sg0Error::InvalidParents.into());
            }
            let mut ords = Vec::new();
            for p in ids {
                let o: u64 = must(a, id_key(p.into_bytes()))?;
                if o >= s.i {
                    return Err(Sg0Error::Invariant);
                }
                ords.push(o);
            }
            let data = input.vertex_data(id)?.ok_or(Sg0Error::MissingMetadata)?;
            if data.merge_blues().len() > 4096 {
                return Err(Sg0Error::ResourceBudget.into());
            }
            let own = Uint256::from_be_bytes(input.receiver_verified_work_be(id)?);
            if own.is_zero() {
                return Err(Sg0Error::ZeroWork.into());
            }
            let mut expected: Option<u64> = None;
            for p in &ords {
                let pf = fact(a, *p)?;
                if expected.is_none() || {
                    let ef = fact(a, expected.unwrap())?;
                    pf.work > ef.work || (pf.work == ef.work && pf.id < ef.id)
                } {
                    expected = Some(*p);
                }
            }
            let selected = match data.selected_parent() {
                Sg0SelectedParentV1::Anchor => None,
                Sg0SelectedParentV1::Vertex(p) => Some(must::<u64>(a, id_key(p.into_bytes()))?),
            };
            if selected != expected || selected.is_some_and(|p| p >= s.i) {
                return Err(Sg0Error::Invariant);
            }
            if let Some(p) = selected {
                if data.blue_work().to_be_bytes() <= fact(a, p)?.work {
                    return Err(Sg0Error::Invariant);
                }
            } else if data.blue_work() != own {
                return Err(Sg0Error::Invariant);
            }
            let f = Fact {
                id: id.into_bytes(),
                parents: ords,
                selected,
                work: data.blue_work().to_be_bytes(),
                blues: data.merge_blues().iter().map(|v| v.into_bytes()).collect(),
            };
            if s.tip.is_none() || {
                let t = fact(a, s.tip.unwrap())?;
                f.work > t.work || (f.work == t.work && f.id < t.id)
            } {
                s.tip = Some(s.i);
            }
            put(&mut w, key(b'f', s.i, 0), &f)?;
            put(&mut w, id_key(f.id), &s.i)?;
            s.i += 1;
            s.cursor = cursor;
        }
        Phase::Matrix => {
            if s.i == n {
                s.phase = Phase::Validate;
                s.i = 0;
                s.j = 0;
                return Ok(w);
            }
            let f = fact(a, s.i)?;
            let mut value = if s.i == s.j { 7 } else { 0 };
            if s.i != s.j {
                for p in &f.parents {
                    value |= flags(a, *p, s.j)? & 1;
                }
                if let Some(p) = f.selected {
                    value |= flags(a, p, s.j)? & 6;
                }
                if f.blues.contains(&fact(a, s.j)?.id) {
                    value |= 4;
                }
                if value & 6 != 0 && value & 1 == 0 {
                    return Err(Sg0Error::Invariant);
                }
            }
            if flags(a, s.i, s.j)? != value {
                return Err(Sg0Error::Invariant);
            }
            s.j += 1;
            if s.j > s.i {
                s.i += 1;
                s.j = 0;
            }
        }
        Phase::Validate => {
            if s.i == n {
                s.phase = if n == 0 {
                    Phase::Block
                } else {
                    Phase::SeedCluster
                };
                s.i = 0;
                s.j = 0;
                s.anti = 0;
                return Ok(w);
            }
            let f = fact(a, s.i)?;
            if f.parents.len() == 2
                && (flags(a, f.parents[0], f.parents[1])? & 1 != 0
                    || flags(a, f.parents[1], f.parents[0])? & 1 != 0)
            {
                return Err(Sg0Error::RedundantOrCyclicParent.into());
            }
            s.i += 1;
        }
        Phase::SeedCluster => {
            // Establish the induction base once. Later successful insertions
            // only change anticone counts of the candidate and <=2 neighbors.
            if s.i == n {
                s.phase = Phase::Block;
            } else if !blue(a, s, s.i)? || s.j == n {
                s.i += 1;
                s.j = 0;
                s.anti = 0;
            } else {
                if blue(a, s, s.j)? && incomparable(a, s.i, s.j)? {
                    s.anti += 1;
                    if s.anti > 2 {
                        return Err(Sg0Error::Invariant);
                    }
                }
                s.j += 1;
            }
        }
        Phase::Block => {
            if n == 0 {
                s.phase = Phase::Done;
                return Ok(w);
            }
            if s.block == n || flags(a, s.tip.ok_or(Sg0Error::Invariant)?, s.block)? & 2 != 0 {
                if s.block < n && fact(a, s.block)?.parents.len() < 2 {
                    // Anchor/single-parent selected-chain vertices have no
                    // merge set. Avoid a complete candidate scan for each.
                    emit(a, s, &mut w, s.block, true)?;
                    s.block += 1;
                } else {
                    reset_scan(s);
                }
            } else {
                s.block += 1;
            }
        }
        Phase::Scan => {
            if s.scan < n {
                let v = s.scan;
                s.scan += 1;
                if !member(a, s, n, v)? || emitted(a, s, v)?.is_some() {
                    return Ok(w);
                }
                s.pending = true;
                let f = fact(a, v)?;
                for p in &f.parents {
                    if emitted(a, s, *p)?.is_none() {
                        return Ok(w);
                    }
                }
                if s.best.is_none() || {
                    let best = fact(a, s.best.unwrap())?;
                    f.work < best.work || (f.work == best.work && f.id < best.id)
                } {
                    s.best = Some(v);
                }
            } else if let Some(v) = s.best {
                if s.block == n {
                    s.candidate = v;
                    s.i = 0;
                    s.j = 0;
                    s.anti = 0;
                    s.incomparable = [None; 2];
                    s.checking_existing = false;
                    s.phase = Phase::Trial;
                } else {
                    let color = flags(a, s.tip.ok_or(Sg0Error::Invariant)?, v)? & 4 != 0;
                    emit(a, s, &mut w, v, color)?;
                    reset_scan(s);
                }
            } else {
                if s.pending {
                    return Err(Sg0Error::Cycle.into());
                }
                if s.block == n {
                    if s.ordered != n {
                        return Err(Sg0Error::Invariant);
                    }
                    s.phase = Phase::Done;
                } else {
                    emit(a, s, &mut w, s.block, true)?;
                    s.block += 1;
                    s.phase = Phase::Block;
                }
            }
        }
        Phase::Trial => {
            let mut result = None;
            if !s.checking_existing {
                if s.i == n {
                    s.checking_existing = true;
                    s.i = 0;
                    s.j = 0;
                    s.anti = 0;
                } else {
                    if blue(a, s, s.i)? && incomparable(a, s.candidate, s.i)? {
                        if let Some(slot) = s.incomparable.iter_mut().find(|v| v.is_none()) {
                            *slot = Some(s.i);
                        } else {
                            result = Some(false);
                        }
                    }
                    s.i += 1;
                }
            } else if s.i >= 2 || s.incomparable[s.i as usize].is_none() {
                result = Some(true);
            } else if s.j == n {
                s.i += 1;
                s.j = 0;
                s.anti = 0;
            } else {
                let existing = s.incomparable[s.i as usize].ok_or(Sg0Error::Invariant)?;
                if blue(a, s, s.j)? && incomparable(a, existing, s.j)? {
                    s.anti += 1;
                    // Adding this candidate would turn an existing count of
                    // K into K+1. Comparable vertices' counts do not change.
                    if s.anti >= 2 {
                        result = Some(false);
                    }
                }
                s.j += 1;
            }
            if let Some(color) = result {
                put(&mut w, key(b'b', s.candidate, 0), &color)?;
                emit(a, s, &mut w, s.candidate, color)?;
                reset_scan(s);
            }
        }
        Phase::Done => {}
    }
    Ok(w)
}
