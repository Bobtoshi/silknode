//! Reuse verified order across receiver-owned, append-only sole-tip transitions.
use super::*;

/// Receiver-owned evidence of exactly one admitted append. Implementors MUST
/// establish that all previous IDs, parents, work and metadata are unchanged,
/// the inventory grows by exactly this child, and both bindings name those
/// exact inventories. This is a local ownership contract, never peer input.
pub trait PagedAppendGraphV1: PagedGraphV1 {
    /// Exact graph binding before the successful local archive append.
    fn previous_binding(&self) -> [u8; 32];
    /// The one newly admitted ID.
    fn appended_id(&self) -> VertexId;
}

/// In-memory, non-deserializable append continuation. Live IDs occupy at most
/// one 64-entry page; older pages are read from authenticated local storage.
/// Existing length-prefixed commitments still require linear hashing, not DAG
/// replay.
#[derive(Clone)]
pub struct PagedAppendPassV1 {
    order: VerifiedPagedOrderV1,
    sorted: Vec<VertexId>,
    base_cursor: u64,
    durable_cursors: Vec<u64>,
    suffix_cursor: usize,
    previous: Option<[u8; 32]>,
    order_cursor: u64,
    graph_hash: Sha256,
    total_hash: Sha256,
    eligible_hash: Sha256,
    graph_done: bool,
    done: bool,
}
impl VerifiedPagedParentV1 {
    /// Extend complete single-parent coverage only after an owner-proven append.
    /// A malformed child, stale source or exhausted overlay is refused before
    /// any continuation is returned. No saved bytes mint this authority.
    pub fn begin_single_parent_append(
        &self,
        g: &impl PagedAppendGraphV1,
        t: &impl TranscriptV1,
    ) -> Result<PagedAppendPassV1> {
        if g.previous_binding() != self.order.graph_binding
            || g.binding() == g.previous_binding()
            || g.count()
                != self
                    .order
                    .total
                    .checked_add(1)
                    .ok_or(Sg0Error::CountOverflow)?
            || t.binding() != self.order.transcript_binding
            || self.parents.ordinary_parents().len() != 1
            || self.order.appended.len() as u64 >= DURABLE_APPEND_PAGE_V1
            || self.order.append_count() >= DURABLE_APPEND_MAX_V1
        {
            return Err(Sg0Error::Invariant);
        }
        let id = g.appended_id();
        if self.order.appended.contains(&id)
            || t.durable_append_ordinal(id)?
                .is_some_and(|ordinal| ordinal < self.order.durable_appended)
            || get::<u64>(t, id_key(id.into_bytes()))?.is_some()
            || !g.receiver_verified_contains(id)?
            || g.parent_set(id)? != self.parents
        {
            return Err(Sg0Error::Invariant);
        }
        let parent = self.parents.ordinary_parents()[0];
        validate_single_parent(g, id, parent)?;
        let mut order = self.order.clone();
        order.graph_binding = g.binding();
        order.total = g.count();
        order.eligible = order
            .eligible
            .checked_add(1)
            .ok_or(Sg0Error::CountOverflow)?;
        order.appended.push(id);
        let mut sorted = order.appended.clone();
        sorted.sort_unstable();
        Ok(PagedAppendPassV1::for_order(order, sorted))
    }
}
impl PagedAppendPassV1 {
    fn for_order(order: VerifiedPagedOrderV1, sorted: Vec<VertexId>) -> Self {
        let pages = (order.durable_appended / DURABLE_APPEND_PAGE_V1) as usize;
        Self {
            graph_hash: start_hash(GRAPH_COMMITMENT_DOMAIN, order.total),
            total_hash: start_hash(TOTAL_ORDER_COMMITMENT_DOMAIN, order.total),
            eligible_hash: start_hash(ELIGIBLE_ORDER_COMMITMENT_DOMAIN, order.eligible),
            order,
            sorted,
            base_cursor: 0,
            durable_cursors: vec![0; pages],
            suffix_cursor: 0,
            previous: None,
            order_cursor: 0,
            graph_done: false,
            done: false,
        }
    }
    /// Immutable base needed to reopen the already verified transcript.
    pub fn transcript_source(&self) -> ([u8; 32], u64) {
        self.order.transcript_source()
    }
    /// Draft order whose immutable base and sealed pages must be reopened for
    /// each bounded advance. It is not usable authority until the pass ends.
    pub fn verified_order(&self) -> &VerifiedPagedOrderV1 {
        &self.order
    }
    /// Hash at most 64 graph/order entries, preserving the pass on any error.
    /// No prior ancestry row or classification microstep is recomputed.
    pub fn advance(
        &mut self,
        g: &impl PagedGraphV1,
        t: &impl TranscriptV1,
    ) -> Result<Option<VerifiedPagedOrderV1>> {
        self.order.check(g, t)?;
        if self.done {
            return Err(Sg0Error::Invariant);
        }
        let mut next = self.clone();
        for _ in 0..64 {
            if !next.graph_done {
                #[derive(Clone, Copy)]
                enum Source {
                    Base,
                    Durable(usize),
                    Live,
                }
                let mut candidates = Vec::with_capacity(next.durable_cursors.len() + 2);
                if next.base_cursor < next.order.base_total {
                    candidates.push((t.sorted_id(next.base_cursor)?, Source::Base));
                }
                for (page, cursor) in next.durable_cursors.iter().copied().enumerate() {
                    if cursor < DURABLE_APPEND_PAGE_V1 {
                        candidates.push((
                            t.durable_append_sorted_id(page as u64, cursor)?
                                .into_bytes(),
                            Source::Durable(page),
                        ));
                    }
                }
                if let Some(id) = next.sorted.get(next.suffix_cursor) {
                    candidates.push((id.into_bytes(), Source::Live));
                }
                if candidates.is_empty() {
                    next.graph_done = true;
                    continue;
                }
                let bytes = candidates
                    .iter()
                    .map(|(id, _)| *id)
                    .min()
                    .ok_or(Sg0Error::Invariant)?;
                let mut matching = candidates.into_iter().filter(|(id, _)| *id == bytes);
                let (_, source) = matching.next().ok_or(Sg0Error::Invariant)?;
                if matching.next().is_some() {
                    return Err(Sg0Error::Invariant);
                }
                match source {
                    Source::Base => next.base_cursor += 1,
                    Source::Durable(page) => next.durable_cursors[page] += 1,
                    Source::Live => next.suffix_cursor += 1,
                }
                if next.previous.is_some_and(|p| p >= bytes) {
                    return Err(Sg0Error::Invariant);
                }
                hash_graph_entry(&mut next.graph_hash, g, VertexId::from_bytes(bytes))?;
                next.previous = Some(bytes);
            } else if next.order_cursor < next.order.total {
                let e = next.order.entry(g, t, next.order_cursor)?;
                next.total_hash.update(e.vertex_id.as_bytes());
                next.total_hash
                    .update([u8::from(e.color == Sg0Color::Blue)]);
                if e.color == Sg0Color::Blue {
                    next.eligible_hash.update(e.vertex_id.as_bytes());
                }
                next.order_cursor += 1;
            } else {
                next.done = true;
                break;
            }
        }
        let out = if next.done {
            next.order.graph = Hash32::new(next.graph_hash.clone().finalize().into());
            next.order.total_order = Hash32::new(next.total_hash.clone().finalize().into());
            next.order.eligible_order = Hash32::new(next.eligible_hash.clone().finalize().into());
            Some(next.order.clone())
        } else {
            None
        };
        *self = next;
        Ok(out)
    }
}

impl VerifiedPagedOrderV1 {
    /// Replace one fully verified live page with the exact authenticated sealed
    /// page. This changes only the capability's bounded representation; all
    /// consensus commitments and graph bindings remain byte-identical.
    pub fn fold_durable_append_page(&self, t: &impl TranscriptV1) -> Result<Self> {
        if self.appended.len() as u64 != DURABLE_APPEND_PAGE_V1
            || t.binding() != self.transcript_binding
            || t.durable_append_count()
                != self
                    .durable_appended
                    .checked_add(DURABLE_APPEND_PAGE_V1)
                    .ok_or(Sg0Error::CountOverflow)?
            || t.append_journal_count() != t.durable_append_count()
        {
            return Err(Sg0Error::Invariant);
        }
        let page = self.durable_appended / DURABLE_APPEND_PAGE_V1;
        let mut sorted = self.appended.clone();
        sorted.sort_unstable();
        for (offset, expected) in self.appended.iter().copied().enumerate() {
            let ordinal = self
                .durable_appended
                .checked_add(offset as u64)
                .ok_or(Sg0Error::CountOverflow)?;
            if t.durable_append_id(ordinal)? != expected
                || t.durable_append_ordinal(expected)? != Some(ordinal)
                || t.durable_append_sorted_id(page, offset as u64)? != sorted[offset]
            {
                return Err(Sg0Error::Invariant);
            }
        }
        let mut next = self.clone();
        next.durable_appended = t.durable_append_count();
        next.durable_append_binding = t.durable_append_binding();
        next.appended.clear();
        Ok(next)
    }
}

#[derive(Clone)]
enum RecoveryPhase {
    Entries,
    Hash(PagedAppendPassV1),
    Done,
}

/// Fresh-process verifier for the authenticated append journal. Stored state
/// chooses records to check but never constructs authority. Each completed ID,
/// graph ordinal, parent, metadata recurrence and sealed permutation is checked
/// again before exact commitments are recomputed.
#[derive(Clone)]
pub struct PagedAppendRecoveryV1 {
    base: VerifiedPagedOrderV1,
    current_binding: [u8; 32],
    current_total: u64,
    durable_binding: [u8; 32],
    sealed: u64,
    journal: u64,
    pending: Option<VertexId>,
    include_pending: bool,
    target: u64,
    cursor: u64,
    previous: Option<VertexId>,
    page: Vec<VertexId>,
    live: Vec<VertexId>,
    phase: RecoveryPhase,
}
impl PagedAppendRecoveryV1 {
    /// Begin only after independently replay-verifying the immutable base job.
    pub fn new(
        base: VerifiedPagedOrderV1,
        base_graph: &impl PagedGraphV1,
        current_graph: &impl PagedGraphV1,
        base_transcript: &impl TranscriptV1,
        durable_transcript: &impl TranscriptV1,
    ) -> Result<Self> {
        base.check_base_source(base_graph, base_transcript)?;
        if base.append_count() != 0
            || durable_transcript.binding() != base.transcript_binding
            || current_graph.count() < base.base_total
        {
            return Err(Sg0Error::Invariant);
        }
        let sealed = durable_transcript.durable_append_count();
        let journal = durable_transcript.append_journal_count();
        let pending = durable_transcript.pending_append_id()?;
        let suffix = current_graph.count() - base.base_total;
        let include_pending =
            suffix == journal.checked_add(1).ok_or(Sg0Error::CountOverflow)? && pending.is_some();
        if suffix != journal && !include_pending {
            return Err(Sg0Error::Invariant);
        }
        let target = suffix;
        if sealed % DURABLE_APPEND_PAGE_V1 != 0
            || sealed > journal
            || journal > DURABLE_APPEND_MAX_V1
            || journal - sealed > DURABLE_APPEND_PAGE_V1
            || target > DURABLE_APPEND_MAX_V1
            || target - sealed > DURABLE_APPEND_PAGE_V1
        {
            return Err(Sg0Error::ResourceBudget);
        }
        let previous = base.base_selected_tip(base_graph, base_transcript)?;
        if target != 0 && previous.is_none() {
            return Err(Sg0Error::Invariant);
        }
        Ok(Self {
            base,
            current_binding: current_graph.binding(),
            current_total: current_graph.count(),
            durable_binding: durable_transcript.durable_append_binding(),
            sealed,
            journal,
            pending,
            include_pending,
            target,
            cursor: 0,
            previous,
            page: Vec::new(),
            live: Vec::new(),
            phase: RecoveryPhase::Entries,
        })
    }
    /// Whether the authenticated pending intent has an exact admitted child.
    pub const fn pending_was_admitted(&self) -> bool {
        self.include_pending
    }
    /// Completed journal count observed before recovery.
    pub const fn journal_count(&self) -> u64 {
        self.journal
    }
    /// Immutable base needed to reopen the authenticated transcript while the
    /// recovery pass remains non-authoritative.
    pub fn base_order(&self) -> &VerifiedPagedOrderV1 {
        &self.base
    }
    /// Verify at most 64 append or hash entries. Errors leave the continuation
    /// unchanged and no persisted cursor/completion flag becomes authority.
    pub fn advance(
        &mut self,
        base_graph: &impl PagedGraphV1,
        current_graph: &impl PagedGraphV1,
        base_transcript: &impl TranscriptV1,
        durable_transcript: &impl TranscriptV1,
    ) -> Result<Option<VerifiedPagedOrderV1>> {
        self.base.check_base_source(base_graph, base_transcript)?;
        if current_graph.binding() != self.current_binding
            || current_graph.count() != self.current_total
            || durable_transcript.binding() != self.base.transcript_binding
            || durable_transcript.durable_append_binding() != self.durable_binding
            || durable_transcript.durable_append_count() != self.sealed
            || durable_transcript.append_journal_count() != self.journal
            || durable_transcript.pending_append_id()? != self.pending
        {
            return Err(Sg0Error::Invariant);
        }
        let mut next = self.clone();
        let out = match &mut next.phase {
            RecoveryPhase::Entries => {
                for _ in 0..64 {
                    if next.cursor == next.target {
                        break;
                    }
                    let id = if next.cursor < next.journal {
                        let id = durable_transcript.append_journal_id(next.cursor)?;
                        if durable_transcript.append_journal_ordinal(id)? != Some(next.cursor) {
                            return Err(Sg0Error::Invariant);
                        }
                        id
                    } else {
                        next.pending.ok_or(Sg0Error::Invariant)?
                    };
                    let absolute = next
                        .base
                        .base_total
                        .checked_add(next.cursor)
                        .ok_or(Sg0Error::CountOverflow)?;
                    let (actual, continuation) = current_graph.next_id(absolute, None)?;
                    if continuation.is_some() || actual != id {
                        return Err(Sg0Error::Invariant);
                    }
                    let parent = next.previous.ok_or(Sg0Error::Invariant)?;
                    validate_single_parent(current_graph, id, parent)?;
                    if next.cursor < next.sealed {
                        next.page.push(id);
                        if next.page.len() as u64 == DURABLE_APPEND_PAGE_V1 {
                            let page = next.cursor / DURABLE_APPEND_PAGE_V1;
                            let mut sorted = next.page.clone();
                            sorted.sort_unstable();
                            for (offset, expected) in sorted.into_iter().enumerate() {
                                if durable_transcript
                                    .durable_append_sorted_id(page, offset as u64)?
                                    != expected
                                {
                                    return Err(Sg0Error::Invariant);
                                }
                            }
                            next.page.clear();
                        }
                    } else {
                        next.live.push(id);
                    }
                    next.previous = Some(id);
                    next.cursor += 1;
                }
                if next.cursor == next.target {
                    if !next.page.is_empty() || next.live.len() as u64 > DURABLE_APPEND_PAGE_V1 {
                        return Err(Sg0Error::Invariant);
                    }
                    let mut order = next.base.clone();
                    order.graph_binding = next.current_binding;
                    order.durable_append_binding = next.durable_binding;
                    order.durable_appended = next.sealed;
                    order.appended = next.live.clone();
                    order.total = next.current_total;
                    order.eligible = order
                        .eligible
                        .checked_add(next.target)
                        .ok_or(Sg0Error::CountOverflow)?;
                    let mut sorted = order.appended.clone();
                    sorted.sort_unstable();
                    next.phase = RecoveryPhase::Hash(PagedAppendPassV1::for_order(order, sorted));
                }
                None
            }
            RecoveryPhase::Hash(pass) => {
                let result = pass.advance(current_graph, durable_transcript)?;
                if result.is_some() {
                    next.phase = RecoveryPhase::Done;
                }
                result
            }
            RecoveryPhase::Done => return Err(Sg0Error::Invariant),
        };
        *self = next;
        Ok(out)
    }
}

fn validate_single_parent(
    g: &impl ReceiverVerifiedSg0Graph,
    id: VertexId,
    parent: VertexId,
) -> Result<()> {
    if !g.receiver_verified_contains(id)?
        || g.parent_set(id)? != Sg0ParentSetV1::vertices(vec![parent])?
    {
        return Err(Sg0Error::Invariant);
    }
    // Re-derive the single-parent metadata, including score/work/empty merge
    // commitment. The receiver still owns proof/body/timestamp validation.
    let prior = metadata(g, parent)?;
    let expected = Sg0VertexDataV1 {
        selected_parent: Sg0SelectedParentV1::Vertex(parent),
        merge_blues: Vec::new(),
        merge_red_count: 0,
        merge_order_commitment: colored_commitment(MERGE_COMMITMENT_DOMAIN, &[])?,
        blue_score: prior
            .blue_score()
            .checked_add(1)
            .ok_or(Sg0Error::ScoreOverflow)?,
        blue_work: prior
            .blue_work()
            .checked_add(work(g, id)?)
            .ok_or(Sg0Error::WorkOverflow)?,
    };
    if metadata(g, id)? != expected {
        return Err(Sg0Error::Invariant);
    }
    Ok(())
}

pub(super) fn hash_graph_entry(
    hash: &mut Sha256,
    g: &impl ReceiverVerifiedSg0Graph,
    id: VertexId,
) -> Result<()> {
    hash.update(id.as_bytes());
    match g.parent_set(id)? {
        Sg0ParentSetV1::Anchor => hash.update([0]),
        Sg0ParentSetV1::Vertices(parents) => {
            if parents.is_empty() || parents.len() > 2 || parents.windows(2).any(|p| p[0] >= p[1]) {
                return Err(Sg0Error::InvalidParents);
            }
            hash.update([1]);
            hash.update((parents.len() as u64).to_le_bytes());
            for p in parents {
                hash.update(p.as_bytes());
            }
        }
    }
    hash.update(work(g, id)?.to_be_bytes());
    let data = metadata(g, id)?;
    match data.selected_parent() {
        Sg0SelectedParentV1::Anchor => hash.update([0]),
        Sg0SelectedParentV1::Vertex(p) => {
            hash.update([1]);
            hash.update(p.as_bytes());
        }
    }
    hash.update(data.merge_order_commitment().as_bytes());
    hash.update(data.blue_score().to_le_bytes());
    hash.update(data.blue_work().to_be_bytes());
    Ok(())
}
