//! Metered ordering, exact chain snapshots and one-parent incremental metadata.
//!
//! This bounds exposed graph reads/visits and returned merge members per local
//! operation. It is NOT a paged order engine or a total-history scaling claim:
//! reference snapshots still materialize their order, and exhausted operations
//! must be retried from the beginning with an explicitly chosen allowance.
//! A budget failure is local deferral, never invalid-peer or absent-data proof.

use super::*;
use std::cell::Cell;

/// Derives the unchanged virtual snapshot with a linear-read chain fast path.
///
/// Inventory and parent edges must prove that the *entire* graph is one chain;
/// merely observing one tip is insufficient. Every metadata recurrence is then
/// checked from the anchor forward. Forks, multiple anchors and merges retain
/// the reference implementation, using the same caller-owned meter (no refill).
/// This still sorts/materializes history and is not a paged order engine.
/// # Errors
/// Propagates missing/corrupt graph evidence, invalid metadata, overflow and the
/// caller's exhausted resource budget. Errors never select the fallback path.
pub fn derive_virtual_order_chain_fast_v1(
    graph: &impl ReceiverVerifiedSg0Graph,
) -> Result<Sg0OrderSnapshotV1, Sg0Error> {
    let vertices = all_vertex_ids(graph)?;
    if vertices.is_empty() {
        return derive_virtual_order(graph);
    }
    let mut root = None;
    let mut children = BTreeMap::new();
    for vertex in &vertices {
        ensure_vertex_exists(graph, *vertex)?;
        let parents = validated_parent_shape_only(graph, *vertex)?;
        match parents.as_slice() {
            [] => {
                if root.replace(*vertex).is_some() {
                    return derive_virtual_order(graph);
                }
            }
            [parent] => {
                if vertices.binary_search(parent).is_err() {
                    return Err(Sg0Error::MissingVertex);
                }
                if parent == vertex {
                    return Err(Sg0Error::Cycle);
                }
                if children.insert(*parent, *vertex).is_some() {
                    return derive_virtual_order(graph);
                }
            }
            _ => return derive_virtual_order(graph),
        }
    }
    let root = root.ok_or(Sg0Error::Cycle)?;
    let empty_merge = colored_commitment(MERGE_COMMITMENT_DOMAIN, &[])?;
    let mut eligible_order = Vec::with_capacity(vertices.len());
    let mut cursor = Some(root);
    let mut selected_parent = Sg0SelectedParentV1::Anchor;
    let mut eligible_work = Uint256::ZERO;
    // Only compact, freshly recurrence-checked chain facts survive this walk.
    // No payloads, merge lists, imported metadata or cross-operation authority.
    let mut facts = Vec::with_capacity(vertices.len());
    while let Some(vertex) = cursor {
        if eligible_order.len() == vertices.len() {
            return Err(Sg0Error::Cycle);
        }
        let vertex_work = work(graph, vertex)?;
        eligible_work = eligible_work
            .checked_add(vertex_work)
            .ok_or(Sg0Error::WorkOverflow)?;
        let data = metadata(graph, vertex)?;
        let score = u128::try_from(eligible_order.len())
            .map_err(|_| Sg0Error::ScoreOverflow)?
            .checked_add(1)
            .ok_or(Sg0Error::ScoreOverflow)?;
        if data.selected_parent != selected_parent
            || !data.merge_blues.is_empty()
            || data.merge_red_count != 0
            || data.merge_order_commitment != empty_merge
            || data.blue_score != score
            || data.blue_work != eligible_work
        {
            return Err(Sg0Error::Invariant);
        }
        facts.push(ChainCommitmentFact {
            id: vertex,
            parent: selected_parent,
            work: vertex_work,
            merge: data.merge_order_commitment,
            score: data.blue_score,
            blue_work: data.blue_work,
        });
        eligible_order.push(vertex);
        selected_parent = Sg0SelectedParentV1::Vertex(vertex);
        cursor = children.remove(&vertex);
    }
    // A root plus an unrelated cycle is not a chain, even with exactly one tip.
    if eligible_order.len() != vertices.len() || !children.is_empty() {
        return Err(Sg0Error::Cycle);
    }
    let colored: Vec<_> = eligible_order
        .iter()
        .map(|id| (*id, Sg0Color::Blue))
        .collect();
    facts.sort_unstable_by_key(|fact| fact.id);
    Ok(Sg0OrderSnapshotV1 {
        graph_commitment: chain_graph_commitment(&facts)?,
        selected_tip: eligible_order.last().copied(),
        total_order_commitment: colored_commitment(TOTAL_ORDER_COMMITMENT_DOMAIN, &colored)?,
        eligible_order_commitment: ids_commitment(
            ELIGIBLE_ORDER_COMMITMENT_DOMAIN,
            &eligible_order,
        )?,
        total_order: eligible_order
            .iter()
            .map(|id| Sg0OrderedVertexV1 {
                vertex_id: *id,
                color: Sg0Color::Blue,
            })
            .collect(),
        eligible_order,
        eligible_work,
    })
}

// Parent edges were fully checked before the walk; each ordinary single parent
// equals the recurrence's selected parent. Thus these fields reproduce exactly
// the reference graph_commitment encoding without rereading verified sources.
struct ChainCommitmentFact {
    id: VertexId,
    parent: Sg0SelectedParentV1,
    work: Uint256,
    merge: Hash32,
    score: u128,
    blue_work: Uint256,
}
fn chain_graph_commitment(facts: &[ChainCommitmentFact]) -> Result<Hash32, Sg0Error> {
    let mut hash = Sha256::new();
    hash.update(GRAPH_COMMITMENT_DOMAIN);
    update_len(&mut hash, facts.len())?;
    for fact in facts {
        hash.update(fact.id.as_bytes());
        match fact.parent {
            Sg0SelectedParentV1::Anchor => hash.update([0]),
            Sg0SelectedParentV1::Vertex(parent) => {
                hash.update([1]);
                update_len(&mut hash, 1)?;
                hash.update(parent.as_bytes());
            }
        }
        hash.update(fact.work.to_be_bytes());
        match fact.parent {
            Sg0SelectedParentV1::Anchor => hash.update([0]),
            Sg0SelectedParentV1::Vertex(parent) => {
                hash.update([1]);
                hash.update(parent.as_bytes());
            }
        }
        hash.update(fact.merge.as_bytes());
        hash.update(fact.score.to_le_bytes());
        hash.update(fact.blue_work.to_be_bytes());
    }
    Ok(Hash32::new(hash.finalize().into()))
}

/// Indexed receiver adapter whose individual reads are independently bounded.
///
/// Implementations must make contains/parent/work/metadata reads fixed-budget,
/// must bound decoded metadata size, and must stop streamed enumeration when
/// its visitor fails. This marker grants no remote-data or consensus authority.
/// Ancestry queries are deliberately reconstructed through the metered wrapper
/// rather than trusting an opaque potentially unbounded adapter walk.
pub trait ReceiverVerifiedBoundedSg0GraphV1: ReceiverVerifiedSg0Graph {}

/// Positive per-operation limits. These are local policy, not profile limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sg0OperationBudgetV1 {
    reads: u64,
    visits: u64,
    merge_members: u64,
}

impl Sg0OperationBudgetV1 {
    /// Creates explicit limits without silently increasing a caller's budget.
    /// # Errors
    /// Rejects a zero limit.
    pub fn new(reads: u64, visits: u64, merge_members: u64) -> Result<Self, Sg0Error> {
        if reads == 0 || visits == 0 || merge_members == 0 {
            return Err(Sg0Error::ResourceBudget);
        }
        Ok(Self {
            reads,
            visits,
            merge_members,
        })
    }
}

/// Cumulative operation counters, including unsuccessful attempted primitives.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sg0OperationUsageV1 {
    /// Calls admitted to an independently bounded primitive or enumeration.
    pub reads: u64,
    /// IDs emitted to a caller from inventory or strict-past enumeration.
    pub visits: u64,
    /// Members in metadata returned by successful primitive reads.
    pub merge_members: u64,
}

/// One shared, non-resettable operation meter over an immutable local graph.
pub struct MeteredSg0GraphV1<'a, G: ReceiverVerifiedBoundedSg0GraphV1> {
    graph: &'a G,
    limit: Sg0OperationBudgetV1,
    used: Cell<Sg0OperationUsageV1>,
    exhausted: Cell<bool>,
}

impl<'a, G: ReceiverVerifiedBoundedSg0GraphV1> MeteredSg0GraphV1<'a, G> {
    /// Pins the caller's immutable receiver graph for this operation.
    #[must_use]
    pub fn new(graph: &'a G, limit: Sg0OperationBudgetV1) -> Self {
        Self {
            graph,
            limit,
            used: Cell::new(Sg0OperationUsageV1::default()),
            exhausted: Cell::new(false),
        }
    }

    /// Returns exact accumulated boundary usage without resetting it.
    #[must_use]
    pub fn usage(&self) -> Sg0OperationUsageV1 {
        self.used.get()
    }

    fn charge(&self, reads: u64, visits: u64, members: u64) -> Result<(), Sg0Error> {
        if self.exhausted.get() {
            return Err(Sg0Error::ResourceBudget);
        }
        let prior = self.used.get();
        let next = (|| {
            Some(Sg0OperationUsageV1 {
                reads: prior.reads.checked_add(reads)?,
                visits: prior.visits.checked_add(visits)?,
                merge_members: prior.merge_members.checked_add(members)?,
            })
        })();
        let Some(next) = next.filter(|next| {
            next.reads <= self.limit.reads
                && next.visits <= self.limit.visits
                && next.merge_members <= self.limit.merge_members
        }) else {
            self.exhausted.set(true);
            return Err(Sg0Error::ResourceBudget);
        };
        self.used.set(next);
        Ok(())
    }
}

impl<G: ReceiverVerifiedBoundedSg0GraphV1> ReceiverVerifiedSg0Graph for MeteredSg0GraphV1<'_, G> {
    fn visit_vertex_ids(
        &self,
        visitor: &mut dyn FnMut(VertexId) -> Result<(), Sg0Error>,
    ) -> Result<(), Sg0Error> {
        self.charge(1, 0, 0)?;
        self.graph.visit_vertex_ids(&mut |id| {
            self.charge(0, 1, 0)?;
            visitor(id)
        })
    }
    fn receiver_verified_contains(&self, vertex: VertexId) -> Result<bool, Sg0Error> {
        self.charge(1, 0, 0)?;
        self.graph.receiver_verified_contains(vertex)
    }
    fn parent_set(&self, vertex: VertexId) -> Result<Sg0ParentSetV1, Sg0Error> {
        self.charge(1, 0, 0)?;
        self.graph.parent_set(vertex)
    }
    fn receiver_verified_work_be(&self, vertex: VertexId) -> Result<[u8; 32], Sg0Error> {
        self.charge(1, 0, 0)?;
        self.graph.receiver_verified_work_be(vertex)
    }
    fn vertex_data(&self, vertex: VertexId) -> Result<Option<Sg0VertexDataV1>, Sg0Error> {
        self.charge(1, 0, 0)?;
        let data = self.graph.vertex_data(vertex)?;
        let members = data.as_ref().map_or(0, |data| data.merge_blues.len());
        self.charge(
            0,
            0,
            u64::try_from(members).map_err(|_| Sg0Error::CountOverflow)?,
        )?;
        Ok(data)
    }
    fn visit_strict_past_ids(
        &self,
        vertex: VertexId,
        visitor: &mut dyn FnMut(VertexId) -> Result<(), Sg0Error>,
    ) -> Result<(), Sg0Error> {
        self.charge(1, 0, 0)?;
        reference_visit_strict_past(self, vertex, &mut |id| {
            self.charge(0, 1, 0)?;
            visitor(id)
        })
    }
    // Default ancestry traverses the above metered walk, never the inner graph's
    // potentially unbounded ancestry override. Every edge read is charged too.
}

/// Derives exact SG-0 metadata for an append, using existing admitted metadata.
///
/// With zero or one parent the merge set is empty. A new vertex is comparable
/// with every inherited blue vertex, so inheriting the parent's locally derived
/// k-cluster cannot change its anticone counts. This case needs no inherited
/// blue-cluster reconstruction. Parent/cycle validation still traverses ancestry;
/// this is not a constant-I/O append claim. Two-parent merges use the unchanged
/// full reference algorithm.
/// Like the reference, this requires authentic locally derived parent metadata;
/// a structural cache decoder alone is not that authority.
/// # Errors
/// Rejects missing evidence, invalid/cyclic parents, zero work and overflow.
pub fn derive_append_vertex_data_v1(
    graph: &impl ReceiverVerifiedSg0Graph,
    vertex: VertexId,
) -> Result<Sg0VertexDataV1, Sg0Error> {
    ensure_vertex_exists(graph, vertex)?;
    let parents = validated_parents(graph, vertex)?;
    if parents.len() > 1 {
        return derive_vertex_data(graph, vertex);
    }
    let own_work = work(graph, vertex)?;
    let (selected_parent, score, prior_work) = match parents.first() {
        Some(parent) => {
            let data = metadata(graph, *parent)?;
            (
                Sg0SelectedParentV1::Vertex(*parent),
                data.blue_score(),
                data.blue_work(),
            )
        }
        None => (Sg0SelectedParentV1::Anchor, 0, Uint256::ZERO),
    };
    Ok(Sg0VertexDataV1 {
        selected_parent,
        merge_blues: Vec::new(),
        merge_red_count: 0,
        merge_order_commitment: colored_commitment(MERGE_COMMITMENT_DOMAIN, &[])?,
        blue_score: score.checked_add(1).ok_or(Sg0Error::ScoreOverflow)?,
        blue_work: prior_work
            .checked_add(own_work)
            .ok_or(Sg0Error::WorkOverflow)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Graph {
        entries: BTreeMap<VertexId, (Sg0ParentSetV1, Sg0VertexDataV1)>,
        candidate: Option<(VertexId, Sg0ParentSetV1)>,
    }
    impl Graph {
        fn id(n: u64) -> VertexId {
            let mut id = [0; 32];
            id[24..].copy_from_slice(&n.to_be_bytes());
            VertexId::from_bytes(id)
        }
        fn push(&mut self, n: u64, parents: Sg0ParentSetV1) {
            self.candidate = Some((Self::id(n), parents.clone()));
            let actual = derive_append_vertex_data_v1(&Reference(self), Self::id(n)).unwrap();
            let expected = derive_vertex_data(&Reference(self), Self::id(n)).unwrap();
            assert_eq!(actual, expected);
            self.entries.insert(Self::id(n), (parents, actual));
            self.candidate = None;
        }
    }
    impl ReceiverVerifiedSg0Graph for Graph {
        fn visit_vertex_ids(
            &self,
            visitor: &mut dyn FnMut(VertexId) -> Result<(), Sg0Error>,
        ) -> Result<(), Sg0Error> {
            for id in self.entries.keys() {
                visitor(*id)?;
            }
            if let Some((id, _)) = &self.candidate {
                visitor(*id)?;
            }
            Ok(())
        }
        fn receiver_verified_contains(&self, id: VertexId) -> Result<bool, Sg0Error> {
            Ok(self.entries.contains_key(&id)
                || self.candidate.as_ref().is_some_and(|(key, _)| *key == id))
        }
        fn parent_set(&self, id: VertexId) -> Result<Sg0ParentSetV1, Sg0Error> {
            if let Some((key, parents)) = &self.candidate {
                if *key == id {
                    return Ok(parents.clone());
                }
            }
            self.entries
                .get(&id)
                .map(|v| v.0.clone())
                .ok_or(Sg0Error::MissingVertex)
        }
        fn receiver_verified_work_be(&self, id: VertexId) -> Result<[u8; 32], Sg0Error> {
            if !self.receiver_verified_contains(id)? {
                return Err(Sg0Error::MissingVertex);
            }
            Ok(Uint256::from_u64(1).to_be_bytes())
        }
        fn vertex_data(&self, id: VertexId) -> Result<Option<Sg0VertexDataV1>, Sg0Error> {
            Ok(self.entries.get(&id).map(|v| v.1.clone()))
        }
        fn visit_strict_past_ids(
            &self,
            _: VertexId,
            _: &mut dyn FnMut(VertexId) -> Result<(), Sg0Error>,
        ) -> Result<(), Sg0Error> {
            panic!("meter must not delegate an unbounded walk")
        }
    }
    impl ReceiverVerifiedBoundedSg0GraphV1 for Graph {}

    fn limit() -> Sg0OperationBudgetV1 {
        Sg0OperationBudgetV1::new(2_000_000, 2_000_000, 2_000_000).unwrap()
    }

    #[test]
    fn chain_fast_path_matches_all_snapshot_fields_with_linear_read_budget() {
        assert_eq!(
            derive_virtual_order_chain_fast_v1(&Graph::default()).unwrap(),
            derive_virtual_order(&Reference(&Graph::default())).unwrap()
        );
        for count in [1_u64, 8, 80] {
            let mut graph = Graph::default();
            // Reverse IDs ensure inventory order is not mistaken for ancestry.
            for offset in 0..count {
                graph.push(
                    count - offset,
                    if offset == 0 {
                        Sg0ParentSetV1::anchor()
                    } else {
                        Sg0ParentSetV1::vertices(vec![Graph::id(count - offset + 1)]).unwrap()
                    },
                );
            }
            let expected = derive_virtual_order(&Reference(&graph)).unwrap();
            let meter = MeteredSg0GraphV1::new(
                &graph,
                Sg0OperationBudgetV1::new(8 * count + 2, count, 1).unwrap(),
            );
            assert_eq!(
                derive_virtual_order_chain_fast_v1(&meter).unwrap(),
                expected
            );
            assert_eq!(meter.usage().visits, count);
            assert!(meter.usage().reads <= 8 * count + 2);
            assert_eq!(meter.usage().merge_members, 0);
        }
    }

    #[test]
    fn chain_fast_path_rejects_disconnected_cycles_and_missing_parents() {
        let mut graph = Graph::default();
        graph.push(1, Sg0ParentSetV1::anchor());
        graph.push(2, Sg0ParentSetV1::vertices(vec![Graph::id(1)]).unwrap());
        graph.push(3, Sg0ParentSetV1::vertices(vec![Graph::id(2)]).unwrap());
        graph.entries.get_mut(&Graph::id(2)).unwrap().0 =
            Sg0ParentSetV1::vertices(vec![Graph::id(3)]).unwrap();
        // Root 1 is the sole tip, but 2 <-> 3 form an unrelated cycle.
        assert_eq!(
            derive_virtual_order_chain_fast_v1(&graph),
            Err(Sg0Error::Cycle)
        );
        graph.entries.get_mut(&Graph::id(2)).unwrap().0 =
            Sg0ParentSetV1::vertices(vec![Graph::id(99)]).unwrap();
        assert_eq!(
            derive_virtual_order_chain_fast_v1(&graph),
            Err(Sg0Error::MissingVertex)
        );
    }

    #[test]
    fn chain_fast_path_checks_metadata_and_never_refills_exhausted_meter() {
        let mut graph = Graph::default();
        graph.push(1, Sg0ParentSetV1::anchor());
        graph.entries.get_mut(&Graph::id(1)).unwrap().1.blue_score = 2;
        assert_eq!(
            derive_virtual_order_chain_fast_v1(&graph),
            Err(Sg0Error::Invariant)
        );
        graph.entries.get_mut(&Graph::id(1)).unwrap().1.blue_score = 1;
        let meter = MeteredSg0GraphV1::new(&graph, Sg0OperationBudgetV1::new(3, 1, 1).unwrap());
        assert_eq!(
            derive_virtual_order_chain_fast_v1(&meter),
            Err(Sg0Error::ResourceBudget)
        );
        assert_eq!(
            derive_virtual_order_chain_fast_v1(&meter),
            Err(Sg0Error::ResourceBudget)
        );
        assert_eq!(meter.usage().reads, 3);
    }

    #[test]
    fn chain_fast_path_falls_back_for_branches_and_multiple_anchors() {
        let mut graph = Graph::default();
        graph.push(1, Sg0ParentSetV1::anchor());
        graph.push(2, Sg0ParentSetV1::vertices(vec![Graph::id(1)]).unwrap());
        graph.push(3, Sg0ParentSetV1::vertices(vec![Graph::id(1)]).unwrap());
        for additional_anchor in [false, true] {
            if additional_anchor {
                graph.push(4, Sg0ParentSetV1::anchor());
            }
            let meter = MeteredSg0GraphV1::new(&graph, limit());
            assert_eq!(
                derive_virtual_order_chain_fast_v1(&meter).unwrap(),
                derive_virtual_order(&Reference(&graph)).unwrap()
            );
        }
    }

    // The reference fixtures need their normal ancestry implementation for
    // differential comparison; only the adversarial-wrapper test uses Graph.
    struct Reference<'a>(&'a Graph);
    impl ReceiverVerifiedSg0Graph for Reference<'_> {
        fn visit_vertex_ids(
            &self,
            visitor: &mut dyn FnMut(VertexId) -> Result<(), Sg0Error>,
        ) -> Result<(), Sg0Error> {
            self.0.visit_vertex_ids(visitor)
        }
        fn receiver_verified_contains(&self, id: VertexId) -> Result<bool, Sg0Error> {
            self.0.receiver_verified_contains(id)
        }
        fn parent_set(&self, id: VertexId) -> Result<Sg0ParentSetV1, Sg0Error> {
            self.0.parent_set(id)
        }
        fn receiver_verified_work_be(&self, id: VertexId) -> Result<[u8; 32], Sg0Error> {
            self.0.receiver_verified_work_be(id)
        }
        fn vertex_data(&self, id: VertexId) -> Result<Option<Sg0VertexDataV1>, Sg0Error> {
            self.0.vertex_data(id)
        }
    }

    #[test]
    fn append_and_metered_order_match_reference_beyond_old_64_vertex_cap() {
        let mut graph = Graph::default();
        for n in 1..=80 {
            let parents = if n == 1 {
                Sg0ParentSetV1::anchor()
            } else {
                Sg0ParentSetV1::vertices(vec![Graph::id(n - 1)]).unwrap()
            };
            graph.push(n, parents);
        }
        let expected = derive_virtual_order(&Reference(&graph)).unwrap();
        let meter = MeteredSg0GraphV1::new(&graph, limit());
        assert_eq!(derive_virtual_order(&meter).unwrap(), expected);
        assert_eq!(expected.eligible_order().len(), 80);
        graph.candidate = Some((
            Graph::id(81),
            Sg0ParentSetV1::vertices(vec![Graph::id(80)]).unwrap(),
        ));
        let meter = MeteredSg0GraphV1::new(&graph, Sg0OperationBudgetV1::new(512, 80, 1).unwrap());
        assert_eq!(
            derive_append_vertex_data_v1(&meter, Graph::id(81)).unwrap(),
            derive_vertex_data(&Reference(&graph), Graph::id(81)).unwrap()
        );
        assert_eq!(meter.usage().visits, 79);
        assert!(meter.usage().reads <= 512);
    }

    #[test]
    fn meter_exhaustion_is_terminal_and_never_absence_or_partial_order() {
        let mut graph = Graph::default();
        graph.push(1, Sg0ParentSetV1::anchor());
        graph.push(2, Sg0ParentSetV1::vertices(vec![Graph::id(1)]).unwrap());
        let meter = MeteredSg0GraphV1::new(&graph, Sg0OperationBudgetV1::new(100, 1, 100).unwrap());
        assert_eq!(derive_virtual_order(&meter), Err(Sg0Error::ResourceBudget));
        assert_eq!(meter.usage().visits, 1);
        assert_eq!(
            meter.receiver_verified_contains(Graph::id(99)),
            Err(Sg0Error::ResourceBudget)
        );
        assert_eq!(
            meter.parent_set(Graph::id(1)),
            Err(Sg0Error::ResourceBudget)
        );
        let reads = MeteredSg0GraphV1::new(&graph, Sg0OperationBudgetV1::new(1, 100, 100).unwrap());
        assert!(reads.receiver_verified_contains(Graph::id(1)).unwrap());
        assert_eq!(
            reads.vertex_data(Graph::id(1)),
            Err(Sg0Error::ResourceBudget)
        );
        assert_eq!(reads.usage().reads, 1);
    }

    #[test]
    fn ancestry_is_charged_and_missing_data_still_errors() {
        let mut graph = Graph::default();
        graph.push(1, Sg0ParentSetV1::anchor());
        graph.push(2, Sg0ParentSetV1::vertices(vec![Graph::id(1)]).unwrap());
        let meter = MeteredSg0GraphV1::new(&graph, limit());
        assert!(
            meter
                .receiver_verified_is_ancestor(Graph::id(1), Graph::id(2))
                .unwrap()
        );
        assert_eq!(meter.usage().visits, 1);
        assert!(meter.usage().reads > 1);
        assert_eq!(
            meter.parent_set(Graph::id(99)),
            Err(Sg0Error::MissingVertex)
        );
        assert!(!meter.receiver_verified_contains(Graph::id(99)).unwrap());
    }

    #[test]
    fn fork_merge_and_inherited_red_colors_match_reference() {
        let mut graph = Graph::default();
        graph.push(1, Sg0ParentSetV1::anchor());
        for n in 2..=5 {
            graph.push(n, Sg0ParentSetV1::vertices(vec![Graph::id(1)]).unwrap());
        }
        graph.push(
            6,
            Sg0ParentSetV1::vertices(vec![Graph::id(2), Graph::id(3)]).unwrap(),
        );
        graph.push(
            7,
            Sg0ParentSetV1::vertices(vec![Graph::id(4), Graph::id(5)]).unwrap(),
        );
        graph.push(
            8,
            Sg0ParentSetV1::vertices(vec![Graph::id(6), Graph::id(7)]).unwrap(),
        );
        graph.push(9, Sg0ParentSetV1::vertices(vec![Graph::id(8)]).unwrap());
        let fast_meter = MeteredSg0GraphV1::new(&graph, limit());
        assert_eq!(
            derive_virtual_order_chain_fast_v1(&fast_meter).unwrap(),
            derive_virtual_order(&Reference(&graph)).unwrap()
        );
        let meter = MeteredSg0GraphV1::new(&graph, limit());
        assert_eq!(
            derive_virtual_order(&meter).unwrap(),
            derive_virtual_order(&Reference(&graph)).unwrap()
        );
    }
}
