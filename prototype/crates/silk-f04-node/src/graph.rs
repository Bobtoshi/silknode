//! Receiver-owned full-data graph. No decoded peer object can construct validity.
mod ancestry;
use crate::{
    Digest, Error, Result,
    budget::{JobBudget, LocalClock},
    carriage::{Candidate, ParentFacts, WorkEngine},
    genesis::Genesis,
    wire::{raw_hash, u32le},
};
use ancestry::{PagedAncestry, RetainedContext};
use silk_order::sg0_v1::{
    ReceiverVerifiedSg0Graph, Sg0Error, Sg0OrderSnapshotV1, Sg0ParentSetV1, Sg0VertexDataV1,
    budgeted::{derive_append_vertex_data_v1, derive_virtual_order_chain_fast_v1},
};
use silk_pow::Uint256;
use silk_sapling_f04::{
    codec::Envelope,
    crypto::{VerifiedEnvelope, verify_many},
    parameters::SaplingParameters,
};
use silk_types::VertexId;
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};

/// Fully verified carrier and ordered cryptographic capabilities; constructor is private.
pub struct VerifiedVertex {
    candidate: Candidate,
    envelopes: Vec<VerifiedEnvelope>,
    facts: ParentFacts,
    metadata: Option<Sg0VertexDataV1>,
    ancestors: PagedAncestry,
    retained_source: Option<RetainedSource>,
}
/// Live receiver-derived source binding, never serialized or imported as validity.
struct RetainedSource {
    id: Digest,
    record_len: usize,
    candidate_len: usize,
}
impl VerifiedVertex {
    /// Immutable exact carrier; parsed fields were rederived from its bytes.
    #[must_use]
    pub const fn candidate(&self) -> &Candidate {
        &self.candidate
    }
    /// Every exact representation in committed order, including duplicates.
    #[must_use]
    pub fn envelopes(&self) -> &[VerifiedEnvelope] {
        &self.envelopes
    }
    /// Parent-local facts, not the current canonical branch's source by index.
    #[must_use]
    pub const fn facts(&self) -> &ParentFacts {
        &self.facts
    }
    pub(crate) fn retained_record(&self) -> Result<Vec<u8>> {
        let bytes = self.candidate.encode();
        let metadata = self
            .metadata
            .as_ref()
            .ok_or(Error::Unavailable("unsealed vertex metadata"))?
            .canonical_cache_bytes_v1()?;
        let mut b = Vec::new();
        b.extend_from_slice(b"SNF04VR1");
        b.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        b.extend_from_slice(&bytes);
        b.extend_from_slice(&self.facts.source_record);
        b.extend_from_slice(&(metadata.len() as u32).to_le_bytes());
        b.extend_from_slice(&metadata);
        Ok(b)
    }
}

/// Append-only admitted red/blue evidence, within the explicit 4,096-vertex horizon.
#[derive(Clone, Default)]
pub struct Graph {
    vertices: Vec<Arc<VerifiedVertex>>,
    index: BTreeMap<VertexId, usize>,
    ancestry_reader: Option<Arc<RetainedContext>>,
}

/// Prepared atomic graph insertion, not visible until durable publication succeeds.
pub(crate) struct PreparedVertex {
    vertex: Arc<VerifiedVertex>,
    revision: usize,
}
impl PreparedVertex {
    pub fn vertex(&self) -> &VerifiedVertex {
        &self.vertex
    }
    /// Call only after the complete original record is durable or freshly replayed.
    /// Exact comparison keeps this address bound to the already verified vertex.
    pub(crate) fn bind_retained_source(&mut self, bytes: &[u8]) -> Result<()> {
        let vertex = Arc::get_mut(&mut self.vertex)
            .ok_or(Error::Unavailable("shared prepared source binding"))?;
        if vertex.retained_source.is_some() || vertex.retained_record()? != bytes {
            return Err(Error::Unavailable("retained source binding mismatch"));
        }
        vertex.retained_source = Some(RetainedSource {
            id: raw_hash(bytes),
            record_len: bytes.len(),
            candidate_len: u32le(bytes, 8)? as usize,
        });
        Ok(())
    }
    pub(crate) fn retain_ancestry(
        &mut self,
        graph: &Graph,
        store: &mut crate::store::Store,
        budget: &JobBudget,
    ) -> Result<()> {
        let reader = graph
            .ancestry_reader
            .as_ref()
            .ok_or(Error::Unavailable("durable graph ancestry reader absent"))?
            .clone();
        Arc::get_mut(&mut self.vertex)
            .ok_or(Error::Unavailable("shared prepared ancestry publication"))?
            .ancestors
            .retain(store, reader, budget)
    }
}

/// Positive exact-byte cache, evictable only as performance state.
#[derive(Default)]
pub(crate) struct CryptoCache {
    entries: BTreeMap<(Digest, Digest), VerifiedEnvelope>,
    fifo: VecDeque<(Digest, Digest)>,
}
impl CryptoCache {
    fn get(&self, e: &Envelope) -> Option<VerifiedEnvelope> {
        self.entries
            .get(&(e.domain(), e.envelope_id()))
            .filter(|v| v.envelope().bytes() == e.bytes())
            .cloned()
    }
    pub(crate) fn insert(&mut self, verified: VerifiedEnvelope) {
        let e = verified.envelope();
        let key = (e.domain(), e.envelope_id());
        if self.entries.contains_key(&key) {
            return;
        }
        // Conservative 4KiB/entry, including map/FIFO/allocator metadata: <=16MiB.
        while self.entries.len() >= 4096 {
            if let Some(old) = self.fifo.pop_front() {
                self.entries.remove(&old);
            }
        }
        self.entries.insert(key, verified);
        self.fifo.push_back(key);
    }
}

impl Graph {
    #[cfg(test)]
    pub(crate) fn retained_ancestry_pages(&self) -> usize {
        self.vertices
            .iter()
            .map(|v| v.ancestors.retained_ids().len())
            .sum()
    }
    pub(crate) fn attach_ancestry_reader(
        &mut self,
        reader: Arc<crate::store::ObjectReader>,
        domain: Digest,
    ) -> Result<()> {
        if !self.is_empty() || self.ancestry_reader.is_some() {
            return Err(Error::Unavailable(
                "ancestry reader must precede fresh replay",
            ));
        }
        self.ancestry_reader = Some(RetainedContext::new(reader, domain));
        Ok(())
    }
    /// Number of fully admitted records, including red evidence.
    #[must_use]
    pub fn len(&self) -> usize {
        self.vertices.len()
    }
    /// Whether this contains no ordinary vertex.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.vertices.is_empty()
    }
    /// Complete admitted evidence in topological admission order, for full-range sync.
    pub fn vertices(&self) -> impl Iterator<Item = &VerifiedVertex> {
        self.vertices.iter().map(AsRef::as_ref)
    }
    /// Disk-backed full evidence export, not a validity constructor. Missing or
    /// damaged source objects refuse the whole range; no resident-byte fallback.
    pub(crate) fn export_retained_range(&self, start: usize, count: usize) -> Result<Vec<Vec<u8>>> {
        if count == 0 || count > 32 || start > self.len() {
            return Err(Error::Unavailable("public range bounds"));
        }
        let reader = self
            .ancestry_reader
            .as_ref()
            .ok_or(Error::Unavailable("durable graph source reader absent"))?;
        self.vertices
            .iter()
            .skip(start)
            .take(count)
            .map(|vertex| {
                let source = vertex
                    .retained_source
                    .as_ref()
                    .ok_or(Error::Unavailable("verified durable source binding absent"))?;
                let bytes = reader.objects().object(source.id, source.record_len)?;
                let end = 12_usize
                    .checked_add(source.candidate_len)
                    .ok_or(Error::Unavailable("retained export length"))?;
                if bytes.len() != source.record_len
                    || bytes.get(..8) != Some(b"SNF04VR1")
                    || u32le(&bytes, 8)? as usize != source.candidate_len
                    || bytes.get(12..end).is_none()
                {
                    return Err(Error::Unavailable("retained export framing"));
                }
                // The checked object hash is bound after fresh full admission;
                // it authenticates original bytes, not externally saved validity.
                Ok(bytes[12..end].to_vec())
            })
            .collect()
    }
    /// Indexed receiver-verified evidence lookup.
    pub fn get(&self, id: VertexId) -> Result<&VerifiedVertex> {
        self.index
            .get(&id)
            .map(|i| self.vertices[*i].as_ref())
            .ok_or(Error::Unavailable("missing admitted vertex"))
    }
    /// Internal reducer dependency read. A durable node must still possess the
    /// exact original source, even while its verified body remains resident.
    /// Default standalone graphs retain their existing borrowed resident API.
    pub(crate) fn get_for_execution(
        &self,
        id: VertexId,
        budget: &JobBudget,
    ) -> Result<&VerifiedVertex> {
        budget.check()?;
        let vertex = self.get(id)?;
        if let Some(reader) = &self.ancestry_reader {
            let source = vertex
                .retained_source
                .as_ref()
                .ok_or(Error::Unavailable("verified durable source binding absent"))?;
            budget.source()?;
            // The live binding was established from the complete exact record.
            // No saved page/flag or decoded peer record constructs a capability.
            reader.objects().object(source.id, source.record_len)?;
            budget.check()?;
        }
        Ok(vertex)
    }
    pub(crate) fn order(&self, budget: &JobBudget) -> Result<Sg0OrderSnapshotV1> {
        Ok(derive_virtual_order_chain_fast_v1(&View {
            graph: self,
            added: None,
            members: None,
            budget,
        })?)
    }
    pub(crate) fn order_with(
        &self,
        prepared: &PreparedVertex,
        budget: &JobBudget,
    ) -> Result<Sg0OrderSnapshotV1> {
        if prepared.revision != self.len() {
            return Err(Error::Unavailable("stale staged order"));
        }
        Ok(derive_virtual_order_chain_fast_v1(&View {
            graph: self,
            added: Some(&prepared.vertex),
            members: None,
            budget,
        })?)
    }
    pub(crate) fn parent_order(
        &self,
        parents: &Sg0ParentSetV1,
        budget: &JobBudget,
    ) -> Result<Sg0OrderSnapshotV1> {
        let bits = self.parent_closure(parents)?;
        Ok(derive_virtual_order_chain_fast_v1(&View {
            graph: self,
            added: None,
            members: Some(&bits),
            budget,
        })?)
    }
    fn parent_closure(&self, parents: &Sg0ParentSetV1) -> Result<PagedAncestry> {
        if let Sg0ParentSetV1::Vertices(p) = parents {
            Sg0ParentSetV1::vertices(p.clone())?;
        }
        let mut bits = PagedAncestry::default();
        for p in parents.ordinary_parents() {
            let i = *self
                .index
                .get(p)
                .ok_or(Error::Unavailable("candidate parent dependency"))?;
            let v = &self.vertices[i];
            bits.union(&v.ancestors)?;
            bits.insert(i)?;
        }
        if let [a, b] = parents.ordinary_parents()
            && (self.is_ancestor(*a, *b)? || self.is_ancestor(*b, *a)?)
        {
            return Err(Error::Invalid("comparable parents"));
        }
        Ok(bits)
    }
    pub(crate) fn is_ancestor(&self, a: VertexId, b: VertexId) -> Result<bool> {
        let ai = *self
            .index
            .get(&a)
            .ok_or(Error::Unavailable("missing ancestor"))?;
        Ok(self.get(b)?.ancestors.contains(ai)?)
    }

    /// Only freshly decoded canonical bytes enter the validity pipeline.
    /// `clock=None` is crate-private and reserved for authenticated local archive replay.
    pub(crate) fn decode_candidate(
        &self,
        bytes: &[u8],
        g: &Genesis,
        clock: Option<&LocalClock>,
    ) -> Result<Candidate> {
        if self.len() >= 4096 {
            return Err(Error::Paused("admitted-vertex reference horizon"));
        }
        let candidate = Candidate::decode(bytes, g)?;
        let id = VertexId::from_bytes(candidate.id);
        if self.index.contains_key(&id) {
            return Err(Error::Unavailable("already admitted exact vertex"));
        }
        if let Some(clock) = clock {
            clock.check_new(candidate.header.timestamp)?;
        }
        Ok(candidate)
    }
    pub(crate) fn verify_body(
        &self,
        candidate: Candidate,
        facts: ParentFacts,
        g: &Genesis,
        parameters: &SaplingParameters,
        work: &mut WorkEngine,
        crypto: &CryptoCache,
        budget: &JobBudget,
    ) -> Result<VerifiedVertex> {
        candidate.header.check_facts(&facts)?;
        budget.check()?;
        work.verify(&candidate, &facts, g)?;
        budget.check()?;
        let mut envelopes = Vec::with_capacity(candidate.body.representations().len());
        let mut missing = Vec::new();
        let mut missing_indices = Vec::new();
        for (i, bytes) in candidate.body.representations().iter().enumerate() {
            let e = Envelope::decode(bytes, &g.domain())?;
            let cached = crypto.get(&e);
            if cached.is_none() {
                missing_indices.push(i);
                missing.push(e);
            }
            envelopes.push(cached);
        }
        let verified = verify_many(missing, parameters, 2)?;
        budget.check()?;
        for (i, v) in missing_indices.into_iter().zip(verified) {
            envelopes[i] = Some(v);
        }
        Ok(VerifiedVertex {
            ancestors: self.parent_closure(&candidate.header.parents)?,
            candidate,
            facts,
            envelopes: envelopes
                .into_iter()
                .map(|v| v.expect("complete exact verification"))
                .collect(),
            metadata: None,
            retained_source: None,
        })
    }
    pub(crate) fn seal(
        &self,
        mut vertex: VerifiedVertex,
        budget: &JobBudget,
    ) -> Result<PreparedVertex> {
        let id = VertexId::from_bytes(vertex.candidate.id);
        vertex.metadata = Some(
            derive_append_vertex_data_v1(
                &View {
                    graph: self,
                    added: Some(&vertex),
                    members: None,
                    budget,
                },
                id,
            )
            .map_err(|error| match error {
                Sg0Error::RedundantOrCyclicParent | Sg0Error::InvalidParents => {
                    Error::Invalid("candidate SG0 parent rule")
                }
                other => Error::Order(other),
            })?,
        );
        budget.check()?;
        Ok(PreparedVertex {
            vertex: Arc::new(vertex),
            revision: self.len(),
        })
    }
    pub(crate) fn publish(&mut self, prepared: PreparedVertex) -> Result<()> {
        if prepared.revision != self.len()
            || self
                .index
                .contains_key(&VertexId::from_bytes(prepared.vertex.candidate.id))
        {
            return Err(Error::Unavailable("stale graph publication"));
        }
        self.index.insert(
            VertexId::from_bytes(prepared.vertex.candidate.id),
            self.len(),
        );
        self.vertices.push(prepared.vertex);
        Ok(())
    }
}

// Each view exposes ONLY admitted evidence plus, privately, one already fully
// verified candidate. Ancestry is derived on insert from immutable parent closure.
struct View<'a> {
    graph: &'a Graph,
    added: Option<&'a VerifiedVertex>,
    members: Option<&'a PagedAncestry>,
    budget: &'a JobBudget,
}
impl View<'_> {
    fn lookup(&self, id: VertexId) -> std::result::Result<&VerifiedVertex, Sg0Error> {
        self.budget.graph_read()?;
        if let Some(v) = self.added.filter(|v| v.candidate.id == id.into_bytes()) {
            return Ok(v);
        }
        let i = *self.graph.index.get(&id).ok_or(Sg0Error::MissingVertex)?;
        if let Some(bits) = self.members
            && !bits.contains(i)?
        {
            return Err(Sg0Error::MissingVertex);
        }
        Ok(&self.graph.vertices[i])
    }
}
impl ReceiverVerifiedSg0Graph for View<'_> {
    fn visit_vertex_ids(
        &self,
        visitor: &mut dyn FnMut(VertexId) -> std::result::Result<(), Sg0Error>,
    ) -> std::result::Result<(), Sg0Error> {
        for (id, i) in &self.graph.index {
            self.budget.graph_read()?;
            if self
                .members
                .map(|bits| bits.contains(*i))
                .transpose()?
                .unwrap_or(true)
            {
                visitor(*id)?;
            }
        }
        if let Some(v) = self.added {
            visitor(VertexId::from_bytes(v.candidate.id))?;
        }
        Ok(())
    }
    fn receiver_verified_contains(&self, id: VertexId) -> std::result::Result<bool, Sg0Error> {
        match self.lookup(id) {
            Ok(_) => Ok(true),
            Err(Sg0Error::MissingVertex) => Ok(false),
            Err(e) => Err(e),
        }
    }
    fn parent_set(&self, id: VertexId) -> std::result::Result<Sg0ParentSetV1, Sg0Error> {
        Ok(self.lookup(id)?.candidate.header.parents.clone())
    }
    fn receiver_verified_work_be(&self, id: VertexId) -> std::result::Result<Digest, Sg0Error> {
        Ok(Uint256::from_u64(self.lookup(id)?.candidate.header.work).to_be_bytes())
    }
    fn vertex_data(&self, id: VertexId) -> std::result::Result<Option<Sg0VertexDataV1>, Sg0Error> {
        Ok(self.lookup(id)?.metadata.clone())
    }
    fn visit_strict_past_ids(
        &self,
        id: VertexId,
        visitor: &mut dyn FnMut(VertexId) -> std::result::Result<(), Sg0Error>,
    ) -> std::result::Result<(), Sg0Error> {
        let bits = self.lookup(id)?.ancestors.materialize()?;
        for (i, v) in self.graph.vertices.iter().enumerate() {
            self.budget.graph_read()?;
            if bits.contains(i)? {
                visitor(VertexId::from_bytes(v.candidate.id))?;
            }
        }
        Ok(())
    }
    fn receiver_verified_is_ancestor(
        &self,
        a: VertexId,
        b: VertexId,
    ) -> std::result::Result<bool, Sg0Error> {
        self.lookup(a)?;
        let v = self.lookup(b)?;
        self.graph
            .index
            .get(&a)
            .map_or(Ok(false), |i| v.ancestors.contains(*i))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::carriage::{Body, Header};

    fn id(label: u8) -> VertexId {
        VertexId::from_bytes([label; 32])
    }

    // Synthetic receiver-view fixture ONLY. No work, proof or live admission
    // acceptance follows from these private test-only vertex constructions.
    fn synthetic_vertex(graph: &Graph, label: u8, labels: &[u8]) -> VerifiedVertex {
        let parents = if labels.is_empty() {
            Sg0ParentSetV1::Anchor
        } else {
            Sg0ParentSetV1::vertices(labels.iter().map(|n| id(*n)).collect()).unwrap()
        };
        let facts = ParentFacts {
            source_record: [0; 184],
            epoch: 0,
            daa: [0; 32],
            work: 1,
            minimum_time: 0,
            source_index: 0,
            source_checkpoint: [0; 32],
            source_j: [0; 32],
            seed: [0; 32],
            key_material: [0; 32],
        };
        VerifiedVertex {
            ancestors: graph.parent_closure(&parents).unwrap(),
            candidate: Candidate {
                id: id(label).into_bytes(),
                body: Body::new(&[9; 32], &[]).unwrap(),
                proof: [0; 52],
                header: Header {
                    bytes: [0; 592],
                    parents,
                    timestamp: u64::from(label),
                    epoch: 0,
                    daa: [0; 32],
                    work: 1,
                    source_index: 0,
                    source_checkpoint: [0; 32],
                    source_j: [0; 32],
                    seed: [0; 32],
                    owner: [0; 32],
                    reward_nonce: [0; 32],
                },
            },
            envelopes: Vec::new(),
            facts,
            metadata: None,
            retained_source: None,
        }
    }

    fn diamond(budget: &JobBudget) -> Graph {
        let mut graph = Graph::default();
        for (label, parents) in [(1, &[][..]), (2, &[1][..]), (3, &[1][..]), (4, &[2, 3][..])] {
            let vertex = synthetic_vertex(&graph, label, parents);
            let prepared = graph.seal(vertex, budget).unwrap();
            graph.publish(prepared).unwrap();
        }
        graph
    }
    fn source_graph(store: &mut crate::store::Store, budget: &JobBudget) -> Graph {
        let mut graph = Graph::default();
        graph
            .attach_ancestry_reader(store.object_reader().unwrap(), [9; 32])
            .unwrap();
        store
            .begin_replay(b"synthetic source export fixture")
            .unwrap();
        for (label, parents) in [(1, &[][..]), (2, &[1][..]), (3, &[1][..])] {
            let mut prepared = graph
                .seal(synthetic_vertex(&graph, label, parents), budget)
                .unwrap();
            let bytes = prepared.vertex().retained_record().unwrap();
            store
                .commit(&[&bytes], b"synthetic complete source head")
                .unwrap();
            prepared.retain_ancestry(&graph, store, budget).unwrap();
            prepared.bind_retained_source(&bytes).unwrap();
            graph.publish(prepared).unwrap();
        }
        graph
    }
    #[test]
    fn disk_source_export_exact_order_bounds_and_held_directory() {
        let (_temp, mut store) = crate::store::ancestry_test_store();
        let graph = source_graph(&mut store, &JobBudget::checkpoint().unwrap());
        let expected: Vec<_> = graph.vertices().map(|v| v.candidate().encode()).collect();
        assert_eq!(graph.export_retained_range(0, 32).unwrap(), expected);
        assert_eq!(graph.export_retained_range(1, 2).unwrap(), expected[1..]);
        assert!(graph.export_retained_range(3, 1).unwrap().is_empty());
        for (start, count) in [(0, 0), (0, 33), (4, 1), (usize::MAX, 1)] {
            assert!(graph.export_retained_range(start, count).is_err());
        }
        drop(store);
        assert_eq!(graph.export_retained_range(0, 32).unwrap(), expected);
    }
    #[test]
    fn disk_source_binding_requires_exact_sealed_bytes_without_mutation() {
        let budget = JobBudget::checkpoint().unwrap();
        let mut graph = Graph::default();
        let mut prepared = graph
            .seal(synthetic_vertex(&graph, 1, &[]), &budget)
            .unwrap();
        let bytes = prepared.vertex().retained_record().unwrap();
        let mut wrong = bytes.clone();
        *wrong.last_mut().unwrap() ^= 1;
        assert!(prepared.bind_retained_source(&wrong).is_err());
        assert!(prepared.vertex.retained_source.is_none());
        prepared.bind_retained_source(&bytes).unwrap();
        assert!(prepared.bind_retained_source(&bytes).is_err());
        graph.publish(prepared).unwrap();
        assert!(graph.export_retained_range(0, 1).is_err());
        let (_temp, store) = crate::store::ancestry_test_store();
        let mut graph = Graph::default();
        graph
            .attach_ancestry_reader(store.object_reader().unwrap(), [9; 32])
            .unwrap();
        let prepared = graph
            .seal(synthetic_vertex(&graph, 1, &[]), &budget)
            .unwrap();
        graph.publish(prepared).unwrap();
        assert!(graph.export_retained_range(0, 1).is_err());
    }
    #[test]
    fn disk_source_missing_tampered_and_hardlinked_objects_refuse_whole_range() {
        let (temp, mut store) = crate::store::ancestry_test_store();
        let graph = source_graph(&mut store, &JobBudget::checkpoint().unwrap());
        let expected = graph.export_retained_range(0, 3).unwrap();
        let source = graph
            .vertices
            .last()
            .unwrap()
            .retained_source
            .as_ref()
            .unwrap();
        let path = temp
            .path()
            .join("store")
            .join(format!("{}.obj", hex::encode(source.id)));
        let held = path.with_extension("held");
        std::fs::rename(&path, &held).unwrap();
        assert!(graph.export_retained_range(0, 3).is_err());
        assert_eq!(graph.len(), 3);
        std::fs::rename(&held, &path).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let mut wrong = bytes.clone();
        wrong[12] ^= 1;
        std::fs::write(&path, wrong).unwrap();
        assert!(graph.export_retained_range(0, 3).is_err());
        std::fs::write(&path, bytes).unwrap();
        std::fs::hard_link(&path, &held).unwrap();
        assert!(graph.export_retained_range(0, 3).is_err());
        std::fs::remove_file(&held).unwrap();
        assert_eq!(graph.export_retained_range(0, 3).unwrap(), expected);
    }
    #[test]
    fn disk_execution_resident_body_never_substitutes_missing_durable_source() {
        let (temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        let graph = source_graph(&mut store, &budget);
        assert_eq!(
            graph
                .get_for_execution(id(3), &budget)
                .unwrap()
                .candidate()
                .id,
            id(3).into_bytes()
        );
        let source = graph
            .vertices
            .last()
            .unwrap()
            .retained_source
            .as_ref()
            .unwrap();
        let path = temp
            .path()
            .join("store")
            .join(format!("{}.obj", hex::encode(source.id)));
        let held = path.with_extension("held");
        std::fs::rename(&path, &held).unwrap();
        assert!(graph.get_for_execution(id(3), &budget).is_err());
        assert!(graph.get(id(3)).is_ok());
        assert_eq!(graph.len(), 3);
        std::fs::rename(&held, &path).unwrap();
        assert!(graph.get_for_execution(id(3), &budget).is_ok());
        let resident = diamond(&budget);
        assert!(resident.get_for_execution(id(4), &budget).is_ok());
    }
    fn disk_diamond(store: &mut crate::store::Store, budget: &JobBudget) -> Graph {
        let mut graph = Graph::default();
        graph
            .attach_ancestry_reader(store.object_reader().unwrap(), [9; 32])
            .unwrap();
        for (label, parents) in [(1, &[][..]), (2, &[1][..]), (3, &[1][..]), (4, &[2, 3][..])] {
            let mut prepared = graph
                .seal(synthetic_vertex(&graph, label, parents), budget)
                .unwrap();
            prepared.retain_ancestry(&graph, store, budget).unwrap();
            graph.publish(prepared).unwrap();
        }
        graph
    }
    #[test]
    fn disk_ancestry_graph_order_parent_views_and_replay_rederive_exact_records() {
        let (temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        let head = store.commit(&[], b"synthetic original source").unwrap();
        let fence = store
            .begin_replay(b"synthetic full source rederivation")
            .unwrap();
        let flat = diamond(&budget);
        let graph = disk_diamond(&mut store, &budget);
        assert_eq!(graph.order(&budget).unwrap(), flat.order(&budget).unwrap());
        let parents = Sg0ParentSetV1::vertices(vec![id(2), id(3)]).unwrap();
        assert_eq!(
            graph.parent_order(&parents, &budget).unwrap(),
            flat.parent_order(&parents, &budget).unwrap()
        );
        assert_eq!(
            graph
                .vertices()
                .map(|v| v.retained_record().unwrap())
                .collect::<Vec<_>>(),
            flat.vertices()
                .map(|v| v.retained_record().unwrap())
                .collect::<Vec<_>>()
        );
        assert_eq!(graph.get(id(4)).unwrap().ancestors.retained_ids().len(), 1);
        store.finish_replay(fence).unwrap();
        drop(graph);
        drop(store);
        let margin = std::env::var_os("SILK_F04_HOST_MARGIN")
            .map_or_else(|| temp.path().to_path_buf(), std::path::PathBuf::from);
        let mut reopened = crate::store::Store::open(&temp.path().join("store"), &margin).unwrap();
        let fence = reopened
            .begin_replay(b"new synthetic source rederivation")
            .unwrap();
        let fresh = disk_diamond(&mut reopened, &budget);
        assert_eq!(fresh.order(&budget).unwrap(), flat.order(&budget).unwrap());
        assert_eq!(reopened.head(), Some(head));
        reopened.finish_replay(fence).unwrap();
    }
    #[test]
    fn disk_ancestry_graph_missing_past_refuses_without_false_or_head_fallback() {
        let (temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        let head = store.commit(&[], b"synthetic complete source").unwrap();
        store
            .begin_job(b"synthetic already-verified graph")
            .unwrap();
        let graph = disk_diamond(&mut store, &budget);
        let page = graph.get(id(3)).unwrap().ancestors.retained_ids()[0];
        std::fs::remove_file(
            temp.path()
                .join("store")
                .join(format!("{}.obj", hex::encode(page))),
        )
        .unwrap();
        let error = graph.is_ancestor(id(1), id(3)).unwrap_err();
        assert!(matches!(error, Error::Order(Sg0Error::Invariant)));
        assert!(!crate::node::storage_integrity_failure(&error));
        let view = View {
            graph: &graph,
            added: None,
            members: None,
            budget: &budget,
        };
        assert_eq!(
            view.receiver_verified_is_ancestor(id(1), id(3)),
            Err(Sg0Error::Invariant)
        );
        let mut visited = Vec::new();
        assert_eq!(
            view.visit_strict_past_ids(id(3), &mut |id| {
                visited.push(id);
                Ok(())
            }),
            Err(Sg0Error::Invariant)
        );
        assert!(visited.is_empty());
        assert!(
            graph
                .parent_order(&Sg0ParentSetV1::vertices(vec![id(3)]).unwrap(), &budget)
                .is_err()
        );
        assert_eq!(store.head(), Some(head));
    }

    #[test]
    fn paged_ancestry_graph_fork_merge_and_parent_views_are_exact() {
        let budget = JobBudget::checkpoint().unwrap();
        let graph = diamond(&budget);
        assert!(graph.is_ancestor(id(1), id(4)).unwrap());
        assert!(graph.is_ancestor(id(2), id(4)).unwrap());
        assert!(!graph.is_ancestor(id(2), id(3)).unwrap());
        assert!(!graph.is_ancestor(id(4), id(4)).unwrap());
        let parents = Sg0ParentSetV1::vertices(vec![id(2), id(3)]).unwrap();
        let members = graph.parent_closure(&parents).unwrap();
        let view = View {
            graph: &graph,
            added: None,
            members: Some(&members),
            budget: &budget,
        };
        let mut visible = Vec::new();
        view.visit_vertex_ids(&mut |v| {
            visible.push(v);
            Ok(())
        })
        .unwrap();
        assert_eq!(visible, vec![id(1), id(2), id(3)]);
        assert!(!view.receiver_verified_contains(id(4)).unwrap());
        let mut past = Vec::new();
        view.visit_strict_past_ids(id(3), &mut |v| {
            past.push(v);
            Ok(())
        })
        .unwrap();
        assert_eq!(past, vec![id(1)]);
        assert!(view.receiver_verified_is_ancestor(id(1), id(3)).unwrap());
        assert_eq!(
            view.receiver_verified_is_ancestor(id(4), id(3)),
            Err(Sg0Error::MissingVertex)
        );
        let comparable = Sg0ParentSetV1::vertices(vec![id(1), id(2)]).unwrap();
        assert!(matches!(
            graph.parent_closure(&comparable),
            Err(Error::Invalid("comparable parents"))
        ));
        assert!(
            graph
                .parent_closure(&Sg0ParentSetV1::vertices(vec![id(9)]).unwrap())
                .is_err()
        );
        let mut parent_order = graph
            .parent_order(&parents, &budget)
            .unwrap()
            .eligible_order()
            .to_vec();
        parent_order.sort_unstable();
        assert_eq!(parent_order, visible);
        let mut all_order = graph.order(&budget).unwrap().eligible_order().to_vec();
        all_order.sort_unstable();
        assert_eq!(all_order, vec![id(1), id(2), id(3), id(4)]);
    }

    #[test]
    fn paged_ancestry_graph_staging_and_clone_preserve_original_evidence() {
        let budget = JobBudget::checkpoint().unwrap();
        let original = diamond(&budget);
        let retained = original
            .vertices()
            .map(|v| v.retained_record().unwrap())
            .collect::<Vec<_>>();
        let mut branch = original.clone();
        let prepared = branch
            .seal(synthetic_vertex(&branch, 5, &[4]), &budget)
            .unwrap();
        let view = View {
            graph: &branch,
            added: Some(prepared.vertex()),
            members: None,
            budget: &budget,
        };
        let mut past = Vec::new();
        view.visit_strict_past_ids(id(5), &mut |v| {
            past.push(v);
            Ok(())
        })
        .unwrap();
        assert_eq!(past, vec![id(1), id(2), id(3), id(4)]);
        assert!(view.receiver_verified_is_ancestor(id(4), id(5)).unwrap());
        assert!(!view.receiver_verified_is_ancestor(id(5), id(5)).unwrap());
        let staged = branch.order_with(&prepared, &budget).unwrap();
        branch.publish(prepared).unwrap();
        assert_eq!(
            branch.order(&budget).unwrap().eligible_order(),
            staged.eligible_order()
        );
        assert!(branch.is_ancestor(id(4), id(5)).unwrap());
        assert_eq!(original.len(), 4);
        assert!(original.get(id(5)).is_err());
        assert_eq!(
            original
                .vertices()
                .map(|v| v.retained_record().unwrap())
                .collect::<Vec<_>>(),
            retained
        );
        assert!(!original.is_ancestor(id(4), id(4)).unwrap());
    }
}
