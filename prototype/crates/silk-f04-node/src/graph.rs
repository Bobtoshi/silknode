//! Receiver-owned full-data graph. No decoded peer object can construct validity.
use crate::{
    Digest, Error, Result,
    budget::{JobBudget, LocalClock},
    carriage::{Candidate, ParentFacts, WorkEngine},
    genesis::Genesis,
};
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
    ancestors: [u64; 64],
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
    /// Indexed receiver-verified evidence lookup.
    pub fn get(&self, id: VertexId) -> Result<&VerifiedVertex> {
        self.index
            .get(&id)
            .map(|i| self.vertices[*i].as_ref())
            .ok_or(Error::Unavailable("missing admitted vertex"))
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
    fn parent_closure(&self, parents: &Sg0ParentSetV1) -> Result<[u64; 64]> {
        if let Sg0ParentSetV1::Vertices(p) = parents {
            Sg0ParentSetV1::vertices(p.clone())?;
        }
        let mut bits = [0; 64];
        for p in parents.ordinary_parents() {
            let i = *self
                .index
                .get(p)
                .ok_or(Error::Unavailable("candidate parent dependency"))?;
            let v = &self.vertices[i];
            for (b, a) in bits.iter_mut().zip(v.ancestors) {
                *b |= a;
            }
            bits[i / 64] |= 1 << (i % 64);
        }
        if let [a, b] = parents.ordinary_parents() {
            if self.is_ancestor(*a, *b)? || self.is_ancestor(*b, *a)? {
                return Err(Error::Invalid("comparable parents"));
            }
        }
        Ok(bits)
    }
    pub(crate) fn is_ancestor(&self, a: VertexId, b: VertexId) -> Result<bool> {
        let ai = *self
            .index
            .get(&a)
            .ok_or(Error::Unavailable("missing ancestor"))?;
        Ok(self.get(b)?.ancestors[ai / 64] & (1 << (ai % 64)) != 0)
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
    members: Option<&'a [u64; 64]>,
    budget: &'a JobBudget,
}
impl View<'_> {
    fn lookup(&self, id: VertexId) -> std::result::Result<&VerifiedVertex, Sg0Error> {
        self.budget.graph_read()?;
        if let Some(v) = self.added.filter(|v| v.candidate.id == id.into_bytes()) {
            return Ok(v);
        }
        let i = *self.graph.index.get(&id).ok_or(Sg0Error::MissingVertex)?;
        if self
            .members
            .is_some_and(|bits| bits[i / 64] & (1 << (i % 64)) == 0)
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
                .is_none_or(|bits| bits[*i / 64] & (1 << (*i % 64)) != 0)
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
        let bits = &self.lookup(id)?.ancestors;
        for (i, v) in self.graph.vertices.iter().enumerate() {
            self.budget.graph_read()?;
            if bits[i / 64] & (1 << (i % 64)) != 0 {
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
        if let Some(i) = self.graph.index.get(&a) {
            Ok(v.ancestors[*i / 64] & (1 << (*i % 64)) != 0)
        } else {
            Ok(false)
        }
    }
}
