//! Receiver-owned full-data graph. No decoded peer object can construct validity.
mod ancestry;
mod index;
use crate::{
    Digest, Error, Result,
    budget::{JobBudget, LocalClock},
    carriage::{Candidate, Header, ParentFacts, WorkEngine},
    genesis::Genesis,
    wire::{raw_hash, u32le},
};
use ancestry::{PagedAncestry, RetainedContext};
use index::VertexIndex;
use silk_order::sg0_v1::{
    ReceiverVerifiedSg0Graph, Sg0Error, Sg0OrderSnapshotV1, Sg0ParentSetV1, Sg0VertexDataV1,
    budgeted::{derive_append_vertex_data_v1, derive_virtual_order_chain_fast_v1},
};
use silk_pow::Uint256;
use silk_sapling_f04::{
    codec::Envelope,
    crypto::{LiveRepresentationBinding, VerifiedEnvelope, verify_many},
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
    info: GraphInfo,
}
/// Immutable receiver-owned graph metadata. No public constructor or mutable fields.
#[derive(Clone)]
pub struct GraphInfo {
    id: Digest,
    header: HeaderRecord,
    facts: ParentFacts,
    metadata: Option<Metadata>,
    ancestors: PagedAncestry,
    retained_source: Option<RetainedSource>,
}
// Full headers are owned only by resident/execution carriers. Durable entries
// retain the minimum sealed SG0 summary plus exact representation binding.
#[derive(Clone)]
enum HeaderRecord {
    Resident(Arc<Header>),
    Retained {
        hash: Digest,
        domain: Digest,
        parents: Sg0ParentSetV1,
        work: u64,
    },
}
impl HeaderRecord {
    fn retain(&self) -> Self {
        match self {
            Self::Resident(header) => Self::Retained {
                hash: raw_hash(&header.bytes),
                domain: header.bytes[560..].try_into().expect("fixed header domain"),
                parents: header.parents.clone(),
                work: header.work,
            },
            Self::Retained { .. } => self.clone(),
        }
    }
    fn matches(&self, header: &Header) -> bool {
        match self {
            Self::Resident(original) => original.bytes == header.bytes,
            Self::Retained {
                hash,
                domain,
                parents,
                work,
            } => {
                raw_hash(&header.bytes) == *hash
                    && header.bytes[560..] == *domain
                    && header.parents == *parents
                    && header.work == *work
            }
        }
    }
    fn parents(&self) -> &Sg0ParentSetV1 {
        match self {
            Self::Resident(header) => &header.parents,
            Self::Retained { parents, .. } => parents,
        }
    }
    fn work(&self) -> u64 {
        match self {
            Self::Resident(header) => header.work,
            Self::Retained { work, .. } => *work,
        }
    }
}
// Only fresh receiver sealing creates Resident. Retained is a live binding to
// that same exact original record, never an imported saved-validity flag.
#[derive(Clone)]
enum Metadata {
    Resident(Arc<Sg0VertexDataV1>),
    Retained { len: usize },
}
impl GraphInfo {
    fn bound_metadata(&self, bytes: &[u8]) -> Result<Sg0VertexDataV1> {
        let Some(Metadata::Retained { len }) = self.metadata else {
            return Err(Error::Unavailable("unbound retained SG0 metadata"));
        };
        let source = self
            .retained_source
            .as_ref()
            .ok_or(Error::Unavailable("retained SG0 source absent"))?;
        let length_at = 12_usize
            .checked_add(source.candidate_len)
            .and_then(|end| end.checked_add(184))
            .ok_or(Error::Unavailable("retained SG0 framing"))?;
        let start = length_at
            .checked_add(4)
            .ok_or(Error::Unavailable("retained SG0 framing"))?;
        let end = start
            .checked_add(len)
            .ok_or(Error::Unavailable("retained SG0 framing"))?;
        if bytes.len() != source.record_len
            || raw_hash(bytes) != source.id
            || bytes.get(..8) != Some(b"SNF04VR1")
            || u32le(bytes, 8)? as usize != source.candidate_len
            || u32le(bytes, length_at)? as usize != len
            || end != bytes.len()
        {
            return Err(Error::Unavailable("retained SG0 original binding mismatch"));
        }
        let encoded = bytes
            .get(start..end)
            .ok_or(Error::Unavailable("retained SG0 framing"))?;
        // Structural decoding grants no authority: the live source binding was
        // created only after complete fresh derivation and full record equality.
        let metadata = Sg0VertexDataV1::decode_cache_untrusted_v1(encoded)?;
        if metadata.canonical_cache_bytes_v1()? != encoded {
            return Err(Error::Unavailable("retained SG0 canonical mismatch"));
        }
        Ok(metadata)
    }
    fn execution_info(&self, bytes: &[u8], header: &Header) -> Result<Self> {
        let mut info = self.clone();
        if !self.header.matches(header) {
            return Err(Error::Unavailable("retained execution header binding"));
        }
        info.header = HeaderRecord::Resident(Arc::new(header.clone()));
        if matches!(self.metadata, Some(Metadata::Retained { .. })) {
            info.metadata = Some(Metadata::Resident(Arc::new(self.bound_metadata(bytes)?)));
        }
        Ok(info)
    }
    fn load_metadata(
        &self,
        reader: Option<&Arc<RetainedContext>>,
        budget: &JobBudget,
    ) -> Result<Option<Sg0VertexDataV1>> {
        match &self.metadata {
            None => Ok(None),
            Some(Metadata::Resident(metadata)) => Ok(Some(metadata.as_ref().clone())),
            Some(Metadata::Retained { .. }) => {
                budget.check()?;
                budget.source()?;
                let source = self
                    .retained_source
                    .as_ref()
                    .ok_or(Error::Unavailable("retained SG0 source absent"))?;
                let reader = reader.ok_or(Error::Unavailable("retained SG0 reader absent"))?;
                let bytes = reader.objects().object(source.id, source.record_len)?;
                let metadata = self.bound_metadata(&bytes)?;
                budget.check()?;
                Ok(Some(metadata))
            }
        }
    }
}
mod sealed {
    pub trait Sealed {}
}
/// Sealed metadata view: decoding peer bytes cannot implement receiver authority.
pub trait GraphEntry: sealed::Sealed {
    /// Read-only metadata belonging to this already receiver-verified entry.
    fn graph_info(&self) -> &GraphInfo;
}
impl sealed::Sealed for VerifiedVertex {}
impl GraphEntry for VerifiedVertex {
    fn graph_info(&self) -> &GraphInfo {
        &self.info
    }
}
/// Internal node entry retains NO `Candidate`, `Body` or `VerifiedEnvelope` bytes.
pub(crate) struct RetainedVertex {
    info: GraphInfo,
    bindings: Vec<LiveRepresentationBinding>,
}
impl sealed::Sealed for RetainedVertex {}
impl GraphEntry for RetainedVertex {
    fn graph_info(&self) -> &GraphInfo {
        &self.info
    }
}
impl RetainedVertex {
    pub(crate) const fn id(&self) -> Digest {
        self.info.id
    }
    pub(crate) fn source_id(&self) -> Result<Digest> {
        self.info
            .retained_source
            .as_ref()
            .map(|s| s.id)
            .ok_or(Error::Unavailable("durable vertex source absent"))
    }
}
pub(crate) trait RetainEntry: GraphEntry + Sized {
    const DURABLE_INDEX: bool;
    fn retain(
        vertex: Arc<VerifiedVertex>,
        reader: Option<&Arc<RetainedContext>>,
    ) -> Result<Arc<Self>>;
    fn resident(vertex: &Arc<Self>) -> Option<Arc<VerifiedVertex>>;
    fn restore(&self, candidate: Candidate, record: &[u8]) -> Result<VerifiedVertex>;
}
impl RetainEntry for VerifiedVertex {
    const DURABLE_INDEX: bool = false;
    fn retain(vertex: Arc<VerifiedVertex>, _: Option<&Arc<RetainedContext>>) -> Result<Arc<Self>> {
        Ok(vertex)
    }
    fn resident(vertex: &Arc<Self>) -> Option<Arc<VerifiedVertex>> {
        Some(vertex.clone())
    }
    fn restore(&self, candidate: Candidate, record: &[u8]) -> Result<VerifiedVertex> {
        if candidate.encode() != self.candidate.encode() {
            return Err(Error::Unavailable(
                "live verified execution source mismatch",
            ));
        }
        let info = self.info.execution_info(record, &candidate.header)?;
        Ok(Self {
            candidate,
            envelopes: self.envelopes.clone(),
            info,
        })
    }
}
impl RetainEntry for RetainedVertex {
    const DURABLE_INDEX: bool = true;
    fn retain(
        vertex: Arc<VerifiedVertex>,
        reader: Option<&Arc<RetainedContext>>,
    ) -> Result<Arc<Self>> {
        if reader.is_none()
            || vertex.info.retained_source.is_none()
            || vertex.info.metadata.is_none()
        {
            return Err(Error::Unavailable(
                "durable vertex requires complete live source binding",
            ));
        }
        let vertex = Arc::try_unwrap(vertex)
            .map_err(|_| Error::Unavailable("shared durable vertex body publication"))?;
        let Some(Metadata::Resident(metadata)) = &vertex.info.metadata else {
            return Err(Error::Unavailable("unsealed durable SG0 metadata"));
        };
        let metadata_len = metadata.canonical_cache_bytes_v1()?.len();
        let bindings = vertex
            .envelopes
            .iter()
            .map(VerifiedEnvelope::live_representation_binding)
            .collect();
        let mut info = vertex.info;
        info.metadata = Some(Metadata::Retained { len: metadata_len });
        info.header = info.header.retain();
        // Candidate, full envelopes AND sealed SG0 data drop before graph credit.
        Ok(Arc::new(Self { info, bindings }))
    }
    fn resident(_: &Arc<Self>) -> Option<Arc<VerifiedVertex>> {
        None
    }
    fn restore(&self, candidate: Candidate, record: &[u8]) -> Result<VerifiedVertex> {
        if candidate.id != self.info.id
            || !self.info.header.matches(&candidate.header)
            || candidate.body.representations().len() != self.bindings.len()
        {
            return Err(Error::Unavailable("durable execution metadata mismatch"));
        }
        let envelopes = candidate
            .body
            .representations()
            .iter()
            .zip(&self.bindings)
            .map(|(bytes, binding)| {
                binding
                    .reattach(Envelope::decode(
                        bytes,
                        &candidate.header.bytes[560..]
                            .try_into()
                            .map_err(|_| Error::Unavailable("durable vertex domain"))?,
                    )?)
                    .map_err(Error::from)
            })
            .collect::<Result<Vec<_>>>()?;
        let info = self.info.execution_info(record, &candidate.header)?;
        Ok(VerifiedVertex {
            candidate,
            envelopes,
            info,
        })
    }
}
/// Live receiver-derived source binding, never serialized or imported as validity.
#[derive(Clone)]
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
        &self.info.facts
    }
    pub(crate) fn retained_record(&self) -> Result<Vec<u8>> {
        let bytes = self.candidate.encode();
        let Some(Metadata::Resident(metadata)) = &self.info.metadata else {
            return Err(Error::Unavailable("unsealed vertex metadata"));
        };
        let metadata = metadata.canonical_cache_bytes_v1()?;
        let mut b = Vec::new();
        b.extend_from_slice(b"SNF04VR1");
        b.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        b.extend_from_slice(&bytes);
        b.extend_from_slice(&self.info.facts.source_record);
        b.extend_from_slice(&(metadata.len() as u32).to_le_bytes());
        b.extend_from_slice(&metadata);
        Ok(b)
    }
}

/// Append-only admitted red/blue evidence, within the explicit 4,096-vertex horizon.
pub type Graph = GraphData<VerifiedVertex>;
pub(crate) type DurableGraph = GraphData<RetainedVertex>;
/// Shared graph/order machinery; the public Graph alias preserves resident borrows.
pub struct GraphData<V> {
    vertices: Vec<Arc<V>>,
    index: VertexIndex,
    ancestry_reader: Option<Arc<RetainedContext>>,
}
impl<V> Default for GraphData<V> {
    fn default() -> Self {
        Self {
            vertices: Vec::new(),
            index: VertexIndex::default(),
            ancestry_reader: None,
        }
    }
}
impl<V> Clone for GraphData<V> {
    fn clone(&self) -> Self {
        Self {
            vertices: self.vertices.clone(),
            index: self.index.clone(),
            ancestry_reader: self.ancestry_reader.clone(),
        }
    }
}

/// Prepared atomic graph insertion, not visible until durable publication succeeds.
pub(crate) struct PreparedVertex {
    vertex: Arc<VerifiedVertex>,
    revision: usize,
    index: Option<VertexIndex>,
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
        if vertex.info.retained_source.is_some() || vertex.retained_record()? != bytes {
            return Err(Error::Unavailable("retained source binding mismatch"));
        }
        vertex.info.retained_source = Some(RetainedSource {
            id: raw_hash(bytes),
            record_len: bytes.len(),
            candidate_len: u32le(bytes, 8)? as usize,
        });
        Ok(())
    }
    pub(crate) fn retain_ancestry<V: RetainEntry>(
        &mut self,
        graph: &GraphData<V>,
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
            .info
            .ancestors
            .retain(store, reader.clone(), budget)?;
        if V::DURABLE_INDEX {
            if self.revision != graph.len() {
                return Err(Error::Unavailable("stale staged vertex index"));
            }
            let mut rows = graph.index.materialize(Some(budget))?;
            if rows
                .insert(VertexId::from_bytes(self.vertex.info.id), graph.len())
                .is_some()
            {
                return Err(Error::Unavailable("duplicate staged vertex index"));
            }
            self.index = Some(VertexIndex::retain(&rows, store, reader.domain(), budget)?);
        }
        Ok(())
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

impl<V: GraphEntry> GraphData<V> {
    #[cfg(test)]
    pub(crate) fn retained_ancestry_pages(&self) -> usize {
        self.vertices
            .iter()
            .map(|v| v.graph_info().ancestors.retained_ids().len())
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
    pub fn vertices(&self) -> impl Iterator<Item = &V> {
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
                    .graph_info()
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
    /// # Errors
    /// Refuses an identifier absent from this receiver's admitted graph.
    pub fn get(&self, id: VertexId) -> Result<&V> {
        self.get_checked(id, None)
    }
    pub(crate) fn find_checked(&self, id: VertexId, budget: &JobBudget) -> Result<Option<&V>> {
        let Some(position) = self.index.lookup(&id, Some(budget))? else {
            return Ok(None);
        };
        let vertex = self
            .vertices
            .get(position)
            .ok_or(Error::Unavailable("vertex index position mismatch"))?;
        if vertex.graph_info().id != id.into_bytes() {
            return Err(Error::Unavailable("vertex index identity mismatch"));
        }
        Ok(Some(vertex.as_ref()))
    }
    #[cfg(test)]
    pub(crate) fn retained_index_pages(&self) -> Vec<Digest> {
        self.index.retained_ids()
    }
    fn position(&self, id: VertexId, budget: Option<&JobBudget>) -> Result<usize> {
        let position = self
            .index
            .lookup(&id, budget)?
            .ok_or(Error::Unavailable("missing admitted vertex"))?;
        if self
            .vertices
            .get(position)
            .is_none_or(|vertex| vertex.graph_info().id != id.into_bytes())
        {
            return Err(Error::Unavailable("vertex index identity mismatch"));
        }
        Ok(position)
    }
    fn get_checked(&self, id: VertexId, budget: Option<&JobBudget>) -> Result<&V> {
        Ok(self.vertices[self.position(id, budget)?].as_ref())
    }
    pub(crate) fn header(
        &self,
        id: VertexId,
        genesis: &Genesis,
        budget: &JobBudget,
    ) -> Result<Arc<Header>> {
        budget.check()?;
        let info = self.get_checked(id, Some(budget))?.graph_info();
        if let HeaderRecord::Resident(header) = &info.header {
            return Ok(header.clone());
        }
        let source = info
            .retained_source
            .as_ref()
            .ok_or(Error::Unavailable("retained header source absent"))?;
        let reader = self
            .ancestry_reader
            .as_ref()
            .ok_or(Error::Unavailable("retained header reader absent"))?;
        budget.source()?;
        let bytes = reader.objects().object(source.id, source.record_len)?;
        let end = 12_usize
            .checked_add(source.candidate_len)
            .ok_or(Error::Unavailable("retained header candidate length"))?;
        if bytes.len() != source.record_len
            || bytes.get(..8) != Some(b"SNF04VR1")
            || u32le(&bytes, 8)? as usize != source.candidate_len
        {
            return Err(Error::Unavailable("retained header source framing"));
        }
        let candidate = Candidate::decode(
            bytes
                .get(12..end)
                .ok_or(Error::Unavailable("retained header candidate framing"))?,
            genesis,
        )?;
        if candidate.id != info.id || !info.header.matches(&candidate.header) {
            return Err(Error::Unavailable(
                "retained header representation mismatch",
            ));
        }
        budget.check()?;
        Ok(Arc::new(candidate.header))
    }
    pub(crate) fn retained_candidate_matches(&self, id: VertexId, expected: &[u8]) -> Result<bool> {
        let info = self.get(id)?.graph_info();
        let source = info
            .retained_source
            .as_ref()
            .ok_or(Error::Unavailable("durable vertex source absent"))?;
        let reader = self
            .ancestry_reader
            .as_ref()
            .ok_or(Error::Unavailable("durable vertex reader absent"))?;
        let bytes = reader.objects().object(source.id, source.record_len)?;
        let end = 12_usize
            .checked_add(source.candidate_len)
            .ok_or(Error::Unavailable("durable candidate length"))?;
        Ok(bytes
            .get(12..end)
            .ok_or(Error::Unavailable("durable candidate framing"))?
            == expected)
    }
    /// Owned execution body loaded from exact durable bytes. This is NOT new
    /// admission: the complete candidate must equal this live receiver's already
    /// verified candidate before its existing typed crypto capabilities are used.
    /// Cold reopen still performs the original complete fresh verification.
    pub(crate) fn load_for_execution(
        &self,
        id: VertexId,
        genesis: &Genesis,
        budget: &JobBudget,
    ) -> Result<Arc<VerifiedVertex>>
    where
        V: RetainEntry,
    {
        budget.check()?;
        let index = self.position(id, Some(budget))?;
        let vertex = &self.vertices[index];
        let Some(reader) = &self.ancestry_reader else {
            return V::resident(vertex).ok_or(Error::Unavailable("durable vertex reader absent"));
        };
        let source = vertex
            .graph_info()
            .retained_source
            .as_ref()
            .ok_or(Error::Unavailable("verified durable source binding absent"))?;
        budget.source()?;
        let bytes = reader.objects().object(source.id, source.record_len)?;
        let end = 12_usize
            .checked_add(source.candidate_len)
            .ok_or(Error::Unavailable("retained execution length"))?;
        if bytes.len() != source.record_len
            || bytes.get(..8) != Some(b"SNF04VR1")
            || u32le(&bytes, 8)? as usize != source.candidate_len
        {
            return Err(Error::Unavailable("retained execution framing"));
        }
        let candidate = Candidate::decode(
            bytes
                .get(12..end)
                .ok_or(Error::Unavailable("retained execution candidate"))?,
            genesis,
        )?;
        let restored = vertex.restore(candidate, &bytes)?;
        budget.check()?;
        Ok(Arc::new(restored))
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
            added: Some(&prepared.vertex.info),
            members: None,
            budget,
        })?)
    }
    pub(crate) fn parent_order(
        &self,
        parents: &Sg0ParentSetV1,
        budget: &JobBudget,
    ) -> Result<Sg0OrderSnapshotV1> {
        let bits = self.parent_closure_checked(parents, Some(budget))?;
        Ok(derive_virtual_order_chain_fast_v1(&View {
            graph: self,
            added: None,
            members: Some(&bits),
            budget,
        })?)
    }
    #[cfg(test)]
    fn parent_closure(&self, parents: &Sg0ParentSetV1) -> Result<PagedAncestry> {
        self.parent_closure_checked(parents, None)
    }
    fn parent_closure_checked(
        &self,
        parents: &Sg0ParentSetV1,
        budget: Option<&JobBudget>,
    ) -> Result<PagedAncestry> {
        if let Sg0ParentSetV1::Vertices(p) = parents {
            Sg0ParentSetV1::vertices(p.clone())?;
        }
        let mut bits = PagedAncestry::default();
        for p in parents.ordinary_parents() {
            let i = self.position(*p, budget)?;
            let v = self.vertices[i].graph_info();
            bits.union(&v.ancestors)?;
            bits.insert(i)?;
        }
        if let [a, b] = parents.ordinary_parents()
            && (self.is_ancestor_checked(*a, *b, budget)?
                || self.is_ancestor_checked(*b, *a, budget)?)
        {
            return Err(Error::Invalid("comparable parents"));
        }
        Ok(bits)
    }
    #[cfg(test)]
    pub(crate) fn is_ancestor(&self, a: VertexId, b: VertexId) -> Result<bool> {
        self.is_ancestor_checked(a, b, None)
    }
    pub(crate) fn is_ancestor_checked(
        &self,
        a: VertexId,
        b: VertexId,
        budget: Option<&JobBudget>,
    ) -> Result<bool> {
        let ai = self.position(a, budget)?;
        Ok(self
            .get_checked(b, budget)?
            .graph_info()
            .ancestors
            .contains(ai)?)
    }

    /// Only freshly decoded canonical bytes enter the validity pipeline.
    /// `clock=None` is crate-private and reserved for authenticated local archive replay.
    pub(crate) fn decode_candidate(
        &self,
        bytes: &[u8],
        g: &Genesis,
        clock: Option<&LocalClock>,
        budget: &JobBudget,
    ) -> Result<Candidate> {
        if self.len() >= 4096 {
            return Err(Error::Paused("admitted-vertex reference horizon"));
        }
        let candidate = Candidate::decode(bytes, g)?;
        let id = VertexId::from_bytes(candidate.id);
        if self.index.lookup(&id, Some(budget))?.is_some() {
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
            info: GraphInfo {
                id: candidate.id,
                header: HeaderRecord::Resident(Arc::new(candidate.header.clone())),
                facts,
                ancestors: self.parent_closure_checked(&candidate.header.parents, Some(budget))?,
                metadata: None,
                retained_source: None,
            },
            candidate,
            envelopes: envelopes
                .into_iter()
                .map(|v| v.expect("complete exact verification"))
                .collect(),
        })
    }
    pub(crate) fn seal(
        &self,
        mut vertex: VerifiedVertex,
        budget: &JobBudget,
    ) -> Result<PreparedVertex> {
        let id = VertexId::from_bytes(vertex.candidate.id);
        vertex.info.metadata = Some(Metadata::Resident(Arc::new(
            derive_append_vertex_data_v1(
                &View {
                    graph: self,
                    added: Some(&vertex.info),
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
        )));
        budget.check()?;
        Ok(PreparedVertex {
            vertex: Arc::new(vertex),
            revision: self.len(),
            index: None,
        })
    }
    #[cfg(test)]
    pub(crate) fn publish(&mut self, prepared: PreparedVertex) -> Result<()>
    where
        V: RetainEntry,
    {
        self.publish_checked(prepared, &JobBudget::checkpoint()?)
    }
    pub(crate) fn publish_checked(
        &mut self,
        prepared: PreparedVertex,
        budget: &JobBudget,
    ) -> Result<()>
    where
        V: RetainEntry,
    {
        budget.check()?;
        if prepared.revision != self.len()
            || self
                .index
                .lookup(
                    &VertexId::from_bytes(prepared.vertex.candidate.id),
                    Some(budget),
                )?
                .is_some()
        {
            return Err(Error::Unavailable("stale graph publication"));
        }
        let id = VertexId::from_bytes(prepared.vertex.candidate.id);
        // Finish every fallible page read before publishing any graph credit.
        let next_index = if V::DURABLE_INDEX {
            let next = prepared
                .index
                .ok_or(Error::Unavailable("durable vertex index absent"))?;
            let rows = next.materialize(Some(budget))?;
            if rows.len() != self.len() + 1 || rows.get(&id) != Some(&self.len()) {
                return Err(Error::Unavailable("staged vertex index length"));
            }
            for (position, vertex) in self.vertices.iter().enumerate() {
                budget.graph_read()?;
                if rows.get(&VertexId::from_bytes(vertex.graph_info().id)) != Some(&position) {
                    return Err(Error::Unavailable("staged vertex index identity"));
                }
            }
            next
        } else {
            let mut rows = self.index.materialize(Some(budget))?;
            rows.insert(id, self.len());
            VertexIndex::Resident(Arc::new(rows))
        };
        budget.check()?;
        let entry = V::retain(prepared.vertex, self.ancestry_reader.as_ref())?;
        self.index = next_index;
        self.vertices.push(entry);
        Ok(())
    }
}

// Each view exposes ONLY admitted evidence plus, privately, one already fully
// verified candidate. Ancestry is derived on insert from immutable parent closure.
struct View<'a, V> {
    graph: &'a GraphData<V>,
    added: Option<&'a GraphInfo>,
    members: Option<&'a PagedAncestry>,
    budget: &'a JobBudget,
}
impl<V: GraphEntry> View<'_, V> {
    fn lookup(&self, id: VertexId) -> std::result::Result<&GraphInfo, Sg0Error> {
        self.budget.graph_read()?;
        if let Some(v) = self.added.filter(|v| v.id == id.into_bytes()) {
            return Ok(v);
        }
        let i = self
            .graph
            .index
            .lookup(&id, Some(self.budget))
            .map_err(index_error)?
            .ok_or(Sg0Error::MissingVertex)?;
        if self
            .graph
            .vertices
            .get(i)
            .is_none_or(|vertex| vertex.graph_info().id != id.into_bytes())
        {
            return Err(Sg0Error::Invariant);
        }
        if let Some(bits) = self.members
            && !bits.contains(i)?
        {
            return Err(Sg0Error::MissingVertex);
        }
        Ok(self.graph.vertices[i].graph_info())
    }
}
impl<V: GraphEntry> ReceiverVerifiedSg0Graph for View<'_, V> {
    fn visit_vertex_ids(
        &self,
        visitor: &mut dyn FnMut(VertexId) -> std::result::Result<(), Sg0Error>,
    ) -> std::result::Result<(), Sg0Error> {
        let rows = self
            .graph
            .index
            .materialize(Some(self.budget))
            .map_err(index_error)?;
        for (id, i) in &rows {
            self.budget.graph_read()?;
            if self
                .graph
                .vertices
                .get(*i)
                .is_none_or(|vertex| vertex.graph_info().id != id.into_bytes())
            {
                return Err(Sg0Error::Invariant);
            }
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
            visitor(VertexId::from_bytes(v.id))?;
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
        Ok(self.lookup(id)?.header.parents().clone())
    }
    fn receiver_verified_work_be(&self, id: VertexId) -> std::result::Result<Digest, Sg0Error> {
        Ok(Uint256::from_u64(self.lookup(id)?.header.work()).to_be_bytes())
    }
    fn vertex_data(&self, id: VertexId) -> std::result::Result<Option<Sg0VertexDataV1>, Sg0Error> {
        self.lookup(id)?
            .load_metadata(self.graph.ancestry_reader.as_ref(), self.budget)
            .map_err(|error| match error {
                Error::Order(error) => error,
                Error::Paused(_) => Sg0Error::ResourceBudget,
                _ => Sg0Error::Invariant,
            })
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
                visitor(VertexId::from_bytes(v.graph_info().id))?;
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
        // The one sealed candidate has no admitted ordinal yet. It cannot be
        // in an existing vertex's strict past, or in its own strict past.
        if self.added.is_some_and(|added| added.id == a.into_bytes()) {
            return Ok(false);
        }
        self.graph
            .index
            .lookup(&a, Some(self.budget))
            .map_err(index_error)?
            .map_or(Err(Sg0Error::Invariant), |i| v.ancestors.contains(i))
    }
}

fn index_error(error: Error) -> Sg0Error {
    match error {
        Error::Order(error) => error,
        Error::Paused(_) => Sg0Error::ResourceBudget,
        _ => Sg0Error::Invariant,
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
    fn synthetic_vertex<V: GraphEntry>(
        graph: &GraphData<V>,
        label: u8,
        labels: &[u8],
    ) -> VerifiedVertex {
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
        let ancestors = graph.parent_closure(&parents).unwrap();
        let candidate = Candidate {
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
        };
        VerifiedVertex {
            info: GraphInfo {
                id: candidate.id,
                header: HeaderRecord::Resident(Arc::new(candidate.header.clone())),
                facts,
                ancestors,
                metadata: None,
                retained_source: None,
            },
            candidate,
            envelopes: Vec::new(),
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
    fn disk_order_staged_source_missing_refuses_core_graph_credit() {
        // Private synthetic publication fixture only; never native admission.
        use crate::core::{
            Admission, Core, Status,
            order::{CoreOrder, snapshot_bytes},
        };
        let (temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        let mut core = Core::new(
            Arc::new(crate::genesis::public_testnet_v1::genesis().unwrap()),
            LocalClock::default(),
        )
        .unwrap();
        core.graph
            .attach_ancestry_reader(store.object_reader().unwrap(), [9; 32])
            .unwrap();
        store
            .begin_replay(b"synthetic order publication fence")
            .unwrap();
        let mut vertex = core
            .graph
            .seal(synthetic_vertex(&core.graph, 1, &[]), &budget)
            .unwrap();
        let order = core.graph.order_with(&vertex, &budget).unwrap();
        let record = vertex.vertex().retained_record().unwrap();
        let original = snapshot_bytes(&order);
        store
            .commit(
                &[&record, &original],
                b"synthetic complete original records",
            )
            .unwrap();
        vertex.bind_retained_source(&record).unwrap();
        vertex
            .retain_ancestry(&core.graph, &mut store, &budget)
            .unwrap();
        let retained = CoreOrder::retain(&order, store.object_reader().unwrap(), &budget).unwrap();
        let path = temp
            .path()
            .join("store")
            .join(format!("{}.obj", hex::encode(raw_hash(&original))));
        std::fs::rename(&path, path.with_extension("held")).unwrap();
        let manifest = core.state.manifest();
        let head = store.head();
        let old_order = core.order.bytes(&budget).unwrap();
        assert!(matches!(
            core.publish(Admission {
                vertex,
                order,
                retained_order: Some(retained),
                status: Status::Ready,
                budget
            }),
            Err(Error::Io(_))
        ));
        assert_eq!(core.graph.len(), 0);
        assert!(core.graph.get(id(1)).is_err());
        assert_eq!(core.state.manifest(), manifest);
        assert_eq!(core.status, Status::Ready);
        assert_eq!(
            core.order.bytes(&JobBudget::checkpoint().unwrap()).unwrap(),
            old_order
        );
        assert_eq!(store.head(), head);
    }
    #[test]
    fn disk_order_retention_drops_both_snapshot_vectors_and_preserves_original_order_bytes() {
        use crate::core::order::{CoreOrder, snapshot_bytes};
        let (_temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        let snapshot = Arc::new(diamond(&budget).order(&budget).unwrap());
        let weak = Arc::downgrade(&snapshot);
        let original = snapshot_bytes(&snapshot);
        let ids = snapshot.eligible_order().to_vec();
        let selected = snapshot.selected_tip();
        store
            .commit(&[&original], b"synthetic original order record")
            .unwrap();
        let retained =
            CoreOrder::retain(&snapshot, store.object_reader().unwrap(), &budget).unwrap();
        assert_eq!(retained.retained_id(), Some(raw_hash(&original)));
        drop(snapshot);
        assert!(weak.upgrade().is_none());
        assert_eq!(retained.bytes(&budget).unwrap(), original);
        assert_eq!(retained.eligible(&budget).unwrap(), ids);
        assert_eq!(retained.selected_tip(), selected);
        assert_eq!(retained.clone().bytes(&budget).unwrap(), original);
    }
    #[test]
    fn disk_order_missing_tampered_hardlinked_original_refuses_all_owned_reads() {
        use crate::core::order::{CoreOrder, snapshot_bytes};
        let (temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        let snapshot = diamond(&budget).order(&budget).unwrap();
        let original = snapshot_bytes(&snapshot);
        assert!(CoreOrder::retain(&snapshot, store.object_reader().unwrap(), &budget).is_err());
        store
            .commit(&[&original], b"synthetic original order record")
            .unwrap();
        let retained =
            CoreOrder::retain(&snapshot, store.object_reader().unwrap(), &budget).unwrap();
        let path = temp
            .path()
            .join("store")
            .join(format!("{}.obj", hex::encode(raw_hash(&original))));
        let held = path.with_extension("held");
        std::fs::rename(&path, &held).unwrap();
        assert!(matches!(retained.bytes(&budget), Err(Error::Io(_))));
        assert!(retained.eligible(&budget).is_err());
        assert!(CoreOrder::retain(&snapshot, store.object_reader().unwrap(), &budget).is_err());
        std::fs::rename(&held, &path).unwrap();
        let mut changed = original.clone();
        *changed.last_mut().unwrap() ^= 1;
        std::fs::write(&path, changed).unwrap();
        assert!(retained.eligible(&budget).is_err());
        std::fs::write(&path, &original).unwrap();
        std::fs::hard_link(&path, &held).unwrap();
        assert!(retained.bytes(&budget).is_err());
        std::fs::remove_file(&held).unwrap();
        std::fs::rename(temp.path().join("store"), temp.path().join("original")).unwrap();
        std::fs::create_dir(temp.path().join("store")).unwrap();
        assert_eq!(retained.bytes(&budget).unwrap(), original);
        let expired = JobBudget::testing(std::time::Duration::ZERO).unwrap();
        assert!(retained.eligible(&expired).is_err());
    }
    #[test]
    fn disk_index_graph_missing_current_or_staged_page_refuses_without_partial_credit() {
        let (temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        let mut graph = DurableGraph::default();
        graph
            .attach_ancestry_reader(store.object_reader().unwrap(), [9; 32])
            .unwrap();
        store
            .begin_replay(b"synthetic index publication fixture")
            .unwrap();
        for (label, parents) in [(1, &[][..]), (2, &[1][..]), (3, &[1][..])] {
            let mut prepared = graph
                .seal(synthetic_vertex(&graph, label, parents), &budget)
                .unwrap();
            let record = prepared.vertex().retained_record().unwrap();
            store
                .commit(&[&record], b"synthetic original record")
                .unwrap();
            prepared.bind_retained_source(&record).unwrap();
            prepared
                .retain_ancestry(&graph, &mut store, &budget)
                .unwrap();
            graph.publish_checked(prepared, &budget).unwrap();
        }
        assert!(matches!(graph.index, VertexIndex::Retained(_)));
        let fork = graph.clone();
        let order = graph.order(&budget).unwrap();
        let current = graph.retained_index_pages()[0];
        let mut prepared = graph
            .seal(synthetic_vertex(&graph, 4, &[2, 3]), &budget)
            .unwrap();
        let record = prepared.vertex().retained_record().unwrap();
        store
            .commit(&[&record], b"synthetic fourth original record")
            .unwrap();
        prepared.bind_retained_source(&record).unwrap();
        prepared
            .retain_ancestry(&graph, &mut store, &budget)
            .unwrap();
        let staged = prepared.index.as_ref().unwrap().retained_ids()[0];
        assert_ne!(staged, current);
        let path = temp
            .path()
            .join("store")
            .join(format!("{}.obj", hex::encode(staged)));
        let held = path.with_extension("held");
        std::fs::rename(&path, &held).unwrap();
        let head = store.head();
        assert!(matches!(
            graph.publish_checked(prepared, &budget),
            Err(Error::Io(_))
        ));
        assert_eq!(graph.len(), 3);
        assert_eq!(graph.retained_index_pages(), vec![current]);
        assert_eq!(graph.order(&budget).unwrap(), order);
        std::fs::rename(&held, &path).unwrap();
        let mut prepared = graph
            .seal(synthetic_vertex(&graph, 4, &[2, 3]), &budget)
            .unwrap();
        prepared.bind_retained_source(&record).unwrap();
        let path = temp
            .path()
            .join("store")
            .join(format!("{}.obj", hex::encode(current)));
        let held = path.with_extension("held");
        std::fs::rename(&path, &held).unwrap();
        assert!(matches!(graph.get(id(2)), Err(Error::Io(_))));
        assert!(graph.find_checked(id(2), &budget).is_err());
        assert!(graph.order(&budget).is_err());
        assert!(
            graph
                .parent_order(
                    &Sg0ParentSetV1::vertices(vec![id(2), id(3)]).unwrap(),
                    &budget
                )
                .is_err()
        );
        assert!(graph.is_ancestor(id(1), id(3)).is_err());
        assert!(
            prepared
                .retain_ancestry(&graph, &mut store, &budget)
                .is_err()
        );
        assert_eq!(graph.len(), 3);
        assert_eq!(store.head(), head);
        std::fs::rename(&held, &path).unwrap();
        prepared
            .retain_ancestry(&graph, &mut store, &budget)
            .unwrap();
        graph.publish_checked(prepared, &budget).unwrap();
        assert_eq!(
            graph.order(&budget).unwrap(),
            diamond(&budget).order(&budget).unwrap()
        );
        assert_eq!(fork.order(&budget).unwrap(), order);
        assert_eq!(fork.retained_index_pages(), vec![current]);
    }
    #[test]
    fn disk_detach_graph_drops_published_carriers_and_preserves_exact_metadata_order_and_sources() {
        let (_temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        let resident = diamond(&budget);
        let mut durable = DurableGraph::default();
        durable
            .attach_ancestry_reader(store.object_reader().unwrap(), [9; 32])
            .unwrap();
        store
            .begin_replay(b"synthetic compact graph fixture")
            .unwrap();
        let mut originals = Vec::new();
        for (label, parents) in [(1, &[][..]), (2, &[1][..]), (3, &[1][..]), (4, &[2, 3][..])] {
            let mut prepared = durable
                .seal(synthetic_vertex(&durable, label, parents), &budget)
                .unwrap();
            let record = prepared.vertex().retained_record().unwrap();
            originals.push(prepared.vertex().candidate().encode());
            store
                .commit(&[&record], b"synthetic complete original source")
                .unwrap();
            prepared
                .retain_ancestry(&durable, &mut store, &budget)
                .unwrap();
            prepared.bind_retained_source(&record).unwrap();
            let weak_body = Arc::downgrade(&prepared.vertex);
            let weak_header = match &prepared.vertex.info.header {
                HeaderRecord::Resident(header) => Arc::downgrade(header),
                HeaderRecord::Retained { .. } => panic!("fresh sealing must own full header"),
            };
            let weak_metadata = match &prepared.vertex.info.metadata {
                Some(Metadata::Resident(metadata)) => Arc::downgrade(metadata),
                _ => panic!("fresh sealing must own receiver-derived metadata"),
            };
            durable.publish(prepared).unwrap();
            assert!(weak_body.upgrade().is_none());
            assert!(weak_header.upgrade().is_none());
            assert!(weak_metadata.upgrade().is_none());
        }
        assert_eq!(
            durable.order(&budget).unwrap(),
            resident.order(&budget).unwrap()
        );
        let parents = Sg0ParentSetV1::vertices(vec![id(2), id(3)]).unwrap();
        assert_eq!(
            durable.parent_order(&parents, &budget).unwrap(),
            resident.parent_order(&parents, &budget).unwrap()
        );
        assert_eq!(durable.export_retained_range(0, 32).unwrap(), originals);
        assert_eq!(
            durable.is_ancestor(id(1), id(4)).unwrap(),
            resident.is_ancestor(id(1), id(4)).unwrap()
        );
        assert!(durable.vertices().all(|v| v.bindings.is_empty()));
        assert!(
            durable
                .vertices()
                .all(|v| matches!(v.info.header, HeaderRecord::Retained { .. }))
        );
        assert!(
            durable
                .vertices()
                .all(|v| matches!(v.info.metadata, Some(Metadata::Retained { .. })))
        );
        assert!(matches!(durable.index, VertexIndex::Retained(_)));
        let retained_view = View {
            graph: &durable,
            added: None,
            members: None,
            budget: &budget,
        };
        let resident_view = View {
            graph: &resident,
            added: None,
            members: None,
            budget: &budget,
        };
        for label in 1..=4 {
            assert_eq!(
                retained_view.vertex_data(id(label)).unwrap(),
                resident_view.vertex_data(id(label)).unwrap()
            );
        }
        drop(store);
        assert_eq!(durable.export_retained_range(0, 32).unwrap(), originals);
    }
    #[test]
    fn disk_header_binding_is_exact_and_keeps_only_immutable_sg0_summary() {
        let graph = Graph::default();
        let vertex = synthetic_vertex(&graph, 1, &[]);
        let full = vertex.candidate.header.clone();
        let retained = vertex.info.header.retain();
        assert!(retained.matches(&full));
        assert_eq!(retained.parents(), &full.parents);
        assert_eq!(retained.work(), full.work);
        let mut changed = full.clone();
        changed.bytes[100] ^= 1;
        assert!(!retained.matches(&changed));
        let mut changed = full.clone();
        changed.bytes[560] ^= 1;
        assert!(!retained.matches(&changed));
        let mut changed = full.clone();
        changed.work += 1;
        assert!(!retained.matches(&changed));
        let mut changed = full;
        changed.parents = Sg0ParentSetV1::vertices(vec![id(2)]).unwrap();
        assert!(!retained.matches(&changed));
    }

    #[test]
    fn disk_metadata_missing_or_tampered_source_refuses_order_and_staging_without_credit() {
        let (temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        let mut graph = DurableGraph::default();
        graph
            .attach_ancestry_reader(store.object_reader().unwrap(), [9; 32])
            .unwrap();
        store
            .begin_replay(b"synthetic disk metadata fixture")
            .unwrap();
        for (label, parents) in [(1, &[][..]), (2, &[1][..]), (3, &[1][..]), (4, &[2, 3][..])] {
            let mut prepared = graph
                .seal(synthetic_vertex(&graph, label, parents), &budget)
                .unwrap();
            let record = prepared.vertex().retained_record().unwrap();
            store
                .commit(&[&record], b"synthetic full receiver-derived source")
                .unwrap();
            prepared
                .retain_ancestry(&graph, &mut store, &budget)
                .unwrap();
            prepared.bind_retained_source(&record).unwrap();
            graph.publish(prepared).unwrap();
        }
        let order = graph.order(&budget).unwrap();
        let head = store.head();
        let source = graph.get(id(4)).unwrap().source_id().unwrap();
        let path = temp
            .path()
            .join("store")
            .join(format!("{}.obj", hex::encode(source)));
        let held = path.with_extension("held");
        let original = std::fs::read(&path).unwrap();
        std::fs::rename(&path, &held).unwrap();
        let view = View {
            graph: &graph,
            added: None,
            members: None,
            budget: &budget,
        };
        assert!(matches!(view.vertex_data(id(4)), Err(Sg0Error::Invariant)));
        assert!(graph.order(&budget).is_err());
        assert!(
            graph
                .seal(synthetic_vertex(&graph, 5, &[4]), &budget)
                .is_err()
        );
        assert_eq!(graph.len(), 4);
        assert!(graph.get(id(5)).is_err());
        assert_eq!(store.head(), head);
        std::fs::rename(&held, &path).unwrap();
        let mut changed = original.clone();
        *changed.last_mut().unwrap() ^= 1;
        std::fs::write(&path, changed).unwrap();
        assert!(matches!(view.vertex_data(id(4)), Err(Sg0Error::Invariant)));
        assert!(graph.order(&budget).is_err());
        assert!(
            graph
                .seal(synthetic_vertex(&graph, 5, &[4]), &budget)
                .is_err()
        );
        assert_eq!(graph.len(), 4);
        assert_eq!(store.head(), head);
        std::fs::write(&path, original).unwrap();
        assert_eq!(graph.order(&budget).unwrap(), order);
    }
    #[test]
    fn disk_detach_graph_unbound_or_shared_body_publication_refuses_without_partial_credit() {
        let (_temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        let mut durable = DurableGraph::default();
        durable
            .attach_ancestry_reader(store.object_reader().unwrap(), [9; 32])
            .unwrap();
        let prepared = durable
            .seal(synthetic_vertex(&durable, 1, &[]), &budget)
            .unwrap();
        assert!(durable.publish(prepared).is_err());
        assert!(durable.is_empty());
        assert!(durable.get(id(1)).is_err());
        store
            .begin_replay(b"synthetic shared compact publication")
            .unwrap();
        let mut prepared = durable
            .seal(synthetic_vertex(&durable, 1, &[]), &budget)
            .unwrap();
        let record = prepared.vertex().retained_record().unwrap();
        store
            .commit(&[&record], b"synthetic complete original source")
            .unwrap();
        prepared
            .retain_ancestry(&durable, &mut store, &budget)
            .unwrap();
        prepared.bind_retained_source(&record).unwrap();
        let held = prepared.vertex.clone();
        assert!(durable.publish(prepared).is_err());
        assert!(durable.is_empty());
        assert!(durable.get(id(1)).is_err());
        assert_eq!(held.candidate().id, id(1).into_bytes());
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
        assert!(prepared.vertex.info.retained_source.is_none());
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
            .info
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
    fn disk_owned_execution_missing_source_is_io_and_resident_adapter_stays_borrowable() {
        let (temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        let graph = source_graph(&mut store, &budget);
        let genesis = crate::genesis::public_testnet_v1::genesis().unwrap();
        let source = graph
            .vertices
            .last()
            .unwrap()
            .info
            .retained_source
            .as_ref()
            .unwrap();
        let path = temp
            .path()
            .join("store")
            .join(format!("{}.obj", hex::encode(source.id)));
        let held = path.with_extension("held");
        std::fs::rename(&path, &held).unwrap();
        assert!(matches!(
            graph.load_for_execution(id(3), &genesis, &budget),
            Err(Error::Io(_))
        ));
        assert!(graph.get(id(3)).is_ok());
        assert_eq!(graph.len(), 3);
        std::fs::rename(&held, &path).unwrap();
        let resident = diamond(&budget);
        let loaded = resident
            .load_for_execution(id(4), &genesis, &budget)
            .unwrap();
        assert!(std::ptr::eq(loaded.as_ref(), resident.get(id(4)).unwrap()));
        assert!(
            resident
                .load_for_execution(id(9), &genesis, &budget)
                .is_err()
        );
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
        assert_eq!(
            graph
                .get(id(4))
                .unwrap()
                .info
                .ancestors
                .retained_ids()
                .len(),
            1
        );
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
        let page = graph.get(id(3)).unwrap().info.ancestors.retained_ids()[0];
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
            added: Some(&prepared.vertex().info),
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
