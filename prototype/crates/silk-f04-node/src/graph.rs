//! Receiver-owned full-data graph. No decoded peer object can construct validity.
mod ancestry;
mod directory;
mod facts;
mod index;
use crate::{
    Digest, Error, Result,
    budget::{JobBudget, LocalClock},
    carriage::{Candidate, Header, ParentFacts, WorkEngine},
    genesis::Genesis,
    wire::{raw_hash, u32le, u64le},
};
use ancestry::{AncestryOperation, PagedAncestry, RetainedContext};
use directory::{DirectoryOperation, VertexDirectory};
use facts::FactsRecord;
use index::{IndexOperation, VertexIndex};
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
    cell::{Ref, RefCell},
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
    facts: FactsRecord,
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
        let source = self
            .retained_source
            .as_ref()
            .ok_or(Error::Unavailable("retained parent facts source absent"))?;
        let start = 12_usize
            .checked_add(source.candidate_len)
            .ok_or(Error::Unavailable("retained parent facts length"))?;
        if bytes.len() != source.record_len
            || raw_hash(bytes) != source.id
            || bytes.get(..8) != Some(b"SNF04VR1")
            || u32le(bytes, 8)? as usize != source.candidate_len
        {
            return Err(Error::Unavailable("retained parent facts original binding"));
        }
        let source_record = bytes
            .get(start..start + 184)
            .ok_or(Error::Unavailable("retained parent facts source framing"))?
            .try_into()
            .map_err(|_| Error::Unavailable("retained parent facts source framing"))?;
        info.facts = self.facts.restore(header, source_record)?;
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
    fn directory_slot(&self) -> Result<Vec<u8>> {
        Err(Error::Unavailable(
            "resident carrier has no directory codec",
        ))
    }
    fn directory_bindings(&self) -> Arc<Vec<LiveRepresentationBinding>> {
        Arc::new(Vec::new())
    }
    fn from_directory(
        _: &[u8],
        _: &Arc<RetainedContext>,
        _: Arc<Vec<LiveRepresentationBinding>>,
    ) -> Result<Arc<Self>> {
        Err(Error::Unavailable(
            "resident carrier cannot adopt live directory slot",
        ))
    }
    fn stage_directory(
        _: &VerifiedVertex,
        _: &Arc<RetainedContext>,
        _: &JobBudget,
    ) -> Result<Arc<Self>> {
        Err(Error::Unavailable(
            "resident carrier cannot stage live directory",
        ))
    }
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
    fn stage_directory(
        vertex: &VerifiedVertex,
        reader: &Arc<RetainedContext>,
        budget: &JobBudget,
    ) -> Result<Arc<Self>> {
        let bytes = vertex.retained_record()?;
        budget.check()?;
        budget.source()?;
        let id = raw_hash(&bytes);
        if reader.objects().object(id, bytes.len())? != bytes {
            return Err(Error::Unavailable(
                "staged directory original source mismatch",
            ));
        }
        let mut info = vertex.info.clone();
        let Some(Metadata::Resident(metadata)) = &info.metadata else {
            return Err(Error::Unavailable("unsealed directory SG0 metadata"));
        };
        info.metadata = Some(Metadata::Retained {
            len: metadata.canonical_cache_bytes_v1()?.len(),
        });
        info.header = info.header.retain();
        info.facts = info.facts.retain();
        info.retained_source = Some(RetainedSource {
            id,
            record_len: bytes.len(),
            candidate_len: u32le(&bytes, 8)? as usize,
        });
        budget.check()?;
        Ok(Arc::new(Self {
            info,
            bindings: vertex
                .envelopes
                .iter()
                .map(VerifiedEnvelope::live_representation_binding)
                .collect(),
        }))
    }
    fn directory_bindings(&self) -> Arc<Vec<LiveRepresentationBinding>> {
        Arc::new(self.bindings.clone())
    }
    fn directory_slot(&self) -> Result<Vec<u8>> {
        let HeaderRecord::Retained {
            hash,
            domain,
            parents,
            work,
        } = &self.info.header
        else {
            return Err(Error::Unavailable("directory requires compact header"));
        };
        let Some(Metadata::Retained { len }) = self.info.metadata else {
            return Err(Error::Unavailable("directory requires sealed metadata"));
        };
        let source = self
            .info
            .retained_source
            .as_ref()
            .ok_or(Error::Unavailable("directory requires original source"))?;
        let mut bytes = Vec::with_capacity(directory::SLOT);
        bytes.extend_from_slice(&self.info.id);
        bytes.extend_from_slice(hash);
        bytes.extend_from_slice(domain);
        bytes.extend_from_slice(&work.to_le_bytes());
        let parent_ids = parents.ordinary_parents();
        bytes.push(
            u8::try_from(parent_ids.len())
                .map_err(|_| Error::Unavailable("directory parent count"))?,
        );
        for position in 0..2 {
            bytes.extend_from_slice(
                parent_ids
                    .get(position)
                    .map_or(&[0; 32][..], |id| &id.as_bytes()[..]),
            );
        }
        bytes.extend_from_slice(&self.info.facts.directory_bytes()?);
        bytes.extend_from_slice(&(len as u64).to_le_bytes());
        bytes.extend_from_slice(&source.id);
        bytes.extend_from_slice(&(source.record_len as u64).to_le_bytes());
        bytes.extend_from_slice(&(source.candidate_len as u64).to_le_bytes());
        bytes.extend_from_slice(&self.info.ancestors.directory_bytes()?);
        if bytes.len() != directory::SLOT {
            return Err(Error::Unavailable("directory slot encoder length"));
        }
        Ok(bytes)
    }
    fn from_directory(
        bytes: &[u8],
        reader: &Arc<RetainedContext>,
        bindings: Arc<Vec<LiveRepresentationBinding>>,
    ) -> Result<Arc<Self>> {
        if bytes.len() != directory::SLOT {
            return Err(Error::Unavailable("directory slot decoder length"));
        }
        let field = |at: usize| -> Result<Digest> {
            bytes[at..at + 32]
                .try_into()
                .map_err(|_| Error::Unavailable("directory slot digest"))
        };
        let count = bytes[104] as usize;
        if count > 2 || bytes[105 + count * 32..169].iter().any(|byte| *byte != 0) {
            return Err(Error::Unavailable("directory slot parent framing"));
        }
        let parents = if count == 0 {
            Sg0ParentSetV1::Anchor
        } else {
            Sg0ParentSetV1::vertices(
                (0..count)
                    .map(|position| field(105 + position * 32).map(VertexId::from_bytes))
                    .collect::<Result<Vec<_>>>()?,
            )?
        };
        let work = u64le(bytes, 96)?;
        let len = usize::try_from(u64le(bytes, 241)?)
            .map_err(|_| Error::Unavailable("directory metadata length"))?;
        let record_len = usize::try_from(u64le(bytes, 281)?)
            .map_err(|_| Error::Unavailable("directory source length"))?;
        let candidate_len = usize::try_from(u64le(bytes, 289)?)
            .map_err(|_| Error::Unavailable("directory candidate length"))?;
        if !(1..=1_000_000).contains(&work)
            || !(720..=90_000).contains(&candidate_len)
            || record_len > 8 * 1024 * 1024
            || record_len < candidate_len + 200
            || len == 0
            || len > record_len
        {
            return Err(Error::Unavailable("directory source bounds"));
        }
        Ok(Arc::new(Self {
            info: GraphInfo {
                id: field(0)?,
                header: HeaderRecord::Retained {
                    hash: field(32)?,
                    domain: field(64)?,
                    parents,
                    work,
                },
                facts: FactsRecord::from_live_directory(&bytes[169..241])?,
                metadata: Some(Metadata::Retained { len }),
                retained_source: Some(RetainedSource {
                    id: field(249)?,
                    record_len,
                    candidate_len,
                }),
                ancestors: PagedAncestry::from_live_directory(&bytes[297..], reader.clone())?,
            },
            bindings: bindings.as_ref().clone(),
        }))
    }
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
        info.facts = info.facts.retain();
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
        self.info.facts.resident()
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
        b.extend_from_slice(&self.facts().source_record);
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
    vertices: VertexDirectory<V>,
    index: VertexIndex,
    ancestry_reader: Option<Arc<RetainedContext>>,
    limits: crate::capacity::HistoryLimitsV1,
}
impl<V> Default for GraphData<V> {
    fn default() -> Self {
        Self {
            vertices: VertexDirectory::default(),
            index: VertexIndex::default(),
            ancestry_reader: None,
            limits: crate::capacity::HistoryLimitsV1::REFERENCE,
        }
    }
}
impl<V> Clone for GraphData<V> {
    fn clone(&self) -> Self {
        Self {
            vertices: self.vertices.clone(),
            index: self.index.clone(),
            ancestry_reader: self.ancestry_reader.clone(),
            limits: self.limits,
        }
    }
}

/// Prepared atomic graph insertion, not visible until durable publication succeeds.
pub(crate) struct PreparedVertex {
    vertex: Arc<VerifiedVertex>,
    revision: usize,
    index: Option<VertexIndex>,
    directory: Option<directory::RetainedDirectory>,
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
            self.index = Some(graph.index.retain_insert(
                VertexId::from_bytes(self.vertex.info.id),
                graph.len(),
                store,
                reader.domain(),
                budget,
            )?);
            let entry = V::stage_directory(&self.vertex, &reader, budget)?;
            self.directory = Some(
                graph
                    .vertices
                    .append(
                        entry,
                        store,
                        reader,
                        budget,
                        V::directory_slot,
                        V::directory_bindings,
                        V::from_directory,
                    )?
                    .into_retained()?,
            );
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
    pub(crate) fn with_limits(limits: crate::capacity::HistoryLimitsV1) -> Self {
        Self {
            limits,
            ..Self::default()
        }
    }
    pub(crate) const fn limits(&self) -> crate::capacity::HistoryLimitsV1 {
        self.limits
    }
    #[cfg(test)]
    pub(crate) fn retained_ancestry_pages(&self) -> usize {
        self.vertices
            .materialize(None)
            .expect("test ancestry directory")
            .iter()
            .map(|v| v.graph_info().ancestors.retained_ids().len())
            .sum()
    }
    pub(crate) fn attach_ancestry_reader(
        &mut self,
        reader: Arc<crate::store::ObjectReader>,
        domain: Digest,
    ) -> Result<()> {
        if !self.is_empty() || self.ancestry_reader.is_some() || reader.limits() != self.limits {
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
        self.vertices.borrowed_iter().map(AsRef::as_ref)
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
        (start..self.len().min(start + count))
            .map(|ordinal| {
                let vertex = self.vertices.load(ordinal, None)?;
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
        self.vertices.borrowed(self.position(id, None)?)
    }
    pub(crate) fn get_owned(&self, id: VertexId, budget: Option<&JobBudget>) -> Result<Arc<V>> {
        let position = self
            .index
            .lookup(&id, budget)?
            .ok_or(Error::Unavailable("missing admitted vertex"))?;
        let vertex = self.vertices.load(position, budget)?;
        if vertex.graph_info().id != id.into_bytes() {
            return Err(Error::Unavailable("vertex index identity mismatch"));
        }
        Ok(vertex)
    }
    #[cfg(test)]
    pub(crate) fn owned_vertices(&self, budget: Option<&JobBudget>) -> Result<Vec<Arc<V>>> {
        self.vertices.materialize(budget)
    }
    pub(crate) fn find_checked(&self, id: VertexId, budget: &JobBudget) -> Result<Option<Arc<V>>> {
        let Some(position) = self.index.lookup(&id, Some(budget))? else {
            return Ok(None);
        };
        let vertex = self.vertices.load(position, Some(budget))?;
        if vertex.graph_info().id != id.into_bytes() {
            return Err(Error::Unavailable("vertex index identity mismatch"));
        }
        Ok(Some(vertex))
    }
    #[cfg(test)]
    pub(crate) fn retained_index_pages(&self) -> Vec<Digest> {
        self.index.retained_ids()
    }
    #[cfg(test)]
    pub(crate) fn retained_directory_pages(&self) -> Vec<Digest> {
        self.vertices.retained_ids()
    }
    #[cfg(test)]
    pub(crate) fn parent_facts_are_retained(&self) -> bool {
        self.vertices
            .materialize(None)
            .expect("test facts directory")
            .iter()
            .all(|vertex| matches!(vertex.graph_info().facts, FactsRecord::Retained { .. }))
    }
    fn position(&self, id: VertexId, budget: Option<&JobBudget>) -> Result<usize> {
        let position = self
            .index
            .lookup(&id, budget)?
            .ok_or(Error::Unavailable("missing admitted vertex"))?;
        if self.vertices.load(position, budget)?.graph_info().id != id.into_bytes() {
            return Err(Error::Unavailable("vertex index identity mismatch"));
        }
        Ok(position)
    }
    pub(crate) fn header(
        &self,
        id: VertexId,
        genesis: &Genesis,
        budget: &JobBudget,
    ) -> Result<Arc<Header>> {
        budget.check()?;
        let vertex = self.get_owned(id, Some(budget))?;
        let info = vertex.graph_info();
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
    pub(crate) fn retained_candidate_matches(
        &self,
        id: VertexId,
        expected: &[u8],
        budget: Option<&JobBudget>,
    ) -> Result<bool> {
        let vertex = self.get_owned(id, budget)?;
        let info = vertex.graph_info();
        let source = info
            .retained_source
            .as_ref()
            .ok_or(Error::Unavailable("durable vertex source absent"))?;
        let reader = self
            .ancestry_reader
            .as_ref()
            .ok_or(Error::Unavailable("durable vertex reader absent"))?;
        if let Some(budget) = budget {
            budget.source()?;
        }
        let bytes = reader.objects().object(source.id, source.record_len)?;
        let end = 12_usize
            .checked_add(source.candidate_len)
            .ok_or(Error::Unavailable("durable candidate length"))?;
        let matches = bytes
            .get(12..end)
            .ok_or(Error::Unavailable("durable candidate framing"))?
            == expected;
        if let Some(budget) = budget {
            budget.check()?;
        }
        Ok(matches)
    }
    pub(crate) fn retained_candidate_hash_matches(
        &self,
        id: VertexId,
        expected: Digest,
        size: usize,
        budget: &JobBudget,
    ) -> Result<bool> {
        let vertex = self.get_owned(id, Some(budget))?;
        let source = vertex
            .graph_info()
            .retained_source
            .as_ref()
            .ok_or(Error::Unavailable("durable vertex source absent"))?;
        if source.candidate_len != size {
            return Ok(false);
        }
        let reader = self
            .ancestry_reader
            .as_ref()
            .ok_or(Error::Unavailable("durable vertex reader absent"))?;
        budget.source()?;
        let bytes = reader.objects().object(source.id, source.record_len)?;
        let end = 12_usize
            .checked_add(source.candidate_len)
            .ok_or(Error::Unavailable("durable candidate length"))?;
        if bytes.len() != source.record_len
            || bytes.get(..8) != Some(b"SNF04VR1")
            || u32le(&bytes, 8)? as usize != source.candidate_len
        {
            return Err(Error::Unavailable("durable candidate framing"));
        }
        let matches = raw_hash(
            bytes
                .get(12..end)
                .ok_or(Error::Unavailable("durable candidate framing"))?,
        ) == expected;
        budget.check()?;
        Ok(matches)
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
        let vertex = self.get_owned(id, Some(budget))?;
        let Some(reader) = &self.ancestry_reader else {
            return V::resident(&vertex).ok_or(Error::Unavailable("durable vertex reader absent"));
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
        Ok(derive_virtual_order_chain_fast_v1(&View::new(
            self, None, None, budget,
        ))?)
    }
    pub(crate) fn order_with(
        &self,
        prepared: &PreparedVertex,
        budget: &JobBudget,
    ) -> Result<Sg0OrderSnapshotV1> {
        if prepared.revision != self.len() {
            return Err(Error::Unavailable("stale staged order"));
        }
        Ok(derive_virtual_order_chain_fast_v1(&View::new(
            self,
            Some(&prepared.vertex.info),
            None,
            budget,
        ))?)
    }
    pub(crate) fn parent_order(
        &self,
        parents: &Sg0ParentSetV1,
        budget: &JobBudget,
    ) -> Result<Sg0OrderSnapshotV1> {
        let bits = self.parent_closure_checked(parents, Some(budget))?;
        Ok(derive_virtual_order_chain_fast_v1(&View::new(
            self,
            None,
            Some(&bits),
            budget,
        ))?)
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
        let mut bits = PagedAncestry::with_horizon(self.limits.vertices());
        for p in parents.ordinary_parents() {
            let i = self.position(*p, budget)?;
            let vertex = self.vertices.load(i, budget)?;
            let v = vertex.graph_info();
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
            .get_owned(b, budget)?
            .graph_info()
            .ancestors
            .contains(ai)?)
    }

    /// One delayed-key search's owned ID snapshot and <=4 target descriptors.
    /// Fresh qualification occurs per immutable operation, not per membership bit.
    pub(crate) fn ancestor_query<'a>(
        &'a self,
        budget: &'a JobBudget,
    ) -> Result<AncestorQuery<'a, V>> {
        let view = View::new(self, None, None, budget);
        // Whole index/directory qualification before returning any query result.
        drop(view.inventory()?);
        let inventory = view
            .inventory
            .into_inner()
            .ok_or(Error::Unavailable("ancestor query inventory absent"))?
            .ordinals;
        Ok(AncestorQuery {
            graph: self,
            budget,
            inventory,
            targets: Vec::new(),
            reads: DirectoryOperation::new(&self.vertices),
            ancestry: AncestryOperation::new(self.ancestry_reader.as_ref()),
        })
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
        if self.len() >= self.limits.vertices() {
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
        budget.phase(crate::budget::AdmissionPhase::Work);
        budget.check()?;
        work.verify(&candidate, &facts, g)?;
        budget.check()?;
        budget.phase(crate::budget::AdmissionPhase::BodyCrypto);
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
        budget.phase(crate::budget::AdmissionPhase::CandidateClosure);
        Ok(VerifiedVertex {
            info: GraphInfo {
                id: candidate.id,
                header: HeaderRecord::Resident(Arc::new(candidate.header.clone())),
                facts: FactsRecord::Resident(Box::new(facts)),
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
            derive_append_vertex_data_v1(&View::new(self, Some(&vertex.info), None, budget), id)
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
            directory: None,
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
            self.vertices.check_shape(budget)?;
            let next = prepared
                .index
                .ok_or(Error::Unavailable("durable vertex index absent"))?;
            let rows = next.inventory(budget)?;
            if rows.ids.len() != self.len() + 1 || rows.ids.last() != Some(&id) {
                return Err(Error::Unavailable("staged vertex index length"));
            }
            self.index.visit_checked(budget, &mut |old_id, position| {
                budget.graph_read()?;
                if rows.ids.get(position) != Some(&old_id) {
                    return Err(Error::Unavailable("staged vertex index identity"));
                }
                Ok(())
            })?;
            let mut current = DirectoryOperation::new(&self.vertices);
            for position in 0..self.len() {
                let vertex = current.load(position, budget)?;
                budget.graph_read()?;
                if rows.ids[position] != VertexId::from_bytes(vertex.graph_info().id) {
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
        let next_directory = if V::DURABLE_INDEX {
            let next = VertexDirectory::from_retained(
                prepared
                    .directory
                    .ok_or(Error::Unavailable("durable vertex directory absent"))?,
                V::from_directory,
            );
            next.check_shape(budget)?;
            self.vertices.check_shape(budget)?;
            let mut entries = DirectoryOperation::new(&next);
            if next.len() != self.len() + 1
                || entries.load(self.len(), budget)?.directory_slot()? != entry.directory_slot()?
            {
                return Err(Error::Unavailable("staged vertex directory identity"));
            }
            let mut current = DirectoryOperation::new(&self.vertices);
            for position in 0..self.len() {
                let old = current.load(position, budget)?;
                let new = entries.load(position, budget)?;
                budget.graph_read()?;
                if old.directory_slot()? != new.directory_slot()? {
                    return Err(Error::Unavailable("staged vertex directory prefix"));
                }
            }
            next
        } else {
            let mut next = self.vertices.clone();
            next.push_resident(entry)?;
            next
        };
        budget.check()?;
        self.index = next_index;
        self.vertices = next_directory;
        Ok(())
    }
}

// Each view exposes ONLY admitted evidence plus, privately, one already fully
// verified candidate. Ancestry is derived on insert from immutable parent closure.
// Positive owned IDs, not metadata/validity flags or decoded graph carriers.
// Both vectors are bounded by the unchanged horizon: <=160 KiB at 4,096 IDs
// on a 64-bit target, excluding their fixed headers and allocator overhead.
struct OrdinalInventory {
    ids: Vec<VertexId>,
    sorted: Vec<usize>,
}
// Only header facts already checked during this View's complete directory pass.
// Parent vectors have at most two IDs; no payload, metadata or ancestry is kept.
struct HeaderFacts {
    parents: Sg0ParentSetV1,
    work: u64,
}
struct ViewInventory {
    ordinals: OrdinalInventory,
    headers: Vec<HeaderFacts>,
}
impl std::ops::Deref for ViewInventory {
    type Target = OrdinalInventory;
    fn deref(&self) -> &Self::Target {
        &self.ordinals
    }
}
/// Crate-private, borrowed from the receiver's immutable live graph only. No
/// persisted constructor, imported IDs, negative cache or graph-wide payloads.
pub(crate) struct AncestorQuery<'a, V> {
    graph: &'a GraphData<V>,
    budget: &'a JobBudget,
    inventory: OrdinalInventory,
    targets: Vec<(VertexId, Arc<V>)>,
    reads: DirectoryOperation<'a, V>,
    ancestry: AncestryOperation<'a>,
}
impl<V: GraphEntry> AncestorQuery<'_, V> {
    fn position(&self, id: VertexId) -> Result<usize> {
        self.budget.check()?;
        let sorted = self
            .inventory
            .sorted
            .binary_search_by_key(&id, |position| self.inventory.ids[*position])
            .map_err(|_| Error::Unavailable("missing admitted vertex"))?;
        Ok(self.inventory.sorted[sorted])
    }
    pub(crate) fn is_ancestor(&mut self, a: VertexId, b: VertexId) -> Result<bool> {
        self.budget.probe()?;
        let ai = self.position(a)?;
        let bi = self.position(b)?;
        let target = if let Some((_, vertex)) = self.targets.iter().find(|(id, _)| *id == b) {
            vertex.clone()
        } else {
            let vertex = self.reads.load(bi, self.budget)?;
            if vertex.graph_info().id != b.into_bytes() {
                return Err(Error::Unavailable("ancestor query target identity"));
            }
            // Frontier has <=4 members; ordinary candidate parent set <=2.
            // Keep a fixed small positive working set even on adversarial search.
            if self.targets.len() == 4 {
                self.targets.remove(0);
            }
            self.targets.push((b, vertex.clone()));
            vertex
        };
        if self.inventory.ids.len() != self.graph.len() {
            return Err(Error::Unavailable("ancestor query graph binding"));
        }
        let found = self
            .ancestry
            .contains(&target.graph_info().ancestors, ai, self.budget)?;
        self.budget.check()?;
        Ok(found)
    }
}
struct View<'a, V> {
    graph: &'a GraphData<V>,
    added: Option<&'a GraphInfo>,
    members: Option<&'a PagedAncestry>,
    budget: &'a JobBudget,
    reads: RefCell<DirectoryOperation<'a, V>>,
    index_reads: RefCell<IndexOperation<'a>>,
    ancestry_reads: RefCell<AncestryOperation<'a>>,
    inventory: RefCell<Option<ViewInventory>>,
}
impl<'a, V> View<'a, V> {
    const fn new(
        graph: &'a GraphData<V>,
        added: Option<&'a GraphInfo>,
        members: Option<&'a PagedAncestry>,
        budget: &'a JobBudget,
    ) -> Self {
        Self {
            graph,
            added,
            members,
            budget,
            reads: RefCell::new(DirectoryOperation::new(&graph.vertices)),
            index_reads: RefCell::new(IndexOperation::new(&graph.index)),
            ancestry_reads: RefCell::new(AncestryOperation::new(graph.ancestry_reader.as_ref())),
            inventory: RefCell::new(None),
        }
    }
}
enum ViewEntry<'a, V> {
    Added(&'a GraphInfo),
    Admitted(Arc<V>),
}
impl<V: GraphEntry> ViewEntry<'_, V> {
    fn info(&self) -> &GraphInfo {
        match self {
            Self::Added(info) => info,
            Self::Admitted(vertex) => vertex.graph_info(),
        }
    }
}
impl<V: GraphEntry> View<'_, V> {
    fn inventory(&self) -> std::result::Result<Ref<'_, ViewInventory>, Sg0Error> {
        self.budget.check().map_err(index_error)?;
        if self.inventory.borrow().is_none() {
            if self.graph.len() > self.graph.limits.vertices() {
                return Err(Sg0Error::Invariant);
            }
            let inventory = self
                .graph
                .index
                .inventory(self.budget)
                .map_err(index_error)?;
            if inventory.ids.len() != self.graph.len() {
                return Err(Sg0Error::Invariant);
            }
            let mut headers = Vec::with_capacity(self.graph.len());
            // One sequential directory pass validates the complete ID/ordinal
            // permutation before any caller receives an inventory or callback.
            for i in 0..self.graph.len() {
                self.budget.graph_read()?;
                let vertex = self
                    .reads
                    .borrow_mut()
                    .load(i, self.budget)
                    .map_err(index_error)?;
                let id = VertexId::from_bytes(vertex.graph_info().id);
                if inventory.ids[i] != id {
                    return Err(Sg0Error::Invariant);
                }
                let parents = vertex.graph_info().header.parents();
                if parents.ordinary_parents().len() > silk_order::sg0_v1::SG0_V1_MAX_PARENTS {
                    return Err(Sg0Error::InvalidParents);
                }
                headers.push(HeaderFacts {
                    parents: parents.clone(),
                    work: vertex.graph_info().header.work(),
                });
            }
            self.budget.check().map_err(index_error)?;
            // Only the fully qualified owned snapshot is installed. No failed
            // or partial inventory escapes, nor survives this immutable View.
            *self.inventory.borrow_mut() = Some(ViewInventory {
                ordinals: inventory,
                headers,
            });
        }
        self.budget.check().map_err(index_error)?;
        Ref::filter_map(self.inventory.borrow(), Option::as_ref).map_err(|_| Sg0Error::Invariant)
    }
    fn header_facts(
        &self,
        id: VertexId,
    ) -> std::result::Result<Option<Ref<'_, HeaderFacts>>, Sg0Error> {
        let inventory = self.inventory.borrow();
        let Some(qualified) = inventory.as_ref() else {
            return Ok(None);
        };
        // Keep the original per-query accounting even though owned checked
        // bytes no longer reopen a directory page. Membership is still checked.
        self.budget.graph_read()?;
        let sorted = qualified
            .sorted
            .binary_search_by_key(&id, |position| qualified.ids[*position])
            .map_err(|_| Sg0Error::MissingVertex)?;
        let ordinal = qualified.sorted[sorted];
        if let Some(bits) = self.members
            && !self
                .ancestry_reads
                .borrow_mut()
                .contains(bits, ordinal, self.budget)?
        {
            return Err(Sg0Error::MissingVertex);
        }
        Ref::filter_map(inventory, |owned| {
            owned.as_ref().and_then(|view| view.headers.get(ordinal))
        })
        .map(Some)
        .map_err(|_| Sg0Error::Invariant)
    }
    fn lookup(&self, id: VertexId) -> std::result::Result<ViewEntry<'_, V>, Sg0Error> {
        self.budget.graph_read()?;
        if let Some(v) = self.added.filter(|v| v.id == id.into_bytes()) {
            return Ok(ViewEntry::Added(v));
        }
        let i = if let Some(inventory) = self.inventory.borrow().as_ref() {
            // Only installed after whole index/directory qualification. Owned
            // immutable operation bytes replace redundant index leaf reads.
            let position = inventory
                .sorted
                .binary_search_by_key(&id, |position| inventory.ids[*position])
                .map_err(|_| Sg0Error::MissingVertex)?;
            inventory.sorted[position]
        } else {
            // Incremental sealing may query before inventory is requested.
            self.index_reads
                .borrow_mut()
                .lookup(&id, self.budget)
                .map_err(index_error)?
                .ok_or(Sg0Error::MissingVertex)?
        };
        let vertex = self
            .reads
            .borrow_mut()
            .load(i, self.budget)
            .map_err(index_error)?;
        if vertex.graph_info().id != id.into_bytes() {
            return Err(Sg0Error::Invariant);
        }
        if let Some(bits) = self.members
            && !self
                .ancestry_reads
                .borrow_mut()
                .contains(bits, i, self.budget)?
        {
            return Err(Sg0Error::MissingVertex);
        }
        Ok(ViewEntry::Admitted(vertex))
    }
}
impl<V: GraphEntry> ReceiverVerifiedSg0Graph for View<'_, V> {
    fn visit_vertex_ids(
        &self,
        visitor: &mut dyn FnMut(VertexId) -> std::result::Result<(), Sg0Error>,
    ) -> std::result::Result<(), Sg0Error> {
        let inventory = self.inventory()?;
        for i in &inventory.sorted {
            self.budget.graph_read()?;
            if self
                .members
                .map(|bits| {
                    self.ancestry_reads
                        .borrow_mut()
                        .contains(bits, *i, self.budget)
                })
                .transpose()?
                .unwrap_or(true)
            {
                visitor(inventory.ids[*i])?;
            }
        }
        if let Some(v) = self.added {
            visitor(VertexId::from_bytes(v.id))?;
        }
        Ok(())
    }
    fn receiver_verified_contains(&self, id: VertexId) -> std::result::Result<bool, Sg0Error> {
        if self.added.is_some_and(|added| added.id == id.into_bytes()) {
            self.budget.graph_read()?;
            return Ok(true);
        }
        match self.header_facts(id) {
            Ok(Some(_)) => return Ok(true),
            Err(Sg0Error::MissingVertex) => return Ok(false),
            Err(error) => return Err(error),
            Ok(None) => {}
        }
        match self.lookup(id) {
            Ok(_) => Ok(true),
            Err(Sg0Error::MissingVertex) => Ok(false),
            Err(e) => Err(e),
        }
    }
    fn parent_set(&self, id: VertexId) -> std::result::Result<Sg0ParentSetV1, Sg0Error> {
        if let Some(added) = self.added.filter(|added| added.id == id.into_bytes()) {
            self.budget.graph_read()?;
            return Ok(added.header.parents().clone());
        }
        if let Some(header) = self.header_facts(id)? {
            return Ok(header.parents.clone());
        }
        Ok(self.lookup(id)?.info().header.parents().clone())
    }
    fn receiver_verified_work_be(&self, id: VertexId) -> std::result::Result<Digest, Sg0Error> {
        if let Some(added) = self.added.filter(|added| added.id == id.into_bytes()) {
            self.budget.graph_read()?;
            return Ok(Uint256::from_u64(added.header.work()).to_be_bytes());
        }
        if let Some(header) = self.header_facts(id)? {
            return Ok(Uint256::from_u64(header.work).to_be_bytes());
        }
        Ok(Uint256::from_u64(self.lookup(id)?.info().header.work()).to_be_bytes())
    }
    fn vertex_data(&self, id: VertexId) -> std::result::Result<Option<Sg0VertexDataV1>, Sg0Error> {
        self.lookup(id)?
            .info()
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
        let positions = self
            .lookup(id)?
            .info()
            .ancestors
            .positions_before(self.graph.len(), self.budget)?;
        // The owned operation inventory preserves all-directory-validation
        // before callbacks without reopening every page for every past walk.
        // Ancestry bytes above remain freshly qualified in full per walk.
        let inventory = self.inventory()?;
        for i in positions {
            self.budget.graph_read()?;
            visitor(inventory.ids[i])?;
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
        let i = if let Some(inventory) = self.inventory.borrow().as_ref() {
            let sorted = inventory
                .sorted
                .binary_search_by_key(&a, |position| inventory.ids[*position])
                .map_err(|_| Sg0Error::Invariant)?;
            inventory.sorted[sorted]
        } else {
            self.index_reads
                .borrow_mut()
                .lookup(&a, self.budget)
                .map_err(index_error)?
                .ok_or(Sg0Error::Invariant)?
        };
        self.ancestry_reads
            .borrow_mut()
            .contains(&v.info().ancestors, i, self.budget)
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

    #[test]
    fn graph_order_scoped_chain_facts_match_reference_and_refuse_fresh_damage() {
        let (temp, mut store) = crate::store::ancestry_test_store();
        let setup = JobBudget::checkpoint().unwrap();
        let mut graph = DurableGraph::default();
        graph
            .attach_ancestry_reader(store.object_reader().unwrap(), [9; 32])
            .unwrap();
        store
            .begin_replay(b"synthetic shuffled chain facts")
            .unwrap();
        let mut previous = None;
        let mut expected = Vec::new();
        // ID order deliberately differs from append/ancestry order across
        // three directory leaves; there is no native work or proof generation.
        for position in 0..129_u16 {
            let label = u8::try_from((position * 53) % 129 + 1).unwrap();
            let parents = previous.into_iter().collect::<Vec<_>>();
            let mut prepared = graph
                .seal(synthetic_vertex(&graph, label, &parents), &setup)
                .unwrap();
            let record = prepared.vertex().retained_record().unwrap();
            store.commit(&[&record], b"synthetic chain head").unwrap();
            prepared.bind_retained_source(&record).unwrap();
            prepared
                .retain_ancestry(&graph, &mut store, &setup)
                .unwrap();
            graph.publish_checked(prepared, &setup).unwrap();
            expected.push(id(label));
            previous = Some(label);
        }
        let original = JobBudget::checkpoint().unwrap();
        let reference =
            silk_order::sg0_v1::derive_virtual_order(&View::new(&graph, None, None, &original))
                .unwrap();
        let budget = JobBudget::vertex().unwrap();
        let actual = graph.order(&budget).unwrap();
        assert_eq!(actual, reference);
        assert_eq!(actual.eligible_order(), expected);
        let sources = budget.source_calls();
        // One original metadata read per vertex; checked directory leaves
        // remain bounded and the commitment does not reopen those originals.
        assert!(sources < 2 * 129, "checked sources={sources}");
        println!(
            "synthetic_graph_order_vertices=129; checked_sources={sources}; exact_reference_snapshot=true; native_work=0; proofs=0; native_timeout_fix_unproven=true"
        );
        let expired = JobBudget::testing(std::time::Duration::ZERO).unwrap();
        assert!(graph.order(&expired).is_err());
        let target = graph.get_owned(expected[128], None).unwrap();
        let source = temp.path().join("store").join(format!(
            "{}.obj",
            hex::encode(target.info.retained_source.as_ref().unwrap().id)
        ));
        let held = source.with_extension("held");
        std::fs::rename(&source, &held).unwrap();
        assert!(graph.order(&JobBudget::checkpoint().unwrap()).is_err());
        std::fs::rename(&held, &source).unwrap();
        let branch_budget = JobBudget::checkpoint().unwrap();
        let branch = diamond(&branch_budget);
        assert_eq!(
            branch.order(&branch_budget).unwrap(),
            silk_order::sg0_v1::derive_virtual_order(&View::new(
                &branch,
                None,
                None,
                &branch_budget,
            ))
            .unwrap()
        );
        // Exact staged order includes the freshly sealed vertex as before.
        let prepared = graph
            .seal(synthetic_vertex(&graph, 200, &[previous.unwrap()]), &setup)
            .unwrap();
        let staged = graph.order_with(&prepared, &setup).unwrap();
        assert_eq!(
            staged,
            silk_order::sg0_v1::derive_virtual_order(&View::new(
                &graph,
                Some(&prepared.vertex().info),
                None,
                &setup,
            ))
            .unwrap()
        );
    }

    #[test]
    fn ancestor_query_matches_original_branch_relations_and_strict_self_rules() {
        let budget = JobBudget::checkpoint().unwrap();
        let graph = diamond(&budget);
        let mut query = graph.ancestor_query(&budget).unwrap();
        for a in 1..=4 {
            for b in 1..=4 {
                assert_eq!(
                    query.is_ancestor(id(a), id(b)).unwrap(),
                    graph
                        .is_ancestor_checked(id(a), id(b), Some(&budget))
                        .unwrap()
                );
                assert!(query.targets.len() <= 4);
            }
        }
        assert!(query.is_ancestor(id(5), id(4)).is_err());
        assert!(query.is_ancestor(id(1), id(5)).is_err());
        assert_eq!(query.targets.len(), 4);
        let expired = JobBudget::testing(std::time::Duration::ZERO).unwrap();
        assert!(graph.ancestor_query(&expired).is_err());
    }

    #[test]
    fn ancestor_query_disk_frontier_reduces_checked_sources_and_is_operation_scoped() {
        let (temp, mut store) = crate::store::ancestry_test_store();
        let setup = JobBudget::checkpoint().unwrap();
        let mut graph = DurableGraph::default();
        graph
            .attach_ancestry_reader(store.object_reader().unwrap(), [9; 32])
            .unwrap();
        store
            .begin_replay(b"synthetic ancestor-query fixture only")
            .unwrap();
        for label in 1..=65_u8 {
            let parents = if label == 1 {
                Vec::new()
            } else {
                vec![label - 1]
            };
            let mut prepared = graph
                .seal(synthetic_vertex(&graph, label, &parents), &setup)
                .unwrap();
            let record = prepared.vertex().retained_record().unwrap();
            store
                .commit(&[&record], b"synthetic query fixture head")
                .unwrap();
            prepared.bind_retained_source(&record).unwrap();
            prepared
                .retain_ancestry(&graph, &mut store, &setup)
                .unwrap();
            graph.publish_checked(prepared, &setup).unwrap();
        }
        let baseline = JobBudget::vertex().unwrap();
        let expected = (1..=64)
            .rev()
            .map(|label| {
                graph
                    .is_ancestor_checked(id(label), id(65), Some(&baseline))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let baseline_sources = baseline.source_calls();
        let mut optimized = JobBudget::vertex().unwrap();
        let trace = optimized.track_admission();
        optimized.phase(crate::budget::AdmissionPhase::ParentFrontierInventory);
        let mut query = graph.ancestor_query(&optimized).unwrap();
        optimized.phase(crate::budget::AdmissionPhase::ParentFrontier);
        let actual = (1..=64)
            .rev()
            .map(|label| query.is_ancestor(id(label), id(65)).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
        let shared_sources = optimized.source_calls();
        assert!(baseline_sources >= 4 * 64);
        assert!(shared_sources <= 6);
        assert!(baseline_sources > shared_sources * 20);
        assert_eq!(trace.failure(), None);
        println!(
            "synthetic_parent_frontier_vertices=65; original_budget_cpu_seconds=2; baseline_checked_source_calls={baseline_sources}; operation_checked_source_calls={shared_sources}; native_work=0; proofs=0; historical_failure_attribution=false"
        );
        let weak = Arc::downgrade(&query.targets[0].1);
        for b in (60..=64).rev() {
            assert!(query.is_ancestor(id(1), id(b)).unwrap());
            assert!(query.targets.len() <= 4);
        }
        // These are owned per-operation bytes, not a promise of rereading an
        // already qualified page after the operator mutates the test fixture.
        let late = temp.path().join("store").join(format!(
            "{}.obj",
            hex::encode(graph.retained_directory_pages()[1])
        ));
        let held = late.with_extension("held");
        std::fs::rename(&late, &held).unwrap();
        assert!(graph.ancestor_query(&JobBudget::vertex().unwrap()).is_err());
        drop(query);
        assert!(weak.upgrade().is_none());
        std::fs::rename(&held, &late).unwrap();
        let fresh_budget = JobBudget::vertex().unwrap();
        let mut fresh = graph.ancestor_query(&fresh_budget).unwrap();
        assert!(fresh.is_ancestor(id(1), id(65)).unwrap());
        assert!(!fresh.is_ancestor(id(65), id(65)).unwrap());
        let target = fresh
            .targets
            .iter()
            .find(|(id, _)| *id == super::tests::id(65))
            .unwrap();
        let ancestry = temp.path().join("store").join(format!(
            "{}.obj",
            hex::encode(target.1.graph_info().ancestors.retained_ids()[0])
        ));
        let held_ancestry = ancestry.with_extension("held");
        std::fs::rename(&ancestry, &held_ancestry).unwrap();
        let cold_budget = JobBudget::vertex().unwrap();
        let mut cold = graph.ancestor_query(&cold_budget).unwrap();
        assert!(cold.is_ancestor(id(1), id(65)).is_err());
        assert_eq!(cold.ancestry.loads(), 0);
        std::fs::rename(&held_ancestry, &ancestry).unwrap();
        assert!(cold.is_ancestor(id(1), id(65)).unwrap());
        let expired = JobBudget::testing(std::time::Duration::ZERO).unwrap();
        assert!(graph.ancestor_query(&expired).is_err());
        assert_eq!(store.active_replay().unwrap().is_some(), true);
    }

    #[test]
    fn incremental_directory_new_page_staging_cannot_credit_a_missing_immutable_prefix() {
        let (temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        let mut graph = DurableGraph::default();
        graph
            .attach_ancestry_reader(store.object_reader().unwrap(), [9; 32])
            .unwrap();
        store
            .begin_replay(b"synthetic directory append boundary")
            .unwrap();
        for label in 1..=64_u8 {
            let parents = if label == 1 {
                Vec::new()
            } else {
                vec![label - 1]
            };
            let mut prepared = graph
                .seal(synthetic_vertex(&graph, label, &parents), &budget)
                .unwrap();
            let record = prepared.vertex().retained_record().unwrap();
            store
                .commit(&[&record], b"synthetic append prefix source")
                .unwrap();
            prepared.bind_retained_source(&record).unwrap();
            prepared
                .retain_ancestry(&graph, &mut store, &budget)
                .unwrap();
            graph.publish_checked(prepared, &budget).unwrap();
        }
        let old_directory = graph.retained_directory_pages();
        let old_index = graph.retained_index_pages();
        let fork = graph.clone();
        let mut prepared = graph
            .seal(synthetic_vertex(&graph, 65, &[64]), &budget)
            .unwrap();
        let record = prepared.vertex().retained_record().unwrap();
        store
            .commit(&[&record], b"synthetic append boundary source")
            .unwrap();
        prepared.bind_retained_source(&record).unwrap();
        let head = store.head();
        let path = temp
            .path()
            .join("store")
            .join(format!("{}.obj", hex::encode(old_directory[0])));
        let held = path.with_extension("held");
        std::fs::rename(&path, &held).unwrap();
        // An append at the page boundary stages only its new page. This is not
        // graph credit or a whole-prefix integrity assertion.
        prepared
            .retain_ancestry(&graph, &mut store, &budget)
            .unwrap();
        assert!(matches!(
            graph.publish_checked(prepared, &budget),
            Err(Error::Io(_))
        ));
        assert_eq!(graph.len(), 64);
        assert_eq!(graph.retained_directory_pages(), old_directory);
        assert_eq!(graph.retained_index_pages(), old_index);
        assert_eq!(store.head(), head);
        std::fs::rename(&held, &path).unwrap();
        let mut prepared = graph
            .seal(synthetic_vertex(&graph, 65, &[64]), &budget)
            .unwrap();
        prepared.bind_retained_source(&record).unwrap();
        prepared
            .retain_ancestry(&graph, &mut store, &budget)
            .unwrap();
        graph.publish_checked(prepared, &budget).unwrap();
        assert_eq!(graph.len(), 65);
        assert_eq!(graph.retained_directory_pages().len(), 2);
        assert_eq!(graph.retained_directory_pages()[0], old_directory[0]);
        assert_eq!(fork.len(), 64);
        assert_eq!(fork.retained_directory_pages(), old_directory);
        let view = View::new(&graph, None, None, &budget);
        let mut visited = Vec::new();
        view.visit_vertex_ids(&mut |id| {
            visited.push(id);
            Ok(())
        })
        .unwrap();
        assert_eq!(view.reads.borrow().loads(), 2);
        assert_eq!(
            visited,
            graph
                .index
                .materialize(Some(&budget))
                .unwrap()
                .into_keys()
                .collect::<Vec<_>>()
        );
        let mut past = Vec::new();
        view.visit_strict_past_ids(id(65), &mut |id| {
            past.push(id);
            Ok(())
        })
        .unwrap();
        assert_eq!(past, (1..=64).map(id).collect::<Vec<_>>());
        assert_eq!(view.reads.borrow().loads(), 2);
        assert_eq!(view.inventory.borrow().as_ref().unwrap().ids.len(), 65);
        assert_eq!(view.inventory.borrow().as_ref().unwrap().sorted.len(), 65);
        let mut repeated_past = Vec::new();
        view.visit_strict_past_ids(id(65), &mut |vertex| {
            repeated_past.push(vertex);
            Ok(())
        })
        .unwrap();
        assert_eq!(repeated_past, past);
        assert_eq!(view.reads.borrow().loads(), 2);
        for label in 1..=64 {
            assert_eq!(
                view.receiver_verified_work_be(id(label)).unwrap(),
                Uint256::from_u64(1).to_be_bytes()
            );
        }
        assert_eq!(view.index_reads.borrow().loads(), 0);
        assert_eq!(view.reads.borrow().loads(), 2);
        assert!(view.receiver_verified_is_ancestor(id(1), id(64)).unwrap());
        assert_eq!(view.index_reads.borrow().loads(), 0);
        for label in 1..64 {
            assert!(
                view.receiver_verified_is_ancestor(id(label), id(64))
                    .unwrap()
            );
        }
        assert!(!view.receiver_verified_is_ancestor(id(64), id(64)).unwrap());
        assert_eq!(view.ancestry_reads.borrow().loads(), 1);
        let target = graph.get_owned(id(65), None).unwrap();
        let filtered = View::new(&graph, None, Some(&target.info.ancestors), &budget);
        let mut members = Vec::new();
        filtered
            .visit_vertex_ids(&mut |vertex| {
                members.push(vertex);
                Ok(())
            })
            .unwrap();
        assert_eq!(members, (1..=64).map(id).collect::<Vec<_>>());
        assert_eq!(filtered.ancestry_reads.borrow().loads(), 1);
        assert!(!filtered.receiver_verified_contains(id(65)).unwrap());
        assert_eq!(filtered.ancestry_reads.borrow().loads(), 1);
        let late_index = temp.path().join("store").join(format!(
            "{}.obj",
            hex::encode(graph.retained_index_pages()[1])
        ));
        let held_index = late_index.with_extension("held");
        std::fs::rename(&late_index, &held_index).unwrap();
        let cold = View::new(&graph, None, None, &budget);
        let mut partial_callbacks = 0;
        assert!(
            cold.visit_vertex_ids(&mut |_| {
                partial_callbacks += 1;
                Ok(())
            })
            .is_err()
        );
        assert!(
            cold.visit_strict_past_ids(id(64), &mut |_| {
                partial_callbacks += 1;
                Ok(())
            })
            .is_err()
        );
        assert_eq!(partial_callbacks, 0);
        assert!(cold.inventory.borrow().is_none());
        std::fs::rename(&held_index, &late_index).unwrap();
        let mut restored = Vec::new();
        cold.visit_vertex_ids(&mut |vertex| {
            restored.push(vertex);
            Ok(())
        })
        .unwrap();
        assert_eq!(restored, visited);
        let later = temp.path().join("store").join(format!(
            "{}.obj",
            hex::encode(graph.retained_directory_pages()[1])
        ));
        let held_later = later.with_extension("held");
        std::fs::rename(&later, &held_later).unwrap();
        let fresh = View::new(&graph, None, None, &budget);
        let mut callbacks = 0;
        assert!(
            fresh
                .visit_strict_past_ids(id(64), &mut |_| {
                    callbacks += 1;
                    Ok(())
                })
                .is_err()
        );
        assert_eq!(callbacks, 0);
        assert!(fresh.inventory.borrow().is_none());
        let fresh = View::new(&graph, None, None, &budget);
        assert!(
            fresh
                .visit_vertex_ids(&mut |_| {
                    callbacks += 1;
                    Ok(())
                })
                .is_err()
        );
        assert_eq!(callbacks, 0);
        assert!(fresh.inventory.borrow().is_none());
        // This operation owns its complete checked IDs, not a fresh-read
        // promise. No full graph carriers or metadata enter that snapshot.
        let mut warm_ids = Vec::new();
        view.visit_vertex_ids(&mut |vertex| {
            warm_ids.push(vertex);
            Ok(())
        })
        .unwrap();
        assert_eq!(warm_ids, visited);
        std::fs::rename(&held_later, &later).unwrap();
        // Strict-past ancestry is still freshly read even with a warm inventory.
        let ancestry = temp.path().join("store").join(format!(
            "{}.obj",
            hex::encode(target.info.ancestors.retained_ids()[0])
        ));
        let held_ancestry = ancestry.with_extension("held");
        std::fs::rename(&ancestry, &held_ancestry).unwrap();
        assert!(
            view.visit_strict_past_ids(id(65), &mut |_| {
                callbacks += 1;
                Ok(())
            })
            .is_err()
        );
        assert_eq!(callbacks, 0);
        std::fs::rename(&held_ancestry, &ancestry).unwrap();
        let mut restored_ids = Vec::new();
        fresh
            .visit_vertex_ids(&mut |vertex| {
                restored_ids.push(vertex);
                Ok(())
            })
            .unwrap();
        assert_eq!(restored_ids, visited);
        assert_eq!(graph.order(&budget).unwrap().eligible_order().len(), 65);
    }
    #[test]
    fn operation_inventory_preserves_reentrant_visitors_and_cumulative_deadline() {
        let budget = JobBudget::checkpoint().unwrap();
        let graph = diamond(&budget);
        let view = View::new(&graph, None, None, &budget);
        let mut ids = Vec::new();
        view.visit_vertex_ids(&mut |vertex| {
            let mut nested = Vec::new();
            view.visit_vertex_ids(&mut |inner| {
                nested.push(inner);
                Ok(())
            })?;
            assert_eq!(nested, (1..=4).map(id).collect::<Vec<_>>());
            ids.push(vertex);
            Ok(())
        })
        .unwrap();
        assert_eq!(ids, (1..=4).map(id).collect::<Vec<_>>());
        assert_eq!(
            view.visit_vertex_ids(&mut |_| Err(Sg0Error::Invariant)),
            Err(Sg0Error::Invariant)
        );
        let deadline = JobBudget::testing(std::time::Duration::from_millis(20)).unwrap();
        let view = View::new(&graph, None, None, &deadline);
        view.inventory().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(21));
        let mut callbacks = 0;
        assert_eq!(
            view.visit_vertex_ids(&mut |_| {
                callbacks += 1;
                Ok(())
            }),
            Err(Sg0Error::ResourceBudget)
        );
        assert_eq!(callbacks, 0);
        assert!(view.inventory.borrow().is_some());
    }

    #[test]
    fn disk_directory_graph_drops_entries_and_refuses_missing_current_or_staged_pages() {
        let (temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        let mut graph = DurableGraph::default();
        graph
            .attach_ancestry_reader(store.object_reader().unwrap(), [9; 32])
            .unwrap();
        store
            .begin_replay(b"synthetic directory publication fixture")
            .unwrap();
        for (label, parents) in [(1, &[][..]), (2, &[1][..]), (3, &[1][..])] {
            let mut prepared = graph
                .seal(synthetic_vertex(&graph, label, parents), &budget)
                .unwrap();
            let record = prepared.vertex().retained_record().unwrap();
            store
                .commit(&[&record], b"synthetic directory original")
                .unwrap();
            prepared.bind_retained_source(&record).unwrap();
            prepared
                .retain_ancestry(&graph, &mut store, &budget)
                .unwrap();
            graph.publish_checked(prepared, &budget).unwrap();
            let loaded = graph.get_owned(id(label), Some(&budget)).unwrap();
            let weak = Arc::downgrade(&loaded);
            drop(loaded);
            assert!(
                weak.upgrade().is_none(),
                "directory must not retain a vertex carrier"
            );
        }
        assert!(matches!(graph.vertices, VertexDirectory::Retained(..)));
        let fork = graph.clone();
        let old_directory = graph.retained_directory_pages();
        let old_index = graph.retained_index_pages();
        let old_order = graph.order(&budget).unwrap();
        let mut prepared = graph
            .seal(synthetic_vertex(&graph, 4, &[2, 3]), &budget)
            .unwrap();
        let record = prepared.vertex().retained_record().unwrap();
        store
            .commit(&[&record], b"synthetic fourth directory original")
            .unwrap();
        prepared.bind_retained_source(&record).unwrap();
        prepared
            .retain_ancestry(&graph, &mut store, &budget)
            .unwrap();
        let staged = VertexDirectory::from_retained(
            prepared.directory.as_ref().unwrap().clone(),
            RetainedVertex::from_directory,
        )
        .retained_ids()[0];
        let path = temp
            .path()
            .join("store")
            .join(format!("{}.obj", hex::encode(staged)));
        let held = path.with_extension("held");
        std::fs::rename(&path, &held).unwrap();
        assert!(matches!(
            graph.publish_checked(prepared, &budget),
            Err(Error::Io(_))
        ));
        assert_eq!(graph.len(), 3);
        assert_eq!(graph.retained_directory_pages(), old_directory);
        assert_eq!(graph.retained_index_pages(), old_index);
        assert_eq!(graph.order(&budget).unwrap(), old_order);
        std::fs::rename(&held, &path).unwrap();
        let mut prepared = graph
            .seal(synthetic_vertex(&graph, 4, &[2, 3]), &budget)
            .unwrap();
        prepared.bind_retained_source(&record).unwrap();
        let head = store.head();
        let path = temp
            .path()
            .join("store")
            .join(format!("{}.obj", hex::encode(old_directory[0])));
        let held = path.with_extension("held");
        std::fs::rename(&path, &held).unwrap();
        assert!(matches!(
            graph.get_owned(id(2), Some(&budget)),
            Err(Error::Io(_))
        ));
        assert!(graph.find_checked(id(2), &budget).is_err());
        assert!(graph.export_retained_range(0, 3).is_err());
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
        assert_eq!(fork.order(&budget).unwrap(), old_order);
        assert_eq!(fork.retained_directory_pages(), old_directory);
    }

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
                facts: FactsRecord::Resident(Box::new(facts)),
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
    fn disk_facts_detaches_payload_restores_exact_original_and_preserves_const_borrow() {
        const fn borrow_facts(vertex: &VerifiedVertex) -> &ParentFacts {
            vertex.facts()
        }
        let (_temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        let mut graph = DurableGraph::default();
        graph
            .attach_ancestry_reader(store.object_reader().unwrap(), [9; 32])
            .unwrap();
        store
            .begin_replay(b"synthetic parent fact retention")
            .unwrap();
        let mut prepared = graph
            .seal(synthetic_vertex(&graph, 1, &[]), &budget)
            .unwrap();
        let expected = borrow_facts(prepared.vertex()).clone();
        let header = prepared.vertex().candidate().header.clone();
        let record = prepared.vertex().retained_record().unwrap();
        store
            .commit(&[&record], b"synthetic full original record")
            .unwrap();
        prepared.bind_retained_source(&record).unwrap();
        prepared
            .retain_ancestry(&graph, &mut store, &budget)
            .unwrap();
        let weak = Arc::downgrade(&prepared.vertex);
        graph.publish_checked(prepared, &budget).unwrap();
        assert!(weak.upgrade().is_none());
        let retained = graph.get_owned(id(1), None).unwrap();
        let info = &retained.info;
        assert!(matches!(info.facts, FactsRecord::Retained { .. }));
        assert!(std::mem::size_of::<FactsRecord>() < std::mem::size_of::<ParentFacts>());
        let restored = info.execution_info(&record, &header).unwrap();
        assert_eq!(restored.facts.resident(), &expected);
        assert!(matches!(restored.facts, FactsRecord::Resident(_)));
        assert_eq!(
            graph
                .get_owned(id(1), None)
                .unwrap()
                .info
                .facts
                .restore(&header, expected.source_record)
                .unwrap()
                .resident(),
            &expected
        );
        let mut changed = record.clone();
        changed[12 + u32le(&record, 8).unwrap() as usize] ^= 1;
        assert!(info.execution_info(&changed, &header).is_err());
        assert_eq!(graph.len(), 1);
        assert_eq!(
            info.execution_info(&record, &header)
                .unwrap()
                .facts
                .resident(),
            &expected
        );
    }
    #[test]
    fn disk_facts_full_live_binding_refuses_any_changed_parent_payload_or_header_claim() {
        let graph = Graph::default();
        let vertex = synthetic_vertex(&graph, 1, &[]);
        let original = vertex.facts().clone();
        let header = vertex.candidate().header.clone();
        let retained = vertex.info.facts.retain();
        let mut source_record = original.source_record;
        source_record[183] ^= 1;
        assert!(retained.restore(&header, source_record).is_err());
        assert!(vertex.info.facts.restore(&header, source_record).is_err());
        for field in 0..7 {
            let mut changed = header.clone();
            match field {
                0 => changed.epoch ^= 1,
                1 => changed.daa[0] ^= 1,
                2 => changed.work += 1,
                3 => changed.source_index ^= 1,
                4 => changed.source_checkpoint[0] ^= 1,
                5 => changed.source_j[0] ^= 1,
                _ => changed.seed[0] ^= 1,
            }
            assert!(retained.restore(&changed, original.source_record).is_err());
        }
        let mut wrong = retained.clone();
        if let FactsRecord::Retained { minimum_time, .. } = &mut wrong {
            *minimum_time = 1;
        }
        assert!(wrong.restore(&header, original.source_record).is_err());
        let mut wrong = retained;
        if let FactsRecord::Retained { key_material, .. } = &mut wrong {
            key_material[0] ^= 1;
        }
        assert!(wrong.restore(&header, original.source_record).is_err());
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
        assert!(core.graph.get_owned(id(1), None).is_err());
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
    fn streamed_publication_crosses_directory_page_and_refuses_late_pages_atomically() {
        let (temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        let mut graph = DurableGraph::default();
        graph
            .attach_ancestry_reader(store.object_reader().unwrap(), [9; 32])
            .unwrap();
        store
            .begin_replay(b"synthetic streamed graph publication")
            .unwrap();
        for label in 1..=65 {
            let parents = if label == 1 { vec![] } else { vec![label - 1] };
            let mut prepared = graph
                .seal(synthetic_vertex(&graph, label, &parents), &budget)
                .unwrap();
            let record = prepared.vertex().retained_record().unwrap();
            store
                .commit(&[&record], b"synthetic public record")
                .unwrap();
            prepared.bind_retained_source(&record).unwrap();
            prepared
                .retain_ancestry(&graph, &mut store, &budget)
                .unwrap();
            graph.publish_checked(prepared, &budget).unwrap();
        }
        let prior = graph.index.materialize(Some(&budget)).unwrap();
        let mut expected = prior.clone();
        expected.insert(id(66), 65);
        let mut prepared = graph
            .seal(synthetic_vertex(&graph, 66, &[65]), &budget)
            .unwrap();
        let record = prepared.vertex().retained_record().unwrap();
        store
            .commit(&[&record], b"synthetic final public record")
            .unwrap();
        prepared.bind_retained_source(&record).unwrap();
        prepared
            .retain_ancestry(&graph, &mut store, &budget)
            .unwrap();
        let oracle = VertexIndex::retain(&expected, &mut store, [9; 32], &budget).unwrap();
        assert_eq!(
            prepared.index.as_ref().unwrap().retained_ids(),
            oracle.retained_ids()
        );
        let current_tail = graph.vertices.retained_ids()[1];
        let next_tail = prepared.directory.as_ref().unwrap();
        let next_ids = VertexDirectory::<RetainedVertex>::from_retained(
            next_tail.clone(),
            RetainedVertex::from_directory,
        )
        .retained_ids();
        let index_tail = prepared.index.as_ref().unwrap().retained_ids()[1];
        for missing in [current_tail, next_ids[1], index_tail] {
            let path = temp
                .path()
                .join("store")
                .join(format!("{}.obj", hex::encode(missing)));
            let held = path.with_extension("held");
            std::fs::rename(&path, &held).unwrap();
            // Fresh receiver-owned staging each time; failed publication cannot
            // leak either directory or index credit to the current graph.
            let attempt = PreparedVertex {
                vertex: prepared.vertex.clone(),
                revision: prepared.revision,
                index: prepared.index.clone(),
                directory: prepared.directory.clone(),
            };
            assert!(graph.publish_checked(attempt, &budget).is_err());
            assert_eq!(graph.len(), 65);
            std::fs::rename(&held, &path).unwrap();
            assert_eq!(graph.index.materialize(Some(&budget)).unwrap(), prior);
        }
        graph.publish_checked(prepared, &budget).unwrap();
        assert_eq!(graph.len(), 66);
        assert_eq!(graph.index.materialize(Some(&budget)).unwrap(), expected);
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
        assert!(matches!(graph.get_owned(id(2), None), Err(Error::Io(_))));
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
        assert!(
            durable
                .owned_vertices(None)
                .unwrap()
                .iter()
                .all(|v| v.bindings.is_empty())
        );
        assert!(
            durable
                .owned_vertices(None)
                .unwrap()
                .into_iter()
                .all(|v| matches!(v.info.header, HeaderRecord::Retained { .. }))
        );
        assert!(
            durable
                .owned_vertices(None)
                .unwrap()
                .into_iter()
                .all(|v| matches!(v.info.metadata, Some(Metadata::Retained { .. })))
        );
        assert!(
            durable
                .owned_vertices(None)
                .unwrap()
                .into_iter()
                .all(|v| matches!(v.info.facts, FactsRecord::Retained { .. }))
        );
        assert!(matches!(durable.index, VertexIndex::Retained(_)));
        let retained_view = View::new(&durable, None, None, &budget);
        let resident_view = View::new(&resident, None, None, &budget);
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
        let source = graph.get_owned(id(4), None).unwrap().source_id().unwrap();
        let path = temp
            .path()
            .join("store")
            .join(format!("{}.obj", hex::encode(source)));
        let held = path.with_extension("held");
        let original = std::fs::read(&path).unwrap();
        std::fs::rename(&path, &held).unwrap();
        let view = View::new(&graph, None, None, &budget);
        assert!(matches!(view.vertex_data(id(4)), Err(Sg0Error::Invariant)));
        assert!(graph.order(&budget).is_err());
        assert!(
            graph
                .seal(synthetic_vertex(&graph, 5, &[4]), &budget)
                .is_err()
        );
        assert_eq!(graph.len(), 4);
        assert!(graph.get_owned(id(5), None).is_err());
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
        assert!(durable.get_owned(id(1), None).is_err());
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
        assert!(durable.get_owned(id(1), None).is_err());
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
            .borrowed_iter()
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
            .borrowed_iter()
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
        let view = View::new(&graph, None, None, &budget);
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
        let view = View::new(&graph, None, Some(&members), &budget);
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
        let view = View::new(&branch, Some(&prepared.vertex().info), None, &budget);
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
