//! Synthetic multi-parent body-store and Gate 2 interval handoff.
//!
//! This module is a deliberately narrow host adapter. It verifies exact body
//! bytes, closes parent dependencies against a trusted Gate 2 checkpoint, and
//! emits a deterministic topological batch. It does not decide proof of work,
//! eligibility, rewards, finality, or consensus.

use sha2::{Digest, Sha256};
use silk_gate2::{
    BodyNamespaceKind, CanonicalDecode, CanonicalEncode, Hash32, MAX_BODIES, OrderedBodyV2,
    OrderedIntervalV1, ParentKind, TrustedExecutionBase, TrustedTransitionV2,
    VerifiedGate2ProfileV1, VerifiedOrderedIntervalV1,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use thiserror::Error;

const STORE_MAGIC: &[u8; 16] = b"SilkDagStoreV1\0\0";
const STORE_VERSION: u16 = 1;
const STORE_FIXED_BYTES: usize = STORE_MAGIC.len() + 2 + 2 + 32 + 32 + 1 + 4;
const STORE_RECORD_FIXED_BYTES: usize = 32 + 32 + 4;
const MAX_PERSISTED_STORE_BYTES: u64 = silk_gate2::MAX_INTERVAL_BYTES as u64
    + (STORE_RECORD_FIXED_BYTES as u64 * MAX_BODIES as u64)
    + STORE_FIXED_BYTES as u64;

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredBody {
    body: OrderedBodyV2,
    canonical_bytes: Vec<u8>,
    canonical_sha256: Hash32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DagContext {
    base_checkpoint_id: Hash32,
    base_body_ids: BTreeSet<Hash32>,
    profile_domain: Hash32,
    fenced: bool,
}

impl DagContext {
    fn from_trusted(
        base: &TrustedExecutionBase,
        profile: &VerifiedGate2ProfileV1,
    ) -> Result<Self, Gate2DagError> {
        if base.checkpoint().native_state.profile_domain != profile.profile().profile_domain {
            return Err(Gate2DagError::ProfileMismatch);
        }
        Ok(Self {
            base_checkpoint_id: base.checkpoint().checkpoint_id,
            base_body_ids: base
                .checkpoint()
                .ordered_body_history
                .iter()
                .copied()
                .collect(),
            profile_domain: profile.profile().profile_domain,
            fenced: base.effective_fence_id().is_some(),
        })
    }
}

/// A local, synthetic store of exact canonical Gate 2 body bytes.
///
/// Admission requires an independently supplied body ID and SHA-256 digest.
/// Those values are test inputs, not proof-of-work or network authority.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SyntheticGate2DagBodyStore {
    bodies: BTreeMap<Hash32, StoredBody>,
}

impl SyntheticGate2DagBodyStore {
    /// Creates an empty local body store.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bodies: BTreeMap::new(),
        }
    }

    /// Returns a deterministic inventory of every admitted canonical body.
    #[must_use]
    pub fn inventory(&self) -> Vec<SyntheticGate2DagBodyPin> {
        self.bodies
            .iter()
            .map(|(body_id, stored)| SyntheticGate2DagBodyPin {
                body_id: *body_id,
                canonical_sha256: stored.canonical_sha256,
                canonical_length: stored.canonical_bytes.len(),
            })
            .collect()
    }

    /// Returns exact canonical bytes for an admitted body identifier.
    #[must_use]
    pub fn canonical_body_bytes(&self, body_id: &Hash32) -> Option<&[u8]> {
        self.bodies
            .get(body_id)
            .map(|stored| stored.canonical_bytes.as_slice())
    }

    /// Admits one complete canonical body after exact ID and digest checks.
    ///
    /// Re-admission is rejected even when the bytes are identical. A caller
    /// therefore cannot silently replace or replay a stored body.
    ///
    /// # Errors
    ///
    /// Returns a stable [`Gate2DagError`] when bytes are malformed, the pin or
    /// ID does not match, or the ID is already present.
    pub fn admit(
        &mut self,
        expected_body_id: Hash32,
        expected_sha256: Hash32,
        canonical_body_bytes: &[u8],
    ) -> Result<(), Gate2DagError> {
        let actual_sha256: Hash32 = Sha256::digest(canonical_body_bytes).into();
        if actual_sha256 != expected_sha256 {
            return Err(Gate2DagError::BodyBytesMismatch);
        }
        let body = OrderedBodyV2::from_canonical_bytes(canonical_body_bytes)
            .map_err(|error| Gate2DagError::Canonical(error.as_code()))?;
        if body.body_id != expected_body_id {
            return Err(Gate2DagError::BodyIdMismatch);
        }
        if let Some(previous) = self.bodies.get(&expected_body_id) {
            return Err(
                if previous.canonical_bytes == canonical_body_bytes
                    && previous.canonical_sha256 == actual_sha256
                {
                    Gate2DagError::DuplicateBody
                } else {
                    Gate2DagError::BodyIdCollision
                },
            );
        }
        self.bodies.insert(
            expected_body_id,
            StoredBody {
                body,
                canonical_bytes: canonical_body_bytes.to_vec(),
                canonical_sha256: actual_sha256,
            },
        );
        Ok(())
    }

    /// Atomically persists this store in a compact deterministic local format.
    ///
    /// Only canonical body bytes, their supplied IDs and digests, the format
    /// version, and the trusted base/profile identity are stored. Readiness and
    /// quarantine state are reconstructed after restart rather than trusted
    /// from disk.
    ///
    /// # Errors
    ///
    /// Returns a stable [`Gate2DagError`] if the store is invalid for the
    /// supplied context, exceeds the local format bound, or cannot be written
    /// and synchronized atomically.
    pub fn persist(
        &self,
        path: &Path,
        base: &TrustedExecutionBase,
        profile: &VerifiedGate2ProfileV1,
    ) -> Result<SyntheticGate2DagStorePin, Gate2DagError> {
        let context = DagContext::from_trusted(base, profile)?;
        self.assemble_for_context(&context)?;
        let bytes = self.persisted_bytes(&context)?;
        let pin = SyntheticGate2DagStorePin::for_local_artifact(&bytes)?;
        atomic_write(path, &bytes)?;
        Ok(pin)
    }

    /// Reopens and fully revalidates a persisted store.
    ///
    /// The out-of-band pin is checked before parsing. Every record is then
    /// decoded through the Gate 2 canonical codec and the DAG context, replay,
    /// cycle, readiness, and quarantine rules are recomputed.
    ///
    /// # Errors
    ///
    /// Fails closed on I/O errors, links or special files, pin mismatch,
    /// truncation, unknown versions, malformed records, incompatible context,
    /// duplicate IDs, or any reconstructed DAG validation error.
    pub fn reopen(
        path: &Path,
        pin: SyntheticGate2DagStorePin,
        base: &TrustedExecutionBase,
        profile: &VerifiedGate2ProfileV1,
    ) -> Result<Self, Gate2DagError> {
        let metadata = fs::symlink_metadata(path).map_err(|_| Gate2DagError::PersistenceIo)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(Gate2DagError::PersistencePath);
        }
        if metadata.len() > MAX_PERSISTED_STORE_BYTES {
            return Err(Gate2DagError::PersistenceTooLarge);
        }
        if metadata.len() != pin.length {
            return Err(Gate2DagError::PersistencePinMismatch);
        }
        let mut file = File::open(path).map_err(|_| Gate2DagError::PersistenceIo)?;
        let capacity =
            usize::try_from(metadata.len()).map_err(|_| Gate2DagError::PersistenceTooLarge)?;
        let mut bytes = Vec::with_capacity(capacity);
        file.read_to_end(&mut bytes)
            .map_err(|_| Gate2DagError::PersistenceIo)?;
        if sha256(&bytes) != pin.sha256 {
            return Err(Gate2DagError::PersistencePinMismatch);
        }
        let context = DagContext::from_trusted(base, profile)?;
        Self::from_persisted_bytes(&bytes, &context)
    }

    /// Retains only bodies not materialized by an exact trusted seal.
    ///
    /// The transition must consume precisely the store's current ready order
    /// from the supplied base. The retained store is then revalidated against
    /// the trusted successor checkpoint before this store is changed. This is
    /// a local lifecycle operation; it neither chooses an order nor creates a
    /// checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`Gate2DagError::TrustedSealMismatch`] if the trusted transition
    /// does not bind the exact current base and ready body set. Other DAG
    /// validation failures are returned unchanged.
    pub fn retain_after_trusted_seal(
        &mut self,
        previous_base: &TrustedExecutionBase,
        profile: &VerifiedGate2ProfileV1,
        sealed: &TrustedTransitionV2,
    ) -> Result<(), Gate2DagError> {
        let assembly = self.assemble_ready_interval(previous_base, profile)?;
        let transition = sealed.transition();
        let successor = sealed.next_checkpoint().checkpoint();
        if &transition.previous != previous_base.checkpoint()
            || &transition.next != successor
            || successor.previous_checkpoint != previous_base.checkpoint().checkpoint_id
            || successor.bodies_in_checkpoint.as_slice() != assembly.ordered_body_ids()
        {
            return Err(Gate2DagError::TrustedSealMismatch);
        }

        let consumed = assembly
            .ordered_body_ids()
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let retained = self
            .bodies
            .iter()
            .filter(|(id, _)| !consumed.contains(*id))
            .map(|(id, body)| (*id, body.clone()))
            .collect();
        let candidate = Self { bodies: retained };
        let successor_base = sealed.next_checkpoint().clone().execution_base();
        candidate.assemble_ready_interval(&successor_base, profile)?;
        *self = candidate;
        Ok(())
    }

    /// Retains every body outside an explicitly selected closure after a trusted seal.
    ///
    /// The selection is supplied by a separate host policy and is revalidated
    /// here as a non-empty, bounded, ancestry-closed set. The trusted
    /// transition must consume exactly that set in this adapter's frozen
    /// topological order. Every non-selected body is retained and revalidated
    /// against the trusted successor before this store changes.
    ///
    /// This method does not select work, establish finality, or implement a
    /// fork choice. It only adapts an already selected synthetic closure to the
    /// trusted Gate 2 sealing boundary.
    ///
    /// # Errors
    ///
    /// Returns a stable [`Gate2DagError`] if the supplied selection is invalid,
    /// the transition binds a different base or ordered body set, or the
    /// retained store is invalid for the trusted successor.
    pub fn retain_after_selected_trusted_seal(
        &mut self,
        previous_base: &TrustedExecutionBase,
        profile: &VerifiedGate2ProfileV1,
        selected_body_ids: &[Hash32],
        sealed: &TrustedTransitionV2,
    ) -> Result<(), Gate2DagError> {
        let assembly =
            self.assemble_selected_closure_interval(previous_base, profile, selected_body_ids)?;
        let transition = sealed.transition();
        let successor = sealed.next_checkpoint().checkpoint();
        if &transition.previous != previous_base.checkpoint()
            || &transition.next != successor
            || successor.previous_checkpoint != previous_base.checkpoint().checkpoint_id
            || successor.bodies_in_checkpoint.as_slice() != assembly.ordered_body_ids()
        {
            return Err(Gate2DagError::SelectedTrustedSealMismatch);
        }

        let retained = assembly
            .retained_body_ids()
            .iter()
            .map(|id| (*id, self.bodies[id].clone()))
            .collect();
        let candidate = Self { bodies: retained };
        let successor_base = sealed.next_checkpoint().clone().execution_base();
        candidate.assemble_ready_interval(&successor_base, profile)?;
        *self = candidate;
        Ok(())
    }

    /// Removes bodies materialized by one independently replayed transition.
    ///
    /// Catch-up may replay a valid interval whose bodies were never admitted
    /// to this local store. Any overlapping local body must nevertheless match
    /// the exact canonical interval body. The adapter then retains every other
    /// body and revalidates it against the locally recomputed successor.
    ///
    /// This method neither trusts a remote checkpoint nor chooses between
    /// histories. Its inputs must already have passed Gate 2 promotion and
    /// transition replay from `previous_base`.
    ///
    /// # Errors
    ///
    /// Fails when the replayed transition does not consume the exact verified
    /// interval, an overlapping local body has different canonical bytes, or
    /// the retained DAG is invalid for the recomputed successor.
    pub fn retain_after_replayed_transition(
        &mut self,
        previous_base: &TrustedExecutionBase,
        profile: &VerifiedGate2ProfileV1,
        interval: &VerifiedOrderedIntervalV1,
        sealed: &TrustedTransitionV2,
    ) -> Result<(), Gate2DagError> {
        self.assemble_ready_interval(previous_base, profile)?;
        let transition = sealed.transition();
        let successor = sealed.next_checkpoint().checkpoint();
        let interval_ids = interval
            .interval()
            .bodies
            .iter()
            .map(|body| body.body_id)
            .collect::<Vec<_>>();
        if &transition.previous != previous_base.checkpoint()
            || &transition.next != successor
            || successor.previous_checkpoint != previous_base.checkpoint().checkpoint_id
            || successor.bodies_in_checkpoint.as_slice() != interval_ids
            || successor.body_bindings_in_checkpoint.as_slice() != interval.body_bindings()
        {
            return Err(Gate2DagError::ReplayedTransitionMismatch);
        }

        for body in &interval.interval().bodies.0 {
            if let Some(stored) = self.bodies.get(&body.body_id)
                && stored.canonical_bytes
                    != body
                        .canonical_bytes()
                        .map_err(|error| Gate2DagError::Canonical(error.as_code()))?
            {
                return Err(Gate2DagError::ReplayedBodyConflict);
            }
        }

        let consumed = interval_ids.into_iter().collect::<BTreeSet<_>>();
        let retained = self
            .bodies
            .iter()
            .filter(|(id, _)| !consumed.contains(*id))
            .map(|(id, body)| (*id, body.clone()))
            .collect();
        let candidate = Self { bodies: retained };
        let successor_base = sealed.next_checkpoint().clone().execution_base();
        candidate.assemble_ready_interval(&successor_base, profile)?;
        *self = candidate;
        Ok(())
    }

    fn persisted_bytes(&self, context: &DagContext) -> Result<Vec<u8>, Gate2DagError> {
        if self.bodies.len() > MAX_BODIES {
            return Err(Gate2DagError::PersistenceTooLarge);
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(STORE_MAGIC);
        bytes.extend_from_slice(&STORE_VERSION.to_le_bytes());
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        bytes.extend_from_slice(&context.base_checkpoint_id);
        bytes.extend_from_slice(&context.profile_domain);
        bytes.push(u8::from(context.fenced));
        let count =
            u32::try_from(self.bodies.len()).map_err(|_| Gate2DagError::PersistenceTooLarge)?;
        bytes.extend_from_slice(&count.to_le_bytes());
        for (id, stored) in &self.bodies {
            bytes.extend_from_slice(id);
            bytes.extend_from_slice(&stored.canonical_sha256);
            let length = u32::try_from(stored.canonical_bytes.len())
                .map_err(|_| Gate2DagError::PersistenceTooLarge)?;
            bytes.extend_from_slice(&length.to_le_bytes());
            bytes.extend_from_slice(&stored.canonical_bytes);
        }
        if u64::try_from(bytes.len()).map_err(|_| Gate2DagError::PersistenceTooLarge)?
            > MAX_PERSISTED_STORE_BYTES
        {
            return Err(Gate2DagError::PersistenceTooLarge);
        }
        Ok(bytes)
    }

    fn from_persisted_bytes(bytes: &[u8], context: &DagContext) -> Result<Self, Gate2DagError> {
        let mut decoder = StoreDecoder::new(bytes);
        if decoder.take(STORE_MAGIC.len())? != STORE_MAGIC {
            return Err(Gate2DagError::PersistenceCorrupt);
        }
        if decoder.u16()? != STORE_VERSION {
            return Err(Gate2DagError::PersistenceVersion);
        }
        if decoder.u16()? != 0 {
            return Err(Gate2DagError::PersistenceCorrupt);
        }
        if decoder.hash32()? != context.base_checkpoint_id
            || decoder.hash32()? != context.profile_domain
            || decoder.u8()? != u8::from(context.fenced)
        {
            return Err(Gate2DagError::PersistenceContext);
        }
        let count =
            usize::try_from(decoder.u32()?).map_err(|_| Gate2DagError::PersistenceTooLarge)?;
        if count > MAX_BODIES {
            return Err(Gate2DagError::PersistenceTooLarge);
        }
        let mut store = Self::new();
        let mut previous_id = None;
        for _ in 0..count {
            let id = decoder.hash32()?;
            if previous_id.is_some_and(|previous| id <= previous) {
                return Err(if previous_id == Some(id) {
                    Gate2DagError::BodyIdCollision
                } else {
                    Gate2DagError::PersistenceCorrupt
                });
            }
            previous_id = Some(id);
            let body_sha256 = decoder.hash32()?;
            let length =
                usize::try_from(decoder.u32()?).map_err(|_| Gate2DagError::PersistenceTooLarge)?;
            if length > silk_gate2::MAX_BODY_BYTES {
                return Err(Gate2DagError::PersistenceTooLarge);
            }
            let body_bytes = decoder.take(length)?;
            store.admit(id, body_sha256, body_bytes)?;
        }
        decoder.finish()?;
        store.assemble_for_context(context)?;
        Ok(store)
    }

    /// Orders every currently ready body and encodes one Gate 2 interval.
    ///
    /// Parents already present in the trusted checkpoint are satisfied.
    /// Admitted bodies with missing ancestors, plus their descendants, remain
    /// pending and are excluded. Ready ties use ascending body ID solely to
    /// make this synthetic handoff independent of arrival order.
    ///
    /// The returned bytes remain unverified. The Gate 2 decoder and trusted
    /// promotion boundary must still accept them before execution.
    ///
    /// # Errors
    ///
    /// Fails closed on replay, cycles, profile/namespace mismatch, unsupported
    /// fenced context, or a ready batch above the Gate 2 interval bound.
    pub fn assemble_ready_interval(
        &self,
        base: &TrustedExecutionBase,
        profile: &VerifiedGate2ProfileV1,
    ) -> Result<SyntheticGate2DagAssembly, Gate2DagError> {
        self.assemble_for_context(&DagContext::from_trusted(base, profile)?)
    }

    /// Encodes one deterministic Gate 2 interval from an explicit body closure.
    ///
    /// A separate host policy supplies the selected body IDs. This adapter
    /// requires that list to be non-empty, unique, known, bounded, and closed
    /// over every parent not already present in trusted checkpoint history. It
    /// then orders only the selected bodies topologically, breaking ready ties
    /// by ascending body ID. Arrival order and map iteration cannot affect the
    /// result.
    ///
    /// The returned bytes remain unverified and must pass the Gate 2 decoder
    /// and trusted promotion boundary. This is a host adapter for synthetic
    /// experiments; it does not choose a selection policy, cumulative work,
    /// consensus, finality, or fork choice.
    ///
    /// # Errors
    ///
    /// Fails closed when the context or stored DAG is invalid, or when the
    /// explicit selection is empty, duplicated, unknown, too large, or not an
    /// ancestry-closed body set relative to the trusted checkpoint.
    pub fn assemble_selected_closure_interval(
        &self,
        base: &TrustedExecutionBase,
        profile: &VerifiedGate2ProfileV1,
        selected_body_ids: &[Hash32],
    ) -> Result<SyntheticGate2DagSelectedAssembly, Gate2DagError> {
        self.assemble_selected_for_context(
            &DagContext::from_trusted(base, profile)?,
            selected_body_ids,
        )
    }

    fn assemble_selected_for_context(
        &self,
        context: &DagContext,
        selected_body_ids: &[Hash32],
    ) -> Result<SyntheticGate2DagSelectedAssembly, Gate2DagError> {
        if selected_body_ids.is_empty() {
            return Err(Gate2DagError::EmptySelection);
        }
        if selected_body_ids.len() > MAX_BODIES {
            return Err(Gate2DagError::TooManySelectedBodies);
        }
        if context.fenced {
            return Err(Gate2DagError::UnsupportedFencedContext);
        }
        self.validate_bodies(context)?;
        self.reject_cycles()?;

        let mut selected = BTreeSet::new();
        for id in selected_body_ids {
            if !selected.insert(*id) {
                return Err(Gate2DagError::DuplicateSelectedBody);
            }
            if !self.bodies.contains_key(id) {
                return Err(Gate2DagError::UnknownSelectedBody);
            }
        }

        for id in &selected {
            if self.bodies[id].body.namespace.parents.iter().any(|parent| {
                !context.base_body_ids.contains(&parent.parent_id)
                    && !selected.contains(&parent.parent_id)
            }) {
                return Err(Gate2DagError::SelectedAncestryNotClosed);
            }
        }

        let mut satisfied = context.base_body_ids.clone();
        let mut remaining = selected.clone();
        let mut ordered_ids = Vec::with_capacity(selected.len());
        while !remaining.is_empty() {
            let ready = remaining.iter().copied().find(|id| {
                self.bodies[id]
                    .body
                    .namespace
                    .parents
                    .iter()
                    .all(|parent| satisfied.contains(&parent.parent_id))
            });
            let Some(id) = ready else {
                // The full admitted graph was checked above, so reaching this
                // branch means the selected subgraph cannot be materialized
                // as an ancestry-closed acyclic interval.
                return Err(Gate2DagError::SelectedAncestryNotClosed);
            };
            remaining.remove(&id);
            satisfied.insert(id);
            ordered_ids.push(id);
        }

        let ordered_bodies = ordered_ids
            .iter()
            .map(|id| self.bodies[id].body.clone())
            .collect::<Vec<_>>();
        let interval_bytes = OrderedIntervalV1 {
            bodies: ordered_bodies.into(),
        }
        .canonical_bytes()
        .map_err(|error| Gate2DagError::Canonical(error.as_code()))?;
        let retained_body_ids = self
            .bodies
            .keys()
            .filter(|id| !selected.contains(*id))
            .copied()
            .collect();

        Ok(SyntheticGate2DagSelectedAssembly {
            ordered_body_ids: ordered_ids,
            retained_body_ids,
            interval_bytes,
        })
    }

    fn assemble_for_context(
        &self,
        context: &DagContext,
    ) -> Result<SyntheticGate2DagAssembly, Gate2DagError> {
        if context.fenced {
            return Err(Gate2DagError::UnsupportedFencedContext);
        }
        self.validate_bodies(context)?;
        self.reject_cycles()?;

        let mut satisfied = context.base_body_ids.clone();
        let mut remaining = self.bodies.keys().copied().collect::<BTreeSet<_>>();
        let mut ordered_ids = Vec::new();

        loop {
            let ready = remaining.iter().copied().find(|id| {
                self.bodies[id]
                    .body
                    .namespace
                    .parents
                    .iter()
                    .all(|parent| satisfied.contains(&parent.parent_id))
            });
            let Some(id) = ready else {
                break;
            };
            remaining.remove(&id);
            satisfied.insert(id);
            ordered_ids.push(id);
            if ordered_ids.len() > MAX_BODIES {
                return Err(Gate2DagError::TooManyReadyBodies);
            }
        }

        let ordered_bodies = ordered_ids
            .iter()
            .map(|id| self.bodies[id].body.clone())
            .collect::<Vec<_>>();
        let interval_bytes = if ordered_bodies.is_empty() {
            None
        } else {
            Some(
                OrderedIntervalV1 {
                    bodies: ordered_bodies.into(),
                }
                .canonical_bytes()
                .map_err(|error| Gate2DagError::Canonical(error.as_code()))?,
            )
        };
        Ok(SyntheticGate2DagAssembly {
            ordered_body_ids: ordered_ids,
            pending_body_ids: remaining.into_iter().collect(),
            interval_bytes,
        })
    }

    fn validate_bodies(&self, context: &DagContext) -> Result<(), Gate2DagError> {
        for (id, stored) in &self.bodies {
            if context.base_body_ids.contains(id) {
                return Err(Gate2DagError::ReplayedBody);
            }
            let namespace = &stored.body.namespace;
            if namespace.namespace_kind != BodyNamespaceKind::Unfenced
                || namespace.profile_domain != context.profile_domain
                || namespace.active_fence_id.is_some()
                || namespace.parents.iter().any(|parent| {
                    parent.parent_kind != ParentKind::Body
                        || parent.profile_domain != context.profile_domain
                        || parent.lineage_fence_id.is_some()
                })
            {
                return Err(Gate2DagError::NamespaceMismatch);
            }
        }
        Ok(())
    }

    fn reject_cycles(&self) -> Result<(), Gate2DagError> {
        fn visit(
            id: Hash32,
            bodies: &BTreeMap<Hash32, StoredBody>,
            active: &mut BTreeSet<Hash32>,
            complete: &mut BTreeSet<Hash32>,
        ) -> Result<(), Gate2DagError> {
            if complete.contains(&id) {
                return Ok(());
            }
            if !active.insert(id) {
                return Err(Gate2DagError::Cycle);
            }
            for parent in &bodies[&id].body.namespace.parents.0 {
                if bodies.contains_key(&parent.parent_id) {
                    visit(parent.parent_id, bodies, active, complete)?;
                }
            }
            active.remove(&id);
            complete.insert(id);
            Ok(())
        }

        let mut active = BTreeSet::new();
        let mut complete = BTreeSet::new();
        for id in self.bodies.keys().copied() {
            visit(id, &self.bodies, &mut active, &mut complete)?;
        }
        Ok(())
    }
}

/// Transport-neutral identity and size pin for one admitted canonical body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyntheticGate2DagBodyPin {
    body_id: Hash32,
    canonical_sha256: Hash32,
    canonical_length: usize,
}

impl SyntheticGate2DagBodyPin {
    /// Returns the body identifier carried by the canonical body.
    #[must_use]
    pub const fn body_id(self) -> Hash32 {
        self.body_id
    }

    /// Returns the SHA-256 digest of the exact canonical bytes.
    #[must_use]
    pub const fn canonical_sha256(self) -> Hash32 {
        self.canonical_sha256
    }

    /// Returns the exact canonical byte length.
    #[must_use]
    pub const fn canonical_length(self) -> usize {
        self.canonical_length
    }
}

/// Out-of-band integrity identity for one exact persisted store artifact.
///
/// This local pin detects accidental or uncoordinated file changes. Creating a
/// pin does not authenticate a peer, prove work, or grant consensus authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyntheticGate2DagStorePin {
    length: u64,
    sha256: Hash32,
}

impl SyntheticGate2DagStorePin {
    /// Computes the local identity of exact store bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Gate2DagError::PersistenceTooLarge`] when the bytes exceed the
    /// bounded prototype format.
    pub fn for_local_artifact(bytes: &[u8]) -> Result<Self, Gate2DagError> {
        let length = u64::try_from(bytes.len()).map_err(|_| Gate2DagError::PersistenceTooLarge)?;
        if length > MAX_PERSISTED_STORE_BYTES {
            return Err(Gate2DagError::PersistenceTooLarge);
        }
        Ok(Self {
            length,
            sha256: sha256(bytes),
        })
    }

    /// Returns the exact persisted byte length.
    #[must_use]
    pub const fn length(self) -> u64 {
        self.length
    }

    /// Returns the SHA-256 digest of the exact persisted bytes.
    #[must_use]
    pub const fn sha256(self) -> Hash32 {
        self.sha256
    }
}

fn sha256(bytes: &[u8]) -> Hash32 {
    Sha256::digest(bytes).into()
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), Gate2DagError> {
    let metadata = fs::symlink_metadata(path);
    if metadata
        .as_ref()
        .is_ok_and(|value| !value.is_file() || value.file_type().is_symlink())
    {
        return Err(Gate2DagError::PersistencePath);
    }
    if let Err(error) = metadata
        && error.kind() != std::io::ErrorKind::NotFound
    {
        return Err(Gate2DagError::PersistenceIo);
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().ok_or(Gate2DagError::PersistencePath)?;
    let mut temporary_name = file_name.to_os_string();
    temporary_name.push(".silknode-tmp");
    let temporary = parent.join(temporary_name);
    if fs::symlink_metadata(&temporary).is_ok() {
        return Err(Gate2DagError::PersistenceTemporaryExists);
    }

    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .map_err(|_| Gate2DagError::PersistenceIo)?;
        file.write_all(bytes)
            .map_err(|_| Gate2DagError::PersistenceIo)?;
        file.sync_all().map_err(|_| Gate2DagError::PersistenceIo)?;
        drop(file);
        fs::rename(&temporary, path).map_err(|_| Gate2DagError::PersistenceIo)?;
        #[cfg(unix)]
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| Gate2DagError::PersistenceIo)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

struct StoreDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> StoreDecoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], Gate2DagError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(Gate2DagError::PersistenceTooLarge)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(Gate2DagError::PersistenceTruncated)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, Gate2DagError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Gate2DagError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, Gate2DagError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn hash32(&mut self) -> Result<Hash32, Gate2DagError> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    const fn finish(self) -> Result<(), Gate2DagError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(Gate2DagError::PersistenceCorrupt)
        }
    }
}

/// One deterministic ready batch plus bodies still blocked on unavailable ancestors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntheticGate2DagAssembly {
    ordered_body_ids: Vec<Hash32>,
    pending_body_ids: Vec<Hash32>,
    interval_bytes: Option<Vec<u8>>,
}

impl SyntheticGate2DagAssembly {
    /// Returns ready body IDs in deterministic topological order.
    #[must_use]
    pub fn ordered_body_ids(&self) -> &[Hash32] {
        &self.ordered_body_ids
    }

    /// Returns admitted body IDs excluded because an ancestor is unavailable.
    #[must_use]
    pub fn pending_body_ids(&self) -> &[Hash32] {
        &self.pending_body_ids
    }

    /// Returns canonical unverified Gate 2 interval bytes when any body is ready.
    #[must_use]
    pub fn interval_bytes(&self) -> Option<&[u8]> {
        self.interval_bytes.as_deref()
    }
}

/// One explicitly selected synthetic closure prepared for Gate 2 handoff.
///
/// Selection is performed outside this type. The adapter records the frozen
/// topological order and the non-selected body IDs that must survive a trusted
/// seal for later host-policy reconsideration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntheticGate2DagSelectedAssembly {
    ordered_body_ids: Vec<Hash32>,
    retained_body_ids: Vec<Hash32>,
    interval_bytes: Vec<u8>,
}

impl SyntheticGate2DagSelectedAssembly {
    /// Returns selected IDs in deterministic topological order.
    #[must_use]
    pub fn ordered_body_ids(&self) -> &[Hash32] {
        &self.ordered_body_ids
    }

    /// Returns every admitted non-selected ID in ascending canonical order.
    #[must_use]
    pub fn retained_body_ids(&self) -> &[Hash32] {
        &self.retained_body_ids
    }

    /// Returns the canonical unverified Gate 2 interval bytes.
    #[must_use]
    pub fn interval_bytes(&self) -> &[u8] {
        &self.interval_bytes
    }
}

/// Stable failures at the synthetic DAG-to-kernel handoff.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum Gate2DagError {
    /// Exact bytes differ from the independently supplied SHA-256 pin.
    #[error("body bytes differ from supplied pin")]
    BodyBytesMismatch,
    /// Decoded body ID differs from the independently supplied ID.
    #[error("decoded body id differs from supplied id")]
    BodyIdMismatch,
    /// Identical body bytes were admitted twice.
    #[error("body was admitted twice")]
    DuplicateBody,
    /// Different bytes attempted to reuse one body ID.
    #[error("different body bytes reuse one body id")]
    BodyIdCollision,
    /// A candidate body ID already exists in trusted checkpoint history.
    #[error("body replays trusted checkpoint history")]
    ReplayedBody,
    /// Body namespace or parent context differs from the active profile.
    #[error("body namespace does not match the active synthetic context")]
    NamespaceMismatch,
    /// This first slice deliberately supports only unfenced Gate 2 execution.
    #[error("fenced execution is outside this synthetic slice")]
    UnsupportedFencedContext,
    /// Admitted body dependencies contain a cycle.
    #[error("body dependencies contain a cycle")]
    Cycle,
    /// More ready bodies exist than one Gate 2 interval permits.
    #[error("ready body batch exceeds the Gate 2 interval bound")]
    TooManyReadyBodies,
    /// A selected-closure handoff must contain at least one body.
    #[error("selected body closure is empty")]
    EmptySelection,
    /// One body ID appears more than once in the explicit selection.
    #[error("selected body closure contains a duplicate id")]
    DuplicateSelectedBody,
    /// An explicit selection names a body that was not admitted.
    #[error("selected body closure contains an unknown id")]
    UnknownSelectedBody,
    /// A selected body depends on an unselected, untrusted ancestor.
    #[error("selected body closure is not ancestry closed")]
    SelectedAncestryNotClosed,
    /// An explicit selection exceeds the Gate 2 body-count bound.
    #[error("selected body closure exceeds the Gate 2 interval bound")]
    TooManySelectedBodies,
    /// Frozen Gate 2 canonical decoding or encoding rejected the bytes.
    #[error("Gate 2 canonical boundary rejected the body: {0}")]
    Canonical(&'static str),
    /// Trusted base and verified profile do not identify the same profile.
    #[error("trusted base and verified profile differ")]
    ProfileMismatch,
    /// A trusted transition does not consume this store's exact ready order.
    #[error("trusted seal does not match the ready DAG interval")]
    TrustedSealMismatch,
    /// A trusted transition does not consume the exact selected closure order.
    #[error("trusted seal does not match the selected DAG closure")]
    SelectedTrustedSealMismatch,
    /// A replayed transition does not bind its exact promoted interval.
    #[error("replayed transition does not match the verified DAG interval")]
    ReplayedTransitionMismatch,
    /// A local body ID overlaps replayed history with different canonical bytes.
    #[error("replayed transition conflicts with a local DAG body")]
    ReplayedBodyConflict,
    /// A local persistence operation failed.
    #[error("local DAG store I/O failed")]
    PersistenceIo,
    /// A persistence path is a link, special file, or otherwise invalid.
    #[error("local DAG store path is invalid")]
    PersistencePath,
    /// A stale temporary file blocks an atomic replacement.
    #[error("local DAG store temporary path already exists")]
    PersistenceTemporaryExists,
    /// Persisted bytes exceed the bounded prototype format.
    #[error("local DAG store exceeds its byte or record bound")]
    PersistenceTooLarge,
    /// Persisted length or digest differs from the out-of-band pin.
    #[error("local DAG store differs from its supplied pin")]
    PersistencePinMismatch,
    /// Persisted bytes end before a declared field or body record.
    #[error("local DAG store is truncated")]
    PersistenceTruncated,
    /// Persisted framing, ordering, or trailing bytes are invalid.
    #[error("local DAG store is corrupt")]
    PersistenceCorrupt,
    /// Persisted format version is unsupported.
    #[error("local DAG store version is unsupported")]
    PersistenceVersion,
    /// Persisted trusted base or profile context differs from the caller.
    #[error("local DAG store context is incompatible")]
    PersistenceContext,
}

impl Gate2DagError {
    /// Returns a stable host-layer diagnostic code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::BodyBytesMismatch => "dag.body_bytes_mismatch",
            Self::BodyIdMismatch => "dag.body_id_mismatch",
            Self::DuplicateBody => "dag.duplicate_body",
            Self::BodyIdCollision => "dag.body_id_collision",
            Self::ReplayedBody => "dag.replayed_body",
            Self::NamespaceMismatch => "dag.namespace_mismatch",
            Self::UnsupportedFencedContext => "dag.unsupported_fenced_context",
            Self::Cycle => "dag.cycle",
            Self::TooManyReadyBodies => "dag.too_many_ready_bodies",
            Self::EmptySelection => "dag.selection_empty",
            Self::DuplicateSelectedBody => "dag.selection_duplicate_body",
            Self::UnknownSelectedBody => "dag.selection_unknown_body",
            Self::SelectedAncestryNotClosed => "dag.selection_ancestry_not_closed",
            Self::TooManySelectedBodies => "dag.selection_too_many_bodies",
            Self::Canonical(code) => code,
            Self::ProfileMismatch => "dag.profile_mismatch",
            Self::TrustedSealMismatch => "dag.trusted_seal_mismatch",
            Self::SelectedTrustedSealMismatch => "dag.selected_trusted_seal_mismatch",
            Self::ReplayedTransitionMismatch => "dag.replayed_transition_mismatch",
            Self::ReplayedBodyConflict => "dag.replayed_body_conflict",
            Self::PersistenceIo => "dag.persistence_io",
            Self::PersistencePath => "dag.persistence_path",
            Self::PersistenceTemporaryExists => "dag.persistence_temporary_exists",
            Self::PersistenceTooLarge => "dag.persistence_too_large",
            Self::PersistencePinMismatch => "dag.persistence_pin_mismatch",
            Self::PersistenceTruncated => "dag.persistence_truncated",
            Self::PersistenceCorrupt => "dag.persistence_corrupt",
            Self::PersistenceVersion => "dag.persistence_version",
            Self::PersistenceContext => "dag.persistence_context",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use silk_gate2::{BodyNamespaceV1, ParentRefV1, SortedUniqueVec};

    fn hash(byte: u8) -> Hash32 {
        [byte; 32]
    }

    fn body_bytes(id: u8, profile: u8, parents: &[u8]) -> Vec<u8> {
        let mut references = parents
            .iter()
            .map(|parent| ParentRefV1 {
                parent_kind: ParentKind::Body,
                parent_id: hash(*parent),
                profile_domain: hash(profile),
                lineage_fence_id: None,
            })
            .collect::<Vec<_>>();
        references.sort_by_key(|parent| parent.canonical_bytes().unwrap());
        OrderedBodyV2 {
            body_id: hash(id),
            namespace: BodyNamespaceV1 {
                namespace_kind: BodyNamespaceKind::Unfenced,
                profile_domain: hash(profile),
                active_fence_id: None,
                parents: SortedUniqueVec::new(references),
            },
            envelopes: Vec::new().into(),
        }
        .canonical_bytes()
        .unwrap()
    }

    fn admit(store: &mut SyntheticGate2DagBodyStore, id: u8, bytes: &[u8]) {
        store
            .admit(hash(id), Sha256::digest(bytes).into(), bytes)
            .unwrap();
    }

    fn context(profile: u8, base: &[u8]) -> DagContext {
        DagContext {
            base_checkpoint_id: hash(0x70),
            base_body_ids: base.iter().map(|value| hash(*value)).collect(),
            profile_domain: hash(profile),
            fenced: false,
        }
    }

    #[test]
    fn multi_parent_merge_orders_independently_of_arrival() {
        let mut store = SyntheticGate2DagBodyStore::new();
        let branch_b = body_bytes(0x11, 0x90, &[0x01]);
        let branch_a = body_bytes(0x21, 0x90, &[0x01]);
        let merge = body_bytes(0x31, 0x90, &[0x11, 0x21]);
        admit(&mut store, 0x31, &merge);
        admit(&mut store, 0x21, &branch_a);
        admit(&mut store, 0x11, &branch_b);

        let assembly = store.assemble_for_context(&context(0x90, &[0x01])).unwrap();
        assert_eq!(
            assembly.ordered_body_ids(),
            &[hash(0x11), hash(0x21), hash(0x31)]
        );
        assert!(assembly.pending_body_ids().is_empty());
        let interval = OrderedIntervalV1::from_canonical_bytes(
            assembly.interval_bytes().expect("ready interval"),
        )
        .unwrap();
        assert_eq!(interval.bodies.len(), 3);
    }

    #[test]
    fn unavailable_ancestry_stays_pending_without_blocking_ready_branch() {
        let mut store = SyntheticGate2DagBodyStore::new();
        let ready = body_bytes(0x11, 0x90, &[0x01]);
        let blocked = body_bytes(0x21, 0x90, &[0xee]);
        let descendant = body_bytes(0x31, 0x90, &[0x21]);
        admit(&mut store, 0x31, &descendant);
        admit(&mut store, 0x21, &blocked);
        admit(&mut store, 0x11, &ready);

        let assembly = store.assemble_for_context(&context(0x90, &[0x01])).unwrap();
        assert_eq!(assembly.ordered_body_ids(), &[hash(0x11)]);
        assert_eq!(assembly.pending_body_ids(), &[hash(0x21), hash(0x31)]);
    }

    #[test]
    fn selected_closure_orders_only_selected_and_identifies_retained() {
        let mut store = SyntheticGate2DagBodyStore::new();
        let branch_a = body_bytes(0x11, 0x90, &[0x01]);
        let branch_b = body_bytes(0x21, 0x90, &[0x01]);
        let alternative = body_bytes(0x22, 0x90, &[0x01]);
        let merge = body_bytes(0x31, 0x90, &[0x11, 0x21]);
        let later = body_bytes(0x41, 0x90, &[0x31]);
        admit(&mut store, 0x41, &later);
        admit(&mut store, 0x31, &merge);
        admit(&mut store, 0x22, &alternative);
        admit(&mut store, 0x21, &branch_b);
        admit(&mut store, 0x11, &branch_a);

        let assembly = store
            .assemble_selected_for_context(
                &context(0x90, &[0x01]),
                &[hash(0x31), hash(0x21), hash(0x11)],
            )
            .unwrap();
        assert_eq!(
            assembly.ordered_body_ids(),
            &[hash(0x11), hash(0x21), hash(0x31)]
        );
        assert_eq!(assembly.retained_body_ids(), &[hash(0x22), hash(0x41)]);
        let interval = OrderedIntervalV1::from_canonical_bytes(assembly.interval_bytes()).unwrap();
        assert_eq!(interval.bodies.len(), 3);
    }

    #[test]
    fn selected_closure_rejects_invalid_explicit_sets() {
        let mut store = SyntheticGate2DagBodyStore::new();
        let branch_a = body_bytes(0x11, 0x90, &[0x01]);
        let branch_b = body_bytes(0x21, 0x90, &[0x01]);
        let merge = body_bytes(0x31, 0x90, &[0x11, 0x21]);
        admit(&mut store, 0x31, &merge);
        admit(&mut store, 0x21, &branch_b);
        admit(&mut store, 0x11, &branch_a);
        let active = context(0x90, &[0x01]);

        assert_eq!(
            store
                .assemble_selected_for_context(&active, &[])
                .unwrap_err()
                .code(),
            "dag.selection_empty"
        );
        assert_eq!(
            store
                .assemble_selected_for_context(&active, &[hash(0x11), hash(0x11)])
                .unwrap_err()
                .code(),
            "dag.selection_duplicate_body"
        );
        assert_eq!(
            store
                .assemble_selected_for_context(&active, &[hash(0xff)])
                .unwrap_err()
                .code(),
            "dag.selection_unknown_body"
        );
        assert_eq!(
            store
                .assemble_selected_for_context(&active, &[hash(0x11), hash(0x31)])
                .unwrap_err()
                .code(),
            "dag.selection_ancestry_not_closed"
        );
        assert_eq!(
            store
                .assemble_selected_for_context(&active, &vec![hash(0x11); MAX_BODIES + 1])
                .unwrap_err()
                .code(),
            "dag.selection_too_many_bodies"
        );
    }

    #[test]
    fn exact_body_pin_id_and_duplicate_are_fail_closed() {
        let bytes = body_bytes(0x11, 0x90, &[0x01]);
        let mut store = SyntheticGate2DagBodyStore::new();
        assert_eq!(
            store
                .admit(hash(0x11), hash(0xff), &bytes)
                .unwrap_err()
                .code(),
            "dag.body_bytes_mismatch"
        );
        assert_eq!(
            store
                .admit(hash(0x12), Sha256::digest(&bytes).into(), &bytes)
                .unwrap_err()
                .code(),
            "dag.body_id_mismatch"
        );
        admit(&mut store, 0x11, &bytes);
        assert_eq!(
            store
                .admit(hash(0x11), Sha256::digest(&bytes).into(), &bytes)
                .unwrap_err()
                .code(),
            "dag.duplicate_body"
        );
    }

    #[test]
    fn cycles_replays_and_namespace_mismatches_reject() {
        let mut cyclic = SyntheticGate2DagBodyStore::new();
        let one = body_bytes(0x11, 0x90, &[0x21]);
        let two = body_bytes(0x21, 0x90, &[0x11]);
        admit(&mut cyclic, 0x11, &one);
        admit(&mut cyclic, 0x21, &two);
        assert_eq!(
            cyclic
                .assemble_for_context(&context(0x90, &[0x01]))
                .unwrap_err()
                .code(),
            "dag.cycle"
        );

        let mut replay = SyntheticGate2DagBodyStore::new();
        let bytes = body_bytes(0x11, 0x90, &[0x01]);
        admit(&mut replay, 0x11, &bytes);
        assert_eq!(
            replay
                .assemble_for_context(&context(0x90, &[0x11]))
                .unwrap_err()
                .code(),
            "dag.replayed_body"
        );
        assert_eq!(
            replay
                .assemble_for_context(&context(0x91, &[0x01]))
                .unwrap_err()
                .code(),
            "dag.namespace_mismatch"
        );
    }
}
