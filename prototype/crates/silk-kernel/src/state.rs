//! Immutable checkpoint state and its canonical commitment.

use std::collections::{BTreeMap, BTreeSet};

use silk_profile::ExecutionProfile;
use silk_types::{
    BodyCommitment, CanonicalEncode, ChainDomain, CheckpointId, Encoder, Hash32, IntentId,
    NoteCommitment, Nullifier, ProfileDomain, VertexId, domain_hash,
};

use crate::{
    GenesisAllocationTemplate, KernelError, NativeNote, NativeStateProjection, RecoveryRecord,
    StateInvariantError,
};

const STATE_DOMAIN: &[u8] = b"Silk-Transparent-State-v1";
const CHECKPOINT_DOMAIN: &[u8] = b"Silk-Transparent-Checkpoint-v1";
const STATE_ENCODING_VERSION: u8 = 1;

/// The source-body context of one effect accepted by a checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptedEffect {
    /// Fully available source body selected by the ordering layer.
    pub body_id: VertexId,
    /// Accepted anchor-independent transaction intent.
    pub intent_id: IntentId,
}

impl CanonicalEncode for AcceptedEffect {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), silk_types::EncodeError> {
        crate::codec::encode_accepted_effect(self, encoder)
    }
}

impl AcceptedEffect {
    pub(crate) fn encode_state_digest_projection(
        &self,
        encoder: &mut Encoder,
    ) -> Result<(), silk_types::EncodeError> {
        self.body_id.encode(encoder)?;
        self.intent_id.encode(encoder)
    }
}

#[allow(clippy::redundant_pub_crate)]
pub(super) struct CheckpointStateParts {
    pub(super) chain_domain: ChainDomain,
    pub(super) profile_domain: ProfileDomain,
    pub(super) checkpoint_id: CheckpointId,
    pub(super) previous_checkpoint: CheckpointId,
    pub(super) checkpoint_index: u64,
    pub(super) live_notes: BTreeMap<NoteCommitment, NativeNote>,
    pub(super) nullifiers: BTreeSet<Nullifier>,
    pub(super) commitment_history: BTreeSet<NoteCommitment>,
    pub(super) recovery_history: Vec<RecoveryRecord>,
    pub(super) ordered_body_history: Vec<VertexId>,
    pub(super) bodies_in_checkpoint: Vec<VertexId>,
    pub(super) body_bindings_in_checkpoint: Vec<BodyCommitment>,
    pub(super) accepted_intents: BTreeSet<IntentId>,
    pub(super) accepted_effects_in_checkpoint: Vec<AcceptedEffect>,
    pub(super) native_issued: u128,
    pub(super) fee_pool: u128,
}

/// Read-only native-kernel projection of one immutable checkpoint.
///
/// The evaluator cannot observe checkpoint-only body bindings or mutate any
/// state through this view.
pub struct BaseNativeStateView<'a> {
    state: &'a CheckpointState,
}

impl<'a> BaseNativeStateView<'a> {
    pub(crate) const fn new(state: &'a CheckpointState) -> Self {
        Self { state }
    }

    pub(crate) const fn chain_domain(&self) -> ChainDomain {
        self.state.chain_domain
    }

    pub(crate) const fn profile_domain(&self) -> ProfileDomain {
        self.state.profile_domain
    }

    pub(crate) const fn checkpoint_id(&self) -> CheckpointId {
        self.state.checkpoint_id
    }

    pub(crate) fn live_note(&self, commitment: &NoteCommitment) -> Option<&'a NativeNote> {
        self.state.live_notes.get(commitment)
    }

    pub(crate) fn contains_nullifier(&self, nullifier: &Nullifier) -> bool {
        self.state.nullifiers.contains(nullifier)
    }

    pub(crate) fn contains_commitment(&self, commitment: &NoteCommitment) -> bool {
        self.state.commitment_history.contains(commitment)
    }

    pub(crate) fn contains_intent(&self, intent_id: &IntentId) -> bool {
        self.state.accepted_intents.contains(intent_id)
    }

    pub(crate) const fn fee_pool(&self) -> u128 {
        self.state.fee_pool
    }
}

/// One fully validated native effect awaiting checkpoint materialization.
pub struct NativeEffect {
    input_commitments: Vec<NoteCommitment>,
    nullifiers: Vec<Nullifier>,
    outputs: Vec<(NoteCommitment, NativeNote, RecoveryRecord)>,
    public_fee: u64,
}

impl NativeEffect {
    pub(crate) const fn new(
        input_commitments: Vec<NoteCommitment>,
        nullifiers: Vec<Nullifier>,
        outputs: Vec<(NoteCommitment, NativeNote, RecoveryRecord)>,
        public_fee: u64,
    ) -> Self {
        Self {
            input_commitments,
            nullifiers,
            outputs,
            public_fee,
        }
    }
}

/// Accumulates validated native effects without access to mutable checkpoint state.
pub struct NativeEffectBuilder {
    input_commitments: Vec<NoteCommitment>,
    nullifiers: BTreeSet<Nullifier>,
    commitments: BTreeSet<NoteCommitment>,
    accepted_intents: BTreeSet<IntentId>,
    outputs: Vec<(NoteCommitment, NativeNote, RecoveryRecord)>,
    public_fee_delta: u128,
}

impl NativeEffectBuilder {
    pub(crate) const fn new() -> Self {
        Self {
            input_commitments: Vec::new(),
            nullifiers: BTreeSet::new(),
            commitments: BTreeSet::new(),
            accepted_intents: BTreeSet::new(),
            outputs: Vec::new(),
            public_fee_delta: 0,
        }
    }

    pub(crate) fn contains_nullifier(&self, nullifier: &Nullifier) -> bool {
        self.nullifiers.contains(nullifier)
    }

    pub(crate) fn contains_commitment(&self, commitment: &NoteCommitment) -> bool {
        self.commitments.contains(commitment)
    }

    pub(crate) fn contains_intent(&self, intent_id: &IntentId) -> bool {
        self.accepted_intents.contains(intent_id)
    }

    pub(crate) const fn current_fee_pool(&self, base: &BaseNativeStateView<'_>) -> Option<u128> {
        base.fee_pool().checked_add(self.public_fee_delta)
    }

    pub(crate) fn stage(
        &mut self,
        intent_id: IntentId,
        effect: NativeEffect,
    ) -> Result<(), KernelError> {
        let next_fee_delta = self
            .public_fee_delta
            .checked_add(u128::from(effect.public_fee))
            .ok_or(KernelError::InternalInvariant(
                "validated fee delta overflowed before atomic stage",
            ))?;
        if self.accepted_intents.contains(&intent_id)
            || effect
                .nullifiers
                .iter()
                .any(|nullifier| self.nullifiers.contains(nullifier))
            || effect
                .outputs
                .iter()
                .any(|(commitment, _, _)| self.commitments.contains(commitment))
        {
            return Err(KernelError::InternalInvariant(
                "validated effect conflicted before atomic stage",
            ));
        }

        self.input_commitments.extend(effect.input_commitments);
        self.nullifiers.extend(effect.nullifiers);
        for (commitment, note, record) in effect.outputs {
            self.commitments.insert(commitment);
            self.outputs.push((commitment, note, record));
        }
        self.accepted_intents.insert(intent_id);
        self.public_fee_delta = next_fee_delta;
        Ok(())
    }

    fn apply_native_effects(self, next: &mut CheckpointState) -> Result<(), KernelError> {
        for commitment in self.input_commitments {
            next.live_notes
                .remove(&commitment)
                .ok_or(KernelError::InternalInvariant(
                    "staged input disappeared before checkpoint materialization",
                ))?;
        }
        for nullifier in self.nullifiers {
            if !next.nullifiers.insert(nullifier) {
                return Err(KernelError::InternalInvariant(
                    "staged nullifier was not unique at checkpoint materialization",
                ));
            }
        }
        for (commitment, note, record) in self.outputs {
            if next.live_notes.insert(commitment, note).is_some()
                || !next.commitment_history.insert(commitment)
            {
                return Err(KernelError::InternalInvariant(
                    "staged commitment was not unique at checkpoint materialization",
                ));
            }
            next.recovery_history.push(record);
        }
        next.fee_pool = next.fee_pool.checked_add(self.public_fee_delta).ok_or(
            KernelError::InternalInvariant("staged fee overflowed at checkpoint materialization"),
        )?;
        for intent_id in self.accepted_intents {
            if !next.accepted_intents.insert(intent_id) {
                return Err(KernelError::InternalInvariant(
                    "staged intent was not unique at checkpoint materialization",
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn materialize_native_projection(
        self,
        base: &CheckpointState,
    ) -> Result<NativeStateProjection, KernelError> {
        let mut next = base.clone();
        self.apply_native_effects(&mut next)?;
        next.validate_native_projection()?;
        Ok(NativeStateProjection::from_checkpoint(&next))
    }

    pub(crate) fn seal_successor(
        self,
        base: &CheckpointState,
        bodies_in_checkpoint: Vec<VertexId>,
        body_bindings_in_checkpoint: Vec<BodyCommitment>,
        accepted_effects_in_checkpoint: Vec<AcceptedEffect>,
    ) -> Result<CheckpointState, KernelError> {
        let mut next = base.clone();
        self.apply_native_effects(&mut next)?;

        next.previous_checkpoint = base.checkpoint_id;
        next.checkpoint_index = base
            .checkpoint_index
            .checked_add(1)
            .ok_or(KernelError::CheckpointIndexOverflow)?;
        next.accepted_effects_in_checkpoint = accepted_effects_in_checkpoint;
        next.bodies_in_checkpoint = bodies_in_checkpoint;
        next.body_bindings_in_checkpoint = body_bindings_in_checkpoint;
        next.ordered_body_history
            .extend(next.bodies_in_checkpoint.iter().copied());
        next.checkpoint_id = CheckpointId::ZERO;
        next.validate()?;
        next.checkpoint_id = next.derive_checkpoint_id()?;
        Ok(next)
    }
}

/// A complete immutable checkpoint snapshot for the transparent native kernel.
///
/// Callers retain old values to roll back and replay from a common checkpoint.
/// No method mutates a previously returned snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointState {
    chain_domain: ChainDomain,
    profile_domain: ProfileDomain,
    checkpoint_id: CheckpointId,
    previous_checkpoint: CheckpointId,
    checkpoint_index: u64,
    live_notes: BTreeMap<NoteCommitment, NativeNote>,
    nullifiers: BTreeSet<Nullifier>,
    commitment_history: BTreeSet<NoteCommitment>,
    recovery_history: Vec<RecoveryRecord>,
    ordered_body_history: Vec<VertexId>,
    bodies_in_checkpoint: Vec<VertexId>,
    body_bindings_in_checkpoint: Vec<BodyCommitment>,
    accepted_intents: BTreeSet<IntentId>,
    accepted_effects_in_checkpoint: Vec<AcceptedEffect>,
    native_issued: u128,
    fee_pool: u128,
}

impl CheckpointState {
    pub(super) fn from_codec_parts(parts: CheckpointStateParts) -> Self {
        Self {
            chain_domain: parts.chain_domain,
            profile_domain: parts.profile_domain,
            checkpoint_id: parts.checkpoint_id,
            previous_checkpoint: parts.previous_checkpoint,
            checkpoint_index: parts.checkpoint_index,
            live_notes: parts.live_notes,
            nullifiers: parts.nullifiers,
            commitment_history: parts.commitment_history,
            recovery_history: parts.recovery_history,
            ordered_body_history: parts.ordered_body_history,
            bodies_in_checkpoint: parts.bodies_in_checkpoint,
            body_bindings_in_checkpoint: parts.body_bindings_in_checkpoint,
            accepted_intents: parts.accepted_intents,
            accepted_effects_in_checkpoint: parts.accepted_effects_in_checkpoint,
            native_issued: parts.native_issued,
            fee_pool: parts.fee_pool,
        }
    }

    /// Builds checkpoint zero from one bounded no-value transparent allocation template.
    ///
    /// Exact template bytes, including entry order, are checked against the
    /// trusted profile commitment before materialization. State entries are then
    /// sorted by their derived chain-bound commitments.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError`] for a duplicate commitment, trusted-template
    /// mismatch, arithmetic overflow, hashing failure, or derived invariant
    /// violation. This constructs the transparent checkpoint-zero allocation
    /// state; the leaf genesis crate binds it into the complete non-PoW state
    /// anchor.
    pub(super) fn genesis(
        execution_profile: &ExecutionProfile,
        allocation_template: GenesisAllocationTemplate,
    ) -> Result<Self, KernelError> {
        let actual_template_hash = allocation_template.template_hash()?;
        let expected_template_hash = execution_profile.genesis_allocation_template_hash();
        if actual_template_hash != expected_template_hash {
            return Err(KernelError::GenesisAllocationTemplateMismatch {
                expected: expected_template_hash,
                actual: actual_template_hash,
            });
        }

        let chain_domain = execution_profile.chain_domain();
        let profile_domain = execution_profile.profile_domain();
        let entries = allocation_template.into_entries();
        let mut keyed = Vec::with_capacity(entries.len());
        for entry in entries {
            let (note, recovery_payload) = entry.into_parts();
            let commitment = note.commitment(chain_domain)?;
            let recovery_record = RecoveryRecord {
                output_commitment: commitment,
                payload: recovery_payload,
            };
            keyed.push((commitment, note, recovery_record));
        }
        keyed.sort_by_key(|(commitment, _, _)| *commitment);
        if keyed.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(KernelError::DuplicateGenesisCommitment);
        }

        let mut native_issued = 0_u128;
        let mut live_notes = BTreeMap::new();
        let mut commitment_history = BTreeSet::new();
        let mut recovery_history = Vec::with_capacity(keyed.len());
        for (commitment, note, recovery_record) in keyed {
            native_issued = native_issued
                .checked_add(u128::from(note.value))
                .ok_or(KernelError::GenesisIssuanceOverflow)?;
            live_notes.insert(commitment, note);
            commitment_history.insert(commitment);
            recovery_history.push(recovery_record);
        }

        let mut state = Self {
            chain_domain,
            profile_domain,
            checkpoint_id: CheckpointId::ZERO,
            previous_checkpoint: CheckpointId::ZERO,
            checkpoint_index: 0,
            live_notes,
            nullifiers: BTreeSet::new(),
            commitment_history,
            recovery_history,
            ordered_body_history: Vec::new(),
            bodies_in_checkpoint: Vec::new(),
            body_bindings_in_checkpoint: Vec::new(),
            accepted_intents: BTreeSet::new(),
            accepted_effects_in_checkpoint: Vec::new(),
            native_issued,
            fee_pool: 0,
        };
        state.validate()?;
        state.checkpoint_id = state.derive_checkpoint_id()?;
        Ok(state)
    }

    /// Returns the immutable network identity.
    #[must_use]
    pub const fn chain_domain(&self) -> ChainDomain {
        self.chain_domain
    }

    /// Returns the active profile identity.
    #[must_use]
    pub const fn profile_domain(&self) -> ProfileDomain {
        self.profile_domain
    }

    /// Returns this snapshot's derived checkpoint identifier.
    #[must_use]
    pub const fn checkpoint_id(&self) -> CheckpointId {
        self.checkpoint_id
    }

    /// Returns the immediately preceding checkpoint identifier.
    #[must_use]
    pub const fn previous_checkpoint(&self) -> CheckpointId {
        self.previous_checkpoint
    }

    /// Returns the monotonically increasing checkpoint index.
    #[must_use]
    pub const fn checkpoint_index(&self) -> u64 {
        self.checkpoint_index
    }

    /// Returns all currently spendable transparent test notes by commitment.
    #[must_use]
    pub const fn live_notes(&self) -> &BTreeMap<NoteCommitment, NativeNote> {
        &self.live_notes
    }

    /// Returns the exact append-only set of consumed nullifiers.
    #[must_use]
    pub const fn nullifiers(&self) -> &BTreeSet<Nullifier> {
        &self.nullifiers
    }

    /// Returns every note commitment ever materialized in this lineage.
    #[must_use]
    pub const fn commitment_history(&self) -> &BTreeSet<NoteCommitment> {
        &self.commitment_history
    }

    /// Returns recovery records in their exact checkpoint append order.
    #[must_use]
    pub fn recovery_history(&self) -> &[RecoveryRecord] {
        &self.recovery_history
    }

    /// Returns all materialized body IDs in their authoritative execution order.
    #[must_use]
    pub fn ordered_body_history(&self) -> &[VertexId] {
        &self.ordered_body_history
    }

    /// Returns body IDs materialized by this checkpoint only.
    #[must_use]
    pub fn bodies_in_checkpoint(&self) -> &[VertexId] {
        &self.bodies_in_checkpoint
    }

    /// Returns exact execution-body bindings materialized by this checkpoint.
    ///
    /// Entries correspond one-to-one and in order with
    /// [`Self::bodies_in_checkpoint`].
    #[must_use]
    pub fn body_bindings_in_checkpoint(&self) -> &[BodyCommitment] {
        &self.body_bindings_in_checkpoint
    }

    /// Returns every transaction intent accepted in this checkpoint lineage.
    #[must_use]
    pub const fn accepted_intents(&self) -> &BTreeSet<IntentId> {
        &self.accepted_intents
    }

    /// Returns accepted intents with exact source-body execution context.
    #[must_use]
    pub fn accepted_effects_in_checkpoint(&self) -> &[AcceptedEffect] {
        &self.accepted_effects_in_checkpoint
    }

    /// Returns the fixed cumulative native issuance established at genesis.
    #[must_use]
    pub const fn native_issued(&self) -> u128 {
        self.native_issued
    }

    /// Returns accepted public fees not yet assigned by any reward extension.
    ///
    /// This slice implements no rewards. Keeping fees in an explicit pool makes
    /// them conserved native value rather than an accidental burn.
    #[must_use]
    pub const fn fee_pool(&self) -> u128 {
        self.fee_pool
    }

    /// Returns whether a commitment is live at exactly this checkpoint.
    #[must_use]
    pub fn contains_live_note(&self, commitment: NoteCommitment) -> bool {
        self.live_notes.contains_key(&commitment)
    }

    /// Computes the canonical logical-state digest, excluding `checkpoint_id`
    /// to avoid a self-referential hash.
    ///
    /// # Errors
    ///
    /// Returns an encoding or domain-hash error if the state cannot be committed.
    pub fn state_digest(&self) -> Result<Hash32, KernelError> {
        let mut encoder = Encoder::new();
        encoder.write_u8(STATE_ENCODING_VERSION);
        self.chain_domain.encode(&mut encoder)?;
        self.profile_domain.encode(&mut encoder)?;
        self.previous_checkpoint.encode(&mut encoder)?;
        self.checkpoint_index.encode(&mut encoder)?;

        encoder.write_len("live notes", self.live_notes.len())?;
        for (commitment, note) in &self.live_notes {
            commitment.encode(&mut encoder)?;
            note.encode(&mut encoder)?;
        }

        let nullifiers = self.nullifiers.iter().copied().collect::<Vec<_>>();
        encoder.write_sorted_unique(&nullifiers)?;
        let commitments = self.commitment_history.iter().copied().collect::<Vec<_>>();
        encoder.write_sorted_unique(&commitments)?;
        encoder.write_list(&self.recovery_history)?;
        encoder.write_list(&self.ordered_body_history)?;
        encoder.write_list(&self.bodies_in_checkpoint)?;
        encoder.write_list(&self.body_bindings_in_checkpoint)?;
        let intents = self.accepted_intents.iter().copied().collect::<Vec<_>>();
        encoder.write_sorted_unique(&intents)?;
        encoder.write_len(
            "accepted effects in checkpoint",
            self.accepted_effects_in_checkpoint.len(),
        )?;
        for effect in &self.accepted_effects_in_checkpoint {
            effect.encode_state_digest_projection(&mut encoder)?;
        }
        self.native_issued.encode(&mut encoder)?;
        self.fee_pool.encode(&mut encoder)?;

        domain_hash(STATE_DOMAIN, &[encoder.as_slice()]).map_err(KernelError::from)
    }

    /// Verifies exact commitment, nullifier, recovery, intent-order, and supply invariants.
    ///
    /// # Errors
    ///
    /// Returns a typed hashing failure or [`StateInvariantError`] at the first
    /// invariant violation in the fixed validation order.
    pub fn validate(&self) -> Result<(), KernelError> {
        validate_native_membership(
            self.chain_domain,
            &self.live_notes,
            &self.nullifiers,
            &self.commitment_history,
            &self.recovery_history,
        )?;

        if has_duplicates(
            self.accepted_effects_in_checkpoint
                .iter()
                .map(|effect| effect.intent_id),
        ) {
            return Err(StateInvariantError::DuplicateCheckpointIntent.into());
        }
        if self
            .accepted_effects_in_checkpoint
            .iter()
            .any(|effect| !self.accepted_intents.contains(&effect.intent_id))
        {
            return Err(StateInvariantError::AcceptedIntentMissingFromHistory.into());
        }
        if self
            .accepted_effects_in_checkpoint
            .iter()
            .any(|effect| !self.bodies_in_checkpoint.contains(&effect.body_id))
        {
            return Err(StateInvariantError::CheckpointBodyHistoryMismatch.into());
        }
        if has_duplicates(self.ordered_body_history.iter().copied()) {
            return Err(StateInvariantError::DuplicateOrderedBody.into());
        }
        if self.bodies_in_checkpoint.len() > self.ordered_body_history.len()
            || !self
                .ordered_body_history
                .ends_with(&self.bodies_in_checkpoint)
        {
            return Err(StateInvariantError::CheckpointBodyHistoryMismatch.into());
        }
        if self.body_bindings_in_checkpoint.len() != self.bodies_in_checkpoint.len() {
            return Err(StateInvariantError::CheckpointBodyBindingMismatch.into());
        }

        validate_native_supply(&self.live_notes, self.native_issued, self.fee_pool)
    }

    pub(crate) fn validate_native_projection(&self) -> Result<(), KernelError> {
        validate_native_membership(
            self.chain_domain,
            &self.live_notes,
            &self.nullifiers,
            &self.commitment_history,
            &self.recovery_history,
        )?;
        validate_native_supply(&self.live_notes, self.native_issued, self.fee_pool)
    }

    pub(crate) fn derive_checkpoint_id(&self) -> Result<CheckpointId, KernelError> {
        let state_digest = self.state_digest()?;
        self.derive_checkpoint_id_from_digest(state_digest)
    }

    pub(crate) fn derive_checkpoint_id_from_digest(
        &self,
        state_digest: Hash32,
    ) -> Result<CheckpointId, KernelError> {
        let index = self.checkpoint_index.to_le_bytes();
        domain_hash(
            CHECKPOINT_DOMAIN,
            &[
                self.chain_domain.as_bytes(),
                self.profile_domain.as_bytes(),
                &index,
                self.previous_checkpoint.as_bytes(),
                state_digest.as_bytes(),
            ],
        )
        .map(CheckpointId::new)
        .map_err(KernelError::from)
    }

    #[cfg(test)]
    pub(crate) const fn empty_for_test(
        chain_domain: ChainDomain,
        profile_domain: ProfileDomain,
    ) -> Self {
        Self {
            chain_domain,
            profile_domain,
            checkpoint_id: CheckpointId::ZERO,
            previous_checkpoint: CheckpointId::ZERO,
            checkpoint_index: 0,
            live_notes: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            commitment_history: BTreeSet::new(),
            recovery_history: Vec::new(),
            ordered_body_history: Vec::new(),
            bodies_in_checkpoint: Vec::new(),
            body_bindings_in_checkpoint: Vec::new(),
            accepted_intents: BTreeSet::new(),
            accepted_effects_in_checkpoint: Vec::new(),
            native_issued: 0,
            fee_pool: 0,
        }
    }

    #[cfg(test)]
    pub(crate) const fn replace_checkpoint_id_for_test(&mut self, checkpoint_id: CheckpointId) {
        self.checkpoint_id = checkpoint_id;
    }
}

#[allow(clippy::redundant_pub_crate)]
pub(super) fn validate_native_membership(
    chain_domain: ChainDomain,
    live_notes: &BTreeMap<NoteCommitment, NativeNote>,
    nullifiers: &BTreeSet<Nullifier>,
    commitment_history: &BTreeSet<NoteCommitment>,
    recovery_history: &[RecoveryRecord],
) -> Result<(), KernelError> {
    for (commitment, note) in live_notes {
        if note.commitment(chain_domain)? != *commitment {
            return Err(StateInvariantError::LiveCommitmentMismatch.into());
        }
        if !commitment_history.contains(commitment) {
            return Err(StateInvariantError::LiveCommitmentMissingFromHistory.into());
        }
        if nullifiers.contains(&note.nullifier(chain_domain)?) {
            return Err(StateInvariantError::LiveNoteAlreadySpent.into());
        }
    }

    let mut recovery_commitments = BTreeSet::new();
    for record in recovery_history {
        if !recovery_commitments.insert(record.output_commitment) {
            return Err(StateInvariantError::DuplicateRecoveryCommitment.into());
        }
    }
    if recovery_commitments != *commitment_history {
        return Err(StateInvariantError::RecoveryHistoryMismatch.into());
    }
    Ok(())
}

#[allow(clippy::redundant_pub_crate)]
pub(super) fn validate_native_supply(
    live_notes: &BTreeMap<NoteCommitment, NativeNote>,
    native_issued: u128,
    fee_pool: u128,
) -> Result<(), KernelError> {
    let live_value = live_notes
        .values()
        .try_fold(0_u128, |sum, note| sum.checked_add(u128::from(note.value)));
    let live_value = live_value.ok_or(StateInvariantError::SupplyOverflow)?;
    let accounted = live_value
        .checked_add(fee_pool)
        .ok_or(StateInvariantError::SupplyOverflow)?;
    if accounted != native_issued {
        return Err(StateInvariantError::SupplyMismatch.into());
    }
    Ok(())
}

fn has_duplicates<T: Ord>(values: impl IntoIterator<Item = T>) -> bool {
    let mut seen = BTreeSet::new();
    values.into_iter().any(|value| !seen.insert(value))
}
