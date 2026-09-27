//! Read-only evaluation and single-use sealing.

#![allow(missing_docs)]

use std::collections::BTreeSet;

use crate::{
    AcceptedEffectBodyV2, AuthorizationRole, BoundedVec, CanonicalEncode, CheckpointStateWireV2,
    ConsensusEnvelopeV1, DecisionBodyV2, DerivedRewardV1, EnvelopeTag, Error, Hash32,
    MAX_ACCEPTED_HISTORY, MAX_LIVE_NOTES, MAX_NATIVE_HISTORY, MAX_STATE_BYTES, MandateStateV1,
    NativeIntervalResultV2, NativeNoteV2, NativeStateV2, NoteType, OutcomeBodyV2, OutputRole,
    RecoveryKind, RecoveryRecordV2, RejectCode, RewardEventBodyV1, RewardOriginV1, ScopeKind,
    SyntheticMigrationEnvelopeV1, TransferEnvelopeV2, TransferKind, TransitionV2,
    TrustedCheckpointV2, TrustedExecutionBase, Unverified, VerifiedGate2ProfileV1,
    VerifiedOrderedIntervalV1, VerifiedSyntheticEligibilityReceiptV1, checkpoint_id, derive_reward,
    envelope_identity, fresh_trusted_checkpoint, lineage_from_successor,
    migration_statement_digest, note_commitment, note_nullifier, recovery_hash, schedule_subsidy,
    transfer_effect_digest,
};

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum PrivateNativeEffectV2 {
    Transfer(NativeEffectBody),
    Mandate(NativeEffectBody),
    ValueMigration(NativeEffectBody),
    SyntheticReward(SyntheticRewardEffectV1),
}

#[derive(Debug)]
struct NativeEffectBody {
    consumed_commitments: Vec<Hash32>,
    consumed_notes: Vec<NativeNoteV2>,
    nullifiers: Vec<Hash32>,
    outputs: Vec<(Hash32, NativeNoteV2, RecoveryRecordV2)>,
    public_fee: u64,
    accepted_effect: AcceptedEffectBodyV2,
    state_canonical_bytes_after_effect: usize,
    accepted_effect_canonical_bytes: usize,
}

#[derive(Debug)]
struct SyntheticRewardEffectV1 {
    event: RewardEventBodyV1,
}

#[derive(Debug)]
pub struct PrivateNativeIntervalPlanV1 {
    base: TrustedExecutionBase,
    profile: VerifiedGate2ProfileV1,
    interval_bytes: Vec<u8>,
    result: NativeIntervalResultV2,
    effects: Vec<PrivateNativeEffectV2>,
    body_ids: Vec<Hash32>,
    body_bindings: Vec<Hash32>,
    projected_checkpoint_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CanonicalCapacity {
    state_after_effect: usize,
    state_projection: usize,
    interval_result: usize,
    checkpoint: usize,
}

impl CanonicalCapacity {
    const fn fits(self, limit: usize) -> bool {
        self.state_projection <= limit && self.interval_result <= limit && self.checkpoint <= limit
    }
}

#[cfg(feature = "private-test-harness")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyntheticCanonicalCapacityV1 {
    pub state_after_effect: usize,
    pub state_projection: usize,
    pub interval_result: usize,
    pub checkpoint: usize,
}

#[cfg(feature = "private-test-harness")]
impl From<CanonicalCapacity> for SyntheticCanonicalCapacityV1 {
    fn from(value: CanonicalCapacity) -> Self {
        Self {
            state_after_effect: value.state_after_effect,
            state_projection: value.state_projection,
            interval_result: value.interval_result,
            checkpoint: value.checkpoint,
        }
    }
}

#[cfg(feature = "private-test-harness")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyntheticCapacityEvidenceV1 {
    pub preflight: SyntheticCanonicalCapacityV1,
    pub final_projection: SyntheticCanonicalCapacityV1,
}

#[derive(Debug)]
pub struct EvaluatedIntervalV2 {
    result: NativeIntervalResultV2,
    plan: PrivateNativeIntervalPlanV1,
    #[cfg(feature = "private-test-harness")]
    preflight_capacity: CanonicalCapacity,
    #[cfg(feature = "private-test-harness")]
    final_capacity: CanonicalCapacity,
}
impl EvaluatedIntervalV2 {
    pub const fn result(&self) -> &NativeIntervalResultV2 {
        &self.result
    }
    pub fn into_plan(self) -> PrivateNativeIntervalPlanV1 {
        self.plan
    }
    #[cfg(feature = "private-test-harness")]
    pub fn synthetic_capacity_evidence(&self) -> SyntheticCapacityEvidenceV1 {
        SyntheticCapacityEvidenceV1 {
            preflight: self.preflight_capacity.into(),
            final_projection: self.final_capacity.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedTransitionV2 {
    transition: TransitionV2,
    previous_base: TrustedExecutionBase,
    next_checkpoint: TrustedCheckpointV2,
}
impl TrustedTransitionV2 {
    pub const fn transition(&self) -> &TransitionV2 {
        &self.transition
    }
    pub const fn next_checkpoint(&self) -> &TrustedCheckpointV2 {
        &self.next_checkpoint
    }
    pub fn rollback(self) -> TrustedExecutionBase {
        self.previous_base
    }
}

fn execution_start_state(
    base: &TrustedExecutionBase,
    profile: &VerifiedGate2ProfileV1,
) -> NativeStateV2 {
    let mut state = base.checkpoint().native_state.clone();
    if let TrustedExecutionBase::Successor(successor) = base {
        let p = profile.profile();
        state.protocol_manifest_hash = p.protocol_manifest_hash;
        state.profile_domain = p.profile_domain;
        state.policy_phase_root = p.policy_phase_root;
        state.active_suite_ids = p.manifest_body.active_suite_ids.clone();
        state.retained_migration_source_suite_ids =
            p.manifest_body.retained_migration_source_suite_ids.clone();
        state.reward_suite_id = p.manifest_body.reward_suite_id;
        state.mandate_suite_id = p.manifest_body.mandate_suite_id;
        state.reward_schedule_hash = p.reward_schedule_hash;
        state.legacy_exit_descriptors = successor.successor_legacy_exit_descriptors.clone();
    }
    state
}

fn reward_state_limit() -> Error {
    Error::code("kernel.reward_state_limit_exceeded")
}

fn capacity_arithmetic_error() -> Error {
    Error::code("kernel.internal_invariant")
}

fn checked_capacity_add(total: usize, addition: usize) -> Result<usize, Error> {
    total
        .checked_add(addition)
        .ok_or_else(capacity_arithmetic_error)
}

fn checked_capacity_mul(count: usize, element_bytes: usize) -> Result<usize, Error> {
    count
        .checked_mul(element_bytes)
        .ok_or_else(capacity_arithmetic_error)
}

fn reward_state_delta(event: &RewardEventBodyV1) -> Result<(usize, usize), Error> {
    let event_bytes = event.canonical_bytes()?.len();
    let mut state_delta = event_bytes;
    if let Some(derived) = &event.derived_reward {
        for addition in [
            32,
            derived.note.canonical_bytes()?.len(),
            32,
            derived.recovery_record.canonical_bytes()?.len(),
        ] {
            state_delta = checked_capacity_add(state_delta, addition)?;
        }
    }
    Ok((state_delta, event_bytes))
}

fn positive_reward_capacity() -> Result<(usize, usize), Error> {
    let origin = RewardOriginV1 {
        previous_checkpoint: [0; 32],
        checkpoint_index: 0,
        body_position: 0,
        body_id: [0; 32],
        body_binding: [0; 32],
        profile_domain: [0; 32],
        reward_suite_id: [0; 32],
        issuance_position: 0,
        receiver: [0; 32],
        nonce: [0; 32],
        subsidy: 0,
        accepted_fees: 0,
    };
    let note = NativeNoteV2 {
        note_type: NoteType::Reward,
        suite_id: [0; 32],
        value: 0,
        owner_tag: [0; 32],
        rho: [0; 32],
        randomness: [0; 32],
        nullifier_key: [0; 32],
        mandate_state: None,
        reward_origin: Some(origin),
    };
    let recovery_record = RecoveryRecordV2 {
        record_kind: RecoveryKind::Reward,
        output_commitment: [0; 32],
        payload: [0; 128],
    };
    reward_state_delta(&RewardEventBodyV1 {
        body_position: 0,
        body_id: [0; 32],
        body_binding: [0; 32],
        issuance_position: 0,
        subsidy: 0,
        accepted_fees: 0,
        total_reward: 0,
        derived_reward: Some(DerivedRewardV1 {
            note,
            commitment: [0; 32],
            recovery_record,
            recovery_hash: [0; 32],
        }),
    })
}

fn rejected_decision_capacity() -> Result<usize, Error> {
    DecisionBodyV2 {
        position: 0,
        body_id: [0; 32],
        body_position: 0,
        envelope_position: 0,
        envelope_tag: EnvelopeTag::Transfer,
        intent_id: [0; 32],
        instance_hash: [0; 32],
        outcome: OutcomeBodyV2::Rejected(RejectCode::StateLimitExceeded),
    }
    .canonical_bytes()
    .map(|bytes| bytes.len())
}

fn accepted_decision_capacity() -> Result<usize, Error> {
    DecisionBodyV2 {
        position: 0,
        body_id: [0; 32],
        body_position: 0,
        envelope_position: 0,
        envelope_tag: EnvelopeTag::Transfer,
        intent_id: [0; 32],
        instance_hash: [0; 32],
        outcome: OutcomeBodyV2::Accepted,
    }
    .canonical_bytes()
    .map(|bytes| bytes.len())
}

#[derive(Debug)]
struct CanonicalCapacityTracker {
    state_canonical_bytes: usize,
    accepted_effect_bytes: usize,
    reward_event_bytes: usize,
    positive_reward_state_bytes: usize,
    positive_reward_event_bytes: usize,
    accepted_decision_bytes: usize,
    worst_decision_bytes: usize,
    total_envelope_count: usize,
    processed_envelope_count: usize,
    emitted_decision_bytes: usize,
    materialized_reward_count: usize,
    body_count: usize,
    base_ordered_history_count: usize,
    active_fence: bool,
    byte_limit: usize,
}

impl CanonicalCapacityTracker {
    fn new(
        base: &TrustedExecutionBase,
        interval: &VerifiedOrderedIntervalV1,
        state: &NativeStateV2,
        byte_limit: usize,
    ) -> Result<Self, Error> {
        if byte_limit > MAX_STATE_BYTES {
            return Err(capacity_arithmetic_error());
        }
        let state_canonical_bytes = state
            .canonical_bytes()
            .map_err(|_| reward_state_limit())?
            .len();
        let (positive_reward_state_bytes, positive_reward_event_bytes) =
            positive_reward_capacity()?;
        let total_envelope_count = interval
            .interval()
            .bodies
            .iter()
            .try_fold(0_usize, |count, body| {
                checked_capacity_add(count, body.envelopes.len())
            })?;
        Ok(Self {
            state_canonical_bytes,
            accepted_effect_bytes: 0,
            reward_event_bytes: 0,
            positive_reward_state_bytes,
            positive_reward_event_bytes,
            accepted_decision_bytes: accepted_decision_capacity()?,
            worst_decision_bytes: rejected_decision_capacity()?,
            total_envelope_count,
            processed_envelope_count: 0,
            emitted_decision_bytes: 0,
            materialized_reward_count: 0,
            body_count: interval.interval().bodies.len(),
            base_ordered_history_count: base.checkpoint().ordered_body_history.len(),
            active_fence: base.effective_fence_id().is_some(),
            byte_limit,
        })
    }

    fn remaining_rewards(&self) -> Result<usize, Error> {
        self.body_count
            .checked_sub(self.materialized_reward_count)
            .ok_or_else(capacity_arithmetic_error)
    }

    fn effect_state_after(&self, effect: &NativeEffectBody) -> Result<(usize, usize), Error> {
        let mut state_bytes = self.state_canonical_bytes;
        for note in &effect.consumed_notes {
            state_bytes = state_bytes
                .checked_sub(checked_capacity_add(32, note.canonical_bytes()?.len())?)
                .ok_or_else(capacity_arithmetic_error)?;
            state_bytes = checked_capacity_add(state_bytes, 32)?;
        }
        for (_, note, recovery) in &effect.outputs {
            for addition in [
                32,
                note.canonical_bytes()?.len(),
                32,
                recovery.canonical_bytes()?.len(),
            ] {
                state_bytes = checked_capacity_add(state_bytes, addition)?;
            }
        }
        let effect_bytes = effect.accepted_effect.canonical_bytes()?.len();
        for addition in [32, effect_bytes] {
            state_bytes = checked_capacity_add(state_bytes, addition)?;
        }
        Ok((state_bytes, effect_bytes))
    }

    fn projected(
        &self,
        effect: Option<&NativeEffectBody>,
        candidate_decision_bytes: Option<usize>,
    ) -> Result<CanonicalCapacity, Error> {
        if effect.is_some() != candidate_decision_bytes.is_some() {
            return Err(capacity_arithmetic_error());
        }
        let (state_after_effect, new_effect_bytes) = match effect {
            Some(value) => self.effect_state_after(value)?,
            None => (self.state_canonical_bytes, 0),
        };
        let effect_bytes = checked_capacity_add(self.accepted_effect_bytes, new_effect_bytes)?;
        let remaining_rewards = self.remaining_rewards()?;
        let projected_state = checked_capacity_add(
            state_after_effect,
            checked_capacity_mul(remaining_rewards, self.positive_reward_state_bytes)?,
        )?;
        let projected_reward_bytes = checked_capacity_add(
            self.reward_event_bytes,
            checked_capacity_mul(remaining_rewards, self.positive_reward_event_bytes)?,
        )?;
        let processed_with_candidate = checked_capacity_add(
            self.processed_envelope_count,
            usize::from(candidate_decision_bytes.is_some()),
        )?;
        let remaining_envelopes = self
            .total_envelope_count
            .checked_sub(processed_with_candidate)
            .ok_or_else(capacity_arithmetic_error)?;
        let decision_bytes = checked_capacity_add(
            checked_capacity_add(
                self.emitted_decision_bytes,
                candidate_decision_bytes.unwrap_or(0),
            )?,
            checked_capacity_mul(remaining_envelopes, self.worst_decision_bytes)?,
        )?;

        let mut interval_result = 2 + 4 + 4 + 4;
        for addition in [
            decision_bytes,
            effect_bytes,
            projected_reward_bytes,
            projected_state,
        ] {
            interval_result = checked_capacity_add(interval_result, addition)?;
        }

        let history_count = checked_capacity_add(self.base_ordered_history_count, self.body_count)?;
        let history_bytes = checked_capacity_mul(history_count, 32)?;
        let body_bytes = checked_capacity_mul(self.body_count, 32)?;
        let fence_bytes = if self.active_fence { 33 } else { 1 };
        let mut checkpoint = 2 + 32 + 32 + 8;
        for addition in [
            projected_state,
            4,
            history_bytes,
            4,
            body_bytes,
            4,
            body_bytes,
            4,
            effect_bytes,
            4,
            projected_reward_bytes,
            fence_bytes,
        ] {
            checkpoint = checked_capacity_add(checkpoint, addition)?;
        }
        Ok(CanonicalCapacity {
            state_after_effect,
            state_projection: checked_capacity_add(2, projected_state)?,
            interval_result,
            checkpoint,
        })
    }

    fn reserve_rewards(&self, state: &NativeStateV2) -> Result<CanonicalCapacity, Error> {
        let remaining_rewards = self.remaining_rewards()?;
        let logical = &state.logical_state;
        if logical
            .live_notes
            .len()
            .checked_add(remaining_rewards)
            .is_none_or(|count| count > MAX_LIVE_NOTES)
            || logical
                .commitment_history
                .len()
                .checked_add(remaining_rewards)
                .is_none_or(|count| count > MAX_NATIVE_HISTORY)
            || logical
                .recovery_history
                .len()
                .checked_add(remaining_rewards)
                .is_none_or(|count| count > MAX_NATIVE_HISTORY)
        {
            return Err(reward_state_limit());
        }
        let capacity = self
            .projected(None, None)
            .map_err(|_| reward_state_limit())?;
        if !capacity.fits(self.byte_limit) {
            return Err(reward_state_limit());
        }
        Ok(capacity)
    }

    fn effect_fits(&self, effect: &mut NativeEffectBody) -> bool {
        let Ok(capacity) = self.projected(Some(effect), Some(self.accepted_decision_bytes)) else {
            return false;
        };
        if !capacity.fits(self.byte_limit) {
            return false;
        }
        let Ok(effect_bytes) = effect.accepted_effect.canonical_bytes() else {
            return false;
        };
        effect.state_canonical_bytes_after_effect = capacity.state_after_effect;
        effect.accepted_effect_canonical_bytes = effect_bytes.len();
        true
    }

    fn accept_effect(&mut self, effect: &NativeEffectBody) -> Result<(), Error> {
        self.state_canonical_bytes = effect.state_canonical_bytes_after_effect;
        self.accepted_effect_bytes = checked_capacity_add(
            self.accepted_effect_bytes,
            effect.accepted_effect_canonical_bytes,
        )?;
        Ok(())
    }

    fn accept_decision(&mut self, decision: &DecisionBodyV2) -> Result<(), Error> {
        if self.processed_envelope_count >= self.total_envelope_count {
            return Err(capacity_arithmetic_error());
        }
        self.emitted_decision_bytes = checked_capacity_add(
            self.emitted_decision_bytes,
            decision.canonical_bytes()?.len(),
        )?;
        self.processed_envelope_count = checked_capacity_add(self.processed_envelope_count, 1)?;
        Ok(())
    }

    fn accept_reward(&mut self, event: &RewardEventBodyV1) -> Result<(), Error> {
        let (state_delta, event_bytes) = reward_state_delta(event)?;
        self.state_canonical_bytes = checked_capacity_add(self.state_canonical_bytes, state_delta)?;
        self.reward_event_bytes = checked_capacity_add(self.reward_event_bytes, event_bytes)?;
        self.materialized_reward_count = checked_capacity_add(self.materialized_reward_count, 1)?;
        Ok(())
    }
}

fn envelope_parts(
    envelope: &ConsensusEnvelopeV1,
) -> (
    &[crate::TransparentInputV2],
    &[crate::TransparentOutputV2],
    &[Hash32],
    &[RecoveryRecordV2],
    u64,
) {
    match envelope {
        ConsensusEnvelopeV1::Transfer(value) => (
            &value.inputs,
            &value.outputs,
            &value.recovery_hashes,
            &value.recovery_records,
            value.public_fee,
        ),
        ConsensusEnvelopeV1::Migration(value) => (
            &value.inputs,
            &value.outputs,
            &value.recovery_hashes,
            &value.recovery_records,
            value.public_fee,
        ),
    }
}

fn common_domains(envelope: &ConsensusEnvelopeV1) -> (Hash32, Hash32, Hash32, Hash32, Hash32, u64) {
    match envelope {
        ConsensusEnvelopeV1::Transfer(value) => (
            value.chain_domain,
            value.protocol_manifest_hash,
            value.profile_domain,
            value.policy_phase_root,
            value.anchor,
            value.expires_checkpoint,
        ),
        ConsensusEnvelopeV1::Migration(value) => (
            value.chain_domain,
            value.protocol_manifest_hash,
            value.profile_domain,
            value.policy_phase_root,
            value.execution_anchor,
            value.expires_checkpoint,
        ),
    }
}

fn has_duplicates<T: Ord + Copy>(values: impl IntoIterator<Item = T>) -> bool {
    let mut set = BTreeSet::new();
    values.into_iter().any(|value| !set.insert(value))
}

struct EvalContext<'a> {
    base: &'a TrustedExecutionBase,
    profile: &'a VerifiedGate2ProfileV1,
    accepted_intents: &'a BTreeSet<Hash32>,
    accepted_nullifiers: &'a BTreeSet<Hash32>,
    accepted_commitments: &'a BTreeSet<Hash32>,
    body_fee: u64,
    reward_reserve_remaining: usize,
    working: &'a NativeStateV2,
    capacity: &'a CanonicalCapacityTracker,
}

fn evaluate_envelope(
    envelope: &ConsensusEnvelopeV1,
    body_id: Hash32,
    envelope_position: u32,
    context: &EvalContext<'_>,
) -> Result<NativeEffectBody, RejectCode> {
    let (intent, _) = envelope_identity(envelope).map_err(|_| RejectCode::StateLimitExceeded)?;
    if context
        .base
        .checkpoint()
        .native_state
        .logical_state
        .accepted_intents
        .contains(&intent)
        || context.accepted_intents.contains(&intent)
    {
        return Err(RejectCode::DuplicateIntent);
    }
    let (inputs, outputs, recovery_hashes, recovery_records, public_fee) = envelope_parts(envelope);
    if inputs.is_empty() {
        return Err(RejectCode::EmptyInputs);
    }
    if inputs.len() > crate::MAX_INPUTS {
        return Err(RejectCode::TooManyInputs);
    }
    if outputs.len() > crate::MAX_OUTPUTS {
        return Err(RejectCode::TooManyOutputs);
    }
    let p = context.profile.profile();
    let checkpoint = context.base.checkpoint();
    let next_index = checkpoint
        .checkpoint_index
        .checked_add(1)
        .ok_or(RejectCode::WrongCheckpoint)?;
    let (chain, manifest, profile_domain, policy, anchor, expires) = common_domains(envelope);
    if chain != p.manifest_body.chain_domain {
        return Err(RejectCode::WrongChain);
    }
    if manifest != p.protocol_manifest_hash {
        return Err(RejectCode::WrongManifest);
    }
    if profile_domain != p.profile_domain {
        return Err(RejectCode::WrongProfile);
    }
    if policy != p.policy_phase_root {
        return Err(RejectCode::WrongPolicyPhaseRoot);
    }
    if anchor != checkpoint.checkpoint_id {
        return Err(RejectCode::WrongCheckpoint);
    }
    if let ConsensusEnvelopeV1::Transfer(value) = envelope
        && value.anchor_epoch != next_index
    {
        return Err(RejectCode::WrongCheckpoint);
    }
    if next_index > expires {
        return Err(RejectCode::Expired);
    }
    match envelope {
        ConsensusEnvelopeV1::Transfer(value) => {
            if !p.manifest_body.active_suite_ids.contains(&value.suite_id) {
                return Err(RejectCode::InactiveSuite);
            }
        }
        ConsensusEnvelopeV1::Migration(value) => {
            if !p
                .manifest_body
                .active_suite_ids
                .contains(&value.new_suite_id)
            {
                return Err(RejectCode::InactiveSuite);
            }
            if value.migration_relation_hash != p.manifest_body.migration_relation_hash {
                return Err(RejectCode::InactiveMigrationRelation);
            }
            let descriptor = context
                .working
                .legacy_exit_descriptors
                .iter()
                .find(|descriptor| descriptor.source_suite_id == value.old_suite_id);
            if !p
                .manifest_body
                .retained_migration_source_suite_ids
                .contains(&value.old_suite_id)
                || descriptor.is_none()
                || descriptor.is_some_and(|d| {
                    d.frozen_source_checkpoint != value.old_anchor_checkpoint
                        || d.frozen_source_note_root != value.old_anchor_root
                        || d.migration_relation_hash != value.migration_relation_hash
                        || d.allowed_transition != crate::LegacyTransitionKind::ValueSuiteMigration
                })
            {
                return Err(RejectCode::MissingLegacyExit);
            }
        }
    }
    if has_duplicates(inputs.iter().map(|value| value.commitment)) {
        return Err(RejectCode::InternalDuplicateInput);
    }
    if has_duplicates(inputs.iter().map(|value| value.nullifier)) {
        return Err(RejectCode::InternalDuplicateNullifier);
    }
    if has_duplicates(outputs.iter().map(|value| value.commitment)) {
        return Err(RejectCode::InternalDuplicateOutput);
    }
    if inputs.iter().any(|value| {
        checkpoint
            .native_state
            .logical_state
            .nullifiers
            .contains(&value.nullifier)
    }) {
        return Err(RejectCode::AlreadySpent);
    }
    if inputs
        .iter()
        .any(|value| context.accepted_nullifiers.contains(&value.nullifier))
    {
        return Err(RejectCode::ConflictLost);
    }
    if outputs.iter().any(|value| {
        checkpoint
            .native_state
            .logical_state
            .commitment_history
            .contains(&value.commitment)
    }) {
        return Err(RejectCode::CommitmentAlreadyExists);
    }
    if outputs
        .iter()
        .any(|value| context.accepted_commitments.contains(&value.commitment))
    {
        return Err(RejectCode::CommitmentConflict);
    }
    let mut input_sum = 0_u64;
    for input in inputs {
        let opened = note_commitment(&chain, &input.witness.note)
            .map_err(|_| RejectCode::WitnessCommitmentMismatch)?;
        if opened != input.commitment {
            return Err(RejectCode::WitnessCommitmentMismatch);
        }
        let nf = note_nullifier(&chain, &input.witness.note, &input.commitment)
            .map_err(|_| RejectCode::NullifierMismatch)?;
        if nf != input.nullifier {
            return Err(RejectCode::NullifierMismatch);
        }
        let Some(base_note) = checkpoint
            .native_state
            .logical_state
            .live_notes
            .get(&input.commitment)
        else {
            return Err(RejectCode::InputNotCheckpointed);
        };
        if base_note != &input.witness.note {
            return Err(RejectCode::WitnessCommitmentMismatch);
        }
        let basic_role = match input.witness.note.note_type {
            NoteType::Value | NoteType::Reward => {
                input.witness.authorization_role == AuthorizationRole::Owner
            }
            NoteType::Mandate => matches!(
                input.witness.authorization_role,
                AuthorizationRole::Principal | AuthorizationRole::Delegate
            ),
        };
        if !input.witness.authorization_valid || !basic_role {
            return Err(RejectCode::InvalidTransparentWitness);
        }
        input_sum = input_sum
            .checked_add(input.witness.note.value)
            .ok_or(RejectCode::ValueOverflow)?;
    }
    let mut output_sum = 0_u64;
    for output in outputs {
        let opened = note_commitment(&chain, &output.note)
            .map_err(|_| RejectCode::OutputCommitmentMismatch)?;
        if opened != output.commitment {
            return Err(RejectCode::OutputCommitmentMismatch);
        }
        output_sum = output_sum
            .checked_add(output.note.value)
            .ok_or(RejectCode::ValueOverflow)?;
    }
    let accounted = output_sum
        .checked_add(public_fee)
        .ok_or(RejectCode::ValueOverflow)?;
    if input_sum != accounted {
        return Err(RejectCode::ConservationFailure);
    }
    match envelope {
        ConsensusEnvelopeV1::Transfer(value) => {
            validate_transfer_semantics(value, p, next_index)?;
        }
        ConsensusEnvelopeV1::Migration(value) => validate_migration_semantics(value, p)?,
    }
    if recovery_hashes.len() != outputs.len() || recovery_records.len() != outputs.len() {
        return Err(RejectCode::RecoveryVectorMismatch);
    }
    for ((output, supplied_hash), record) in
        outputs.iter().zip(recovery_hashes).zip(recovery_records)
    {
        if record.output_commitment != output.commitment {
            return Err(RejectCode::RecoveryCommitmentMismatch);
        }
        let expected_kind = match output.output_role {
            OutputRole::MandateCreate | OutputRole::MandateSuccessor => RecoveryKind::MandateDual,
            OutputRole::RewardDerived => RecoveryKind::Reward,
            _ => RecoveryKind::Ordinary,
        };
        if record.record_kind != expected_kind {
            return Err(RejectCode::RecoveryKindMismatch);
        }
        if recovery_hash(&chain, record).map_err(|_| RejectCode::RecoveryHashMismatch)?
            != *supplied_hash
        {
            return Err(RejectCode::RecoveryHashMismatch);
        }
    }
    let new_body_fee = context
        .body_fee
        .checked_add(public_fee)
        .ok_or(RejectCode::BodyFeeLimit)?;
    if new_body_fee > p.manifest_body.max_accepted_fees_per_body {
        return Err(RejectCode::BodyFeeLimit);
    }
    context
        .working
        .logical_state
        .fee_pool
        .checked_add(u128::from(public_fee))
        .ok_or(RejectCode::FeePoolOverflow)?;
    let projected_live = context
        .working
        .logical_state
        .live_notes
        .len()
        .saturating_sub(inputs.len())
        .saturating_add(outputs.len())
        .saturating_add(context.reward_reserve_remaining);
    if projected_live > MAX_LIVE_NOTES
        || context
            .working
            .logical_state
            .nullifiers
            .len()
            .saturating_add(inputs.len())
            > MAX_NATIVE_HISTORY
        || context
            .working
            .logical_state
            .commitment_history
            .len()
            .saturating_add(outputs.len())
            .saturating_add(context.reward_reserve_remaining)
            > MAX_NATIVE_HISTORY
        || context
            .working
            .logical_state
            .recovery_history
            .len()
            .saturating_add(outputs.len())
            .saturating_add(context.reward_reserve_remaining)
            > MAX_NATIVE_HISTORY
        || context
            .working
            .logical_state
            .accepted_intents
            .len()
            .saturating_add(1)
            > MAX_ACCEPTED_HISTORY
        || context
            .working
            .logical_state
            .accepted_effect_history
            .len()
            .saturating_add(1)
            > MAX_ACCEPTED_HISTORY
    {
        return Err(RejectCode::StateLimitExceeded);
    }

    let effect_digest = match envelope {
        ConsensusEnvelopeV1::Transfer(value) => transfer_effect_digest(value),
        ConsensusEnvelopeV1::Migration(value) => migration_statement_digest(value),
    }
    .map_err(|_| RejectCode::StateLimitExceeded)?;
    let accepted_effect = AcceptedEffectBodyV2 {
        body_id,
        envelope_position,
        envelope_tag: envelope.tag(),
        intent_id: intent,
        effect_digest,
        output_commitments: BoundedVec::new(
            outputs.iter().map(|output| output.commitment).collect(),
        )
        .map_err(|_| RejectCode::StateLimitExceeded)?,
        output_roles: BoundedVec::new(outputs.iter().map(|output| output.output_role).collect())
            .map_err(|_| RejectCode::StateLimitExceeded)?,
    };
    let mut effect = NativeEffectBody {
        consumed_commitments: inputs.iter().map(|input| input.commitment).collect(),
        consumed_notes: inputs
            .iter()
            .map(|input| input.witness.note.clone())
            .collect(),
        nullifiers: inputs.iter().map(|input| input.nullifier).collect(),
        outputs: outputs
            .iter()
            .zip(recovery_records)
            .map(|(output, recovery)| (output.commitment, output.note.clone(), recovery.clone()))
            .collect(),
        public_fee,
        accepted_effect,
        state_canonical_bytes_after_effect: 0,
        accepted_effect_canonical_bytes: 0,
    };
    if !context.capacity.effect_fits(&mut effect) {
        return Err(RejectCode::StateLimitExceeded);
    }
    Ok(effect)
}

fn validate_transfer_semantics(
    value: &TransferEnvelopeV2,
    profile: &crate::Gate2ProfileV1,
    inclusion_epoch: u64,
) -> Result<(), RejectCode> {
    let p = value;
    if !crate::enabled_transfer_kinds(profile).contains(&p.transition_kind) {
        return Err(RejectCode::PolicyBranchDisabled);
    }
    if p.outputs.iter().any(|output| {
        output.note.note_type == NoteType::Reward || output.output_role == OutputRole::RewardDerived
    }) {
        return Err(RejectCode::RewardOutputReserved);
    }
    let input_suites = p
        .inputs
        .iter()
        .all(|input| input.witness.note.suite_id == p.suite_id);
    let output_suites = p
        .outputs
        .iter()
        .all(|output| output.note.suite_id == p.suite_id);
    let output_options = p.outputs.iter().all(|output| match output.note.note_type {
        NoteType::Value => {
            output.note.mandate_state.is_none() && output.note.reward_origin.is_none()
        }
        NoteType::Mandate => {
            output.note.mandate_state.is_some() && output.note.reward_origin.is_none()
        }
        NoteType::Reward => {
            output.note.mandate_state.is_none() && output.note.reward_origin.is_some()
        }
    });
    let matrix = match p.transition_kind {
        TransferKind::Ordinary => {
            p.inputs
                .iter()
                .all(|i| matches!(i.witness.note.note_type, NoteType::Value | NoteType::Reward))
                && p.outputs.iter().all(|o| {
                    o.note.note_type == NoteType::Value && o.output_role == OutputRole::Ordinary
                })
                && p.action_evidence.is_none()
        }
        TransferKind::MandateCreate => {
            p.inputs
                .iter()
                .all(|i| matches!(i.witness.note.note_type, NoteType::Value | NoteType::Reward))
                && p.outputs.iter().all(|o| {
                    (o.note.note_type == NoteType::Mandate
                        && o.output_role == OutputRole::MandateCreate)
                        || (o.note.note_type == NoteType::Value
                            && o.output_role == OutputRole::PrincipalReturn)
                })
        }
        TransferKind::MandateAction | TransferKind::MandateExhaust => {
            p.inputs
                .iter()
                .all(|i| i.witness.note.note_type == NoteType::Mandate)
                && p.outputs.iter().all(|o| {
                    (o.note.note_type == NoteType::Value
                        && o.output_role == OutputRole::MandatePayment)
                        || (o.note.note_type == NoteType::Mandate
                            && o.output_role == OutputRole::MandateSuccessor)
                })
        }
        TransferKind::MandateRevoke | TransferKind::MandateExpireReclaim => {
            p.inputs
                .iter()
                .all(|i| i.witness.note.note_type == NoteType::Mandate)
                && p.outputs.iter().all(|o| {
                    o.note.note_type == NoteType::Value
                        && o.output_role != OutputRole::RewardDerived
                })
        }
        TransferKind::SplitDelegate => false,
    };
    if !input_suites || !output_suites || !output_options || !matrix {
        return Err(RejectCode::InvalidNoteTypeTransition);
    }
    match p.transition_kind {
        TransferKind::Ordinary => {}
        TransferKind::MandateCreate => validate_mandate_create(p, profile, inclusion_epoch)?,
        TransferKind::MandateAction | TransferKind::MandateExhaust => {
            validate_mandate_action(p, profile, inclusion_epoch)?;
        }
        TransferKind::MandateRevoke | TransferKind::MandateExpireReclaim => {
            validate_mandate_reclaim(p, inclusion_epoch)?;
        }
        TransferKind::SplitDelegate => return Err(RejectCode::PolicyBranchDisabled),
    }
    Ok(())
}

fn mandate(note: &NativeNoteV2) -> Result<&MandateStateV1, RejectCode> {
    note.mandate_state
        .as_ref()
        .ok_or(RejectCode::InvalidNoteTypeTransition)
}

fn validate_mandate_create(
    value: &TransferEnvelopeV2,
    profile: &crate::Gate2ProfileV1,
    inclusion_epoch: u64,
) -> Result<(), RejectCode> {
    let mandates = value
        .outputs
        .iter()
        .filter(|o| o.output_role == OutputRole::MandateCreate)
        .collect::<Vec<_>>();
    let returns = value
        .outputs
        .iter()
        .filter(|o| o.output_role == OutputRole::PrincipalReturn)
        .collect::<Vec<_>>();
    if mandates.is_empty() || returns.len() > 1 || value.action_evidence.is_some() {
        return Err(RejectCode::MandateTransitionShape);
    }
    if value
        .inputs
        .iter()
        .any(|input| input.witness.authorization_role != AuthorizationRole::Owner)
    {
        return Err(RejectCode::MandateAuthorization);
    }
    if mandates.iter().any(|output| {
        mandate(&output.note).is_ok_and(|m| m.frequency_mode != crate::FrequencyMode::SerialWindow)
    }) {
        return Err(RejectCode::FrequencyModeUnsupported);
    }
    if mandates
        .iter()
        .any(|output| mandate(&output.note).is_ok_and(|m| m.delegation_depth_left != 0))
    {
        return Err(RejectCode::DelegationDisabled);
    }
    for output in &mandates {
        let m = mandate(&output.note)?;
        if output.note.suite_id != profile.manifest_body.mandate_suite_id
            || output.note.owner_tag != m.principal_spend_tag
            || m.policy_module_id != profile.manifest_body.mandate_policy_module_id
            || m.mandate_version != profile.manifest_body.mandate_version
        {
            return Err(RejectCode::MandateAuthorityChanged);
        }
    }
    let owners = value
        .inputs
        .iter()
        .map(|input| input.witness.note.owner_tag)
        .collect::<BTreeSet<_>>();
    if owners.len() != 1 {
        return Err(RejectCode::MandateAuthorityChanged);
    }
    let owner = *owners.iter().next().expect("nonempty inputs checked");
    if mandates.iter().any(|output| output.note.owner_tag != owner) {
        return Err(RejectCode::MandateAuthorityChanged);
    }
    for output in &mandates {
        let m = mandate(&output.note)?;
        if m.parent_policy_hash != [0; 32]
            || !m.policy_caveat_hashes.is_empty()
            || m.per_action_limit > output.note.value
        {
            return Err(RejectCode::MandatePolicyWidened);
        }
        if output.note.value == 0
            || m.last_action_anchor.is_some()
            || m.actions_in_window != 0
            || m.window_size_checkpoints == 0
            || m.max_actions_per_window == 0
            || m.remaining_action_tokens == 0
            || m.recipient_roots.is_empty()
            || m.application_roots.is_empty()
            || m.expiry_checkpoint < inclusion_epoch
            || m.window_index != inclusion_epoch / u64::from(m.window_size_checkpoints)
        {
            return Err(RejectCode::MandateCounterInvalid);
        }
    }
    if returns.iter().any(|output| output.note.owner_tag != owner) {
        return Err(RejectCode::MandateReturnInvalid);
    }
    Ok(())
}

fn validate_mandate_action(
    value: &TransferEnvelopeV2,
    profile: &crate::Gate2ProfileV1,
    inclusion_epoch: u64,
) -> Result<(), RejectCode> {
    let payments = value
        .outputs
        .iter()
        .filter(|o| o.output_role == OutputRole::MandatePayment)
        .collect::<Vec<_>>();
    let successors = value
        .outputs
        .iter()
        .filter(|o| o.output_role == OutputRole::MandateSuccessor)
        .collect::<Vec<_>>();
    if value.inputs.len() != 1
        || payments.is_empty()
        || value.action_evidence.as_ref().is_none_or(|e| {
            e.recipient_scope_openings.is_empty() || e.application_scope_openings.is_empty()
        })
    {
        return Err(RejectCode::MandateTransitionShape);
    }
    let input = &value.inputs[0];
    if input.witness.authorization_role != AuthorizationRole::Delegate {
        return Err(RejectCode::MandateAuthorization);
    }
    let parent = mandate(&input.witness.note)?;
    if parent.frequency_mode != crate::FrequencyMode::SerialWindow
        || successors.iter().any(|s| {
            mandate(&s.note).is_ok_and(|m| m.frequency_mode != crate::FrequencyMode::SerialWindow)
        })
    {
        return Err(RejectCode::FrequencyModeUnsupported);
    }
    if successors
        .iter()
        .any(|s| mandate(&s.note).is_ok_and(|m| m.delegation_depth_left != 0))
    {
        return Err(RejectCode::DelegationDisabled);
    }
    let evidence = value.action_evidence.as_ref().expect("shape checked");
    if evidence
        .recipient_scope_openings
        .iter()
        .any(|s| s.scope_kind != ScopeKind::Recipient)
        || evidence
            .application_scope_openings
            .iter()
            .any(|s| s.scope_kind != ScopeKind::Application)
    {
        return Err(RejectCode::MandateScopeDenied);
    }
    let recipient_roots = evidence
        .recipient_scope_openings
        .iter()
        .map(|scope| crate::scope_root(&value.chain_domain, scope))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| RejectCode::MandateScopeDenied)?;
    let application_roots = evidence
        .application_scope_openings
        .iter()
        .map(|scope| crate::scope_root(&value.chain_domain, scope))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| RejectCode::MandateScopeDenied)?;
    if recipient_roots.as_slice() != parent.recipient_roots.as_slice()
        || application_roots.as_slice() != parent.application_roots.as_slice()
    {
        return Err(RejectCode::MandateScopeDenied);
    }
    if !evidence
        .application_scope_openings
        .iter()
        .all(|scope| scope.members.contains(&evidence.application_tag))
        || payments.iter().any(|payment| {
            !evidence
                .recipient_scope_openings
                .iter()
                .all(|scope| scope.members.contains(&payment.note.owner_tag))
        })
    {
        return Err(RejectCode::MandateScopeDenied);
    }
    let payment_total = payments.iter().try_fold(0_u64, |sum, output| {
        sum.checked_add(output.note.value)
            .ok_or(RejectCode::ValueOverflow)
    })?;
    if payment_total > parent.per_action_limit {
        return Err(RejectCode::MandatePaymentLimit);
    }
    for successor_output in &successors {
        let successor = mandate(&successor_output.note)?;
        if successor_output.note.suite_id != profile.manifest_body.mandate_suite_id
            || successor.policy_module_id != profile.manifest_body.mandate_policy_module_id
            || successor.mandate_version != profile.manifest_body.mandate_version
            || successor_output.note.owner_tag != successor.principal_spend_tag
        {
            return Err(RejectCode::MandateAuthorityChanged);
        }
        if matches!(
            value.transition_kind,
            TransferKind::MandateAction | TransferKind::MandateExhaust
        ) && (successor_output.note.suite_id != input.witness.note.suite_id
            || successor_output.note.owner_tag != input.witness.note.owner_tag
            || successor.policy_module_id != parent.policy_module_id
            || successor.mandate_version != parent.mandate_version
            || successor.principal_spend_tag != parent.principal_spend_tag
            || successor.principal_recovery_tag != parent.principal_recovery_tag
            || successor.delegate_auth_tag != parent.delegate_auth_tag
            || successor.receipt_disclosure_tag != parent.receipt_disclosure_tag)
        {
            return Err(RejectCode::MandateAuthorityChanged);
        }
    }
    if matches!(
        value.transition_kind,
        TransferKind::MandateAction | TransferKind::MandateExhaust
    ) {
        for successor_output in &successors {
            let successor = mandate(&successor_output.note)?;
            if successor.per_action_limit > parent.per_action_limit
                || successor.expiry_checkpoint > parent.expiry_checkpoint
                || successor.minimum_interval < parent.minimum_interval
                || successor.window_size_checkpoints != parent.window_size_checkpoints
                || successor.max_actions_per_window > parent.max_actions_per_window
                || !parent
                    .recipient_roots
                    .iter()
                    .all(|root| successor.recipient_roots.contains(root))
                || !parent
                    .application_roots
                    .iter()
                    .all(|root| successor.application_roots.contains(root))
                || successor.parent_policy_hash != [0; 32]
                || !successor.policy_caveat_hashes.is_empty()
            {
                return Err(RejectCode::MandatePolicyWidened);
            }
        }
    }
    validate_action_counters(value, parent, &successors, inclusion_epoch)?;
    match value.transition_kind {
        TransferKind::MandateAction if successors.len() == 1 => {
            if successors[0].note.value == 0 || successors[0].note.mandate_state.is_none() {
                return Err(RejectCode::MandateSuccessorInvalid);
            }
        }
        TransferKind::MandateAction | TransferKind::MandateExhaust if !successors.is_empty() => {
            return Err(RejectCode::MandateSuccessorInvalid);
        }
        TransferKind::MandateAction => return Err(RejectCode::MandateSuccessorInvalid),
        TransferKind::MandateExhaust => {}
        _ => unreachable!("action validator branch"),
    }
    Ok(())
}

fn validate_action_counters(
    value: &TransferEnvelopeV2,
    parent: &MandateStateV1,
    successors: &[&crate::TransparentOutputV2],
    inclusion_epoch: u64,
) -> Result<(), RejectCode> {
    if value.expires_checkpoint > parent.expiry_checkpoint
        || inclusion_epoch > parent.expiry_checkpoint
    {
        return Err(RejectCode::MandateCounterInvalid);
    }
    if let Some(last) = parent.last_action_anchor {
        let earliest = last
            .checked_add(u64::from(parent.minimum_interval))
            .ok_or(RejectCode::MandateCounterInvalid)?;
        if inclusion_epoch < earliest {
            return Err(RejectCode::MandateCounterInvalid);
        }
    }
    let window = inclusion_epoch / u64::from(parent.window_size_checkpoints);
    if window < parent.window_index {
        return Err(RejectCode::MandateCounterInvalid);
    }
    let count = if window == parent.window_index {
        if parent.actions_in_window >= parent.max_actions_per_window {
            return Err(RejectCode::MandateCounterInvalid);
        }
        parent
            .actions_in_window
            .checked_add(1)
            .ok_or(RejectCode::MandateCounterInvalid)?
    } else {
        1
    };
    if value.transition_kind == TransferKind::MandateExhaust {
        if parent.remaining_action_tokens != 1 {
            return Err(RejectCode::MandateCounterInvalid);
        }
    } else {
        let expected_tokens = parent
            .remaining_action_tokens
            .checked_sub(1)
            .ok_or(RejectCode::MandateCounterInvalid)?;
        if successors.len() == 1 {
            let successor = mandate(&successors[0].note)?;
            if expected_tokens == 0
                || successor.last_action_anchor != Some(value.anchor_epoch)
                || successor.remaining_action_tokens != expected_tokens
                || successor.window_index != window
                || successor.actions_in_window != count
            {
                return Err(RejectCode::MandateCounterInvalid);
            }
        }
    }
    Ok(())
}

fn validate_mandate_reclaim(
    value: &TransferEnvelopeV2,
    inclusion_epoch: u64,
) -> Result<(), RejectCode> {
    if value.inputs.len() != 1 || value.action_evidence.is_some() {
        return Err(RejectCode::MandateTransitionShape);
    }
    let input = &value.inputs[0];
    let parent = mandate(&input.witness.note)?;
    if input.witness.authorization_role != AuthorizationRole::Principal {
        return Err(RejectCode::MandateAuthorization);
    }
    if parent.frequency_mode != crate::FrequencyMode::SerialWindow {
        return Err(RejectCode::FrequencyModeUnsupported);
    }
    if value.transition_kind == TransferKind::MandateExpireReclaim
        && inclusion_epoch <= parent.expiry_checkpoint
    {
        return Err(RejectCode::MandateNotExpired);
    }
    if value.outputs.len() != 1 {
        return Err(RejectCode::MandateReturnInvalid);
    }
    let output = &value.outputs[0];
    if output.output_role != OutputRole::PrincipalReturn
        || output.note.owner_tag != parent.principal_spend_tag
        || output.note.value.checked_add(value.public_fee) != Some(input.witness.note.value)
    {
        return Err(RejectCode::MandateReturnInvalid);
    }
    Ok(())
}

fn validate_migration_semantics(
    value: &SyntheticMigrationEnvelopeV1,
    profile: &crate::Gate2ProfileV1,
) -> Result<(), RejectCode> {
    if value
        .inputs
        .iter()
        .any(|input| input.witness.note.note_type != NoteType::Value)
    {
        return Err(RejectCode::MigrationValueOnly);
    }
    let destination_suites = profile
        .manifest_body
        .active_suite_ids
        .iter()
        .filter(|suite| {
            **suite != profile.manifest_body.reward_suite_id
                && **suite != profile.manifest_body.mandate_suite_id
        })
        .collect::<Vec<_>>();
    if value.old_suite_id == value.new_suite_id
        || destination_suites.as_slice() != [&value.new_suite_id]
        || value
            .inputs
            .iter()
            .any(|input| input.witness.note.suite_id != value.old_suite_id)
        || value
            .outputs
            .iter()
            .any(|output| output.note.suite_id != value.new_suite_id)
    {
        return Err(RejectCode::MigrationSuiteMismatch);
    }
    if value.outputs.iter().any(|output| {
        output.note.note_type != NoteType::Value
            || output.output_role != OutputRole::MigrationDestination
    }) {
        return Err(RejectCode::MigrationOutputRole);
    }
    Ok(())
}

fn apply_native_effect(state: &mut NativeStateV2, body: &NativeEffectBody) -> Result<(), Error> {
    for commitment in &body.consumed_commitments {
        let index = state
            .logical_state
            .live_notes
            .binary_search_by_key(commitment, |(key, _)| *key)
            .map_err(|_| Error::code("kernel.internal_invariant"))?;
        state.logical_state.live_notes.remove(index);
    }
    for nullifier in &body.nullifiers {
        let position = state
            .logical_state
            .nullifiers
            .binary_search(nullifier)
            .unwrap_or_else(|index| index);
        state.logical_state.nullifiers.insert(position, *nullifier);
    }
    for (commitment, note, recovery) in &body.outputs {
        let position = state
            .logical_state
            .live_notes
            .binary_search_by_key(commitment, |(key, _)| *key)
            .unwrap_or_else(|index| index);
        state
            .logical_state
            .live_notes
            .insert(position, (*commitment, note.clone()));
        state.logical_state.commitment_history.push(*commitment);
        state.logical_state.recovery_history.push(recovery.clone());
    }
    let intent_position = state
        .logical_state
        .accepted_intents
        .binary_search(&body.accepted_effect.intent_id)
        .unwrap_or_else(|index| index);
    state
        .logical_state
        .accepted_intents
        .insert(intent_position, body.accepted_effect.intent_id);
    state
        .logical_state
        .accepted_effect_history
        .push(body.accepted_effect.clone());
    state.logical_state.fee_pool = state
        .logical_state
        .fee_pool
        .checked_add(u128::from(body.public_fee))
        .ok_or_else(|| Error::code("kernel.internal_invariant"))?;
    Ok(())
}

fn apply_reward_effect(
    state: &mut NativeStateV2,
    effect: &SyntheticRewardEffectV1,
) -> Result<(), Error> {
    let event = &effect.event;
    state.logical_state.issuance_cursor = event.issuance_position;
    state.logical_state.native_issued = state
        .logical_state
        .native_issued
        .checked_add(u128::from(event.subsidy))
        .ok_or_else(|| Error::code("kernel.internal_invariant"))?;
    state.logical_state.fee_pool = state
        .logical_state
        .fee_pool
        .checked_sub(u128::from(event.accepted_fees))
        .ok_or_else(|| Error::code("kernel.internal_invariant"))?;
    if let Some(derived) = &event.derived_reward {
        let position = state
            .logical_state
            .live_notes
            .binary_search_by_key(&derived.commitment, |(key, _)| *key)
            .unwrap_or_else(|index| index);
        state
            .logical_state
            .live_notes
            .insert(position, (derived.commitment, derived.note.clone()));
        state
            .logical_state
            .commitment_history
            .push(derived.commitment);
        state
            .logical_state
            .recovery_history
            .push(derived.recovery_record.clone());
    }
    state
        .logical_state
        .issuance_event_history
        .push(event.clone());
    Ok(())
}

pub fn evaluate_interval(
    base: &TrustedExecutionBase,
    profile: &VerifiedGate2ProfileV1,
    receipt: &VerifiedSyntheticEligibilityReceiptV1,
    interval: &VerifiedOrderedIntervalV1,
) -> Result<EvaluatedIntervalV2, Error> {
    evaluate_interval_with_capacity_limit(base, profile, receipt, interval, MAX_STATE_BYTES)
}

#[cfg(feature = "private-test-harness")]
pub fn evaluate_interval_with_synthetic_capacity_limit(
    _authority: &crate::SyntheticHarnessAuthority,
    base: &TrustedExecutionBase,
    profile: &VerifiedGate2ProfileV1,
    receipt: &VerifiedSyntheticEligibilityReceiptV1,
    interval: &VerifiedOrderedIntervalV1,
    byte_limit: usize,
) -> Result<EvaluatedIntervalV2, Error> {
    evaluate_interval_with_capacity_limit(base, profile, receipt, interval, byte_limit)
}

fn evaluate_interval_with_capacity_limit(
    base: &TrustedExecutionBase,
    profile: &VerifiedGate2ProfileV1,
    receipt: &VerifiedSyntheticEligibilityReceiptV1,
    interval: &VerifiedOrderedIntervalV1,
    byte_limit: usize,
) -> Result<EvaluatedIntervalV2, Error> {
    if interval.trusted_base_identity != base.checkpoint().checkpoint_id
        || interval.verified_profile_domain != profile.profile().profile_domain
        || receipt.receipt().base_checkpoint != base.checkpoint().checkpoint_id
    {
        return Err(Error::code("kernel.checkpoint_binding_mismatch"));
    }
    let base_state = &base.checkpoint().native_state.logical_state;
    let body_count = interval.interval().bodies.len();
    let mut working = execution_start_state(base, profile);
    let mut capacity = CanonicalCapacityTracker::new(base, interval, &working, byte_limit)?;
    let preflight_capacity = capacity.reserve_rewards(&working)?;
    debug_assert!(preflight_capacity.fits(byte_limit));
    let mut issued = base_state.native_issued;
    for (j, _) in receipt.receipt().entries.iter().enumerate() {
        let position = base_state
            .issuance_cursor
            .checked_add(j as u128 + 1)
            .ok_or_else(|| Error::code("kernel.issuance_cursor_overflow"))?;
        issued = issued
            .checked_add(u128::from(schedule_subsidy(profile, position)?))
            .ok_or_else(|| Error::code("kernel.native_issuance_overflow"))?;
    }
    let _ = issued;
    let mut decisions = Vec::new();
    let mut accepted_effects = Vec::new();
    let mut reward_events = Vec::new();
    let mut effects = Vec::new();
    let mut accepted_intents = BTreeSet::new();
    let mut accepted_nullifiers = BTreeSet::new();
    let mut accepted_commitments = BTreeSet::new();
    let mut global_position = 0_u32;
    for (body_position, body) in interval.interval().bodies.iter().enumerate() {
        let mut body_fee = 0_u64;
        for (envelope_position, envelope) in body.envelopes.iter().enumerate() {
            let (intent_id, instance_hash) = envelope_identity(envelope)?;
            let context = EvalContext {
                base,
                profile,
                accepted_intents: &accepted_intents,
                accepted_nullifiers: &accepted_nullifiers,
                accepted_commitments: &accepted_commitments,
                body_fee,
                reward_reserve_remaining: body_count - body_position,
                working: &working,
                capacity: &capacity,
            };
            let evaluated =
                evaluate_envelope(envelope, body.body_id, envelope_position as u32, &context);
            let outcome = match evaluated {
                Ok(effect) => {
                    body_fee = body_fee
                        .checked_add(effect.public_fee)
                        .ok_or_else(|| Error::code("kernel.internal_invariant"))?;
                    accepted_intents.insert(effect.accepted_effect.intent_id);
                    accepted_nullifiers.extend(effect.nullifiers.iter().copied());
                    accepted_commitments.extend(effect.outputs.iter().map(|(cm, _, _)| *cm));
                    apply_native_effect(&mut working, &effect)?;
                    capacity.accept_effect(&effect)?;
                    accepted_effects.push(effect.accepted_effect.clone());
                    let private = match envelope {
                        ConsensusEnvelopeV1::Transfer(value)
                            if value.transition_kind == TransferKind::Ordinary =>
                        {
                            PrivateNativeEffectV2::Transfer(effect)
                        }
                        ConsensusEnvelopeV1::Transfer(_) => PrivateNativeEffectV2::Mandate(effect),
                        ConsensusEnvelopeV1::Migration(_) => {
                            PrivateNativeEffectV2::ValueMigration(effect)
                        }
                    };
                    effects.push(private);
                    OutcomeBodyV2::Accepted
                }
                Err(code) => OutcomeBodyV2::Rejected(code),
            };
            let decision = DecisionBodyV2 {
                position: global_position,
                body_id: body.body_id,
                body_position: body_position as u32,
                envelope_position: envelope_position as u32,
                envelope_tag: envelope.tag(),
                intent_id,
                instance_hash,
                outcome,
            };
            capacity.accept_decision(&decision)?;
            decisions.push(decision);
            global_position = global_position
                .checked_add(1)
                .ok_or_else(|| Error::code("kernel.internal_invariant"))?;
        }
        let entry = &receipt.receipt().entries[body_position];
        let issuance_position = base_state
            .issuance_cursor
            .checked_add(body_position as u128 + 1)
            .ok_or_else(|| Error::code("kernel.issuance_cursor_overflow"))?;
        let subsidy = schedule_subsidy(profile, issuance_position)?;
        let derived_reward = derive_reward(
            profile,
            base.checkpoint().checkpoint_id,
            receipt.receipt().next_checkpoint_index,
            body_position as u32,
            entry,
            issuance_position,
            subsidy,
            body_fee,
        )?;
        if let Some(derived) = &derived_reward
            && (working
                .logical_state
                .commitment_history
                .contains(&derived.commitment)
                || accepted_commitments.contains(&derived.commitment))
        {
            return Err(Error::code("kernel.reward_derivation_conflict"));
        }
        let total_reward = subsidy
            .checked_add(body_fee)
            .ok_or_else(|| Error::code("kernel.native_issuance_overflow"))?;
        let event = RewardEventBodyV1 {
            body_position: body_position as u32,
            body_id: body.body_id,
            body_binding: interval.body_bindings()[body_position],
            issuance_position,
            subsidy,
            accepted_fees: body_fee,
            total_reward,
            derived_reward,
        };
        let reward_effect = SyntheticRewardEffectV1 {
            event: event.clone(),
        };
        apply_reward_effect(&mut working, &reward_effect)?;
        capacity.accept_reward(&event)?;
        reward_events.push(event);
        effects.push(PrivateNativeEffectV2::SyntheticReward(reward_effect));
    }
    let actual_state_bytes = working
        .canonical_bytes()
        .map_err(|_| reward_state_limit())?
        .len();
    let final_capacity = capacity
        .projected(None, None)
        .map_err(|_| capacity_arithmetic_error())?;
    if actual_state_bytes != capacity.state_canonical_bytes
        || actual_state_bytes != final_capacity.state_after_effect
    {
        return Err(capacity_arithmetic_error());
    }
    if !final_capacity.fits(byte_limit) {
        return Err(reward_state_limit());
    }
    let result = NativeIntervalResultV2 {
        decisions: decisions.into(),
        accepted_effects: accepted_effects.into(),
        reward_events: reward_events.into(),
        resulting_native_state: working,
    };
    if result.canonical_bytes()?.len() != final_capacity.interval_result {
        return Err(capacity_arithmetic_error());
    }
    let plan = PrivateNativeIntervalPlanV1 {
        base: base.clone(),
        profile: profile.clone(),
        interval_bytes: interval.interval().canonical_bytes()?,
        result: result.clone(),
        effects,
        body_ids: interval
            .interval()
            .bodies
            .iter()
            .map(|body| body.body_id)
            .collect(),
        body_bindings: interval.body_bindings().to_vec(),
        projected_checkpoint_bytes: final_capacity.checkpoint,
    };
    Ok(EvaluatedIntervalV2 {
        result,
        plan,
        #[cfg(feature = "private-test-harness")]
        preflight_capacity,
        #[cfg(feature = "private-test-harness")]
        final_capacity,
    })
}

pub fn verify_native_interval_result(
    unverified: Unverified<NativeIntervalResultV2>,
    base: &TrustedExecutionBase,
    profile: &VerifiedGate2ProfileV1,
    receipt: &VerifiedSyntheticEligibilityReceiptV1,
    interval: &VerifiedOrderedIntervalV1,
) -> Result<NativeIntervalResultV2, Error> {
    let recomputed = evaluate_interval(base, profile, receipt, interval)?.result;
    if unverified.decoded() != &recomputed {
        return Err(Error::code("codec.native_interval_result_mismatch"));
    }
    Ok(recomputed)
}

pub fn seal_interval(
    interval: &VerifiedOrderedIntervalV1,
    plan: PrivateNativeIntervalPlanV1,
) -> Result<TrustedTransitionV2, Error> {
    if interval.interval().canonical_bytes()? != plan.interval_bytes {
        return Err(Error::code("kernel.internal_invariant"));
    }
    let mut state = execution_start_state(&plan.base, &plan.profile);
    for effect in &plan.effects {
        match effect {
            PrivateNativeEffectV2::Transfer(value)
            | PrivateNativeEffectV2::Mandate(value)
            | PrivateNativeEffectV2::ValueMigration(value) => {
                apply_native_effect(&mut state, value)?
            }
            PrivateNativeEffectV2::SyntheticReward(value) => {
                apply_reward_effect(&mut state, value)?
            }
        }
    }
    if state != plan.result.resulting_native_state {
        return Err(Error::code("kernel.internal_invariant"));
    }
    let previous = plan.base.checkpoint().clone();
    let next_index = previous
        .checkpoint_index
        .checked_add(1)
        .ok_or_else(|| Error::code("kernel.checkpoint_index_overflow"))?;
    let mut body_history = previous.ordered_body_history.clone();
    body_history.extend(plan.body_ids.iter().copied());
    let active_fence_id = plan.base.effective_fence_id();
    let mut next = CheckpointStateWireV2 {
        checkpoint_id: [0; 32],
        previous_checkpoint: previous.checkpoint_id,
        checkpoint_index: next_index,
        native_state: state,
        ordered_body_history: body_history,
        bodies_in_checkpoint: plan.body_ids.clone().into(),
        body_bindings_in_checkpoint: plan.body_bindings.clone().into(),
        accepted_effects_in_checkpoint: plan.result.accepted_effects.clone(),
        reward_events_in_checkpoint: plan.result.reward_events.clone(),
        active_fence_id,
    };
    next.checkpoint_id = checkpoint_id(&next)?;
    if next.canonical_bytes()?.len() != plan.projected_checkpoint_bytes {
        return Err(capacity_arithmetic_error());
    }
    let lineage = match &plan.base {
        TrustedExecutionBase::Checkpoint(value) => value.lineage().cloned(),
        TrustedExecutionBase::Successor(value) => Some(lineage_from_successor(value)),
    };
    let trusted_next = fresh_trusted_checkpoint(next.clone(), &plan.profile, lineage)?;
    let transition = TransitionV2 {
        previous,
        next,
        execution_fence_id: match &plan.base {
            TrustedExecutionBase::Successor(value) => Some(value.fence_id),
            _ => None,
        },
        decisions: plan.result.decisions.clone(),
        reward_events: plan.result.reward_events.clone(),
    };
    Ok(TrustedTransitionV2 {
        transition,
        previous_base: plan.base,
        next_checkpoint: trusted_next,
    })
}

pub fn verify_transition(
    unverified: Unverified<TransitionV2>,
    base: &TrustedExecutionBase,
    profile: &VerifiedGate2ProfileV1,
    receipt: &VerifiedSyntheticEligibilityReceiptV1,
    interval: &VerifiedOrderedIntervalV1,
) -> Result<TrustedTransitionV2, Error> {
    let evaluated = evaluate_interval(base, profile, receipt, interval)?;
    let sealed = seal_interval(interval, evaluated.into_plan())?;
    if unverified.decoded() != sealed.transition() {
        return Err(Error::code("codec.transition_mismatch"));
    }
    Ok(sealed)
}

#[cfg(test)]
mod tests {
    use super::{CanonicalCapacity, checked_capacity_add};
    use crate::MAX_STATE_BYTES;

    #[test]
    fn canonical_capacity_is_inclusive_at_the_exact_byte_boundary() {
        let exact = CanonicalCapacity {
            state_after_effect: MAX_STATE_BYTES - 2,
            state_projection: MAX_STATE_BYTES,
            interval_result: MAX_STATE_BYTES,
            checkpoint: MAX_STATE_BYTES,
        };
        assert!(exact.fits(MAX_STATE_BYTES));
        assert!(!exact.fits(MAX_STATE_BYTES - 1));
        assert_eq!(
            checked_capacity_add(usize::MAX, 1).unwrap_err().as_code(),
            "kernel.internal_invariant"
        );
    }
}
