//! Trusted-state validation and capability types.

#![allow(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};

#[cfg(feature = "private-test-harness")]
use sha2::{Digest, Sha256};

use crate::{
    BodyNamespaceKind, CanonicalEncode, CheckpointStateWireV2, DerivedRewardV1, EligibilityEntryV1,
    Error, Hash32, LegacyExitDescriptorV1, LegacyTransitionKind, MAX_BODY_BYTES, MAX_BODY_HISTORY,
    MAX_ENVELOPE_BYTES, MAX_ENVELOPES, MAX_ISSUANCE_EVENTS, NativeNoteV2, NoteType, OrderedBodyV2,
    OrderedIntervalV1, OutputRole, ParentKind, ProfileHandoffBodyV1, RecoveryKind,
    RecoveryRecordV2, RewardEventBodyV1, RewardOriginV1, SortedUniqueVec,
    SyntheticEligibilityReceiptV1, TransitionAnchorBodyV1, Unverified, VerifiedGate2ProfileV1,
    body_binding, checkpoint_id, envelope_identity, legacy_anchor_set_hash, note_commitment,
    note_nullifier, recovery_hash, reward_component, reward_recovery_payload, reward_seed,
};

#[cfg(feature = "private-test-harness")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntheticHarnessAuthority {
    marker: (),
}
#[cfg(feature = "private-test-harness")]
impl SyntheticHarnessAuthority {
    pub const fn for_private_valueless_tests() -> Self {
        Self { marker: () }
    }

    fn authenticate_artifact(
        bytes: &[u8],
        expected_length: usize,
        expected_sha256: Hash32,
        mismatch_code: &'static str,
    ) -> Result<Vec<u8>, Error> {
        let actual_sha256: Hash32 = Sha256::digest(bytes).into();
        if bytes.len() != expected_length || actual_sha256 != expected_sha256 {
            return Err(Error::code(mismatch_code));
        }
        Ok(bytes.to_vec())
    }

    pub fn authenticate_checkpoint_artifact(
        &self,
        bytes: &[u8],
        expected_length: usize,
        expected_sha256: Hash32,
    ) -> Result<CheckpointPin, Error> {
        Ok(CheckpointPin {
            bytes: Self::authenticate_artifact(
                bytes,
                expected_length,
                expected_sha256,
                "codec.checkpoint_pin_mismatch",
            )?,
        })
    }

    pub fn authenticate_interval_artifact(
        &self,
        bytes: &[u8],
        expected_length: usize,
        expected_sha256: Hash32,
    ) -> Result<SyntheticOrderedIntervalPin, Error> {
        Ok(SyntheticOrderedIntervalPin {
            bytes: Self::authenticate_artifact(
                bytes,
                expected_length,
                expected_sha256,
                "codec.interval_pin_mismatch",
            )?,
        })
    }

    pub fn authenticate_receipt_artifact(
        &self,
        bytes: &[u8],
        expected_length: usize,
        expected_sha256: Hash32,
    ) -> Result<SyntheticEligibilityReceiptPin, Error> {
        Ok(SyntheticEligibilityReceiptPin {
            bytes: Self::authenticate_artifact(
                bytes,
                expected_length,
                expected_sha256,
                "codec.eligibility_pin_mismatch",
            )?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointPin {
    bytes: Vec<u8>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntheticOrderedIntervalPin {
    bytes: Vec<u8>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntheticEligibilityReceiptPin {
    bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FenceLineageCapability {
    fence_id: Hash32,
    legacy_exit_descriptors: SortedUniqueVec<LegacyExitDescriptorV1, { crate::MAX_LEGACY_EXITS }>,
}
impl FenceLineageCapability {
    pub const fn fence_id(&self) -> &Hash32 {
        &self.fence_id
    }
    pub fn legacy_exit_descriptors(&self) -> &[LegacyExitDescriptorV1] {
        &self.legacy_exit_descriptors
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedCheckpointV2 {
    checkpoint: CheckpointStateWireV2,
    pin: CheckpointPin,
    lineage: Option<FenceLineageCapability>,
}
impl TrustedCheckpointV2 {
    pub const fn checkpoint(&self) -> &CheckpointStateWireV2 {
        &self.checkpoint
    }
    pub const fn lineage(&self) -> Option<&FenceLineageCapability> {
        self.lineage.as_ref()
    }
    pub fn execution_base(self) -> TrustedExecutionBase {
        TrustedExecutionBase::Checkpoint(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SuccessorExecutionBaseV1 {
    pub(crate) predecessor_checkpoint: TrustedCheckpointV2,
    pub(crate) predecessor_profile: VerifiedGate2ProfileV1,
    pub(crate) successor_profile: VerifiedGate2ProfileV1,
    pub(crate) handoff: ProfileHandoffBodyV1,
    pub(crate) transition_anchor: TransitionAnchorBodyV1,
    pub(crate) transition_anchor_id: Hash32,
    pub(crate) fence_id: Hash32,
    pub(crate) successor_legacy_exit_descriptors:
        SortedUniqueVec<LegacyExitDescriptorV1, { crate::MAX_LEGACY_EXITS }>,
}
impl SuccessorExecutionBaseV1 {
    pub const fn predecessor(&self) -> &TrustedCheckpointV2 {
        &self.predecessor_checkpoint
    }
    pub const fn successor_profile(&self) -> &VerifiedGate2ProfileV1 {
        &self.successor_profile
    }
    pub const fn fence_id(&self) -> &Hash32 {
        &self.fence_id
    }
    pub fn execution_base(self) -> TrustedExecutionBase {
        TrustedExecutionBase::Successor(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum TrustedExecutionBase {
    Checkpoint(TrustedCheckpointV2),
    Successor(SuccessorExecutionBaseV1),
}
impl TrustedExecutionBase {
    pub const fn checkpoint(&self) -> &CheckpointStateWireV2 {
        match self {
            Self::Checkpoint(value) => &value.checkpoint,
            Self::Successor(value) => &value.predecessor_checkpoint.checkpoint,
        }
    }
    pub const fn effective_fence_id(&self) -> Option<Hash32> {
        match self {
            Self::Checkpoint(value) => match &value.lineage {
                Some(v) => Some(v.fence_id),
                None => None,
            },
            Self::Successor(value) => Some(value.fence_id),
        }
    }
    pub fn rollback(self) -> TrustedExecutionBase {
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedOrderedIntervalV1 {
    interval: OrderedIntervalV1,
    pub(crate) trusted_base_identity: Hash32,
    pub(crate) verified_profile_domain: Hash32,
    pin: SyntheticOrderedIntervalPin,
    body_bindings: Vec<Hash32>,
}
impl VerifiedOrderedIntervalV1 {
    pub const fn interval(&self) -> &OrderedIntervalV1 {
        &self.interval
    }
    pub fn body_bindings(&self) -> &[Hash32] {
        &self.body_bindings
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSyntheticEligibilityReceiptV1 {
    receipt: SyntheticEligibilityReceiptV1,
    pin: SyntheticEligibilityReceiptPin,
}
impl VerifiedSyntheticEligibilityReceiptV1 {
    pub const fn receipt(&self) -> &SyntheticEligibilityReceiptV1 {
        &self.receipt
    }
}

fn required_recovery_kind(note: &NativeNoteV2) -> RecoveryKind {
    match note.note_type {
        NoteType::Value => RecoveryKind::Ordinary,
        NoteType::Mandate => RecoveryKind::MandateDual,
        NoteType::Reward => RecoveryKind::Reward,
    }
}

pub(crate) fn validate_mandate_note(
    note: &NativeNoteV2,
    profile: &VerifiedGate2ProfileV1,
) -> Result<(), Error> {
    let Some(mandate) = note.mandate_state.as_ref() else {
        return Err(Error::code("kernel.invalid_state"));
    };
    let p = &profile.profile().manifest_body;
    if note.value == 0
        || note.owner_tag != mandate.principal_spend_tag
        || note.suite_id != p.mandate_suite_id
        || mandate.policy_module_id != p.mandate_policy_module_id
        || mandate.mandate_version != p.mandate_version
        || mandate.delegation_depth_left != 0
        || mandate.frequency_mode != crate::FrequencyMode::SerialWindow
        || mandate.window_size_checkpoints == 0
        || mandate.max_actions_per_window == 0
        || mandate.actions_in_window > mandate.max_actions_per_window
        || mandate.remaining_action_tokens == 0
        || mandate.recipient_roots.is_empty()
        || mandate.application_roots.is_empty()
        || mandate.parent_policy_hash != [0; 32]
        || !mandate.policy_caveat_hashes.is_empty()
    {
        return Err(Error::code("kernel.invalid_state"));
    }
    Ok(())
}

pub(crate) fn validate_note_options(
    note: &NativeNoteV2,
    profile: &VerifiedGate2ProfileV1,
) -> Result<(), Error> {
    match note.note_type {
        NoteType::Value if note.mandate_state.is_none() && note.reward_origin.is_none() => Ok(()),
        NoteType::Mandate if note.mandate_state.is_some() && note.reward_origin.is_none() => {
            validate_mandate_note(note, profile)
        }
        NoteType::Reward
            if note.mandate_state.is_none()
                && note.reward_origin.is_some()
                && note.suite_id == profile.profile().manifest_body.reward_suite_id =>
        {
            Ok(())
        }
        _ => Err(Error::code("kernel.invalid_state")),
    }
}

pub(crate) fn schedule_subsidy(
    profile: &VerifiedGate2ProfileV1,
    position: u128,
) -> Result<u64, Error> {
    if position == 0 {
        return Err(Error::code("kernel.invalid_state"));
    }
    profile
        .profile()
        .manifest_body
        .synthetic_reward_schedule
        .bands
        .iter()
        .rev()
        .find(|band| band.start_position <= position)
        .map(|band| band.subsidy)
        .ok_or_else(|| Error::code("kernel.invalid_state"))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn derive_reward(
    profile: &VerifiedGate2ProfileV1,
    previous_checkpoint: Hash32,
    checkpoint_index: u64,
    body_position: u32,
    entry: &EligibilityEntryV1,
    issuance_position: u128,
    subsidy: u64,
    accepted_fees: u64,
) -> Result<Option<DerivedRewardV1>, Error> {
    let total = subsidy
        .checked_add(accepted_fees)
        .ok_or_else(|| Error::code("kernel.native_issuance_overflow"))?;
    if total == 0 {
        return Ok(None);
    }
    let chain = profile.profile().manifest_body.chain_domain;
    let seed = reward_seed(
        &chain,
        &previous_checkpoint,
        checkpoint_index,
        body_position,
        &entry.body_id,
        &entry.body_binding,
        &profile.profile().profile_domain,
        &entry.reward_suite_id,
        issuance_position,
        &entry.receiver,
        &entry.nonce,
        subsidy,
        accepted_fees,
    )?;
    let origin = RewardOriginV1 {
        previous_checkpoint,
        checkpoint_index,
        body_position,
        body_id: entry.body_id,
        body_binding: entry.body_binding,
        profile_domain: profile.profile().profile_domain,
        reward_suite_id: entry.reward_suite_id,
        issuance_position,
        receiver: entry.receiver,
        nonce: entry.nonce,
        subsidy,
        accepted_fees,
    };
    let note = NativeNoteV2 {
        note_type: NoteType::Reward,
        suite_id: entry.reward_suite_id,
        value: total,
        owner_tag: entry.receiver,
        rho: reward_component(b"Silk-Transparent-Reward-Rho-v1", &seed)?,
        randomness: reward_component(b"Silk-Transparent-Reward-Randomness-v1", &seed)?,
        nullifier_key: reward_component(b"Silk-Transparent-Reward-Nullifier-Key-v1", &seed)?,
        mandate_state: None,
        reward_origin: Some(origin),
    };
    let commitment = note_commitment(&chain, &note)?;
    let recovery_record = RecoveryRecordV2 {
        record_kind: RecoveryKind::Reward,
        output_commitment: commitment,
        payload: reward_recovery_payload(&seed)?,
    };
    let recovery_hash_value = recovery_hash(&chain, &recovery_record)?;
    Ok(Some(DerivedRewardV1 {
        note,
        commitment,
        recovery_record,
        recovery_hash: recovery_hash_value,
    }))
}

fn validate_reward_event(
    event: &RewardEventBodyV1,
    profile: &VerifiedGate2ProfileV1,
) -> Result<(), Error> {
    let subsidy = schedule_subsidy(profile, event.issuance_position)?;
    if event.subsidy != subsidy
        || event.accepted_fees > profile.profile().manifest_body.max_accepted_fees_per_body
        || event.total_reward
            != event
                .subsidy
                .checked_add(event.accepted_fees)
                .ok_or_else(|| Error::code("kernel.invalid_state"))?
    {
        return Err(Error::code("kernel.checkpoint_binding_mismatch"));
    }
    let Some(derived) = event.derived_reward.as_ref() else {
        return if event.total_reward == 0 {
            Ok(())
        } else {
            Err(Error::code("kernel.invalid_state"))
        };
    };
    if event.total_reward == 0 {
        return Err(Error::code("kernel.invalid_state"));
    }
    let Some(origin) = derived.note.reward_origin.as_ref() else {
        return Err(Error::code("kernel.invalid_state"));
    };
    // Historical rewards retain the profile domain that created them.  A
    // successor profile preserves the schedule and reward suite but must not
    // rewrite that committed origin while replaying the global history.
    let expected_origin = RewardOriginV1 {
        previous_checkpoint: origin.previous_checkpoint,
        checkpoint_index: origin.checkpoint_index,
        body_position: event.body_position,
        body_id: event.body_id,
        body_binding: event.body_binding,
        profile_domain: origin.profile_domain,
        reward_suite_id: origin.reward_suite_id,
        issuance_position: event.issuance_position,
        receiver: origin.receiver,
        nonce: origin.nonce,
        subsidy: event.subsidy,
        accepted_fees: event.accepted_fees,
    };
    let chain = profile.profile().manifest_body.chain_domain;
    let seed = reward_seed(
        &chain,
        &expected_origin.previous_checkpoint,
        expected_origin.checkpoint_index,
        expected_origin.body_position,
        &expected_origin.body_id,
        &expected_origin.body_binding,
        &expected_origin.profile_domain,
        &expected_origin.reward_suite_id,
        expected_origin.issuance_position,
        &expected_origin.receiver,
        &expected_origin.nonce,
        expected_origin.subsidy,
        expected_origin.accepted_fees,
    )?;
    let expected_note = NativeNoteV2 {
        note_type: NoteType::Reward,
        suite_id: expected_origin.reward_suite_id,
        value: event.total_reward,
        owner_tag: expected_origin.receiver,
        rho: reward_component(b"Silk-Transparent-Reward-Rho-v1", &seed)?,
        randomness: reward_component(b"Silk-Transparent-Reward-Randomness-v1", &seed)?,
        nullifier_key: reward_component(b"Silk-Transparent-Reward-Nullifier-Key-v1", &seed)?,
        mandate_state: None,
        reward_origin: Some(expected_origin),
    };
    let commitment = note_commitment(&chain, &expected_note)?;
    let recovery_record = RecoveryRecordV2 {
        record_kind: RecoveryKind::Reward,
        output_commitment: commitment,
        payload: reward_recovery_payload(&seed)?,
    };
    let expected = DerivedRewardV1 {
        note: expected_note,
        commitment,
        recovery_hash: recovery_hash(&chain, &recovery_record)?,
        recovery_record,
    };
    if &expected != derived {
        return Err(Error::code("kernel.invalid_state"));
    }
    Ok(())
}

pub fn validate_checkpoint_state(
    checkpoint: &CheckpointStateWireV2,
    profile: &VerifiedGate2ProfileV1,
    lineage: Option<&FenceLineageCapability>,
) -> Result<(), Error> {
    let state = &checkpoint.native_state;
    let p = profile.profile();
    if state.protocol_manifest_hash != p.protocol_manifest_hash
        || state.profile_domain != p.profile_domain
        || state.policy_phase_root != p.policy_phase_root
        || state.active_suite_ids != p.manifest_body.active_suite_ids
        || state.retained_migration_source_suite_ids
            != p.manifest_body.retained_migration_source_suite_ids
        || state.reward_suite_id != p.manifest_body.reward_suite_id
        || state.mandate_suite_id != p.manifest_body.mandate_suite_id
        || state.reward_schedule_hash != p.reward_schedule_hash
        || state.logical_state.chain_domain != p.manifest_body.chain_domain
    {
        return Err(Error::code("kernel.checkpoint_binding_mismatch"));
    }
    match (checkpoint.active_fence_id, lineage) {
        (None, None) if state.legacy_exit_descriptors.is_empty() => {}
        (Some(id), Some(expected))
            if id == expected.fence_id
                && state.legacy_exit_descriptors == expected.legacy_exit_descriptors => {}
        _ => return Err(Error::code("kernel.checkpoint_binding_mismatch")),
    }
    let chain = state.logical_state.chain_domain;
    let mut history_counts = BTreeMap::new();
    for cm in &state.logical_state.commitment_history.0 {
        *history_counts.entry(*cm).or_insert(0_u32) += 1;
    }
    if state.logical_state.commitment_history.len() != state.logical_state.recovery_history.len() {
        return Err(Error::code("kernel.invalid_state"));
    }
    for (cm, note) in state.logical_state.live_notes.iter() {
        if (!state.active_suite_ids.contains(&note.suite_id)
            && !state
                .retained_migration_source_suite_ids
                .contains(&note.suite_id))
            || note_commitment(&chain, note)? != *cm
            || history_counts.get(cm) != Some(&1)
            || state
                .logical_state
                .nullifiers
                .contains(&note_nullifier(&chain, note, cm)?)
        {
            return Err(Error::code("kernel.invalid_state"));
        }
        validate_note_options(note, profile)?;
        if state
            .retained_migration_source_suite_ids
            .contains(&note.suite_id)
            && note.note_type != NoteType::Value
        {
            return Err(Error::code("kernel.invalid_state"));
        }
    }
    let mut seen_commitments = BTreeSet::new();
    for (index, cm) in state.logical_state.commitment_history.iter().enumerate() {
        if !seen_commitments.insert(*cm) {
            return Err(Error::code("kernel.invalid_state"));
        }
        let record = &state.logical_state.recovery_history[index];
        if record.output_commitment != *cm {
            return Err(Error::code("kernel.invalid_state"));
        }
        if let Some(note) = state.logical_state.live_notes.get(cm)
            && record.record_kind != required_recovery_kind(note)
        {
            return Err(Error::code("kernel.invalid_state"));
        }
    }
    let intent_set = state
        .logical_state
        .accepted_intents
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if intent_set.len() != state.logical_state.accepted_intents.len() {
        return Err(Error::code("kernel.invalid_state"));
    }
    let body_positions = checkpoint
        .ordered_body_history
        .iter()
        .enumerate()
        .map(|(position, body_id)| (*body_id, position))
        .collect::<BTreeMap<_, _>>();
    let mut effect_intents = BTreeSet::new();
    let mut last_effect_position: Option<(usize, u32)> = None;
    for effect in &state.logical_state.accepted_effect_history.0 {
        if !effect_intents.insert(effect.intent_id) || !intent_set.contains(&effect.intent_id) {
            return Err(Error::code("kernel.invalid_state"));
        }
        let Some(body_position) = body_positions.get(&effect.body_id).copied() else {
            return Err(Error::code("kernel.invalid_state"));
        };
        let position = (body_position, effect.envelope_position);
        if last_effect_position.is_some_and(|previous| position <= previous) {
            return Err(Error::code("kernel.invalid_state"));
        }
        last_effect_position = Some(position);
    }
    if intent_set != effect_intents {
        return Err(Error::code("kernel.invalid_state"));
    }
    let current_bodies = checkpoint
        .bodies_in_checkpoint
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut current_effect_start = state.logical_state.accepted_effect_history.len();
    while current_effect_start > 0
        && current_bodies.contains(
            &state.logical_state.accepted_effect_history[current_effect_start - 1].body_id,
        )
    {
        current_effect_start -= 1;
    }
    if checkpoint.accepted_effects_in_checkpoint.as_slice()
        != &state.logical_state.accepted_effect_history[current_effect_start..]
    {
        return Err(Error::code("kernel.invalid_state"));
    }

    if state.logical_state.issuance_cursor > MAX_ISSUANCE_EVENTS as u128
        || state.logical_state.issuance_event_history.len() as u128
            != state.logical_state.issuance_cursor
    {
        return Err(Error::code("kernel.invalid_state"));
    }
    if state.logical_state.issuance_event_history.len() != checkpoint.ordered_body_history.len()
        || state
            .logical_state
            .issuance_event_history
            .iter()
            .zip(checkpoint.ordered_body_history.iter())
            .any(|(event, body_id)| event.body_id != *body_id)
    {
        return Err(Error::code("kernel.invalid_state"));
    }
    let mut subsidy_total = 0_u128;
    let mut last_reward_commitment_position: Option<usize> = None;
    let mut effect_index = 0_usize;
    let mut expected_materialization = Vec::new();
    let mut expected_recovery_kinds = vec![RecoveryKind::Ordinary, RecoveryKind::Ordinary];
    for (index, event) in state
        .logical_state
        .issuance_event_history
        .iter()
        .enumerate()
    {
        if event.issuance_position != index as u128 + 1 {
            return Err(Error::code("kernel.invalid_state"));
        }
        while effect_index < state.logical_state.accepted_effect_history.len()
            && state.logical_state.accepted_effect_history[effect_index].body_id == event.body_id
        {
            let effect = &state.logical_state.accepted_effect_history[effect_index];
            if effect.output_commitments.len() != effect.output_roles.len()
                || effect.output_roles.contains(&OutputRole::RewardDerived)
            {
                return Err(Error::code("kernel.invalid_state"));
            }
            expected_materialization.extend_from_slice(&effect.output_commitments);
            expected_recovery_kinds.extend(effect.output_roles.iter().map(|role| match role {
                OutputRole::MandateCreate | OutputRole::MandateSuccessor => {
                    RecoveryKind::MandateDual
                }
                _ => RecoveryKind::Ordinary,
            }));
            effect_index += 1;
        }
        validate_reward_event(event, profile)?;
        subsidy_total = subsidy_total
            .checked_add(u128::from(event.subsidy))
            .ok_or_else(|| Error::code("kernel.invalid_state"))?;
        if !checkpoint.ordered_body_history.contains(&event.body_id) {
            return Err(Error::code("kernel.invalid_state"));
        }
        if let Some(derived) = &event.derived_reward {
            expected_materialization.push(derived.commitment);
            expected_recovery_kinds.push(RecoveryKind::Reward);
            if history_counts.get(&derived.commitment) != Some(&1) {
                return Err(Error::code("kernel.invalid_state"));
            }
            let Some(position) = state
                .logical_state
                .commitment_history
                .iter()
                .position(|commitment| *commitment == derived.commitment)
            else {
                return Err(Error::code("kernel.invalid_state"));
            };
            if last_reward_commitment_position.is_some_and(|previous| position <= previous) {
                return Err(Error::code("kernel.invalid_state"));
            }
            last_reward_commitment_position = Some(position);
            if state.logical_state.recovery_history[position] != derived.recovery_record {
                return Err(Error::code("kernel.invalid_state"));
            }
        }
    }
    if effect_index != state.logical_state.accepted_effect_history.len()
        || state.logical_state.commitment_history.len() != 2 + expected_materialization.len()
        || state.logical_state.commitment_history[2..] != expected_materialization
        || state
            .logical_state
            .recovery_history
            .iter()
            .map(|record| record.record_kind)
            .ne(expected_recovery_kinds)
    {
        return Err(Error::code("kernel.invalid_state"));
    }
    if state.logical_state.native_issued
        != state
            .logical_state
            .native_genesis_issued
            .checked_add(subsidy_total)
            .ok_or_else(|| Error::code("kernel.invalid_state"))?
    {
        return Err(Error::code("kernel.invalid_state"));
    }
    if checkpoint.reward_events_in_checkpoint.len()
        > state.logical_state.issuance_event_history.len()
        || !state
            .logical_state
            .issuance_event_history
            .ends_with(&checkpoint.reward_events_in_checkpoint)
        || checkpoint.reward_events_in_checkpoint.len() != checkpoint.bodies_in_checkpoint.len()
        || checkpoint
            .reward_events_in_checkpoint
            .iter()
            .zip(
                checkpoint
                    .bodies_in_checkpoint
                    .iter()
                    .zip(checkpoint.body_bindings_in_checkpoint.iter()),
            )
            .enumerate()
            .any(|(position, (event, (body_id, binding)))| {
                event.body_position != position as u32
                    || event.body_id != *body_id
                    || event.body_binding != *binding
                    || event.derived_reward.as_ref().is_some_and(|derived| {
                        derived.note.reward_origin.as_ref().is_none_or(|origin| {
                            origin.previous_checkpoint != checkpoint.previous_checkpoint
                                || origin.checkpoint_index != checkpoint.checkpoint_index
                        })
                    })
            })
    {
        return Err(Error::code("kernel.invalid_state"));
    }
    if let Some(derived) = checkpoint
        .reward_events_in_checkpoint
        .last()
        .and_then(|event| event.derived_reward.as_ref())
        && state.logical_state.commitment_history.last() != Some(&derived.commitment)
    {
        return Err(Error::code("kernel.invalid_state"));
    }

    for descriptor in &state.legacy_exit_descriptors.0 {
        if !state
            .retained_migration_source_suite_ids
            .contains(&descriptor.source_suite_id)
            || descriptor.migration_relation_hash != p.manifest_body.migration_relation_hash
            || descriptor.allowed_transition != LegacyTransitionKind::ValueSuiteMigration
        {
            return Err(Error::code("kernel.invalid_state"));
        }
    }
    for suite in &state.retained_migration_source_suite_ids.0 {
        if state
            .legacy_exit_descriptors
            .iter()
            .filter(|d| d.source_suite_id == *suite)
            .count()
            != 1
        {
            return Err(Error::code("kernel.invalid_state"));
        }
    }
    let _legacy = legacy_anchor_set_hash(state)?;
    if checkpoint.ordered_body_history.len() > MAX_BODY_HISTORY
        || checkpoint.bodies_in_checkpoint.len() != checkpoint.body_bindings_in_checkpoint.len()
        || checkpoint.bodies_in_checkpoint.len() > checkpoint.ordered_body_history.len()
        || !checkpoint
            .ordered_body_history
            .ends_with(&checkpoint.bodies_in_checkpoint)
    {
        return Err(Error::code("kernel.invalid_state"));
    }
    let mut body_ids = BTreeSet::new();
    if checkpoint
        .ordered_body_history
        .iter()
        .any(|body| !body_ids.insert(*body))
    {
        return Err(Error::code("kernel.invalid_state"));
    }
    if checkpoint
        .accepted_effects_in_checkpoint
        .iter()
        .any(|e| !checkpoint.bodies_in_checkpoint.contains(&e.body_id))
        || checkpoint
            .reward_events_in_checkpoint
            .iter()
            .any(|e| !checkpoint.bodies_in_checkpoint.contains(&e.body_id))
    {
        return Err(Error::code("kernel.invalid_state"));
    }
    if state.logical_state.native_burned != 0
        || state.logical_state.native_issued < state.logical_state.native_burned
    {
        return Err(Error::code("kernel.invalid_state"));
    }
    let live_sum = state
        .logical_state
        .live_notes
        .iter()
        .try_fold(0_u128, |sum, (_, note)| {
            sum.checked_add(u128::from(note.value))
                .ok_or_else(|| Error::code("kernel.invalid_state"))
        })?;
    let accounted = live_sum
        .checked_add(state.logical_state.fee_pool)
        .ok_or_else(|| Error::code("kernel.invalid_state"))?;
    if accounted != state.logical_state.native_issued - state.logical_state.native_burned
        || state.logical_state.fee_pool != 0
    {
        return Err(Error::code("kernel.invalid_state"));
    }
    if checkpoint_id(checkpoint)? != checkpoint.checkpoint_id {
        return Err(Error::code("codec.checkpoint_identity_mismatch"));
    }
    Ok(())
}

pub fn promote_checkpoint(
    unverified: Unverified<CheckpointStateWireV2>,
    profile: &VerifiedGate2ProfileV1,
    lineage: Option<FenceLineageCapability>,
    pin: &CheckpointPin,
) -> Result<TrustedCheckpointV2, Error> {
    let checkpoint = unverified.into_inner();
    validate_checkpoint_state(&checkpoint, profile, lineage.as_ref())?;
    if checkpoint.canonical_bytes()? != pin.bytes {
        return Err(Error::code("codec.checkpoint_pin_mismatch"));
    }
    Ok(TrustedCheckpointV2 {
        checkpoint,
        pin: pin.clone(),
        lineage,
    })
}

/// Replays checkpoint promotion against the opaque byte pin already carried
/// by an independently trusted checkpoint capability.
pub fn verify_checkpoint_replay(
    unverified: Unverified<CheckpointStateWireV2>,
    expected: &TrustedCheckpointV2,
    profile: &VerifiedGate2ProfileV1,
) -> Result<TrustedCheckpointV2, Error> {
    promote_checkpoint(unverified, profile, expected.lineage.clone(), &expected.pin)
}

fn validate_namespace(
    body: &OrderedBodyV2,
    body_position: usize,
    base: &TrustedExecutionBase,
    profile: &VerifiedGate2ProfileV1,
) -> Result<(), Error> {
    let namespace = &body.namespace;
    if namespace.profile_domain != profile.profile().profile_domain {
        return Err(Error::code("kernel.body_namespace_mismatch"));
    }
    let mut parent_ids = BTreeSet::new();
    if namespace
        .parents
        .iter()
        .any(|p| !parent_ids.insert(p.parent_id))
    {
        return Err(Error::code("kernel.body_namespace_mismatch"));
    }
    match base {
        TrustedExecutionBase::Checkpoint(trusted) if trusted.lineage.is_none() => {
            if namespace.namespace_kind != BodyNamespaceKind::Unfenced
                || namespace.active_fence_id.is_some()
                || namespace.parents.iter().any(|p| {
                    p.parent_kind != ParentKind::Body
                        || p.profile_domain != profile.profile().profile_domain
                        || p.lineage_fence_id.is_some()
                })
                || (namespace.parents.is_empty()
                    && !(body_position == 0
                        && trusted.checkpoint.checkpoint_index == 0
                        && trusted.checkpoint.ordered_body_history.is_empty()))
            {
                return Err(Error::code("kernel.body_namespace_mismatch"));
            }
        }
        TrustedExecutionBase::Successor(successor) => match namespace.namespace_kind {
            BodyNamespaceKind::Unfenced => {
                return Err(Error::code("kernel.body_namespace_mismatch"));
            }
            BodyNamespaceKind::FenceDirect => {
                if namespace.active_fence_id != Some(successor.fence_id)
                    || namespace.parents.len() != 1
                {
                    return Err(Error::code("kernel.body_namespace_mismatch"));
                }
                let p = &namespace.parents[0];
                if p.parent_kind != ParentKind::Fence
                    || p.parent_id != successor.fence_id
                    || p.profile_domain != profile.profile().profile_domain
                    || p.lineage_fence_id != Some(successor.fence_id)
                {
                    return Err(Error::code("kernel.body_namespace_mismatch"));
                }
            }
            BodyNamespaceKind::FenceDescendant => {
                validate_descendant(namespace, successor.fence_id, profile)?
            }
        },
        TrustedExecutionBase::Checkpoint(trusted) => {
            let fence = trusted.lineage.as_ref().expect("matched arm").fence_id;
            if namespace.namespace_kind != BodyNamespaceKind::FenceDescendant {
                return Err(Error::code("kernel.body_namespace_mismatch"));
            }
            validate_descendant(namespace, fence, profile)?;
        }
    }
    Ok(())
}

fn validate_descendant(
    namespace: &crate::BodyNamespaceV1,
    fence: Hash32,
    profile: &VerifiedGate2ProfileV1,
) -> Result<(), Error> {
    if namespace.active_fence_id != Some(fence)
        || namespace.parents.is_empty()
        || namespace.parents.iter().any(|p| {
            p.parent_kind != ParentKind::Body
                || p.profile_domain != profile.profile().profile_domain
                || p.lineage_fence_id != Some(fence)
        })
    {
        return Err(Error::code("kernel.body_namespace_mismatch"));
    }
    Ok(())
}

pub fn promote_ordered_interval(
    unverified: Unverified<OrderedIntervalV1>,
    base: &TrustedExecutionBase,
    profile: &VerifiedGate2ProfileV1,
    pin: &SyntheticOrderedIntervalPin,
) -> Result<VerifiedOrderedIntervalV1, Error> {
    let interval = unverified.into_inner();
    let checkpoint = base.checkpoint();
    let expected_profile = match base {
        TrustedExecutionBase::Checkpoint(_) => checkpoint.native_state.profile_domain,
        TrustedExecutionBase::Successor(value) => value.successor_profile.profile().profile_domain,
    };
    if expected_profile != profile.profile().profile_domain {
        return Err(Error::code("kernel.checkpoint_binding_mismatch"));
    }
    let lineage = match base {
        TrustedExecutionBase::Checkpoint(v) => v.lineage.as_ref(),
        TrustedExecutionBase::Successor(_) => None,
    };
    if matches!(base, TrustedExecutionBase::Checkpoint(_)) {
        validate_checkpoint_state(checkpoint, profile, lineage)?;
    }
    if checkpoint_id(checkpoint)? != checkpoint.checkpoint_id {
        return Err(Error::code("codec.checkpoint_identity_mismatch"));
    }
    if interval.bodies.is_empty() {
        return Err(Error::code("kernel.empty_checkpoint"));
    }
    if interval.bodies.len() > crate::MAX_BODIES {
        return Err(Error::code("kernel.too_many_ordered_bodies"));
    }
    let total_envelopes = interval.bodies.iter().try_fold(0_usize, |sum, body| {
        sum.checked_add(body.envelopes.len())
            .ok_or_else(|| Error::code("kernel.too_many_envelopes"))
    })?;
    if total_envelopes > MAX_ENVELOPES {
        return Err(Error::code("kernel.too_many_envelopes"));
    }
    if checkpoint
        .ordered_body_history
        .len()
        .saturating_add(interval.bodies.len())
        > MAX_BODY_HISTORY
    {
        return Err(Error::code("kernel.body_history_limit"));
    }
    let mut ids = checkpoint
        .ordered_body_history
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut bindings = Vec::with_capacity(interval.bodies.len());
    let mut has_direct = false;
    for (body_position, body) in interval.bodies.iter().enumerate() {
        if !ids.insert(body.body_id) {
            return Err(Error::code("kernel.duplicate_ordered_body"));
        }
        validate_namespace(body, body_position, base, profile)?;
        has_direct |= body.namespace.namespace_kind == BodyNamespaceKind::FenceDirect;
        let body_bytes = body.canonical_bytes()?;
        if body_bytes.len() > MAX_BODY_BYTES {
            return Err(Error::code("canonical.byte_limit_exceeded"));
        }
        let mut prior: Option<(Hash32, Hash32, Vec<u8>)> = None;
        for envelope in &body.envelopes.0 {
            let canonical = envelope.canonical_bytes()?;
            if canonical.len() > MAX_ENVELOPE_BYTES {
                return Err(Error::code("canonical.byte_limit_exceeded"));
            }
            let (intent, instance) = envelope_identity(envelope)?;
            let key = (intent, instance, canonical);
            if prior.as_ref().is_some_and(|old| key <= *old) {
                return Err(Error::code("kernel.noncanonical_body_envelopes"));
            }
            prior = Some(key);
        }
        bindings.push(body_binding(
            &profile.profile().manifest_body.chain_domain,
            &profile.profile().profile_domain,
            &body.namespace,
            &body.envelopes,
        )?);
    }
    if matches!(base, TrustedExecutionBase::Successor(_)) && !has_direct {
        return Err(Error::code("kernel.body_namespace_mismatch"));
    }
    if interval.canonical_bytes()? != pin.bytes {
        return Err(Error::code("codec.interval_pin_mismatch"));
    }
    Ok(VerifiedOrderedIntervalV1 {
        interval,
        trusted_base_identity: checkpoint.checkpoint_id,
        verified_profile_domain: profile.profile().profile_domain,
        pin: pin.clone(),
        body_bindings: bindings,
    })
}

pub fn promote_eligibility_receipt(
    unverified: Unverified<SyntheticEligibilityReceiptV1>,
    base: &TrustedExecutionBase,
    profile: &VerifiedGate2ProfileV1,
    interval: &VerifiedOrderedIntervalV1,
    pin: &SyntheticEligibilityReceiptPin,
) -> Result<VerifiedSyntheticEligibilityReceiptV1, Error> {
    let receipt = unverified.into_inner();
    if receipt.canonical_bytes()? != pin.bytes {
        return Err(Error::code("codec.eligibility_pin_mismatch"));
    }
    let checkpoint = base.checkpoint();
    let next_index = checkpoint
        .checkpoint_index
        .checked_add(1)
        .ok_or_else(|| Error::code("kernel.checkpoint_index_overflow"))?;
    let p = profile.profile();
    if receipt.chain_domain != p.manifest_body.chain_domain
        || receipt.protocol_manifest_hash != p.protocol_manifest_hash
        || receipt.profile_domain != p.profile_domain
        || receipt.base_checkpoint != checkpoint.checkpoint_id
        || receipt.base_issuance_cursor != checkpoint.native_state.logical_state.issuance_cursor
        || receipt.next_checkpoint_index != next_index
        || receipt.entries.len() != interval.interval.bodies.len()
        || receipt
            .entries
            .iter()
            .zip(interval.interval.bodies.iter().zip(&interval.body_bindings))
            .any(|(entry, (body, binding))| {
                entry.body_id != body.body_id
                    || entry.body_binding != *binding
                    || entry.reward_suite_id != p.manifest_body.reward_suite_id
            })
    {
        return Err(Error::code("kernel.eligibility_receipt_mismatch"));
    }
    let next_cursor = receipt
        .base_issuance_cursor
        .checked_add(receipt.entries.len() as u128)
        .ok_or_else(|| Error::code("kernel.issuance_history_limit"))?;
    if next_cursor > MAX_ISSUANCE_EVENTS as u128
        || checkpoint
            .native_state
            .logical_state
            .issuance_event_history
            .len()
            .saturating_add(receipt.entries.len())
            > MAX_ISSUANCE_EVENTS
    {
        return Err(Error::code("kernel.issuance_history_limit"));
    }
    Ok(VerifiedSyntheticEligibilityReceiptV1 {
        receipt,
        pin: pin.clone(),
    })
}

pub(crate) fn fresh_trusted_checkpoint(
    checkpoint: CheckpointStateWireV2,
    profile: &VerifiedGate2ProfileV1,
    lineage: Option<FenceLineageCapability>,
) -> Result<TrustedCheckpointV2, Error> {
    validate_checkpoint_state(&checkpoint, profile, lineage.as_ref())?;
    let pin = CheckpointPin {
        bytes: checkpoint.canonical_bytes()?,
    };
    Ok(TrustedCheckpointV2 {
        checkpoint,
        pin,
        lineage,
    })
}

pub(crate) fn lineage_from_successor(value: &SuccessorExecutionBaseV1) -> FenceLineageCapability {
    FenceLineageCapability {
        fence_id: value.fence_id,
        legacy_exit_descriptors: value.successor_legacy_exit_descriptors.clone(),
    }
}
