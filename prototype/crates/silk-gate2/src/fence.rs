//! Synthetic successor profile fence.

#![allow(missing_docs)]

use crate::{
    CanonicalEncode, Error, FenceTransitionV1, Gate2ProfileV1, LegacyExitDescriptorV1,
    LegacyTransitionKind, NoteType, ProfileHandoffBodyV1, ProfileKind, SuccessorExecutionBaseV1,
    TransitionAnchorBodyV1, TrustedCheckpointV2, Unverified, VerifiedGate2ProfileV1,
    accepted_effect_root, canonical_sorted_descriptors, cumulative_recovery_root, fence_id,
    legacy_anchor_set_hash, note_history_root, nullifier_root, profile_handoff_hash,
    transition_anchor_id, validate_checkpoint_state,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedFenceTransitionV1 {
    transition: FenceTransitionV1,
    capability: SuccessorExecutionBaseV1,
}
impl TrustedFenceTransitionV1 {
    pub const fn transition(&self) -> &FenceTransitionV1 {
        &self.transition
    }
    pub const fn capability(&self) -> &SuccessorExecutionBaseV1 {
        &self.capability
    }
    pub fn into_capability(self) -> SuccessorExecutionBaseV1 {
        self.capability
    }
    pub fn rollback(self) -> TrustedCheckpointV2 {
        self.capability.predecessor_checkpoint
    }
}

fn same_reward_schedule(a: &Gate2ProfileV1, b: &Gate2ProfileV1) -> Result<bool, Error> {
    Ok(a.manifest_body
        .synthetic_reward_schedule
        .canonical_bytes()?
        == b.manifest_body
            .synthetic_reward_schedule
            .canonical_bytes()?)
}

fn validate_fence_candidate_fields(
    checkpoint: &crate::CheckpointStateWireV2,
    predecessor: &Gate2ProfileV1,
    successor: &Gate2ProfileV1,
    externally_pinned_successor: &Gate2ProfileV1,
) -> Result<crate::Hash32, Error> {
    let a = &predecessor.manifest_body;
    let b = &successor.manifest_body;
    if b.profile_kind != ProfileKind::Successor
        || b.activation_checkpoint != checkpoint.checkpoint_index
    {
        return Err(Error::code("fence.wrong_activation_checkpoint"));
    }
    if b.predecessor_manifest_hash != predecessor.protocol_manifest_hash
        || b.predecessor_profile_domain != predecessor.profile_domain
    {
        return Err(Error::code("fence.predecessor_mismatch"));
    }
    if b.chain_domain != a.chain_domain
        || b.synthetic_constitution_hash != a.synthetic_constitution_hash
    {
        return Err(Error::code("fence.incompatible_constitution"));
    }
    if b.transition_semantics_id != a.transition_semantics_id {
        return Err(Error::code("fence.incompatible_constitution"));
    }
    if !same_reward_schedule(predecessor, successor)?
        || b.max_accepted_fees_per_body != a.max_accepted_fees_per_body
        || b.reward_suite_id != a.reward_suite_id
        || b.issuance_module_id != a.issuance_module_id
        || b.issuance_abi != a.issuance_abi
    {
        return Err(Error::code("fence.issuance_schedule_changed"));
    }
    if b.mandate_suite_id != a.mandate_suite_id
        || b.mandate_policy_module_id != a.mandate_policy_module_id
        || b.mandate_version != a.mandate_version
    {
        return Err(Error::code("fence.mandate_policy_migration_unimplemented"));
    }
    if b.state_commitment_migration_hash != [0; 32] {
        return Err(Error::code("fence.accumulator_migration_unimplemented"));
    }
    if b.native_kernel_module_id
        != externally_pinned_successor
            .manifest_body
            .native_kernel_module_id
        || b.checkpoint_module_id
            != externally_pinned_successor
                .manifest_body
                .checkpoint_module_id
    {
        return Err(Error::code("fence.incompatible_constitution"));
    }
    let removed = a
        .active_suite_ids
        .iter()
        .filter(|suite| !b.active_suite_ids.contains(suite))
        .copied()
        .collect::<Vec<_>>();
    let added = b
        .active_suite_ids
        .iter()
        .filter(|suite| !a.active_suite_ids.contains(suite))
        .copied()
        .collect::<Vec<_>>();
    if removed.len() != 1
        || added.len() != 1
        || b.retained_migration_source_suite_ids.as_slice() != removed
        || a.active_suite_ids
            .iter()
            .filter(|suite| b.active_suite_ids.contains(suite))
            .count()
            + 1
            != a.active_suite_ids.len()
    {
        return Err(Error::code("fence.unsupported_suite_delta"));
    }
    let removed_suite = removed[0];
    if checkpoint
        .native_state
        .logical_state
        .live_notes
        .iter()
        .any(|(_, note)| note.suite_id == removed_suite && note.note_type != NoteType::Value)
    {
        return Err(Error::code("fence.unimplemented_exit_required"));
    }
    Ok(removed_suite)
}

#[cfg(feature = "private-test-harness")]
pub fn validate_synthetic_fence_candidate(
    checkpoint: &crate::CheckpointStateWireV2,
    predecessor: &Gate2ProfileV1,
    successor: &Gate2ProfileV1,
    externally_pinned_successor: &VerifiedGate2ProfileV1,
) -> Result<(), Error> {
    validate_fence_candidate_fields(
        checkpoint,
        predecessor,
        successor,
        externally_pinned_successor.profile(),
    )
    .map(|_| ())
}

pub fn construct_fence(
    predecessor_checkpoint: &TrustedCheckpointV2,
    predecessor_profile: &VerifiedGate2ProfileV1,
    successor_profile: &VerifiedGate2ProfileV1,
) -> Result<TrustedFenceTransitionV1, Error> {
    validate_checkpoint_state(
        predecessor_checkpoint.checkpoint(),
        predecessor_profile,
        predecessor_checkpoint.lineage(),
    )?;
    let checkpoint = predecessor_checkpoint.checkpoint();
    let predecessor = predecessor_profile.profile();
    let successor = successor_profile.profile();
    let a = &predecessor.manifest_body;
    let b = &successor.manifest_body;
    let removed_suite = validate_fence_candidate_fields(
        checkpoint,
        predecessor,
        successor,
        successor_profile.profile(),
    )?;

    let predecessor_note_root = note_history_root(&checkpoint.native_state)?;
    let predecessor_nullifier_root = nullifier_root(&checkpoint.native_state)?;
    let predecessor_recovery_root = cumulative_recovery_root(&checkpoint.native_state)?;
    let predecessor_effect_root = accepted_effect_root(&checkpoint.native_state)?;
    let predecessor_legacy = legacy_anchor_set_hash(&checkpoint.native_state)?;
    let handoff = ProfileHandoffBodyV1 {
        chain_domain: a.chain_domain,
        predecessor_manifest_hash: predecessor.protocol_manifest_hash,
        predecessor_profile_domain: predecessor.profile_domain,
        predecessor_checkpoint: checkpoint.checkpoint_id,
        checkpoint_index: checkpoint.checkpoint_index,
        note_history_root: predecessor_note_root,
        nullifier_root: predecessor_nullifier_root,
        cumulative_recovery_root: predecessor_recovery_root,
        accepted_effect_root: predecessor_effect_root,
        native_genesis_issued: checkpoint.native_state.logical_state.native_genesis_issued,
        native_issued: checkpoint.native_state.logical_state.native_issued,
        native_burned: checkpoint.native_state.logical_state.native_burned,
        issuance_cursor: checkpoint.native_state.logical_state.issuance_cursor,
        security_epoch: checkpoint.native_state.logical_state.security_epoch,
        legacy_anchor_set_hash: predecessor_legacy,
        synthetic_order_carry_hash: checkpoint
            .native_state
            .logical_state
            .synthetic_order_carry_hash,
        synthetic_daa_carry_hash: checkpoint
            .native_state
            .logical_state
            .synthetic_daa_carry_hash,
        synthetic_pow_key_carry_hash: checkpoint
            .native_state
            .logical_state
            .synthetic_pow_key_carry_hash,
    };
    let handoff_hash = profile_handoff_hash(&handoff)?;
    let descriptor = LegacyExitDescriptorV1 {
        source_suite_id: removed_suite,
        frozen_source_checkpoint: checkpoint.checkpoint_id,
        frozen_source_note_root: predecessor_note_root,
        migration_relation_hash: b.migration_relation_hash,
        allowed_transition: LegacyTransitionKind::ValueSuiteMigration,
    };
    let descriptors = canonical_sorted_descriptors(vec![descriptor])?;
    let mut successor_state = checkpoint.native_state.clone();
    successor_state.protocol_manifest_hash = successor.protocol_manifest_hash;
    successor_state.profile_domain = successor.profile_domain;
    successor_state.policy_phase_root = successor.policy_phase_root;
    successor_state.active_suite_ids = b.active_suite_ids.clone();
    successor_state.retained_migration_source_suite_ids =
        b.retained_migration_source_suite_ids.clone();
    successor_state.reward_suite_id = b.reward_suite_id;
    successor_state.mandate_suite_id = b.mandate_suite_id;
    successor_state.reward_schedule_hash = successor.reward_schedule_hash;
    successor_state.legacy_exit_descriptors = descriptors.clone();
    let successor_legacy = legacy_anchor_set_hash(&successor_state)?;
    let anchor = TransitionAnchorBodyV1 {
        chain_domain: a.chain_domain,
        predecessor_checkpoint: checkpoint.checkpoint_id,
        checkpoint_index: checkpoint.checkpoint_index,
        successor_manifest_hash: successor.protocol_manifest_hash,
        transition_semantics_id: b.transition_semantics_id,
        profile_handoff_hash: handoff_hash,
        state_commitment_migration_hash: b.state_commitment_migration_hash,
        successor_note_history_root: predecessor_note_root,
        successor_nullifier_root: predecessor_nullifier_root,
        successor_cumulative_recovery_root: predecessor_recovery_root,
        successor_accepted_effect_root: predecessor_effect_root,
        native_issued: checkpoint.native_state.logical_state.native_issued,
        native_burned: checkpoint.native_state.logical_state.native_burned,
        issuance_cursor: checkpoint.native_state.logical_state.issuance_cursor,
        security_epoch: checkpoint.native_state.logical_state.security_epoch,
        legacy_anchor_set_hash: successor_legacy,
    };
    let anchor_id = transition_anchor_id(&anchor)?;
    let fence_id_value = fence_id(
        &checkpoint.checkpoint_id,
        &successor.protocol_manifest_hash,
        &b.transition_semantics_id,
        &handoff_hash,
        &anchor_id,
        &a.chain_domain,
    )?;
    let transition = FenceTransitionV1 {
        predecessor: checkpoint.clone(),
        successor_profile: successor.clone(),
        handoff: handoff.clone(),
        transition_anchor: anchor.clone(),
        transition_anchor_id: anchor_id,
        fence_id: fence_id_value,
    };
    let capability = SuccessorExecutionBaseV1 {
        predecessor_checkpoint: predecessor_checkpoint.clone(),
        predecessor_profile: predecessor_profile.clone(),
        successor_profile: successor_profile.clone(),
        handoff,
        transition_anchor: anchor,
        transition_anchor_id: anchor_id,
        fence_id: fence_id_value,
        successor_legacy_exit_descriptors: descriptors,
    };
    Ok(TrustedFenceTransitionV1 {
        transition,
        capability,
    })
}

pub fn verify_fence_transition(
    unverified: Unverified<FenceTransitionV1>,
    predecessor_checkpoint: &TrustedCheckpointV2,
    predecessor_profile: &VerifiedGate2ProfileV1,
    successor_profile: &VerifiedGate2ProfileV1,
) -> Result<TrustedFenceTransitionV1, Error> {
    let recomputed = construct_fence(
        predecessor_checkpoint,
        predecessor_profile,
        successor_profile,
    )?;
    if unverified.decoded() != recomputed.transition() {
        return Err(Error::code("codec.fence_transition_mismatch"));
    }
    Ok(recomputed)
}
