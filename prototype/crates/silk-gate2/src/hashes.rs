//! Frozen framed hash equations.

#![allow(missing_docs)]

use crate::canonical::domain_hash;
use crate::{
    BodyNamespaceV1, BoundedVec, CanonicalEncode, CheckpointStateWireV2, ConsensusEnvelopeV1,
    Error, Gate2ProfileV1, Hash32, InputPairV1, LegacyExitDescriptorV1, NativeNoteV2,
    NativeStateV2, OutputPairV1, ProfileHandoffBodyV1, RecoveryRecordV2, SortedUniqueVec,
    SyntheticEligibilityReceiptV1, SyntheticMigrationEnvelopeV1, TransferEffectProjectionV2,
    TransferEnvelopeV2, TransferKind, TransitionAnchorBodyV1,
};

const ZERO32: Hash32 = [0; 32];

fn bytes<T: CanonicalEncode>(value: &T) -> Result<Vec<u8>, Error> {
    value.canonical_bytes()
}

pub fn protocol_manifest_hash(profile: &Gate2ProfileV1) -> Result<Hash32, Error> {
    let body = bytes(&profile.manifest_body)?;
    domain_hash(b"Silk-Gate2-Synthetic-Manifest-v1", &[&body])
}

pub fn profile_domain(profile: &Gate2ProfileV1) -> Result<Hash32, Error> {
    let major = profile.manifest_body.protocol_major.to_le_bytes();
    domain_hash(
        b"SilkNode-Protocol-Profile",
        &[
            profile.manifest_body.chain_domain.as_slice(),
            major.as_slice(),
            profile.protocol_manifest_hash.as_slice(),
        ],
    )
}

pub fn reward_schedule_hash(profile: &Gate2ProfileV1) -> Result<Hash32, Error> {
    let schedule = bytes(&profile.manifest_body.synthetic_reward_schedule)?;
    domain_hash(
        b"Silk-Gate2-Synthetic-Reward-Schedule-v1",
        &[
            profile.manifest_body.chain_domain.as_slice(),
            schedule.as_slice(),
        ],
    )
}

pub fn policy_leaf(profile: &Gate2ProfileV1, kind: TransferKind) -> Result<Hash32, Error> {
    let mandate_version = profile.manifest_body.mandate_version.to_le_bytes();
    let kind = [kind as u8];
    let phase = [profile.manifest_body.policy_lifecycle_phase as u8];
    domain_hash(
        b"Silk-Policy-Phase",
        &[
            profile.manifest_body.chain_domain.as_slice(),
            profile.protocol_manifest_hash.as_slice(),
            profile.manifest_body.mandate_policy_module_id.as_slice(),
            mandate_version.as_slice(),
            kind.as_slice(),
            phase.as_slice(),
        ],
    )
}

pub fn enabled_transfer_kinds(profile: &Gate2ProfileV1) -> &'static [TransferKind] {
    use crate::PolicyLifecyclePhase::{CreateAndUse, PrincipalExitOnly, UseOnly};
    const CREATE: [TransferKind; 6] = [
        TransferKind::Ordinary,
        TransferKind::MandateCreate,
        TransferKind::MandateAction,
        TransferKind::MandateExhaust,
        TransferKind::MandateRevoke,
        TransferKind::MandateExpireReclaim,
    ];
    const USE: [TransferKind; 5] = [
        TransferKind::Ordinary,
        TransferKind::MandateAction,
        TransferKind::MandateExhaust,
        TransferKind::MandateRevoke,
        TransferKind::MandateExpireReclaim,
    ];
    const EXIT: [TransferKind; 3] = [
        TransferKind::Ordinary,
        TransferKind::MandateRevoke,
        TransferKind::MandateExpireReclaim,
    ];
    match profile.manifest_body.policy_lifecycle_phase {
        CreateAndUse => &CREATE,
        UseOnly => &USE,
        PrincipalExitOnly => &EXIT,
    }
}

pub fn policy_phase_root(profile: &Gate2ProfileV1) -> Result<Hash32, Error> {
    let mut leaves = enabled_transfer_kinds(profile)
        .iter()
        .map(|kind| policy_leaf(profile, *kind))
        .collect::<Result<Vec<_>, _>>()?;
    leaves.sort_unstable();
    leaves.dedup();
    if leaves.is_empty() {
        return Err(Error::code("profile.invalid_derived_field"));
    }
    while leaves.len() > 1 {
        let mut parents = Vec::with_capacity(leaves.len().div_ceil(2));
        for pair in leaves.chunks(2) {
            let left = pair[0];
            let right = *pair.get(1).unwrap_or(&left);
            parents.push(domain_hash(
                b"Silk-Policy-Phase-Node-v1",
                &[
                    profile.manifest_body.chain_domain.as_slice(),
                    left.as_slice(),
                    right.as_slice(),
                ],
            )?);
        }
        leaves = parents;
    }
    Ok(leaves[0])
}

pub fn scope_root(chain: &Hash32, scope: &crate::TransparentScopeV1) -> Result<Hash32, Error> {
    let members = bytes(&scope.members)?;
    domain_hash(
        b"Silk-Transparent-Scope-v1",
        &[
            chain.as_slice(),
            [scope.scope_kind as u8].as_slice(),
            members.as_slice(),
        ],
    )
}

pub fn note_commitment(chain: &Hash32, note: &NativeNoteV2) -> Result<Hash32, Error> {
    let note = bytes(note)?;
    domain_hash(
        b"Silk-Transparent-Note-v2",
        &[chain.as_slice(), note.as_slice()],
    )
}

pub fn note_nullifier(chain: &Hash32, note: &NativeNoteV2, cm: &Hash32) -> Result<Hash32, Error> {
    domain_hash(
        b"Silk-Transparent-Nullifier-v2",
        &[
            chain.as_slice(),
            note.suite_id.as_slice(),
            note.nullifier_key.as_slice(),
            note.rho.as_slice(),
            cm.as_slice(),
        ],
    )
}

pub fn recovery_hash(chain: &Hash32, record: &RecoveryRecordV2) -> Result<Hash32, Error> {
    let record = bytes(record)?;
    domain_hash(
        b"Silk-Transparent-Recovery-Record-v2",
        &[chain.as_slice(), record.as_slice()],
    )
}

pub fn transfer_projection(envelope: &TransferEnvelopeV2) -> TransferEffectProjectionV2 {
    TransferEffectProjectionV2 {
        chain_domain: envelope.chain_domain,
        protocol_manifest_hash: envelope.protocol_manifest_hash,
        profile_domain: envelope.profile_domain,
        policy_phase_root: envelope.policy_phase_root,
        suite_id: envelope.suite_id,
        anchor_epoch: envelope.anchor_epoch,
        expires_checkpoint: envelope.expires_checkpoint,
        public_fee: envelope.public_fee,
        transition_kind: envelope.transition_kind,
        action_evidence: envelope.action_evidence.clone(),
        input_pairs: envelope
            .inputs
            .iter()
            .map(|input| InputPairV1 {
                commitment: input.commitment,
                nullifier: input.nullifier,
            })
            .collect::<Vec<_>>()
            .into(),
        output_pairs: envelope
            .outputs
            .iter()
            .map(|output| OutputPairV1 {
                output_role: output.output_role,
                commitment: output.commitment,
            })
            .collect::<Vec<_>>()
            .into(),
        recovery_hashes: envelope.recovery_hashes.clone(),
    }
}

pub fn transfer_effect_digest(envelope: &TransferEnvelopeV2) -> Result<Hash32, Error> {
    let projection = bytes(&transfer_projection(envelope))?;
    domain_hash(b"Silk-Transparent-Effect-v2", &[&projection])
}

pub fn transfer_intent_id(envelope: &TransferEnvelopeV2) -> Result<Hash32, Error> {
    let effect = transfer_effect_digest(envelope)?;
    domain_hash(b"Silk-Transparent-Intent-v2", &[&effect])
}

pub fn transfer_instance_hash(envelope: &TransferEnvelopeV2) -> Result<Hash32, Error> {
    let intent = transfer_intent_id(envelope)?;
    let canonical = bytes(envelope)?;
    domain_hash(
        b"Silk-Transparent-Instance-v2",
        &[
            intent.as_slice(),
            envelope.anchor.as_slice(),
            canonical.as_slice(),
        ],
    )
}

pub fn migration_statement_digest(
    envelope: &SyntheticMigrationEnvelopeV1,
) -> Result<Hash32, Error> {
    let input_pairs: BoundedVec<InputPairV1, { crate::MAX_INPUTS }> = envelope
        .inputs
        .iter()
        .map(|input| InputPairV1 {
            commitment: input.commitment,
            nullifier: input.nullifier,
        })
        .collect::<Vec<_>>()
        .into();
    let output_pairs: BoundedVec<OutputPairV1, { crate::MAX_OUTPUTS }> = envelope
        .outputs
        .iter()
        .map(|output| OutputPairV1 {
            output_role: output.output_role,
            commitment: output.commitment,
        })
        .collect::<Vec<_>>()
        .into();
    let inputs = bytes(&input_pairs)?;
    let outputs = bytes(&output_pairs)?;
    let recoveries = bytes(&envelope.recovery_hashes)?;
    let expires = envelope.expires_checkpoint.to_le_bytes();
    let fee = envelope.public_fee.to_le_bytes();
    domain_hash(
        b"Silk-Transparent-Migration-Statement-v1",
        &[
            envelope.chain_domain.as_slice(),
            envelope.protocol_manifest_hash.as_slice(),
            envelope.profile_domain.as_slice(),
            envelope.policy_phase_root.as_slice(),
            envelope.migration_relation_hash.as_slice(),
            envelope.old_suite_id.as_slice(),
            envelope.new_suite_id.as_slice(),
            envelope.old_anchor_checkpoint.as_slice(),
            envelope.old_anchor_root.as_slice(),
            expires.as_slice(),
            inputs.as_slice(),
            outputs.as_slice(),
            recoveries.as_slice(),
            fee.as_slice(),
            envelope.value_binding_nonce.as_slice(),
        ],
    )
}

pub fn migration_intent_id(envelope: &SyntheticMigrationEnvelopeV1) -> Result<Hash32, Error> {
    let statement = migration_statement_digest(envelope)?;
    domain_hash(b"Silk-Transparent-Migration-Intent-v1", &[&statement])
}

pub fn migration_instance_hash(envelope: &SyntheticMigrationEnvelopeV1) -> Result<Hash32, Error> {
    let intent = migration_intent_id(envelope)?;
    let canonical = bytes(envelope)?;
    domain_hash(
        b"Silk-Transparent-Migration-Instance-v1",
        &[
            intent.as_slice(),
            envelope.execution_anchor.as_slice(),
            canonical.as_slice(),
        ],
    )
}

pub fn envelope_identity(envelope: &ConsensusEnvelopeV1) -> Result<(Hash32, Hash32), Error> {
    match envelope {
        ConsensusEnvelopeV1::Transfer(value) => {
            Ok((transfer_intent_id(value)?, transfer_instance_hash(value)?))
        }
        ConsensusEnvelopeV1::Migration(value) => {
            Ok((migration_intent_id(value)?, migration_instance_hash(value)?))
        }
    }
}

pub fn body_binding(
    chain: &Hash32,
    profile: &Hash32,
    namespace: &BodyNamespaceV1,
    envelopes: &BoundedVec<ConsensusEnvelopeV1, { crate::MAX_ENVELOPES }>,
) -> Result<Hash32, Error> {
    let namespace = bytes(namespace)?;
    let envelopes = bytes(envelopes)?;
    domain_hash(
        b"Silk-Transparent-Ordered-Body-v2",
        &[
            chain.as_slice(),
            profile.as_slice(),
            [2].as_slice(),
            namespace.as_slice(),
            envelopes.as_slice(),
        ],
    )
}

fn hash_list<T: CanonicalEncode>(
    domain: &[u8],
    chain: &Hash32,
    value: &T,
) -> Result<Hash32, Error> {
    let canonical = bytes(value)?;
    domain_hash(domain, &[chain.as_slice(), canonical.as_slice()])
}

pub fn note_history_root(state: &NativeStateV2) -> Result<Hash32, Error> {
    hash_list(
        b"Silk-Transparent-Note-History-Root-v2",
        &state.logical_state.chain_domain,
        &state.logical_state.commitment_history,
    )
}
pub fn nullifier_root(state: &NativeStateV2) -> Result<Hash32, Error> {
    hash_list(
        b"Silk-Transparent-Nullifier-Root-v2",
        &state.logical_state.chain_domain,
        &state.logical_state.nullifiers,
    )
}
pub fn cumulative_recovery_root(state: &NativeStateV2) -> Result<Hash32, Error> {
    hash_list(
        b"Silk-Transparent-Recovery-Root-v2",
        &state.logical_state.chain_domain,
        &state.logical_state.recovery_history,
    )
}
pub fn accepted_effect_root(state: &NativeStateV2) -> Result<Hash32, Error> {
    hash_list(
        b"Silk-Transparent-Accepted-Effect-Root-v2",
        &state.logical_state.chain_domain,
        &state.logical_state.accepted_effect_history,
    )
}
pub fn legacy_anchor_set_hash(state: &NativeStateV2) -> Result<Hash32, Error> {
    hash_list(
        b"Silk-Transparent-Legacy-Anchor-Set-v1",
        &state.logical_state.chain_domain,
        &state.legacy_exit_descriptors,
    )
}
pub fn logical_native_state_digest(state: &NativeStateV2) -> Result<Hash32, Error> {
    let canonical = bytes(&state.logical_state)?;
    domain_hash(b"Silk-Transparent-Logical-Native-State-v2", &[&canonical])
}

pub fn checkpoint_state_digest(checkpoint: &CheckpointStateWireV2) -> Result<Hash32, Error> {
    let state = &checkpoint.native_state;
    let logical = logical_native_state_digest(state)?;
    let active = bytes(&state.active_suite_ids)?;
    let retained = bytes(&state.retained_migration_source_suite_ids)?;
    let descriptors = bytes(&state.legacy_exit_descriptors)?;
    let legacy = legacy_anchor_set_hash(state)?;
    let body_history = bytes(&checkpoint.ordered_body_history)?;
    let bodies = bytes(&checkpoint.bodies_in_checkpoint)?;
    let bindings = bytes(&checkpoint.body_bindings_in_checkpoint)?;
    let effects = bytes(&checkpoint.accepted_effects_in_checkpoint)?;
    let rewards = bytes(&checkpoint.reward_events_in_checkpoint)?;
    let fence = bytes(&checkpoint.active_fence_id)?;
    domain_hash(
        b"Silk-Transparent-State-v2",
        &[
            [2].as_slice(),
            checkpoint.previous_checkpoint.as_slice(),
            checkpoint.checkpoint_index.to_le_bytes().as_slice(),
            logical.as_slice(),
            state.protocol_manifest_hash.as_slice(),
            state.profile_domain.as_slice(),
            state.policy_phase_root.as_slice(),
            active.as_slice(),
            retained.as_slice(),
            state.reward_suite_id.as_slice(),
            state.mandate_suite_id.as_slice(),
            state.reward_schedule_hash.as_slice(),
            descriptors.as_slice(),
            legacy.as_slice(),
            body_history.as_slice(),
            bodies.as_slice(),
            bindings.as_slice(),
            effects.as_slice(),
            rewards.as_slice(),
            fence.as_slice(),
        ],
    )
}

pub fn checkpoint_id(checkpoint: &CheckpointStateWireV2) -> Result<Hash32, Error> {
    let digest = checkpoint_state_digest(checkpoint)?;
    domain_hash(
        b"Silk-Transparent-Checkpoint-v2",
        &[
            checkpoint
                .native_state
                .logical_state
                .chain_domain
                .as_slice(),
            checkpoint.native_state.protocol_manifest_hash.as_slice(),
            checkpoint.native_state.profile_domain.as_slice(),
            checkpoint.checkpoint_index.to_le_bytes().as_slice(),
            checkpoint.previous_checkpoint.as_slice(),
            digest.as_slice(),
        ],
    )
}

pub fn profile_handoff_hash(handoff: &ProfileHandoffBodyV1) -> Result<Hash32, Error> {
    let canonical = bytes(handoff)?;
    domain_hash(
        b"Silk-Transparent-Profile-Handoff-v1",
        &[canonical.as_slice()],
    )
}

pub fn transition_anchor_id(anchor: &TransitionAnchorBodyV1) -> Result<Hash32, Error> {
    let canonical = bytes(anchor)?;
    domain_hash(
        b"Silk-Transparent-Transition-Anchor-v1",
        &[anchor.chain_domain.as_slice(), canonical.as_slice()],
    )
}

pub fn fence_id(
    predecessor: &Hash32,
    successor_manifest: &Hash32,
    transition_semantics: &Hash32,
    handoff_hash: &Hash32,
    anchor_id: &Hash32,
    chain: &Hash32,
) -> Result<Hash32, Error> {
    domain_hash(
        b"Silk-Transparent-Profile-Fence-v1",
        &[
            chain.as_slice(),
            predecessor.as_slice(),
            successor_manifest.as_slice(),
            transition_semantics.as_slice(),
            handoff_hash.as_slice(),
            anchor_id.as_slice(),
        ],
    )
}

pub fn eligibility_receipt_pin_digest(
    receipt: &SyntheticEligibilityReceiptV1,
) -> Result<Hash32, Error> {
    let canonical = bytes(receipt)?;
    domain_hash(
        b"Silk-Gate2-Eligibility-Receipt-Pin-v1",
        &[canonical.as_slice()],
    )
}

#[allow(clippy::too_many_arguments)]
pub fn reward_seed(
    chain: &Hash32,
    previous_checkpoint: &Hash32,
    next_checkpoint_index: u64,
    body_position: u32,
    body_id: &Hash32,
    body_binding: &Hash32,
    profile: &Hash32,
    reward_suite: &Hash32,
    position: u128,
    receiver: &Hash32,
    nonce: &Hash32,
    subsidy: u64,
    accepted_fees: u64,
) -> Result<Hash32, Error> {
    domain_hash(
        b"Silk-Transparent-Reward-Seed-v1",
        &[
            chain.as_slice(),
            previous_checkpoint.as_slice(),
            next_checkpoint_index.to_le_bytes().as_slice(),
            body_position.to_le_bytes().as_slice(),
            body_id.as_slice(),
            body_binding.as_slice(),
            profile.as_slice(),
            reward_suite.as_slice(),
            position.to_le_bytes().as_slice(),
            receiver.as_slice(),
            nonce.as_slice(),
            subsidy.to_le_bytes().as_slice(),
            accepted_fees.to_le_bytes().as_slice(),
        ],
    )
}

pub fn reward_component(domain: &[u8], seed: &Hash32) -> Result<Hash32, Error> {
    domain_hash(domain, &[seed.as_slice()])
}

pub fn reward_recovery_payload(seed: &Hash32) -> Result<[u8; 128], Error> {
    let mut payload = [0_u8; 128];
    for index in 0_u32..4 {
        let block = domain_hash(
            b"Silk-Transparent-Reward-Recovery-Block-v1",
            &[seed.as_slice(), index.to_le_bytes().as_slice()],
        )?;
        let start = index as usize * 32;
        payload[start..start + 32].copy_from_slice(&block);
    }
    Ok(payload)
}

pub fn is_zero(value: &Hash32) -> bool {
    *value == ZERO32
}

pub(crate) fn canonical_sorted_descriptors(
    values: Vec<LegacyExitDescriptorV1>,
) -> Result<SortedUniqueVec<LegacyExitDescriptorV1, { crate::MAX_LEGACY_EXITS }>, Error> {
    let mut values = values;
    values.sort_by_key(|value| value.canonical_bytes().unwrap_or_default());
    let result = SortedUniqueVec::new(values);
    result.canonical_bytes()?;
    Ok(result)
}
