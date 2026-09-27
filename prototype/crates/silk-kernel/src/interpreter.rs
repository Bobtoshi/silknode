//! Canonical greedy application and immutable checkpoint sealing.

use std::collections::BTreeSet;

use silk_profile::ExecutionProfile;
use silk_types::{Hash32, IntentId, NoteCommitment, Nullifier, VertexId};

use crate::state::{BaseNativeStateView, NativeEffect, NativeEffectBuilder};
use crate::{
    AcceptedEffect, CheckpointState, KernelError, MAX_INPUTS, MAX_ORDERED_BODIES, MAX_OUTPUTS,
    MAX_TRANSACTIONS, NativeNote, NativeTransaction, OrderedBody, RecoveryRecord, RejectCode,
};

/// Final disposition of one candidate transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// The complete effect was applied atomically.
    Accepted,
    /// No part of the effect was applied.
    Rejected(RejectCode),
}

/// A deterministic decision in canonical intent/instance order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Decision {
    /// Zero-based position in the complete checkpoint execution trace.
    pub position: u32,
    /// Source body selected by the ordering layer.
    pub body_id: VertexId,
    /// Zero-based authoritative body position in this checkpoint.
    pub body_position: u32,
    /// Zero-based canonical intent/instance position within the source body.
    pub transaction_position: u32,
    /// Anchor-independent effect identifier.
    pub intent_id: IntentId,
    /// Full anchor-and-witness tie-break digest.
    pub instance_hash: Hash32,
    /// Atomic acceptance or stable rejection code.
    pub outcome: Outcome,
}

/// An immutable base/next checkpoint pair plus its complete decision trace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transition {
    previous: CheckpointState,
    next: CheckpointState,
    decisions: Vec<Decision>,
}

impl Transition {
    /// Returns the unchanged base snapshot.
    #[must_use]
    pub const fn previous(&self) -> &CheckpointState {
        &self.previous
    }

    /// Returns the newly materialized snapshot.
    #[must_use]
    pub const fn next(&self) -> &CheckpointState {
        &self.next
    }

    /// Returns decisions in canonical application order.
    #[must_use]
    pub fn decisions(&self) -> &[Decision] {
        &self.decisions
    }

    /// Projects the native-kernel result committed by this sealed transition.
    ///
    /// The returned value excludes checkpoint-only history and identity fields.
    #[must_use]
    pub fn native_interval_result(&self) -> crate::NativeIntervalResult {
        crate::NativeIntervalResult::from_transition(self)
    }

    /// Consumes the transition and returns its next state.
    #[must_use]
    pub fn into_next(self) -> CheckpointState {
        self.next
    }

    /// Consumes the transition and restores the byte-identical base snapshot.
    #[must_use]
    pub fn rollback(self) -> CheckpointState {
        self.previous
    }
}

struct Candidate<'a> {
    transaction: &'a NativeTransaction,
    intent_id: IntentId,
    instance_hash: Hash32,
    canonical_bytes: Vec<u8>,
}

struct ValidatedInputs {
    commitments: Vec<NoteCommitment>,
    nullifiers: Vec<Nullifier>,
    value: u128,
}

struct ValidatedOutputs {
    outputs: Vec<(NoteCommitment, NativeNote)>,
    value: u128,
}

type Validation<T> = Result<Result<T, RejectCode>, KernelError>;

/// Applies already ordered bodies and seals one deterministic next checkpoint.
///
/// Outer body order is authoritative and is preserved exactly; the ordering
/// layer must supply only fully available, verified body identifiers. Within
/// each body, candidates must already be ordered by
/// `(intent_id, instance_hash, canonical_transaction_bytes)`; malformed order
/// invalidates the checkpoint call rather than being silently repaired. A
/// rejected effect reserves no nullifier, commitment, fee, or intent. Inputs
/// are looked up only in `base`, so outputs accepted in this call cannot be
/// spent until a later checkpoint. This function contains no graph or
/// fork-choice algorithm.
///
/// # Errors
///
/// Returns [`KernelError`] if the base state is not bound to the explicit
/// execution profile, the batch exceeds its bound, the base state is invalid,
/// an identifier cannot be derived, the checkpoint index overflows, or
/// post-validation materialization contradicts an invariant. Ordinary
/// transaction failures are returned as [`Decision`] values, not errors.
// Keep the crate boundary explicit even though the private parent module makes
// this visibility equivalent today; `runtime` is the only intended caller.
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn apply_and_seal(
    execution_profile: &ExecutionProfile,
    base: &CheckpointState,
    ordered_bodies: &[OrderedBody],
) -> Result<Transition, KernelError> {
    if execution_profile.chain_domain() != base.chain_domain() {
        return Err(KernelError::ExecutionChainMismatch {
            execution: execution_profile.chain_domain(),
            state: base.chain_domain(),
        });
    }
    if execution_profile.profile_domain() != base.profile_domain() {
        return Err(KernelError::ExecutionProfileMismatch {
            execution: execution_profile.profile_domain(),
            state: base.profile_domain(),
        });
    }
    if ordered_bodies.is_empty() {
        return Err(KernelError::EmptyCheckpoint);
    }
    if ordered_bodies.len() > MAX_ORDERED_BODIES {
        return Err(KernelError::TooManyOrderedBodies {
            actual: ordered_bodies.len(),
            max: MAX_ORDERED_BODIES,
        });
    }
    let transaction_count = ordered_bodies.iter().try_fold(0_usize, |count, body| {
        count.checked_add(body.transactions.len())
    });
    let transaction_count = transaction_count.ok_or(KernelError::TooManyTransactions {
        actual: usize::MAX,
        max: MAX_TRANSACTIONS,
    })?;
    if transaction_count > MAX_TRANSACTIONS {
        return Err(KernelError::TooManyTransactions {
            actual: transaction_count,
            max: MAX_TRANSACTIONS,
        });
    }
    base.validate()?;
    validate_body_ids(base, ordered_bodies)?;

    let base_view = BaseNativeStateView::new(base);
    let mut effects = NativeEffectBuilder::new();
    let mut decisions = Vec::with_capacity(transaction_count);
    let mut accepted_effects = Vec::new();
    let mut body_bindings = Vec::with_capacity(ordered_bodies.len());

    for (body_position, body) in ordered_bodies.iter().enumerate() {
        let candidates = candidates_for_body(body)?;
        body_bindings
            .push(body.execution_binding(base_view.chain_domain(), base_view.profile_domain())?);
        evaluate_candidates(
            &base_view,
            &mut effects,
            &mut decisions,
            &mut accepted_effects,
            body,
            body_position,
            candidates,
        )?;
    }

    let next = effects.seal_successor(
        base,
        ordered_bodies.iter().map(|body| body.body_id).collect(),
        body_bindings,
        accepted_effects,
    )?;

    Ok(Transition {
        previous: base.clone(),
        next,
        decisions,
    })
}

// Keep native evaluation callable only within the crate; `runtime` is the sole
// promotion boundary and decoded results never become staged effects.
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn evaluate_native_interval(
    execution_profile: &ExecutionProfile,
    base: &CheckpointState,
    ordered_bodies: &[OrderedBody],
) -> Result<crate::NativeIntervalResult, KernelError> {
    if execution_profile.chain_domain() != base.chain_domain() {
        return Err(KernelError::ExecutionChainMismatch {
            execution: execution_profile.chain_domain(),
            state: base.chain_domain(),
        });
    }
    if execution_profile.profile_domain() != base.profile_domain() {
        return Err(KernelError::ExecutionProfileMismatch {
            execution: execution_profile.profile_domain(),
            state: base.profile_domain(),
        });
    }
    if ordered_bodies.len() > MAX_ORDERED_BODIES {
        return Err(KernelError::TooManyOrderedBodies {
            actual: ordered_bodies.len(),
            max: MAX_ORDERED_BODIES,
        });
    }
    let transaction_count = ordered_bodies.iter().try_fold(0_usize, |count, body| {
        count.checked_add(body.transactions.len())
    });
    let transaction_count = transaction_count.ok_or(KernelError::TooManyTransactions {
        actual: usize::MAX,
        max: MAX_TRANSACTIONS,
    })?;
    if transaction_count > MAX_TRANSACTIONS {
        return Err(KernelError::TooManyTransactions {
            actual: transaction_count,
            max: MAX_TRANSACTIONS,
        });
    }
    base.validate_native_projection()?;

    let base_view = BaseNativeStateView::new(base);
    let mut effects = NativeEffectBuilder::new();
    let mut decisions = Vec::with_capacity(transaction_count);
    let mut accepted_effects = Vec::new();
    let candidates_by_body = ordered_bodies
        .iter()
        .map(candidates_for_body)
        .collect::<Result<Vec<_>, _>>()?;
    for (body_position, (body, candidates)) in
        ordered_bodies.iter().zip(candidates_by_body).enumerate()
    {
        evaluate_candidates(
            &base_view,
            &mut effects,
            &mut decisions,
            &mut accepted_effects,
            body,
            body_position,
            candidates,
        )?;
    }
    let resulting_native_state = effects.materialize_native_projection(base)?;
    Ok(crate::NativeIntervalResult::from_execution(
        decisions,
        accepted_effects,
        resulting_native_state,
    ))
}

fn evaluate_candidates(
    base_view: &BaseNativeStateView<'_>,
    effects: &mut NativeEffectBuilder,
    decisions: &mut Vec<Decision>,
    accepted_effects: &mut Vec<AcceptedEffect>,
    body: &OrderedBody,
    body_position: usize,
    candidates: Vec<Candidate<'_>>,
) -> Result<(), KernelError> {
    for (transaction_position, candidate) in candidates.into_iter().enumerate() {
        let outcome = if base_view.contains_intent(&candidate.intent_id)
            || effects.contains_intent(&candidate.intent_id)
        {
            Outcome::Rejected(RejectCode::DuplicateIntent)
        } else {
            let current_fee_pool =
                effects
                    .current_fee_pool(base_view)
                    .ok_or(KernelError::InternalInvariant(
                        "staged fee pool overflowed before transaction validation",
                    ))?;
            match validate_transaction(base_view, candidate.transaction, effects, current_fee_pool)?
            {
                Ok(effect) => {
                    effects.stage(candidate.intent_id, effect)?;
                    accepted_effects.push(AcceptedEffect {
                        body_id: body.body_id,
                        intent_id: candidate.intent_id,
                    });
                    Outcome::Accepted
                }
                Err(code) => Outcome::Rejected(code),
            }
        };
        decisions.push(Decision {
            position: checked_position(decisions.len(), "decision")?,
            body_id: body.body_id,
            body_position: checked_position(body_position, "body")?,
            transaction_position: checked_position(transaction_position, "transaction")?,
            intent_id: candidate.intent_id,
            instance_hash: candidate.instance_hash,
            outcome,
        });
    }
    Ok(())
}

fn candidates_for_body(body: &OrderedBody) -> Result<Vec<Candidate<'_>>, KernelError> {
    let mut candidates = Vec::with_capacity(body.transactions.len());
    for transaction in &body.transactions {
        candidates.push(Candidate {
            transaction,
            intent_id: transaction.intent_id()?,
            instance_hash: transaction.instance_hash()?,
            canonical_bytes: silk_types::CanonicalEncode::to_canonical_bytes(transaction)?,
        });
    }
    if candidates
        .windows(2)
        .any(|pair| !compare_candidates(&pair[0], &pair[1]).is_lt())
    {
        return Err(KernelError::NonCanonicalBodyTransactions);
    }
    Ok(candidates)
}

fn compare_candidates(left: &Candidate<'_>, right: &Candidate<'_>) -> std::cmp::Ordering {
    (
        left.intent_id,
        left.instance_hash,
        left.canonical_bytes.as_slice(),
    )
        .cmp(&(
            right.intent_id,
            right.instance_hash,
            right.canonical_bytes.as_slice(),
        ))
}

fn validate_body_ids(
    base: &CheckpointState,
    ordered_bodies: &[OrderedBody],
) -> Result<(), KernelError> {
    let mut seen = base
        .ordered_body_history()
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if ordered_bodies.iter().any(|body| !seen.insert(body.body_id)) {
        return Err(KernelError::DuplicateOrderedBody);
    }
    Ok(())
}

fn checked_position(position: usize, kind: &'static str) -> Result<u32, KernelError> {
    u32::try_from(position).map_err(|_| KernelError::InternalInvariant(kind))
}

fn validate_transaction(
    base: &BaseNativeStateView<'_>,
    transaction: &NativeTransaction,
    effects: &NativeEffectBuilder,
    current_fee_pool: u128,
) -> Validation<NativeEffect> {
    if let Some(code) = preliminary_rejection(base, transaction) {
        return Ok(Err(code));
    }
    if let Some(code) = conflict_rejection(base, transaction, effects) {
        return Ok(Err(code));
    }
    let inputs = match validate_inputs(base, transaction)? {
        Ok(inputs) => inputs,
        Err(code) => return Ok(Err(code)),
    };
    let outputs = match validate_outputs(base, transaction)? {
        Ok(outputs) => outputs,
        Err(code) => return Ok(Err(code)),
    };
    let Some(outputs_plus_fee) = outputs
        .value
        .checked_add(u128::from(transaction.public_fee))
    else {
        return Ok(Err(RejectCode::ValueOverflow));
    };
    if inputs.value != outputs_plus_fee {
        return Ok(Err(RejectCode::ConservationFailure));
    }
    let outputs = match validate_recovery(base, transaction, outputs)? {
        Ok(outputs) => outputs,
        Err(code) => return Ok(Err(code)),
    };
    if current_fee_pool
        .checked_add(u128::from(transaction.public_fee))
        .is_none()
    {
        return Ok(Err(RejectCode::FeePoolOverflow));
    }

    Ok(Ok(NativeEffect::new(
        inputs.commitments,
        inputs.nullifiers,
        outputs,
        transaction.public_fee,
    )))
}

fn preliminary_rejection(
    base: &BaseNativeStateView<'_>,
    transaction: &NativeTransaction,
) -> Option<RejectCode> {
    if transaction.inputs.is_empty() {
        return Some(RejectCode::EmptyInputs);
    }
    if transaction.inputs.len() > MAX_INPUTS {
        return Some(RejectCode::TooManyInputs);
    }
    if transaction.outputs.len() > MAX_OUTPUTS {
        return Some(RejectCode::TooManyOutputs);
    }
    if transaction.chain_domain != base.chain_domain() {
        return Some(RejectCode::WrongChain);
    }
    if transaction.profile_domain != base.profile_domain() {
        return Some(RejectCode::WrongProfile);
    }
    if transaction.anchor != base.checkpoint_id() {
        return Some(RejectCode::WrongCheckpoint);
    }
    if contains_duplicate(transaction.inputs.iter().map(|input| input.commitment)) {
        return Some(RejectCode::InternalDuplicateInput);
    }
    if contains_duplicate(transaction.inputs.iter().map(|input| input.nullifier)) {
        return Some(RejectCode::InternalDuplicateNullifier);
    }
    if contains_duplicate(transaction.outputs.iter().map(|output| output.commitment)) {
        return Some(RejectCode::InternalDuplicateOutput);
    }
    None
}

fn conflict_rejection(
    base: &BaseNativeStateView<'_>,
    transaction: &NativeTransaction,
    effects: &NativeEffectBuilder,
) -> Option<RejectCode> {
    if transaction
        .inputs
        .iter()
        .any(|input| base.contains_nullifier(&input.nullifier))
    {
        return Some(RejectCode::AlreadySpent);
    }
    if transaction
        .inputs
        .iter()
        .any(|input| effects.contains_nullifier(&input.nullifier))
    {
        return Some(RejectCode::ConflictLost);
    }
    if transaction
        .outputs
        .iter()
        .any(|output| base.contains_commitment(&output.commitment))
    {
        return Some(RejectCode::CommitmentAlreadyExists);
    }
    if transaction
        .outputs
        .iter()
        .any(|output| effects.contains_commitment(&output.commitment))
    {
        return Some(RejectCode::CommitmentConflict);
    }
    None
}

fn validate_inputs(
    base: &BaseNativeStateView<'_>,
    transaction: &NativeTransaction,
) -> Validation<ValidatedInputs> {
    let mut commitments = Vec::with_capacity(transaction.inputs.len());
    let mut nullifiers = Vec::with_capacity(transaction.inputs.len());
    let mut input_value = 0_u128;
    for input in &transaction.inputs {
        let derived_commitment = input.witness.note.commitment(base.chain_domain())?;
        if derived_commitment != input.commitment {
            return Ok(Err(RejectCode::WitnessCommitmentMismatch));
        }
        let derived_nullifier = input.witness.note.nullifier(base.chain_domain())?;
        if derived_nullifier != input.nullifier {
            return Ok(Err(RejectCode::NullifierMismatch));
        }
        let Some(checkpoint_note) = base.live_note(&input.commitment) else {
            return Ok(Err(RejectCode::InputNotCheckpointed));
        };
        if checkpoint_note != &input.witness.note {
            return Ok(Err(RejectCode::WitnessCommitmentMismatch));
        }
        if !input.witness.authorization_valid {
            return Ok(Err(RejectCode::InvalidTransparentWitness));
        }
        let Some(updated_input_value) =
            input_value.checked_add(u128::from(input.witness.note.value))
        else {
            return Ok(Err(RejectCode::ValueOverflow));
        };
        input_value = updated_input_value;
        commitments.push(input.commitment);
        nullifiers.push(input.nullifier);
    }

    Ok(Ok(ValidatedInputs {
        commitments,
        nullifiers,
        value: input_value,
    }))
}

fn validate_outputs(
    base: &BaseNativeStateView<'_>,
    transaction: &NativeTransaction,
) -> Validation<ValidatedOutputs> {
    let mut outputs = Vec::with_capacity(transaction.outputs.len());
    let mut output_value = 0_u128;
    for output in &transaction.outputs {
        let derived_commitment = output.note.commitment(base.chain_domain())?;
        if derived_commitment != output.commitment {
            return Ok(Err(RejectCode::OutputCommitmentMismatch));
        }
        let Some(updated_output_value) = output_value.checked_add(u128::from(output.note.value))
        else {
            return Ok(Err(RejectCode::ValueOverflow));
        };
        output_value = updated_output_value;
        outputs.push((output.commitment, output.note.clone()));
    }

    Ok(Ok(ValidatedOutputs {
        outputs,
        value: output_value,
    }))
}

fn validate_recovery(
    base: &BaseNativeStateView<'_>,
    transaction: &NativeTransaction,
    outputs: ValidatedOutputs,
) -> Validation<Vec<(NoteCommitment, NativeNote, RecoveryRecord)>> {
    if transaction.recovery_hashes.len() != transaction.outputs.len()
        || transaction.recovery_records.len() != transaction.outputs.len()
    {
        return Ok(Err(RejectCode::RecoveryVectorMismatch));
    }
    let mut records = Vec::with_capacity(outputs.outputs.len());
    for (slot, (commitment, note)) in outputs.outputs.into_iter().enumerate() {
        let record = &transaction.recovery_records[slot];
        if record.output_commitment != commitment {
            return Ok(Err(RejectCode::RecoveryCommitmentMismatch));
        }
        let record_hash = record.record_hash(base.chain_domain())?;
        if transaction.recovery_hashes[slot] != record_hash {
            return Ok(Err(RejectCode::RecoveryHashMismatch));
        }
        records.push((commitment, note, record.clone()));
    }
    Ok(Ok(records))
}

fn contains_duplicate<T: Ord>(values: impl IntoIterator<Item = T>) -> bool {
    let mut seen = BTreeSet::new();
    values.into_iter().any(|value| !seen.insert(value))
}
