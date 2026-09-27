//! Versioned, language-neutral codecs for transparent kernel evidence.
//!
//! Decoding never creates a trusted checkpoint, result, or transition.  The
//! `Unverified*` values in this module must be promoted through invariant,
//! checkpoint-identity, pin, or deterministic-replay checks before use.

use std::collections::{BTreeMap, BTreeSet};

use silk_types::{
    BodyCommitment, CanonicalDecode, CanonicalEncode, ChainDomain, CheckpointId, DecodeError,
    Decoder, EncodeError, Encoder, Hash32, IntentId, NoteCommitment, Nullifier, ProfileDomain,
    VertexId, validate_sorted_unique,
};

use crate::state::{CheckpointStateParts, validate_native_membership, validate_native_supply};
use crate::{
    AcceptedEffect, CheckpointState, CodecVerificationError, Decision, MAX_ORDERED_BODIES,
    MAX_TRANSACTIONS, NativeNote, Outcome, RecoveryRecord, RejectCode, Transition,
};

/// Shared version byte for the first transparent evidence-codec family.
pub const CODEC_VERSION: u8 = 0x01;
/// Object tag for `NativeStateProjectionV1`.
pub const NATIVE_STATE_PROJECTION_TAG: u8 = 0xc0;
/// Object tag for `OutcomeV1`.
pub const OUTCOME_TAG: u8 = 0xc1;
/// Object tag for `DecisionV1`.
pub const DECISION_TAG: u8 = 0xc2;
/// Object tag for `AcceptedEffectV1`.
pub const ACCEPTED_EFFECT_TAG: u8 = 0xc3;
/// Object tag for `NativeIntervalResultV1`.
pub const NATIVE_INTERVAL_RESULT_TAG: u8 = 0xc4;
/// Object tag for `CheckpointStateV1`.
pub const CHECKPOINT_STATE_TAG: u8 = 0xc5;
/// Object tag for `TransitionV1`.
pub const TRANSITION_TAG: u8 = 0xc6;

const OUTCOME_ACCEPTED: u8 = 0;
const OUTCOME_REJECTED: u8 = 1;
const HASH_BYTES: usize = 32;
const NATIVE_NOTE_BYTES: usize = 1 + 8 + (4 * HASH_BYTES);
const LIVE_NOTE_ENTRY_BYTES: usize = HASH_BYTES + NATIVE_NOTE_BYTES;
const RECOVERY_RECORD_BYTES: usize = 1 + HASH_BYTES + crate::RECOVERY_PAYLOAD_BYTES;
const ACCEPTED_EFFECT_BYTES: usize = 2 + (2 * HASH_BYTES);
const MIN_OUTCOME_BYTES: usize = 3;
const MIN_DECISION_BYTES: usize =
    2 + 4 + HASH_BYTES + 4 + 4 + HASH_BYTES + HASH_BYTES + MIN_OUTCOME_BYTES;

fn encode_prefix(encoder: &mut Encoder, tag: u8) {
    encoder.write_u8(tag);
    encoder.write_u8(CODEC_VERSION);
}

fn decode_prefix(decoder: &mut Decoder<'_>, tag: u8) -> Result<(), DecodeError> {
    decoder.read_tag(&[tag])?;
    decoder.read_tag(&[CODEC_VERSION])?;
    Ok(())
}

const fn remaining_item_bound(decoder: &Decoder<'_>, minimum_item_bytes: usize) -> usize {
    decoder.remaining() / minimum_item_bytes
}

const fn limited_remaining_item_bound(
    decoder: &Decoder<'_>,
    minimum_item_bytes: usize,
    semantic_limit: usize,
) -> usize {
    let remaining_bound = remaining_item_bound(decoder, minimum_item_bytes);
    if remaining_bound < semantic_limit {
        remaining_bound
    } else {
        semantic_limit
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NativeStateFields {
    live_notes: BTreeMap<NoteCommitment, NativeNote>,
    nullifiers: BTreeSet<Nullifier>,
    commitment_history: BTreeSet<NoteCommitment>,
    recovery_history: Vec<RecoveryRecord>,
    accepted_intents: BTreeSet<IntentId>,
    native_issued: u128,
    fee_pool: u128,
}

impl NativeStateFields {
    fn from_checkpoint(state: &CheckpointState) -> Self {
        Self {
            live_notes: state.live_notes().clone(),
            nullifiers: state.nullifiers().clone(),
            commitment_history: state.commitment_history().clone(),
            recovery_history: state.recovery_history().to_vec(),
            accepted_intents: state.accepted_intents().clone(),
            native_issued: state.native_issued(),
            fee_pool: state.fee_pool(),
        }
    }

    fn validate(&self, chain_domain: ChainDomain) -> Result<(), CodecVerificationError> {
        validate_native_membership(
            chain_domain,
            &self.live_notes,
            &self.nullifiers,
            &self.commitment_history,
            &self.recovery_history,
        )?;
        validate_native_supply(&self.live_notes, self.native_issued, self.fee_pool)?;
        Ok(())
    }
}

fn encode_live_notes(
    encoder: &mut Encoder,
    live_notes: &BTreeMap<NoteCommitment, NativeNote>,
) -> Result<(), EncodeError> {
    encoder.write_len("live notes", live_notes.len())?;
    for (commitment, note) in live_notes {
        commitment.encode(encoder)?;
        note.encode(encoder)?;
    }
    Ok(())
}

fn decode_live_notes(
    decoder: &mut Decoder<'_>,
) -> Result<BTreeMap<NoteCommitment, NativeNote>, DecodeError> {
    let maximum = remaining_item_bound(decoder, LIVE_NOTE_ENTRY_BYTES);
    let length = decoder.read_len("live notes", maximum)?;
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(length)
        .map_err(|_| DecodeError::AllocationFailed {
            kind: "live notes",
            length,
        })?;
    for _ in 0..length {
        entries.push((
            NoteCommitment::decode(decoder)?,
            NativeNote::decode(decoder)?,
        ));
    }
    let keys = entries
        .iter()
        .map(|(commitment, _)| *commitment)
        .collect::<Vec<_>>();
    validate_sorted_unique(&keys)?;
    Ok(entries.into_iter().collect())
}

fn encode_native_fields(
    encoder: &mut Encoder,
    fields: &NativeStateFields,
) -> Result<(), EncodeError> {
    encode_live_notes(encoder, &fields.live_notes)?;
    let nullifiers = fields.nullifiers.iter().copied().collect::<Vec<_>>();
    encoder.write_sorted_unique(&nullifiers)?;
    let commitments = fields
        .commitment_history
        .iter()
        .copied()
        .collect::<Vec<_>>();
    encoder.write_sorted_unique(&commitments)?;
    encoder.write_list(&fields.recovery_history)?;
    let intents = fields.accepted_intents.iter().copied().collect::<Vec<_>>();
    encoder.write_sorted_unique(&intents)?;
    encoder.write_u128(fields.native_issued);
    encoder.write_u128(fields.fee_pool);
    Ok(())
}

fn decode_hash_set<T: CanonicalDecode + Ord>(
    decoder: &mut Decoder<'_>,
) -> Result<BTreeSet<T>, DecodeError> {
    let maximum = remaining_item_bound(decoder, HASH_BYTES);
    Ok(decoder.read_sorted_unique(maximum)?.into_iter().collect())
}

fn decode_hash_list<T: CanonicalDecode>(
    decoder: &mut Decoder<'_>,
    semantic_limit: Option<usize>,
) -> Result<Vec<T>, DecodeError> {
    let remaining = remaining_item_bound(decoder, HASH_BYTES);
    let maximum = semantic_limit.map_or(remaining, |limit| remaining.min(limit));
    decoder.read_list(maximum)
}

fn decode_native_fields(decoder: &mut Decoder<'_>) -> Result<NativeStateFields, DecodeError> {
    let live_notes = decode_live_notes(decoder)?;
    let nullifiers = decode_hash_set(decoder)?;
    let commitment_history = decode_hash_set(decoder)?;
    let recovery_limit = remaining_item_bound(decoder, RECOVERY_RECORD_BYTES);
    let recovery_history = decoder.read_list(recovery_limit)?;
    let accepted_intents = decode_hash_set(decoder)?;
    let native_issued = decoder.read_u128()?;
    let fee_pool = decoder.read_u128()?;
    Ok(NativeStateFields {
        live_notes,
        nullifiers,
        commitment_history,
        recovery_history,
        accepted_intents,
        native_issued,
        fee_pool,
    })
}

/// A validated logical native-state projection without checkpoint-only fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeStateProjection {
    fields: NativeStateFields,
}

impl NativeStateProjection {
    pub(super) fn from_checkpoint(state: &CheckpointState) -> Self {
        Self {
            fields: NativeStateFields::from_checkpoint(state),
        }
    }

    /// Returns all currently live notes in canonical commitment order.
    #[must_use]
    pub const fn live_notes(&self) -> &BTreeMap<NoteCommitment, NativeNote> {
        &self.fields.live_notes
    }

    /// Returns the sorted set of consumed nullifiers.
    #[must_use]
    pub const fn nullifiers(&self) -> &BTreeSet<Nullifier> {
        &self.fields.nullifiers
    }

    /// Returns every commitment ever materialized in this lineage.
    #[must_use]
    pub const fn commitment_history(&self) -> &BTreeSet<NoteCommitment> {
        &self.fields.commitment_history
    }

    /// Returns recovery records in checkpoint append order.
    #[must_use]
    pub fn recovery_history(&self) -> &[RecoveryRecord] {
        &self.fields.recovery_history
    }

    /// Returns all accepted intent identifiers in sorted order.
    #[must_use]
    pub const fn accepted_intents(&self) -> &BTreeSet<IntentId> {
        &self.fields.accepted_intents
    }

    /// Returns cumulative native issuance.
    #[must_use]
    pub const fn native_issued(&self) -> u128 {
        self.fields.native_issued
    }

    /// Returns conserved fees awaiting a later reward rule.
    #[must_use]
    pub const fn fee_pool(&self) -> u128 {
        self.fields.fee_pool
    }
}

impl CanonicalEncode for NativeStateProjection {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encode_prefix(encoder, NATIVE_STATE_PROJECTION_TAG);
        encode_native_fields(encoder, &self.fields)
    }
}

/// Canonically parsed but semantically unverified native-state projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnverifiedNativeStateProjection {
    fields: NativeStateFields,
}

impl UnverifiedNativeStateProjection {
    /// Validates membership, recovery, and supply invariants for an explicit chain.
    ///
    /// This establishes internal native-state validity only.  It does not prove
    /// checkpoint identity, lineage, finality, or authorization to execute.
    ///
    /// # Errors
    ///
    /// Returns the first native state invariant or hashing failure.
    pub fn verify(
        self,
        chain_domain: ChainDomain,
    ) -> Result<NativeStateProjection, CodecVerificationError> {
        self.fields.validate(chain_domain)?;
        Ok(NativeStateProjection {
            fields: self.fields,
        })
    }
}

impl CanonicalEncode for UnverifiedNativeStateProjection {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encode_prefix(encoder, NATIVE_STATE_PROJECTION_TAG);
        encode_native_fields(encoder, &self.fields)
    }
}

impl CanonicalDecode for UnverifiedNativeStateProjection {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_prefix(decoder, NATIVE_STATE_PROJECTION_TAG)?;
        Ok(Self {
            fields: decode_native_fields(decoder)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UnverifiedOutcomeValue {
    Accepted,
    Rejected(u16),
}

/// Canonically parsed but semantically unverified transaction outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnverifiedOutcome {
    value: UnverifiedOutcomeValue,
}

impl UnverifiedOutcome {
    const fn from_outcome(outcome: Outcome) -> Self {
        let value = match outcome {
            Outcome::Accepted => UnverifiedOutcomeValue::Accepted,
            Outcome::Rejected(code) => UnverifiedOutcomeValue::Rejected(code.numeric()),
        };
        Self { value }
    }

    /// Promotes a known accepted or rejected outcome.
    ///
    /// # Errors
    ///
    /// Returns [`crate::UnknownRejectCode`] for an unassigned rejection number.
    pub fn verify(self) -> Result<Outcome, CodecVerificationError> {
        match self.value {
            UnverifiedOutcomeValue::Accepted => Ok(Outcome::Accepted),
            UnverifiedOutcomeValue::Rejected(code) => {
                Ok(Outcome::Rejected(RejectCode::try_from(code)?))
            }
        }
    }
}

fn encode_unverified_outcome(value: UnverifiedOutcomeValue, encoder: &mut Encoder) {
    encode_prefix(encoder, OUTCOME_TAG);
    match value {
        UnverifiedOutcomeValue::Accepted => encoder.write_u8(OUTCOME_ACCEPTED),
        UnverifiedOutcomeValue::Rejected(code) => {
            encoder.write_u8(OUTCOME_REJECTED);
            encoder.write_u16(code);
        }
    }
}

impl CanonicalEncode for Outcome {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encode_unverified_outcome(UnverifiedOutcome::from_outcome(*self).value, encoder);
        Ok(())
    }
}

impl CanonicalEncode for UnverifiedOutcome {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encode_unverified_outcome(self.value, encoder);
        Ok(())
    }
}

impl CanonicalDecode for UnverifiedOutcome {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_prefix(decoder, OUTCOME_TAG)?;
        let value = match decoder.read_tag(&[OUTCOME_ACCEPTED, OUTCOME_REJECTED])? {
            OUTCOME_ACCEPTED => UnverifiedOutcomeValue::Accepted,
            OUTCOME_REJECTED => UnverifiedOutcomeValue::Rejected(decoder.read_u16()?),
            _ => unreachable!("read_tag accepted only a listed outcome"),
        };
        Ok(Self { value })
    }
}

/// Canonically parsed but semantically unverified execution decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnverifiedDecision {
    position: u32,
    body_id: VertexId,
    body_position: u32,
    transaction_position: u32,
    intent_id: IntentId,
    instance_hash: Hash32,
    outcome: UnverifiedOutcome,
}

impl UnverifiedDecision {
    fn into_candidate(self) -> Result<Decision, CodecVerificationError> {
        Ok(Decision {
            position: self.position,
            body_id: self.body_id,
            body_position: self.body_position,
            transaction_position: self.transaction_position,
            intent_id: self.intent_id,
            instance_hash: self.instance_hash,
            outcome: self.outcome.verify()?,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn encode_decision_fields(
    position: u32,
    body_id: VertexId,
    body_position: u32,
    transaction_position: u32,
    intent_id: IntentId,
    instance_hash: Hash32,
    outcome: &impl CanonicalEncode,
    encoder: &mut Encoder,
) -> Result<(), EncodeError> {
    encode_prefix(encoder, DECISION_TAG);
    encoder.write_u32(position);
    body_id.encode(encoder)?;
    encoder.write_u32(body_position);
    encoder.write_u32(transaction_position);
    intent_id.encode(encoder)?;
    instance_hash.encode(encoder)?;
    outcome.encode(encoder)
}

impl CanonicalEncode for Decision {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encode_decision_fields(
            self.position,
            self.body_id,
            self.body_position,
            self.transaction_position,
            self.intent_id,
            self.instance_hash,
            &self.outcome,
            encoder,
        )
    }
}

impl CanonicalEncode for UnverifiedDecision {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encode_decision_fields(
            self.position,
            self.body_id,
            self.body_position,
            self.transaction_position,
            self.intent_id,
            self.instance_hash,
            &self.outcome,
            encoder,
        )
    }
}

impl CanonicalDecode for UnverifiedDecision {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_prefix(decoder, DECISION_TAG)?;
        Ok(Self {
            position: decoder.read_u32()?,
            body_id: VertexId::decode(decoder)?,
            body_position: decoder.read_u32()?,
            transaction_position: decoder.read_u32()?,
            intent_id: IntentId::decode(decoder)?,
            instance_hash: Hash32::decode(decoder)?,
            outcome: UnverifiedOutcome::decode(decoder)?,
        })
    }
}

/// Canonically parsed but semantically unverified accepted-effect reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnverifiedAcceptedEffect {
    body_id: VertexId,
    intent_id: IntentId,
}

impl UnverifiedAcceptedEffect {
    const fn into_candidate(self) -> AcceptedEffect {
        AcceptedEffect {
            body_id: self.body_id,
            intent_id: self.intent_id,
        }
    }
}

#[allow(clippy::redundant_pub_crate)]
pub(super) fn encode_accepted_effect(
    effect: &AcceptedEffect,
    encoder: &mut Encoder,
) -> Result<(), EncodeError> {
    encode_prefix(encoder, ACCEPTED_EFFECT_TAG);
    effect.body_id.encode(encoder)?;
    effect.intent_id.encode(encoder)
}

impl CanonicalEncode for UnverifiedAcceptedEffect {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encode_prefix(encoder, ACCEPTED_EFFECT_TAG);
        self.body_id.encode(encoder)?;
        self.intent_id.encode(encoder)
    }
}

impl CanonicalDecode for UnverifiedAcceptedEffect {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_prefix(decoder, ACCEPTED_EFFECT_TAG)?;
        Ok(Self {
            body_id: VertexId::decode(decoder)?,
            intent_id: IntentId::decode(decoder)?,
        })
    }
}

/// Validated native execution result before checkpoint-only projection fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeIntervalResult {
    decisions: Vec<Decision>,
    accepted_effects: Vec<AcceptedEffect>,
    resulting_native_state: NativeStateProjection,
}

impl NativeIntervalResult {
    pub(super) const fn from_execution(
        decisions: Vec<Decision>,
        accepted_effects: Vec<AcceptedEffect>,
        resulting_native_state: NativeStateProjection,
    ) -> Self {
        Self {
            decisions,
            accepted_effects,
            resulting_native_state,
        }
    }

    pub(super) fn from_transition(transition: &Transition) -> Self {
        Self {
            decisions: transition.decisions().to_vec(),
            accepted_effects: transition.next().accepted_effects_in_checkpoint().to_vec(),
            resulting_native_state: NativeStateProjection::from_checkpoint(transition.next()),
        }
    }

    /// Returns decisions in canonical execution order.
    #[must_use]
    pub fn decisions(&self) -> &[Decision] {
        &self.decisions
    }

    /// Returns accepted effects in execution order.
    #[must_use]
    pub fn accepted_effects(&self) -> &[AcceptedEffect] {
        &self.accepted_effects
    }

    /// Returns the validated resulting native state.
    #[must_use]
    pub const fn resulting_native_state(&self) -> &NativeStateProjection {
        &self.resulting_native_state
    }
}

impl CanonicalEncode for NativeIntervalResult {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encode_prefix(encoder, NATIVE_INTERVAL_RESULT_TAG);
        encoder.write_list(&self.decisions)?;
        encoder.write_list(&self.accepted_effects)?;
        self.resulting_native_state.encode(encoder)
    }
}

/// Canonically parsed but semantically unverified native interval result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnverifiedNativeIntervalResult {
    decisions: Vec<UnverifiedDecision>,
    accepted_effects: Vec<UnverifiedAcceptedEffect>,
    resulting_native_state: UnverifiedNativeStateProjection,
}

impl UnverifiedNativeIntervalResult {
    pub(super) fn into_candidate(
        self,
        chain_domain: ChainDomain,
    ) -> Result<NativeIntervalResult, CodecVerificationError> {
        let decisions = self
            .decisions
            .into_iter()
            .map(UnverifiedDecision::into_candidate)
            .collect::<Result<Vec<_>, _>>()?;
        let accepted_effects = self
            .accepted_effects
            .into_iter()
            .map(UnverifiedAcceptedEffect::into_candidate)
            .collect();
        let resulting_native_state = self.resulting_native_state.verify(chain_domain)?;
        Ok(NativeIntervalResult {
            decisions,
            accepted_effects,
            resulting_native_state,
        })
    }
}

impl CanonicalEncode for UnverifiedNativeIntervalResult {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encode_prefix(encoder, NATIVE_INTERVAL_RESULT_TAG);
        encoder.write_list(&self.decisions)?;
        encoder.write_list(&self.accepted_effects)?;
        self.resulting_native_state.encode(encoder)
    }
}

impl CanonicalDecode for UnverifiedNativeIntervalResult {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_prefix(decoder, NATIVE_INTERVAL_RESULT_TAG)?;
        let decision_limit =
            limited_remaining_item_bound(decoder, MIN_DECISION_BYTES, MAX_TRANSACTIONS);
        let decisions = decoder.read_list(decision_limit)?;
        let effect_limit =
            limited_remaining_item_bound(decoder, ACCEPTED_EFFECT_BYTES, MAX_TRANSACTIONS);
        let accepted_effects = decoder.read_list(effect_limit)?;
        Ok(Self {
            decisions,
            accepted_effects,
            resulting_native_state: UnverifiedNativeStateProjection::decode(decoder)?,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn encode_checkpoint_fields(
    encoder: &mut Encoder,
    chain_domain: ChainDomain,
    profile_domain: ProfileDomain,
    checkpoint_id: CheckpointId,
    previous_checkpoint: CheckpointId,
    checkpoint_index: u64,
    native: &NativeStateFields,
    ordered_body_history: &[VertexId],
    bodies_in_checkpoint: &[VertexId],
    body_bindings_in_checkpoint: &[BodyCommitment],
    accepted_effects_in_checkpoint: &[AcceptedEffect],
) -> Result<(), EncodeError> {
    encode_prefix(encoder, CHECKPOINT_STATE_TAG);
    chain_domain.encode(encoder)?;
    profile_domain.encode(encoder)?;
    checkpoint_id.encode(encoder)?;
    previous_checkpoint.encode(encoder)?;
    encoder.write_u64(checkpoint_index);
    encode_live_notes(encoder, &native.live_notes)?;
    let nullifiers = native.nullifiers.iter().copied().collect::<Vec<_>>();
    encoder.write_sorted_unique(&nullifiers)?;
    let commitments = native
        .commitment_history
        .iter()
        .copied()
        .collect::<Vec<_>>();
    encoder.write_sorted_unique(&commitments)?;
    encoder.write_list(&native.recovery_history)?;
    encoder.write_list(ordered_body_history)?;
    encoder.write_list(bodies_in_checkpoint)?;
    encoder.write_list(body_bindings_in_checkpoint)?;
    let intents = native.accepted_intents.iter().copied().collect::<Vec<_>>();
    encoder.write_sorted_unique(&intents)?;
    encoder.write_list(accepted_effects_in_checkpoint)?;
    encoder.write_u128(native.native_issued);
    encoder.write_u128(native.fee_pool);
    Ok(())
}

impl CanonicalEncode for CheckpointState {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        let native = NativeStateFields::from_checkpoint(self);
        encode_checkpoint_fields(
            encoder,
            self.chain_domain(),
            self.profile_domain(),
            self.checkpoint_id(),
            self.previous_checkpoint(),
            self.checkpoint_index(),
            &native,
            self.ordered_body_history(),
            self.bodies_in_checkpoint(),
            self.body_bindings_in_checkpoint(),
            self.accepted_effects_in_checkpoint(),
        )
    }
}

/// Canonically parsed checkpoint fields without invariant or identity authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnverifiedCheckpointState {
    chain_domain: ChainDomain,
    profile_domain: ProfileDomain,
    checkpoint_id: CheckpointId,
    previous_checkpoint: CheckpointId,
    checkpoint_index: u64,
    native: NativeStateFields,
    ordered_body_history: Vec<VertexId>,
    bodies_in_checkpoint: Vec<VertexId>,
    body_bindings_in_checkpoint: Vec<BodyCommitment>,
    accepted_effects_in_checkpoint: Vec<UnverifiedAcceptedEffect>,
}

impl UnverifiedCheckpointState {
    pub(super) fn into_candidate(self) -> CheckpointState {
        CheckpointState::from_codec_parts(CheckpointStateParts {
            chain_domain: self.chain_domain,
            profile_domain: self.profile_domain,
            checkpoint_id: self.checkpoint_id,
            previous_checkpoint: self.previous_checkpoint,
            checkpoint_index: self.checkpoint_index,
            live_notes: self.native.live_notes,
            nullifiers: self.native.nullifiers,
            commitment_history: self.native.commitment_history,
            recovery_history: self.native.recovery_history,
            ordered_body_history: self.ordered_body_history,
            bodies_in_checkpoint: self.bodies_in_checkpoint,
            body_bindings_in_checkpoint: self.body_bindings_in_checkpoint,
            accepted_intents: self.native.accepted_intents,
            accepted_effects_in_checkpoint: self
                .accepted_effects_in_checkpoint
                .into_iter()
                .map(UnverifiedAcceptedEffect::into_candidate)
                .collect(),
            native_issued: self.native.native_issued,
            fee_pool: self.native.fee_pool,
        })
    }
}

impl CanonicalEncode for UnverifiedCheckpointState {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        let accepted = self
            .accepted_effects_in_checkpoint
            .iter()
            .copied()
            .map(UnverifiedAcceptedEffect::into_candidate)
            .collect::<Vec<_>>();
        encode_checkpoint_fields(
            encoder,
            self.chain_domain,
            self.profile_domain,
            self.checkpoint_id,
            self.previous_checkpoint,
            self.checkpoint_index,
            &self.native,
            &self.ordered_body_history,
            &self.bodies_in_checkpoint,
            &self.body_bindings_in_checkpoint,
            &accepted,
        )
    }
}

impl CanonicalDecode for UnverifiedCheckpointState {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_prefix(decoder, CHECKPOINT_STATE_TAG)?;
        let chain_domain = ChainDomain::decode(decoder)?;
        let profile_domain = ProfileDomain::decode(decoder)?;
        let checkpoint_id = CheckpointId::decode(decoder)?;
        let previous_checkpoint = CheckpointId::decode(decoder)?;
        let checkpoint_index = decoder.read_u64()?;
        let live_notes = decode_live_notes(decoder)?;
        let nullifiers = decode_hash_set(decoder)?;
        let commitment_history = decode_hash_set(decoder)?;
        let recovery_limit = remaining_item_bound(decoder, RECOVERY_RECORD_BYTES);
        let recovery_history = decoder.read_list(recovery_limit)?;
        let ordered_body_history = decode_hash_list(decoder, None)?;
        let bodies_in_checkpoint = decode_hash_list(decoder, Some(MAX_ORDERED_BODIES))?;
        let body_bindings_in_checkpoint = decode_hash_list(decoder, Some(MAX_ORDERED_BODIES))?;
        let accepted_intents = decode_hash_set(decoder)?;
        let effect_limit =
            limited_remaining_item_bound(decoder, ACCEPTED_EFFECT_BYTES, MAX_TRANSACTIONS);
        let accepted_effects_in_checkpoint = decoder.read_list(effect_limit)?;
        let native_issued = decoder.read_u128()?;
        let fee_pool = decoder.read_u128()?;
        Ok(Self {
            chain_domain,
            profile_domain,
            checkpoint_id,
            previous_checkpoint,
            checkpoint_index,
            native: NativeStateFields {
                live_notes,
                nullifiers,
                commitment_history,
                recovery_history,
                accepted_intents,
                native_issued,
                fee_pool,
            },
            ordered_body_history,
            bodies_in_checkpoint,
            body_bindings_in_checkpoint,
            accepted_effects_in_checkpoint,
        })
    }
}

/// Canonically parsed transition fields without replay or checkpoint authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnverifiedTransition {
    previous: UnverifiedCheckpointState,
    next: UnverifiedCheckpointState,
    decisions: Vec<UnverifiedDecision>,
}

impl UnverifiedTransition {
    pub(super) fn into_parts(
        self,
    ) -> (
        UnverifiedCheckpointState,
        UnverifiedCheckpointState,
        Vec<UnverifiedDecision>,
    ) {
        (self.previous, self.next, self.decisions)
    }
}

impl CanonicalEncode for Transition {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encode_prefix(encoder, TRANSITION_TAG);
        self.previous().encode(encoder)?;
        self.next().encode(encoder)?;
        encoder.write_list(self.decisions())
    }
}

impl CanonicalEncode for UnverifiedTransition {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encode_prefix(encoder, TRANSITION_TAG);
        self.previous.encode(encoder)?;
        self.next.encode(encoder)?;
        encoder.write_list(&self.decisions)
    }
}

impl CanonicalDecode for UnverifiedTransition {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_prefix(decoder, TRANSITION_TAG)?;
        let previous = UnverifiedCheckpointState::decode(decoder)?;
        let next = UnverifiedCheckpointState::decode(decoder)?;
        let decision_limit =
            limited_remaining_item_bound(decoder, MIN_DECISION_BYTES, MAX_TRANSACTIONS);
        Ok(Self {
            previous,
            next,
            decisions: decoder.read_list(decision_limit)?,
        })
    }
}

#[allow(clippy::redundant_pub_crate)]
pub(super) fn decisions_from_unverified(
    decisions: Vec<UnverifiedDecision>,
) -> Result<Vec<Decision>, CodecVerificationError> {
    decisions
        .into_iter()
        .map(UnverifiedDecision::into_candidate)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> Hash32 {
        Hash32::new([byte; HASH_BYTES])
    }

    #[test]
    fn all_outcomes_round_trip_only_through_unverified_values() {
        let mut outcomes = vec![Outcome::Accepted];
        for numeric in 1..=25 {
            outcomes.push(Outcome::Rejected(
                RejectCode::try_from(numeric).expect("assigned rejection code"),
            ));
        }
        for outcome in outcomes {
            let bytes = outcome.to_canonical_bytes().expect("outcome encodes");
            let decoded =
                UnverifiedOutcome::from_canonical_bytes(&bytes).expect("outcome candidate decodes");
            assert_eq!(decoded.verify().expect("known outcome promotes"), outcome);
        }
    }

    #[test]
    fn unknown_rejection_number_decodes_but_cannot_promote() {
        let bytes = [OUTCOME_TAG, CODEC_VERSION, OUTCOME_REJECTED, 0xff, 0xff];
        let decoded = UnverifiedOutcome::from_canonical_bytes(&bytes)
            .expect("unknown semantic code is still canonical bytes");
        let error = decoded.verify().expect_err("unknown code cannot promote");
        assert_eq!(error.code(), "codec.unknown_reject_code");
    }

    #[test]
    fn decision_and_accepted_effect_have_distinct_tagged_round_trips() {
        let decision = Decision {
            position: 3,
            body_id: VertexId::new(hash(1)),
            body_position: 1,
            transaction_position: 2,
            intent_id: IntentId::new(hash(2)),
            instance_hash: hash(3),
            outcome: Outcome::Rejected(RejectCode::WrongChain),
        };
        let decision_bytes = decision.to_canonical_bytes().expect("decision encodes");
        assert_eq!(decision_bytes[0..2], [DECISION_TAG, CODEC_VERSION]);
        let decoded = UnverifiedDecision::from_canonical_bytes(&decision_bytes)
            .expect("decision candidate decodes")
            .into_candidate()
            .expect("known outcome promotes");
        assert_eq!(decoded, decision);

        let effect = AcceptedEffect {
            body_id: VertexId::new(hash(4)),
            intent_id: IntentId::new(hash(5)),
        };
        let effect_bytes = effect.to_canonical_bytes().expect("effect encodes");
        assert_eq!(effect_bytes[0..2], [ACCEPTED_EFFECT_TAG, CODEC_VERSION]);
        let decoded = UnverifiedAcceptedEffect::from_canonical_bytes(&effect_bytes)
            .expect("effect candidate decodes")
            .into_candidate();
        assert_eq!(decoded, effect);
    }

    #[test]
    fn checkpoint_codec_preserves_state_digest_projection() {
        let chain = ChainDomain::new(hash(6));
        let profile = ProfileDomain::new(hash(7));
        let mut state = CheckpointState::empty_for_test(chain, profile);
        state
            .validate()
            .expect("empty no-value checkpoint state validates");
        let before = state.state_digest().expect("state digest derives");
        state.replace_checkpoint_id_for_test(
            state
                .derive_checkpoint_id()
                .expect("checkpoint identity derives"),
        );

        let bytes = state.to_canonical_bytes().expect("checkpoint encodes");
        assert_eq!(bytes[0..2], [CHECKPOINT_STATE_TAG, CODEC_VERSION]);
        let candidate = UnverifiedCheckpointState::from_canonical_bytes(&bytes)
            .expect("checkpoint candidate decodes")
            .into_candidate();
        candidate
            .validate()
            .expect("decoded fields retain invariants");
        assert_eq!(candidate, state);
        assert_eq!(candidate.state_digest().expect("digest derives"), before);
        assert_eq!(
            candidate
                .derive_checkpoint_id()
                .expect("checkpoint identity derives"),
            state.checkpoint_id()
        );
    }

    #[test]
    fn remaining_bytes_bound_blocks_allocation_from_a_forged_count() {
        let mut bytes = vec![NATIVE_STATE_PROJECTION_TAG, CODEC_VERSION];
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        let error = UnverifiedNativeStateProjection::from_canonical_bytes(&bytes)
            .expect_err("forged count rejects before allocation");
        assert!(matches!(error, DecodeError::LimitExceeded { .. }));
    }

    #[test]
    fn every_top_level_type_rejects_trailing_bytes_and_unknown_versions() {
        let outcome = Outcome::Accepted
            .to_canonical_bytes()
            .expect("outcome encodes");
        let mut trailing = outcome.clone();
        trailing.push(0);
        assert!(matches!(
            UnverifiedOutcome::from_canonical_bytes(&trailing),
            Err(DecodeError::TrailingBytes { .. })
        ));
        let mut unknown = outcome;
        unknown[1] = 2;
        assert!(matches!(
            UnverifiedOutcome::from_canonical_bytes(&unknown),
            Err(DecodeError::UnknownTag { .. })
        ));
    }
}
