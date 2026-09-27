//! Reduced no-value Gate A genesis receipt.

use silk_profile::ExecutionProfile;
use silk_types::{
    CanonicalDecode, CanonicalEncode, ChainDomain, CheckpointId, DecodeError, Decoder, EncodeError,
    Encoder, GenesisCommitment, Hash32, ManifestHash, ProfileDomain,
};

use crate::{CheckpointState, KernelError};

const GATE_A_GENESIS_RECEIPT_VERSION: u8 = 1;
const GATE_A_GENESIS_RECEIPT_TAGS: &[u8] = &[GATE_A_GENESIS_RECEIPT_VERSION];

/// A field whose supplied Gate A genesis receipt value failed recomputation.
///
/// Variant order is the fixed comparison precedence used by
/// [`GateAGenesisReceipt::verify`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateAGenesisReceiptField {
    /// Literal protocol major retained by the trusted receipt template.
    ProtocolMajor,
    /// Five-input non-circular genesis commitment.
    GenesisCommitment,
    /// Immutable chain domain derived from the genesis commitment.
    ChainDomain,
    /// Chain-bound activated genesis manifest hash.
    ProtocolManifestHash,
    /// Activated protocol-profile domain.
    ProfileDomain,
    /// Transparent checkpoint-zero logical-state digest.
    CheckpointZeroStateDigest,
    /// Transparent checkpoint-zero identifier.
    CheckpointZeroId,
}

/// Exact derived outputs of the reduced no-value Gate A genesis path.
///
/// This receipt is not a proof-of-work vertex and is never a
/// [`silk_types::VertexId`] or [`silk_types::GenesisId`]. It contains only
/// values already derived and checked by the current profile and transparent
/// checkpoint-zero controls.
/// Raw field construction is intentionally unavailable:
///
/// ```compile_fail
/// use silk_kernel::GateAGenesisReceipt;
///
/// fn forge() {
///     let _ = GateAGenesisReceipt {
///         protocol_major: 1,
///     };
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GateAGenesisReceipt {
    protocol_major: u32,
    genesis_commitment: GenesisCommitment,
    chain_domain: ChainDomain,
    protocol_manifest_hash: ManifestHash,
    profile_domain: ProfileDomain,
    checkpoint_zero_state_digest: Hash32,
    checkpoint_zero_id: CheckpointId,
}

impl GateAGenesisReceipt {
    pub(crate) fn materialize(
        execution_profile: &ExecutionProfile,
        state: &CheckpointState,
    ) -> Result<Self, KernelError> {
        validate_checkpoint_zero(execution_profile, state)?;
        let (checkpoint_zero_state_digest, checkpoint_zero_id) =
            recompute_checkpoint_zero_commitments(state)?;
        Ok(Self {
            protocol_major: execution_profile.protocol_major(),
            genesis_commitment: execution_profile.genesis_commitment(),
            chain_domain: execution_profile.chain_domain(),
            protocol_manifest_hash: execution_profile.manifest_hash(),
            profile_domain: execution_profile.profile_domain(),
            checkpoint_zero_state_digest,
            checkpoint_zero_id,
        })
    }

    /// Verifies every receipt field against one sealed profile and checkpoint zero.
    ///
    /// The state/profile boundary is checked before receipt fields. Receipt
    /// mismatches then use the declaration order of [`GateAGenesisReceiptField`].
    ///
    /// # Errors
    ///
    /// Returns a state/profile/checkpoint-zero error, a hashing error, or the
    /// first exact receipt-field mismatch.
    pub fn verify(
        &self,
        execution_profile: &ExecutionProfile,
        state: &CheckpointState,
    ) -> Result<(), KernelError> {
        let expected = Self::materialize(execution_profile, state)?;
        let fields = [
            (
                self.protocol_major == expected.protocol_major,
                GateAGenesisReceiptField::ProtocolMajor,
            ),
            (
                self.genesis_commitment == expected.genesis_commitment,
                GateAGenesisReceiptField::GenesisCommitment,
            ),
            (
                self.chain_domain == expected.chain_domain,
                GateAGenesisReceiptField::ChainDomain,
            ),
            (
                self.protocol_manifest_hash == expected.protocol_manifest_hash,
                GateAGenesisReceiptField::ProtocolManifestHash,
            ),
            (
                self.profile_domain == expected.profile_domain,
                GateAGenesisReceiptField::ProfileDomain,
            ),
            (
                self.checkpoint_zero_state_digest == expected.checkpoint_zero_state_digest,
                GateAGenesisReceiptField::CheckpointZeroStateDigest,
            ),
            (
                self.checkpoint_zero_id == expected.checkpoint_zero_id,
                GateAGenesisReceiptField::CheckpointZeroId,
            ),
        ];
        for (matches, field) in fields {
            if !matches {
                return Err(KernelError::GenesisReceiptMismatch { field });
            }
        }
        Ok(())
    }

    /// Returns the literal genesis protocol major.
    #[must_use]
    pub const fn protocol_major(&self) -> u32 {
        self.protocol_major
    }

    /// Returns the five-input non-circular genesis commitment.
    #[must_use]
    pub const fn genesis_commitment(&self) -> GenesisCommitment {
        self.genesis_commitment
    }

    /// Returns the immutable derived chain domain.
    #[must_use]
    pub const fn chain_domain(&self) -> ChainDomain {
        self.chain_domain
    }

    /// Returns the exact activated genesis manifest hash.
    #[must_use]
    pub const fn protocol_manifest_hash(&self) -> ManifestHash {
        self.protocol_manifest_hash
    }

    /// Returns the exact activated profile domain.
    #[must_use]
    pub const fn profile_domain(&self) -> ProfileDomain {
        self.profile_domain
    }

    /// Returns the transparent checkpoint-zero logical-state digest.
    #[must_use]
    pub const fn checkpoint_zero_state_digest(&self) -> Hash32 {
        self.checkpoint_zero_state_digest
    }

    /// Returns the transparent checkpoint-zero identifier.
    #[must_use]
    pub const fn checkpoint_zero_id(&self) -> CheckpointId {
        self.checkpoint_zero_id
    }
}

impl CanonicalEncode for GateAGenesisReceipt {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_u8(GATE_A_GENESIS_RECEIPT_VERSION);
        self.protocol_major.encode(encoder)?;
        self.genesis_commitment.encode(encoder)?;
        self.chain_domain.encode(encoder)?;
        self.protocol_manifest_hash.encode(encoder)?;
        self.profile_domain.encode(encoder)?;
        self.checkpoint_zero_state_digest.encode(encoder)?;
        self.checkpoint_zero_id.encode(encoder)
    }
}

impl CanonicalDecode for GateAGenesisReceipt {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decoder.read_tag(GATE_A_GENESIS_RECEIPT_TAGS)?;
        Ok(Self {
            protocol_major: u32::decode(decoder)?,
            genesis_commitment: GenesisCommitment::decode(decoder)?,
            chain_domain: ChainDomain::decode(decoder)?,
            protocol_manifest_hash: ManifestHash::decode(decoder)?,
            profile_domain: ProfileDomain::decode(decoder)?,
            checkpoint_zero_state_digest: Hash32::decode(decoder)?,
            checkpoint_zero_id: CheckpointId::decode(decoder)?,
        })
    }
}

/// Checkpoint zero paired with its deterministic reduced Gate A receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializedGenesis {
    state: CheckpointState,
    receipt: GateAGenesisReceipt,
}

impl MaterializedGenesis {
    pub(crate) const fn new(state: CheckpointState, receipt: GateAGenesisReceipt) -> Self {
        Self { state, receipt }
    }

    /// Returns the materialized transparent checkpoint-zero state.
    #[must_use]
    pub const fn state(&self) -> &CheckpointState {
        &self.state
    }

    /// Returns the exact reduced Gate A genesis receipt.
    #[must_use]
    pub const fn receipt(&self) -> &GateAGenesisReceipt {
        &self.receipt
    }

    /// Consumes the wrapper and returns checkpoint zero with its receipt.
    #[must_use]
    pub fn into_parts(self) -> (CheckpointState, GateAGenesisReceipt) {
        (self.state, self.receipt)
    }
}

fn validate_checkpoint_zero(
    execution_profile: &ExecutionProfile,
    state: &CheckpointState,
) -> Result<(), KernelError> {
    if execution_profile.chain_domain() != state.chain_domain() {
        return Err(KernelError::ExecutionChainMismatch {
            execution: execution_profile.chain_domain(),
            state: state.chain_domain(),
        });
    }
    if execution_profile.profile_domain() != state.profile_domain() {
        return Err(KernelError::ExecutionProfileMismatch {
            execution: execution_profile.profile_domain(),
            state: state.profile_domain(),
        });
    }
    state.validate()?;
    if state.checkpoint_index() != 0
        || state.previous_checkpoint() != CheckpointId::ZERO
        || !state.nullifiers().is_empty()
        || !state.ordered_body_history().is_empty()
        || !state.bodies_in_checkpoint().is_empty()
        || !state.body_bindings_in_checkpoint().is_empty()
        || !state.accepted_intents().is_empty()
        || !state.accepted_effects_in_checkpoint().is_empty()
        || state.fee_pool() != 0
    {
        return Err(KernelError::GenesisReceiptRequiresCheckpointZero);
    }
    Ok(())
}

fn recompute_checkpoint_zero_commitments(
    state: &CheckpointState,
) -> Result<(Hash32, CheckpointId), KernelError> {
    let state_digest = state.state_digest()?;
    let checkpoint_id = state.derive_checkpoint_id_from_digest(state_digest)?;
    if checkpoint_id != state.checkpoint_id() {
        return Err(KernelError::InternalInvariant(
            "stored checkpoint-zero identifier differs from its recomputed identifier",
        ));
    }
    Ok((state_digest, checkpoint_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corrupted_stored_checkpoint_zero_id_rejects() {
        let mut state = CheckpointState::empty_for_test(
            ChainDomain::from_bytes([0x11; 32]),
            ProfileDomain::from_bytes([0x22; 32]),
        );
        state.validate().expect("empty checkpoint zero is valid");
        state.replace_checkpoint_id_for_test(
            state
                .derive_checkpoint_id()
                .expect("checkpoint identifier derives"),
        );
        recompute_checkpoint_zero_commitments(&state)
            .expect("the correctly stored identifier verifies");

        state.replace_checkpoint_id_for_test(CheckpointId::from_bytes([0x33; 32]));
        let error = recompute_checkpoint_zero_commitments(&state)
            .expect_err("a corrupted stored identifier must reject");
        assert!(matches!(&error, KernelError::InternalInvariant(_)));
        assert_eq!(error.code(), "kernel.internal_invariant");
    }
}
