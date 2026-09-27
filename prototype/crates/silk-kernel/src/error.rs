//! Stable transaction rejection codes and structural kernel failures.

use silk_types::{
    ChainDomain, CheckpointId, GenesisAllocationTemplateHash, ModuleId, ProfileDomain,
};
use thiserror::Error;

use crate::genesis::GateAGenesisReceiptField;

/// A deterministic transaction-level rejection.
///
/// Numeric discriminants and string codes are consensus fixtures. New variants
/// must be appended; existing values must never be reordered or repurposed.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[repr(u16)]
pub enum RejectCode {
    /// The intent was already accepted in this checkpoint lineage or interval.
    #[error("transaction intent was already accepted")]
    DuplicateIntent = 1,
    /// The transaction names another immutable chain domain.
    #[error("transaction is bound to another chain domain")]
    WrongChain = 2,
    /// The transaction names another active protocol profile.
    #[error("transaction is bound to another protocol profile")]
    WrongProfile = 3,
    /// The transaction is not anchored to the exact base checkpoint.
    #[error("transaction is not anchored to the base checkpoint")]
    WrongCheckpoint = 4,
    /// A user transaction did not contain an input.
    #[error("transaction has no input")]
    EmptyInputs = 5,
    /// The input vector exceeds the Gate A resource bound.
    #[error("transaction has too many inputs")]
    TooManyInputs = 6,
    /// The output vector exceeds the Gate A resource bound.
    #[error("transaction has too many outputs")]
    TooManyOutputs = 7,
    /// Output, recovery-hash, and recovery-record vector lengths differ.
    #[error("recovery vectors do not match the output vector")]
    RecoveryVectorMismatch = 8,
    /// An input commitment occurs more than once in the transaction.
    #[error("transaction repeats an input commitment")]
    InternalDuplicateInput = 9,
    /// A nullifier occurs more than once in the transaction.
    #[error("transaction repeats a nullifier")]
    InternalDuplicateNullifier = 10,
    /// An output commitment occurs more than once in the transaction.
    #[error("transaction repeats an output commitment")]
    InternalDuplicateOutput = 11,
    /// An input opening does not derive the claimed commitment.
    #[error("transparent input witness does not open its commitment")]
    WitnessCommitmentMismatch = 12,
    /// An input is absent from the exact base checkpoint's live-note set.
    #[error("input is not live in the base checkpoint")]
    InputNotCheckpointed = 13,
    /// The transparent test authorization marker is false.
    #[error("transparent witness authorization marker is false")]
    InvalidTransparentWitness = 14,
    /// The public nullifier is not the one derived from the input opening.
    #[error("input nullifier does not match its transparent opening")]
    NullifierMismatch = 15,
    /// The nullifier was consumed before the base checkpoint.
    #[error("nullifier was already spent before this interval")]
    AlreadySpent = 16,
    /// An earlier canonical transaction in this interval consumed the input.
    #[error("transaction lost a same-interval nullifier conflict")]
    ConflictLost = 17,
    /// An output opening does not derive the claimed commitment.
    #[error("transparent output does not open its commitment")]
    OutputCommitmentMismatch = 18,
    /// The commitment occurred at any prior point in checkpoint history.
    #[error("output commitment already exists in checkpoint history")]
    CommitmentAlreadyExists = 19,
    /// An earlier canonical transaction in this interval created the commitment.
    #[error("output commitment conflicts with an earlier interval output")]
    CommitmentConflict = 20,
    /// A recovery record is not paired with its output slot's commitment.
    #[error("recovery record is paired with the wrong output commitment")]
    RecoveryCommitmentMismatch = 21,
    /// A recovery record does not hash to the transaction's declared value.
    #[error("recovery record hash does not match the declared hash")]
    RecoveryHashMismatch = 22,
    /// A checked value sum overflowed its consensus accumulator.
    #[error("native value accumulator overflowed")]
    ValueOverflow = 23,
    /// Input value does not exactly equal output value plus the public fee.
    #[error("native value conservation failed")]
    ConservationFailure = 24,
    /// Adding the accepted fee would overflow the checkpoint fee pool.
    #[error("checkpoint fee pool overflowed")]
    FeePoolOverflow = 25,
}

impl RejectCode {
    /// Returns the frozen numeric code used by binary differential fixtures.
    #[must_use]
    pub const fn numeric(self) -> u16 {
        self as u16
    }

    /// Returns the frozen language-neutral text code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::DuplicateIntent => "kernel.duplicate_intent",
            Self::WrongChain => "kernel.wrong_chain",
            Self::WrongProfile => "kernel.wrong_profile",
            Self::WrongCheckpoint => "kernel.wrong_checkpoint",
            Self::EmptyInputs => "kernel.empty_inputs",
            Self::TooManyInputs => "kernel.too_many_inputs",
            Self::TooManyOutputs => "kernel.too_many_outputs",
            Self::RecoveryVectorMismatch => "kernel.recovery_vector_mismatch",
            Self::InternalDuplicateInput => "kernel.internal_duplicate_input",
            Self::InternalDuplicateNullifier => "kernel.internal_duplicate_nullifier",
            Self::InternalDuplicateOutput => "kernel.internal_duplicate_output",
            Self::WitnessCommitmentMismatch => "kernel.witness_commitment_mismatch",
            Self::InputNotCheckpointed => "kernel.input_not_checkpointed",
            Self::InvalidTransparentWitness => "kernel.invalid_transparent_witness",
            Self::NullifierMismatch => "kernel.nullifier_mismatch",
            Self::AlreadySpent => "kernel.already_spent",
            Self::ConflictLost => "kernel.conflict_lost",
            Self::OutputCommitmentMismatch => "kernel.output_commitment_mismatch",
            Self::CommitmentAlreadyExists => "kernel.commitment_already_exists",
            Self::CommitmentConflict => "kernel.commitment_conflict",
            Self::RecoveryCommitmentMismatch => "kernel.recovery_commitment_mismatch",
            Self::RecoveryHashMismatch => "kernel.recovery_hash_mismatch",
            Self::ValueOverflow => "kernel.value_overflow",
            Self::ConservationFailure => "kernel.conservation_failure",
            Self::FeePoolOverflow => "kernel.fee_pool_overflow",
        }
    }
}

/// A numeric transaction-rejection value that is not assigned by this ABI.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("unknown transaction rejection code {numeric}")]
pub struct UnknownRejectCode {
    numeric: u16,
}

impl UnknownRejectCode {
    /// Returns the unassigned numeric value.
    #[must_use]
    pub const fn numeric(self) -> u16 {
        self.numeric
    }
}

impl TryFrom<u16> for RejectCode {
    type Error = UnknownRejectCode;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::DuplicateIntent),
            2 => Ok(Self::WrongChain),
            3 => Ok(Self::WrongProfile),
            4 => Ok(Self::WrongCheckpoint),
            5 => Ok(Self::EmptyInputs),
            6 => Ok(Self::TooManyInputs),
            7 => Ok(Self::TooManyOutputs),
            8 => Ok(Self::RecoveryVectorMismatch),
            9 => Ok(Self::InternalDuplicateInput),
            10 => Ok(Self::InternalDuplicateNullifier),
            11 => Ok(Self::InternalDuplicateOutput),
            12 => Ok(Self::WitnessCommitmentMismatch),
            13 => Ok(Self::InputNotCheckpointed),
            14 => Ok(Self::InvalidTransparentWitness),
            15 => Ok(Self::NullifierMismatch),
            16 => Ok(Self::AlreadySpent),
            17 => Ok(Self::ConflictLost),
            18 => Ok(Self::OutputCommitmentMismatch),
            19 => Ok(Self::CommitmentAlreadyExists),
            20 => Ok(Self::CommitmentConflict),
            21 => Ok(Self::RecoveryCommitmentMismatch),
            22 => Ok(Self::RecoveryHashMismatch),
            23 => Ok(Self::ValueOverflow),
            24 => Ok(Self::ConservationFailure),
            25 => Ok(Self::FeePoolOverflow),
            numeric => Err(UnknownRejectCode { numeric }),
        }
    }
}

/// Failure while promoting a canonically decoded kernel value into trusted runtime state.
#[derive(Debug, Error)]
pub enum CodecVerificationError {
    /// The decoded object carried an unassigned transaction rejection code.
    #[error(transparent)]
    UnknownRejectCode(#[from] UnknownRejectCode),
    /// The decoded checkpoint ID differs from the ID recomputed from its state.
    #[error("decoded checkpoint ID {stored} does not match recomputed ID {derived}")]
    CheckpointIdentityMismatch {
        /// Identifier carried by the decoded checkpoint.
        stored: CheckpointId,
        /// Identifier recomputed from the validated state projection.
        derived: CheckpointId,
    },
    /// The decoded checkpoint does not match the independently supplied trusted pin.
    #[error("decoded checkpoint ID {actual} does not match expected pin {expected}")]
    CheckpointPinMismatch {
        /// Independently trusted checkpoint identifier.
        expected: CheckpointId,
        /// Identifier carried by the decoded and internally validated checkpoint.
        actual: CheckpointId,
    },
    /// A decoded native result differs from deterministic execution over trusted inputs.
    #[error("decoded native interval result differs from deterministic replay")]
    NativeIntervalResultMismatch,
    /// A decoded transition differs from deterministic execution over trusted inputs.
    #[error("decoded transition differs from deterministic replay")]
    TransitionMismatch,
    /// Deterministic replay or decoded-state validation failed structurally.
    #[error(transparent)]
    Kernel(#[from] KernelError),
}

impl CodecVerificationError {
    /// Returns the stable language-neutral promotion failure code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnknownRejectCode(_) => "codec.unknown_reject_code",
            Self::CheckpointIdentityMismatch { .. } => "codec.checkpoint_identity_mismatch",
            Self::CheckpointPinMismatch { .. } => "codec.checkpoint_pin_mismatch",
            Self::NativeIntervalResultMismatch => "codec.native_interval_result_mismatch",
            Self::TransitionMismatch => "codec.transition_mismatch",
            Self::Kernel(error) => error.code(),
        }
    }
}

/// A violated invariant in a materialized checkpoint state.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum StateInvariantError {
    /// A live-note map key is not the commitment of its stored opening.
    #[error("live-note key does not match the stored opening")]
    LiveCommitmentMismatch,
    /// A live commitment is absent from append-only commitment history.
    #[error("live commitment is absent from commitment history")]
    LiveCommitmentMissingFromHistory,
    /// A live note already has a nullifier in the spent set.
    #[error("live note has an already-spent nullifier")]
    LiveNoteAlreadySpent,
    /// Two recovery-history entries name the same output commitment.
    #[error("recovery history repeats an output commitment")]
    DuplicateRecoveryCommitment,
    /// Recovery history and append-only commitment history contain different keys.
    #[error("recovery history does not exactly cover commitment history")]
    RecoveryHistoryMismatch,
    /// The accepted-intent sequence for this checkpoint contains a duplicate.
    #[error("checkpoint accepted-intent sequence contains a duplicate")]
    DuplicateCheckpointIntent,
    /// A checkpoint-local accepted intent is absent from global intent history.
    #[error("checkpoint accepted intent is absent from intent history")]
    AcceptedIntentMissingFromHistory,
    /// A materialized body identifier occurs more than once in the lineage.
    #[error("ordered body history contains a duplicate")]
    DuplicateOrderedBody,
    /// Checkpoint-local bodies are not the exact suffix of body history.
    #[error("checkpoint body list is not the suffix of ordered body history")]
    CheckpointBodyHistoryMismatch,
    /// Checkpoint body IDs and canonical content bindings are not one-to-one.
    #[error("checkpoint body IDs and content bindings have different lengths")]
    CheckpointBodyBindingMismatch,
    /// Summing live notes and the fee pool overflowed the native accumulator.
    #[error("state supply accumulator overflowed")]
    SupplyOverflow,
    /// Live notes plus the fee pool do not equal cumulative native issuance.
    #[error("materialized native supply does not equal issuance")]
    SupplyMismatch,
}

/// A structural failure that invalidates genesis, the base state, or the checkpoint call.
#[derive(Debug, Error)]
pub enum KernelError {
    /// The activated native-kernel descriptor is not the exact implementation compiled here.
    #[error(
        "execution profile native kernel {actual_module} ABI {actual_abi} does not match compiled native kernel {expected_module} ABI {expected_abi}"
    )]
    NativeKernelBindingMismatch {
        /// Exact semantic module implemented by this transparent host.
        expected_module: ModuleId,
        /// Semantic module requested by the sealed execution profile.
        actual_module: ModuleId,
        /// Exact host ABI implemented by this transparent host.
        expected_abi: u16,
        /// Host ABI requested by the sealed execution profile.
        actual_abi: u16,
    },
    /// The activated checkpoint descriptor is not the exact implementation compiled here.
    #[error(
        "execution profile checkpoint {actual_module} ABI {actual_abi} does not match compiled checkpoint {expected_module} ABI {expected_abi}"
    )]
    CheckpointBindingMismatch {
        /// Exact semantic module implemented by this transparent host.
        expected_module: ModuleId,
        /// Semantic module requested by the sealed execution profile.
        actual_module: ModuleId,
        /// Exact host ABI implemented by this transparent host.
        expected_abi: u16,
        /// Host ABI requested by the sealed execution profile.
        actual_abi: u16,
    },
    /// The explicit execution token belongs to another immutable chain.
    #[error("execution chain {execution} does not match state chain {state}")]
    ExecutionChainMismatch {
        /// Chain authorized by the sealed execution token.
        execution: ChainDomain,
        /// Chain committed by the supplied checkpoint state.
        state: ChainDomain,
    },
    /// The explicit execution token belongs to another consensus profile.
    #[error("execution profile {execution} does not match state profile {state}")]
    ExecutionProfileMismatch {
        /// Profile authorized by the sealed execution token.
        execution: ProfileDomain,
        /// Profile committed by the supplied checkpoint state.
        state: ProfileDomain,
    },
    /// The supplied transparent template differs from the trusted genesis input.
    #[error("genesis allocation template {actual} does not match trusted template {expected}")]
    GenesisAllocationTemplateMismatch {
        /// Template hash carried by the sealed execution profile.
        expected: GenesisAllocationTemplateHash,
        /// Hash derived from the exact supplied canonical template.
        actual: GenesisAllocationTemplateHash,
    },
    /// Genesis contains the same note commitment more than once.
    #[error("genesis contains a duplicate note commitment")]
    DuplicateGenesisCommitment,
    /// Genesis issuance overflowed the `u128` native counter.
    #[error("genesis native issuance overflowed")]
    GenesisIssuanceOverflow,
    /// A receipt was requested from a state other than exact checkpoint zero.
    #[error("Gate A genesis receipt requires an exact checkpoint-zero state")]
    GenesisReceiptRequiresCheckpointZero,
    /// A supplied receipt field differed from its recomputed value.
    #[error("Gate A genesis receipt field {field:?} does not match recomputed value")]
    GenesisReceiptMismatch {
        /// First mismatching field in fixed receipt order.
        field: GateAGenesisReceiptField,
    },
    /// A checkpoint call did not contain a newly ordered body.
    #[error("checkpoint requires at least one ordered body")]
    EmptyCheckpoint,
    /// A checkpoint exceeds the bounded ordered-body count.
    #[error("checkpoint body count {actual} exceeds limit {max}")]
    TooManyOrderedBodies {
        /// Supplied body count.
        actual: usize,
        /// Consensus resource limit.
        max: usize,
    },
    /// A body identifier was already materialized in this lineage or interval.
    #[error("ordered body identifier is duplicated")]
    DuplicateOrderedBody,
    /// Transactions in one body are not already in canonical intent/instance order.
    #[error("ordered body contains non-canonical transaction order")]
    NonCanonicalBodyTransactions,
    /// A checkpoint batch exceeds its transaction resource limit.
    #[error("checkpoint transaction count {actual} exceeds limit {max}")]
    TooManyTransactions {
        /// Supplied transaction count.
        actual: usize,
        /// Consensus resource limit.
        max: usize,
    },
    /// The checkpoint index cannot advance without overflowing `u64`.
    #[error("checkpoint index overflowed")]
    CheckpointIndexOverflow,
    /// The supplied base or newly derived state violates a structural invariant.
    #[error(transparent)]
    InvalidState(#[from] StateInvariantError),
    /// Canonical encoding required for an identifier failed.
    #[error(transparent)]
    CanonicalEncoding(#[from] silk_types::EncodeError),
    /// A domain-separated identifier could not be constructed.
    #[error(transparent)]
    DomainHash(#[from] silk_types::DomainHashError),
    /// A post-validation mutation contradicted the validated effect.
    #[error("internal invariant failed: {0}")]
    InternalInvariant(&'static str),
}

impl KernelError {
    /// Returns the stable language-neutral code for a structural kernel failure.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NativeKernelBindingMismatch { .. } => "kernel.native_kernel_binding_mismatch",
            Self::CheckpointBindingMismatch { .. } => "kernel.checkpoint_binding_mismatch",
            Self::ExecutionChainMismatch { .. } => "kernel.execution_chain_mismatch",
            Self::ExecutionProfileMismatch { .. } => "kernel.execution_profile_mismatch",
            Self::GenesisAllocationTemplateMismatch { .. } => {
                "kernel.genesis_allocation_template_mismatch"
            }
            Self::DuplicateGenesisCommitment => "kernel.duplicate_genesis_commitment",
            Self::GenesisIssuanceOverflow => "kernel.genesis_issuance_overflow",
            Self::GenesisReceiptRequiresCheckpointZero => {
                "kernel.genesis_receipt_requires_checkpoint_zero"
            }
            Self::GenesisReceiptMismatch { .. } => "kernel.genesis_receipt_mismatch",
            Self::EmptyCheckpoint => "kernel.empty_checkpoint",
            Self::TooManyOrderedBodies { .. } => "kernel.too_many_ordered_bodies",
            Self::DuplicateOrderedBody => "kernel.duplicate_ordered_body",
            Self::NonCanonicalBodyTransactions => "kernel.noncanonical_body_transactions",
            Self::TooManyTransactions { .. } => "kernel.too_many_transactions",
            Self::CheckpointIndexOverflow => "kernel.checkpoint_index_overflow",
            Self::InvalidState(_) => "kernel.invalid_state",
            Self::CanonicalEncoding(error) => error.code(),
            Self::DomainHash(error) => error.code(),
            Self::InternalInvariant(_) => "kernel.internal_invariant",
        }
    }
}
