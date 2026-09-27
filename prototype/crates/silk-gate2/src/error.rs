//! Stable Gate 2 rejection and structural errors.

use thiserror::Error;

/// Deterministic transaction rejection codes.
///
/// Values 1 through 25 retain their predecessor meanings. Gate 2 appends
/// values 26 through 52 without reordering an existing value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum RejectCode {
    /// Intent already accepted.
    DuplicateIntent = 1,
    /// Wrong chain domain.
    WrongChain = 2,
    /// Wrong profile domain.
    WrongProfile = 3,
    /// Wrong base checkpoint or anchor epoch.
    WrongCheckpoint = 4,
    /// Empty input vector.
    EmptyInputs = 5,
    /// Input vector above the safe bound.
    TooManyInputs = 6,
    /// Output vector above the safe bound.
    TooManyOutputs = 7,
    /// Recovery vectors do not match outputs.
    RecoveryVectorMismatch = 8,
    /// Duplicate input commitment.
    InternalDuplicateInput = 9,
    /// Duplicate input nullifier.
    InternalDuplicateNullifier = 10,
    /// Duplicate output commitment.
    InternalDuplicateOutput = 11,
    /// Input opening or exact base opening mismatch.
    WitnessCommitmentMismatch = 12,
    /// Input is absent from the base checkpoint.
    InputNotCheckpointed = 13,
    /// Transparent authorization marker/role is invalid.
    InvalidTransparentWitness = 14,
    /// Nullifier does not match the input opening.
    NullifierMismatch = 15,
    /// Nullifier was spent before this interval.
    AlreadySpent = 16,
    /// Earlier interval effect consumed the nullifier.
    ConflictLost = 17,
    /// Output opening does not match its commitment.
    OutputCommitmentMismatch = 18,
    /// Output commitment exists in history.
    CommitmentAlreadyExists = 19,
    /// Earlier interval output used this commitment.
    CommitmentConflict = 20,
    /// Recovery record names another output.
    RecoveryCommitmentMismatch = 21,
    /// Recovery hash does not match record bytes.
    RecoveryHashMismatch = 22,
    /// Checked value arithmetic overflowed.
    ValueOverflow = 23,
    /// Native value conservation failed.
    ConservationFailure = 24,
    /// Temporary fee-pool arithmetic overflowed.
    FeePoolOverflow = 25,
    /// Wrong manifest hash.
    WrongManifest = 26,
    /// Wrong policy-phase root.
    WrongPolicyPhaseRoot = 27,
    /// Envelope expired at the inclusion checkpoint.
    Expired = 28,
    /// Transfer or migration destination suite is inactive.
    InactiveSuite = 29,
    /// Migration relation is inactive.
    InactiveMigrationRelation = 30,
    /// Matching retained legacy exit is absent.
    MissingLegacyExit = 31,
    /// Note type, output role, or suite matrix is invalid.
    InvalidNoteTypeTransition = 32,
    /// User envelope attempted reserved reward creation.
    RewardOutputReserved = 33,
    /// Mandate input/output/action-evidence shape is invalid.
    MandateTransitionShape = 34,
    /// Mandate authorization role is wrong.
    MandateAuthorization = 35,
    /// Mandate scope proof/control is denied.
    MandateScopeDenied = 36,
    /// Mandate payment exceeds its per-action limit.
    MandatePaymentLimit = 37,
    /// Mandate successor/exhaust shape is invalid.
    MandateSuccessorInvalid = 38,
    /// Stable mandate authority changed.
    MandateAuthorityChanged = 39,
    /// Mandate policy widened.
    MandatePolicyWidened = 40,
    /// Mandate temporal/action counter transition is invalid.
    MandateCounterInvalid = 41,
    /// Initial-profile delegation is disabled.
    DelegationDisabled = 42,
    /// Reclaim occurred before strict expiry.
    MandateNotExpired = 43,
    /// Principal return is invalid.
    MandateReturnInvalid = 44,
    /// Only serial-window frequency is supported.
    FrequencyModeUnsupported = 45,
    /// Migration input is not VALUE.
    MigrationValueOnly = 46,
    /// Migration suite relationship is invalid.
    MigrationSuiteMismatch = 47,
    /// Migration output role/type is invalid.
    MigrationOutputRole = 48,
    /// Accepted fee total for one body exceeds profile cap.
    BodyFeeLimit = 49,
    /// Recovery kind does not match output type/role.
    RecoveryKindMismatch = 50,
    /// Selected policy branch is disabled in the current phase.
    PolicyBranchDisabled = 51,
    /// Accepted effect would exceed finite Gate 2 state bounds.
    StateLimitExceeded = 52,
}

impl RejectCode {
    /// Numeric ABI value.
    #[must_use]
    pub const fn numeric(self) -> u16 {
        self as u16
    }

    /// Stable language-neutral text code.
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
            Self::WrongManifest => "kernel.wrong_manifest",
            Self::WrongPolicyPhaseRoot => "kernel.wrong_policy_phase_root",
            Self::Expired => "kernel.expired",
            Self::InactiveSuite => "kernel.inactive_suite",
            Self::InactiveMigrationRelation => "kernel.inactive_migration_relation",
            Self::MissingLegacyExit => "kernel.missing_legacy_exit",
            Self::InvalidNoteTypeTransition => "kernel.invalid_note_type_transition",
            Self::RewardOutputReserved => "kernel.reward_output_reserved",
            Self::MandateTransitionShape => "kernel.mandate_transition_shape",
            Self::MandateAuthorization => "kernel.mandate_authorization",
            Self::MandateScopeDenied => "kernel.mandate_scope_denied",
            Self::MandatePaymentLimit => "kernel.mandate_payment_limit",
            Self::MandateSuccessorInvalid => "kernel.mandate_successor_invalid",
            Self::MandateAuthorityChanged => "kernel.mandate_authority_changed",
            Self::MandatePolicyWidened => "kernel.mandate_policy_widened",
            Self::MandateCounterInvalid => "kernel.mandate_counter_invalid",
            Self::DelegationDisabled => "kernel.delegation_disabled",
            Self::MandateNotExpired => "kernel.mandate_not_expired",
            Self::MandateReturnInvalid => "kernel.mandate_return_invalid",
            Self::FrequencyModeUnsupported => "kernel.frequency_mode_unsupported",
            Self::MigrationValueOnly => "kernel.migration_value_only",
            Self::MigrationSuiteMismatch => "kernel.migration_suite_mismatch",
            Self::MigrationOutputRole => "kernel.migration_output_role",
            Self::BodyFeeLimit => "kernel.body_fee_limit",
            Self::RecoveryKindMismatch => "kernel.recovery_kind_mismatch",
            Self::PolicyBranchDisabled => "kernel.policy_branch_disabled",
            Self::StateLimitExceeded => "kernel.state_limit_exceeded",
        }
    }
}

impl TryFrom<u16> for RejectCode {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        const ALL: [RejectCode; 52] = [
            RejectCode::DuplicateIntent,
            RejectCode::WrongChain,
            RejectCode::WrongProfile,
            RejectCode::WrongCheckpoint,
            RejectCode::EmptyInputs,
            RejectCode::TooManyInputs,
            RejectCode::TooManyOutputs,
            RejectCode::RecoveryVectorMismatch,
            RejectCode::InternalDuplicateInput,
            RejectCode::InternalDuplicateNullifier,
            RejectCode::InternalDuplicateOutput,
            RejectCode::WitnessCommitmentMismatch,
            RejectCode::InputNotCheckpointed,
            RejectCode::InvalidTransparentWitness,
            RejectCode::NullifierMismatch,
            RejectCode::AlreadySpent,
            RejectCode::ConflictLost,
            RejectCode::OutputCommitmentMismatch,
            RejectCode::CommitmentAlreadyExists,
            RejectCode::CommitmentConflict,
            RejectCode::RecoveryCommitmentMismatch,
            RejectCode::RecoveryHashMismatch,
            RejectCode::ValueOverflow,
            RejectCode::ConservationFailure,
            RejectCode::FeePoolOverflow,
            RejectCode::WrongManifest,
            RejectCode::WrongPolicyPhaseRoot,
            RejectCode::Expired,
            RejectCode::InactiveSuite,
            RejectCode::InactiveMigrationRelation,
            RejectCode::MissingLegacyExit,
            RejectCode::InvalidNoteTypeTransition,
            RejectCode::RewardOutputReserved,
            RejectCode::MandateTransitionShape,
            RejectCode::MandateAuthorization,
            RejectCode::MandateScopeDenied,
            RejectCode::MandatePaymentLimit,
            RejectCode::MandateSuccessorInvalid,
            RejectCode::MandateAuthorityChanged,
            RejectCode::MandatePolicyWidened,
            RejectCode::MandateCounterInvalid,
            RejectCode::DelegationDisabled,
            RejectCode::MandateNotExpired,
            RejectCode::MandateReturnInvalid,
            RejectCode::FrequencyModeUnsupported,
            RejectCode::MigrationValueOnly,
            RejectCode::MigrationSuiteMismatch,
            RejectCode::MigrationOutputRole,
            RejectCode::BodyFeeLimit,
            RejectCode::RecoveryKindMismatch,
            RejectCode::PolicyBranchDisabled,
            RejectCode::StateLimitExceeded,
        ];
        if value == 0 || usize::from(value) > ALL.len() {
            return Err(Error::code("codec.unknown_reject_code"));
        }
        Ok(ALL[usize::from(value - 1)])
    }
}

/// Structural validation, canonical-codec, profile, fence, or host failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("{code}")]
pub struct Error {
    code: &'static str,
}

impl Error {
    /// Constructs a stable coded failure.
    #[must_use]
    pub const fn code(code: &'static str) -> Self {
        Self { code }
    }

    /// Returns the language-neutral code.
    #[must_use]
    pub const fn as_code(&self) -> &'static str {
        self.code
    }
}
