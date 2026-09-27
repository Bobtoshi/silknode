//! Statically bound transparent execution host.

use silk_profile::ExecutionProfile;
use silk_types::CheckpointId;

use crate::{
    CheckpointState, CodecVerificationError, GateAGenesisReceipt, GenesisAllocationTemplate,
    KernelError, MaterializedGenesis, NativeIntervalResult, OrderedBody, Transition,
    UnverifiedCheckpointState, UnverifiedNativeIntervalResult, UnverifiedTransition,
    transparent_checkpoint_descriptor, transparent_native_kernel_descriptor,
};

/// An opaque checkpoint-identity capability derived from already trusted state.
///
/// Decoded checkpoint bytes and bare [`CheckpointId`] values cannot create this
/// capability. Callers must retain or deterministically reconstruct a trusted
/// [`CheckpointState`] before they can authorize promotion of decoded state.
/// Cloning or copying a pin preserves that existing authority; it does not
/// enlarge it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustedCheckpointPin {
    checkpoint_id: CheckpointId,
}

impl TrustedCheckpointPin {
    /// Derives a checkpoint pin from state the caller already trusts.
    #[must_use]
    pub const fn from_trusted_state(state: &CheckpointState) -> Self {
        Self {
            checkpoint_id: state.checkpoint_id(),
        }
    }

    /// Returns the checkpoint identifier carried by this capability.
    #[must_use]
    pub const fn checkpoint_id(self) -> CheckpointId {
        self.checkpoint_id
    }
}

/// The sole public host for transparent genesis and checkpoint execution.
///
/// Construction checks both semantic module identities and ABI versions from a
/// sealed [`ExecutionProfile`] against the exact descriptors compiled into this
/// crate. The check is an implementation-compatibility assertion, not proof of
/// which source or binary artifact is executing.
///
/// Direct state construction is intentionally unavailable:
///
/// ```compile_fail
/// use silk_kernel::{CheckpointState, GenesisAllocationTemplate};
/// use silk_profile::ExecutionProfile;
///
/// fn bypass(profile: &ExecutionProfile, template: GenesisAllocationTemplate) {
///     let _ = CheckpointState::genesis(profile, template);
/// }
/// ```
///
/// The raw checkpoint function is not part of the public API:
///
/// ```compile_fail
/// use silk_kernel::{CheckpointState, OrderedBody};
/// use silk_profile::ExecutionProfile;
///
/// fn bypass(profile: &ExecutionProfile, state: &CheckpointState, bodies: &[OrderedBody]) {
///     let _ = silk_kernel::apply_and_seal(profile, state, bodies);
/// }
/// ```
///
/// The sealed host cannot be assembled without its checks:
///
/// ```compile_fail
/// use silk_kernel::TransparentExecutionHost;
/// use silk_profile::ExecutionProfile;
///
/// fn bypass(profile: ExecutionProfile) {
///     let _ = TransparentExecutionHost { execution_profile: profile };
/// }
/// ```
///
/// Raw note vectors are not a genesis input:
///
/// ```compile_fail
/// use silk_kernel::{NativeNote, TransparentExecutionHost};
///
/// fn raw_genesis(host: &TransparentExecutionHost, notes: Vec<NativeNote>) {
///     let _ = host.genesis(notes);
/// }
/// ```
///
/// Internal state views and effect builders are not caller capabilities:
///
/// ```compile_fail
/// use silk_kernel::{BaseNativeStateView, NativeEffectBuilder};
///
/// fn bypass() {
///     let _ = NativeEffectBuilder::new();
/// }
/// ```
#[derive(Debug)]
pub struct TransparentExecutionHost {
    execution_profile: ExecutionProfile,
}

impl TransparentExecutionHost {
    /// Binds an activated profile to both transparent execution modules.
    ///
    /// Native-kernel identity has fixed precedence over checkpoint identity.
    /// Unknown IDs and ABI versions always fail; this host has no fallback or
    /// dynamic implementation registry.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError`] if a compiled descriptor cannot be reconstructed
    /// or either exact semantic identity and ABI tuple differs from the profile.
    pub fn bind(execution_profile: ExecutionProfile) -> Result<Self, KernelError> {
        let native_kernel = transparent_native_kernel_descriptor().map_err(|_| {
            KernelError::InternalInvariant("compiled native-kernel descriptor is invalid")
        })?;
        let actual_native_module = execution_profile.native_kernel_module_id();
        let actual_native_abi = execution_profile.native_kernel_abi_version();
        if actual_native_module != native_kernel.module_id()
            || actual_native_abi != native_kernel.abi_version()
        {
            return Err(KernelError::NativeKernelBindingMismatch {
                expected_module: native_kernel.module_id(),
                actual_module: actual_native_module,
                expected_abi: native_kernel.abi_version(),
                actual_abi: actual_native_abi,
            });
        }

        let checkpoint = transparent_checkpoint_descriptor().map_err(|_| {
            KernelError::InternalInvariant("compiled checkpoint descriptor is invalid")
        })?;
        let actual_checkpoint_module = execution_profile.checkpoint_module_id();
        let actual_checkpoint_abi = execution_profile.checkpoint_abi_version();
        if actual_checkpoint_module != checkpoint.module_id()
            || actual_checkpoint_abi != checkpoint.abi_version()
        {
            return Err(KernelError::CheckpointBindingMismatch {
                expected_module: checkpoint.module_id(),
                actual_module: actual_checkpoint_module,
                expected_abi: checkpoint.abi_version(),
                actual_abi: actual_checkpoint_abi,
            });
        }

        Ok(Self { execution_profile })
    }

    /// Returns the exact sealed profile owned by this host.
    #[must_use]
    pub const fn execution_profile(&self) -> &ExecutionProfile {
        &self.execution_profile
    }

    /// Materializes transparent checkpoint zero and its reduced Gate A receipt.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError`] if template binding, materialization, hashing, or
    /// a derived state invariant fails.
    pub fn genesis(
        &self,
        allocation_template: GenesisAllocationTemplate,
    ) -> Result<MaterializedGenesis, KernelError> {
        let state = CheckpointState::genesis(&self.execution_profile, allocation_template)?;
        let receipt = GateAGenesisReceipt::materialize(&self.execution_profile, &state)?;
        Ok(MaterializedGenesis::new(state, receipt))
    }

    /// Applies already ordered bodies and seals one immutable next checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError`] for a structural host, state, body, resource, or
    /// hashing failure. Transaction failures remain typed [`crate::Decision`]
    /// outcomes in the returned transition.
    pub fn apply_and_seal(
        &self,
        base: &CheckpointState,
        ordered_bodies: &[OrderedBody],
    ) -> Result<Transition, KernelError> {
        crate::interpreter::apply_and_seal(&self.execution_profile, base, ordered_bodies)
    }

    /// Promotes a decoded checkpoint only after context, invariants, identity,
    /// and a checkpoint pin derived from already trusted state all match.
    ///
    /// The pin cannot be created from a bare identifier or from the decoded
    /// candidate itself.
    ///
    /// # Errors
    ///
    /// Returns the first host-context, state-invariant, recomputed-identity, or
    /// trusted-pin mismatch.
    pub fn verify_checkpoint_state(
        &self,
        candidate: UnverifiedCheckpointState,
        trusted_pin: TrustedCheckpointPin,
    ) -> Result<CheckpointState, CodecVerificationError> {
        self.verify_checkpoint_candidate(candidate, trusted_pin)
    }

    /// Promotes a decoded native result only by replaying trusted execution inputs.
    ///
    /// # Errors
    ///
    /// Returns a structural replay/state failure, unknown decoded rejection
    /// code, or exact result mismatch.
    pub fn verify_native_interval_result(
        &self,
        candidate: UnverifiedNativeIntervalResult,
        trusted_base: &CheckpointState,
        ordered_bodies: &[OrderedBody],
    ) -> Result<NativeIntervalResult, CodecVerificationError> {
        let expected = crate::interpreter::evaluate_native_interval(
            &self.execution_profile,
            trusted_base,
            ordered_bodies,
        )?;
        let actual = candidate.into_candidate(self.execution_profile.chain_domain())?;
        if actual != expected {
            return Err(CodecVerificationError::NativeIntervalResultMismatch);
        }
        Ok(expected)
    }

    /// Promotes a decoded transition only by replaying a trusted base and body order.
    ///
    /// Both decoded checkpoints must first satisfy their recomputed identities
    /// and the independently derived previous/next pins.  Successful promotion
    /// returns the freshly replayed transition, never rewrapped candidate data.
    ///
    /// # Errors
    ///
    /// Returns the first structural replay, checkpoint verification, unknown
    /// rejection-code, or exact candidate mismatch.
    pub fn verify_transition(
        &self,
        candidate: UnverifiedTransition,
        trusted_base: &CheckpointState,
        ordered_bodies: &[OrderedBody],
    ) -> Result<Transition, CodecVerificationError> {
        let expected = self.apply_and_seal(trusted_base, ordered_bodies)?;
        let (previous, next, decisions) = candidate.into_parts();
        let previous = self.verify_checkpoint_candidate(
            previous,
            TrustedCheckpointPin::from_trusted_state(trusted_base),
        )?;
        let next = self.verify_checkpoint_candidate(
            next,
            TrustedCheckpointPin::from_trusted_state(expected.next()),
        )?;
        let decisions = crate::codec::decisions_from_unverified(decisions)?;
        if previous != *trusted_base
            || next != *expected.next()
            || decisions != expected.decisions()
        {
            return Err(CodecVerificationError::TransitionMismatch);
        }
        Ok(expected)
    }

    fn verify_checkpoint_candidate(
        &self,
        candidate: UnverifiedCheckpointState,
        trusted_pin: TrustedCheckpointPin,
    ) -> Result<CheckpointState, CodecVerificationError> {
        let candidate = candidate.into_candidate();
        if self.execution_profile.chain_domain() != candidate.chain_domain() {
            return Err(KernelError::ExecutionChainMismatch {
                execution: self.execution_profile.chain_domain(),
                state: candidate.chain_domain(),
            }
            .into());
        }
        if self.execution_profile.profile_domain() != candidate.profile_domain() {
            return Err(KernelError::ExecutionProfileMismatch {
                execution: self.execution_profile.profile_domain(),
                state: candidate.profile_domain(),
            }
            .into());
        }
        candidate.validate()?;
        let stored = candidate.checkpoint_id();
        let derived = candidate.derive_checkpoint_id()?;
        if stored != derived {
            return Err(CodecVerificationError::CheckpointIdentityMismatch { stored, derived });
        }
        if stored != trusted_pin.checkpoint_id() {
            return Err(CodecVerificationError::CheckpointPinMismatch {
                expected: trusted_pin.checkpoint_id(),
                actual: stored,
            });
        }
        Ok(candidate)
    }
}
