//! Exact semantic descriptors for the transparent execution implementation.

use silk_profile::{ModuleDescriptor, ModuleType, ProfileError, StateDomain};
use silk_types::{Hash32, domain_hash};

const NATIVE_KERNEL_ABI_VERSION: u16 = 2;
const CHECKPOINT_ABI_VERSION: u16 = 3;

const NATIVE_KERNEL_SPEC_DOMAIN: &[u8] = b"Silk-Transparent-NativeKernel-Spec-v2";
const NATIVE_KERNEL_INTERFACE_DOMAIN: &[u8] = b"Silk-Transparent-NativeKernel-Interface-v2";
const NATIVE_KERNEL_PARAMETERS_DOMAIN: &[u8] = b"Silk-Transparent-NativeKernel-Parameters-v2";
const NATIVE_KERNEL_VECTORS_DOMAIN: &[u8] = b"Silk-Transparent-NativeKernel-Vectors-v2";
const CHECKPOINT_SPEC_DOMAIN: &[u8] = b"Silk-Transparent-Checkpoint-Spec-v3";
const CHECKPOINT_INTERFACE_DOMAIN: &[u8] = b"Silk-Transparent-Checkpoint-Interface-v3";
const CHECKPOINT_PARAMETERS_DOMAIN: &[u8] = b"Silk-Transparent-Checkpoint-Parameters-v3";
const CHECKPOINT_VECTORS_DOMAIN: &[u8] = b"Silk-Transparent-Checkpoint-Vectors-v3";

const NATIVE_KERNEL_SPEC: &[u8] =
    include_bytes!("../../../spec/transparent-execution-v2/native-kernel-spec.md");
const NATIVE_KERNEL_INTERFACE: &[u8] =
    include_bytes!("../../../spec/transparent-execution-v2/native-kernel-interface.json");
const NATIVE_KERNEL_PARAMETERS: &[u8] =
    include_bytes!("../../../spec/transparent-execution-v2/native-kernel-parameters.json");
const NATIVE_KERNEL_VECTORS: &[u8] =
    include_bytes!("../../../spec/transparent-execution-v2/native-kernel-vectors.json");
const CHECKPOINT_SPEC: &[u8] =
    include_bytes!("../../../spec/transparent-execution-v2/checkpoint-spec.md");
const CHECKPOINT_INTERFACE: &[u8] =
    include_bytes!("../../../spec/transparent-execution-v2/checkpoint-interface.json");
const CHECKPOINT_PARAMETERS: &[u8] =
    include_bytes!("../../../spec/transparent-execution-v2/checkpoint-parameters.json");
const CHECKPOINT_VECTORS: &[u8] =
    include_bytes!("../../../spec/transparent-execution-v2/checkpoint-vectors.json");

fn artifact_hash(domain: &'static [u8], bytes: &'static [u8]) -> Result<Hash32, ProfileError> {
    domain_hash(domain, &[bytes]).map_err(ProfileError::from)
}

/// Reconstructs the exact transparent native-kernel descriptor compiled here.
///
/// Every semantic root hashes one exact checked-in artifact under its own
/// nonempty domain. Ordered verified bodies are host ABI input rather than a
/// call to a specific ordering implementation, so this descriptor has no
/// module dependency.
///
/// # Errors
///
/// Returns [`ProfileError`] if a static artifact hash or descriptor cannot be
/// constructed. Such a failure is a build defect, never an untrusted-input
/// fallback condition.
pub fn transparent_native_kernel_descriptor() -> Result<ModuleDescriptor, ProfileError> {
    ModuleDescriptor::new(
        ModuleType::NativeKernel,
        NATIVE_KERNEL_ABI_VERSION,
        artifact_hash(NATIVE_KERNEL_SPEC_DOMAIN, NATIVE_KERNEL_SPEC)?,
        artifact_hash(NATIVE_KERNEL_INTERFACE_DOMAIN, NATIVE_KERNEL_INTERFACE)?,
        artifact_hash(NATIVE_KERNEL_VECTORS_DOMAIN, NATIVE_KERNEL_VECTORS)?,
        artifact_hash(NATIVE_KERNEL_PARAMETERS_DOMAIN, NATIVE_KERNEL_PARAMETERS)?,
        vec![],
        vec![
            StateDomain::CanonicalOrder,
            StateDomain::NoteCommitments,
            StateDomain::Nullifiers,
            StateDomain::RecoveryHistory,
            StateDomain::AcceptedEffects,
            StateDomain::NativeSupply,
            StateDomain::Checkpoints,
        ],
        vec![
            StateDomain::NoteCommitments,
            StateDomain::Nullifiers,
            StateDomain::RecoveryHistory,
            StateDomain::AcceptedEffects,
            StateDomain::NativeSupply,
        ],
    )
}

/// Reconstructs the exact transparent checkpoint descriptor compiled here.
///
/// The sole semantic dependency is the exact compiled native-kernel descriptor;
/// callers cannot inject or substitute a dependency identity.
///
/// # Errors
///
/// Returns [`ProfileError`] if a static artifact hash or either descriptor
/// cannot be constructed. Such a failure is a build defect, never an
/// untrusted-input fallback condition.
pub fn transparent_checkpoint_descriptor() -> Result<ModuleDescriptor, ProfileError> {
    let native_kernel = transparent_native_kernel_descriptor()?;
    ModuleDescriptor::new(
        ModuleType::Checkpoint,
        CHECKPOINT_ABI_VERSION,
        artifact_hash(CHECKPOINT_SPEC_DOMAIN, CHECKPOINT_SPEC)?,
        artifact_hash(CHECKPOINT_INTERFACE_DOMAIN, CHECKPOINT_INTERFACE)?,
        artifact_hash(CHECKPOINT_VECTORS_DOMAIN, CHECKPOINT_VECTORS)?,
        artifact_hash(CHECKPOINT_PARAMETERS_DOMAIN, CHECKPOINT_PARAMETERS)?,
        vec![native_kernel.module_id()],
        vec![
            StateDomain::CanonicalOrder,
            StateDomain::NoteCommitments,
            StateDomain::Nullifiers,
            StateDomain::RecoveryHistory,
            StateDomain::AcceptedEffects,
            StateDomain::NativeSupply,
            StateDomain::Checkpoints,
        ],
        vec![StateDomain::Checkpoints],
    )
}
