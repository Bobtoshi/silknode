//! Profile pins and validation.

#![allow(missing_docs)]

use sha2::{Digest, Sha256};

use crate::canonical::domain_hash;
use crate::{
    CHECKPOINT_ABI, CanonicalDecode, CanonicalEncode, Decoder, Encoder, Error, Gate2ProfileV1,
    Hash32, NATIVE_KERNEL_ABI, PolicyLifecyclePhase, ProfileKind, SortedUniqueVec, Unverified,
    decode_unverified, policy_phase_root, profile_domain, protocol_manifest_hash,
    reward_schedule_hash,
};

pub const CONTRACT_SUBJECT_DIGEST: Hash32 = [
    0x7f, 0x57, 0x3e, 0x2e, 0x88, 0x56, 0x1d, 0x31, 0xdf, 0x48, 0x01, 0x91, 0x69, 0x9c, 0x9a, 0x2c,
    0x3e, 0x56, 0x85, 0xe4, 0xce, 0x3a, 0x1b, 0x3a, 0x3f, 0x43, 0x96, 0x67, 0x41, 0x3a, 0x3b, 0x0f,
];
pub const REGISTRY_SUBJECT_DIGEST: Hash32 = [
    0x9f, 0x1e, 0xe0, 0xb4, 0x7f, 0x01, 0xf9, 0x70, 0xef, 0x86, 0xd1, 0x52, 0x9d, 0xdf, 0x96, 0x22,
    0x0a, 0x0a, 0xe0, 0x55, 0x15, 0xcb, 0x9f, 0x35, 0xc3, 0x45, 0x57, 0xd8, 0x9e, 0x49, 0xa8, 0xa7,
];

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ModuleType {
    NativeKernel = 5,
    Checkpoint = 6,
    Issuance = 7,
    MandatePolicy = 9,
}
impl CanonicalEncode for ModuleType {
    fn encode(&self, e: &mut Encoder) -> Result<(), Error> {
        e.u8(*self as u8);
        Ok(())
    }
}
impl CanonicalDecode for ModuleType {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, Error> {
        match d.u8()? {
            5 => Ok(Self::NativeKernel),
            6 => Ok(Self::Checkpoint),
            7 => Ok(Self::Issuance),
            9 => Ok(Self::MandatePolicy),
            _ => Err(Error::code("canonical.unknown_tag")),
        }
    }
}
impl crate::WireMin for ModuleType {
    const MIN_BYTES: usize = 1;
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum StateDomain {
    CanonicalOrder = 3,
    NoteCommitments = 4,
    Nullifiers = 5,
    RecoveryHistory = 6,
    AcceptedEffects = 7,
    NativeSupply = 8,
    IssuanceCursor = 9,
    Checkpoints = 10,
    ProtocolProfiles = 11,
    PolicyPhases = 12,
    ProofSuites = 13,
}
impl CanonicalEncode for StateDomain {
    fn encode(&self, e: &mut Encoder) -> Result<(), Error> {
        e.u8(*self as u8);
        Ok(())
    }
}
impl CanonicalDecode for StateDomain {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, Error> {
        match d.u8()? {
            3 => Ok(Self::CanonicalOrder),
            4 => Ok(Self::NoteCommitments),
            5 => Ok(Self::Nullifiers),
            6 => Ok(Self::RecoveryHistory),
            7 => Ok(Self::AcceptedEffects),
            8 => Ok(Self::NativeSupply),
            9 => Ok(Self::IssuanceCursor),
            10 => Ok(Self::Checkpoints),
            11 => Ok(Self::ProtocolProfiles),
            12 => Ok(Self::PolicyPhases),
            13 => Ok(Self::ProofSuites),
            _ => Err(Error::code("canonical.unknown_tag")),
        }
    }
}
impl crate::WireMin for StateDomain {
    const MIN_BYTES: usize = 1;
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum DescriptorRole {
    NativeKernelA = 1,
    CheckpointA = 2,
    SyntheticIssuance = 3,
    MandatePolicy = 4,
    NativeKernelB = 5,
    CheckpointB = 6,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleDescriptor {
    pub module_type: ModuleType,
    pub abi_version: u16,
    pub normative_spec_hash: Hash32,
    pub interface_schema_hash: Hash32,
    pub conformance_vector_root: Hash32,
    pub parameter_hash: Hash32,
    pub module_id: Hash32,
    pub dependency_ids: SortedUniqueVec<Hash32, 64>,
    pub declared_state_reads: SortedUniqueVec<StateDomain, 64>,
    pub declared_state_writes: SortedUniqueVec<StateDomain, 64>,
}
impl CanonicalEncode for ModuleDescriptor {
    fn encode(&self, e: &mut Encoder) -> Result<(), Error> {
        self.module_type.encode(e)?;
        self.abi_version.encode(e)?;
        self.normative_spec_hash.encode(e)?;
        self.interface_schema_hash.encode(e)?;
        self.conformance_vector_root.encode(e)?;
        self.parameter_hash.encode(e)?;
        self.module_id.encode(e)?;
        self.dependency_ids.encode(e)?;
        self.declared_state_reads.encode(e)?;
        self.declared_state_writes.encode(e)
    }
}
impl CanonicalDecode for ModuleDescriptor {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, Error> {
        Ok(Self {
            module_type: ModuleType::decode(d)?,
            abi_version: u16::decode(d)?,
            normative_spec_hash: Hash32::decode(d)?,
            interface_schema_hash: Hash32::decode(d)?,
            conformance_vector_root: Hash32::decode(d)?,
            parameter_hash: Hash32::decode(d)?,
            module_id: Hash32::decode(d)?,
            dependency_ids: SortedUniqueVec::decode(d)?,
            declared_state_reads: SortedUniqueVec::decode(d)?,
            declared_state_writes: SortedUniqueVec::decode(d)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DescriptorConformancePin {
    pub bytes: Vec<u8>,
    pub raw_sha256: Hash32,
    pub framed_root: Hash32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DescriptorRolePin {
    pub role: DescriptorRole,
    pub conformance_precommit: DescriptorConformancePin,
    pub descriptor: ModuleDescriptor,
    pub canonical_descriptor_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DescriptorPinSetV1 {
    pub contract_bytes: Vec<u8>,
    pub registry_bytes: Vec<u8>,
    pub contract_subject_digest: Hash32,
    pub registry_subject_digest: Hash32,
    pub roles: Vec<DescriptorRolePin>,
    pub transition_semantics_id: Hash32,
    pub chain_domain: Hash32,
    pub synthetic_constitution_hash: Hash32,
    pub profile_a_bytes: Vec<u8>,
    pub profile_b_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedGate2ProfileV1 {
    profile: Gate2ProfileV1,
    canonical_bytes: Vec<u8>,
}
impl VerifiedGate2ProfileV1 {
    pub const fn profile(&self) -> &Gate2ProfileV1 {
        &self.profile
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

fn is_zero(value: &Hash32) -> bool {
    *value == [0; 32]
}

fn expected_role(role: DescriptorRole) -> (ModuleType, u16) {
    match role {
        DescriptorRole::NativeKernelA | DescriptorRole::NativeKernelB => {
            (ModuleType::NativeKernel, 3)
        }
        DescriptorRole::CheckpointA | DescriptorRole::CheckpointB => (ModuleType::Checkpoint, 4),
        DescriptorRole::SyntheticIssuance => (ModuleType::Issuance, 1),
        DescriptorRole::MandatePolicy => (ModuleType::MandatePolicy, 1),
    }
}

fn exact_caps(role: DescriptorRole) -> (&'static [StateDomain], &'static [StateDomain]) {
    use StateDomain as D;
    const KERNEL_READS: [D; 11] = [
        D::CanonicalOrder,
        D::NoteCommitments,
        D::Nullifiers,
        D::RecoveryHistory,
        D::AcceptedEffects,
        D::NativeSupply,
        D::IssuanceCursor,
        D::Checkpoints,
        D::ProtocolProfiles,
        D::PolicyPhases,
        D::ProofSuites,
    ];
    const KERNEL_WRITES: [D; 6] = [
        D::NoteCommitments,
        D::Nullifiers,
        D::RecoveryHistory,
        D::AcceptedEffects,
        D::NativeSupply,
        D::IssuanceCursor,
    ];
    const CHECKPOINT_WRITES: [D; 1] = [D::Checkpoints];
    const ISSUANCE_READS: [D; 6] = [
        D::CanonicalOrder,
        D::NativeSupply,
        D::IssuanceCursor,
        D::Checkpoints,
        D::ProtocolProfiles,
        D::ProofSuites,
    ];
    const MANDATE_READS: [D; 3] = [D::ProtocolProfiles, D::PolicyPhases, D::ProofSuites];
    match role {
        DescriptorRole::NativeKernelA | DescriptorRole::NativeKernelB => {
            (&KERNEL_READS, &KERNEL_WRITES)
        }
        DescriptorRole::CheckpointA | DescriptorRole::CheckpointB => {
            (&KERNEL_READS, &CHECKPOINT_WRITES)
        }
        DescriptorRole::SyntheticIssuance => (&ISSUANCE_READS, &[]),
        DescriptorRole::MandatePolicy => (&MANDATE_READS, &[]),
    }
}

fn artifact_hash(
    domain: &[u8],
    role: DescriptorRole,
    module_type: ModuleType,
    abi: u16,
    parts: &[&[u8]],
) -> Result<Hash32, Error> {
    let role = [role as u8];
    let module_type = [module_type as u8];
    let abi = abi.to_le_bytes();
    let mut framed: Vec<&[u8]> = vec![role.as_slice(), module_type.as_slice(), abi.as_slice()];
    framed.extend_from_slice(parts);
    domain_hash(domain, &framed)
}

pub fn module_id(descriptor: &ModuleDescriptor) -> Result<Hash32, Error> {
    let module_type = [descriptor.module_type as u8];
    let abi = descriptor.abi_version.to_le_bytes();
    let dependencies = descriptor.dependency_ids.canonical_bytes()?;
    let reads = descriptor.declared_state_reads.canonical_bytes()?;
    let writes = descriptor.declared_state_writes.canonical_bytes()?;
    domain_hash(
        b"Silk-Consensus-Module",
        &[
            module_type.as_slice(),
            abi.as_slice(),
            descriptor.normative_spec_hash.as_slice(),
            descriptor.interface_schema_hash.as_slice(),
            descriptor.conformance_vector_root.as_slice(),
            descriptor.parameter_hash.as_slice(),
            dependencies.as_slice(),
            reads.as_slice(),
            writes.as_slice(),
        ],
    )
}

impl DescriptorPinSetV1 {
    pub fn validate(&self) -> Result<(), Error> {
        if self.contract_bytes.is_empty()
            || self.registry_bytes.is_empty()
            || is_zero(&self.contract_subject_digest)
            || is_zero(&self.registry_subject_digest)
            || is_zero(&self.transition_semantics_id)
            || is_zero(&self.chain_domain)
            || is_zero(&self.synthetic_constitution_hash)
            || self.profile_a_bytes.is_empty()
            || self.profile_b_bytes.is_empty()
            || self.roles.len() != 6
            || self.roles.iter().any(|r| {
                r.conformance_precommit.bytes.is_empty()
                    || is_zero(&r.conformance_precommit.raw_sha256)
                    || is_zero(&r.conformance_precommit.framed_root)
                    || r.canonical_descriptor_bytes.is_empty()
                    || is_zero(&r.descriptor.module_id)
            })
        {
            return Err(Error::code("precommit.missing_artifact_pin"));
        }

        let contract = domain_hash(
            b"Silk-Transparent-Gate2-Contract-v1",
            &[self.contract_bytes.as_slice()],
        )?;
        let registry = domain_hash(
            b"Silk-Transparent-Gate2-Registry-v1",
            &[self.registry_bytes.as_slice()],
        )?;
        if contract != self.contract_subject_digest
            || registry != self.registry_subject_digest
            || contract != CONTRACT_SUBJECT_DIGEST
            || registry != REGISTRY_SUBJECT_DIGEST
        {
            return Err(Error::code("precommit.artifact_root_mismatch"));
        }
        for role in &self.roles {
            let mut raw = Sha256::new();
            raw.update(&role.conformance_precommit.bytes);
            let raw: Hash32 = raw.finalize().into();
            let (module_type, abi) = expected_role(role.role);
            let framed = artifact_hash(
                b"Silk-Gate2-Module-Conformance-Precommit-v1",
                role.role,
                module_type,
                abi,
                &[role.conformance_precommit.bytes.as_slice()],
            )?;
            if raw != role.conformance_precommit.raw_sha256
                || framed != role.conformance_precommit.framed_root
            {
                return Err(Error::code("precommit.artifact_root_mismatch"));
            }
        }

        let mut roles = self.roles.iter().map(|r| r.role).collect::<Vec<_>>();
        roles.sort_unstable();
        roles.dedup();
        let expected = [
            DescriptorRole::NativeKernelA,
            DescriptorRole::CheckpointA,
            DescriptorRole::SyntheticIssuance,
            DescriptorRole::MandatePolicy,
            DescriptorRole::NativeKernelB,
            DescriptorRole::CheckpointB,
        ];
        if roles.as_slice() != expected {
            return Err(Error::code("precommit.descriptor_shape_mismatch"));
        }
        for role in &self.roles {
            let (module_type, abi) = expected_role(role.role);
            let descriptor = &role.descriptor;
            let normative = artifact_hash(
                b"Silk-Gate2-Module-Normative-Spec-v1",
                role.role,
                module_type,
                abi,
                &[
                    self.contract_subject_digest.as_slice(),
                    self.registry_subject_digest.as_slice(),
                ],
            )?;
            let interface = artifact_hash(
                b"Silk-Gate2-Module-Interface-Schema-v1",
                role.role,
                module_type,
                abi,
                &[self.registry_subject_digest.as_slice()],
            )?;
            let parameter = artifact_hash(
                b"Silk-Gate2-Module-Parameters-v1",
                role.role,
                module_type,
                abi,
                &[self.registry_subject_digest.as_slice()],
            )?;
            if descriptor.module_type != module_type
                || descriptor.abi_version != abi
                || descriptor.normative_spec_hash != normative
                || descriptor.interface_schema_hash != interface
                || descriptor.parameter_hash != parameter
                || descriptor.conformance_vector_root != role.conformance_precommit.framed_root
                || descriptor.canonical_bytes()? != role.canonical_descriptor_bytes
            {
                return Err(Error::code("precommit.descriptor_shape_mismatch"));
            }
        }

        let id = |wanted| {
            self.roles
                .iter()
                .find(|r| r.role == wanted)
                .map(|r| r.descriptor.module_id)
                .expect("complete role set")
        };
        for role in &self.roles {
            let mut expected_dependencies = match role.role {
                DescriptorRole::NativeKernelA | DescriptorRole::NativeKernelB => vec![
                    id(DescriptorRole::SyntheticIssuance),
                    id(DescriptorRole::MandatePolicy),
                ],
                DescriptorRole::CheckpointA => vec![id(DescriptorRole::NativeKernelA)],
                DescriptorRole::CheckpointB => vec![id(DescriptorRole::NativeKernelB)],
                DescriptorRole::SyntheticIssuance | DescriptorRole::MandatePolicy => vec![],
            };
            expected_dependencies.sort_unstable();
            if role.descriptor.dependency_ids.as_slice() != expected_dependencies {
                return Err(Error::code("precommit.descriptor_dependency_mismatch"));
            }
        }

        for role in &self.roles {
            let (reads, writes) = exact_caps(role.role);
            if role.descriptor.declared_state_reads.as_slice() != reads
                || role.descriptor.declared_state_writes.as_slice() != writes
            {
                return Err(Error::code("precommit.descriptor_capability_mismatch"));
            }
        }
        for role in &self.roles {
            if module_id(&role.descriptor)? != role.descriptor.module_id {
                return Err(Error::code("precommit.module_id_mismatch"));
            }
        }

        let profile_a = decode_unverified::<Gate2ProfileV1>(&self.profile_a_bytes)
            .map_err(|_| Error::code("precommit.profile_descriptor_pin_mismatch"))?;
        let profile_b = decode_unverified::<Gate2ProfileV1>(&self.profile_b_bytes)
            .map_err(|_| Error::code("precommit.profile_descriptor_pin_mismatch"))?;
        if !self.profile_role_binding(profile_a.decoded(), true)
            || !self.profile_role_binding(profile_b.decoded(), false)
        {
            return Err(Error::code("precommit.profile_descriptor_pin_mismatch"));
        }
        Ok(())
    }

    fn role_id(&self, role: DescriptorRole) -> Option<Hash32> {
        self.roles
            .iter()
            .find(|item| item.role == role)
            .map(|item| item.descriptor.module_id)
    }

    fn profile_role_binding(&self, profile: &Gate2ProfileV1, a: bool) -> bool {
        let body = &profile.manifest_body;
        let kernel = if a {
            DescriptorRole::NativeKernelA
        } else {
            DescriptorRole::NativeKernelB
        };
        let checkpoint = if a {
            DescriptorRole::CheckpointA
        } else {
            DescriptorRole::CheckpointB
        };
        body.native_kernel_module_id == self.role_id(kernel).unwrap_or([0; 32])
            && body.native_kernel_abi == NATIVE_KERNEL_ABI
            && body.checkpoint_module_id == self.role_id(checkpoint).unwrap_or([0; 32])
            && body.checkpoint_abi == CHECKPOINT_ABI
            && body.issuance_module_id
                == self
                    .role_id(DescriptorRole::SyntheticIssuance)
                    .unwrap_or([0; 32])
            && body.issuance_abi == 1
            && body.mandate_policy_module_id
                == self
                    .role_id(DescriptorRole::MandatePolicy)
                    .unwrap_or([0; 32])
            && body.mandate_version == 1
    }
}

fn validate_profile_semantics(
    profile: &Gate2ProfileV1,
    pins: &DescriptorPinSetV1,
) -> Result<(), Error> {
    let body = &profile.manifest_body;
    let expected_major = match body.profile_kind {
        ProfileKind::Genesis => 2,
        ProfileKind::Successor => 3,
    };
    if is_zero(&body.chain_domain)
        || is_zero(&body.synthetic_constitution_hash)
        || body.chain_domain != pins.chain_domain
        || body.synthetic_constitution_hash != pins.synthetic_constitution_hash
        || body.protocol_major != expected_major
    {
        return Err(Error::code("profile.invalid_profile_shape"));
    }
    let is_a = body.profile_kind == ProfileKind::Genesis;
    if !pins.profile_role_binding(profile, is_a) {
        return Err(Error::code("profile.unsupported_module"));
    }
    if is_zero(&body.transition_semantics_id)
        || body.transition_semantics_id != pins.transition_semantics_id
    {
        return Err(Error::code("profile.unsupported_transition_semantics"));
    }
    if !is_zero(&body.state_commitment_migration_hash) {
        return Err(Error::code("profile.accumulator_migration_unimplemented"));
    }
    let bands = &body.synthetic_reward_schedule.bands;
    if bands.is_empty()
        || bands[0].start_position != 1
        || bands
            .windows(2)
            .any(|pair| pair[0].start_position >= pair[1].start_position)
    {
        return Err(Error::code("profile.invalid_reward_schedule"));
    }
    let max_subsidy = bands.iter().map(|band| band.subsidy).max().unwrap_or(0);
    if max_subsidy
        .checked_add(body.max_accepted_fees_per_body)
        .is_none()
    {
        return Err(Error::code("profile.invalid_reward_schedule"));
    }
    match body.profile_kind {
        ProfileKind::Genesis => {
            if !is_zero(&body.predecessor_manifest_hash)
                || !is_zero(&body.predecessor_profile_domain)
                || body.upgrade_schedule.is_some()
                || body.activation_checkpoint != 0
            {
                return Err(Error::code("profile.invalid_upgrade_schedule"));
            }
        }
        ProfileKind::Successor => {
            let Some(schedule) = &body.upgrade_schedule else {
                return Err(Error::code("profile.invalid_upgrade_schedule"));
            };
            if is_zero(&body.predecessor_manifest_hash)
                || is_zero(&body.predecessor_profile_domain)
                || body.activation_checkpoint != schedule.activation_checkpoint
            {
                return Err(Error::code("profile.invalid_upgrade_schedule"));
            }
            if !(schedule.proposal_checkpoint < schedule.review_close_checkpoint
                && schedule.review_close_checkpoint <= schedule.exit_open_checkpoint
                && schedule.exit_open_checkpoint < schedule.exit_close_checkpoint
                && schedule.exit_close_checkpoint < schedule.activation_checkpoint
                && schedule.activation_checkpoint < schedule.overlap_end_checkpoint)
            {
                return Err(Error::code("profile.invalid_upgrade_schedule"));
            }
        }
    }
    if body.active_suite_ids.is_empty()
        || body
            .active_suite_ids
            .iter()
            .any(|suite| body.retained_migration_source_suite_ids.contains(suite))
        || !body.active_suite_ids.contains(&body.reward_suite_id)
        || !body.active_suite_ids.contains(&body.mandate_suite_id)
        || (body.profile_kind == ProfileKind::Genesis
            && !body.retained_migration_source_suite_ids.is_empty())
        || (body.profile_kind == ProfileKind::Successor
            && body.retained_migration_source_suite_ids.len() != 1)
    {
        return Err(Error::code("profile.invalid_suite_lifecycle"));
    }
    match body.profile_kind {
        ProfileKind::Genesis
            if body.policy_lifecycle_phase != PolicyLifecyclePhase::CreateAndUse
                || !is_zero(&body.migration_relation_hash) =>
        {
            return Err(Error::code("profile.invalid_suite_lifecycle"));
        }
        ProfileKind::Successor
            if body.policy_lifecycle_phase != PolicyLifecyclePhase::UseOnly
                || is_zero(&body.migration_relation_hash) =>
        {
            return Err(Error::code("profile.invalid_suite_lifecycle"));
        }
        _ => {}
    }
    if policy_phase_root(profile)? != profile.policy_phase_root
        || reward_schedule_hash(profile)? != profile.reward_schedule_hash
        || protocol_manifest_hash(profile)? != profile.protocol_manifest_hash
        || profile_domain(profile)? != profile.profile_domain
    {
        return Err(Error::code("profile.invalid_derived_field"));
    }
    Ok(())
}

#[cfg(feature = "private-test-harness")]
pub fn validate_synthetic_profile_candidate(
    profile: &Gate2ProfileV1,
    pins: &DescriptorPinSetV1,
) -> Result<(), Error> {
    pins.validate()?;
    validate_profile_semantics(profile, pins)
}

pub fn promote_profile(
    unverified: Unverified<Gate2ProfileV1>,
    pins: &DescriptorPinSetV1,
) -> Result<VerifiedGate2ProfileV1, Error> {
    pins.validate()?;
    let profile = unverified.into_inner();
    let canonical = profile.canonical_bytes()?;
    if canonical != pins.profile_a_bytes && canonical != pins.profile_b_bytes {
        return Err(Error::code("codec.profile_pin_mismatch"));
    }
    validate_profile_semantics(&profile, pins)?;
    Ok(VerifiedGate2ProfileV1 {
        profile,
        canonical_bytes: canonical,
    })
}
