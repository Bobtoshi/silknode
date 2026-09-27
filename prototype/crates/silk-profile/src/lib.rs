#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Fail-closed protocol-profile validation for the `SilkNode` Gate A prototype.
//!
//! This crate represents semantic module descriptors, derives their identities
//! from canonical content, and validates a complete manifest against trusted
//! local release support and the immutable capability ceilings committed by a
//! chain constitution. It is deliberately not a runtime plugin loader.

use core::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use silk_types::{
    CanonicalDecode, CanonicalEncode, ChainDomain, CollectionError, DecodeError, Decoder,
    DomainHashError, EncodeError, Encoder, GateAGenesisReceiptTemplateHash,
    GenesisAllocationTemplateHash, GenesisCommitment, GenesisManifestTemplateHash,
    GenesisObjectTemplateHash, Hash32, ManifestHash, ModuleId, ProfileDomain, derive_chain_domain,
    derive_genesis_allocation_template_hash, derive_genesis_commitment, derive_profile_domain,
    domain_hash, hash_domains, validate_sorted_unique,
};
use thiserror::Error;

/// Maximum module descriptors accepted from one Gate A manifest.
pub const MAX_MODULES: usize = 256;
/// Maximum direct dependencies accepted for one module.
pub const MAX_DEPENDENCIES_PER_MODULE: usize = 64;
/// Maximum state domains accepted in one read or write capability list.
pub const MAX_CAPABILITIES_PER_MODULE: usize = 64;
/// Maximum role-cap entries accepted in one constitutional capability table.
pub const MAX_ROLE_CAPS: usize = 256;

const MODULE_TYPE_TAGS: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
const STATE_DOMAIN_TAGS: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
const UPGRADE_SCHEDULE_TAGS: &[u8] = &[0, 1];
const GENESIS_MANIFEST_TEMPLATE_VERSION: u8 = 1;
const GENESIS_MANIFEST_TEMPLATE_TAGS: &[u8] = &[GENESIS_MANIFEST_TEMPLATE_VERSION];
/// Stable top-level tag for the deterministic genesis-object template.
pub const GENESIS_OBJECT_TEMPLATE_TAG: u8 = 0xa0;
/// Stable wire-format version of the deterministic genesis-object template.
pub const GENESIS_OBJECT_TEMPLATE_VERSION: u8 = 1;
/// Exact byte length of a version-one canonical genesis-object template.
pub const GENESIS_OBJECT_TEMPLATE_V1_ENCODED_LENGTH: usize = 236;
const GENESIS_OBJECT_TEMPLATE_TAGS: &[u8] = &[GENESIS_OBJECT_TEMPLATE_TAG];
const GENESIS_OBJECT_TEMPLATE_VERSIONS: &[u8] = &[GENESIS_OBJECT_TEMPLATE_VERSION];
const GATE_A_GENESIS_RECEIPT_TEMPLATE_VERSION: u8 = 1;
const GATE_A_GENESIS_RECEIPT_TEMPLATE_TAGS: &[u8] = &[GATE_A_GENESIS_RECEIPT_TEMPLATE_VERSION];
const ZERO_DERIVED_HASH_PLACEHOLDER: [u8; Hash32::LENGTH] = [0; Hash32::LENGTH];

/// Consensus module roles understood by this release.
///
/// Unknown tags fail canonical decoding. The first seven roles are exclusive:
/// a complete active profile must contain exactly one descriptor for each.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ModuleType {
    /// Canonical wire rules and resource limits.
    WireLimits = 1,
    /// Proof-of-work validity and work measurement.
    ProofOfWork = 2,
    /// Difficulty and target transition rules.
    DifficultyAdjustment = 3,
    /// Deterministic graph or linear-history ordering.
    GraphOrder = 4,
    /// Native note, nullifier, recovery, and counter interpreter.
    NativeKernel = 5,
    /// Checkpoint derivation and serialization.
    Checkpoint = 6,
    /// Constitution-fixed native issuance schedule.
    Issuance = 7,
    /// A cryptographic proof/encryption suite; scheduled suites may overlap.
    ProofSuite = 8,
    /// A fixed mandate-policy grammar; scheduled policy versions may overlap.
    MandatePolicy = 9,
    /// Deterministic recovery-root and recovery-delta logic.
    Recovery = 10,
}

impl ModuleType {
    /// Roles which must have exactly one authoritative module in every profile.
    pub const REQUIRED_EXCLUSIVE: [Self; 7] = [
        Self::WireLimits,
        Self::ProofOfWork,
        Self::DifficultyAdjustment,
        Self::GraphOrder,
        Self::NativeKernel,
        Self::Checkpoint,
        Self::Issuance,
    ];

    /// Returns the stable canonical tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Self {
        match tag {
            1 => Self::WireLimits,
            2 => Self::ProofOfWork,
            3 => Self::DifficultyAdjustment,
            4 => Self::GraphOrder,
            5 => Self::NativeKernel,
            6 => Self::Checkpoint,
            7 => Self::Issuance,
            8 => Self::ProofSuite,
            9 => Self::MandatePolicy,
            10 => Self::Recovery,
            _ => unreachable!("tag was checked before conversion"),
        }
    }
}

impl CanonicalEncode for ModuleType {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_u8(self.tag());
        Ok(())
    }
}

impl CanonicalDecode for ModuleType {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self::from_tag(decoder.read_tag(MODULE_TYPE_TAGS)?))
    }
}

/// Typed state surfaces that may be exposed to a consensus module.
///
/// These are capabilities, not ambient database handles. A conforming host
/// supplies only typed views/effect builders for the declared subset.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum StateDomain {
    /// Canonical vertex headers and parent relations.
    GraphHeaders = 1,
    /// Verified, fully available vertex bodies.
    GraphBodies = 2,
    /// The deterministic accepted vertex/effect order.
    CanonicalOrder = 3,
    /// Native note-commitment history and accumulator state.
    NoteCommitments = 4,
    /// Exact native nullifier state.
    Nullifiers = 5,
    /// Recovery-record history and accumulator state.
    RecoveryHistory = 6,
    /// Accepted-effect history and accumulator state.
    AcceptedEffects = 7,
    /// Native issued and burned supply counters.
    NativeSupply = 8,
    /// Monotone constitution-wide issuance cursor.
    IssuanceCursor = 9,
    /// Materialized checkpoint state.
    Checkpoints = 10,
    /// Activated profile and transition metadata.
    ProtocolProfiles = 11,
    /// Mandate-policy phase schedule and root.
    PolicyPhases = 12,
    /// Active and retained proof-suite metadata.
    ProofSuites = 13,
}

impl StateDomain {
    /// Returns the stable canonical tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Self {
        match tag {
            1 => Self::GraphHeaders,
            2 => Self::GraphBodies,
            3 => Self::CanonicalOrder,
            4 => Self::NoteCommitments,
            5 => Self::Nullifiers,
            6 => Self::RecoveryHistory,
            7 => Self::AcceptedEffects,
            8 => Self::NativeSupply,
            9 => Self::IssuanceCursor,
            10 => Self::Checkpoints,
            11 => Self::ProtocolProfiles,
            12 => Self::PolicyPhases,
            13 => Self::ProofSuites,
            _ => unreachable!("tag was checked before conversion"),
        }
    }
}

impl CanonicalEncode for StateDomain {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_u8(self.tag());
        Ok(())
    }
}

impl CanonicalDecode for StateDomain {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self::from_tag(decoder.read_tag(STATE_DOMAIN_TAGS)?))
    }
}

/// A semantic consensus-module descriptor.
///
/// `module_id` is redundant by design: validation recomputes it from every
/// other field and rejects a mismatch before the module can become active.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleDescriptor {
    module_type: ModuleType,
    abi_version: u16,
    normative_spec_hash: Hash32,
    interface_schema_hash: Hash32,
    conformance_vector_root: Hash32,
    parameter_hash: Hash32,
    module_id: ModuleId,
    dependency_ids: Vec<ModuleId>,
    declared_state_reads: Vec<StateDomain>,
    declared_state_writes: Vec<StateDomain>,
}

impl Ord for ModuleDescriptor {
    fn cmp(&self, other: &Self) -> Ordering {
        self.module_id.cmp(&other.module_id)
    }
}

impl PartialOrd for ModuleDescriptor {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl ModuleDescriptor {
    /// Constructs a canonical descriptor and derives its module identity.
    ///
    /// # Errors
    ///
    /// Returns a collection error if any set-like list is not strictly sorted
    /// and unique, or an encoding/hash error if identity derivation fails.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        module_type: ModuleType,
        abi_version: u16,
        normative_spec_hash: Hash32,
        interface_schema_hash: Hash32,
        conformance_vector_root: Hash32,
        parameter_hash: Hash32,
        dependency_ids: Vec<ModuleId>,
        declared_state_reads: Vec<StateDomain>,
        declared_state_writes: Vec<StateDomain>,
    ) -> Result<Self, ProfileError> {
        validate_descriptor_lists(
            &dependency_ids,
            &declared_state_reads,
            &declared_state_writes,
        )?;
        let module_id = compute_module_id(
            module_type,
            abi_version,
            normative_spec_hash,
            interface_schema_hash,
            conformance_vector_root,
            parameter_hash,
            &dependency_ids,
            &declared_state_reads,
            &declared_state_writes,
        )?;
        Ok(Self {
            module_type,
            abi_version,
            normative_spec_hash,
            interface_schema_hash,
            conformance_vector_root,
            parameter_hash,
            module_id,
            dependency_ids,
            declared_state_reads,
            declared_state_writes,
        })
    }

    /// Returns the consensus role implemented by this descriptor.
    #[must_use]
    pub const fn module_type(&self) -> ModuleType {
        self.module_type
    }

    /// Returns the canonical host-interface version.
    #[must_use]
    pub const fn abi_version(&self) -> u16 {
        self.abi_version
    }

    /// Returns the hash of the normative behavior specification.
    #[must_use]
    pub const fn normative_spec_hash(&self) -> Hash32 {
        self.normative_spec_hash
    }

    /// Returns the hash of the canonical host-interface schema.
    #[must_use]
    pub const fn interface_schema_hash(&self) -> Hash32 {
        self.interface_schema_hash
    }

    /// Returns the root of the release's conformance vectors.
    #[must_use]
    pub const fn conformance_vector_root(&self) -> Hash32 {
        self.conformance_vector_root
    }

    /// Returns the hash of role-specific consensus parameters.
    #[must_use]
    pub const fn parameter_hash(&self) -> Hash32 {
        self.parameter_hash
    }

    /// Returns the content-derived semantic module identity.
    #[must_use]
    pub const fn module_id(&self) -> ModuleId {
        self.module_id
    }

    /// Returns the sorted direct module dependencies.
    #[must_use]
    pub fn dependency_ids(&self) -> &[ModuleId] {
        &self.dependency_ids
    }

    /// Returns the sorted declared state-read capabilities.
    #[must_use]
    pub fn declared_state_reads(&self) -> &[StateDomain] {
        &self.declared_state_reads
    }

    /// Returns the sorted declared state-write capabilities.
    #[must_use]
    pub fn declared_state_writes(&self) -> &[StateDomain] {
        &self.declared_state_writes
    }

    /// Recomputes the module identity from all semantic descriptor fields.
    ///
    /// # Errors
    ///
    /// Returns an error if a set-like field is non-canonical or hashing fails.
    pub fn recompute_id(&self) -> Result<ModuleId, ProfileError> {
        compute_module_id(
            self.module_type,
            self.abi_version,
            self.normative_spec_hash,
            self.interface_schema_hash,
            self.conformance_vector_root,
            self.parameter_hash,
            &self.dependency_ids,
            &self.declared_state_reads,
            &self.declared_state_writes,
        )
    }

    fn validate_structure(&self) -> Result<(), ProfileError> {
        validate_descriptor_lists(
            &self.dependency_ids,
            &self.declared_state_reads,
            &self.declared_state_writes,
        )?;
        let computed = self.recompute_id()?;
        if computed != self.module_id {
            return Err(ProfileError::ModuleIdMismatch {
                claimed: self.module_id,
                computed,
            });
        }
        Ok(())
    }
}

impl CanonicalEncode for ModuleDescriptor {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.module_type.encode(encoder)?;
        encoder.write_u16(self.abi_version);
        self.normative_spec_hash.encode(encoder)?;
        self.interface_schema_hash.encode(encoder)?;
        self.conformance_vector_root.encode(encoder)?;
        self.parameter_hash.encode(encoder)?;
        self.module_id.encode(encoder)?;
        encoder.write_sorted_unique(&self.dependency_ids)?;
        encoder.write_sorted_unique(&self.declared_state_reads)?;
        encoder.write_sorted_unique(&self.declared_state_writes)?;
        Ok(())
    }
}

impl CanonicalDecode for ModuleDescriptor {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            module_type: ModuleType::decode(decoder)?,
            abi_version: decoder.read_u16()?,
            normative_spec_hash: Hash32::decode(decoder)?,
            interface_schema_hash: Hash32::decode(decoder)?,
            conformance_vector_root: Hash32::decode(decoder)?,
            parameter_hash: Hash32::decode(decoder)?,
            module_id: ModuleId::decode(decoder)?,
            dependency_ids: decoder.read_sorted_unique(MAX_DEPENDENCIES_PER_MODULE)?,
            declared_state_reads: decoder.read_sorted_unique(MAX_CAPABILITIES_PER_MODULE)?,
            declared_state_writes: decoder.read_sorted_unique(MAX_CAPABILITIES_PER_MODULE)?,
        })
    }
}

/// One immutable role-specific capability ceiling from the chain constitution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoleCapabilityCap {
    module_type: ModuleType,
    max_state_reads: Vec<StateDomain>,
    max_state_writes: Vec<StateDomain>,
}

impl Ord for RoleCapabilityCap {
    fn cmp(&self, other: &Self) -> Ordering {
        self.module_type.cmp(&other.module_type)
    }
}

impl PartialOrd for RoleCapabilityCap {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl RoleCapabilityCap {
    /// Constructs one canonical role capability ceiling.
    ///
    /// # Errors
    ///
    /// Returns an error if a capability list is not sorted and unique.
    pub fn new(
        module_type: ModuleType,
        max_state_reads: Vec<StateDomain>,
        max_state_writes: Vec<StateDomain>,
    ) -> Result<Self, ProfileError> {
        map_collection(
            "constitutional read cap",
            validate_sorted_unique(&max_state_reads),
        )?;
        map_collection(
            "constitutional write cap",
            validate_sorted_unique(&max_state_writes),
        )?;
        Ok(Self {
            module_type,
            max_state_reads,
            max_state_writes,
        })
    }

    /// Returns the role governed by this ceiling.
    #[must_use]
    pub const fn module_type(&self) -> ModuleType {
        self.module_type
    }

    /// Returns the maximum permitted read domains.
    #[must_use]
    pub fn max_state_reads(&self) -> &[StateDomain] {
        &self.max_state_reads
    }

    /// Returns the maximum permitted write domains.
    #[must_use]
    pub fn max_state_writes(&self) -> &[StateDomain] {
        &self.max_state_writes
    }
}

impl CanonicalEncode for RoleCapabilityCap {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.module_type.encode(encoder)?;
        encoder.write_sorted_unique(&self.max_state_reads)?;
        encoder.write_sorted_unique(&self.max_state_writes)?;
        Ok(())
    }
}

impl CanonicalDecode for RoleCapabilityCap {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            module_type: ModuleType::decode(decoder)?,
            max_state_reads: decoder.read_sorted_unique(MAX_CAPABILITIES_PER_MODULE)?,
            max_state_writes: decoder.read_sorted_unique(MAX_CAPABILITIES_PER_MODULE)?,
        })
    }
}

/// Trusted capability ceilings for one immutable chain constitution.
///
/// The full constitution contains emission, cadence, and lifecycle commitments
/// outside this crate. `chain_constitution_hash` identifies that complete
/// object; this table supplies the role caps a conforming release extracted
/// from it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConstitutionalCaps {
    chain_constitution_hash: Hash32,
    role_caps: Vec<RoleCapabilityCap>,
}

impl ConstitutionalCaps {
    /// Constructs a canonical trusted capability table.
    ///
    /// # Errors
    ///
    /// Returns an error for duplicate or unsorted role entries, or malformed
    /// capability lists.
    pub fn new(
        chain_constitution_hash: Hash32,
        role_caps: Vec<RoleCapabilityCap>,
    ) -> Result<Self, ProfileError> {
        ensure_limit("constitutional role caps", role_caps.len(), MAX_ROLE_CAPS)?;
        map_collection(
            "constitutional role caps",
            validate_sorted_unique(&role_caps),
        )?;
        for cap in &role_caps {
            map_collection(
                "constitutional read cap",
                validate_sorted_unique(&cap.max_state_reads),
            )?;
            map_collection(
                "constitutional write cap",
                validate_sorted_unique(&cap.max_state_writes),
            )?;
        }
        Ok(Self {
            chain_constitution_hash,
            role_caps,
        })
    }

    /// Returns the hash of the complete chain constitution.
    #[must_use]
    pub const fn chain_constitution_hash(&self) -> Hash32 {
        self.chain_constitution_hash
    }

    /// Returns the canonical per-role ceilings.
    #[must_use]
    pub fn role_caps(&self) -> &[RoleCapabilityCap] {
        &self.role_caps
    }

    fn cap_for(&self, module_type: ModuleType) -> Option<&RoleCapabilityCap> {
        self.role_caps
            .binary_search_by_key(&module_type, RoleCapabilityCap::module_type)
            .ok()
            .map(|index| &self.role_caps[index])
    }
}

impl CanonicalEncode for ConstitutionalCaps {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_constitution_hash.encode(encoder)?;
        encoder.write_sorted_unique(&self.role_caps)?;
        Ok(())
    }
}

impl CanonicalDecode for ConstitutionalCaps {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            chain_constitution_hash: Hash32::decode(decoder)?,
            role_caps: decoder.read_sorted_unique(MAX_ROLE_CAPS)?,
        })
    }
}

/// A content-addressed checkpoint schedule for one protocol-profile change.
///
/// Genesis is structurally distinct because it has no predecessor and is not
/// an upgrade. Every successor uses the versioned schedule variant, so an old
/// client rejects a future schedule schema instead of silently applying
/// unknown timing rules.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpgradeSchedule {
    /// The predecessor-free genesis profile, active from checkpoint zero.
    Genesis,
    /// The first fail-closed checkpoint schedule schema.
    V1(UpgradeScheduleV1),
}

impl UpgradeSchedule {
    /// Constructs the unique predecessor-free genesis sentinel.
    #[must_use]
    pub const fn genesis() -> Self {
        Self::Genesis
    }

    /// Constructs and validates a version-one successor schedule.
    ///
    /// Review begins when the proposal is published. Review must close after
    /// publication and no later than the opening of the user exit window. The
    /// exit window, post-exit activation delay, and compatibility overlap must
    /// each span at least one checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::InvalidUpgradeSchedule`] when the checkpoint
    /// ordering would create a zero-length or inverted phase.
    pub fn v1(
        proposal_checkpoint: u64,
        review_close_checkpoint: u64,
        exit_open_checkpoint: u64,
        exit_close_checkpoint: u64,
        activation_checkpoint: u64,
        overlap_end_checkpoint: u64,
    ) -> Result<Self, ProfileError> {
        let schedule = UpgradeScheduleV1 {
            proposal_checkpoint,
            review_close_checkpoint,
            exit_open_checkpoint,
            exit_close_checkpoint,
            activation_checkpoint,
            overlap_end_checkpoint,
        };
        schedule.validate()?;
        Ok(Self::V1(schedule))
    }

    /// Returns the successor schedule fields, or `None` for genesis.
    #[must_use]
    pub const fn as_v1(&self) -> Option<&UpgradeScheduleV1> {
        match self {
            Self::Genesis => None,
            Self::V1(schedule) => Some(schedule),
        }
    }

    /// Returns the checkpoint fence at which this profile becomes active.
    #[must_use]
    pub const fn activation_checkpoint(self) -> u64 {
        match self {
            Self::Genesis => 0,
            Self::V1(schedule) => schedule.activation_checkpoint,
        }
    }

    fn validate_for_predecessor(
        &self,
        predecessor_manifest_hash: ManifestHash,
    ) -> Result<(), ProfileError> {
        match (predecessor_manifest_hash == ManifestHash::ZERO, self) {
            (true, Self::Genesis) => Ok(()),
            (false, Self::V1(schedule)) => schedule.validate(),
            (true, Self::V1(_)) => Err(ProfileError::InvalidUpgradeSchedule {
                reason: "a successor schedule requires a nonzero predecessor manifest",
            }),
            (false, Self::Genesis) => Err(ProfileError::InvalidUpgradeSchedule {
                reason: "the genesis schedule requires the zero predecessor sentinel",
            }),
        }
    }
}

impl CanonicalEncode for UpgradeSchedule {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::Genesis => encoder.write_u8(0),
            Self::V1(schedule) => {
                encoder.write_u8(1);
                schedule.encode(encoder)?;
            }
        }
        Ok(())
    }
}

impl CanonicalDecode for UpgradeSchedule {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match decoder.read_tag(UPGRADE_SCHEDULE_TAGS)? {
            0 => Ok(Self::Genesis),
            1 => Ok(Self::V1(UpgradeScheduleV1::decode(decoder)?)),
            _ => unreachable!("tag was checked before conversion"),
        }
    }
}

/// Exact checkpoint fields committed by a version-one successor schedule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::struct_field_names)]
pub struct UpgradeScheduleV1 {
    proposal_checkpoint: u64,
    review_close_checkpoint: u64,
    exit_open_checkpoint: u64,
    exit_close_checkpoint: u64,
    activation_checkpoint: u64,
    overlap_end_checkpoint: u64,
}

impl UpgradeScheduleV1 {
    /// Returns the checkpoint at which the complete proposal is published.
    #[must_use]
    pub const fn proposal_checkpoint(&self) -> u64 {
        self.proposal_checkpoint
    }

    /// Returns the last checkpoint in the public review period.
    #[must_use]
    pub const fn review_close_checkpoint(&self) -> u64 {
        self.review_close_checkpoint
    }

    /// Returns the checkpoint at which the declared user exit window opens.
    #[must_use]
    pub const fn exit_open_checkpoint(&self) -> u64 {
        self.exit_open_checkpoint
    }

    /// Returns the checkpoint at which the declared user exit window closes.
    #[must_use]
    pub const fn exit_close_checkpoint(&self) -> u64 {
        self.exit_close_checkpoint
    }

    /// Returns the checkpoint fence at which the successor becomes active.
    #[must_use]
    pub const fn activation_checkpoint(&self) -> u64 {
        self.activation_checkpoint
    }

    /// Returns the final checkpoint of the bounded compatibility overlap.
    #[must_use]
    pub const fn overlap_end_checkpoint(&self) -> u64 {
        self.overlap_end_checkpoint
    }

    const fn validate(&self) -> Result<(), ProfileError> {
        if self.review_close_checkpoint <= self.proposal_checkpoint {
            return Err(ProfileError::InvalidUpgradeSchedule {
                reason: "review close must follow proposal publication",
            });
        }
        if self.exit_open_checkpoint < self.review_close_checkpoint {
            return Err(ProfileError::InvalidUpgradeSchedule {
                reason: "the exit window cannot open before review closes",
            });
        }
        if self.exit_close_checkpoint <= self.exit_open_checkpoint {
            return Err(ProfileError::InvalidUpgradeSchedule {
                reason: "the exit window must have nonzero duration",
            });
        }
        if self.activation_checkpoint <= self.exit_close_checkpoint {
            return Err(ProfileError::InvalidUpgradeSchedule {
                reason: "activation must follow the exit window",
            });
        }
        if self.overlap_end_checkpoint <= self.activation_checkpoint {
            return Err(ProfileError::InvalidUpgradeSchedule {
                reason: "the compatibility overlap must have nonzero duration",
            });
        }
        Ok(())
    }
}

impl CanonicalEncode for UpgradeScheduleV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_u64(self.proposal_checkpoint);
        encoder.write_u64(self.review_close_checkpoint);
        encoder.write_u64(self.exit_open_checkpoint);
        encoder.write_u64(self.exit_close_checkpoint);
        encoder.write_u64(self.activation_checkpoint);
        encoder.write_u64(self.overlap_end_checkpoint);
        Ok(())
    }
}

impl CanonicalDecode for UpgradeScheduleV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            proposal_checkpoint: decoder.read_u64()?,
            review_close_checkpoint: decoder.read_u64()?,
            exit_open_checkpoint: decoder.read_u64()?,
            exit_close_checkpoint: decoder.read_u64()?,
            activation_checkpoint: decoder.read_u64()?,
            overlap_end_checkpoint: decoder.read_u64()?,
        })
    }
}

/// A versioned, chain-independent projection of the genesis protocol manifest.
///
/// The outer tag is part of the canonical bytes and makes future projection
/// schemas fail closed. Version 1 covers every field in the current Gate A
/// [`ProtocolManifest`]. That manifest contains no chain-derived fields, so the
/// projection retains every field literally. A later manifest schema with a
/// chain-derived field requires a new explicit projection version rather than
/// silently changing this one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GenesisManifestTemplate {
    /// The complete version-one projection.
    V1(GenesisManifestTemplateV1),
}

impl GenesisManifestTemplate {
    /// Returns the version-one projection fields.
    #[must_use]
    pub const fn as_v1(&self) -> &GenesisManifestTemplateV1 {
        match self {
            Self::V1(template) => template,
        }
    }

    /// Derives the identity of this exact canonical template.
    ///
    /// Structural manifest validation runs before encoding and hashing. In
    /// particular, a predecessor-bound successor cannot be represented as a
    /// genesis template merely by using this type's wire tag.
    ///
    /// # Errors
    ///
    /// Returns a manifest structural error, a genesis-only projection error,
    /// or an encoding/hash framing error.
    pub fn hash(&self) -> Result<GenesisManifestTemplateHash, ProfileError> {
        self.validate_structure()?;
        let bytes = self.to_canonical_bytes()?;
        domain_hash(hash_domains::GENESIS_MANIFEST_TEMPLATE, &[&bytes])
            .map(GenesisManifestTemplateHash::new)
            .map_err(ProfileError::from)
    }

    /// Verifies that a final genesis manifest has this exact projection.
    ///
    /// Equality is checked over the complete typed projection, not only its
    /// digest. The digest pair in a mismatch is diagnostic and deterministic.
    /// The expected template is validated first, followed by full structural
    /// validation and genesis-only projection of `final_manifest`.
    ///
    /// # Errors
    ///
    /// Returns the first structural or genesis-only projection error, followed
    /// by [`ProfileError::GenesisManifestProjectionMismatch`] when both sides
    /// are valid but differ.
    pub fn verify_final_manifest_projection(
        &self,
        final_manifest: &ProtocolManifest,
    ) -> Result<(), ProfileError> {
        self.validate_structure()?;
        let actual = final_manifest.genesis_template()?;
        if actual != *self {
            return Err(ProfileError::GenesisManifestProjectionMismatch {
                expected: self.hash()?,
                actual: actual.hash()?,
            });
        }
        Ok(())
    }

    fn validate_structure(&self) -> Result<(), ProfileError> {
        match self {
            Self::V1(template) => template.validate_structure(),
        }
    }
}

impl CanonicalEncode for GenesisManifestTemplate {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::V1(template) => {
                encoder.write_u8(GENESIS_MANIFEST_TEMPLATE_VERSION);
                template.encode_fields(encoder)
            }
        }
    }
}

impl CanonicalDecode for GenesisManifestTemplate {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match decoder.read_tag(GENESIS_MANIFEST_TEMPLATE_TAGS)? {
            GENESIS_MANIFEST_TEMPLATE_VERSION => {
                GenesisManifestTemplateV1::decode_fields(decoder).map(Self::V1)
            }
            _ => unreachable!("tag was checked before conversion"),
        }
    }
}

/// Fields in the version-one genesis-manifest projection.
///
/// Construction is deliberately limited to canonical decoding and
/// [`ProtocolManifest::genesis_template`]. Decoding establishes only wire
/// canonicality; [`GenesisManifestTemplate::hash`] and projection verification
/// run the complete current manifest structural and genesis-only checks before
/// treating decoded fields as a valid template.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenesisManifestTemplateV1 {
    protocol_major: u32,
    chain_constitution_hash: Hash32,
    predecessor_manifest_hash: ManifestHash,
    upgrade_schedule: UpgradeSchedule,
    module_descriptors: Vec<ModuleDescriptor>,
}

impl GenesisManifestTemplateV1 {
    /// Returns the projected protocol major version.
    #[must_use]
    pub const fn protocol_major(&self) -> u32 {
        self.protocol_major
    }

    /// Returns the projected immutable chain-constitution hash.
    #[must_use]
    pub const fn chain_constitution_hash(&self) -> Hash32 {
        self.chain_constitution_hash
    }

    /// Returns the projected zero predecessor sentinel.
    #[must_use]
    pub const fn predecessor_manifest_hash(&self) -> ManifestHash {
        self.predecessor_manifest_hash
    }

    /// Returns the projected genesis schedule.
    #[must_use]
    pub const fn upgrade_schedule(&self) -> &UpgradeSchedule {
        &self.upgrade_schedule
    }

    /// Returns all projected module descriptors in canonical module-ID order.
    #[must_use]
    pub fn module_descriptors(&self) -> &[ModuleDescriptor] {
        &self.module_descriptors
    }

    fn validate_structure(&self) -> Result<(), ProfileError> {
        let manifest = ProtocolManifest::new(
            self.protocol_major,
            self.chain_constitution_hash,
            self.predecessor_manifest_hash,
            self.upgrade_schedule,
            self.module_descriptors.clone(),
        )?;
        if !matches!(manifest.upgrade_schedule, UpgradeSchedule::Genesis) {
            return Err(ProfileError::SuccessorRequiresTransitionActivation);
        }
        Ok(())
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_u32(self.protocol_major);
        self.chain_constitution_hash.encode(encoder)?;
        self.predecessor_manifest_hash.encode(encoder)?;
        self.upgrade_schedule.encode(encoder)?;
        encoder.write_sorted_unique(&self.module_descriptors)
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            protocol_major: decoder.read_u32()?,
            chain_constitution_hash: Hash32::decode(decoder)?,
            predecessor_manifest_hash: ManifestHash::decode(decoder)?,
            upgrade_schedule: UpgradeSchedule::decode(decoder)?,
            module_descriptors: decoder.read_sorted_unique(MAX_MODULES)?,
        })
    }
}

/// Closed derivation recipes committed by the canonical genesis-object template.
///
/// Version one defines a deterministic non-PoW state anchor. It deliberately
/// contains no target, timestamp, nonce, reward, work, parent, or graph-vertex
/// field. Adding or reinterpreting a recipe is a wire-format change and
/// requires a new template version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum GenesisObjectRecipe {
    /// Five-input genesis commitment defined by [`derive_genesis_commitment`].
    FiveInputGenesisCommitmentV1 = 1,
    /// Immutable chain domain defined by [`derive_chain_domain`].
    ChainDomainV1 = 2,
    /// Chain-bound hash of the exact activated genesis manifest.
    ProtocolManifestHashV1 = 3,
    /// Profile domain for the exact activated genesis manifest.
    ProfileDomainV1 = 4,
    /// Transparent checkpoint-zero logical-state digest.
    TransparentCheckpointZeroStateDigestV1 = 5,
    /// Transparent checkpoint-zero identifier derived from that state digest.
    TransparentCheckpointZeroIdV1 = 6,
}

impl GenesisObjectRecipe {
    /// Recipes in the exact order used by template version one.
    pub const ORDERED: [Self; 6] = [
        Self::FiveInputGenesisCommitmentV1,
        Self::ChainDomainV1,
        Self::ProtocolManifestHashV1,
        Self::ProfileDomainV1,
        Self::TransparentCheckpointZeroStateDigestV1,
        Self::TransparentCheckpointZeroIdV1,
    ];

    /// Returns the stable canonical tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

/// Chain-independent projection of the deterministic genesis state anchor.
///
/// The distinct `0xa0` object tag prevents this 236-byte template from being
/// confused with the earlier reduced receipt template. Version one retains
/// the literal protocol major and allocation-template hash, then commits six
/// all-zero derived slots paired with closed recipes. The final object is not
/// a proof-of-work vertex; the first ordinary child is the first mined vertex.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GenesisObjectTemplate {
    /// Deterministic non-PoW state-anchor template version one.
    V1(GenesisObjectTemplateV1),
}

impl GenesisObjectTemplate {
    /// Projects exact, validated chain-independent genesis inputs.
    ///
    /// # Errors
    ///
    /// Returns the first structural or genesis-only manifest-template error.
    pub fn from_genesis_inputs(
        manifest_template: &GenesisManifestTemplate,
        allocation_template_hash: GenesisAllocationTemplateHash,
    ) -> Result<Self, ProfileError> {
        manifest_template.validate_structure()?;
        Ok(Self::V1(GenesisObjectTemplateV1 {
            protocol_major: manifest_template.as_v1().protocol_major(),
            allocation_template_hash,
        }))
    }

    /// Returns the version-one fields.
    #[must_use]
    pub const fn as_v1(&self) -> &GenesisObjectTemplateV1 {
        match self {
            Self::V1(template) => template,
        }
    }

    /// Returns the literal protocol major retained by this template.
    #[must_use]
    pub const fn protocol_major(&self) -> u32 {
        self.as_v1().protocol_major
    }

    /// Returns the exact chain-independent allocation-template hash.
    #[must_use]
    pub const fn genesis_allocation_template_hash(&self) -> GenesisAllocationTemplateHash {
        self.as_v1().allocation_template_hash
    }

    /// Returns the ordered closed recipe set committed by version one.
    #[must_use]
    pub const fn recipes(&self) -> &'static [GenesisObjectRecipe; 6] {
        &GenesisObjectRecipe::ORDERED
    }

    /// Hashes the exact canonical state-anchor projection.
    ///
    /// # Errors
    ///
    /// Returns a canonical encoding or domain-hash framing error.
    pub fn hash(&self) -> Result<GenesisObjectTemplateHash, ProfileError> {
        let bytes = self.to_canonical_bytes()?;
        domain_hash(hash_domains::GENESIS_OBJECT_TEMPLATE, &[&bytes])
            .map(GenesisObjectTemplateHash::new)
            .map_err(ProfileError::from)
    }
}

impl CanonicalEncode for GenesisObjectTemplate {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_u8(GENESIS_OBJECT_TEMPLATE_TAG);
        match self {
            Self::V1(template) => {
                encoder.write_u8(GENESIS_OBJECT_TEMPLATE_VERSION);
                template.encode_fields(encoder)?;
            }
        }
        Ok(())
    }
}

impl CanonicalDecode for GenesisObjectTemplate {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decoder.read_tag(GENESIS_OBJECT_TEMPLATE_TAGS)?;
        match decoder.read_tag(GENESIS_OBJECT_TEMPLATE_VERSIONS)? {
            GENESIS_OBJECT_TEMPLATE_VERSION => {
                GenesisObjectTemplateV1::decode_fields(decoder).map(Self::V1)
            }
            _ => unreachable!("version was checked before conversion"),
        }
    }
}

/// Literal fields in genesis-object-template version one.
///
/// Construction is limited to canonical decoding and projection from exact
/// validated genesis inputs. All derived slots and recipes are fixed by the
/// enclosing version and cannot be selected by a caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenesisObjectTemplateV1 {
    protocol_major: u32,
    allocation_template_hash: GenesisAllocationTemplateHash,
}

impl GenesisObjectTemplateV1 {
    /// Returns the retained genesis protocol major.
    #[must_use]
    pub const fn protocol_major(&self) -> u32 {
        self.protocol_major
    }

    /// Returns the exact chain-independent allocation-template hash.
    #[must_use]
    pub const fn genesis_allocation_template_hash(&self) -> GenesisAllocationTemplateHash {
        self.allocation_template_hash
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_u32(self.protocol_major);
        self.allocation_template_hash.encode(encoder)?;
        for recipe in GenesisObjectRecipe::ORDERED {
            encoder.write_fixed(&ZERO_DERIVED_HASH_PLACEHOLDER);
            encoder.write_u8(recipe.tag());
        }
        Ok(())
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let protocol_major = decoder.read_u32()?;
        let allocation_template_hash = GenesisAllocationTemplateHash::decode(decoder)?;
        for expected in GenesisObjectRecipe::ORDERED {
            let placeholder_offset = decoder.position();
            let placeholder = decoder.read_fixed::<{ Hash32::LENGTH }>()?;
            if placeholder != ZERO_DERIVED_HASH_PLACEHOLDER {
                return Err(DecodeError::NonZeroPlaceholder {
                    offset: placeholder_offset,
                });
            }
            decoder.read_tag(&[expected.tag()])?;
        }
        Ok(Self {
            protocol_major,
            allocation_template_hash,
        })
    }
}

/// Closed derivation recipes committed by the reduced Gate A genesis receipt.
///
/// These tags describe values the current prototype can already derive. They
/// do not describe a proof-of-work vertex, bootstrap target, timestamp, reward,
/// nonce, body root, or [`silk_types::GenesisId`]. Adding or reinterpreting a
/// recipe is a wire-format change and requires a new receipt-template version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum GateAGenesisReceiptRecipe {
    /// Five-input genesis commitment defined by [`derive_genesis_commitment`].
    FiveInputGenesisCommitmentV1 = 1,
    /// Immutable chain domain defined by [`derive_chain_domain`].
    ChainDomainV1 = 2,
    /// Chain-bound hash of the exact activated genesis manifest.
    ProtocolManifestHashV1 = 3,
    /// Profile domain for the exact activated genesis manifest.
    ProfileDomainV1 = 4,
    /// Transparent checkpoint-zero logical-state digest.
    TransparentCheckpointZeroStateDigestV1 = 5,
    /// Transparent checkpoint-zero identifier derived from that state digest.
    TransparentCheckpointZeroIdV1 = 6,
}

impl GateAGenesisReceiptRecipe {
    /// Recipes in the exact order used by the template and materialized receipt.
    pub const ORDERED: [Self; 6] = [
        Self::FiveInputGenesisCommitmentV1,
        Self::ChainDomainV1,
        Self::ProtocolManifestHashV1,
        Self::ProfileDomainV1,
        Self::TransparentCheckpointZeroStateDigestV1,
        Self::TransparentCheckpointZeroIdV1,
    ];

    /// Returns the stable canonical tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

/// A typed, versioned template for the reduced no-value Gate A genesis receipt.
///
/// This deliberately is not [`GenesisObjectTemplate`]. Version one retains the
/// literal `protocol_major` and commits six all-zero derived-field slots paired
/// with closed recipe tags. It closed A2a-5's former arbitrary test input and
/// remains as detached diagnostic evidence after A2a-6 replaces it in the
/// object-template commitment slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GateAGenesisReceiptTemplate {
    /// The complete reduced receipt-template version one.
    V1(GateAGenesisReceiptTemplateV1),
}

impl GateAGenesisReceiptTemplate {
    /// Projects the exact current genesis manifest into a reduced receipt template.
    ///
    /// # Errors
    ///
    /// Returns the first structural or genesis-only manifest-template error.
    pub fn from_genesis_manifest_template(
        manifest_template: &GenesisManifestTemplate,
    ) -> Result<Self, ProfileError> {
        manifest_template.validate_structure()?;
        Ok(Self::V1(GateAGenesisReceiptTemplateV1 {
            protocol_major: manifest_template.as_v1().protocol_major(),
        }))
    }

    /// Returns the literal protocol major retained by this template.
    #[must_use]
    pub const fn protocol_major(&self) -> u32 {
        match self {
            Self::V1(template) => template.protocol_major,
        }
    }

    /// Returns the ordered closed recipe set committed by version one.
    #[must_use]
    pub const fn recipes(&self) -> &'static [GateAGenesisReceiptRecipe; 6] {
        &GateAGenesisReceiptRecipe::ORDERED
    }

    /// Reproduces the historical A2a-5 object-slot hash of this reduced template.
    ///
    /// Current genesis identity derivation does not consume this value; it is
    /// retained only so the detached A2a-5 fixture remains reproducible. It
    /// must not be substituted for [`GenesisObjectTemplate::hash`]. Its return
    /// type is intentionally incompatible with [`GenesisObjectTemplateHash`].
    ///
    /// # Errors
    ///
    /// Returns a canonical encoding or domain-hash framing error.
    pub fn historical_a2a5_object_slot_hash(
        &self,
    ) -> Result<GateAGenesisReceiptTemplateHash, ProfileError> {
        let bytes = self.to_canonical_bytes()?;
        domain_hash(hash_domains::GENESIS_OBJECT_TEMPLATE, &[&bytes])
            .map(GateAGenesisReceiptTemplateHash::new)
            .map_err(ProfileError::from)
    }
}

// Lock the real method boundary, not merely a locally constructed value: the
// historical receipt hash must never regress to the current object-template
// hash type without failing compilation.
const _: fn(&GateAGenesisReceiptTemplate) -> Result<GateAGenesisReceiptTemplateHash, ProfileError> =
    GateAGenesisReceiptTemplate::historical_a2a5_object_slot_hash;

impl CanonicalEncode for GateAGenesisReceiptTemplate {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::V1(template) => {
                encoder.write_u8(GATE_A_GENESIS_RECEIPT_TEMPLATE_VERSION);
                template.encode_fields(encoder);
                Ok(())
            }
        }
    }
}

impl CanonicalDecode for GateAGenesisReceiptTemplate {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match decoder.read_tag(GATE_A_GENESIS_RECEIPT_TEMPLATE_TAGS)? {
            GATE_A_GENESIS_RECEIPT_TEMPLATE_VERSION => {
                GateAGenesisReceiptTemplateV1::decode_fields(decoder).map(Self::V1)
            }
            _ => unreachable!("tag was checked before conversion"),
        }
    }
}

/// Literal fields in reduced Gate A genesis receipt-template version one.
///
/// Construction is limited to canonical decoding and projection from a valid
/// [`GenesisManifestTemplate`]. All derived slots and recipe tags are fixed by
/// the enclosing version and therefore cannot be selected by a caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GateAGenesisReceiptTemplateV1 {
    protocol_major: u32,
}

impl GateAGenesisReceiptTemplateV1 {
    /// Returns the retained genesis protocol major.
    #[must_use]
    pub const fn protocol_major(&self) -> u32 {
        self.protocol_major
    }

    fn encode_fields(&self, encoder: &mut Encoder) {
        encoder.write_u32(self.protocol_major);
        for recipe in GateAGenesisReceiptRecipe::ORDERED {
            encoder.write_fixed(&ZERO_DERIVED_HASH_PLACEHOLDER);
            encoder.write_u8(recipe.tag());
        }
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let protocol_major = decoder.read_u32()?;
        for expected in GateAGenesisReceiptRecipe::ORDERED {
            let placeholder_offset = decoder.position();
            let placeholder = decoder.read_fixed::<{ Hash32::LENGTH }>()?;
            if placeholder != ZERO_DERIVED_HASH_PLACEHOLDER {
                return Err(DecodeError::NonZeroPlaceholder {
                    offset: placeholder_offset,
                });
            }
            decoder.read_tag(&[expected.tag()])?;
        }
        Ok(Self { protocol_major })
    }
}

/// Gate A's module-bearing projection of a protocol manifest.
///
/// Later slices add suite/policy schedules and transition commitments. This
/// projection already binds the immutable constitution, predecessor,
/// fail-closed upgrade schedule, and complete sorted module descriptor set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolManifest {
    protocol_major: u32,
    chain_constitution_hash: Hash32,
    predecessor_manifest_hash: ManifestHash,
    upgrade_schedule: UpgradeSchedule,
    module_descriptors: Vec<ModuleDescriptor>,
}

impl ProtocolManifest {
    /// Constructs a structurally canonical manifest.
    ///
    /// Full dependency, authority, capability, and local-support checks happen
    /// in [`ProfileValidator::validate`].
    ///
    /// # Errors
    ///
    /// Returns an error unless descriptors are strictly sorted by module ID,
    /// unique, and individually content-addressed.
    pub fn new(
        protocol_major: u32,
        chain_constitution_hash: Hash32,
        predecessor_manifest_hash: ManifestHash,
        upgrade_schedule: UpgradeSchedule,
        module_descriptors: Vec<ModuleDescriptor>,
    ) -> Result<Self, ProfileError> {
        let manifest = Self {
            protocol_major,
            chain_constitution_hash,
            predecessor_manifest_hash,
            upgrade_schedule,
            module_descriptors,
        };
        manifest.validate_structure()?;
        Ok(manifest)
    }

    /// Returns the profile's protocol major version.
    #[must_use]
    pub const fn protocol_major(&self) -> u32 {
        self.protocol_major
    }

    /// Returns the repeated immutable chain-constitution hash.
    #[must_use]
    pub const fn chain_constitution_hash(&self) -> Hash32 {
        self.chain_constitution_hash
    }

    /// Returns the predecessor manifest, or the explicit zero sentinel at genesis.
    #[must_use]
    pub const fn predecessor_manifest_hash(&self) -> ManifestHash {
        self.predecessor_manifest_hash
    }

    /// Returns the content-addressed genesis or successor timing schedule.
    #[must_use]
    pub const fn upgrade_schedule(&self) -> &UpgradeSchedule {
        &self.upgrade_schedule
    }

    /// Returns the declared activation checkpoint.
    #[must_use]
    pub const fn activation_checkpoint(&self) -> u64 {
        self.upgrade_schedule.activation_checkpoint()
    }

    /// Returns the complete descriptor set in canonical module-ID order.
    #[must_use]
    pub fn module_descriptors(&self) -> &[ModuleDescriptor] {
        &self.module_descriptors
    }

    /// Derives `H("Silk-Protocol-Manifest", chain_domain, CanonicalEncode(self))`.
    ///
    /// # Errors
    ///
    /// Returns an error if canonical encoding or framed hashing fails.
    pub fn manifest_hash(&self, chain_domain: ChainDomain) -> Result<ManifestHash, ProfileError> {
        self.validate_structure()?;
        let bytes = self.to_canonical_bytes()?;
        domain_hash(
            hash_domains::PROTOCOL_MANIFEST,
            &[chain_domain.as_bytes(), &bytes],
        )
        .map(ManifestHash::new)
        .map_err(ProfileError::from)
    }

    /// Constructs the complete canonical version-one genesis projection.
    ///
    /// The current manifest contains no chain-derived fields, so every field is
    /// retained literally. The explicit destructuring makes any later manifest
    /// field addition a compile-time projection decision.
    ///
    /// # Errors
    ///
    /// Returns structural manifest errors first, then
    /// [`ProfileError::SuccessorRequiresTransitionActivation`] when called for
    /// a predecessor-bound successor rather than genesis.
    pub fn genesis_template(&self) -> Result<GenesisManifestTemplate, ProfileError> {
        self.validate_structure()?;
        if !matches!(self.upgrade_schedule, UpgradeSchedule::Genesis) {
            return Err(ProfileError::SuccessorRequiresTransitionActivation);
        }

        let Self {
            protocol_major,
            chain_constitution_hash,
            predecessor_manifest_hash,
            upgrade_schedule,
            module_descriptors,
        } = self;
        Ok(GenesisManifestTemplate::V1(GenesisManifestTemplateV1 {
            protocol_major: *protocol_major,
            chain_constitution_hash: *chain_constitution_hash,
            predecessor_manifest_hash: *predecessor_manifest_hash,
            upgrade_schedule: *upgrade_schedule,
            module_descriptors: module_descriptors.clone(),
        }))
    }

    /// Compatibility wrapper for the canonical genesis-template hash.
    ///
    /// This delegates to [`ProtocolManifest::genesis_template`] and
    /// [`GenesisManifestTemplate::hash`], preserving the pre-existing bytes and
    /// hash while keeping one normative projection implementation.
    ///
    /// # Errors
    ///
    /// Returns structural manifest errors first, then
    /// [`ProfileError::SuccessorRequiresTransitionActivation`] when called for
    /// a predecessor-bound successor rather than genesis.
    pub fn genesis_template_hash(&self) -> Result<GenesisManifestTemplateHash, ProfileError> {
        self.genesis_template()?.hash()
    }

    fn validate_structure(&self) -> Result<(), ProfileError> {
        self.upgrade_schedule
            .validate_for_predecessor(self.predecessor_manifest_hash)?;
        ensure_limit(
            "manifest module descriptors",
            self.module_descriptors.len(),
            MAX_MODULES,
        )?;
        map_collection(
            "manifest module descriptors",
            validate_sorted_unique(&self.module_descriptors),
        )?;
        for descriptor in &self.module_descriptors {
            descriptor.validate_structure()?;
        }
        Ok(())
    }
}

impl CanonicalEncode for ProtocolManifest {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_u32(self.protocol_major);
        self.chain_constitution_hash.encode(encoder)?;
        self.predecessor_manifest_hash.encode(encoder)?;
        self.upgrade_schedule.encode(encoder)?;
        encoder.write_sorted_unique(&self.module_descriptors)?;
        Ok(())
    }
}

impl CanonicalDecode for ProtocolManifest {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            protocol_major: decoder.read_u32()?,
            chain_constitution_hash: Hash32::decode(decoder)?,
            predecessor_manifest_hash: ManifestHash::decode(decoder)?,
            upgrade_schedule: UpgradeSchedule::decode(decoder)?,
            module_descriptors: decoder.read_sorted_unique(MAX_MODULES)?,
        })
    }
}

/// A consistently derived chain-independent genesis identity trusted by a release.
///
/// All fields are private and the only constructor derives the manifest hash,
/// constitution, allocation hash, deterministic state-anchor template hash,
/// complete genesis commitment, and chain domain from exact typed inputs. The
/// reduced Gate A receipt template is retained only as detached diagnostic
/// evidence and does not occupy the object-template commitment slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivedGenesisIdentity {
    genesis_manifest_template: GenesisManifestTemplate,
    genesis_object_template: GenesisObjectTemplate,
    gate_a_genesis_receipt_template: GateAGenesisReceiptTemplate,
    chain_constitution_hash: Hash32,
    genesis_manifest_template_hash: GenesisManifestTemplateHash,
    genesis_allocation_template_hash: GenesisAllocationTemplateHash,
    genesis_object_template_hash: GenesisObjectTemplateHash,
    genesis_commitment: GenesisCommitment,
    chain_domain: ChainDomain,
}

impl DerivedGenesisIdentity {
    /// Derives a self-consistent genesis identity from exact trusted inputs.
    ///
    /// The manifest-template hash and constitution are derived from the same
    /// structurally valid typed template retained for activation. The same
    /// allocation-template byte slice is used both for its diagnostic hash and
    /// as the direct allocation-template part of the normative genesis
    /// commitment. No value is learned from a candidate manifest here.
    ///
    /// # Errors
    ///
    /// Returns the first manifest-template structural or genesis-only error,
    /// followed by a domain-hash framing error if any supplied byte length
    /// cannot be represented by the version-1 transcript.
    pub fn derive(
        network_id: &[u8],
        genesis_manifest_template: GenesisManifestTemplate,
        canonical_allocation_template_bytes: &[u8],
    ) -> Result<Self, ProfileError> {
        let genesis_manifest_template_hash = genesis_manifest_template.hash()?;
        let genesis_allocation_template_hash =
            derive_genesis_allocation_template_hash(canonical_allocation_template_bytes)?;
        let genesis_object_template = GenesisObjectTemplate::from_genesis_inputs(
            &genesis_manifest_template,
            genesis_allocation_template_hash,
        )?;
        let genesis_object_template_hash = genesis_object_template.hash()?;
        let gate_a_genesis_receipt_template =
            GateAGenesisReceiptTemplate::from_genesis_manifest_template(
                &genesis_manifest_template,
            )?;
        let chain_constitution_hash = genesis_manifest_template.as_v1().chain_constitution_hash();
        let genesis_commitment = derive_genesis_commitment(
            network_id,
            chain_constitution_hash,
            genesis_manifest_template_hash,
            canonical_allocation_template_bytes,
            genesis_object_template_hash,
        )?;
        let chain_domain = derive_chain_domain(network_id, genesis_commitment)?;
        Ok(Self {
            genesis_manifest_template,
            genesis_object_template,
            gate_a_genesis_receipt_template,
            chain_constitution_hash,
            genesis_manifest_template_hash,
            genesis_allocation_template_hash,
            genesis_object_template_hash,
            genesis_commitment,
            chain_domain,
        })
    }

    /// Returns the exact typed genesis-manifest projection retained by this identity.
    #[must_use]
    pub const fn genesis_manifest_template(&self) -> &GenesisManifestTemplate {
        &self.genesis_manifest_template
    }

    /// Returns the exact deterministic genesis state-anchor template.
    #[must_use]
    pub const fn genesis_object_template(&self) -> &GenesisObjectTemplate {
        &self.genesis_object_template
    }

    /// Returns the exact reduced Gate A genesis receipt template.
    #[must_use]
    pub const fn gate_a_genesis_receipt_template(&self) -> &GateAGenesisReceiptTemplate {
        &self.gate_a_genesis_receipt_template
    }

    /// Returns the constitution committed by this genesis identity.
    #[must_use]
    pub const fn chain_constitution_hash(&self) -> Hash32 {
        self.chain_constitution_hash
    }

    /// Returns the exact genesis-manifest projection hash.
    #[must_use]
    pub const fn genesis_manifest_template_hash(&self) -> GenesisManifestTemplateHash {
        self.genesis_manifest_template_hash
    }

    /// Returns the hash of the exact canonical allocation-template bytes.
    #[must_use]
    pub const fn genesis_allocation_template_hash(&self) -> GenesisAllocationTemplateHash {
        self.genesis_allocation_template_hash
    }

    /// Returns the deterministic non-PoW state-anchor template hash committed
    /// by the five-input genesis derivation.
    #[must_use]
    pub const fn genesis_object_template_hash(&self) -> GenesisObjectTemplateHash {
        self.genesis_object_template_hash
    }

    /// Returns the complete non-circular genesis commitment.
    #[must_use]
    pub const fn genesis_commitment(&self) -> GenesisCommitment {
        self.genesis_commitment
    }

    /// Returns the immutable chain domain derived from this identity.
    #[must_use]
    pub const fn chain_domain(&self) -> ChainDomain {
        self.chain_domain
    }
}

/// Trusted validator configuration bundled with one client release.
#[derive(Clone, Debug)]
pub struct ProfileValidator {
    constitutional_caps: ConstitutionalCaps,
    supported_module_ids: BTreeSet<ModuleId>,
    trusted_genesis_pin: Option<GenesisProfilePin>,
}

impl ProfileValidator {
    /// Creates a validator from trusted constitution data and locally
    /// implemented module IDs.
    #[must_use]
    pub const fn new(
        constitutional_caps: ConstitutionalCaps,
        supported_module_ids: BTreeSet<ModuleId>,
    ) -> Self {
        Self {
            constitutional_caps,
            supported_module_ids,
            trusted_genesis_pin: None,
        }
    }

    /// Creates a validator which may activate exactly one pinned genesis profile.
    ///
    /// The pin is trusted release configuration, not data learned from the
    /// manifest being validated. Ordinary [`Self::new`] validators remain able
    /// to validate profiles but cannot mint an [`ExecutionProfile`].
    #[must_use]
    pub const fn new_with_genesis_pin(
        constitutional_caps: ConstitutionalCaps,
        supported_module_ids: BTreeSet<ModuleId>,
        trusted_genesis_pin: GenesisProfilePin,
    ) -> Self {
        Self {
            constitutional_caps,
            supported_module_ids,
            trusted_genesis_pin: Some(trusted_genesis_pin),
        }
    }

    /// Validates a complete manifest and derives its manifest/profile identities.
    ///
    /// # Errors
    ///
    /// Rejects malformed identities and collections, an unexpected
    /// constitution, unsupported modules, incomplete or cyclic dependencies,
    /// missing/duplicate exclusive authorities, and any capability widening.
    pub fn validate(
        &self,
        chain_domain: ChainDomain,
        manifest: ProtocolManifest,
    ) -> Result<ValidatedProfile, ProfileError> {
        manifest.validate_structure()?;
        if manifest.chain_constitution_hash != self.constitutional_caps.chain_constitution_hash {
            return Err(ProfileError::ConstitutionMismatch {
                expected: self.constitutional_caps.chain_constitution_hash,
                actual: manifest.chain_constitution_hash,
            });
        }

        let modules: BTreeMap<ModuleId, &ModuleDescriptor> = manifest
            .module_descriptors
            .iter()
            .map(|descriptor| (descriptor.module_id, descriptor))
            .collect();

        for descriptor in &manifest.module_descriptors {
            if !self.supported_module_ids.contains(&descriptor.module_id) {
                return Err(ProfileError::UnsupportedModule(descriptor.module_id));
            }
            let cap = self
                .constitutional_caps
                .cap_for(descriptor.module_type)
                .ok_or(ProfileError::MissingRoleCap(descriptor.module_type))?;
            ensure_subset(
                descriptor,
                CapabilityKind::Read,
                &descriptor.declared_state_reads,
                &cap.max_state_reads,
            )?;
            ensure_subset(
                descriptor,
                CapabilityKind::Write,
                &descriptor.declared_state_writes,
                &cap.max_state_writes,
            )?;
            for dependency in &descriptor.dependency_ids {
                if !modules.contains_key(dependency) {
                    return Err(ProfileError::MissingDependency {
                        module: descriptor.module_id,
                        dependency: *dependency,
                    });
                }
            }
        }

        validate_exclusive_roles(&manifest.module_descriptors)?;
        validate_acyclic(&modules)?;

        let manifest_hash = manifest.manifest_hash(chain_domain)?;
        let profile_domain =
            derive_profile_domain(chain_domain, manifest.protocol_major, manifest_hash)?;
        Ok(ValidatedProfile {
            chain_domain,
            manifest,
            manifest_hash,
            profile_domain,
        })
    }

    /// Canonical-decodes and validates a manifest in one fail-closed operation.
    ///
    /// # Errors
    ///
    /// Returns structural decoding errors, including unknown tags and trailing
    /// bytes, or any semantic validation error from [`Self::validate`].
    pub fn decode_and_validate(
        &self,
        chain_domain: ChainDomain,
        bytes: &[u8],
    ) -> Result<ValidatedProfile, ProfileError> {
        let manifest = ProtocolManifest::from_canonical_bytes(bytes)?;
        self.validate(chain_domain, manifest)
    }

    /// Validates and activates the one release-pinned genesis profile.
    ///
    /// Full structural, constitutional, support, dependency, authority, and
    /// capability validation runs before activation checks. A generic validator
    /// created with [`Self::new`] therefore cannot turn a merely valid manifest
    /// into execution authority.
    ///
    /// # Errors
    ///
    /// Returns any ordinary validation error first. Activation checks then have
    /// stable precedence: missing pin; successor schedule; pinned constitution;
    /// exact typed manifest projection; derived chain domain; final manifest hash;
    /// native-kernel module identity; and checkpoint module identity.
    pub fn validate_and_activate_genesis(
        &self,
        chain_domain: ChainDomain,
        manifest: ProtocolManifest,
    ) -> Result<ExecutionProfile, ProfileError> {
        let validated = self.validate(chain_domain, manifest)?;
        self.activate_validated_genesis(&validated)
    }

    /// Canonical-decodes, validates, and activates the release-pinned genesis.
    ///
    /// # Errors
    ///
    /// Returns structural decoding errors, including unknown tags and trailing
    /// bytes, followed by the validation and activation errors documented by
    /// [`Self::validate_and_activate_genesis`].
    pub fn decode_and_activate_genesis(
        &self,
        chain_domain: ChainDomain,
        bytes: &[u8],
    ) -> Result<ExecutionProfile, ProfileError> {
        let manifest = ProtocolManifest::from_canonical_bytes(bytes)?;
        self.validate_and_activate_genesis(chain_domain, manifest)
    }

    fn activate_validated_genesis(
        &self,
        validated: &ValidatedProfile,
    ) -> Result<ExecutionProfile, ProfileError> {
        let pin = self
            .trusted_genesis_pin
            .as_ref()
            .ok_or(ProfileError::MissingGenesisPin)?;
        if !matches!(
            validated.manifest.upgrade_schedule,
            UpgradeSchedule::Genesis
        ) {
            return Err(ProfileError::SuccessorRequiresTransitionActivation);
        }
        if validated.manifest.chain_constitution_hash != pin.identity.chain_constitution_hash {
            return Err(ProfileError::PinnedGenesisConstitutionMismatch {
                expected: pin.identity.chain_constitution_hash,
                actual: validated.manifest.chain_constitution_hash,
            });
        }
        if let Err(error) = pin
            .identity
            .genesis_manifest_template
            .verify_final_manifest_projection(&validated.manifest)
        {
            return match error {
                ProfileError::GenesisManifestProjectionMismatch { expected, actual } => {
                    Err(ProfileError::PinnedGenesisManifestTemplateMismatch { expected, actual })
                }
                other => Err(other),
            };
        }
        if validated.chain_domain != pin.identity.chain_domain {
            return Err(ProfileError::PinnedChainDomainMismatch {
                expected: pin.identity.chain_domain,
                actual: validated.chain_domain,
            });
        }
        if validated.manifest_hash != pin.genesis_manifest_hash {
            return Err(ProfileError::PinnedManifestMismatch {
                expected: pin.genesis_manifest_hash,
                actual: validated.manifest_hash,
            });
        }

        let native_kernel = validated
            .manifest
            .module_descriptors
            .iter()
            .find(|descriptor| descriptor.module_type == ModuleType::NativeKernel)
            .ok_or(ProfileError::MissingExclusiveRole(ModuleType::NativeKernel))?;
        if native_kernel.module_id != pin.native_kernel_module_id {
            return Err(ProfileError::PinnedNativeKernelMismatch {
                expected: pin.native_kernel_module_id,
                actual: native_kernel.module_id,
            });
        }

        let checkpoint = validated
            .manifest
            .module_descriptors
            .iter()
            .find(|descriptor| descriptor.module_type == ModuleType::Checkpoint)
            .ok_or(ProfileError::MissingExclusiveRole(ModuleType::Checkpoint))?;
        if checkpoint.module_id != pin.checkpoint_module_id {
            return Err(ProfileError::PinnedCheckpointMismatch {
                expected: pin.checkpoint_module_id,
                actual: checkpoint.module_id,
            });
        }

        Ok(ExecutionProfile {
            genesis_identity: pin.identity.clone(),
            manifest_hash: validated.manifest_hash,
            profile_domain: validated.profile_domain,
            native_kernel_module_id: native_kernel.module_id,
            native_kernel_abi_version: native_kernel.abi_version,
            checkpoint_module_id: checkpoint.module_id,
            checkpoint_abi_version: checkpoint.abi_version,
        })
    }
}

/// A manifest which passed all structural and release-local authority checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedProfile {
    chain_domain: ChainDomain,
    manifest: ProtocolManifest,
    manifest_hash: ManifestHash,
    profile_domain: ProfileDomain,
}

impl ValidatedProfile {
    /// Returns the immutable chain domain supplied to profile validation.
    #[must_use]
    pub const fn chain_domain(&self) -> ChainDomain {
        self.chain_domain
    }

    /// Returns the validated manifest.
    #[must_use]
    pub const fn manifest(&self) -> &ProtocolManifest {
        &self.manifest
    }

    /// Returns the content-derived manifest identity.
    #[must_use]
    pub const fn manifest_hash(&self) -> ManifestHash {
        self.manifest_hash
    }

    /// Returns the rule-dependent profile domain derived from the manifest.
    #[must_use]
    pub const fn profile_domain(&self) -> ProfileDomain {
        self.profile_domain
    }

    /// Consumes the wrapper and returns the validated manifest.
    #[must_use]
    pub fn into_manifest(self) -> ProtocolManifest {
        self.manifest
    }
}

/// Trusted release pin for the only profile permitted to create chain genesis.
///
/// This is local release configuration, not a consensus object and not a claim
/// that compiled code implements the pinned modules. Its identity retains the
/// exact trusted genesis-manifest and non-PoW state-anchor templates and binds
/// the remaining genesis commitments. The reduced receipt remains detached
/// diagnostic evidence. This pin does not validate the first mined child or
/// attest compiled code. An external compiled host must consume and enforce
/// both the native-kernel and checkpoint identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenesisProfilePin {
    identity: DerivedGenesisIdentity,
    genesis_manifest_hash: ManifestHash,
    native_kernel_module_id: ModuleId,
    checkpoint_module_id: ModuleId,
}

impl GenesisProfilePin {
    /// Constructs an exact trusted genesis activation pin.
    #[must_use]
    pub const fn new(
        identity: DerivedGenesisIdentity,
        genesis_manifest_hash: ManifestHash,
        native_kernel_module_id: ModuleId,
        checkpoint_module_id: ModuleId,
    ) -> Self {
        Self {
            identity,
            genesis_manifest_hash,
            native_kernel_module_id,
            checkpoint_module_id,
        }
    }

    /// Returns the only chain domain this pin may activate.
    #[must_use]
    pub const fn chain_domain(&self) -> ChainDomain {
        self.identity.chain_domain
    }

    /// Returns the complete trusted derived genesis identity.
    #[must_use]
    pub const fn identity(&self) -> &DerivedGenesisIdentity {
        &self.identity
    }

    /// Returns the trusted complete non-circular genesis commitment.
    #[must_use]
    pub const fn genesis_commitment(&self) -> GenesisCommitment {
        self.identity.genesis_commitment
    }

    /// Returns the trusted genesis-manifest projection hash.
    #[must_use]
    pub const fn genesis_manifest_template_hash(&self) -> GenesisManifestTemplateHash {
        self.identity.genesis_manifest_template_hash
    }

    /// Returns the trusted allocation-template byte hash.
    #[must_use]
    pub const fn genesis_allocation_template_hash(&self) -> GenesisAllocationTemplateHash {
        self.identity.genesis_allocation_template_hash
    }

    /// Returns the exact deterministic genesis state-anchor template.
    #[must_use]
    pub const fn genesis_object_template(&self) -> &GenesisObjectTemplate {
        &self.identity.genesis_object_template
    }

    /// Returns the exact reduced Gate A genesis receipt template.
    #[must_use]
    pub const fn gate_a_genesis_receipt_template(&self) -> &GateAGenesisReceiptTemplate {
        &self.identity.gate_a_genesis_receipt_template
    }

    /// Returns the deterministic state-anchor template hash committed by the
    /// genesis identity.
    #[must_use]
    pub const fn genesis_object_template_hash(&self) -> GenesisObjectTemplateHash {
        self.identity.genesis_object_template_hash
    }

    /// Returns the only genesis manifest hash this pin may activate.
    #[must_use]
    pub const fn genesis_manifest_hash(&self) -> ManifestHash {
        self.genesis_manifest_hash
    }

    /// Returns the exact native-kernel module required by the pinned manifest.
    #[must_use]
    pub const fn native_kernel_module_id(&self) -> ModuleId {
        self.native_kernel_module_id
    }

    /// Returns the exact checkpoint module required by the pinned manifest.
    #[must_use]
    pub const fn checkpoint_module_id(&self) -> ModuleId {
        self.checkpoint_module_id
    }
}

/// A sealed, release-pinned genesis profile suitable for execution binding.
///
/// Only [`ProfileValidator::validate_and_activate_genesis`] and
/// [`ProfileValidator::decode_and_activate_genesis`] can construct this type.
/// Valid successor manifests require a future transition-activation witness and
/// cannot be promoted merely because their standalone validation succeeds.
/// This token binds the exact trusted genesis-manifest and deterministic
/// non-PoW state-anchor templates plus the remaining genesis commitments. It
/// does not validate the first mined child or attest compiled code. An external
/// compiled host must consume and enforce both exposed module identities and
/// ABI versions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionProfile {
    genesis_identity: DerivedGenesisIdentity,
    manifest_hash: ManifestHash,
    profile_domain: ProfileDomain,
    native_kernel_module_id: ModuleId,
    native_kernel_abi_version: u16,
    checkpoint_module_id: ModuleId,
    checkpoint_abi_version: u16,
}

impl ExecutionProfile {
    /// Returns the pinned immutable chain domain.
    #[must_use]
    pub const fn chain_domain(&self) -> ChainDomain {
        self.genesis_identity.chain_domain
    }

    /// Returns the complete non-circular genesis commitment.
    #[must_use]
    pub const fn genesis_commitment(&self) -> GenesisCommitment {
        self.genesis_identity.genesis_commitment
    }

    /// Returns the activated genesis-manifest projection hash.
    #[must_use]
    pub const fn genesis_manifest_template_hash(&self) -> GenesisManifestTemplateHash {
        self.genesis_identity.genesis_manifest_template_hash
    }

    /// Returns the activated canonical allocation-template byte hash.
    #[must_use]
    pub const fn genesis_allocation_template_hash(&self) -> GenesisAllocationTemplateHash {
        self.genesis_identity.genesis_allocation_template_hash
    }

    /// Returns the exact deterministic genesis state-anchor template.
    #[must_use]
    pub const fn genesis_object_template(&self) -> &GenesisObjectTemplate {
        &self.genesis_identity.genesis_object_template
    }

    /// Returns the literal genesis protocol major committed by both templates.
    #[must_use]
    pub const fn protocol_major(&self) -> u32 {
        self.genesis_identity
            .gate_a_genesis_receipt_template
            .protocol_major()
    }

    /// Returns the exact reduced Gate A genesis receipt template.
    #[must_use]
    pub const fn gate_a_genesis_receipt_template(&self) -> &GateAGenesisReceiptTemplate {
        &self.genesis_identity.gate_a_genesis_receipt_template
    }

    /// Returns the deterministic state-anchor template hash committed by the
    /// genesis identity.
    #[must_use]
    pub const fn genesis_object_template_hash(&self) -> GenesisObjectTemplateHash {
        self.genesis_identity.genesis_object_template_hash
    }

    /// Returns the exact activated genesis manifest identity.
    #[must_use]
    pub const fn manifest_hash(&self) -> ManifestHash {
        self.manifest_hash
    }

    /// Returns the rule-dependent domain derived from the activated manifest.
    #[must_use]
    pub const fn profile_domain(&self) -> ProfileDomain {
        self.profile_domain
    }

    /// Returns the exact native-kernel semantic module identity.
    #[must_use]
    pub const fn native_kernel_module_id(&self) -> ModuleId {
        self.native_kernel_module_id
    }

    /// Returns the canonical host ABI version declared by the native kernel.
    #[must_use]
    pub const fn native_kernel_abi_version(&self) -> u16 {
        self.native_kernel_abi_version
    }

    /// Returns the exact checkpoint semantic module identity.
    #[must_use]
    pub const fn checkpoint_module_id(&self) -> ModuleId {
        self.checkpoint_module_id
    }

    /// Returns the canonical host ABI version declared by the checkpoint module.
    #[must_use]
    pub const fn checkpoint_abi_version(&self) -> u16 {
        self.checkpoint_abi_version
    }
}

/// Whether a rejected state-domain capability was a read or write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityKind {
    /// Read-only state view.
    Read,
    /// Typed state-effect builder.
    Write,
}

/// Deterministic profile construction or validation failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProfileError {
    /// Canonical byte construction failed.
    #[error(transparent)]
    Encode(#[from] EncodeError),
    /// Canonical byte decoding failed.
    #[error(transparent)]
    Decode(#[from] DecodeError),
    /// Domain-separated identity hashing failed.
    #[error(transparent)]
    Hash(#[from] DomainHashError),
    /// A consensus collection exceeded its explicit resource bound.
    #[error("{field} length {length} exceeds limit {max}")]
    ResourceLimitExceeded {
        /// Name of the bounded field.
        field: &'static str,
        /// Supplied element count.
        length: usize,
        /// Maximum accepted element count.
        max: usize,
    },
    /// A set-like descriptor, manifest, or constitution field was non-canonical.
    #[error("{field} is not sorted and unique: {source}")]
    NonCanonicalCollection {
        /// Name of the malformed field.
        field: &'static str,
        /// First duplicate or out-of-order position.
        source: CollectionError,
    },
    /// A claimed module ID did not match the complete descriptor content.
    #[error("module id {claimed} does not match recomputed id {computed}")]
    ModuleIdMismatch {
        /// ID serialized in the descriptor.
        claimed: ModuleId,
        /// ID derived from all semantic fields.
        computed: ModuleId,
    },
    /// The manifest's genesis/successor schedule or checkpoint order is invalid.
    #[error("invalid upgrade schedule: {reason}")]
    InvalidUpgradeSchedule {
        /// Stable human-readable explanation of the violated invariant.
        reason: &'static str,
    },
    /// The manifest names a chain constitution other than the configured one.
    #[error("manifest constitution {actual} does not match configured constitution {expected}")]
    ConstitutionMismatch {
        /// Locally configured immutable constitution.
        expected: Hash32,
        /// Constitution repeated in the manifest.
        actual: Hash32,
    },
    /// This release does not implement the named module semantics.
    #[error("unsupported module id {0}")]
    UnsupportedModule(ModuleId),
    /// No immutable role ceiling was configured for a used module type.
    #[error("missing constitutional capability cap for role {0:?}")]
    MissingRoleCap(ModuleType),
    /// A descriptor requested authority outside its role ceiling.
    #[error("module {module} exceeds its {kind:?} cap for {domain:?}")]
    CapabilityWidening {
        /// Module requesting the forbidden domain.
        module: ModuleId,
        /// Read or write authority.
        kind: CapabilityKind,
        /// State domain outside the constitutional maximum.
        domain: StateDomain,
    },
    /// A dependency ID was not present in the same complete manifest.
    #[error("module {module} requires missing dependency {dependency}")]
    MissingDependency {
        /// Dependent module.
        module: ModuleId,
        /// Absent dependency.
        dependency: ModuleId,
    },
    /// The dependency graph contained a cycle.
    #[error("module dependency cycle reaches {0}")]
    DependencyCycle(ModuleId),
    /// A required exclusive consensus role had no authoritative module.
    #[error("required exclusive role {0:?} is missing")]
    MissingExclusiveRole(ModuleType),
    /// A required exclusive consensus role had more than one authority.
    #[error("required exclusive role {0:?} has multiple modules")]
    DuplicateExclusiveRole(ModuleType),
    /// This validator has no trusted genesis activation pin.
    #[error("validator has no trusted genesis profile pin")]
    MissingGenesisPin,
    /// A valid successor still needs an independently verified transition activation.
    #[error("successor profile requires transition activation")]
    SuccessorRequiresTransitionActivation,
    /// A final genesis manifest does not reproduce the exact trusted projection.
    #[error("genesis manifest projection {actual} does not match template {expected}")]
    GenesisManifestProjectionMismatch {
        /// Hash of the complete expected typed projection.
        expected: GenesisManifestTemplateHash,
        /// Hash of the complete projection reconstructed from the final manifest.
        actual: GenesisManifestTemplateHash,
    },
    /// The validated manifest and trusted genesis identity name different constitutions.
    #[error("genesis constitution {actual} does not match pinned constitution {expected}")]
    PinnedGenesisConstitutionMismatch {
        /// Constitution fixed by the trusted derived genesis identity.
        expected: Hash32,
        /// Constitution repeated by the validated candidate manifest.
        actual: Hash32,
    },
    /// The validated genesis projection differs from the trusted template hash.
    #[error("genesis manifest template {actual} does not match pinned template {expected}")]
    PinnedGenesisManifestTemplateMismatch {
        /// Manifest-template hash fixed by trusted release configuration.
        expected: GenesisManifestTemplateHash,
        /// Hash recomputed from the validated candidate manifest.
        actual: GenesisManifestTemplateHash,
    },
    /// The supplied validation chain differs from the trusted derived chain.
    #[error("validated chain {actual} does not match pinned derived chain {expected}")]
    PinnedChainDomainMismatch {
        /// Chain derived by the trusted genesis identity.
        expected: ChainDomain,
        /// Chain supplied to ordinary profile validation.
        actual: ChainDomain,
    },
    /// A valid genesis did not match the exact trusted chain-bound manifest pin.
    #[error("validated genesis manifest {actual} does not match pinned manifest {expected}")]
    PinnedManifestMismatch {
        /// Genesis manifest hash fixed by trusted release configuration.
        expected: ManifestHash,
        /// Chain-bound hash of the validated manifest.
        actual: ManifestHash,
    },
    /// The manifest's native kernel differed from the trusted genesis pin.
    #[error("native kernel {actual} does not match pinned module {expected}")]
    PinnedNativeKernelMismatch {
        /// Native-kernel module fixed by trusted release configuration.
        expected: ModuleId,
        /// Native-kernel module declared by the validated genesis manifest.
        actual: ModuleId,
    },
    /// The manifest's checkpoint module differed from the trusted genesis pin.
    #[error("checkpoint module {actual} does not match pinned module {expected}")]
    PinnedCheckpointMismatch {
        /// Checkpoint module fixed by trusted release configuration.
        expected: ModuleId,
        /// Checkpoint module declared by the validated genesis manifest.
        actual: ModuleId,
    },
}

impl ProfileError {
    /// Returns a stable rejection code for differential fixtures.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Encode(error) => error.code(),
            Self::Decode(error) => error.code(),
            Self::Hash(error) => error.code(),
            Self::ResourceLimitExceeded { .. } => "profile.resource_limit_exceeded",
            Self::NonCanonicalCollection { source, .. } => source.code(),
            Self::ModuleIdMismatch { .. } => "profile.module_id_mismatch",
            Self::InvalidUpgradeSchedule { .. } => "profile.invalid_upgrade_schedule",
            Self::ConstitutionMismatch { .. } => "profile.constitution_mismatch",
            Self::UnsupportedModule(_) => "profile.unsupported_module",
            Self::MissingRoleCap(_) => "profile.missing_role_cap",
            Self::CapabilityWidening { .. } => "profile.capability_widening",
            Self::MissingDependency { .. } => "profile.missing_dependency",
            Self::DependencyCycle(_) => "profile.dependency_cycle",
            Self::MissingExclusiveRole(_) => "profile.missing_exclusive_role",
            Self::DuplicateExclusiveRole(_) => "profile.duplicate_exclusive_role",
            Self::MissingGenesisPin => "profile.missing_genesis_pin",
            Self::SuccessorRequiresTransitionActivation => {
                "profile.successor_requires_transition_activation"
            }
            Self::GenesisManifestProjectionMismatch { .. } => {
                "profile.genesis_manifest_projection_mismatch"
            }
            Self::PinnedGenesisConstitutionMismatch { .. } => {
                "profile.pinned_genesis_constitution_mismatch"
            }
            Self::PinnedGenesisManifestTemplateMismatch { .. } => {
                "profile.pinned_genesis_manifest_template_mismatch"
            }
            Self::PinnedChainDomainMismatch { .. } => "profile.pinned_chain_domain_mismatch",
            Self::PinnedManifestMismatch { .. } => "profile.pinned_manifest_mismatch",
            Self::PinnedNativeKernelMismatch { .. } => "profile.pinned_native_kernel_mismatch",
            Self::PinnedCheckpointMismatch { .. } => "profile.pinned_checkpoint_mismatch",
        }
    }
}

fn map_collection<T>(
    field: &'static str,
    result: Result<T, CollectionError>,
) -> Result<T, ProfileError> {
    result.map_err(|source| ProfileError::NonCanonicalCollection { field, source })
}

fn validate_descriptor_lists(
    dependencies: &[ModuleId],
    reads: &[StateDomain],
    writes: &[StateDomain],
) -> Result<(), ProfileError> {
    ensure_limit(
        "module dependencies",
        dependencies.len(),
        MAX_DEPENDENCIES_PER_MODULE,
    )?;
    ensure_limit(
        "module state reads",
        reads.len(),
        MAX_CAPABILITIES_PER_MODULE,
    )?;
    ensure_limit(
        "module state writes",
        writes.len(),
        MAX_CAPABILITIES_PER_MODULE,
    )?;
    map_collection("module dependencies", validate_sorted_unique(dependencies))?;
    map_collection("module state reads", validate_sorted_unique(reads))?;
    map_collection("module state writes", validate_sorted_unique(writes))?;
    Ok(())
}

const fn ensure_limit(field: &'static str, length: usize, max: usize) -> Result<(), ProfileError> {
    if length > max {
        return Err(ProfileError::ResourceLimitExceeded { field, length, max });
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn compute_module_id(
    module_type: ModuleType,
    abi_version: u16,
    normative_spec_hash: Hash32,
    interface_schema_hash: Hash32,
    conformance_vector_root: Hash32,
    parameter_hash: Hash32,
    dependency_ids: &[ModuleId],
    declared_state_reads: &[StateDomain],
    declared_state_writes: &[StateDomain],
) -> Result<ModuleId, ProfileError> {
    validate_descriptor_lists(dependency_ids, declared_state_reads, declared_state_writes)?;
    let dependencies = canonical_set_bytes(dependency_ids)?;
    let reads = canonical_set_bytes(declared_state_reads)?;
    let writes = canonical_set_bytes(declared_state_writes)?;
    let module_type = [module_type.tag()];
    let abi_version = abi_version.to_le_bytes();
    domain_hash(
        hash_domains::CONSENSUS_MODULE,
        &[
            &module_type,
            &abi_version,
            normative_spec_hash.as_bytes(),
            interface_schema_hash.as_bytes(),
            conformance_vector_root.as_bytes(),
            parameter_hash.as_bytes(),
            &dependencies,
            &reads,
            &writes,
        ],
    )
    .map(ModuleId::new)
    .map_err(ProfileError::from)
}

fn canonical_set_bytes<T: CanonicalEncode + Ord>(values: &[T]) -> Result<Vec<u8>, EncodeError> {
    let mut encoder = Encoder::new();
    encoder.write_sorted_unique(values)?;
    Ok(encoder.into_bytes())
}

fn ensure_subset(
    descriptor: &ModuleDescriptor,
    kind: CapabilityKind,
    requested: &[StateDomain],
    maximum: &[StateDomain],
) -> Result<(), ProfileError> {
    for domain in requested {
        if maximum.binary_search(domain).is_err() {
            return Err(ProfileError::CapabilityWidening {
                module: descriptor.module_id,
                kind,
                domain: *domain,
            });
        }
    }
    Ok(())
}

fn validate_exclusive_roles(descriptors: &[ModuleDescriptor]) -> Result<(), ProfileError> {
    for required in ModuleType::REQUIRED_EXCLUSIVE {
        let mut matching = descriptors
            .iter()
            .filter(|descriptor| descriptor.module_type == required);
        if matching.next().is_none() {
            return Err(ProfileError::MissingExclusiveRole(required));
        }
        if matching.next().is_some() {
            return Err(ProfileError::DuplicateExclusiveRole(required));
        }
    }
    Ok(())
}

fn validate_acyclic(modules: &BTreeMap<ModuleId, &ModuleDescriptor>) -> Result<(), ProfileError> {
    let mut visiting = BTreeSet::new();
    let mut complete = BTreeSet::new();
    for module_id in modules.keys().copied() {
        visit_module(module_id, modules, &mut visiting, &mut complete)?;
    }
    Ok(())
}

fn visit_module(
    module_id: ModuleId,
    modules: &BTreeMap<ModuleId, &ModuleDescriptor>,
    visiting: &mut BTreeSet<ModuleId>,
    complete: &mut BTreeSet<ModuleId>,
) -> Result<(), ProfileError> {
    if complete.contains(&module_id) {
        return Ok(());
    }
    if !visiting.insert(module_id) {
        return Err(ProfileError::DependencyCycle(module_id));
    }
    let descriptor = modules
        .get(&module_id)
        .expect("dependency closure was checked before cycle detection");
    for dependency in &descriptor.dependency_ids {
        visit_module(*dependency, modules, visiting, complete)?;
    }
    visiting.remove(&module_id);
    complete.insert(module_id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct GenesisManifestFixture {
        schema: String,
        case_id: String,
        canonical_template_hex: String,
        expected: GenesisManifestFixtureExpected,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct GenesisManifestFixtureExpected {
        canonical_length_bytes: usize,
        template_hash_hex: String,
        projection: GenesisManifestFixtureProjection,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct GenesisManifestFixtureProjection {
        template_version_u8: u8,
        protocol_major_u32: u32,
        chain_constitution_hash_hex: String,
        predecessor_manifest_hash_hex: String,
        upgrade_schedule: GenesisManifestFixtureSchedule,
        module_descriptors: Vec<GenesisManifestFixtureDescriptor>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct GenesisManifestFixtureSchedule {
        tag_u8: u8,
        kind: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct GenesisManifestFixtureDescriptor {
        module_type_tag_u8: u8,
        abi_version_u16: u16,
        normative_spec_hash_hex: String,
        interface_schema_hash_hex: String,
        conformance_vector_root_hex: String,
        parameter_hash_hex: String,
        module_id_hex: String,
        dependency_ids_hex: Vec<String>,
        declared_state_read_tags_u8: Vec<u8>,
        declared_state_write_tags_u8: Vec<u8>,
    }

    fn fixture_hex(value: &str, field: &str) -> Vec<u8> {
        assert!(
            !value.is_empty() && value.len().is_multiple_of(2),
            "{field} must contain a nonempty whole-byte hexadecimal value"
        );
        assert!(
            value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "{field} must use canonical lowercase hexadecimal"
        );
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let pair = core::str::from_utf8(pair).expect("hex fixture is ASCII");
                u8::from_str_radix(pair, 16).expect("validated hexadecimal pair")
            })
            .collect()
    }

    fn assert_fixture_hash(field: &str, actual: &impl ToString, expected: &str) {
        assert_eq!(
            fixture_hex(expected, field).len(),
            Hash32::LENGTH,
            "{field} must be exactly 32 bytes"
        );
        assert_eq!(actual.to_string(), expected, "{field} differs");
    }

    fn assert_fixture_descriptor(
        index: usize,
        actual: &ModuleDescriptor,
        expected: &GenesisManifestFixtureDescriptor,
    ) {
        assert_eq!(
            actual.module_type().tag(),
            expected.module_type_tag_u8,
            "module {index} type differs"
        );
        assert_eq!(
            actual.abi_version(),
            expected.abi_version_u16,
            "module {index} ABI differs"
        );
        assert_fixture_hash(
            "normative_spec_hash_hex",
            &actual.normative_spec_hash(),
            &expected.normative_spec_hash_hex,
        );
        assert_fixture_hash(
            "interface_schema_hash_hex",
            &actual.interface_schema_hash(),
            &expected.interface_schema_hash_hex,
        );
        assert_fixture_hash(
            "conformance_vector_root_hex",
            &actual.conformance_vector_root(),
            &expected.conformance_vector_root_hex,
        );
        assert_fixture_hash(
            "parameter_hash_hex",
            &actual.parameter_hash(),
            &expected.parameter_hash_hex,
        );
        assert_fixture_hash(
            "module_id_hex",
            &actual.module_id(),
            &expected.module_id_hex,
        );
        assert_eq!(
            actual.dependency_ids().len(),
            expected.dependency_ids_hex.len(),
            "module {index} dependency count differs"
        );
        for (actual_dependency, expected_dependency) in actual
            .dependency_ids()
            .iter()
            .zip(&expected.dependency_ids_hex)
        {
            assert_fixture_hash("dependency_ids_hex", actual_dependency, expected_dependency);
        }
        assert_eq!(
            actual
                .declared_state_reads()
                .iter()
                .map(|domain| domain.tag())
                .collect::<Vec<_>>(),
            expected.declared_state_read_tags_u8,
            "module {index} read capabilities differ"
        );
        assert_eq!(
            actual
                .declared_state_writes()
                .iter()
                .map(|domain| domain.tag())
                .collect::<Vec<_>>(),
            expected.declared_state_write_tags_u8,
            "module {index} write capabilities differ"
        );
    }

    fn hash(byte: u8) -> Hash32 {
        Hash32::new([byte; 32])
    }

    fn descriptor(
        module_type: ModuleType,
        seed: u8,
        dependencies: Vec<ModuleId>,
        reads: Vec<StateDomain>,
        writes: Vec<StateDomain>,
    ) -> ModuleDescriptor {
        ModuleDescriptor::new(
            module_type,
            1,
            hash(seed),
            hash(seed.wrapping_add(1)),
            hash(seed.wrapping_add(2)),
            hash(seed.wrapping_add(3)),
            dependencies,
            reads,
            writes,
        )
        .expect("fixture descriptor is canonical")
    }

    fn base_descriptors() -> Vec<ModuleDescriptor> {
        let wire = descriptor(ModuleType::WireLimits, 10, vec![], vec![], vec![]);
        let pow = descriptor(
            ModuleType::ProofOfWork,
            20,
            vec![wire.module_id()],
            vec![StateDomain::GraphHeaders],
            vec![],
        );
        let daa = descriptor(
            ModuleType::DifficultyAdjustment,
            30,
            vec![pow.module_id()],
            vec![StateDomain::GraphHeaders, StateDomain::Checkpoints],
            vec![],
        );
        let order = descriptor(
            ModuleType::GraphOrder,
            40,
            vec![pow.module_id()],
            vec![StateDomain::GraphHeaders, StateDomain::GraphBodies],
            vec![StateDomain::CanonicalOrder],
        );
        let kernel = descriptor(
            ModuleType::NativeKernel,
            50,
            vec![order.module_id()],
            vec![StateDomain::CanonicalOrder, StateDomain::Checkpoints],
            vec![
                StateDomain::NoteCommitments,
                StateDomain::Nullifiers,
                StateDomain::RecoveryHistory,
                StateDomain::AcceptedEffects,
                StateDomain::NativeSupply,
                StateDomain::IssuanceCursor,
                StateDomain::Checkpoints,
            ],
        );
        let checkpoint = descriptor(
            ModuleType::Checkpoint,
            60,
            vec![kernel.module_id()],
            vec![
                StateDomain::CanonicalOrder,
                StateDomain::NoteCommitments,
                StateDomain::Nullifiers,
                StateDomain::RecoveryHistory,
                StateDomain::AcceptedEffects,
                StateDomain::NativeSupply,
                StateDomain::IssuanceCursor,
            ],
            vec![],
        );
        let issuance = descriptor(
            ModuleType::Issuance,
            70,
            vec![checkpoint.module_id()],
            vec![StateDomain::IssuanceCursor],
            vec![],
        );
        let mut modules = vec![wire, pow, daa, order, kernel, checkpoint, issuance];
        modules.sort();
        modules
    }

    fn caps(constitution_hash: Hash32) -> ConstitutionalCaps {
        let all = [
            StateDomain::GraphHeaders,
            StateDomain::GraphBodies,
            StateDomain::CanonicalOrder,
            StateDomain::NoteCommitments,
            StateDomain::Nullifiers,
            StateDomain::RecoveryHistory,
            StateDomain::AcceptedEffects,
            StateDomain::NativeSupply,
            StateDomain::IssuanceCursor,
            StateDomain::Checkpoints,
            StateDomain::ProtocolProfiles,
            StateDomain::PolicyPhases,
            StateDomain::ProofSuites,
        ];
        let mut role_caps = MODULE_TYPE_TAGS
            .iter()
            .copied()
            .map(|tag| {
                RoleCapabilityCap::new(ModuleType::from_tag(tag), all.to_vec(), all.to_vec())
                    .expect("fixture cap is canonical")
            })
            .collect::<Vec<_>>();
        role_caps.sort();
        ConstitutionalCaps::new(constitution_hash, role_caps).expect("caps are canonical")
    }

    fn valid_fixture() -> (ChainDomain, ProtocolManifest, ProfileValidator) {
        let chain = ChainDomain::from_bytes([0xa5; 32]);
        let constitution_hash = hash(200);
        let modules = base_descriptors();
        let supported = modules.iter().map(ModuleDescriptor::module_id).collect();
        let manifest = ProtocolManifest::new(
            1,
            constitution_hash,
            ManifestHash::ZERO,
            UpgradeSchedule::genesis(),
            modules,
        )
        .expect("fixture manifest is canonical");
        (
            chain,
            manifest,
            ProfileValidator::new(caps(constitution_hash), supported),
        )
    }

    fn native_kernel(manifest: &ProtocolManifest) -> &ModuleDescriptor {
        manifest
            .module_descriptors()
            .iter()
            .find(|descriptor| descriptor.module_type() == ModuleType::NativeKernel)
            .expect("complete fixture has exactly one native kernel")
    }

    fn checkpoint(manifest: &ProtocolManifest) -> &ModuleDescriptor {
        manifest
            .module_descriptors()
            .iter()
            .find(|descriptor| descriptor.module_type() == ModuleType::Checkpoint)
            .expect("complete fixture has exactly one checkpoint module")
    }

    const TEST_NETWORK_ID: &[u8] = b"silknode-profile-gate-a";
    const TEST_ALLOCATION_TEMPLATE: &[u8] = b"silknode-test-allocation-template-v1";
    fn genesis_identity(manifest: &ProtocolManifest) -> DerivedGenesisIdentity {
        DerivedGenesisIdentity::derive(
            TEST_NETWORK_ID,
            manifest
                .genesis_template()
                .expect("genesis manifest template projects"),
            TEST_ALLOCATION_TEMPLATE,
        )
        .expect("genesis identity derives")
    }

    fn genesis_pin(manifest: &ProtocolManifest) -> GenesisProfilePin {
        let identity = genesis_identity(manifest);
        let chain_domain = identity.chain_domain();
        GenesisProfilePin::new(
            identity,
            manifest
                .manifest_hash(chain_domain)
                .expect("manifest hashes"),
            native_kernel(manifest).module_id(),
            checkpoint(manifest).module_id(),
        )
    }

    fn pinned_validator(manifest: &ProtocolManifest, pin: &GenesisProfilePin) -> ProfileValidator {
        let supported = manifest
            .module_descriptors()
            .iter()
            .map(ModuleDescriptor::module_id)
            .collect();
        ProfileValidator::new_with_genesis_pin(
            caps(manifest.chain_constitution_hash()),
            supported,
            pin.clone(),
        )
    }

    #[test]
    fn validates_complete_profile_and_round_trips_canonical_bytes() {
        let (chain, manifest, validator) = valid_fixture();
        let bytes = manifest.to_canonical_bytes().expect("manifest encodes");
        let validated = validator
            .decode_and_validate(chain, &bytes)
            .expect("manifest validates");
        assert_eq!(validated.chain_domain(), chain);
        assert_eq!(validated.manifest(), &manifest);
        assert_eq!(
            validated.manifest_hash(),
            manifest.manifest_hash(chain).expect("manifest hashes")
        );
        assert_eq!(
            validated.profile_domain(),
            derive_profile_domain(chain, 1, validated.manifest_hash())
                .expect("profile domain derives")
        );
        // Frozen language-neutral vectors. Changing one is a consensus-format
        // change, not routine test maintenance.
        assert_eq!(
            manifest.module_descriptors()[0].module_id().to_string(),
            "3bb030597f5e046916b0d4c0a1606720d255d19f57b63e64730bb4609ec84490"
        );
        assert_eq!(
            validated.manifest_hash().to_string(),
            "d4192d6aa7e854bc90e88c2cc3ffd51fc6b85fc53275ed038786166eca0072ed"
        );
        assert_eq!(
            validated.profile_domain().to_string(),
            "db488f9087eac53711ae398660410148430e8d5810a954cc9edeff226688d734"
        );
    }

    #[test]
    fn genesis_manifest_template_projection_is_versioned_and_frozen() {
        let (_, manifest, _) = valid_fixture();
        let template = manifest
            .genesis_template()
            .expect("genesis template projects");
        let template_hash = manifest
            .genesis_template_hash()
            .expect("genesis template hashes");
        let manifest_bytes = manifest.to_canonical_bytes().expect("manifest encodes");
        let mut projected = Vec::with_capacity(1 + manifest_bytes.len());
        projected.push(GENESIS_MANIFEST_TEMPLATE_VERSION);
        projected.extend_from_slice(&manifest_bytes);
        assert_eq!(
            template.to_canonical_bytes().expect("template encodes"),
            projected
        );
        assert_eq!(
            template.hash().expect("typed template hashes"),
            template_hash
        );
        let explicit = domain_hash(hash_domains::GENESIS_MANIFEST_TEMPLATE, &[&projected])
            .map(GenesisManifestTemplateHash::new)
            .expect("explicit projection hashes");

        assert_eq!(template_hash, explicit);
        assert_eq!(
            template_hash.to_string(),
            "86d4074365bb28bcefd7d7a9e185d38b4f2490970097a30b45c13d5906009cc0"
        );
    }

    #[test]
    fn gate_a_genesis_receipt_template_is_typed_versioned_and_frozen() {
        let (_, manifest, _) = valid_fixture();
        let manifest_template = manifest
            .genesis_template()
            .expect("genesis manifest template projects");
        let template =
            GateAGenesisReceiptTemplate::from_genesis_manifest_template(&manifest_template)
                .expect("receipt template projects");
        let mut expected = Vec::with_capacity(203);
        expected.push(GATE_A_GENESIS_RECEIPT_TEMPLATE_VERSION);
        expected.extend_from_slice(&manifest.protocol_major().to_le_bytes());
        for recipe in GateAGenesisReceiptRecipe::ORDERED {
            expected.extend_from_slice(&ZERO_DERIVED_HASH_PLACEHOLDER);
            expected.push(recipe.tag());
        }

        let bytes = template.to_canonical_bytes().expect("template encodes");
        assert_eq!(bytes, expected);
        assert_eq!(bytes.len(), 203);
        assert_eq!(template.protocol_major(), manifest.protocol_major());
        assert_eq!(template.recipes(), &GateAGenesisReceiptRecipe::ORDERED);
        assert_eq!(
            GateAGenesisReceiptTemplate::from_canonical_bytes(&bytes),
            Ok(template.clone())
        );
        assert_eq!(
            template
                .historical_a2a5_object_slot_hash()
                .expect("reduced receipt template hashes")
                .to_string(),
            "b3959108b6a54272ac1cff33c49ac1abf8550e44e2d51354a0b5f280d1d07f7d"
        );
        assert_eq!(
            genesis_identity(&manifest).gate_a_genesis_receipt_template(),
            &template
        );
    }

    #[test]
    fn genesis_object_template_is_typed_versioned_and_frozen() {
        let (_, manifest, _) = valid_fixture();
        let manifest_template = manifest
            .genesis_template()
            .expect("genesis manifest template projects");
        let allocation_hash = derive_genesis_allocation_template_hash(TEST_ALLOCATION_TEMPLATE)
            .expect("allocation template hashes");
        let template =
            GenesisObjectTemplate::from_genesis_inputs(&manifest_template, allocation_hash)
                .expect("object template projects");
        let mut expected = Vec::with_capacity(GENESIS_OBJECT_TEMPLATE_V1_ENCODED_LENGTH);
        expected.push(GENESIS_OBJECT_TEMPLATE_TAG);
        expected.push(GENESIS_OBJECT_TEMPLATE_VERSION);
        expected.extend_from_slice(&manifest.protocol_major().to_le_bytes());
        expected.extend_from_slice(allocation_hash.as_bytes());
        for recipe in GenesisObjectRecipe::ORDERED {
            expected.extend_from_slice(&ZERO_DERIVED_HASH_PLACEHOLDER);
            expected.push(recipe.tag());
        }

        let bytes = template.to_canonical_bytes().expect("template encodes");
        assert_eq!(bytes, expected);
        assert_eq!(bytes.len(), GENESIS_OBJECT_TEMPLATE_V1_ENCODED_LENGTH);
        assert_eq!(template.protocol_major(), manifest.protocol_major());
        assert_eq!(template.genesis_allocation_template_hash(), allocation_hash);
        assert_eq!(template.recipes(), &GenesisObjectRecipe::ORDERED);
        assert_eq!(
            GenesisObjectTemplate::from_canonical_bytes(&bytes),
            Ok(template.clone())
        );
        assert_eq!(
            template.hash().expect("object template hashes").to_string(),
            "8fadb22ccfdeb9ba21bd48a9802d172239c1bdbb48e32922a91d26dc4cb07cd3"
        );
        assert_eq!(
            genesis_identity(&manifest).genesis_object_template(),
            &template
        );
        let receipt_template =
            GateAGenesisReceiptTemplate::from_genesis_manifest_template(&manifest_template)
                .expect("receipt template projects");
        assert_ne!(
            template.hash().expect("object template hashes").as_bytes(),
            receipt_template
                .historical_a2a5_object_slot_hash()
                .expect("historical receipt template hashes")
                .as_bytes()
        );
    }

    #[test]
    fn genesis_object_template_rejects_noncanonical_and_receipt_forms() {
        let (_, manifest, _) = valid_fixture();
        let manifest_template = manifest
            .genesis_template()
            .expect("genesis manifest template projects");
        let allocation_hash = derive_genesis_allocation_template_hash(TEST_ALLOCATION_TEMPLATE)
            .expect("allocation template hashes");
        let bytes = GenesisObjectTemplate::from_genesis_inputs(&manifest_template, allocation_hash)
            .expect("object template projects")
            .to_canonical_bytes()
            .expect("object template encodes");

        for length in 0..bytes.len() {
            assert!(matches!(
                GenesisObjectTemplate::from_canonical_bytes(&bytes[..length]),
                Err(DecodeError::UnexpectedEof { .. })
            ));
        }

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            GenesisObjectTemplate::from_canonical_bytes(&trailing),
            Err(DecodeError::TrailingBytes { .. })
        ));

        for (offset, value) in [(0, 0xa1), (1, 2)] {
            let mut unknown = bytes.clone();
            unknown[offset] = value;
            assert!(matches!(
                GenesisObjectTemplate::from_canonical_bytes(&unknown),
                Err(DecodeError::UnknownTag {
                    offset: actual,
                    value: actual_value
                }) if actual == offset && actual_value == value
            ));
        }

        for (index, recipe) in GenesisObjectRecipe::ORDERED.into_iter().enumerate() {
            let placeholder_offset = 38 + index * 33;
            let recipe_offset = placeholder_offset + Hash32::LENGTH;

            let mut nonzero_placeholder = bytes.clone();
            nonzero_placeholder[placeholder_offset] = 1;
            assert_eq!(
                GenesisObjectTemplate::from_canonical_bytes(&nonzero_placeholder),
                Err(DecodeError::NonZeroPlaceholder {
                    offset: placeholder_offset
                })
            );

            let mut unknown_recipe = bytes.clone();
            unknown_recipe[recipe_offset] = recipe.tag().wrapping_add(1);
            assert!(matches!(
                GenesisObjectTemplate::from_canonical_bytes(&unknown_recipe),
                Err(DecodeError::UnknownTag { offset, .. }) if offset == recipe_offset
            ));
        }

        let receipt_template =
            GateAGenesisReceiptTemplate::from_genesis_manifest_template(&manifest_template)
                .expect("receipt template projects")
                .to_canonical_bytes()
                .expect("receipt template encodes");
        assert!(matches!(
            GenesisObjectTemplate::from_canonical_bytes(&receipt_template),
            Err(DecodeError::UnknownTag {
                offset: 0,
                value: GATE_A_GENESIS_RECEIPT_TEMPLATE_VERSION
            })
        ));
    }

    #[test]
    fn gate_a_genesis_receipt_template_rejects_every_noncanonical_slot_form() {
        let (_, manifest, _) = valid_fixture();
        let bytes = GateAGenesisReceiptTemplate::from_genesis_manifest_template(
            &manifest
                .genesis_template()
                .expect("genesis manifest template projects"),
        )
        .expect("receipt template projects")
        .to_canonical_bytes()
        .expect("receipt template encodes");

        for length in 0..bytes.len() {
            assert!(matches!(
                GateAGenesisReceiptTemplate::from_canonical_bytes(&bytes[..length]),
                Err(DecodeError::UnexpectedEof { .. })
            ));
        }

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            GateAGenesisReceiptTemplate::from_canonical_bytes(&trailing),
            Err(DecodeError::TrailingBytes { .. })
        ));

        let mut unknown_version = bytes.clone();
        unknown_version[0] = 2;
        assert!(matches!(
            GateAGenesisReceiptTemplate::from_canonical_bytes(&unknown_version),
            Err(DecodeError::UnknownTag {
                offset: 0,
                value: 2
            })
        ));

        for (index, recipe) in GateAGenesisReceiptRecipe::ORDERED.into_iter().enumerate() {
            let placeholder_offset = 5 + index * 33;
            let recipe_offset = placeholder_offset + Hash32::LENGTH;

            let mut nonzero_placeholder = bytes.clone();
            nonzero_placeholder[placeholder_offset] = 1;
            assert_eq!(
                GateAGenesisReceiptTemplate::from_canonical_bytes(&nonzero_placeholder),
                Err(DecodeError::NonZeroPlaceholder {
                    offset: placeholder_offset
                })
            );

            let mut unknown_recipe = bytes.clone();
            unknown_recipe[recipe_offset] = recipe.tag().wrapping_add(1);
            assert!(matches!(
                GateAGenesisReceiptTemplate::from_canonical_bytes(&unknown_recipe),
                Err(DecodeError::UnknownTag { offset, .. }) if offset == recipe_offset
            ));
        }
    }

    #[test]
    fn consumes_strict_language_neutral_genesis_manifest_fixture() {
        let document = include_str!("../../../fixtures/genesis-manifest-v1.json");
        let fixture: GenesisManifestFixture =
            serde_json::from_str(document).expect("strict genesis fixture schema parses");
        assert_eq!(
            fixture.schema,
            "silknode.gate-a.genesis-manifest-template.v1"
        );
        assert_eq!(fixture.case_id, "profile-valid-fixture-v1");

        let bytes = fixture_hex(&fixture.canonical_template_hex, "canonical_template_hex");
        assert_eq!(bytes.len(), fixture.expected.canonical_length_bytes);
        let template = GenesisManifestTemplate::from_canonical_bytes(&bytes)
            .expect("fixture template bytes decode exactly");
        assert_fixture_hash(
            "template_hash_hex",
            &template.hash().expect("fixture template hashes"),
            &fixture.expected.template_hash_hex,
        );

        let projection = fixture.expected.projection;
        assert_eq!(
            projection.template_version_u8,
            GENESIS_MANIFEST_TEMPLATE_VERSION
        );
        let fields = template.as_v1();
        assert_eq!(fields.protocol_major(), projection.protocol_major_u32);
        assert_fixture_hash(
            "chain_constitution_hash_hex",
            &fields.chain_constitution_hash(),
            &projection.chain_constitution_hash_hex,
        );
        assert_fixture_hash(
            "predecessor_manifest_hash_hex",
            &fields.predecessor_manifest_hash(),
            &projection.predecessor_manifest_hash_hex,
        );
        assert_eq!(projection.upgrade_schedule.tag_u8, 0);
        assert_eq!(projection.upgrade_schedule.kind, "genesis");
        assert!(matches!(
            fields.upgrade_schedule(),
            UpgradeSchedule::Genesis
        ));

        assert_eq!(
            fields.module_descriptors().len(),
            projection.module_descriptors.len()
        );
        for (index, (actual, expected)) in fields
            .module_descriptors()
            .iter()
            .zip(&projection.module_descriptors)
            .enumerate()
        {
            assert_fixture_descriptor(index, actual, expected);
        }

        let (_, manifest, _) = valid_fixture();
        template
            .verify_final_manifest_projection(&manifest)
            .expect("fixture exactly projects the Rust manifest");
        assert_eq!(
            manifest
                .genesis_template()
                .expect("Rust manifest projects")
                .to_canonical_bytes()
                .expect("Rust projection encodes"),
            bytes
        );
    }

    #[test]
    fn genesis_manifest_template_round_trips_and_exposes_complete_v1_projection() {
        let (_, manifest, _) = valid_fixture();
        let template = manifest
            .genesis_template()
            .expect("genesis template projects");
        let bytes = template.to_canonical_bytes().expect("template encodes");
        let decoded =
            GenesisManifestTemplate::from_canonical_bytes(&bytes).expect("exact template decodes");

        assert_eq!(decoded, template);
        assert_eq!(decoded.hash(), template.hash());
        let fields = decoded.as_v1();
        assert_eq!(fields.protocol_major(), manifest.protocol_major());
        assert_eq!(
            fields.chain_constitution_hash(),
            manifest.chain_constitution_hash()
        );
        assert_eq!(
            fields.predecessor_manifest_hash(),
            manifest.predecessor_manifest_hash()
        );
        assert_eq!(fields.upgrade_schedule(), manifest.upgrade_schedule());
        assert_eq!(fields.module_descriptors(), manifest.module_descriptors());
        decoded
            .verify_final_manifest_projection(&manifest)
            .expect("exact final projection verifies");
    }

    #[test]
    fn genesis_manifest_template_decode_rejects_unknown_trailing_and_every_truncation() {
        let (_, manifest, _) = valid_fixture();
        let template = manifest
            .genesis_template()
            .expect("genesis template projects");
        let bytes = template.to_canonical_bytes().expect("template encodes");

        let mut unknown = bytes.clone();
        unknown[0] = GENESIS_MANIFEST_TEMPLATE_VERSION + 1;
        assert_eq!(
            GenesisManifestTemplate::from_canonical_bytes(&unknown)
                .expect_err("unknown template version rejects")
                .code(),
            "canonical.unknown_tag"
        );

        let mut extended = bytes.clone();
        extended.push(0);
        assert_eq!(
            GenesisManifestTemplate::from_canonical_bytes(&extended)
                .expect_err("trailing template bytes reject")
                .code(),
            "canonical.trailing_bytes"
        );

        for length in 0..bytes.len() {
            let error = GenesisManifestTemplate::from_canonical_bytes(&bytes[..length])
                .expect_err("every strict prefix is truncated");
            assert_eq!(
                error.code(),
                "canonical.unexpected_eof",
                "unexpected error for prefix length {length}"
            );
        }
    }

    #[test]
    fn genesis_manifest_template_rejects_successor_projection_after_structure_checks() {
        let (_, manifest, _) = valid_fixture();
        let expected = manifest
            .genesis_template()
            .expect("genesis template projects");
        let successor = ProtocolManifest::new(
            manifest.protocol_major() + 1,
            manifest.chain_constitution_hash(),
            ManifestHash::from_bytes([0x44; 32]),
            UpgradeSchedule::v1(10, 20, 30, 40, 50, 60).expect("schedule is ordered"),
            manifest.module_descriptors().to_vec(),
        )
        .expect("successor is structurally valid");

        let error = successor
            .genesis_template()
            .expect_err("successor cannot project as genesis");
        assert_eq!(error, ProfileError::SuccessorRequiresTransitionActivation);
        assert_eq!(
            expected
                .verify_final_manifest_projection(&successor)
                .expect_err("successor error precedes projection mismatch"),
            ProfileError::SuccessorRequiresTransitionActivation
        );

        let successor_bytes = successor
            .to_canonical_bytes()
            .expect("successor manifest encodes");
        let mut template_bytes = Vec::with_capacity(1 + successor_bytes.len());
        template_bytes.push(GENESIS_MANIFEST_TEMPLATE_VERSION);
        template_bytes.extend_from_slice(&successor_bytes);
        let decoded = GenesisManifestTemplate::from_canonical_bytes(&template_bytes)
            .expect("wire-canonical successor-shaped template decodes");
        assert_eq!(
            decoded
                .hash()
                .expect_err("semantic template validation rejects successor"),
            ProfileError::SuccessorRequiresTransitionActivation
        );
        assert_eq!(
            DerivedGenesisIdentity::derive(TEST_NETWORK_ID, decoded, TEST_ALLOCATION_TEMPLATE,)
                .expect_err("a successor-shaped template cannot derive genesis identity"),
            ProfileError::SuccessorRequiresTransitionActivation
        );
    }

    #[test]
    fn genesis_manifest_template_detects_every_genesis_valid_field_mutation() {
        let (_, manifest, _) = valid_fixture();
        let expected = manifest
            .genesis_template()
            .expect("genesis template projects");
        let expected_hash = expected.hash().expect("expected template hashes");

        let mut changed_major = manifest.clone();
        changed_major.protocol_major += 1;
        let mut changed_constitution = manifest.clone();
        changed_constitution.chain_constitution_hash = hash(201);
        let mut changed_modules = manifest;
        changed_modules.module_descriptors[0] =
            descriptor(ModuleType::WireLimits, 11, vec![], vec![], vec![]);
        changed_modules.module_descriptors.sort();

        for changed in [changed_major, changed_constitution, changed_modules] {
            let actual = changed
                .genesis_template()
                .expect("changed genesis still projects");
            let actual_hash = actual.hash().expect("actual template hashes");
            assert_ne!(actual, expected);
            assert_ne!(actual_hash, expected_hash);
            let error = expected
                .verify_final_manifest_projection(&changed)
                .expect_err("changed projection rejects");
            assert_eq!(
                error,
                ProfileError::GenesisManifestProjectionMismatch {
                    expected: expected_hash,
                    actual: actual_hash,
                }
            );
            assert_eq!(error.code(), "profile.genesis_manifest_projection_mismatch");
        }
    }

    #[test]
    fn pinned_genesis_activates_a_sealed_execution_profile() {
        let (_, manifest, _) = valid_fixture();
        let pin = genesis_pin(&manifest);
        let chain = pin.chain_domain();
        assert_eq!(pin.chain_domain(), chain);
        assert_eq!(pin.identity(), &genesis_identity(&manifest));
        assert_eq!(
            pin.identity().genesis_manifest_template(),
            &manifest
                .genesis_template()
                .expect("genesis template projects")
        );
        assert_eq!(
            pin.genesis_manifest_template_hash(),
            manifest
                .genesis_template_hash()
                .expect("genesis template hashes")
        );
        assert_eq!(
            pin.genesis_allocation_template_hash(),
            derive_genesis_allocation_template_hash(TEST_ALLOCATION_TEMPLATE)
                .expect("allocation template hashes")
        );
        assert_eq!(
            pin.genesis_object_template_hash(),
            pin.genesis_object_template()
                .hash()
                .expect("genesis object template hashes")
        );
        assert_eq!(
            pin.genesis_manifest_hash(),
            manifest.manifest_hash(chain).expect("manifest hashes")
        );
        assert_eq!(
            pin.native_kernel_module_id(),
            native_kernel(&manifest).module_id()
        );
        assert_eq!(
            pin.checkpoint_module_id(),
            checkpoint(&manifest).module_id()
        );

        let validator = pinned_validator(&manifest, &pin);
        let bytes = manifest.to_canonical_bytes().expect("manifest encodes");
        let execution = validator
            .decode_and_activate_genesis(chain, &bytes)
            .expect("exact pinned genesis activates");

        assert_eq!(execution.chain_domain(), chain);
        assert_eq!(execution.genesis_commitment(), pin.genesis_commitment());
        assert_eq!(
            execution.genesis_manifest_template_hash(),
            pin.genesis_manifest_template_hash()
        );
        assert_eq!(
            execution.genesis_allocation_template_hash(),
            pin.genesis_allocation_template_hash()
        );
        assert_eq!(
            execution.genesis_object_template_hash(),
            pin.genesis_object_template_hash()
        );
        assert_eq!(execution.manifest_hash(), pin.genesis_manifest_hash());
        assert_eq!(
            execution.profile_domain(),
            derive_profile_domain(
                chain,
                manifest.protocol_major(),
                pin.genesis_manifest_hash()
            )
            .expect("profile domain derives")
        );
        assert_eq!(
            execution.native_kernel_module_id(),
            native_kernel(&manifest).module_id()
        );
        assert_eq!(
            execution.native_kernel_abi_version(),
            native_kernel(&manifest).abi_version()
        );
        assert_eq!(
            execution.checkpoint_module_id(),
            checkpoint(&manifest).module_id()
        );
        assert_eq!(
            execution.checkpoint_abi_version(),
            checkpoint(&manifest).abi_version()
        );
    }

    #[test]
    fn generic_validator_validates_but_cannot_activate() {
        let (chain, manifest, validator) = valid_fixture();
        validator
            .validate(chain, manifest.clone())
            .expect("generic validation remains available");
        let error = validator
            .validate_and_activate_genesis(chain, manifest)
            .expect_err("generic validator has no activation authority");
        assert_eq!(error, ProfileError::MissingGenesisPin);
        assert_eq!(error.code(), "profile.missing_genesis_pin");
    }

    #[test]
    fn activation_runs_full_validation_before_pin_checks() {
        let (chain, mut manifest, validator) = valid_fixture();
        manifest.module_descriptors[0].module_id = ModuleId::from_bytes([0xff; 32]);
        manifest.module_descriptors.sort();

        let error = validator
            .validate_and_activate_genesis(chain, manifest)
            .expect_err("invalid manifest rejects before the missing pin");
        assert_eq!(error.code(), "profile.module_id_mismatch");
    }

    #[test]
    fn altered_major_with_the_same_modules_fails_the_manifest_pin() {
        let (_, manifest, _) = valid_fixture();
        let pin = genesis_pin(&manifest);
        let chain = pin.chain_domain();
        let validator = pinned_validator(&manifest, &pin);
        let changed = ProtocolManifest::new(
            manifest.protocol_major() + 1,
            manifest.chain_constitution_hash(),
            ManifestHash::ZERO,
            UpgradeSchedule::genesis(),
            manifest.module_descriptors().to_vec(),
        )
        .expect("changed-major genesis remains structurally valid");
        let changed_template = changed
            .genesis_template()
            .expect("changed template projects");
        assert_ne!(
            changed_template.hash().expect("changed template hashes"),
            pin.genesis_manifest_template_hash()
        );
        let changed_identity = DerivedGenesisIdentity::derive(
            TEST_NETWORK_ID,
            changed_template,
            TEST_ALLOCATION_TEMPLATE,
        )
        .expect("changed identity derives consistently");
        assert_ne!(changed_identity.chain_domain(), pin.chain_domain());
        validator
            .validate(chain, changed.clone())
            .expect("changed major remains a valid standalone profile");

        let error = validator
            .validate_and_activate_genesis(chain, changed)
            .expect_err("a new major changes the pinned genesis projection");
        assert!(matches!(
            error,
            ProfileError::PinnedGenesisManifestTemplateMismatch { .. }
        ));
        assert_eq!(
            error.code(),
            "profile.pinned_genesis_manifest_template_mismatch"
        );
    }

    #[test]
    fn valid_successor_requires_transition_activation_before_execution() {
        let (_, genesis, _) = valid_fixture();
        let pin = genesis_pin(&genesis);
        let chain = pin.chain_domain();
        let validator = pinned_validator(&genesis, &pin);
        let successor = ProtocolManifest::new(
            genesis.protocol_major() + 1,
            genesis.chain_constitution_hash(),
            ManifestHash::from_bytes([0x44; 32]),
            UpgradeSchedule::v1(10, 20, 30, 40, 50, 60).expect("schedule is ordered"),
            genesis.module_descriptors().to_vec(),
        )
        .expect("successor is structurally valid");
        let template_error = successor
            .genesis_template_hash()
            .expect_err("a successor has no genesis template projection");
        assert_eq!(
            template_error,
            ProfileError::SuccessorRequiresTransitionActivation
        );
        assert_eq!(
            template_error.code(),
            "profile.successor_requires_transition_activation"
        );
        validator
            .validate(chain, successor.clone())
            .expect("successor standalone validation succeeds");

        let error = validator
            .validate_and_activate_genesis(chain, successor)
            .expect_err("standalone validation is not transition activation");
        assert_eq!(error, ProfileError::SuccessorRequiresTransitionActivation);
        assert_eq!(
            error.code(),
            "profile.successor_requires_transition_activation"
        );
    }

    #[test]
    fn wrong_native_kernel_pin_fails_after_manifest_match() {
        let (_, manifest, _) = valid_fixture();
        let wrong_kernel = ModuleId::from_bytes([0xfe; 32]);
        let identity = genesis_identity(&manifest);
        let chain = identity.chain_domain();
        let pin = GenesisProfilePin::new(
            identity,
            manifest.manifest_hash(chain).expect("manifest hashes"),
            wrong_kernel,
            checkpoint(&manifest).module_id(),
        );
        let validator = pinned_validator(&manifest, &pin);

        let error = validator
            .validate_and_activate_genesis(chain, manifest)
            .expect_err("native-kernel pin is exact");
        assert!(matches!(
            error,
            ProfileError::PinnedNativeKernelMismatch {
                expected,
                actual: _
            } if expected == wrong_kernel
        ));
        assert_eq!(error.code(), "profile.pinned_native_kernel_mismatch");
    }

    #[test]
    fn wrong_checkpoint_pin_fails_after_native_kernel_match() {
        let (_, manifest, _) = valid_fixture();
        let wrong_checkpoint = ModuleId::from_bytes([0xfd; 32]);
        let identity = genesis_identity(&manifest);
        let chain = identity.chain_domain();
        let pin = GenesisProfilePin::new(
            identity,
            manifest.manifest_hash(chain).expect("manifest hashes"),
            native_kernel(&manifest).module_id(),
            wrong_checkpoint,
        );
        let validator = pinned_validator(&manifest, &pin);

        let error = validator
            .validate_and_activate_genesis(chain, manifest)
            .expect_err("checkpoint pin is exact");
        assert!(matches!(
            error,
            ProfileError::PinnedCheckpointMismatch {
                expected,
                actual: _
            } if expected == wrong_checkpoint
        ));
        assert_eq!(error.code(), "profile.pinned_checkpoint_mismatch");
    }

    #[test]
    fn native_kernel_pin_mismatch_precedes_checkpoint_pin_mismatch() {
        let (_, manifest, _) = valid_fixture();
        let wrong_kernel = ModuleId::from_bytes([0xfc; 32]);
        let wrong_checkpoint = ModuleId::from_bytes([0xfb; 32]);
        let identity = genesis_identity(&manifest);
        let chain = identity.chain_domain();
        let pin = GenesisProfilePin::new(
            identity,
            manifest.manifest_hash(chain).expect("manifest hashes"),
            wrong_kernel,
            wrong_checkpoint,
        );
        let validator = pinned_validator(&manifest, &pin);

        let error = validator
            .validate_and_activate_genesis(chain, manifest)
            .expect_err("native-kernel mismatch has stable precedence");
        assert!(matches!(
            error,
            ProfileError::PinnedNativeKernelMismatch {
                expected,
                actual: _
            } if expected == wrong_kernel
        ));
        assert_eq!(error.code(), "profile.pinned_native_kernel_mismatch");
    }

    #[test]
    fn pinned_constitution_mismatch_precedes_other_identity_mismatches() {
        let (_, manifest, _) = valid_fixture();
        let wrong_constitution = hash(201);
        let wrong_manifest = ProtocolManifest::new(
            manifest.protocol_major(),
            wrong_constitution,
            ManifestHash::ZERO,
            UpgradeSchedule::genesis(),
            manifest.module_descriptors().to_vec(),
        )
        .expect("wrong-constitution manifest remains structurally valid");
        let identity = DerivedGenesisIdentity::derive(
            TEST_NETWORK_ID,
            wrong_manifest
                .genesis_template()
                .expect("wrong-constitution template projects"),
            TEST_ALLOCATION_TEMPLATE,
        )
        .expect("compound-wrong identity derives");
        let chain = identity.chain_domain();
        let pin = GenesisProfilePin::new(
            identity,
            ManifestHash::from_bytes([0xfd; 32]),
            ModuleId::from_bytes([0xfc; 32]),
            ModuleId::from_bytes([0xfb; 32]),
        );
        let validator = pinned_validator(&manifest, &pin);

        let error = validator
            .validate_and_activate_genesis(chain, manifest.clone())
            .expect_err("pinned constitution is checked before later pin fields");
        assert_eq!(
            error,
            ProfileError::PinnedGenesisConstitutionMismatch {
                expected: wrong_constitution,
                actual: manifest.chain_constitution_hash(),
            }
        );
        assert_eq!(error.code(), "profile.pinned_genesis_constitution_mismatch");
    }

    #[test]
    fn wrong_final_manifest_pin_fails_after_derived_identity_matches() {
        let (_, manifest, _) = valid_fixture();
        let identity = genesis_identity(&manifest);
        let chain = identity.chain_domain();
        let wrong_manifest = ManifestHash::from_bytes([0xfb; 32]);
        let pin = GenesisProfilePin::new(
            identity,
            wrong_manifest,
            native_kernel(&manifest).module_id(),
            checkpoint(&manifest).module_id(),
        );
        let validator = pinned_validator(&manifest, &pin);
        let actual = manifest.manifest_hash(chain).expect("manifest hashes");

        let error = validator
            .validate_and_activate_genesis(chain, manifest)
            .expect_err("final chain-bound manifest pin remains exact");
        assert_eq!(
            error,
            ProfileError::PinnedManifestMismatch {
                expected: wrong_manifest,
                actual,
            }
        );
        assert_eq!(error.code(), "profile.pinned_manifest_mismatch");
    }

    #[test]
    fn genesis_pin_is_exactly_chain_bound() {
        let (_, manifest, _) = valid_fixture();
        let pin = genesis_pin(&manifest);
        let chain = pin.chain_domain();
        let validator = pinned_validator(&manifest, &pin);
        let other_chain = ChainDomain::from_bytes([0xa6; 32]);
        let validated_elsewhere = validator
            .validate(other_chain, manifest.clone())
            .expect("the generic validator supports a separate network");
        assert_eq!(validated_elsewhere.chain_domain(), other_chain);
        assert_ne!(
            validated_elsewhere.profile_domain(),
            validator
                .validate(chain, manifest.clone())
                .expect("original chain validates")
                .profile_domain()
        );

        let error = validator
            .validate_and_activate_genesis(other_chain, manifest)
            .expect_err("the activation pin cannot cross chain domains");
        assert!(matches!(
            error,
            ProfileError::PinnedChainDomainMismatch {
                expected,
                actual,
            } if expected == chain && actual == other_chain
        ));
        assert_eq!(error.code(), "profile.pinned_chain_domain_mismatch");
    }

    #[test]
    fn content_changes_module_and_manifest_identity() {
        let (chain, original_manifest, validator) = valid_fixture();
        let original_module = &original_manifest.module_descriptors()[0];
        let changed_module = ModuleDescriptor::new(
            original_module.module_type,
            original_module.abi_version,
            original_module.normative_spec_hash,
            original_module.interface_schema_hash,
            original_module.conformance_vector_root,
            hash(254),
            original_module.dependency_ids.clone(),
            original_module.declared_state_reads.clone(),
            original_module.declared_state_writes.clone(),
        )
        .expect("changed module derives");
        assert_ne!(original_module.module_id, changed_module.module_id);

        let narrow = descriptor(ModuleType::WireLimits, 5, vec![], vec![], vec![]);
        let wider = descriptor(
            ModuleType::WireLimits,
            5,
            vec![],
            vec![StateDomain::GraphHeaders],
            vec![],
        );
        assert_ne!(
            narrow.module_id, wider.module_id,
            "capability changes must change semantic module identity"
        );

        let original_hash = validator
            .validate(chain, original_manifest)
            .expect("original validates")
            .manifest_hash();
        let changed_major = ProtocolManifest::new(
            2,
            hash(200),
            ManifestHash::ZERO,
            UpgradeSchedule::genesis(),
            base_descriptors(),
        )
        .expect("changed manifest constructs");
        assert_ne!(
            original_hash,
            changed_major
                .manifest_hash(chain)
                .expect("changed manifest hashes")
        );
    }

    #[test]
    fn successor_schedule_round_trips_and_every_field_changes_identity() {
        let (chain, genesis, validator) = valid_fixture();
        let predecessor = ManifestHash::from_bytes([0x44; 32]);
        let schedule =
            UpgradeSchedule::v1(10, 20, 30, 40, 50, 60).expect("successor schedule is ordered");
        let fields = schedule.as_v1().expect("schedule is version one");
        assert_eq!(fields.proposal_checkpoint(), 10);
        assert_eq!(fields.review_close_checkpoint(), 20);
        assert_eq!(fields.exit_open_checkpoint(), 30);
        assert_eq!(fields.exit_close_checkpoint(), 40);
        assert_eq!(fields.activation_checkpoint(), 50);
        assert_eq!(fields.overlap_end_checkpoint(), 60);

        let original = ProtocolManifest::new(
            2,
            genesis.chain_constitution_hash,
            predecessor,
            schedule,
            genesis.module_descriptors.clone(),
        )
        .expect("successor manifest constructs");
        let bytes = original.to_canonical_bytes().expect("manifest encodes");
        let original_profile = validator
            .decode_and_validate(chain, &bytes)
            .expect("successor validates");
        assert_eq!(original_profile.manifest(), &original);

        let alternatives = [
            UpgradeSchedule::v1(11, 20, 30, 40, 50, 60),
            UpgradeSchedule::v1(10, 21, 30, 40, 50, 60),
            UpgradeSchedule::v1(10, 20, 31, 40, 50, 60),
            UpgradeSchedule::v1(10, 20, 30, 41, 50, 60),
            UpgradeSchedule::v1(10, 20, 30, 40, 51, 60),
            UpgradeSchedule::v1(10, 20, 30, 40, 50, 61),
        ];
        for alternative in alternatives {
            let changed = ProtocolManifest::new(
                2,
                genesis.chain_constitution_hash,
                predecessor,
                alternative.expect("alternative remains ordered"),
                genesis.module_descriptors.clone(),
            )
            .expect("changed manifest constructs");
            let changed_profile = validator
                .validate(chain, changed)
                .expect("changed successor validates");
            assert_ne!(
                changed_profile.manifest_hash(),
                original_profile.manifest_hash(),
                "every exact schedule field must affect the manifest hash"
            );
            assert_ne!(
                changed_profile.profile_domain(),
                original_profile.profile_domain(),
                "every exact schedule field must affect the profile domain"
            );
        }

        // Frozen language-neutral successor vectors.
        assert_eq!(
            original_profile.manifest_hash().to_string(),
            "d094d0e7ea88e878846b66460bf7639b112e5000770dfd5809dc9f551071d6e8"
        );
        assert_eq!(
            original_profile.profile_domain().to_string(),
            "56c4367d4a21b14ded095198c3be51713bdeb5c43282883f4d7487503311b27d"
        );
    }

    #[test]
    fn rejects_zero_length_inverted_and_wrong_lineage_schedules() {
        let invalid = [
            UpgradeSchedule::v1(10, 10, 20, 30, 40, 50),
            UpgradeSchedule::v1(10, 20, 19, 30, 40, 50),
            UpgradeSchedule::v1(10, 20, 20, 20, 40, 50),
            UpgradeSchedule::v1(10, 20, 20, 30, 30, 50),
            UpgradeSchedule::v1(10, 20, 20, 30, 40, 40),
        ];
        for error in invalid {
            assert_eq!(
                error.expect_err("invalid schedule rejects").code(),
                "profile.invalid_upgrade_schedule"
            );
        }

        let (chain, genesis, validator) = valid_fixture();
        let predecessor = ManifestHash::from_bytes([0x55; 32]);
        assert_eq!(
            ProtocolManifest::new(
                2,
                genesis.chain_constitution_hash,
                predecessor,
                UpgradeSchedule::genesis(),
                genesis.module_descriptors.clone(),
            )
            .expect_err("genesis sentinel cannot be reused by a successor")
            .code(),
            "profile.invalid_upgrade_schedule"
        );

        let invalid_wire_manifest = ProtocolManifest {
            protocol_major: 2,
            chain_constitution_hash: genesis.chain_constitution_hash,
            predecessor_manifest_hash: predecessor,
            upgrade_schedule: UpgradeSchedule::V1(UpgradeScheduleV1 {
                proposal_checkpoint: 10,
                review_close_checkpoint: 20,
                exit_open_checkpoint: 30,
                exit_close_checkpoint: 40,
                activation_checkpoint: 40,
                overlap_end_checkpoint: 50,
            }),
            module_descriptors: genesis.module_descriptors.clone(),
        };
        let invalid_bytes = invalid_wire_manifest
            .to_canonical_bytes()
            .expect("malformed wire fixture encodes structurally");
        assert_eq!(
            validator
                .decode_and_validate(chain, &invalid_bytes)
                .expect_err("decoded zero-length activation delay rejects")
                .code(),
            "profile.invalid_upgrade_schedule"
        );

        assert_eq!(
            ProtocolManifest::new(
                1,
                genesis.chain_constitution_hash,
                ManifestHash::ZERO,
                UpgradeSchedule::v1(10, 20, 20, 30, 40, 50).expect("schedule itself is ordered"),
                genesis.module_descriptors,
            )
            .expect_err("a predecessor-free manifest must use genesis")
            .code(),
            "profile.invalid_upgrade_schedule"
        );
    }

    #[test]
    fn rejects_unknown_tags_and_trailing_bytes() {
        assert!(matches!(
            ModuleType::from_canonical_bytes(&[0xff]),
            Err(DecodeError::UnknownTag { value: 0xff, .. })
        ));
        assert!(matches!(
            StateDomain::from_canonical_bytes(&[0xff]),
            Err(DecodeError::UnknownTag { value: 0xff, .. })
        ));
        assert!(matches!(
            UpgradeSchedule::from_canonical_bytes(&[0xff]),
            Err(DecodeError::UnknownTag { value: 0xff, .. })
        ));

        let (chain, manifest, validator) = valid_fixture();
        let mut bytes = manifest.to_canonical_bytes().expect("manifest encodes");
        bytes.push(0);
        assert_eq!(
            validator
                .decode_and_validate(chain, &bytes)
                .expect_err("trailing byte rejects")
                .code(),
            "canonical.trailing_bytes"
        );
    }

    #[test]
    fn rejects_noncanonical_dependency_and_capability_lists() {
        let id = ModuleId::from_bytes([1; 32]);
        let duplicate_dependency = ModuleDescriptor::new(
            ModuleType::WireLimits,
            1,
            hash(1),
            hash(2),
            hash(3),
            hash(4),
            vec![id, id],
            vec![],
            vec![],
        )
        .expect_err("duplicate dependency rejects");
        assert_eq!(duplicate_dependency.code(), "canonical.duplicate_item");

        let unsorted_reads = ModuleDescriptor::new(
            ModuleType::WireLimits,
            1,
            hash(1),
            hash(2),
            hash(3),
            hash(4),
            vec![],
            vec![StateDomain::Nullifiers, StateDomain::NoteCommitments],
            vec![],
        )
        .expect_err("unsorted capabilities reject");
        assert_eq!(unsorted_reads.code(), "canonical.unsorted_items");
    }

    #[test]
    fn rejects_local_construction_above_consensus_resource_bounds() {
        let dependencies = (0_u8..=u8::try_from(MAX_DEPENDENCIES_PER_MODULE).unwrap())
            .map(|byte| ModuleId::from_bytes([byte; 32]))
            .collect();
        let error = ModuleDescriptor::new(
            ModuleType::WireLimits,
            1,
            hash(1),
            hash(2),
            hash(3),
            hash(4),
            dependencies,
            vec![],
            vec![],
        )
        .expect_err("oversized dependency set rejects");
        assert_eq!(error.code(), "profile.resource_limit_exceeded");
    }

    #[test]
    fn rejects_forged_identity_and_unsupported_module() {
        let (chain, manifest, validator) = valid_fixture();
        let mut forged = manifest.clone();
        forged.module_descriptors[0].module_id = ModuleId::from_bytes([0xff; 32]);
        forged.module_descriptors.sort();
        assert_eq!(
            validator
                .validate(chain, forged)
                .expect_err("forged id rejects")
                .code(),
            "profile.module_id_mismatch"
        );

        let unsupported_validator =
            ProfileValidator::new(caps(manifest.chain_constitution_hash), BTreeSet::new());
        assert_eq!(
            unsupported_validator
                .validate(chain, manifest)
                .expect_err("unknown module rejects")
                .code(),
            "profile.unsupported_module"
        );
    }

    #[test]
    fn rejects_missing_dependency_and_dependency_cycle() {
        let (chain, mut missing, _) = valid_fixture();
        let absent = ModuleId::from_bytes([0xee; 32]);
        missing.module_descriptors[0].dependency_ids = vec![absent];
        missing.module_descriptors[0].module_id = missing.module_descriptors[0]
            .recompute_id()
            .expect("identity recomputes");
        missing.module_descriptors.sort();
        let supported = missing
            .module_descriptors
            .iter()
            .map(ModuleDescriptor::module_id)
            .collect();
        let validator = ProfileValidator::new(caps(missing.chain_constitution_hash), supported);
        assert_eq!(
            validator
                .validate(chain, missing)
                .expect_err("missing dependency rejects")
                .code(),
            "profile.missing_dependency"
        );

        let constitution_hash = hash(201);
        let mut modules = base_descriptors();
        let first = modules[0].module_id;
        let second = modules[1].module_id;
        modules[0].dependency_ids = vec![second];
        modules[0].module_id = modules[0].recompute_id().expect("identity recomputes");
        modules[1].dependency_ids = vec![modules[0].module_id];
        modules[1].module_id = modules[1].recompute_id().expect("identity recomputes");
        // Repoint the first edge after the second ID changed, producing a
        // stable two-node cycle and re-derive both IDs to keep identities valid.
        modules[0].dependency_ids = vec![modules[1].module_id];
        modules[0].module_id = modules[0].recompute_id().expect("identity recomputes");
        modules[1].dependency_ids = vec![modules[0].module_id];
        modules[1].module_id = modules[1].recompute_id().expect("identity recomputes");
        modules.sort();
        let supported = modules.iter().map(ModuleDescriptor::module_id).collect();
        let cycle = ProtocolManifest {
            protocol_major: 1,
            chain_constitution_hash: constitution_hash,
            predecessor_manifest_hash: ManifestHash::ZERO,
            upgrade_schedule: UpgradeSchedule::genesis(),
            module_descriptors: modules,
        };
        let cycle_validator = ProfileValidator::new(caps(constitution_hash), supported);
        let error = cycle_validator
            .validate(chain, cycle)
            .expect_err("cycle rejects");
        // Content-addressed dependency cycles cannot generally reach a fixed
        // point by mutation. The first stale edge therefore fails closure;
        // explicit cycle coverage uses the graph helper below.
        assert!(matches!(error, ProfileError::MissingDependency { .. }));

        let mut synthetic = BTreeMap::new();
        let mut left = descriptor(ModuleType::WireLimits, 1, vec![], vec![], vec![]);
        let mut right = descriptor(ModuleType::ProofOfWork, 9, vec![], vec![], vec![]);
        left.dependency_ids = vec![right.module_id];
        right.dependency_ids = vec![left.module_id];
        synthetic.insert(left.module_id, &left);
        synthetic.insert(right.module_id, &right);
        assert!(matches!(
            validate_acyclic(&synthetic),
            Err(ProfileError::DependencyCycle(_))
        ));
        let _ = first;
    }

    #[test]
    fn rejects_missing_and_duplicate_exclusive_authority() {
        let (chain, manifest, _) = valid_fixture();
        let mut missing_modules = manifest.module_descriptors.clone();
        missing_modules.retain(|module| module.module_type != ModuleType::Issuance);
        let supported = missing_modules
            .iter()
            .map(ModuleDescriptor::module_id)
            .collect();
        let missing = ProtocolManifest::new(
            1,
            manifest.chain_constitution_hash,
            ManifestHash::ZERO,
            UpgradeSchedule::genesis(),
            missing_modules,
        )
        .expect("structurally valid");
        assert_eq!(
            ProfileValidator::new(caps(manifest.chain_constitution_hash), supported)
                .validate(chain, missing)
                .expect_err("missing role rejects")
                .code(),
            "profile.missing_exclusive_role"
        );

        let mut duplicate_modules = manifest.module_descriptors.clone();
        duplicate_modules.push(descriptor(ModuleType::Issuance, 99, vec![], vec![], vec![]));
        duplicate_modules.sort();
        let supported = duplicate_modules
            .iter()
            .map(ModuleDescriptor::module_id)
            .collect();
        let duplicate = ProtocolManifest::new(
            1,
            manifest.chain_constitution_hash,
            ManifestHash::ZERO,
            UpgradeSchedule::genesis(),
            duplicate_modules,
        )
        .expect("structurally valid");
        assert_eq!(
            ProfileValidator::new(caps(manifest.chain_constitution_hash), supported)
                .validate(chain, duplicate)
                .expect_err("duplicate role rejects")
                .code(),
            "profile.duplicate_exclusive_role"
        );
    }

    #[test]
    fn enforces_constitution_and_read_write_caps() {
        let (chain, manifest, _) = valid_fixture();
        let supported: BTreeSet<ModuleId> = manifest
            .module_descriptors
            .iter()
            .map(ModuleDescriptor::module_id)
            .collect();
        let wrong_constitution = ProfileValidator::new(caps(hash(0)), supported.clone());
        assert_eq!(
            wrong_constitution
                .validate(chain, manifest.clone())
                .expect_err("constitution mismatch rejects")
                .code(),
            "profile.constitution_mismatch"
        );

        let mut restrictive = caps(manifest.chain_constitution_hash);
        let kernel_cap = restrictive
            .role_caps
            .iter_mut()
            .find(|cap| cap.module_type == ModuleType::NativeKernel)
            .expect("kernel cap exists");
        kernel_cap
            .max_state_writes
            .retain(|domain| *domain != StateDomain::NativeSupply);
        let validator = ProfileValidator::new(restrictive, supported);
        assert!(matches!(
            validator.validate(chain, manifest),
            Err(ProfileError::CapabilityWidening {
                kind: CapabilityKind::Write,
                domain: StateDomain::NativeSupply,
                ..
            })
        ));
    }
}
