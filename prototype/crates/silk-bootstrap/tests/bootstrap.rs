//! End-to-end public-API tests for the authenticated first-child anchor reference.

use serde::Deserialize;
use silk_bootstrap::{
    A2A6_RELEASE_GENESIS_ID, BootstrapError, FIRST_CHILD_ANCHOR_REFERENCE_TAG,
    FIRST_CHILD_ANCHOR_REFERENCE_V1_ENCODED_LENGTH, FIRST_CHILD_ANCHOR_REFERENCE_VERSION,
    PinnedGenesisAnchor, UnverifiedFirstChildAnchorReference,
};
use silk_genesis::{GenesisObject, GenesisObjectError, GenesisObjectPin};
use silk_kernel::{
    GenesisAllocationTemplate, GenesisAllocationTemplateEntry, NativeNote, RECOVERY_PAYLOAD_BYTES,
    TransparentExecutionHost, transparent_checkpoint_descriptor,
    transparent_native_kernel_descriptor,
};
use silk_profile::{
    ConstitutionalCaps, DerivedGenesisIdentity, ExecutionProfile, GenesisProfilePin,
    ModuleDescriptor, ModuleType, ProfileValidator, ProtocolManifest, RoleCapabilityCap,
    StateDomain, UpgradeSchedule,
};
use silk_types::{CanonicalDecode, CanonicalEncode, GenesisId, Hash32, ManifestHash, ModuleId};

const TEST_NETWORK_ID: &[u8] = b"silknode-kernel-gate-a-v1";
const REFERENCE_FIXTURE: &str =
    include_str!("../../../fixtures/first-child-anchor-reference-v1.json");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReferenceFixture {
    schema: String,
    case_id: String,
    scope: ReferenceFixtureScope,
    canonical_reference_hex: String,
    genesis_context: ReferenceFixtureContext,
    expected: ReferenceFixtureExpected,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
struct ReferenceFixtureScope {
    no_value: bool,
    reference_only: bool,
    genesis_is_not_a_vertex: bool,
    mining_policy_not_selected: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReferenceFixtureContext {
    fixture: String,
    genesis_id_hex: String,
    chain_domain_hex: String,
    protocol_manifest_hash_hex: String,
    profile_domain_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReferenceFixtureExpected {
    canonical_length_bytes: usize,
    projection: ReferenceFixtureProjection,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReferenceFixtureProjection {
    reference_tag_u8: u8,
    version_u8: u8,
    genesis_id_hex: String,
}

const fn hash(byte: u8) -> Hash32 {
    Hash32::new([byte; Hash32::LENGTH])
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

fn fixture_genesis_id(fixture: &ReferenceFixture) -> GenesisId {
    GenesisId::from_slice(&fixture_hex(
        &fixture.genesis_context.genesis_id_hex,
        "genesis_context.genesis_id_hex",
    ))
    .expect("fixture genesis ID is exactly 32 bytes")
}

fn profile_descriptor(
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

fn profile_modules() -> Vec<ModuleDescriptor> {
    let wire = profile_descriptor(ModuleType::WireLimits, 10, vec![], vec![], vec![]);
    let pow = profile_descriptor(
        ModuleType::ProofOfWork,
        20,
        vec![wire.module_id()],
        vec![StateDomain::GraphHeaders],
        vec![],
    );
    let daa = profile_descriptor(
        ModuleType::DifficultyAdjustment,
        30,
        vec![pow.module_id()],
        vec![StateDomain::GraphHeaders, StateDomain::Checkpoints],
        vec![],
    );
    let order = profile_descriptor(
        ModuleType::GraphOrder,
        40,
        vec![pow.module_id()],
        vec![StateDomain::GraphHeaders, StateDomain::GraphBodies],
        vec![StateDomain::CanonicalOrder],
    );
    let native_kernel =
        transparent_native_kernel_descriptor().expect("compiled kernel descriptor is canonical");
    let checkpoint =
        transparent_checkpoint_descriptor().expect("compiled checkpoint descriptor is canonical");
    let issuance = profile_descriptor(
        ModuleType::Issuance,
        70,
        vec![checkpoint.module_id()],
        vec![StateDomain::IssuanceCursor],
        vec![],
    );
    let mut modules = vec![wire, pow, daa, order, native_kernel, checkpoint, issuance];
    modules.sort();
    modules
}

fn execution_profile(canonical_allocation_template: &[u8]) -> ExecutionProfile {
    let constitution_hash = hash(0xc8);
    let modules = profile_modules();
    let native_kernel_module_id = modules
        .iter()
        .find(|module| module.module_type() == ModuleType::NativeKernel)
        .expect("fixture has a native kernel")
        .module_id();
    let checkpoint_module_id = modules
        .iter()
        .find(|module| module.module_type() == ModuleType::Checkpoint)
        .expect("fixture has a checkpoint module")
        .module_id();
    let supported = modules.iter().map(ModuleDescriptor::module_id).collect();
    let mut role_caps = modules
        .iter()
        .map(|module| {
            RoleCapabilityCap::new(
                module.module_type(),
                module.declared_state_reads().to_vec(),
                module.declared_state_writes().to_vec(),
            )
            .expect("fixture capability cap is canonical")
        })
        .collect::<Vec<_>>();
    role_caps.sort();
    let caps = ConstitutionalCaps::new(constitution_hash, role_caps)
        .expect("fixture constitution is canonical");
    let manifest = ProtocolManifest::new(
        1,
        constitution_hash,
        ManifestHash::ZERO,
        UpgradeSchedule::genesis(),
        modules,
    )
    .expect("fixture genesis manifest is canonical");
    let identity = DerivedGenesisIdentity::derive(
        TEST_NETWORK_ID,
        manifest
            .genesis_template()
            .expect("genesis manifest projects"),
        canonical_allocation_template,
    )
    .expect("genesis identity derives");
    let chain_domain = identity.chain_domain();
    let manifest_hash = manifest
        .manifest_hash(chain_domain)
        .expect("manifest identity derives");
    let pin = GenesisProfilePin::new(
        identity,
        manifest_hash,
        native_kernel_module_id,
        checkpoint_module_id,
    );
    ProfileValidator::new_with_genesis_pin(caps, supported, pin)
        .validate_and_activate_genesis(chain_domain, manifest)
        .expect("exact pinned genesis profile activates")
}

const fn note(seed: u8, value: u64) -> NativeNote {
    NativeNote {
        value,
        owner_tag: hash(seed),
        rho: hash(seed.wrapping_add(1)),
        randomness: hash(seed.wrapping_add(2)),
        nullifier_key: hash(seed.wrapping_add(3)),
    }
}

fn template_payload(index: usize) -> [u8; RECOVERY_PAYLOAD_BYTES] {
    let mut payload = [0xa6; RECOVERY_PAYLOAD_BYTES];
    payload[..8].copy_from_slice(
        &u64::try_from(index)
            .expect("test allocation index fits u64")
            .to_le_bytes(),
    );
    payload
}

fn allocation_template(notes: &[NativeNote]) -> GenesisAllocationTemplate {
    let entries = notes
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, note)| GenesisAllocationTemplateEntry::new(note, template_payload(index)))
        .collect();
    GenesisAllocationTemplate::new(entries).expect("fixture allocation template is bounded")
}

fn materialize_object(notes: &[NativeNote]) -> GenesisObject {
    let allocation = allocation_template(notes);
    let allocation_bytes = allocation
        .to_canonical_bytes()
        .expect("allocation template encodes");
    let profile = execution_profile(&allocation_bytes);
    let host = TransparentExecutionHost::bind(profile).expect("compiled host binds exact profile");
    let materialized = host
        .genesis(allocation)
        .expect("checkpoint zero materializes");
    GenesisObject::materialize(host.execution_profile(), &materialized)
        .expect("genesis object materializes")
}

#[test]
fn strict_fixture_binds_verified_genesis_and_promotes_exact_reference() {
    let fixture: ReferenceFixture =
        serde_json::from_str(REFERENCE_FIXTURE).expect("strict bootstrap fixture parses");
    assert_eq!(fixture.schema, "silknode.first-child-anchor-reference.v1");
    assert_eq!(
        fixture.case_id,
        "transparent-two-entry-first-child-anchor-reference-v1"
    );
    assert!(fixture.scope.no_value);
    assert!(fixture.scope.reference_only);
    assert!(fixture.scope.genesis_is_not_a_vertex);
    assert!(fixture.scope.mining_policy_not_selected);
    assert_eq!(fixture.genesis_context.fixture, "genesis-object-v1.json");

    let object = materialize_object(&[note(0x71, 11), note(0x81, 13)]);
    let expected_id = fixture_genesis_id(&fixture);
    assert_eq!(expected_id, A2A6_RELEASE_GENESIS_ID);
    let anchor = PinnedGenesisAnchor::bind_a2a6_release(&object)
        .expect("verified genesis object satisfies built-in A2a-6 release pin");
    assert_eq!(anchor.genesis_id(), expected_id);
    assert_eq!(
        anchor.chain_domain().to_string(),
        fixture.genesis_context.chain_domain_hex
    );
    assert_eq!(
        anchor.profile_domain().to_string(),
        fixture.genesis_context.profile_domain_hex
    );
    assert_eq!(
        anchor.protocol_manifest_hash().to_string(),
        fixture.genesis_context.protocol_manifest_hash_hex
    );
    assert_eq!(
        anchor.protocol_manifest_hash(),
        object.protocol_manifest_hash()
    );

    let bytes = fixture_hex(&fixture.canonical_reference_hex, "canonical_reference_hex");
    assert_eq!(bytes.len(), FIRST_CHILD_ANCHOR_REFERENCE_V1_ENCODED_LENGTH);
    assert_eq!(
        fixture.expected.canonical_length_bytes,
        FIRST_CHILD_ANCHOR_REFERENCE_V1_ENCODED_LENGTH
    );
    assert_eq!(
        fixture.expected.projection.reference_tag_u8,
        FIRST_CHILD_ANCHOR_REFERENCE_TAG
    );
    assert_eq!(
        fixture.expected.projection.version_u8,
        FIRST_CHILD_ANCHOR_REFERENCE_VERSION
    );
    assert_eq!(
        fixture.expected.projection.genesis_id_hex,
        fixture.genesis_context.genesis_id_hex
    );

    let candidate = UnverifiedFirstChildAnchorReference::from_canonical_bytes(&bytes)
        .expect("canonical fixture decodes only as an unverified candidate");
    assert_eq!(
        candidate
            .to_canonical_bytes()
            .expect("candidate re-encodes"),
        bytes
    );
    let verified = candidate
        .verify(&anchor)
        .expect("candidate names exact pinned anchor");
    assert_eq!(verified.genesis_id(), expected_id);
    assert_eq!(verified.chain_domain(), object.chain_domain());
    assert_eq!(verified.profile_domain(), object.profile_domain());
    assert_eq!(
        verified.to_canonical_bytes().expect("verified re-encodes"),
        bytes
    );
}

#[test]
fn caller_self_pinned_alternate_genesis_cannot_enter_bootstrap() {
    let object = materialize_object(&[note(0x71, 11), note(0x81, 13)]);
    let anchor =
        PinnedGenesisAnchor::bind_a2a6_release(&object).expect("exact A2a-6 release object binds");
    let expected_id = anchor.genesis_id();
    assert_eq!(expected_id, A2A6_RELEASE_GENESIS_ID);
    let candidate_bytes = {
        let fixture: ReferenceFixture =
            serde_json::from_str(REFERENCE_FIXTURE).expect("strict bootstrap fixture parses");
        fixture_hex(&fixture.canonical_reference_hex, "canonical_reference_hex")
    };
    let candidate = UnverifiedFirstChildAnchorReference::from_canonical_bytes(&candidate_bytes)
        .expect("reference fixture decodes");
    candidate
        .verify(&anchor)
        .expect("fixture reference matches original genesis context");

    let other_object = materialize_object(&[note(0x72, 11), note(0x82, 13)]);
    let other_id = other_object.id().expect("other verified object ID derives");
    assert_ne!(other_id, A2A6_RELEASE_GENESIS_ID);
    let attacker_pin = GenesisObjectPin::new(other_id);
    assert_eq!(
        attacker_pin
            .verify(&other_object)
            .expect("generic caller-selected matcher accepts its own object"),
        other_id
    );
    let error = PinnedGenesisAnchor::bind_a2a6_release(&other_object)
        .expect_err("alternate self-pinned object must not create bootstrap authority");
    assert_eq!(error.code(), "genesis.id_mismatch");
    assert!(matches!(
        error,
        BootstrapError::Genesis(GenesisObjectError::GenesisIdMismatch { expected, actual })
            if expected == A2A6_RELEASE_GENESIS_ID && actual == other_id
    ));
}

#[test]
fn complete_cross_type_objects_cannot_decode_as_anchor_references() {
    let object = materialize_object(&[note(0x71, 11), note(0x81, 13)]);
    let object_bytes = object.to_canonical_bytes().expect("genesis object encodes");
    let raw_id = object
        .id()
        .expect("verified object ID derives")
        .into_bytes();

    assert!(UnverifiedFirstChildAnchorReference::from_canonical_bytes(&object_bytes).is_err());
    assert!(UnverifiedFirstChildAnchorReference::from_canonical_bytes(&raw_id).is_err());
}
