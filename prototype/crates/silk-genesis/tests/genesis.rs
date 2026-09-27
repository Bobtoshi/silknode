//! End-to-end public-API tests for the deterministic genesis state anchor.

use serde::Deserialize;
use silk_genesis::{
    GENESIS_OBJECT_TAG, GENESIS_OBJECT_VERSION, GenesisObject, GenesisObjectError,
    GenesisObjectField, GenesisObjectPin, UnverifiedGenesisObject,
};
use silk_kernel::{
    GenesisAllocationTemplate, GenesisAllocationTemplateEntry, NativeNote, RECOVERY_PAYLOAD_BYTES,
    TransparentExecutionHost, transparent_checkpoint_descriptor,
    transparent_native_kernel_descriptor,
};
use silk_profile::{
    ConstitutionalCaps, DerivedGenesisIdentity, ExecutionProfile, GENESIS_OBJECT_TEMPLATE_TAG,
    GENESIS_OBJECT_TEMPLATE_VERSION, GenesisObjectRecipe, GenesisObjectTemplate, GenesisProfilePin,
    ModuleDescriptor, ModuleType, ProfileValidator, ProtocolManifest, RoleCapabilityCap,
    StateDomain, UpgradeSchedule,
};
use silk_types::{CanonicalDecode, CanonicalEncode, GenesisId, Hash32, ManifestHash, ModuleId};

const TEST_NETWORK_ID: &[u8] = b"silknode-kernel-gate-a-v1";
const GENESIS_OBJECT_FIXTURE: &str = include_str!("../../../fixtures/genesis-object-v1.json");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GenesisObjectFixture {
    schema: String,
    case_id: String,
    claims: GenesisObjectFixtureClaims,
    canonical_template_hex: String,
    canonical_object_hex: String,
    expected: GenesisObjectFixtureExpected,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
struct GenesisObjectFixtureClaims {
    no_value: bool,
    non_pow_state_anchor: bool,
    detached_from_descriptor_root: bool,
    no_reward: bool,
    no_work: bool,
    first_child_pow_not_implemented: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GenesisObjectFixtureExpected {
    template: GenesisObjectFixtureTemplate,
    object: GenesisObjectFixtureObject,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GenesisObjectFixtureTemplate {
    canonical_length_bytes: usize,
    template_hash_hex: String,
    projection: GenesisObjectFixtureTemplateProjection,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GenesisObjectFixtureTemplateProjection {
    template_tag_u8: u8,
    version_u8: u8,
    protocol_major_u32: u32,
    allocation_template_hash_hex: String,
    derived_slots: Vec<GenesisObjectFixtureSlot>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GenesisObjectFixtureSlot {
    field: String,
    zero_placeholder_hex: String,
    recipe_tag_u8: u8,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GenesisObjectFixtureObject {
    canonical_length_bytes: usize,
    genesis_id_pin_hex: String,
    projection: GenesisObjectFixtureObjectProjection,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GenesisObjectFixtureObjectProjection {
    object_tag_u8: u8,
    version_u8: u8,
    protocol_major_u32: u32,
    allocation_template_hash_hex: String,
    genesis_commitment_hex: String,
    chain_domain_hex: String,
    protocol_manifest_hash_hex: String,
    profile_domain_hex: String,
    checkpoint_zero_state_digest_hex: String,
    checkpoint_zero_id_hex: String,
}

fn hash(byte: u8) -> Hash32 {
    Hash32::from([byte; Hash32::LENGTH])
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

fn fixed_release_genesis_id() -> GenesisId {
    let fixture: GenesisObjectFixture =
        serde_json::from_str(GENESIS_OBJECT_FIXTURE).expect("strict genesis-object fixture parses");
    GenesisId::from_slice(&fixture_hex(
        &fixture.expected.object.genesis_id_pin_hex,
        "genesis_id_pin_hex",
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

fn note(seed: u8, value: u64) -> NativeNote {
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

#[test]
fn public_genesis_path_materializes_verifies_and_pins_exact_object() {
    let allocation = allocation_template(&[note(0x71, 11), note(0x81, 13)]);
    let allocation_bytes = allocation
        .to_canonical_bytes()
        .expect("allocation template encodes");
    let profile = execution_profile(&allocation_bytes);
    let host = TransparentExecutionHost::bind(profile).expect("compiled host binds exact profile");
    let materialized = host
        .genesis(allocation)
        .expect("checkpoint zero materializes");

    let object = GenesisObject::materialize(host.execution_profile(), &materialized)
        .expect("genesis object materializes");
    let canonical_object = object.to_canonical_bytes().expect("object encodes");
    let candidate = UnverifiedGenesisObject::from_canonical_bytes(&canonical_object)
        .expect("canonical object candidate decodes");
    let verified = candidate
        .verify(host.execution_profile(), &materialized)
        .expect("recomputed object verifies");
    assert_eq!(verified, object);

    let genesis_id = object.id().expect("genesis object ID derives");
    let fixed_genesis_id = fixed_release_genesis_id();
    assert_eq!(genesis_id, fixed_genesis_id);
    let pin = GenesisObjectPin::new(fixed_genesis_id);
    assert_eq!(
        pin.verify(&verified)
            .expect("exact genesis object pin verifies"),
        fixed_genesis_id
    );
    let wrong_pin = GenesisObjectPin::new(GenesisId::ZERO);
    assert!(matches!(
        wrong_pin.verify(&verified),
        Err(GenesisObjectError::GenesisIdMismatch { expected, actual })
            if expected == GenesisId::ZERO && actual == genesis_id
    ));

    let mut mutated_bytes = object.to_canonical_bytes().expect("object encodes");
    mutated_bytes[2] ^= 1;
    mutated_bytes[198] ^= 1;
    let mutated = UnverifiedGenesisObject::from_canonical_bytes(&mutated_bytes)
        .expect("mutation stays structural");
    assert!(matches!(
        mutated.verify(host.execution_profile(), &materialized),
        Err(GenesisObjectError::ObjectMismatch {
            field: GenesisObjectField::ProtocolMajor
        })
    ));
}

#[test]
#[allow(clippy::too_many_lines)]
fn consumes_strict_language_neutral_genesis_object_fixture() {
    let document = GENESIS_OBJECT_FIXTURE;
    let fixture: GenesisObjectFixture =
        serde_json::from_str(document).expect("strict genesis-object fixture parses");
    assert_eq!(fixture.schema, "silknode.genesis-object.v1");
    assert_eq!(fixture.case_id, "transparent-two-entry-genesis-object-v1");
    assert!(fixture.claims.no_value);
    assert!(fixture.claims.non_pow_state_anchor);
    assert!(fixture.claims.detached_from_descriptor_root);
    assert!(fixture.claims.no_reward);
    assert!(fixture.claims.no_work);
    assert!(fixture.claims.first_child_pow_not_implemented);

    let allocation = allocation_template(&[note(0x71, 11), note(0x81, 13)]);
    let allocation_bytes = allocation
        .to_canonical_bytes()
        .expect("allocation template encodes");
    let profile = execution_profile(&allocation_bytes);
    let host = TransparentExecutionHost::bind(profile).expect("compiled host binds exact profile");
    let materialized = host
        .genesis(allocation)
        .expect("checkpoint zero materializes");
    let object = GenesisObject::materialize(host.execution_profile(), &materialized)
        .expect("genesis object materializes");

    let expected_template_bytes =
        fixture_hex(&fixture.canonical_template_hex, "canonical_template_hex");
    let expected_object_bytes = fixture_hex(&fixture.canonical_object_hex, "canonical_object_hex");
    let decoded_template = GenesisObjectTemplate::from_canonical_bytes(&expected_template_bytes)
        .expect("fixture template decodes exactly");
    let decoded_object = UnverifiedGenesisObject::from_canonical_bytes(&expected_object_bytes)
        .expect("fixture object candidate decodes exactly");

    assert_eq!(
        &decoded_template,
        host.execution_profile().genesis_object_template()
    );
    assert_eq!(
        decoded_object
            .to_canonical_bytes()
            .expect("fixture object candidate re-encodes"),
        expected_object_bytes
    );
    let verified_object = decoded_object
        .verify(host.execution_profile(), &materialized)
        .expect("fixture object candidate verifies");
    assert_eq!(verified_object, object);
    assert_eq!(
        expected_template_bytes.len(),
        fixture.expected.template.canonical_length_bytes
    );
    assert_eq!(
        expected_object_bytes.len(),
        fixture.expected.object.canonical_length_bytes
    );
    assert_eq!(
        decoded_template
            .hash()
            .expect("fixture template hashes")
            .to_string(),
        fixture.expected.template.template_hash_hex
    );

    let template_projection = fixture.expected.template.projection;
    assert_eq!(
        template_projection.template_tag_u8,
        GENESIS_OBJECT_TEMPLATE_TAG
    );
    assert_eq!(
        template_projection.version_u8,
        GENESIS_OBJECT_TEMPLATE_VERSION
    );
    assert_eq!(
        template_projection.protocol_major_u32,
        decoded_template.protocol_major()
    );
    assert_eq!(
        template_projection.allocation_template_hash_hex,
        decoded_template
            .genesis_allocation_template_hash()
            .to_string()
    );
    let expected_slot_names = [
        "genesis_commitment",
        "chain_domain",
        "protocol_manifest_hash",
        "profile_domain",
        "checkpoint_zero_state_digest",
        "checkpoint_zero_id",
    ];
    assert_eq!(
        template_projection.derived_slots.len(),
        GenesisObjectRecipe::ORDERED.len()
    );
    for ((slot, expected_name), recipe) in template_projection
        .derived_slots
        .iter()
        .zip(expected_slot_names)
        .zip(GenesisObjectRecipe::ORDERED)
    {
        assert_eq!(slot.field, expected_name);
        assert_eq!(
            fixture_hex(&slot.zero_placeholder_hex, "zero_placeholder_hex"),
            vec![0; Hash32::LENGTH]
        );
        assert_eq!(slot.recipe_tag_u8, recipe.tag());
    }

    let object_projection = fixture.expected.object.projection;
    assert_eq!(object_projection.object_tag_u8, GENESIS_OBJECT_TAG);
    assert_eq!(object_projection.version_u8, GENESIS_OBJECT_VERSION);
    assert_eq!(
        object_projection.protocol_major_u32,
        object.protocol_major()
    );
    assert_eq!(
        object_projection.allocation_template_hash_hex,
        object.genesis_allocation_template_hash().to_string()
    );
    assert_eq!(
        object_projection.genesis_commitment_hex,
        object.genesis_commitment().to_string()
    );
    assert_eq!(
        object_projection.chain_domain_hex,
        object.chain_domain().to_string()
    );
    assert_eq!(
        object_projection.protocol_manifest_hash_hex,
        object.protocol_manifest_hash().to_string()
    );
    assert_eq!(
        object_projection.profile_domain_hex,
        object.profile_domain().to_string()
    );
    assert_eq!(
        object_projection.checkpoint_zero_state_digest_hex,
        object.checkpoint_zero_state_digest().to_string()
    );
    assert_eq!(
        object_projection.checkpoint_zero_id_hex,
        object.checkpoint_zero_id().to_string()
    );

    let expected_genesis_id = GenesisId::from_slice(&fixture_hex(
        &fixture.expected.object.genesis_id_pin_hex,
        "genesis_id_pin_hex",
    ))
    .expect("fixture genesis ID is exactly 32 bytes");
    assert_eq!(object.id().expect("object ID derives"), expected_genesis_id);
    assert_eq!(
        GenesisObjectPin::new(expected_genesis_id)
            .verify(&verified_object)
            .expect("fixture release pin verifies"),
        expected_genesis_id
    );
}
