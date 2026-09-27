//! Cross-language vectors for authenticated-anchor linear control ordering.

use serde::{
    Deserialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::Value;
use silk_bootstrap::{
    A2A6_RELEASE_GENESIS_ID, BootstrapError, PinnedGenesisAnchor,
    UnverifiedFirstChildAnchorReference, VerifiedFirstChildAnchorReference,
};
use silk_genesis::{GenesisObject, GenesisObjectError, GenesisObjectPin};
use silk_kernel::{
    GenesisAllocationTemplate, GenesisAllocationTemplateEntry, NativeNote, RECOVERY_PAYLOAD_BYTES,
    TransparentExecutionHost, transparent_checkpoint_descriptor,
    transparent_native_kernel_descriptor,
};
use silk_order::{
    LinearControlVertexId, LinearHistory, LinearParent, LinearVertex, cumulative_work_order,
};
use silk_profile::{
    ConstitutionalCaps, DerivedGenesisIdentity, ExecutionProfile, GenesisProfilePin,
    ModuleDescriptor, ModuleType, ProfileValidator, ProtocolManifest, RoleCapabilityCap,
    StateDomain, UpgradeSchedule,
};
use silk_types::{CanonicalDecode, CanonicalEncode, Hash32, ManifestHash, ModuleId};
use std::collections::{BTreeMap, btree_map::Entry};
use std::fmt;
use std::fs;
use std::path::PathBuf;

const TEST_NETWORK_ID: &[u8] = b"silknode-kernel-gate-a-v1";
const FIXTURE_SCHEMA: &str = "silknode.gate-a.linear-order.v1";
const DUPLICATE_KEY_CODE: &str = "fixture.duplicate_key";
const EXPECTED_FIXTURE_NAMES: &[&str] = &[
    "linear-order-anchor-id-collision-v1.json",
    "linear-order-anchor-mismatch-v1.json",
    "linear-order-cycle-v1.json",
    "linear-order-duplicate-malformed-v1.json",
    "linear-order-duplicate-v1.json",
    "linear-order-empty-v1.json",
    "linear-order-leading-zero-v1.json",
    "linear-order-missing-parent-v1.json",
    "linear-order-multi-error-permuted-v1.json",
    "linear-order-multi-error-v1.json",
    "linear-order-multiple-parents-v1.json",
    "linear-order-overflow-v1.json",
    "linear-order-parentless-v1.json",
    "linear-order-raw-anchor-parent-v1.json",
    "linear-order-unavailable-cycle-v1.json",
    "linear-order-unavailable-v1.json",
    "linear-order-uppercase-v1.json",
    "linear-order-v1.json",
    "linear-order-whitespace-v1.json",
    "linear-order-zero-work-v1.json",
];

struct StrictJsonValue(Value);

struct StrictJsonValueVisitor;

impl<'de> Visitor<'de> for StrictJsonValueVisitor {
    type Value = StrictJsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(StrictJsonValue)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        StrictJsonValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictJsonValue>()? {
            values.push(value.0);
        }
        Ok(StrictJsonValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(DUPLICATE_KEY_CODE));
            }
            let value = object.next_value::<StrictJsonValue>()?;
            values.insert(key, value.0);
        }
        Ok(StrictJsonValue(Value::Object(values)))
    }
}

impl<'de> Deserialize<'de> for StrictJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonValueVisitor)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    schema: String,
    anchor_reference_hex: String,
    vertices: Vec<VertexFixture>,
    expected: Option<Expected>,
    expected_error: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VertexFixture {
    id: String,
    parent: Value,
    declared_test_work: String,
    body_available: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    order: Vec<String>,
    cumulative_test_work: String,
}

fn parse_fixture(document: &str) -> Result<Fixture, String> {
    let root = match serde_json::from_str::<StrictJsonValue>(document) {
        Ok(root) => root.0,
        Err(error) => {
            let message = error.to_string();
            if message.contains(DUPLICATE_KEY_CODE) {
                return Err(DUPLICATE_KEY_CODE.into());
            }
            return Err(message);
        }
    };
    let object = root
        .as_object()
        .ok_or_else(|| "fixture.invalid_shape".to_owned())?;
    if object.get("schema").and_then(Value::as_str) != Some(FIXTURE_SCHEMA) {
        return Err("fixture.unknown_schema".into());
    }
    let has_common_keys = object.contains_key("schema")
        && object.contains_key("anchor_reference_hex")
        && object.contains_key("vertices");
    let is_success = object.len() == 4 && has_common_keys && object.contains_key("expected");
    let is_failure = object.len() == 4 && has_common_keys && object.contains_key("expected_error");
    if is_success == is_failure {
        return Err("fixture.invalid_shape".into());
    }
    if is_success {
        let expected = object["expected"]
            .as_object()
            .ok_or_else(|| "fixture.invalid_shape".to_owned())?;
        if expected.len() != 2
            || !expected.contains_key("order")
            || !expected.contains_key("cumulative_test_work")
        {
            return Err("fixture.invalid_shape".into());
        }
    } else if !object["expected_error"].is_string() {
        return Err("fixture.invalid_shape".into());
    }

    let fixture: Fixture =
        serde_json::from_value(root).map_err(|_| "fixture.invalid_shape".to_owned())?;
    if (is_success && (fixture.expected.is_none() || fixture.expected_error.is_some()))
        || (is_failure && (fixture.expected.is_some() || fixture.expected_error.is_none()))
    {
        return Err("fixture.invalid_shape".into());
    }
    Ok(fixture)
}

fn fixture_paths() -> Vec<PathBuf> {
    let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
    let mut paths = Vec::new();
    for entry in fs::read_dir(&fixture_dir).expect("fixture directory is readable") {
        let path = entry.expect("fixture directory entry is readable").path();
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if path.is_file() && name.starts_with("linear-order") && name.ends_with("-v1.json") {
            paths.push(path);
        }
    }
    paths.sort();
    let names = paths
        .iter()
        .map(|path| {
            path.file_name()
                .and_then(|value| value.to_str())
                .expect("fixture name is UTF-8")
        })
        .collect::<Vec<_>>();
    assert_eq!(names, EXPECTED_FIXTURE_NAMES);
    paths
}

fn hash(value: &str) -> Result<Hash32, String> {
    if value.len() != 64 {
        return Err("fixture.hash_length".into());
    }
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err("fixture.hash_case".into());
    }
    if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("fixture.hash_hex".into());
    }
    let mut bytes = [0_u8; Hash32::LENGTH];
    for (index, output) in bytes.iter_mut().enumerate() {
        *output = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "fixture.hash_hex")?;
    }
    Ok(Hash32::new(bytes))
}

fn hex(value: &str, expected_bytes: usize, code: &str) -> Result<Vec<u8>, String> {
    if value.len() != expected_bytes * 2
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(code.into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = core::str::from_utf8(pair).map_err(|_| code)?;
            u8::from_str_radix(pair, 16).map_err(|_| code.into())
        })
        .collect()
}

fn work(value: &str) -> Result<u128, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("fixture.u128_decimal".into());
    }
    if value.len() > 1 && value.starts_with('0') {
        return Err("fixture.u128_canonical".into());
    }
    value.parse().map_err(|_| "fixture.u128_overflow".into())
}

fn parse_reference(value: &str) -> Result<UnverifiedFirstChildAnchorReference, String> {
    let bytes = hex(value, 34, "fixture.anchor_reference_hex")?;
    UnverifiedFirstChildAnchorReference::from_canonical_bytes(&bytes)
        .map_err(|error| error.code().to_owned())
}

fn parse_parent(value: &Value, anchor: &PinnedGenesisAnchor) -> Result<LinearParent, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "fixture.parent_shape".to_owned())?;
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| "fixture.parent_shape".to_owned())?;
    match kind {
        "anchor" if object.len() == 2 && object.contains_key("reference_hex") => {
            let reference_hex = object["reference_hex"]
                .as_str()
                .ok_or_else(|| "fixture.parent_shape".to_owned())?;
            let verified = parse_reference(reference_hex)?
                .verify(anchor)
                .map_err(|error| error.code().to_owned())?;
            Ok(LinearParent::anchor(&verified))
        }
        "vertex" if object.len() == 2 && object.contains_key("id") => {
            let parent_id = object["id"]
                .as_str()
                .ok_or_else(|| "fixture.parent_shape".to_owned())?;
            Ok(LinearParent::vertex(
                LinearControlVertexId::from_test_oracle_hash(hash(parent_id)?),
            ))
        }
        _ => Err("fixture.parent_shape".into()),
    }
}

fn evaluate_fixture(document: &str) -> Result<LinearHistory, String> {
    let fixture = parse_fixture(document)?;
    if fixture.schema != FIXTURE_SCHEMA {
        return Err("fixture.unknown_schema".into());
    }

    let object = release_genesis_object();
    let anchor =
        PinnedGenesisAnchor::bind_a2a6_release(&object).map_err(|error| error.code().to_owned())?;
    let verified_anchor = parse_reference(&fixture.anchor_reference_hex)?
        .verify(&anchor)
        .map_err(|error| error.code().to_owned())?;

    let mut vertices = BTreeMap::new();
    for vertex in fixture.vertices {
        let id = LinearControlVertexId::from_test_oracle_hash(hash(&vertex.id)?);
        match vertices.entry(id) {
            Entry::Occupied(_) => return Err("fixture.duplicate_vertex".into()),
            Entry::Vacant(slot) => {
                slot.insert(LinearVertex {
                    id,
                    parent: parse_parent(&vertex.parent, &anchor)?,
                    declared_test_work: work(&vertex.declared_test_work)?,
                    body_available: vertex.body_available,
                });
            }
        }
    }

    cumulative_work_order(&verified_anchor, &vertices).map_err(|error| error.code().to_owned())
}

fn assert_fixture(document: &str) {
    let fixture = parse_fixture(document).expect("fixture envelope parses");
    let result = evaluate_fixture(document);
    if let Some(expected_error) = fixture.expected_error {
        assert_eq!(result, Err(expected_error));
        assert!(fixture.expected.is_none());
        return;
    }

    let expected = fixture
        .expected
        .expect("success fixture has expected result");
    let result = result.expect("success fixture evaluates");
    assert!(fixture.expected_error.is_none());
    assert_eq!(
        result.vertices,
        expected
            .order
            .iter()
            .map(|id| {
                LinearControlVertexId::from_test_oracle_hash(
                    hash(id).expect("expected control hash is canonical"),
                )
            })
            .collect::<Vec<_>>(),
    );
    assert_eq!(
        result.cumulative_test_work,
        work(&expected.cumulative_test_work).expect("expected test work is canonical")
    );
}

#[test]
fn discovers_exact_fixture_set_and_matches_all_language_neutral_vectors() {
    for path in fixture_paths() {
        let fixture = fs::read_to_string(&path).expect("fixture is readable UTF-8");
        assert_fixture(&fixture);
    }
}

#[test]
fn root_envelope_requires_exactly_one_typed_expectation() {
    let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
    let success_document = fs::read_to_string(fixture_dir.join("linear-order-v1.json"))
        .expect("success fixture is readable");
    let failure_document = fs::read_to_string(fixture_dir.join("linear-order-cycle-v1.json"))
        .expect("failure fixture is readable");

    let mut success: Value = serde_json::from_str(&success_document).expect("success JSON parses");
    success
        .as_object_mut()
        .expect("success root is an object")
        .insert("expected_error".into(), Value::String("order.cycle".into()));
    assert_eq!(
        evaluate_fixture(&success.to_string()),
        Err("fixture.invalid_shape".into())
    );

    let mut success_without_expected: Value =
        serde_json::from_str(&success_document).expect("success JSON parses");
    success_without_expected
        .as_object_mut()
        .expect("success root is an object")
        .remove("expected");
    assert_eq!(
        evaluate_fixture(&success_without_expected.to_string()),
        Err("fixture.invalid_shape".into())
    );

    let mut null_expected: Value =
        serde_json::from_str(&success_document).expect("success JSON parses");
    null_expected
        .as_object_mut()
        .expect("success root is an object")
        .insert("expected".into(), Value::Null);
    assert_eq!(
        evaluate_fixture(&null_expected.to_string()),
        Err("fixture.invalid_shape".into())
    );

    let mut failure: Value = serde_json::from_str(&failure_document).expect("failure JSON parses");
    failure
        .as_object_mut()
        .expect("failure root is an object")
        .insert("expected".into(), Value::Object(serde_json::Map::new()));
    assert_eq!(
        evaluate_fixture(&failure.to_string()),
        Err("fixture.invalid_shape".into())
    );

    let mut null_error: Value =
        serde_json::from_str(&failure_document).expect("failure JSON parses");
    null_error
        .as_object_mut()
        .expect("failure root is an object")
        .insert("expected_error".into(), Value::Null);
    assert_eq!(
        evaluate_fixture(&null_error.to_string()),
        Err("fixture.invalid_shape".into())
    );
}

#[test]
fn duplicate_key_inside_parent_rejects_before_semantic_parsing() {
    let fixture = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/linear-order-v1.json"),
    )
    .expect("positive fixture is readable");
    let marker = "\"kind\": \"anchor\",";
    let malformed = fixture.replacen(
        marker,
        "\"kind\": \"anchor\",\n        \"kind\": \"anchor\",",
        1,
    );
    assert_ne!(malformed, fixture);
    assert_eq!(evaluate_fixture(&malformed), Err(DUPLICATE_KEY_CODE.into()));
}

#[test]
fn public_order_accepts_only_contextually_verified_anchor() {
    let _: fn(
        &VerifiedFirstChildAnchorReference,
        &BTreeMap<LinearControlVertexId, LinearVertex>,
    ) -> Result<LinearHistory, silk_order::OrderError> = cumulative_work_order;
}

#[test]
fn caller_self_pinned_alternate_genesis_cannot_reach_order() {
    let alternate = genesis_object(&[note(0x72, 11), note(0x82, 13)]);
    let alternate_id = alternate
        .id()
        .expect("alternate verified object ID derives");
    assert_ne!(alternate_id, A2A6_RELEASE_GENESIS_ID);

    let attacker_pin = GenesisObjectPin::new(alternate_id);
    assert_eq!(
        attacker_pin
            .verify(&alternate)
            .expect("generic caller-selected matcher accepts its own object"),
        alternate_id
    );

    let error = PinnedGenesisAnchor::bind_a2a6_release(&alternate)
        .expect_err("alternate self-pinned object must not create an order anchor");
    assert!(matches!(
        error,
        BootstrapError::Genesis(GenesisObjectError::GenesisIdMismatch { expected, actual })
            if expected == A2A6_RELEASE_GENESIS_ID && actual == alternate_id
    ));
}

fn release_genesis_object() -> GenesisObject {
    genesis_object(&[note(0x71, 11), note(0x81, 13)])
}

fn genesis_object(notes: &[NativeNote]) -> GenesisObject {
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

const fn hash_seed(byte: u8) -> Hash32 {
    Hash32::new([byte; Hash32::LENGTH])
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
        hash_seed(seed),
        hash_seed(seed.wrapping_add(1)),
        hash_seed(seed.wrapping_add(2)),
        hash_seed(seed.wrapping_add(3)),
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
    let constitution_hash = hash_seed(0xc8);
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
        owner_tag: hash_seed(seed),
        rho: hash_seed(seed.wrapping_add(1)),
        randomness: hash_seed(seed.wrapping_add(2)),
        nullifier_key: hash_seed(seed.wrapping_add(3)),
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
