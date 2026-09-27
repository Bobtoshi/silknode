//! Detached cross-language transition, codec, replay, and tamper corpus.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::Value;
use silk_kernel::{
    CheckpointState, GenesisAllocationTemplate, NativeIntervalResult, OrderedBody, Outcome,
    Transition, TransparentExecutionHost, TrustedCheckpointPin, UnverifiedAcceptedEffect,
    UnverifiedCheckpointState, UnverifiedDecision, UnverifiedNativeIntervalResult,
    UnverifiedNativeStateProjection, UnverifiedOutcome, UnverifiedTransition,
    transparent_checkpoint_descriptor, transparent_native_kernel_descriptor,
};
use silk_profile::{
    ConstitutionalCaps, DerivedGenesisIdentity, ExecutionProfile, GenesisProfilePin,
    ModuleDescriptor, ModuleType, ProfileValidator, ProtocolManifest, RoleCapabilityCap,
    StateDomain, UpgradeSchedule,
};
use silk_types::{CanonicalDecode, CanonicalEncode, Hash32, ManifestHash, ModuleId};

const FIXTURE_BYTES: &str =
    include_str!("../../../fixtures/transparent-kernel-transition-differential-v1.json");

const COMPOUND_CASE_IDS: [&str; 6] = [
    "compound_empty_inputs_precedes_wrong_chain",
    "compound_wrong_chain_precedes_duplicate_input",
    "compound_wrong_chain_precedes_recovery_vector",
    "compound_history_conflict_precedes_output_opening",
    "compound_already_spent_precedes_witness_opening",
    "compound_conservation_precedes_recovery_hash",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    coherent_checkpoint_pin_case: PinCase,
    compound_cases: Vec<Case>,
    conflict_case_ids: Vec<String>,
    context: Context,
    field_coverage: FieldCoverage,
    malformed_codec_cases: Vec<MalformedCase>,
    mutation_matrix: Vec<SemanticMutation>,
    positive_case: PositiveCase,
    properties: Properties,
    rejection_cases: Vec<Case>,
    rejection_slots: Vec<RejectionSlot>,
    schema: String,
    scope: Scope,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Scope {
    descriptor_root_bound: bool,
    kind: String,
    second_kernel_interpreter: bool,
    valuable_assets: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    allocation_template_canonical_hex: String,
    chain_domain_hex: String,
    genesis_checkpoint_id_hex: String,
    network_id_hex: String,
    profile_domain_hex: String,
    protocol_major_u32: u32,
    trusted_allocation_template_hash_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    expected_transition_artifacts: TransitionArtifacts,
    expected_outcomes: Vec<ExpectedOutcome>,
    id: String,
    ordered_bodies_hex: Vec<String>,
    prelude_bodies_hex: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PositiveCase {
    expected_artifacts: ExpectedArtifacts,
    expected_outcomes: Vec<ExpectedOutcome>,
    id: String,
    ordered_bodies_hex: Vec<String>,
    prelude_bodies_hex: Vec<String>,
}

impl PositiveCase {
    fn as_case(&self) -> Case {
        Case {
            expected_transition_artifacts: TransitionArtifacts {
                c4_hex: self.expected_artifacts.c4_hex.clone(),
                c6_hex: self.expected_artifacts.c6_hex.clone(),
            },
            expected_outcomes: self.expected_outcomes.clone(),
            id: self.id.clone(),
            ordered_bodies_hex: self.ordered_bodies_hex.clone(),
            prelude_bodies_hex: self.prelude_bodies_hex.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TransitionArtifacts {
    c4_hex: String,
    c6_hex: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedOutcome {
    code: String,
    numeric_u16: u16,
    outcome: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
struct ExpectedArtifacts {
    c0_hex: String,
    c1_hex: String,
    c2_hex: String,
    c3_hex: String,
    c4_hex: String,
    c5_hex: String,
    c6_hex: String,
}

impl ExpectedArtifacts {
    fn decoded(&self) -> BTreeMap<&'static str, Vec<u8>> {
        BTreeMap::from([
            ("c0", hex_bytes(&self.c0_hex)),
            ("c1", hex_bytes(&self.c1_hex)),
            ("c2", hex_bytes(&self.c2_hex)),
            ("c3", hex_bytes(&self.c3_hex)),
            ("c4", hex_bytes(&self.c4_hex)),
            ("c5", hex_bytes(&self.c5_hex)),
            ("c6", hex_bytes(&self.c6_hex)),
        ])
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RejectionSlot {
    classification: String,
    code: String,
    decision_index_u32: u32,
    numeric_u16: u16,
    rationale: String,
    reachable_case_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Properties {
    base_immutable: bool,
    deterministic_replay: bool,
    rollback_returns_base: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MalformedCase {
    artifact: String,
    expected_error_code: String,
    id: String,
    operation: Operation,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SemanticMutation {
    base_artifact: String,
    expected_error_code: String,
    field: String,
    id: String,
    object: String,
    operation: Operation,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Operation {
    SetByte {
        offset_u32: u32,
        value_u8: u8,
    },
    TruncateTail {
        count_u32: u32,
    },
    Append {
        hex: String,
    },
    ReplaceRange {
        offset_u32: u32,
        remove_u32: u32,
        hex: String,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FieldCoverage {
    c0: Vec<String>,
    c1: Vec<String>,
    c2: Vec<String>,
    c3: Vec<String>,
    c4: Vec<String>,
    c5: Vec<String>,
    c6: Vec<String>,
}

impl FieldCoverage {
    fn entries(&self) -> [(&'static str, &[String]); 7] {
        [
            ("c0", &self.c0),
            ("c1", &self.c1),
            ("c2", &self.c2),
            ("c3", &self.c3),
            ("c4", &self.c4),
            ("c5", &self.c5),
            ("c6", &self.c6),
        ]
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PinCase {
    artifact_hex: String,
    expected_error_code: String,
    external_pin_hex: String,
    id: String,
}

struct ExecutedCase {
    base: CheckpointState,
    bodies: Vec<OrderedBody>,
    transition: Transition,
}

fn fixture() -> Fixture {
    serde_json::from_str(FIXTURE_BYTES).expect("transition fixture is strict valid JSON")
}

fn fixture_value() -> Value {
    serde_json::from_str(FIXTURE_BYTES).expect("transition fixture is valid JSON")
}

fn hash(byte: u8) -> Hash32 {
    Hash32::from([byte; 32])
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("fixture hex must use lowercase ASCII"),
    }
}

fn hex_bytes(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2), "fixture hex length is even");
    assert!(value.is_ascii(), "fixture hex is ASCII");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
        .collect()
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
    .expect("test descriptor is canonical")
}

fn profile_modules() -> Vec<ModuleDescriptor> {
    let wire = descriptor(ModuleType::WireLimits, 10, vec![], vec![], vec![]);
    let pow = descriptor(
        ModuleType::ProofOfWork,
        20,
        vec![wire.module_id()],
        vec![StateDomain::GraphHeaders],
        vec![],
    );
    let difficulty = descriptor(
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
    let kernel = transparent_native_kernel_descriptor().expect("kernel descriptor is canonical");
    let checkpoint =
        transparent_checkpoint_descriptor().expect("checkpoint descriptor is canonical");
    let issuance = descriptor(
        ModuleType::Issuance,
        70,
        vec![checkpoint.module_id()],
        vec![StateDomain::IssuanceCursor],
        vec![],
    );
    let mut modules = vec![wire, pow, difficulty, order, kernel, checkpoint, issuance];
    modules.sort();
    modules
}

fn execution_profile(context: &Context, trusted_template: &[u8]) -> ExecutionProfile {
    let modules = profile_modules();
    let constitution_hash = hash(0xc8);
    let native_kernel_module_id = modules
        .iter()
        .find(|module| module.module_type() == ModuleType::NativeKernel)
        .expect("profile has a native kernel")
        .module_id();
    let checkpoint_module_id = modules
        .iter()
        .find(|module| module.module_type() == ModuleType::Checkpoint)
        .expect("profile has a checkpoint module")
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
            .expect("role cap is canonical")
        })
        .collect::<Vec<_>>();
    role_caps.sort();
    let caps = ConstitutionalCaps::new(constitution_hash, role_caps)
        .expect("constitutional caps are canonical");
    let manifest = ProtocolManifest::new(
        context.protocol_major_u32,
        constitution_hash,
        ManifestHash::ZERO,
        UpgradeSchedule::genesis(),
        modules,
    )
    .expect("genesis manifest is canonical");
    let identity = DerivedGenesisIdentity::derive(
        &hex_bytes(&context.network_id_hex),
        manifest
            .genesis_template()
            .expect("manifest projects a genesis template"),
        trusted_template,
    )
    .expect("genesis identity derives");
    let chain = identity.chain_domain();
    let manifest_hash = manifest
        .manifest_hash(chain)
        .expect("genesis manifest hashes");
    let pin = GenesisProfilePin::new(
        identity,
        manifest_hash,
        native_kernel_module_id,
        checkpoint_module_id,
    );
    ProfileValidator::new_with_genesis_pin(caps, supported, pin)
        .validate_and_activate_genesis(chain, manifest)
        .expect("profile activates")
}

fn host_and_genesis(context: &Context) -> (TransparentExecutionHost, CheckpointState) {
    let template_bytes = hex_bytes(&context.allocation_template_canonical_hex);
    let template = GenesisAllocationTemplate::from_canonical_bytes(&template_bytes)
        .expect("trusted allocation template decodes");
    assert_eq!(
        template
            .to_canonical_bytes()
            .expect("allocation template re-encodes"),
        template_bytes
    );
    assert_eq!(
        template
            .template_hash()
            .expect("template hashes")
            .to_string(),
        context.trusted_allocation_template_hash_hex
    );
    let profile = execution_profile(context, &template_bytes);
    assert_eq!(profile.chain_domain().to_string(), context.chain_domain_hex);
    assert_eq!(
        profile.profile_domain().to_string(),
        context.profile_domain_hex
    );
    let host = TransparentExecutionHost::bind(profile).expect("profile binds to this host");
    let materialized = host.genesis(template).expect("genesis materializes");
    let (genesis, _) = materialized.into_parts();
    assert_eq!(
        genesis.checkpoint_id().to_string(),
        context.genesis_checkpoint_id_hex
    );
    (host, genesis)
}

fn bodies(values: &[String]) -> Vec<OrderedBody> {
    values
        .iter()
        .map(|value| {
            let bytes = hex_bytes(value);
            let body = OrderedBody::from_canonical_bytes(&bytes).expect("fixture body decodes");
            assert_eq!(
                body.to_canonical_bytes().expect("fixture body re-encodes"),
                bytes
            );
            body
        })
        .collect()
}

fn assert_outcomes(expected: &[ExpectedOutcome], transition: &Transition) {
    assert_eq!(expected.len(), transition.decisions().len());
    for (expected, actual) in expected.iter().zip(transition.decisions()) {
        match actual.outcome {
            Outcome::Accepted => {
                assert_eq!(expected.outcome, "accepted");
                assert_eq!(expected.numeric_u16, 0);
                assert!(expected.code.is_empty());
            }
            Outcome::Rejected(code) => {
                assert_eq!(expected.outcome, "rejected");
                assert_eq!(expected.numeric_u16, code.numeric());
                assert_eq!(expected.code, code.code());
            }
        }
    }
}

fn execute_case(
    host: &TransparentExecutionHost,
    genesis: &CheckpointState,
    value: &Case,
) -> ExecutedCase {
    assert!(!value.id.is_empty(), "case IDs are nonempty");
    let mut base = genesis.clone();
    let prelude = bodies(&value.prelude_bodies_hex);
    if !prelude.is_empty() {
        base = host
            .apply_and_seal(&base, &prelude)
            .expect("case prelude executes")
            .into_next();
    }
    let ordered = bodies(&value.ordered_bodies_hex);
    assert!(!ordered.is_empty(), "target case contains a body");
    let transition = host
        .apply_and_seal(&base, &ordered)
        .expect("case transition executes");
    assert_outcomes(&value.expected_outcomes, &transition);
    let result = transition.native_interval_result();
    assert_eq!(
        result.to_canonical_bytes().expect("case c4 encodes"),
        hex_bytes(&value.expected_transition_artifacts.c4_hex),
        "{} c4 full transition artifact",
        value.id
    );
    assert_eq!(
        transition.to_canonical_bytes().expect("case c6 encodes"),
        hex_bytes(&value.expected_transition_artifacts.c6_hex),
        "{} c6 full transition artifact",
        value.id
    );
    ExecutedCase {
        base,
        bodies: ordered,
        transition,
    }
}

fn artifact_bytes(
    transition: &Transition,
    result: &NativeIntervalResult,
) -> BTreeMap<&'static str, Vec<u8>> {
    let first_decision = transition
        .decisions()
        .first()
        .expect("positive transition has a decision");
    let first_effect = result
        .accepted_effects()
        .first()
        .expect("positive transition has an accepted effect");
    BTreeMap::from([
        (
            "c0",
            result
                .resulting_native_state()
                .to_canonical_bytes()
                .expect("c0 encodes"),
        ),
        (
            "c1",
            first_decision
                .outcome
                .to_canonical_bytes()
                .expect("c1 encodes"),
        ),
        (
            "c2",
            first_decision.to_canonical_bytes().expect("c2 encodes"),
        ),
        ("c3", first_effect.to_canonical_bytes().expect("c3 encodes")),
        ("c4", result.to_canonical_bytes().expect("c4 encodes")),
        (
            "c5",
            transition.next().to_canonical_bytes().expect("c5 encodes"),
        ),
        ("c6", transition.to_canonical_bytes().expect("c6 encodes")),
    ])
}

fn mutate(base: &[u8], operation: &Operation) -> Vec<u8> {
    let mut bytes = base.to_vec();
    match operation {
        Operation::SetByte {
            offset_u32,
            value_u8,
        } => {
            let offset = usize::try_from(*offset_u32).expect("offset fits usize");
            *bytes.get_mut(offset).expect("set-byte offset is in range") = *value_u8;
        }
        Operation::TruncateTail { count_u32 } => {
            let count = usize::try_from(*count_u32).expect("count fits usize");
            let length = bytes
                .len()
                .checked_sub(count)
                .expect("truncate count is in range");
            bytes.truncate(length);
        }
        Operation::Append { hex } => bytes.extend(hex_bytes(hex)),
        Operation::ReplaceRange {
            offset_u32,
            remove_u32,
            hex,
        } => {
            let offset = usize::try_from(*offset_u32).expect("offset fits usize");
            let remove = usize::try_from(*remove_u32).expect("remove length fits usize");
            let end = offset
                .checked_add(remove)
                .expect("replacement range does not overflow");
            assert!(end <= bytes.len(), "replacement range is in bounds");
            bytes.splice(offset..end, hex_bytes(hex));
        }
    }
    assert_ne!(bytes, base, "fixture mutation changes bytes");
    bytes
}

fn decode_error_code(artifact: &str, bytes: &[u8]) -> &'static str {
    let result = match artifact {
        "c0" => UnverifiedNativeStateProjection::from_canonical_bytes(bytes).map(|_| ()),
        "c1" => UnverifiedOutcome::from_canonical_bytes(bytes).map(|_| ()),
        "c2" => UnverifiedDecision::from_canonical_bytes(bytes).map(|_| ()),
        "c3" => UnverifiedAcceptedEffect::from_canonical_bytes(bytes).map(|_| ()),
        "c4" => UnverifiedNativeIntervalResult::from_canonical_bytes(bytes).map(|_| ()),
        "c5" => UnverifiedCheckpointState::from_canonical_bytes(bytes).map(|_| ()),
        "c6" => UnverifiedTransition::from_canonical_bytes(bytes).map(|_| ()),
        other => panic!("unknown artifact {other}"),
    };
    result
        .expect_err("malformed artifact must fail decoding")
        .code()
}

fn promotion_error_code(
    host: &TransparentExecutionHost,
    positive: &ExecutedCase,
    artifact: &str,
    bytes: &[u8],
) -> &'static str {
    match artifact {
        "c4" => host
            .verify_native_interval_result(
                UnverifiedNativeIntervalResult::from_canonical_bytes(bytes)
                    .expect("semantic c4 mutation decodes"),
                &positive.base,
                &positive.bodies,
            )
            .expect_err("semantic c4 mutation must not promote")
            .code(),
        "c5" => host
            .verify_checkpoint_state(
                UnverifiedCheckpointState::from_canonical_bytes(bytes)
                    .expect("semantic c5 mutation decodes"),
                TrustedCheckpointPin::from_trusted_state(positive.transition.next()),
            )
            .expect_err("semantic c5 mutation must not promote")
            .code(),
        "c6" => host
            .verify_transition(
                UnverifiedTransition::from_canonical_bytes(bytes)
                    .expect("semantic c6 mutation decodes"),
                &positive.base,
                &positive.bodies,
            )
            .expect_err("semantic c6 mutation must not promote")
            .code(),
        other => panic!("unsupported promotion artifact {other}"),
    }
}

fn expected_field_coverage() -> BTreeMap<&'static str, &'static [&'static str]> {
    BTreeMap::from([
        (
            "c0",
            &[
                "live_notes",
                "nullifiers",
                "commitment_history",
                "recovery_history",
                "accepted_intents",
                "native_issued",
                "fee_pool",
            ][..],
        ),
        ("c1", &["variant", "reject_code"]),
        (
            "c2",
            &[
                "position",
                "body_id",
                "body_position",
                "transaction_position",
                "intent_id",
                "instance_hash",
                "outcome",
            ],
        ),
        ("c3", &["body_id", "intent_id"]),
        (
            "c4",
            &["decisions", "accepted_effects", "resulting_native_state"],
        ),
        (
            "c5",
            &[
                "chain_domain",
                "profile_domain",
                "checkpoint_id",
                "previous_checkpoint",
                "checkpoint_index",
                "live_notes",
                "nullifiers",
                "commitment_history",
                "recovery_history",
                "ordered_body_history",
                "bodies_in_checkpoint",
                "body_bindings_in_checkpoint",
                "accepted_intents",
                "accepted_effects_in_checkpoint",
                "native_issued",
                "fee_pool",
            ],
        ),
        ("c6", &["previous", "next", "decisions"]),
    ])
}

fn expected_mutation_locations() -> BTreeMap<(&'static str, &'static str), (&'static str, u32, u32)>
{
    BTreeMap::from([
        (("c0", "live_notes"), ("c4", 425, 1)),
        (("c0", "nullifiers"), ("c4", 767, 32)),
        (("c0", "commitment_history"), ("c4", 803, 96)),
        (("c0", "recovery_history"), ("c4", 936, 1)),
        (("c0", "accepted_intents"), ("c4", 1_390, 32)),
        (("c0", "native_issued"), ("c4", 1_422, 1)),
        (("c0", "fee_pool"), ("c4", 1_438, 1)),
        (("c1", "variant"), ("c4", 118, 0)),
        (("c1", "reject_code"), ("c4", 347, 2)),
        (("c2", "position"), ("c4", 8, 1)),
        (("c2", "body_id"), ("c4", 12, 32)),
        (("c2", "body_position"), ("c4", 44, 1)),
        (("c2", "transaction_position"), ("c4", 48, 1)),
        (("c2", "intent_id"), ("c4", 52, 32)),
        (("c2", "instance_hash"), ("c4", 84, 32)),
        (("c2", "outcome"), ("c4", 118, 0)),
        (("c3", "body_id"), ("c4", 355, 32)),
        (("c3", "intent_id"), ("c4", 387, 32)),
        (("c4", "decisions"), ("c4", 2, 346)),
        (("c4", "accepted_effects"), ("c4", 349, 70)),
        (("c4", "resulting_native_state"), ("c4", 1_438, 1)),
        (("c5", "chain_domain"), ("c5", 2, 32)),
        (("c5", "profile_domain"), ("c5", 34, 32)),
        (("c5", "checkpoint_id"), ("c5", 66, 32)),
        (("c5", "previous_checkpoint"), ("c5", 98, 32)),
        (("c5", "checkpoint_index"), ("c5", 130, 1)),
        (("c5", "live_notes"), ("c5", 142, 1)),
        (("c5", "nullifiers"), ("c5", 484, 32)),
        (("c5", "commitment_history"), ("c5", 520, 64)),
        (("c5", "recovery_history"), ("c5", 653, 1)),
        (("c5", "ordered_body_history"), ("c5", 1_107, 32)),
        (("c5", "bodies_in_checkpoint"), ("c5", 1_207, 32)),
        (("c5", "body_bindings_in_checkpoint"), ("c5", 1_307, 32)),
        (("c5", "accepted_intents"), ("c5", 1_407, 32)),
        (("c5", "accepted_effects_in_checkpoint"), ("c5", 1_477, 32)),
        (("c5", "native_issued"), ("c5", 1_509, 1)),
        (("c5", "fee_pool"), ("c5", 1_525, 1)),
        (("c6", "previous"), ("c6", 68, 32)),
        (("c6", "next"), ("c6", 636, 32)),
        (("c6", "decisions"), ("c6", 2_111, 346)),
    ])
}

fn object_mut<'a>(value: &'a mut Value, pointer: &str) -> &'a mut serde_json::Map<String, Value> {
    value
        .pointer_mut(pointer)
        .and_then(Value::as_object_mut)
        .unwrap_or_else(|| panic!("{pointer} identifies an object"))
}

#[test]
fn shared_transition_corpus_executes_and_promotes_exact_bytes() {
    let fixture = fixture();
    assert_eq!(
        fixture.schema,
        "silknode.transparent-kernel-transition-differential.v1"
    );
    assert_eq!(fixture.scope.kind, "detached_full_transition_corpus");
    assert!(!fixture.scope.descriptor_root_bound);
    assert!(!fixture.scope.second_kernel_interpreter);
    assert!(!fixture.scope.valuable_assets);

    let (host, genesis) = host_and_genesis(&fixture.context);
    let positive_case = fixture.positive_case.as_case();
    let positive = execute_case(&host, &genesis, &positive_case);
    let result = positive.transition.native_interval_result();
    let artifacts = artifact_bytes(&positive.transition, &result);
    assert_eq!(
        artifacts,
        fixture.positive_case.expected_artifacts.decoded()
    );

    let c0 = UnverifiedNativeStateProjection::from_canonical_bytes(&artifacts["c0"])
        .expect("c0 candidate decodes")
        .verify(host.execution_profile().chain_domain())
        .expect("valid c0 invariants promote");
    assert_eq!(&c0, result.resulting_native_state());
    let c1 = UnverifiedOutcome::from_canonical_bytes(&artifacts["c1"])
        .expect("c1 candidate decodes")
        .verify()
        .expect("known c1 outcome promotes");
    assert_eq!(c1, positive.transition.decisions()[0].outcome);
    assert_eq!(
        UnverifiedDecision::from_canonical_bytes(&artifacts["c2"])
            .expect("c2 candidate decodes")
            .to_canonical_bytes()
            .expect("c2 candidate re-encodes"),
        artifacts["c2"]
    );
    assert_eq!(
        UnverifiedAcceptedEffect::from_canonical_bytes(&artifacts["c3"])
            .expect("c3 candidate decodes")
            .to_canonical_bytes()
            .expect("c3 candidate re-encodes"),
        artifacts["c3"]
    );
    assert_eq!(
        host.verify_native_interval_result(
            UnverifiedNativeIntervalResult::from_canonical_bytes(&artifacts["c4"])
                .expect("c4 candidate decodes"),
            &positive.base,
            &positive.bodies,
        )
        .expect("exact replay promotes c4"),
        result
    );
    assert_eq!(
        host.verify_checkpoint_state(
            UnverifiedCheckpointState::from_canonical_bytes(&artifacts["c5"])
                .expect("c5 candidate decodes"),
            TrustedCheckpointPin::from_trusted_state(positive.transition.next()),
        )
        .expect("identity and external pin promote c5"),
        *positive.transition.next()
    );
    assert_eq!(
        host.verify_transition(
            UnverifiedTransition::from_canonical_bytes(&artifacts["c6"])
                .expect("c6 candidate decodes"),
            &positive.base,
            &positive.bodies,
        )
        .expect("exact replay promotes c6"),
        positive.transition
    );
}

#[test]
fn every_rejection_slot_precedence_conflict_replay_and_rollback_are_executed() {
    let fixture = fixture();
    let (host, genesis) = host_and_genesis(&fixture.context);
    let mut executed = BTreeMap::new();
    for value in &fixture.rejection_cases {
        let result = execute_case(&host, &genesis, value);
        assert!(executed.insert(value.id.clone(), result).is_none());
    }
    assert_eq!(executed.len(), 21);
    assert_eq!(fixture.rejection_slots.len(), 25);
    let unreachable = BTreeSet::from([6_u16, 7, 23, 25]);
    let mut reachable_ids = BTreeSet::new();
    for (offset, slot) in fixture.rejection_slots.iter().enumerate() {
        let numeric = u16::try_from(offset + 1).expect("25 slots fit u16");
        assert_eq!(slot.numeric_u16, numeric);
        let code = silk_kernel::RejectCode::try_from(numeric).expect("slot is assigned");
        assert_eq!(slot.code, code.code());
        if unreachable.contains(&numeric) {
            assert_eq!(slot.classification, "unreachable_boundary");
            assert!(slot.reachable_case_id.is_empty());
            assert_eq!(slot.decision_index_u32, 0);
            assert!(!slot.rationale.is_empty());
        } else {
            assert_eq!(slot.classification, "reachable_transition");
            assert!(slot.rationale.is_empty());
            let transition = &executed[&slot.reachable_case_id].transition;
            let decision = &transition.decisions()
                [usize::try_from(slot.decision_index_u32).expect("index fits usize")];
            assert_eq!(decision.outcome, Outcome::Rejected(code));
            assert!(reachable_ids.insert(slot.reachable_case_id.clone()));
        }
    }
    assert_eq!(reachable_ids, executed.keys().cloned().collect());

    assert_eq!(
        fixture
            .compound_cases
            .iter()
            .map(|value| value.id.as_str())
            .collect::<Vec<_>>(),
        COMPOUND_CASE_IDS
    );
    for value in &fixture.compound_cases {
        execute_case(&host, &genesis, value);
    }
    assert_eq!(
        fixture.conflict_case_ids,
        ["reject_17_conflict_lost", "reject_20_commitment_conflict"]
    );
    for case_id in &fixture.conflict_case_ids {
        let decisions = executed[case_id].transition.decisions();
        assert!(matches!(decisions[0].outcome, Outcome::Accepted));
        assert!(matches!(decisions[1].outcome, Outcome::Rejected(_)));
    }

    assert!(fixture.properties.base_immutable);
    assert!(fixture.properties.deterministic_replay);
    assert!(fixture.properties.rollback_returns_base);
    let positive_case = fixture.positive_case.as_case();
    let positive = execute_case(&host, &genesis, &positive_case);
    let genesis_before = genesis
        .to_canonical_bytes()
        .expect("genesis snapshot encodes");
    let replay = host
        .apply_and_seal(&positive.base, &positive.bodies)
        .expect("clean replay executes");
    assert_eq!(replay, positive.transition);
    assert_eq!(positive.transition.clone().rollback(), positive.base);
    assert_eq!(
        genesis.to_canonical_bytes().expect("genesis re-encodes"),
        genesis_before
    );
}

#[test]
fn malformed_and_every_logical_field_mutation_fail_closed() {
    let fixture = fixture();
    let (host, genesis) = host_and_genesis(&fixture.context);
    let positive_case = fixture.positive_case.as_case();
    let positive = execute_case(&host, &genesis, &positive_case);
    let result = positive.transition.native_interval_result();
    let artifacts = artifact_bytes(&positive.transition, &result);

    let mut malformed_ids = BTreeSet::new();
    for value in &fixture.malformed_codec_cases {
        assert!(!value.id.is_empty());
        assert!(malformed_ids.insert(&value.id));
        let base = artifacts
            .get(value.artifact.as_str())
            .expect("malformed case names an artifact");
        let changed = mutate(base, &value.operation);
        assert_eq!(
            decode_error_code(&value.artifact, &changed),
            value.expected_error_code
        );
    }
    assert_eq!(fixture.malformed_codec_cases.len(), 33);

    let expected = expected_field_coverage();
    for (object, fields) in fixture.field_coverage.entries() {
        let expected_fields = expected[object];
        assert_eq!(
            fields.iter().map(String::as_str).collect::<Vec<_>>(),
            expected_fields
        );
    }
    let mut observed: BTreeMap<&str, BTreeSet<&str>> = expected
        .keys()
        .copied()
        .map(|name| (name, BTreeSet::new()))
        .collect();
    let expected_locations = expected_mutation_locations();
    assert_eq!(expected_locations.len(), 40);
    let mut mutation_ids = BTreeSet::new();
    for value in &fixture.mutation_matrix {
        assert!(!value.id.is_empty());
        assert!(mutation_ids.insert(&value.id));
        let expected_fields = expected
            .get(value.object.as_str())
            .expect("mutation names a known object");
        assert!(expected_fields.contains(&value.field.as_str()));
        assert!(
            observed
                .get_mut(value.object.as_str())
                .expect("observed object exists")
                .insert(value.field.as_str()),
            "field has one exact mutation"
        );
        let (expected_base, expected_offset, expected_remove) = expected_locations
            .get(&(value.object.as_str(), value.field.as_str()))
            .expect("field has one frozen mutation location");
        assert_eq!(&value.base_artifact, expected_base);
        match &value.operation {
            Operation::ReplaceRange {
                offset_u32,
                remove_u32,
                ..
            } => {
                assert_eq!(offset_u32, expected_offset);
                assert_eq!(remove_u32, expected_remove);
            }
            _ => panic!("semantic field mutations use exact replace-range operations"),
        }
        let base = artifacts
            .get(value.base_artifact.as_str())
            .expect("mutation names a base artifact");
        let changed = mutate(base, &value.operation);
        assert_eq!(
            promotion_error_code(&host, &positive, &value.base_artifact, &changed),
            value.expected_error_code
        );
    }
    assert_eq!(fixture.mutation_matrix.len(), 40);
    for (object, expected_fields) in expected {
        assert_eq!(
            observed[object],
            expected_fields.iter().copied().collect::<BTreeSet<_>>()
        );
    }

    let pin_case = &fixture.coherent_checkpoint_pin_case;
    assert!(!pin_case.id.is_empty());
    let candidate =
        UnverifiedCheckpointState::from_canonical_bytes(&hex_bytes(&pin_case.artifact_hex))
            .expect("coherent alternate checkpoint decodes");
    assert_eq!(
        pin_case.external_pin_hex,
        positive.transition.next().checkpoint_id().to_string()
    );
    let error = host
        .verify_checkpoint_state(
            candidate,
            TrustedCheckpointPin::from_trusted_state(positive.transition.next()),
        )
        .expect_err("coherent checkpoint cannot bypass the external pin");
    assert_eq!(error.code(), pin_case.expected_error_code);
}

#[test]
fn fixture_rejects_unknown_and_missing_fields_at_every_layer() {
    let unknown_pointers = [
        "",
        "/scope",
        "/context",
        "/positive_case",
        "/positive_case/expected_artifacts",
        "/rejection_slots/0",
        "/rejection_cases/0",
        "/rejection_cases/0/expected_transition_artifacts",
        "/rejection_cases/0/expected_outcomes/0",
        "/compound_cases/0",
        "/compound_cases/0/expected_transition_artifacts",
        "/properties",
        "/malformed_codec_cases/0",
        "/malformed_codec_cases/0/operation",
        "/field_coverage",
        "/mutation_matrix/0",
        "/mutation_matrix/0/operation",
        "/coherent_checkpoint_pin_case",
    ];
    for pointer in unknown_pointers {
        let mut value = fixture_value();
        object_mut(&mut value, pointer).insert("unexpected_field".to_owned(), Value::Bool(true));
        assert!(serde_json::from_value::<Fixture>(value).is_err());
    }

    let missing = [
        ("", "schema"),
        ("/scope", "kind"),
        ("/context", "network_id_hex"),
        ("/positive_case", "ordered_bodies_hex"),
        ("/positive_case/expected_artifacts", "c0_hex"),
        ("/rejection_slots/0", "classification"),
        ("/rejection_cases/0", "expected_outcomes"),
        ("/rejection_cases/0/expected_transition_artifacts", "c4_hex"),
        ("/rejection_cases/0/expected_outcomes/0", "code"),
        ("/compound_cases/0", "prelude_bodies_hex"),
        ("/compound_cases/0/expected_transition_artifacts", "c6_hex"),
        ("/properties", "deterministic_replay"),
        ("/malformed_codec_cases/0", "expected_error_code"),
        ("/malformed_codec_cases/0/operation", "kind"),
        ("/field_coverage", "c0"),
        ("/mutation_matrix/0", "field"),
        ("/mutation_matrix/0/operation", "remove_u32"),
        ("/coherent_checkpoint_pin_case", "external_pin_hex"),
    ];
    for (pointer, field) in missing {
        let mut value = fixture_value();
        assert!(object_mut(&mut value, pointer).remove(field).is_some());
        assert!(serde_json::from_value::<Fixture>(value).is_err());
    }
}
