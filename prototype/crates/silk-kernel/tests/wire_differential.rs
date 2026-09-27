//! Detached finite-corpus checks for the transparent kernel wire and hash contract.

use serde::Deserialize;
use serde_json::Value;
use silk_kernel::{
    MAX_INPUTS, MAX_OUTPUTS, MAX_TRANSACTIONS, NativeNote, NativeTransaction, OrderedBody,
    RECOVERY_PAYLOAD_BYTES, RecoveryRecord,
};
use silk_types::{
    CanonicalDecode, CanonicalEncode, ChainDomain, CheckpointId, DecodeError, Hash32,
    NoteCommitment, ProfileDomain,
};

const FIXTURE_BYTES: &str =
    include_str!("../../../fixtures/transparent-kernel-wire-differential-v1.json");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    context: ContextFixture,
    limits: LimitFixture,
    malformed_cases: Vec<MalformedCase>,
    notes: NoteFixtures,
    ordered_body: OrderedBodyFixture,
    recovery_records: RecoveryFixtures,
    schema: String,
    scope: ScopeFixture,
    transaction: TransactionFixture,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextFixture {
    #[serde(rename = "anchor_checkpoint_hex")]
    anchor_checkpoint: String,
    #[serde(rename = "body_id_hex")]
    body_id: String,
    #[serde(rename = "chain_domain_hex")]
    chain_domain: String,
    #[serde(rename = "profile_domain_hex")]
    profile_domain: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitFixture {
    max_inputs_per_transaction: usize,
    max_outputs_per_transaction: usize,
    max_transactions_per_body: usize,
    recovery_payload_bytes: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeFixture {
    kind: String,
    second_kernel_interpreter: bool,
    state_transition_coverage: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoteFixtures {
    source: NoteFixture,
    output: NoteFixture,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoteFixture {
    value_u64: String,
    owner_tag_hex: String,
    rho_hex: String,
    randomness_hex: String,
    nullifier_key_hex: String,
    expected_commitment_hex: String,
    #[serde(default)]
    expected_nullifier_hex: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryFixtures {
    source: RecoveryFixture,
    output: RecoveryFixture,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryFixture {
    output_commitment_hex: String,
    payload_length_bytes: usize,
    payload_repeat_byte_hex: String,
    expected_record_hash_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TransactionFixture {
    canonical_hex: String,
    expected_canonical_length_bytes: usize,
    expected_effect_digest_hex: String,
    expected_intent_id_hex: String,
    expected_instance_hash_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OrderedBodyFixture {
    canonical_hex: String,
    expected_canonical_length_bytes: usize,
    expected_execution_binding_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MalformedCase {
    id: String,
    base_ref: BaseReference,
    operation: Mutation,
    expected_error_code: String,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BaseReference {
    Transaction,
    OrderedBody,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Mutation {
    SetByte { offset_u32: u32, value_u8: u8 },
    TruncateTail { count_u32: u32 },
    Append { hex: String },
    SetU32Le { offset_u32: u32, value_u32: u32 },
}

fn fixture() -> Fixture {
    serde_json::from_str(FIXTURE_BYTES).expect("detached differential fixture is valid JSON")
}

fn fixture_value() -> Value {
    serde_json::from_str(FIXTURE_BYTES).expect("detached differential fixture is valid JSON")
}

fn assert_fixture_rejects(value: &Value, case: &str) {
    let bytes = serde_json::to_vec(value).expect("mutated fixture serializes");
    assert!(
        serde_json::from_slice::<Fixture>(&bytes).is_err(),
        "fixture unexpectedly accepted {case}"
    );
}

fn insert_unknown_field(value: &mut Value, pointer: &str) {
    value
        .pointer_mut(pointer)
        .and_then(Value::as_object_mut)
        .unwrap_or_else(|| panic!("fixture pointer {pointer} names an object"))
        .insert("unexpected_field".to_owned(), Value::Bool(true));
}

fn hex_bytes(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex input has an odd length");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
        .collect()
}

const fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("fixture hex must use lowercase ASCII"),
    }
}

fn fixed_bytes<const N: usize>(value: &str) -> [u8; N] {
    hex_bytes(value)
        .try_into()
        .unwrap_or_else(|bytes: Vec<u8>| panic!("expected {N} bytes, received {}", bytes.len()))
}

fn note(value: &NoteFixture) -> NativeNote {
    NativeNote {
        value: value.value_u64.parse().expect("note value is a u64"),
        owner_tag: Hash32::new(fixed_bytes(&value.owner_tag_hex)),
        rho: Hash32::new(fixed_bytes(&value.rho_hex)),
        randomness: Hash32::new(fixed_bytes(&value.randomness_hex)),
        nullifier_key: Hash32::new(fixed_bytes(&value.nullifier_key_hex)),
    }
}

fn recovery_record(value: &RecoveryFixture) -> RecoveryRecord {
    assert_eq!(value.payload_length_bytes, RECOVERY_PAYLOAD_BYTES);
    let payload_byte = fixed_bytes::<1>(&value.payload_repeat_byte_hex)[0];
    RecoveryRecord {
        output_commitment: NoteCommitment::from_bytes(fixed_bytes(&value.output_commitment_hex)),
        payload: [payload_byte; RECOVERY_PAYLOAD_BYTES],
    }
}

fn mutate(base: &[u8], operation: &Mutation) -> Vec<u8> {
    let mut bytes = base.to_vec();
    match operation {
        Mutation::SetByte {
            offset_u32,
            value_u8,
        } => {
            let offset = usize::try_from(*offset_u32).expect("mutation offset fits usize");
            *bytes.get_mut(offset).expect("set-byte offset is in range") = *value_u8;
        }
        Mutation::TruncateTail { count_u32 } => {
            let count = usize::try_from(*count_u32).expect("truncate count fits usize");
            let length = bytes
                .len()
                .checked_sub(count)
                .expect("truncate count is in range");
            bytes.truncate(length);
        }
        Mutation::Append { hex } => bytes.extend(hex_bytes(hex)),
        Mutation::SetU32Le {
            offset_u32,
            value_u32,
        } => {
            let offset = usize::try_from(*offset_u32).expect("mutation offset fits usize");
            let end = offset
                .checked_add(4)
                .expect("mutation range does not overflow");
            bytes
                .get_mut(offset..end)
                .expect("u32 mutation range is in bounds")
                .copy_from_slice(&value_u32.to_le_bytes());
        }
    }
    bytes
}

fn assert_fixture_scope(fixture: &Fixture) {
    assert_eq!(
        fixture.schema,
        "silknode.transparent-kernel-wire-differential.v1"
    );
    assert_eq!(fixture.scope.kind, "detached_finite_wire_hash_corpus");
    assert!(!fixture.scope.second_kernel_interpreter);
    assert!(!fixture.scope.state_transition_coverage);
    assert_eq!(fixture.limits.max_inputs_per_transaction, MAX_INPUTS);
    assert_eq!(fixture.limits.max_outputs_per_transaction, MAX_OUTPUTS);
    assert_eq!(fixture.limits.max_transactions_per_body, MAX_TRANSACTIONS);
    assert_eq!(
        fixture.limits.recovery_payload_bytes,
        RECOVERY_PAYLOAD_BYTES
    );
}

fn assert_hash_fixtures(
    fixture: &Fixture,
    chain_domain: ChainDomain,
) -> (NativeNote, NativeNote, RecoveryRecord) {
    let source_note = note(&fixture.notes.source);
    let output_note = note(&fixture.notes.output);
    assert_eq!(
        source_note
            .commitment(chain_domain)
            .expect("source commitment derives")
            .to_string(),
        fixture.notes.source.expected_commitment_hex
    );
    assert_eq!(
        source_note
            .nullifier(chain_domain)
            .expect("source nullifier derives")
            .to_string(),
        fixture
            .notes
            .source
            .expected_nullifier_hex
            .as_deref()
            .expect("source fixture includes a nullifier")
    );
    assert_eq!(
        output_note
            .commitment(chain_domain)
            .expect("output commitment derives")
            .to_string(),
        fixture.notes.output.expected_commitment_hex
    );
    assert!(fixture.notes.output.expected_nullifier_hex.is_none());

    let source_recovery = recovery_record(&fixture.recovery_records.source);
    let output_recovery = recovery_record(&fixture.recovery_records.output);
    assert_eq!(
        source_recovery
            .record_hash(chain_domain)
            .expect("source recovery hash derives")
            .to_string(),
        fixture.recovery_records.source.expected_record_hash_hex
    );
    assert_eq!(
        output_recovery
            .record_hash(chain_domain)
            .expect("output recovery hash derives")
            .to_string(),
        fixture.recovery_records.output.expected_record_hash_hex
    );

    (source_note, output_note, output_recovery)
}

#[test]
fn detached_fixture_matches_transaction_body_and_hash_contract() {
    let fixture = fixture();
    assert_fixture_scope(&fixture);
    let chain_domain = ChainDomain::from_bytes(fixed_bytes(&fixture.context.chain_domain));
    let profile_domain = ProfileDomain::from_bytes(fixed_bytes(&fixture.context.profile_domain));
    let (source_note, output_note, output_recovery) = assert_hash_fixtures(&fixture, chain_domain);

    let transaction_bytes = hex_bytes(&fixture.transaction.canonical_hex);
    assert_eq!(
        transaction_bytes.len(),
        fixture.transaction.expected_canonical_length_bytes
    );
    let transaction = NativeTransaction::from_canonical_bytes(&transaction_bytes)
        .expect("canonical transaction decodes");
    assert_eq!(
        transaction
            .to_canonical_bytes()
            .expect("transaction re-encodes"),
        transaction_bytes
    );
    assert_eq!(transaction.chain_domain, chain_domain);
    assert_eq!(transaction.profile_domain, profile_domain);
    assert_eq!(
        transaction.anchor,
        CheckpointId::from_bytes(fixed_bytes(&fixture.context.anchor_checkpoint))
    );
    assert_eq!(transaction.inputs()[0].witness.note, source_note);
    assert_eq!(transaction.outputs()[0].note, output_note);
    assert_eq!(transaction.recovery_records(), [output_recovery]);
    assert_eq!(
        transaction
            .effect_digest()
            .expect("effect derives")
            .to_string(),
        fixture.transaction.expected_effect_digest_hex
    );
    assert_eq!(
        transaction.intent_id().expect("intent derives").to_string(),
        fixture.transaction.expected_intent_id_hex
    );
    assert_eq!(
        transaction
            .instance_hash()
            .expect("instance derives")
            .to_string(),
        fixture.transaction.expected_instance_hash_hex
    );

    let body_bytes = hex_bytes(&fixture.ordered_body.canonical_hex);
    assert_eq!(
        body_bytes.len(),
        fixture.ordered_body.expected_canonical_length_bytes
    );
    let body = OrderedBody::from_canonical_bytes(&body_bytes).expect("canonical body decodes");
    assert_eq!(
        body.to_canonical_bytes().expect("body re-encodes"),
        body_bytes
    );
    assert_eq!(body.body_id.to_string(), fixture.context.body_id);
    assert_eq!(body.transactions, [transaction]);
    assert_eq!(
        body.execution_binding(chain_domain, profile_domain)
            .expect("body binding derives")
            .to_string(),
        fixture.ordered_body.expected_execution_binding_hex
    );
}

#[test]
fn detached_fixture_malformed_bytes_fail_closed() {
    let fixture = fixture();
    let transaction = hex_bytes(&fixture.transaction.canonical_hex);
    let ordered_body = hex_bytes(&fixture.ordered_body.canonical_hex);

    for case in &fixture.malformed_cases {
        let base = match case.base_ref {
            BaseReference::Transaction => transaction.as_slice(),
            BaseReference::OrderedBody => ordered_body.as_slice(),
        };
        let malformed = mutate(base, &case.operation);
        let error: DecodeError = match case.base_ref {
            BaseReference::Transaction => NativeTransaction::from_canonical_bytes(&malformed)
                .expect_err("malformed transaction must reject"),
            BaseReference::OrderedBody => OrderedBody::from_canonical_bytes(&malformed)
                .expect_err("malformed body must reject"),
        };
        assert_eq!(
            error.code(),
            case.expected_error_code,
            "unexpected rejection for {}",
            case.id
        );
    }
}

#[test]
fn detached_fixture_rejects_unknown_fields_at_every_object_shape() {
    let object_pointers = [
        "",
        "/context",
        "/limits",
        "/scope",
        "/notes",
        "/notes/source",
        "/recovery_records",
        "/recovery_records/source",
        "/transaction",
        "/ordered_body",
        "/malformed_cases/0",
    ];
    for pointer in object_pointers {
        let mut value = fixture_value();
        insert_unknown_field(&mut value, pointer);
        assert_fixture_rejects(&value, &format!("unknown field at {pointer:?}"));
    }

    // Exercise every internally tagged mutation variant, not just one operation.
    for index in [0_usize, 2, 3, 4] {
        let pointer = format!("/malformed_cases/{index}/operation");
        let mut value = fixture_value();
        insert_unknown_field(&mut value, &pointer);
        assert_fixture_rejects(
            &value,
            &format!("unknown field in mutation operation {index}"),
        );
    }
}

#[test]
fn detached_fixture_requires_every_scope_and_limit_field() {
    for (pointer, fields) in [
        (
            "/scope",
            &[
                "kind",
                "second_kernel_interpreter",
                "state_transition_coverage",
            ][..],
        ),
        (
            "/limits",
            &[
                "max_inputs_per_transaction",
                "max_outputs_per_transaction",
                "max_transactions_per_body",
                "recovery_payload_bytes",
            ][..],
        ),
    ] {
        for field in fields {
            let mut value = fixture_value();
            value
                .pointer_mut(pointer)
                .and_then(Value::as_object_mut)
                .expect("fixture pointer names an object")
                .remove(*field)
                .unwrap_or_else(|| panic!("fixture object contains {field}"));
            assert_fixture_rejects(&value, &format!("missing {pointer}/{field}"));
        }
    }
}
