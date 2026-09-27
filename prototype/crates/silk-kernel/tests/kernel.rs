//! Adversarial acceptance tests for the transparent Gate A kernel.

use serde::Deserialize;
use silk_kernel::{
    CheckpointState, CodecVerificationError, GateAGenesisReceipt, GateAGenesisReceiptField,
    GenesisAllocationTemplate, GenesisAllocationTemplateEntry, KernelError,
    MAX_GENESIS_ALLOCATIONS, MAX_INPUTS, NativeNote, NativeTransaction, OrderedBody, Outcome,
    RECOVERY_PAYLOAD_BYTES, RecoveryRecord, RejectCode, TransparentExecutionHost, TransparentInput,
    TransparentOutput, TransparentWitness, TrustedCheckpointPin, UnverifiedCheckpointState,
    UnverifiedNativeIntervalResult, UnverifiedTransition, transparent_checkpoint_descriptor,
    transparent_native_kernel_descriptor,
};
use silk_profile::{
    ConstitutionalCaps, DerivedGenesisIdentity, ExecutionProfile, GateAGenesisReceiptRecipe,
    GenesisProfilePin, ModuleDescriptor, ModuleType, ProfileValidator, ProtocolManifest,
    RoleCapabilityCap, StateDomain, UpgradeSchedule,
};
use silk_types::{
    CanonicalDecode, CanonicalEncode, ChainDomain, CheckpointId, DecodeError, Hash32, IntentId,
    ManifestHash, ModuleId, ProfileDomain, VertexId, domain_hash,
};

const TEST_NETWORK_ID: &[u8] = b"silknode-kernel-gate-a-v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GenesisReceiptFixture {
    schema: String,
    case_id: String,
    canonical_template_hex: String,
    canonical_receipt_hex: String,
    expected: GenesisReceiptFixtureExpected,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GenesisReceiptFixtureExpected {
    template: GenesisReceiptFixtureTemplate,
    receipt: GenesisReceiptFixtureReceipt,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GenesisReceiptFixtureTemplate {
    canonical_length_bytes: usize,
    template_hash_hex: String,
    projection: GenesisReceiptFixtureTemplateProjection,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GenesisReceiptFixtureTemplateProjection {
    template_version_u8: u8,
    protocol_major_u32: u32,
    derived_slots: Vec<GenesisReceiptFixtureSlot>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GenesisReceiptFixtureSlot {
    field: String,
    zero_placeholder_hex: String,
    recipe_tag_u8: u8,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GenesisReceiptFixtureReceipt {
    canonical_length_bytes: usize,
    projection: GenesisReceiptFixtureProjection,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GenesisReceiptFixtureProjection {
    receipt_version_u8: u8,
    protocol_major_u32: u32,
    genesis_commitment_hex: String,
    chain_domain_hex: String,
    protocol_manifest_hash_hex: String,
    profile_domain_hex: String,
    checkpoint_zero_state_digest_hex: String,
    checkpoint_zero_id_hex: String,
}

fn hash(byte: u8) -> Hash32 {
    Hash32::from([byte; 32])
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

fn profile_descriptor(
    module_type: ModuleType,
    seed: u8,
    dependencies: Vec<silk_types::ModuleId>,
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
    .expect("kernel fixture descriptor is canonical")
}

#[derive(Clone)]
struct DescriptorInputs {
    module_type: ModuleType,
    abi_version: u16,
    normative_spec_hash: Hash32,
    interface_schema_hash: Hash32,
    conformance_vector_root: Hash32,
    parameter_hash: Hash32,
    dependency_ids: Vec<ModuleId>,
    declared_state_reads: Vec<StateDomain>,
    declared_state_writes: Vec<StateDomain>,
}

impl DescriptorInputs {
    fn from_descriptor(descriptor: &ModuleDescriptor) -> Self {
        Self {
            module_type: descriptor.module_type(),
            abi_version: descriptor.abi_version(),
            normative_spec_hash: descriptor.normative_spec_hash(),
            interface_schema_hash: descriptor.interface_schema_hash(),
            conformance_vector_root: descriptor.conformance_vector_root(),
            parameter_hash: descriptor.parameter_hash(),
            dependency_ids: descriptor.dependency_ids().to_vec(),
            declared_state_reads: descriptor.declared_state_reads().to_vec(),
            declared_state_writes: descriptor.declared_state_writes().to_vec(),
        }
    }

    fn build(self) -> ModuleDescriptor {
        ModuleDescriptor::new(
            self.module_type,
            self.abi_version,
            self.normative_spec_hash,
            self.interface_schema_hash,
            self.conformance_vector_root,
            self.parameter_hash,
            self.dependency_ids,
            self.declared_state_reads,
            self.declared_state_writes,
        )
        .expect("mutated test descriptor remains canonical")
    }
}

fn descriptor_semantic_mutations(descriptor: &ModuleDescriptor) -> Vec<ModuleDescriptor> {
    let original = DescriptorInputs::from_descriptor(descriptor);
    let mut mutations = Vec::new();

    let mut changed = original.clone();
    changed.module_type = match descriptor.module_type() {
        ModuleType::NativeKernel => ModuleType::Checkpoint,
        _ => ModuleType::NativeKernel,
    };
    mutations.push(changed.build());

    let mut changed = original.clone();
    changed.abi_version = changed
        .abi_version
        .checked_add(1)
        .expect("test ABI advances");
    mutations.push(changed.build());

    let mut changed = original.clone();
    changed.normative_spec_hash = hash(0xe1);
    mutations.push(changed.build());

    let mut changed = original.clone();
    changed.interface_schema_hash = hash(0xe2);
    mutations.push(changed.build());

    let mut changed = original.clone();
    changed.conformance_vector_root = hash(0xe3);
    mutations.push(changed.build());

    let mut changed = original.clone();
    changed.parameter_hash = hash(0xe4);
    mutations.push(changed.build());

    let mut changed = original.clone();
    if changed.dependency_ids.is_empty() {
        changed
            .dependency_ids
            .push(ModuleId::from_bytes([0xe5; 32]));
    } else {
        changed.dependency_ids.clear();
    }
    mutations.push(changed.build());

    let mut changed = original.clone();
    changed.declared_state_reads.pop();
    mutations.push(changed.build());

    let mut changed = original;
    changed.declared_state_writes.pop();
    mutations.push(changed.build());

    mutations
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
    let kernel = transparent_native_kernel_descriptor()
        .expect("compiled native-kernel descriptor is canonical");
    let checkpoint =
        transparent_checkpoint_descriptor().expect("compiled checkpoint descriptor is canonical");
    let issuance = profile_descriptor(
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

fn replace_descriptor(modules: &mut [ModuleDescriptor], replacement: ModuleDescriptor) {
    let slot = modules
        .iter_mut()
        .find(|descriptor| descriptor.module_type() == replacement.module_type())
        .expect("fixture contains the replaced exclusive role");
    *slot = replacement;
}

fn modules_with_native_kernel(native_kernel: ModuleDescriptor) -> Vec<ModuleDescriptor> {
    let mut modules = profile_modules();
    let mut checkpoint = DescriptorInputs::from_descriptor(
        &transparent_checkpoint_descriptor().expect("compiled checkpoint descriptor is canonical"),
    );
    checkpoint.dependency_ids = vec![native_kernel.module_id()];
    let checkpoint = checkpoint.build();

    let mut issuance = DescriptorInputs::from_descriptor(
        modules
            .iter()
            .find(|descriptor| descriptor.module_type() == ModuleType::Issuance)
            .expect("fixture has issuance"),
    );
    issuance.dependency_ids = vec![checkpoint.module_id()];
    let issuance = issuance.build();

    replace_descriptor(&mut modules, native_kernel);
    replace_descriptor(&mut modules, checkpoint);
    replace_descriptor(&mut modules, issuance);
    modules.sort();
    modules
}

fn modules_with_checkpoint(checkpoint: ModuleDescriptor) -> Vec<ModuleDescriptor> {
    let mut modules = profile_modules();
    let mut issuance = DescriptorInputs::from_descriptor(
        modules
            .iter()
            .find(|descriptor| descriptor.module_type() == ModuleType::Issuance)
            .expect("fixture has issuance"),
    );
    issuance.dependency_ids = vec![checkpoint.module_id()];
    let issuance = issuance.build();

    replace_descriptor(&mut modules, checkpoint);
    replace_descriptor(&mut modules, issuance);
    modules.sort();
    modules
}

fn execution_profile_for(
    allocation_template: &GenesisAllocationTemplate,
    protocol_major: u32,
) -> ExecutionProfile {
    let allocation_template_bytes = allocation_template
        .to_canonical_bytes()
        .expect("allocation template encodes");
    execution_profile_for_trusted_allocation_bytes(&allocation_template_bytes, protocol_major)
}

fn execution_profile_for_trusted_allocation_bytes(
    trusted_allocation_template_bytes: &[u8],
    protocol_major: u32,
) -> ExecutionProfile {
    execution_profile_for_modules(
        trusted_allocation_template_bytes,
        protocol_major,
        profile_modules(),
    )
}

fn execution_profile_for_modules(
    trusted_allocation_template_bytes: &[u8],
    protocol_major: u32,
    modules: Vec<ModuleDescriptor>,
) -> ExecutionProfile {
    let constitution_hash = hash(0xc8);
    let native_kernel_module_id = modules
        .iter()
        .find(|module| module.module_type() == ModuleType::NativeKernel)
        .expect("fixture has one native kernel")
        .module_id();
    let checkpoint_module_id = modules
        .iter()
        .find(|module| module.module_type() == ModuleType::Checkpoint)
        .expect("fixture has one checkpoint module")
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
            .expect("fixture role cap is canonical")
        })
        .collect::<Vec<_>>();
    role_caps.sort();
    let caps = ConstitutionalCaps::new(constitution_hash, role_caps)
        .expect("fixture constitutional caps are canonical");
    let manifest = ProtocolManifest::new(
        protocol_major,
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
            .expect("fixture genesis manifest template projects"),
        trusted_allocation_template_bytes,
    )
    .expect("fixture genesis identity derives");
    let chain = identity.chain_domain();
    let manifest_hash = manifest
        .manifest_hash(chain)
        .expect("fixture manifest hashes");
    let pin = GenesisProfilePin::new(
        identity,
        manifest_hash,
        native_kernel_module_id,
        checkpoint_module_id,
    );
    ProfileValidator::new_with_genesis_pin(caps, supported, pin)
        .validate_and_activate_genesis(chain, manifest)
        .expect("exact pinned genesis profile activates")
}

fn execution_profile_for_empty_template_with_modules(
    modules: Vec<ModuleDescriptor>,
) -> ExecutionProfile {
    let allocation_template = allocation_template(&[]);
    let bytes = allocation_template
        .to_canonical_bytes()
        .expect("empty allocation template encodes");
    execution_profile_for_modules(&bytes, 1, modules)
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

fn indexed_hash(index: usize, marker: u8) -> Hash32 {
    let mut bytes = [marker; 32];
    bytes[..8].copy_from_slice(
        &u64::try_from(index)
            .expect("test note index fits u64")
            .to_le_bytes(),
    );
    Hash32::from(bytes)
}

fn indexed_note(index: usize, value: u64) -> NativeNote {
    NativeNote {
        value,
        owner_tag: indexed_hash(index, 0x11),
        rho: indexed_hash(index, 0x22),
        randomness: indexed_hash(index, 0x33),
        nullifier_key: indexed_hash(index, 0x44),
    }
}

const fn recovery(commitment: silk_types::NoteCommitment, byte: u8) -> RecoveryRecord {
    RecoveryRecord {
        output_commitment: commitment,
        payload: [byte; RECOVERY_PAYLOAD_BYTES],
    }
}

fn template_payload(index: usize) -> [u8; RECOVERY_PAYLOAD_BYTES] {
    let mut payload = [0xa6; RECOVERY_PAYLOAD_BYTES];
    payload[..8].copy_from_slice(
        &u64::try_from(index)
            .expect("test template index fits u64")
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
    GenesisAllocationTemplate::new(entries).expect("test allocation template is bounded")
}

fn host_for_profile(execution_profile: ExecutionProfile) -> TransparentExecutionHost {
    TransparentExecutionHost::bind(execution_profile)
        .expect("fixture profile matches the compiled host")
}

fn genesis(notes: &[NativeNote]) -> (TransparentExecutionHost, CheckpointState) {
    let allocation_template = allocation_template(notes);
    let execution_profile = execution_profile_for(&allocation_template, 1);
    let host = host_for_profile(execution_profile);
    let materialized = host
        .genesis(allocation_template)
        .expect("valid test genesis");
    materialized
        .receipt()
        .verify(host.execution_profile(), materialized.state())
        .expect("materialized receipt verifies");
    let (state, _) = materialized.into_parts();
    (host, state)
}

fn assert_template_mismatch(
    execution_profile: &ExecutionProfile,
    allocation_template: GenesisAllocationTemplate,
) {
    let expected = execution_profile.genesis_allocation_template_hash();
    let actual = allocation_template
        .template_hash()
        .expect("candidate template hashes");
    let host = host_for_profile(execution_profile.clone());
    let error = host
        .genesis(allocation_template)
        .expect_err("different template must fail before materialization");
    assert_eq!(error.code(), "kernel.genesis_allocation_template_mismatch");
    match error {
        KernelError::GenesisAllocationTemplateMismatch {
            expected: error_expected,
            actual: error_actual,
        } => {
            assert_eq!(error_expected, expected);
            assert_eq!(error_actual, actual);
        }
        other => panic!("unexpected structural error: {other}"),
    }
}

fn transaction(
    state: &CheckpointState,
    inputs: &[NativeNote],
    outputs: &[NativeNote],
    public_fee: u64,
) -> NativeTransaction {
    let inputs = inputs
        .iter()
        .cloned()
        .map(|value| TransparentInput {
            commitment: value
                .commitment(state.chain_domain())
                .expect("input commitment"),
            nullifier: value
                .nullifier(state.chain_domain())
                .expect("input nullifier"),
            witness: TransparentWitness {
                note: value,
                authorization_valid: true,
            },
        })
        .collect();
    let outputs = outputs
        .iter()
        .cloned()
        .map(|value| TransparentOutput {
            commitment: value
                .commitment(state.chain_domain())
                .expect("output commitment"),
            note: value,
        })
        .collect::<Vec<_>>();
    let recovery_records = outputs
        .iter()
        .enumerate()
        .map(|(slot, output)| recovery(output.commitment, u8::try_from(slot + 1).expect("small")))
        .collect::<Vec<_>>();
    let recovery_hashes = recovery_records
        .iter()
        .map(|record| {
            record
                .record_hash(state.chain_domain())
                .expect("record hash")
        })
        .collect();
    NativeTransaction::new(
        state.chain_domain(),
        state.profile_domain(),
        state.checkpoint_id(),
        public_fee,
        inputs,
        outputs,
        recovery_hashes,
        recovery_records,
    )
    .expect("bounded test transaction")
}

fn replace_records(
    transaction: &NativeTransaction,
    recovery_records: Vec<RecoveryRecord>,
) -> NativeTransaction {
    NativeTransaction::new(
        transaction.chain_domain,
        transaction.profile_domain,
        transaction.anchor,
        transaction.public_fee,
        transaction.inputs().to_vec(),
        transaction.outputs().to_vec(),
        transaction.recovery_hashes().to_vec(),
        recovery_records,
    )
    .expect("replacement remains bounded")
}

fn replace_records_and_hashes(
    transaction: &NativeTransaction,
    recovery_records: Vec<RecoveryRecord>,
) -> NativeTransaction {
    let recovery_hashes = recovery_records
        .iter()
        .map(|record| {
            record
                .record_hash(transaction.chain_domain)
                .expect("test record hashes")
        })
        .collect();
    NativeTransaction::new(
        transaction.chain_domain,
        transaction.profile_domain,
        transaction.anchor,
        transaction.public_fee,
        transaction.inputs().to_vec(),
        transaction.outputs().to_vec(),
        recovery_hashes,
        recovery_records,
    )
    .expect("replacement remains bounded")
}

fn replace_inputs(
    transaction: &NativeTransaction,
    inputs: Vec<TransparentInput>,
) -> NativeTransaction {
    NativeTransaction::new(
        transaction.chain_domain,
        transaction.profile_domain,
        transaction.anchor,
        transaction.public_fee,
        inputs,
        transaction.outputs().to_vec(),
        transaction.recovery_hashes().to_vec(),
        transaction.recovery_records().to_vec(),
    )
    .expect("replacement remains bounded")
}

fn replace_outputs(
    transaction: &NativeTransaction,
    outputs: Vec<TransparentOutput>,
) -> NativeTransaction {
    NativeTransaction::new(
        transaction.chain_domain,
        transaction.profile_domain,
        transaction.anchor,
        transaction.public_fee,
        transaction.inputs().to_vec(),
        outputs,
        transaction.recovery_hashes().to_vec(),
        transaction.recovery_records().to_vec(),
    )
    .expect("replacement remains bounded")
}

const fn body(byte: u8, transactions: Vec<NativeTransaction>) -> OrderedBody {
    OrderedBody {
        body_id: VertexId::from_bytes([byte; 32]),
        transactions,
    }
}

fn canonical_body(byte: u8, mut transactions: Vec<NativeTransaction>) -> OrderedBody {
    transactions.sort_by(|left, right| {
        (
            left.intent_id().expect("left intent"),
            left.instance_hash().expect("left instance"),
            left.to_canonical_bytes().expect("left bytes"),
        )
            .cmp(&(
                right.intent_id().expect("right intent"),
                right.instance_hash().expect("right instance"),
                right.to_canonical_bytes().expect("right bytes"),
            ))
    });
    body(byte, transactions)
}

fn outcome_for(transition: &silk_kernel::Transition, intent: IntentId) -> Outcome {
    transition
        .decisions()
        .iter()
        .find(|decision| decision.intent_id == intent)
        .expect("intent has a decision")
        .outcome
}

fn apply_with_host(
    host: &TransparentExecutionHost,
    state: &CheckpointState,
    bodies: &[OrderedBody],
) -> Result<silk_kernel::Transition, KernelError> {
    host.apply_and_seal(state, bodies)
}

fn bytes_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[test]
fn compiled_descriptor_artifacts_bytes_and_ids_are_frozen() {
    let artifacts: [(&[u8], &[u8], &str); 8] = [
        (
            b"Silk-Transparent-NativeKernel-Spec-v2",
            include_bytes!("../../../spec/transparent-execution-v2/native-kernel-spec.md"),
            "1cf801af2b5df3915062d269d0f46a82366af748c594a7fb3133077d513dc677",
        ),
        (
            b"Silk-Transparent-NativeKernel-Interface-v2",
            include_bytes!("../../../spec/transparent-execution-v2/native-kernel-interface.json"),
            "88f59125c999bb0960fc6d9c6e65a8e17cacd3a32d2dd42efad630e4fb73dd53",
        ),
        (
            b"Silk-Transparent-NativeKernel-Parameters-v2",
            include_bytes!("../../../spec/transparent-execution-v2/native-kernel-parameters.json"),
            "0a8228586ce54a61e7250bc7c9caae657913df7baedc93b57d5f90d43136ad41",
        ),
        (
            b"Silk-Transparent-NativeKernel-Vectors-v2",
            include_bytes!("../../../spec/transparent-execution-v2/native-kernel-vectors.json"),
            "dc877f1e6aa08f029e29f63bd567de9f96dde896e92a6031a66a6bb0fbd400dc",
        ),
        (
            b"Silk-Transparent-Checkpoint-Spec-v3",
            include_bytes!("../../../spec/transparent-execution-v2/checkpoint-spec.md"),
            "f1b43788c0bb51a4fd05aaf0e2124e35963a1d2f54dabb65fc1bce0c1ddac5ca",
        ),
        (
            b"Silk-Transparent-Checkpoint-Interface-v3",
            include_bytes!("../../../spec/transparent-execution-v2/checkpoint-interface.json"),
            "2cfab6dc3927b31fd033e543e99a5283412e11762acfd4b2c82d0316f900ab2f",
        ),
        (
            b"Silk-Transparent-Checkpoint-Parameters-v3",
            include_bytes!("../../../spec/transparent-execution-v2/checkpoint-parameters.json"),
            "558b0d60b1d6fed4befe9d0c4c73f058110b8883f8140392199331d0ce6b9159",
        ),
        (
            b"Silk-Transparent-Checkpoint-Vectors-v3",
            include_bytes!("../../../spec/transparent-execution-v2/checkpoint-vectors.json"),
            "e5e264c9783a9f6eee65462f4ea179d16cd26121af8cc28a1e3e3d87afbb0098",
        ),
    ];
    for (domain, bytes, expected) in artifacts {
        assert_eq!(
            domain_hash(domain, &[bytes])
                .expect("frozen exact artifact hashes")
                .to_string(),
            expected
        );
    }

    let native_kernel = transparent_native_kernel_descriptor().expect("native descriptor");
    assert_eq!(
        native_kernel.module_id().to_string(),
        "c3b41dd10b9ca5dcd589b2e1828eeb0f2f68c27cadf03ad6c864382e70a70aed"
    );
    assert_eq!(
        bytes_hex(
            &native_kernel
                .to_canonical_bytes()
                .expect("native descriptor encodes")
        ),
        "0502001cf801af2b5df3915062d269d0f46a82366af748c594a7fb3133077d513dc67788f59125c999bb0960fc6d9c6e65a8e17cacd3a32d2dd42efad630e4fb73dd53dc877f1e6aa08f029e29f63bd567de9f96dde896e92a6031a66a6bb0fbd400dc0a8228586ce54a61e7250bc7c9caae657913df7baedc93b57d5f90d43136ad41c3b41dd10b9ca5dcd589b2e1828eeb0f2f68c27cadf03ad6c864382e70a70aed00000000070000000304050607080a050000000405060708"
    );

    let checkpoint = transparent_checkpoint_descriptor().expect("checkpoint descriptor");
    assert_eq!(
        checkpoint.module_id().to_string(),
        "a0ec1eda9c1b26fef14b149c8cc3d9f265622e71defbf70be03659bfa688ce86"
    );
    assert_eq!(
        bytes_hex(
            &checkpoint
                .to_canonical_bytes()
                .expect("checkpoint descriptor encodes")
        ),
        "060300f1b43788c0bb51a4fd05aaf0e2124e35963a1d2f54dabb65fc1bce0c1ddac5ca2cfab6dc3927b31fd033e543e99a5283412e11762acfd4b2c82d0316f900ab2fe5e264c9783a9f6eee65462f4ea179d16cd26121af8cc28a1e3e3d87afbb0098558b0d60b1d6fed4befe9d0c4c73f058110b8883f8140392199331d0ce6b9159a0ec1eda9c1b26fef14b149c8cc3d9f265622e71defbf70be03659bfa688ce8601000000c3b41dd10b9ca5dcd589b2e1828eeb0f2f68c27cadf03ad6c864382e70a70aed070000000304050607080a010000000a"
    );
}

#[test]
fn compiled_descriptors_have_exact_roles_dependencies_and_reviewed_capabilities() {
    let native_kernel = transparent_native_kernel_descriptor().expect("native descriptor");
    let checkpoint = transparent_checkpoint_descriptor().expect("checkpoint descriptor");
    let reads = [
        StateDomain::CanonicalOrder,
        StateDomain::NoteCommitments,
        StateDomain::Nullifiers,
        StateDomain::RecoveryHistory,
        StateDomain::AcceptedEffects,
        StateDomain::NativeSupply,
        StateDomain::Checkpoints,
    ];

    assert_eq!(native_kernel.module_type(), ModuleType::NativeKernel);
    assert_eq!(native_kernel.abi_version(), 2);
    assert!(native_kernel.dependency_ids().is_empty());
    assert_eq!(native_kernel.declared_state_reads(), reads);
    assert_eq!(
        native_kernel.declared_state_writes(),
        [
            StateDomain::NoteCommitments,
            StateDomain::Nullifiers,
            StateDomain::RecoveryHistory,
            StateDomain::AcceptedEffects,
            StateDomain::NativeSupply,
        ]
    );

    assert_eq!(checkpoint.module_type(), ModuleType::Checkpoint);
    assert_eq!(checkpoint.abi_version(), 3);
    assert_eq!(checkpoint.dependency_ids(), [native_kernel.module_id()]);
    assert_eq!(checkpoint.declared_state_reads(), reads);
    assert_eq!(
        checkpoint.declared_state_writes(),
        [StateDomain::Checkpoints]
    );
}

#[test]
fn every_descriptor_semantic_input_changes_each_compiled_module_identity() {
    for descriptor in [
        transparent_native_kernel_descriptor().expect("native descriptor"),
        transparent_checkpoint_descriptor().expect("checkpoint descriptor"),
    ] {
        let mutations = descriptor_semantic_mutations(&descriptor);
        assert_eq!(mutations.len(), 9);
        for mutation in mutations {
            assert_ne!(
                mutation.module_id(),
                descriptor.module_id(),
                "every descriptor field must be identity-bearing"
            );
        }
    }
}

#[test]
fn host_rejects_an_unknown_native_kernel_without_fallback() {
    let expected = transparent_native_kernel_descriptor().expect("native descriptor");
    let mut alternate = DescriptorInputs::from_descriptor(&expected);
    alternate.parameter_hash = hash(0xf1);
    let alternate = alternate.build();
    let actual_id = alternate.module_id();
    let profile =
        execution_profile_for_empty_template_with_modules(modules_with_native_kernel(alternate));

    let error = TransparentExecutionHost::bind(profile)
        .expect_err("an unknown semantic native kernel must not use this implementation");
    assert_eq!(error.code(), "kernel.native_kernel_binding_mismatch");
    match error {
        KernelError::NativeKernelBindingMismatch {
            expected_module,
            actual_module,
            expected_abi,
            actual_abi,
        } => {
            assert_eq!(expected_module, expected.module_id());
            assert_eq!(actual_module, actual_id);
            assert_eq!(expected_abi, 2);
            assert_eq!(actual_abi, 2);
        }
        other => panic!("unexpected binding error: {other}"),
    }
}

#[test]
fn host_rejects_an_unknown_native_kernel_abi_before_checkpoint_binding() {
    let expected = transparent_native_kernel_descriptor().expect("native descriptor");
    let mut alternate = DescriptorInputs::from_descriptor(&expected);
    alternate.abi_version = 3;
    let alternate = alternate.build();
    let actual_id = alternate.module_id();
    let profile =
        execution_profile_for_empty_template_with_modules(modules_with_native_kernel(alternate));

    let error = TransparentExecutionHost::bind(profile)
        .expect_err("an unknown native ABI must fail before its dependent checkpoint");
    match error {
        KernelError::NativeKernelBindingMismatch {
            expected_module,
            actual_module,
            expected_abi,
            actual_abi,
        } => {
            assert_eq!(expected_module, expected.module_id());
            assert_eq!(actual_module, actual_id);
            assert_eq!(expected_abi, 2);
            assert_eq!(actual_abi, 3);
        }
        other => panic!("unexpected binding error: {other}"),
    }
}

#[test]
fn host_rejects_an_unknown_checkpoint_without_fallback() {
    let expected = transparent_checkpoint_descriptor().expect("checkpoint descriptor");
    let mut alternate = DescriptorInputs::from_descriptor(&expected);
    alternate.parameter_hash = hash(0xf2);
    let alternate = alternate.build();
    let actual_id = alternate.module_id();
    let profile =
        execution_profile_for_empty_template_with_modules(modules_with_checkpoint(alternate));

    let error = TransparentExecutionHost::bind(profile)
        .expect_err("an unknown semantic checkpoint must not use this implementation");
    assert_eq!(error.code(), "kernel.checkpoint_binding_mismatch");
    match error {
        KernelError::CheckpointBindingMismatch {
            expected_module,
            actual_module,
            expected_abi,
            actual_abi,
        } => {
            assert_eq!(expected_module, expected.module_id());
            assert_eq!(actual_module, actual_id);
            assert_eq!(expected_abi, 3);
            assert_eq!(actual_abi, 3);
        }
        other => panic!("unexpected binding error: {other}"),
    }
}

#[test]
fn host_rejects_an_unknown_checkpoint_abi() {
    let expected = transparent_checkpoint_descriptor().expect("checkpoint descriptor");
    let mut alternate = DescriptorInputs::from_descriptor(&expected);
    alternate.abi_version = 4;
    let alternate = alternate.build();
    let actual_id = alternate.module_id();
    let profile =
        execution_profile_for_empty_template_with_modules(modules_with_checkpoint(alternate));

    let error =
        TransparentExecutionHost::bind(profile).expect_err("an unknown checkpoint ABI must fail");
    match error {
        KernelError::CheckpointBindingMismatch {
            expected_module,
            actual_module,
            expected_abi,
            actual_abi,
        } => {
            assert_eq!(expected_module, expected.module_id());
            assert_eq!(actual_module, actual_id);
            assert_eq!(expected_abi, 3);
            assert_eq!(actual_abi, 4);
        }
        other => panic!("unexpected binding error: {other}"),
    }
}

#[test]
fn valid_effect_is_atomic_and_native_value_is_conserved() {
    let source = note(10, 10);
    let (execution_profile, state) = genesis(std::slice::from_ref(&source));
    let spend = transaction(&state, &[source], &[note(20, 6), note(30, 3)], 1);
    let intent = spend.intent_id().expect("intent");
    let transition = apply_with_host(&execution_profile, &state, &[body(1, vec![spend])])
        .expect("checkpoint seals");

    assert_eq!(outcome_for(&transition, intent), Outcome::Accepted);
    assert_eq!(transition.previous(), &state);
    assert_eq!(state.live_notes().len(), 1, "base snapshot was not mutated");
    assert_eq!(transition.next().live_notes().len(), 2);
    assert_eq!(transition.next().nullifiers().len(), 1);
    assert_eq!(transition.next().fee_pool(), 1);
    assert_eq!(transition.next().native_issued(), 10);
    assert_eq!(transition.next().recovery_history().len(), 3);
    transition
        .next()
        .validate()
        .expect("supply invariant holds");
}

#[test]
fn body_precedence_wins_before_cross_body_intent_order() {
    let source = note(10, 7);
    let (execution_profile, state) = genesis(std::slice::from_ref(&source));
    let left = transaction(&state, std::slice::from_ref(&source), &[note(20, 7)], 0);
    let right = transaction(&state, &[source], &[note(30, 7)], 0);
    let (lower, higher) = if left.intent_id().expect("left") < right.intent_id().expect("right") {
        (left, right)
    } else {
        (right, left)
    };
    let low_id = lower.intent_id().expect("low");
    let high_id = higher.intent_id().expect("high");

    let high_first = apply_with_host(
        &execution_profile,
        &state,
        &[body(1, vec![higher.clone()]), body(2, vec![lower.clone()])],
    )
    .expect("high-intent body is still first");
    assert_eq!(outcome_for(&high_first, high_id), Outcome::Accepted);
    assert_eq!(
        outcome_for(&high_first, low_id),
        Outcome::Rejected(RejectCode::ConflictLost)
    );

    let low_first = apply_with_host(
        &execution_profile,
        &state,
        &[body(2, vec![lower]), body(1, vec![higher])],
    )
    .expect("low body first");
    assert_eq!(outcome_for(&low_first, low_id), Outcome::Accepted);
    assert_ne!(high_first.next(), low_first.next());
    assert_ne!(
        high_first.next().checkpoint_id(),
        low_first.next().checkpoint_id()
    );
}

#[test]
fn body_order_must_be_canonical_and_moving_effect_changes_context() {
    let first = note(10, 5);
    let second = note(20, 8);
    let (execution_profile, state) = genesis(&[first.clone(), second.clone()]);
    let tx_a = transaction(&state, &[first], &[note(30, 5)], 0);
    let tx_b = transaction(&state, &[second], &[note(40, 8)], 0);

    let canonical = canonical_body(1, vec![tx_a.clone(), tx_b]);
    let mut descending = canonical.transactions.clone();
    descending.reverse();
    apply_with_host(&execution_profile, &state, std::slice::from_ref(&canonical))
        .expect("canonical body seals");
    assert!(matches!(
        apply_with_host(&execution_profile, &state, &[body(1, descending)]),
        Err(KernelError::NonCanonicalBodyTransactions)
    ));

    let in_first = apply_with_host(
        &execution_profile,
        &state,
        &[body(2, vec![tx_a.clone()]), body(3, Vec::new())],
    )
    .expect("first placement seals");
    let in_second = apply_with_host(
        &execution_profile,
        &state,
        &[body(2, Vec::new()), body(3, vec![tx_a])],
    )
    .expect("second placement seals");
    assert_ne!(
        in_first.next().accepted_effects_in_checkpoint(),
        in_second.next().accepted_effects_in_checkpoint()
    );
    assert_ne!(
        in_first.next().checkpoint_id(),
        in_second.next().checkpoint_id()
    );
}

#[test]
fn same_interval_child_is_not_a_checkpoint_input() {
    let source = note(10, 9);
    let child = note(20, 9);
    let (execution_profile, state) = genesis(std::slice::from_ref(&source));
    let parent = transaction(&state, &[source], std::slice::from_ref(&child), 0);
    let child_spend = transaction(&state, &[child], &[note(30, 9)], 0);
    let child_intent = child_spend.intent_id().expect("child intent");
    let transition = apply_with_host(
        &execution_profile,
        &state,
        &[body(1, vec![parent]), body(2, vec![child_spend])],
    )
    .expect("checkpoint seals");

    assert_eq!(
        outcome_for(&transition, child_intent),
        Outcome::Rejected(RejectCode::InputNotCheckpointed)
    );
    assert_eq!(transition.next().nullifiers().len(), 1);
}

#[test]
fn overlapping_multi_input_loser_has_no_partial_effect() {
    let a = note(10, 4);
    let b = note(20, 6);
    let c = note(30, 8);
    let (execution_profile, state) = genesis(&[a.clone(), b.clone(), c.clone()]);
    let left = transaction(&state, &[a, b.clone()], &[note(40, 10)], 0);
    let right = transaction(&state, &[b, c], &[note(50, 14)], 0);
    let transition = apply_with_host(
        &execution_profile,
        &state,
        &[canonical_body(1, vec![left, right])],
    )
    .expect("seals");

    assert_eq!(
        transition
            .decisions()
            .iter()
            .filter(|decision| decision.outcome == Outcome::Accepted)
            .count(),
        1
    );
    assert_eq!(
        transition
            .decisions()
            .iter()
            .filter(|decision| decision.outcome == Outcome::Rejected(RejectCode::ConflictLost))
            .count(),
        1
    );
    assert_eq!(transition.next().nullifiers().len(), 2);
    assert_eq!(transition.next().live_notes().len(), 2);
    transition.next().validate().expect("no partial value loss");
}

#[test]
fn same_interval_commitment_and_duplicate_intent_are_rejected() {
    let first = note(10, 5);
    let second = note(20, 5);
    let shared_output = note(30, 5);
    let (execution_profile, state) = genesis(&[first.clone(), second.clone()]);
    let left = transaction(&state, &[first], std::slice::from_ref(&shared_output), 0);
    let right = transaction(&state, &[second], &[shared_output], 0);
    let collision = apply_with_host(
        &execution_profile,
        &state,
        &[canonical_body(1, vec![left, right])],
    )
    .expect("seals");
    assert_eq!(
        collision
            .decisions()
            .iter()
            .filter(|decision| decision.outcome == Outcome::Accepted)
            .count(),
        1
    );
    assert_eq!(
        collision
            .decisions()
            .iter()
            .filter(|decision| {
                decision.outcome == Outcome::Rejected(RejectCode::CommitmentConflict)
            })
            .count(),
        1
    );

    let source = note(40, 7);
    let (replay_profile, replay_base) = genesis(std::slice::from_ref(&source));
    let duplicate = transaction(&replay_base, &[source], &[note(50, 7)], 0);
    assert!(matches!(
        apply_with_host(
            &replay_profile,
            &replay_base,
            &[body(2, vec![duplicate.clone(), duplicate.clone()])]
        ),
        Err(KernelError::NonCanonicalBodyTransactions)
    ));
    let duplicate_trace = apply_with_host(
        &replay_profile,
        &replay_base,
        &[body(2, vec![duplicate.clone()]), body(3, vec![duplicate])],
    )
    .expect("seals");
    assert_eq!(duplicate_trace.decisions()[0].outcome, Outcome::Accepted);
    assert_eq!(
        duplicate_trace.decisions()[1].outcome,
        Outcome::Rejected(RejectCode::DuplicateIntent)
    );
}

#[test]
fn missing_reordered_and_forged_recovery_records_reject_without_state_effects() {
    let source = note(10, 10);
    let (execution_profile, state) = genesis(std::slice::from_ref(&source));
    let valid = transaction(&state, &[source], &[note(20, 4), note(30, 6)], 0);

    let mut missing_records = valid.recovery_records().to_vec();
    missing_records.pop();
    let missing = replace_records(&valid, missing_records);
    assert_single_rejection(
        &execution_profile,
        &state,
        missing,
        RejectCode::RecoveryVectorMismatch,
        1,
    );

    let mut reordered_records = valid.recovery_records().to_vec();
    reordered_records.swap(0, 1);
    let reordered = replace_records(&valid, reordered_records);
    assert_single_rejection(
        &execution_profile,
        &state,
        reordered,
        RejectCode::RecoveryCommitmentMismatch,
        2,
    );

    let mut forged_records = valid.recovery_records().to_vec();
    forged_records[0].payload[0] ^= 1;
    let forged = replace_records(&valid, forged_records);
    assert_single_rejection(
        &execution_profile,
        &state,
        forged,
        RejectCode::RecoveryHashMismatch,
        3,
    );
}

fn assert_single_rejection(
    execution_profile: &TransparentExecutionHost,
    state: &CheckpointState,
    transaction: NativeTransaction,
    code: RejectCode,
    body_id: u8,
) {
    assert_eq!(
        state.chain_domain(),
        execution_profile.execution_profile().chain_domain()
    );
    assert_eq!(
        state.profile_domain(),
        execution_profile.execution_profile().profile_domain()
    );
    let transition = apply_with_host(
        execution_profile,
        state,
        &[body(body_id, vec![transaction])],
    )
    .expect("matching execution profile seals");
    assert_eq!(transition.decisions()[0].outcome, Outcome::Rejected(code));
    assert_eq!(transition.next().live_notes(), state.live_notes());
    assert_eq!(transition.next().nullifiers(), state.nullifiers());
    assert_eq!(
        transition.next().commitment_history(),
        state.commitment_history()
    );
    assert_eq!(transition.next().fee_pool(), state.fee_pool());
}

#[test]
fn historical_commitments_and_spent_nullifiers_never_reenter() {
    let source = note(10, 10);
    let middle = note(20, 10);
    let (execution_profile, state) = genesis(std::slice::from_ref(&source));
    let first = transaction(
        &state,
        std::slice::from_ref(&source),
        std::slice::from_ref(&middle),
        0,
    );
    let state_one = apply_with_host(&execution_profile, &state, &[body(1, vec![first])])
        .expect("first seals")
        .into_next();

    let recreate = transaction(&state_one, &[middle], std::slice::from_ref(&source), 0);
    let recreate_id = recreate.intent_id().expect("intent");
    let recreated =
        apply_with_host(&execution_profile, &state_one, &[body(2, vec![recreate])]).expect("seals");
    assert_eq!(
        outcome_for(&recreated, recreate_id),
        Outcome::Rejected(RejectCode::CommitmentAlreadyExists)
    );

    let replay_spend = transaction(&state_one, &[source], &[note(30, 10)], 0);
    let replay_id = replay_spend.intent_id().expect("replay intent");
    let replayed = apply_with_host(
        &execution_profile,
        &state_one,
        &[body(3, vec![replay_spend])],
    )
    .expect("seals");
    assert_eq!(
        outcome_for(&replayed, replay_id),
        Outcome::Rejected(RejectCode::AlreadySpent)
    );
}

#[test]
fn rollback_and_clean_replay_are_byte_identical() {
    let source = note(10, 11);
    let (execution_profile, state) = genesis(std::slice::from_ref(&source));
    assert_eq!(
        state.chain_domain(),
        execution_profile.execution_profile().chain_domain()
    );
    assert_eq!(
        state.profile_domain(),
        execution_profile.execution_profile().profile_domain()
    );
    let spend = transaction(&state, &[source], &[note(20, 10)], 1);
    let bodies = [body(1, vec![spend])];
    let first = apply_with_host(&execution_profile, &state, &bodies).expect("first replay");
    let expected_next = first.next().clone();
    let expected_decisions = first.decisions().to_vec();
    assert_eq!(
        expected_next.chain_domain(),
        execution_profile.execution_profile().chain_domain()
    );
    assert_eq!(
        expected_next.profile_domain(),
        execution_profile.execution_profile().profile_domain()
    );
    let rolled_back = first.rollback();
    assert_eq!(
        rolled_back.chain_domain(),
        execution_profile.execution_profile().chain_domain()
    );
    assert_eq!(
        rolled_back.profile_domain(),
        execution_profile.execution_profile().profile_domain()
    );
    assert_eq!(rolled_back, state);

    let replay = apply_with_host(&execution_profile, &state, &bodies).expect("clean replay");
    assert_eq!(replay.next(), &expected_next);
    assert_eq!(replay.decisions(), expected_decisions);
    assert_eq!(
        replay.next().state_digest().expect("state digest"),
        expected_next.state_digest().expect("state digest")
    );
}

#[test]
fn decoded_checkpoint_requires_internal_identity_and_a_trusted_state_pin() {
    let source = note(10, 11);
    let (host, state) = genesis(std::slice::from_ref(&source));
    let bytes = state.to_canonical_bytes().expect("checkpoint encodes");

    let candidate = UnverifiedCheckpointState::from_canonical_bytes(&bytes)
        .expect("checkpoint candidate decodes");
    let trusted_pin = TrustedCheckpointPin::from_trusted_state(&state);
    let promoted = host
        .verify_checkpoint_state(candidate, trusted_pin)
        .expect("matching identity and trusted pin promote");
    assert_eq!(promoted, state);

    let spend = transaction(&state, &[source], &[note(20, 10)], 1);
    let next = host
        .apply_and_seal(&state, &[body(1, vec![spend])])
        .expect("trusted alternate pin transition executes");
    let wrong_pin = TrustedCheckpointPin::from_trusted_state(next.next());
    let candidate = UnverifiedCheckpointState::from_canonical_bytes(&bytes)
        .expect("checkpoint candidate decodes again");
    assert!(matches!(
        host.verify_checkpoint_state(candidate, wrong_pin),
        Err(CodecVerificationError::CheckpointPinMismatch { .. })
    ));

    let mut changed_id = bytes.clone();
    changed_id[2 + 32 + 32] ^= 1;
    let candidate = UnverifiedCheckpointState::from_canonical_bytes(&changed_id)
        .expect("mutated stored identity remains canonical bytes");
    assert!(matches!(
        host.verify_checkpoint_state(candidate, trusted_pin),
        Err(CodecVerificationError::CheckpointIdentityMismatch { .. })
    ));

    let mut changed_issuance = bytes;
    let issuance_offset = changed_issuance
        .len()
        .checked_sub(32)
        .expect("checkpoint ends in two u128 fields");
    changed_issuance[issuance_offset] ^= 1;
    let candidate = UnverifiedCheckpointState::from_canonical_bytes(&changed_issuance)
        .expect("mutated issuance remains canonical bytes");
    let error = host
        .verify_checkpoint_state(candidate, trusted_pin)
        .expect_err("invalid supply cannot promote");
    assert_eq!(error.code(), "kernel.invalid_state");
}

#[test]
fn decoded_results_and_transitions_promote_only_by_deterministic_replay() {
    let source = note(10, 11);
    let (host, state) = genesis(std::slice::from_ref(&source));
    let spend = transaction(&state, &[source], &[note(20, 10)], 1);
    let bodies = [body(1, vec![spend])];
    let transition = host
        .apply_and_seal(&state, &bodies)
        .expect("trusted transition executes");

    let result = transition.native_interval_result();
    let result_bytes = result.to_canonical_bytes().expect("native result encodes");
    let candidate = UnverifiedNativeIntervalResult::from_canonical_bytes(&result_bytes)
        .expect("native result candidate decodes");
    assert_eq!(
        host.verify_native_interval_result(candidate, &state, &bodies)
            .expect("exact replay promotes result"),
        result
    );

    let mut changed_result = result_bytes;
    let first_decision_position = 2 + 4 + 2;
    changed_result[first_decision_position] ^= 1;
    let candidate = UnverifiedNativeIntervalResult::from_canonical_bytes(&changed_result)
        .expect("mutated decision remains canonical bytes");
    assert!(matches!(
        host.verify_native_interval_result(candidate, &state, &bodies),
        Err(CodecVerificationError::NativeIntervalResultMismatch)
    ));

    let transition_bytes = transition.to_canonical_bytes().expect("transition encodes");
    let candidate = UnverifiedTransition::from_canonical_bytes(&transition_bytes)
        .expect("transition candidate decodes");
    assert_eq!(
        host.verify_transition(candidate, &state, &bodies)
            .expect("exact replay promotes transition"),
        transition
    );

    let mut changed_transition = transition_bytes;
    let first_decision = changed_transition
        .len()
        .checked_sub(113)
        .expect("one accepted decision has fixed minimum size");
    changed_transition[first_decision + 2] ^= 1;
    let candidate = UnverifiedTransition::from_canonical_bytes(&changed_transition)
        .expect("mutated transition decision remains canonical bytes");
    assert!(matches!(
        host.verify_transition(candidate, &state, &bodies),
        Err(CodecVerificationError::TransitionMismatch)
    ));
}

#[test]
fn native_result_replay_accepts_empty_intervals_and_repeated_literal_body_ids() {
    let first_source = note(0x41, 5);
    let second_source = note(0x51, 7);
    let (host, state) = genesis(&[first_source.clone(), second_source.clone()]);

    let empty_transition = host
        .apply_and_seal(&state, &[body(0xa0, Vec::new())])
        .expect("one empty body remains a valid checkpoint");
    let empty_result = empty_transition.native_interval_result();
    let empty_bytes = empty_result
        .to_canonical_bytes()
        .expect("empty native result encodes");
    let empty_candidate = UnverifiedNativeIntervalResult::from_canonical_bytes(&empty_bytes)
        .expect("empty native result candidate decodes");
    assert_eq!(
        host.verify_native_interval_result(empty_candidate, &state, &[])
            .expect("an empty native interval promotes"),
        empty_result
    );

    let first_spend = transaction(&state, &[first_source], &[note(0x61, 5)], 0);
    let second_spend = transaction(&state, &[second_source], &[note(0x71, 7)], 0);
    let unique_bodies = [
        body(0xa1, vec![first_spend.clone()]),
        body(0xa2, vec![second_spend.clone()]),
    ];
    let unique_result = host
        .apply_and_seal(&state, &unique_bodies)
        .expect("unique checkpoint body IDs seal")
        .native_interval_result();
    let mut repeated_bytes = unique_result
        .to_canonical_bytes()
        .expect("native result encodes");
    let second_body_id = [0xa2; 32];
    let matching_offsets = repeated_bytes
        .windows(second_body_id.len())
        .enumerate()
        .filter_map(|(offset, bytes)| (bytes == second_body_id).then_some(offset))
        .collect::<Vec<_>>();
    assert_eq!(
        matching_offsets.len(),
        2,
        "second literal body ID occurs once in its decision and accepted effect"
    );
    for offset in matching_offsets {
        repeated_bytes[offset..offset + second_body_id.len()].copy_from_slice(&[0xa1; 32]);
    }
    let repeated_candidate = UnverifiedNativeIntervalResult::from_canonical_bytes(&repeated_bytes)
        .expect("repeated-body native result candidate decodes");
    let repeated_bodies = [
        body(0xa1, vec![first_spend]),
        body(0xa1, vec![second_spend]),
    ];
    let promoted = host
        .verify_native_interval_result(repeated_candidate, &state, &repeated_bodies)
        .expect("literal body IDs may repeat in a native interval");
    assert_eq!(
        promoted
            .to_canonical_bytes()
            .expect("promoted native result encodes"),
        repeated_bytes
    );
    assert_eq!(promoted.decisions().len(), 2);
    assert!(
        promoted
            .decisions()
            .iter()
            .all(|decision| decision.body_id == VertexId::from_bytes([0xa1; 32]))
    );
    assert!(
        promoted
            .decisions()
            .iter()
            .all(|decision| decision.outcome == Outcome::Accepted)
    );
    assert_eq!(promoted.accepted_effects().len(), 2);
    assert!(
        promoted
            .accepted_effects()
            .iter()
            .all(|effect| effect.body_id == VertexId::from_bytes([0xa1; 32]))
    );

    assert!(matches!(
        host.apply_and_seal(&state, &[]),
        Err(KernelError::EmptyCheckpoint)
    ));
    assert!(matches!(
        host.apply_and_seal(&state, &repeated_bodies),
        Err(KernelError::DuplicateOrderedBody)
    ));
}

#[test]
fn rejected_body_bytes_are_checkpoint_bound_even_when_body_id_is_reused() {
    let source = note(10, 10);
    let (execution_profile, state) = genesis(std::slice::from_ref(&source));
    let mut first = transaction(&state, &[source], &[note(20, 10)], 0);
    first.chain_domain = ChainDomain::from_bytes([9; 32]);
    first = replace_records_and_hashes(&first, first.recovery_records().to_vec());
    let mut second = first.clone();
    second.public_fee = 1;
    let mut changed_records = first.recovery_records().to_vec();
    changed_records[0].payload[0] ^= 1;
    let third = replace_records_and_hashes(&first, changed_records);

    let first_transition = apply_with_host(
        &execution_profile,
        &state,
        &[body(0x66, vec![first.clone()])],
    )
    .expect("first body seals");
    let second_transition =
        apply_with_host(&execution_profile, &state, &[body(0x66, vec![second])])
            .expect("second body seals");
    let third_transition = apply_with_host(&execution_profile, &state, &[body(0x66, vec![third])])
        .expect("third body seals");
    assert_eq!(
        first_transition.decisions()[0].outcome,
        Outcome::Rejected(RejectCode::WrongChain)
    );
    assert_eq!(
        second_transition.decisions()[0].outcome,
        Outcome::Rejected(RejectCode::WrongChain)
    );
    assert_eq!(
        third_transition.decisions()[0].outcome,
        Outcome::Rejected(RejectCode::WrongChain)
    );
    assert_eq!(
        first_transition.next().live_notes(),
        second_transition.next().live_notes()
    );
    assert_ne!(
        first_transition.next().body_bindings_in_checkpoint(),
        second_transition.next().body_bindings_in_checkpoint()
    );
    assert_ne!(
        first_transition.next().body_bindings_in_checkpoint(),
        third_transition.next().body_bindings_in_checkpoint()
    );
    assert_ne!(
        first_transition
            .next()
            .state_digest()
            .expect("first digest"),
        second_transition
            .next()
            .state_digest()
            .expect("second digest")
    );
    assert_ne!(
        first_transition.next().checkpoint_id(),
        second_transition.next().checkpoint_id()
    );
    assert_ne!(
        first_transition.next().checkpoint_id(),
        third_transition.next().checkpoint_id()
    );

    let mut fourth = first;
    fourth.public_fee = 2;
    let forward = apply_with_host(
        &execution_profile,
        &state,
        &[
            body(0x67, vec![fourth.clone()]),
            body(0x68, vec![fourth.clone()]),
        ],
    )
    .expect("forward placement seals");
    let mut fifth = fourth.clone();
    fifth.public_fee = 3;
    let swapped = apply_with_host(
        &execution_profile,
        &state,
        &[body(0x67, vec![fifth]), body(0x68, vec![fourth])],
    )
    .expect("swapped placement seals");
    assert_eq!(
        forward.next().bodies_in_checkpoint(),
        swapped.next().bodies_in_checkpoint()
    );
    assert_ne!(
        forward.next().body_bindings_in_checkpoint(),
        swapped.next().body_bindings_in_checkpoint()
    );
    assert_ne!(
        forward.next().checkpoint_id(),
        swapped.next().checkpoint_id()
    );
}

#[test]
fn chain_profile_anchor_authorization_and_conservation_fail_closed() {
    let source = note(10, 10);
    let (execution_profile, state) = genesis(std::slice::from_ref(&source));
    let valid = transaction(&state, &[source], &[note(20, 10)], 0);

    let mut wrong_chain = valid.clone();
    wrong_chain.chain_domain = ChainDomain::from_bytes([9; 32]);
    assert_single_rejection(
        &execution_profile,
        &state,
        wrong_chain,
        RejectCode::WrongChain,
        1,
    );
    let mut wrong_profile = valid.clone();
    wrong_profile.profile_domain = ProfileDomain::from_bytes([9; 32]);
    assert_single_rejection(
        &execution_profile,
        &state,
        wrong_profile,
        RejectCode::WrongProfile,
        2,
    );
    let mut wrong_anchor = valid.clone();
    wrong_anchor.anchor = CheckpointId::from_bytes([9; 32]);
    assert_single_rejection(
        &execution_profile,
        &state,
        wrong_anchor,
        RejectCode::WrongCheckpoint,
        3,
    );
    let mut unauthorized_inputs = valid.inputs().to_vec();
    unauthorized_inputs[0].witness.authorization_valid = false;
    let unauthorized = replace_inputs(&valid, unauthorized_inputs);
    assert_single_rejection(
        &execution_profile,
        &state,
        unauthorized,
        RejectCode::InvalidTransparentWitness,
        4,
    );
    let unconserved = transaction(&state, &[note(10, 10)], &[note(30, 9)], 0);
    assert_single_rejection(
        &execution_profile,
        &state,
        unconserved,
        RejectCode::ConservationFailure,
        5,
    );
}

#[test]
fn compound_failures_follow_the_frozen_gate_a_precedence() {
    let source = note(10, 10);
    let (execution_profile, state) = genesis(std::slice::from_ref(&source));
    let valid = transaction(&state, std::slice::from_ref(&source), &[note(20, 10)], 0);

    let mut wrong_chain = valid.clone();
    wrong_chain.chain_domain = ChainDomain::from_bytes([9; 32]);
    let empty_wrong_chain = NativeTransaction::new(
        wrong_chain.chain_domain,
        wrong_chain.profile_domain,
        wrong_chain.anchor,
        wrong_chain.public_fee,
        Vec::new(),
        wrong_chain.outputs().to_vec(),
        wrong_chain.recovery_hashes().to_vec(),
        wrong_chain.recovery_records().to_vec(),
    )
    .expect("bounded compound failure");
    assert_single_rejection(
        &execution_profile,
        &state,
        empty_wrong_chain,
        RejectCode::EmptyInputs,
        0x71,
    );

    let duplicate_wrong_chain = NativeTransaction::new(
        wrong_chain.chain_domain,
        wrong_chain.profile_domain,
        wrong_chain.anchor,
        wrong_chain.public_fee,
        vec![
            wrong_chain.inputs()[0].clone(),
            wrong_chain.inputs()[0].clone(),
        ],
        wrong_chain.outputs().to_vec(),
        wrong_chain.recovery_hashes().to_vec(),
        wrong_chain.recovery_records().to_vec(),
    )
    .expect("bounded compound failure");
    assert_single_rejection(
        &execution_profile,
        &state,
        duplicate_wrong_chain,
        RejectCode::WrongChain,
        0x76,
    );

    let missing_recovery_wrong_chain = NativeTransaction::new(
        wrong_chain.chain_domain,
        wrong_chain.profile_domain,
        wrong_chain.anchor,
        wrong_chain.public_fee,
        wrong_chain.inputs().to_vec(),
        wrong_chain.outputs().to_vec(),
        wrong_chain.recovery_hashes().to_vec(),
        Vec::new(),
    )
    .expect("bounded compound failure");
    assert_single_rejection(
        &execution_profile,
        &state,
        missing_recovery_wrong_chain,
        RejectCode::WrongChain,
        0x77,
    );

    let historical = source.commitment(state.chain_domain()).expect("commitment");
    let mut forged_outputs = valid.outputs().to_vec();
    forged_outputs[0].commitment = historical;
    let forged_historical = replace_outputs(&valid, forged_outputs);
    assert_single_rejection(
        &execution_profile,
        &state,
        forged_historical,
        RejectCode::CommitmentAlreadyExists,
        0x72,
    );

    let first = apply_with_host(&execution_profile, &state, &[body(0x73, vec![valid])])
        .expect("first spend seals")
        .into_next();
    let mut replay = transaction(&first, &[source], &[note(30, 10)], 0);
    let mut forged_inputs = replay.inputs().to_vec();
    forged_inputs[0].witness.note.owner_tag = hash(0xfe);
    replay = replace_inputs(&replay, forged_inputs);
    assert_single_rejection(
        &execution_profile,
        &first,
        replay,
        RejectCode::AlreadySpent,
        0x74,
    );

    let unconserved = transaction(&state, &[note(10, 10)], &[note(40, 9)], 0);
    let mut corrupt_records = unconserved.recovery_records().to_vec();
    corrupt_records[0].payload[0] ^= 1;
    let corrupt_and_unconserved = replace_records(&unconserved, corrupt_records);
    assert_single_rejection(
        &execution_profile,
        &state,
        corrupt_and_unconserved,
        RejectCode::ConservationFailure,
        0x75,
    );
}

#[test]
fn base_conflicts_precede_interval_conflicts_across_complete_vectors() {
    let interval_source = note(10, 5);
    let spent_source = note(20, 7);
    let (execution_profile, state) = genesis(&[interval_source.clone(), spent_source.clone()]);
    let spend_base = transaction(
        &state,
        std::slice::from_ref(&spent_source),
        &[note(30, 7)],
        0,
    );
    let next_base = apply_with_host(&execution_profile, &state, &[body(0x81, vec![spend_base])])
        .expect("base spend seals")
        .into_next();

    let win_interval = transaction(
        &next_base,
        std::slice::from_ref(&interval_source),
        &[note(40, 5)],
        0,
    );
    let mixed_inputs = transaction(
        &next_base,
        &[interval_source, spent_source],
        &[note(50, 12)],
        0,
    );
    let mixed_input_id = mixed_inputs.intent_id().expect("mixed input intent");
    let input_transition = apply_with_host(
        &execution_profile,
        &next_base,
        &[
            body(0x82, vec![win_interval]),
            body(0x83, vec![mixed_inputs]),
        ],
    )
    .expect("input conflict interval seals");
    assert_eq!(
        outcome_for(&input_transition, mixed_input_id),
        Outcome::Rejected(RejectCode::AlreadySpent)
    );

    let first_source = note(60, 3);
    let second_source = note(70, 8);
    let historical = note(80, 1);
    let (output_profile, output_base) = genesis(&[
        first_source.clone(),
        second_source.clone(),
        historical.clone(),
    ]);
    let pending = note(90, 3);
    let create_pending = transaction(
        &output_base,
        &[first_source],
        std::slice::from_ref(&pending),
        0,
    );
    let candidate = transaction(&output_base, &[second_source], &[pending, note(100, 5)], 0);
    let mut mixed_outputs = candidate.outputs().to_vec();
    mixed_outputs[1].commitment = historical
        .commitment(output_base.chain_domain())
        .expect("historical commitment");
    let mixed_outputs = replace_outputs(&candidate, mixed_outputs);
    let mixed_output_id = mixed_outputs.intent_id().expect("mixed output intent");
    let output_transition = apply_with_host(
        &output_profile,
        &output_base,
        &[
            body(0x84, vec![create_pending]),
            body(0x85, vec![mixed_outputs]),
        ],
    )
    .expect("output conflict interval seals");
    assert_eq!(
        outcome_for(&output_transition, mixed_output_id),
        Outcome::Rejected(RejectCode::CommitmentAlreadyExists)
    );
}

#[test]
fn canonical_transaction_bytes_round_trip_and_reject_extensions() {
    let source = note(10, 3);
    let (_execution_profile, state) = genesis(std::slice::from_ref(&source));
    let transaction = transaction(&state, &[source], &[note(20, 3)], 0);
    let bytes = transaction.to_canonical_bytes().expect("encodes");
    assert_eq!(
        NativeTransaction::from_canonical_bytes(&bytes),
        Ok(transaction)
    );

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(matches!(
        NativeTransaction::from_canonical_bytes(&trailing),
        Err(DecodeError::TrailingBytes { .. })
    ));
    let mut unknown_tag = bytes;
    unknown_tag[0] = 99;
    assert!(matches!(
        NativeTransaction::from_canonical_bytes(&unknown_tag),
        Err(DecodeError::UnknownTag { value: 99, .. })
    ));

    let mut impossible_body = vec![1];
    impossible_body.extend_from_slice(&[0_u8; 32]);
    impossible_body.extend_from_slice(&1_u32.to_le_bytes());
    impossible_body.push(0xff);
    assert!(matches!(
        OrderedBody::from_canonical_bytes(&impossible_body),
        Err(DecodeError::LimitExceeded { .. })
    ));

    let mut transaction_prefix = vec![0_u8; 105];
    transaction_prefix[0] = 1;
    let transaction_cases = [
        {
            let mut encoded = transaction_prefix.clone();
            encoded.extend_from_slice(&1_u32.to_le_bytes());
            encoded.push(0xff);
            encoded
        },
        {
            let mut encoded = transaction_prefix.clone();
            encoded.extend_from_slice(&0_u32.to_le_bytes());
            encoded.extend_from_slice(&1_u32.to_le_bytes());
            encoded.push(0xff);
            encoded
        },
        {
            let mut encoded = transaction_prefix.clone();
            encoded.extend_from_slice(&0_u32.to_le_bytes());
            encoded.extend_from_slice(&0_u32.to_le_bytes());
            encoded.extend_from_slice(&1_u32.to_le_bytes());
            encoded.push(0xff);
            encoded
        },
        {
            let mut encoded = transaction_prefix;
            encoded.extend_from_slice(&0_u32.to_le_bytes());
            encoded.extend_from_slice(&0_u32.to_le_bytes());
            encoded.extend_from_slice(&0_u32.to_le_bytes());
            encoded.extend_from_slice(&1_u32.to_le_bytes());
            encoded.push(0xff);
            encoded
        },
    ];
    for encoded in transaction_cases {
        assert!(matches!(
            NativeTransaction::from_canonical_bytes(&encoded),
            Err(DecodeError::LimitExceeded { .. })
        ));
    }

    let impossible_template = [1, 1, 0, 0, 0, 0xff];
    assert!(matches!(
        GenesisAllocationTemplate::from_canonical_bytes(&impossible_template),
        Err(DecodeError::LimitExceeded { .. })
    ));
}

#[test]
fn gate_a_genesis_receipt_is_canonical_recomputed_and_fail_closed() {
    let allocation_template = allocation_template(&[note(0x71, 11), note(0x81, 13)]);
    let execution_profile = execution_profile_for(&allocation_template, 1);
    let host = host_for_profile(execution_profile.clone());
    let materialized = host
        .genesis(allocation_template)
        .expect("receipt fixture genesis materializes");
    let state = materialized.state();
    let receipt = materialized.receipt();

    receipt
        .verify(&execution_profile, state)
        .expect("receipt recomputes exactly");
    assert_eq!(receipt.protocol_major(), execution_profile.protocol_major());
    assert_eq!(
        receipt.genesis_commitment(),
        execution_profile.genesis_commitment()
    );
    assert_eq!(receipt.chain_domain(), execution_profile.chain_domain());
    assert_eq!(
        receipt.protocol_manifest_hash(),
        execution_profile.manifest_hash()
    );
    assert_eq!(receipt.profile_domain(), execution_profile.profile_domain());
    assert_eq!(
        receipt.checkpoint_zero_state_digest(),
        state.state_digest().expect("state digest derives")
    );
    assert_eq!(receipt.checkpoint_zero_id(), state.checkpoint_id());

    let bytes = receipt.to_canonical_bytes().expect("receipt encodes");
    assert_eq!(bytes.len(), 197);
    assert_eq!(
        GateAGenesisReceipt::from_canonical_bytes(&bytes),
        Ok(receipt.clone())
    );
    for length in 0..bytes.len() {
        assert!(matches!(
            GateAGenesisReceipt::from_canonical_bytes(&bytes[..length]),
            Err(DecodeError::UnexpectedEof { .. })
        ));
    }

    let mut unknown_version = bytes.clone();
    unknown_version[0] = 2;
    assert!(matches!(
        GateAGenesisReceipt::from_canonical_bytes(&unknown_version),
        Err(DecodeError::UnknownTag {
            offset: 0,
            value: 2
        })
    ));
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(matches!(
        GateAGenesisReceipt::from_canonical_bytes(&trailing),
        Err(DecodeError::TrailingBytes { .. })
    ));

    let mutations = [
        (1, GateAGenesisReceiptField::ProtocolMajor),
        (5, GateAGenesisReceiptField::GenesisCommitment),
        (37, GateAGenesisReceiptField::ChainDomain),
        (69, GateAGenesisReceiptField::ProtocolManifestHash),
        (101, GateAGenesisReceiptField::ProfileDomain),
        (133, GateAGenesisReceiptField::CheckpointZeroStateDigest),
        (165, GateAGenesisReceiptField::CheckpointZeroId),
    ];
    for (offset, expected_field) in mutations {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        let candidate = GateAGenesisReceipt::from_canonical_bytes(&changed)
            .expect("field mutation remains canonical");
        assert!(matches!(
            candidate.verify(&execution_profile, state),
            Err(KernelError::GenesisReceiptMismatch { field }) if field == expected_field
        ));
    }

    let mut compound_mismatch = bytes;
    for (offset, _) in mutations {
        compound_mismatch[offset] ^= 1;
    }
    let candidate = GateAGenesisReceipt::from_canonical_bytes(&compound_mismatch)
        .expect("compound field mutation remains canonical");
    assert!(matches!(
        candidate.verify(&execution_profile, state),
        Err(KernelError::GenesisReceiptMismatch {
            field: GateAGenesisReceiptField::ProtocolMajor
        })
    ));
}

#[test]
#[allow(clippy::too_many_lines)]
fn consumes_strict_language_neutral_genesis_receipt_fixture() {
    let document = include_str!("../../../fixtures/genesis-receipt-v1.json");
    let fixture: GenesisReceiptFixture =
        serde_json::from_str(document).expect("strict receipt fixture schema parses");
    assert_eq!(fixture.schema, "silknode.gate-a.genesis-receipt.v1");
    assert_eq!(fixture.case_id, "transparent-two-entry-genesis-v1");

    let allocation_template = allocation_template(&[note(0x71, 11), note(0x81, 13)]);
    let execution_profile = execution_profile_for(&allocation_template, 1);
    let host = host_for_profile(execution_profile.clone());
    let materialized = host
        .genesis(allocation_template)
        .expect("fixture genesis materializes");
    let template = execution_profile.gate_a_genesis_receipt_template();
    let template_bytes = template.to_canonical_bytes().expect("template encodes");
    let receipt_bytes = materialized
        .receipt()
        .to_canonical_bytes()
        .expect("receipt encodes");

    assert_eq!(
        fixture_hex(&fixture.canonical_template_hex, "canonical_template_hex"),
        template_bytes
    );
    assert_eq!(
        fixture_hex(&fixture.canonical_receipt_hex, "canonical_receipt_hex"),
        receipt_bytes
    );
    assert_eq!(
        fixture.expected.template.canonical_length_bytes,
        template_bytes.len()
    );
    assert_eq!(
        fixture.expected.receipt.canonical_length_bytes,
        receipt_bytes.len()
    );
    assert_eq!(
        fixture.expected.template.template_hash_hex,
        template
            .historical_a2a5_object_slot_hash()
            .expect("receipt template hashes")
            .to_string()
    );

    let template_projection = fixture.expected.template.projection;
    assert_eq!(template_projection.template_version_u8, 1);
    assert_eq!(
        template_projection.protocol_major_u32,
        template.protocol_major()
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
        GateAGenesisReceiptRecipe::ORDERED.len()
    );
    for ((slot, name), recipe) in template_projection
        .derived_slots
        .iter()
        .zip(expected_slot_names)
        .zip(GateAGenesisReceiptRecipe::ORDERED)
    {
        assert_eq!(slot.field, name);
        assert_eq!(
            fixture_hex(&slot.zero_placeholder_hex, "zero_placeholder_hex"),
            vec![0; Hash32::LENGTH]
        );
        assert_eq!(slot.recipe_tag_u8, recipe.tag());
    }

    let receipt_projection = fixture.expected.receipt.projection;
    let receipt = materialized.receipt();
    assert_eq!(receipt_projection.receipt_version_u8, 1);
    assert_eq!(
        receipt_projection.protocol_major_u32,
        receipt.protocol_major()
    );
    assert_eq!(
        receipt_projection.genesis_commitment_hex,
        receipt.genesis_commitment().to_string()
    );
    assert_eq!(
        receipt_projection.chain_domain_hex,
        receipt.chain_domain().to_string()
    );
    assert_eq!(
        receipt_projection.protocol_manifest_hash_hex,
        receipt.protocol_manifest_hash().to_string()
    );
    assert_eq!(
        receipt_projection.profile_domain_hex,
        receipt.profile_domain().to_string()
    );
    assert_eq!(
        receipt_projection.checkpoint_zero_state_digest_hex,
        receipt.checkpoint_zero_state_digest().to_string()
    );
    assert_eq!(
        receipt_projection.checkpoint_zero_id_hex,
        receipt.checkpoint_zero_id().to_string()
    );
    assert_eq!(bytes_hex(&template_bytes), fixture.canonical_template_hex);
    assert_eq!(bytes_hex(&receipt_bytes), fixture.canonical_receipt_hex);
}

#[test]
fn gate_a_genesis_receipt_rejects_cross_network_and_state_substitution() {
    let first_template = allocation_template(&[note(0x91, 5)]);
    let first_profile = execution_profile_for(&first_template, 1);
    let first_host = host_for_profile(first_profile);
    let first = first_host
        .genesis(first_template)
        .expect("first genesis materializes");

    let second_template = allocation_template(&[note(0xa1, 5)]);
    let second_profile = execution_profile_for(&second_template, 1);
    let second_host = host_for_profile(second_profile.clone());
    let second = second_host
        .genesis(second_template)
        .expect("second genesis materializes");

    assert!(matches!(
        first.receipt().verify(&second_profile, second.state()),
        Err(KernelError::GenesisReceiptMismatch {
            field: GateAGenesisReceiptField::GenesisCommitment
        })
    ));
    assert!(matches!(
        first.receipt().verify(&second_profile, first.state()),
        Err(KernelError::ExecutionChainMismatch { .. })
    ));

    let source = note(0x91, 5);
    let spend = transaction(first.state(), &[source], &[note(0x92, 5)], 0);
    let transition = first_host
        .apply_and_seal(first.state(), &[body(0xe1, vec![spend])])
        .expect("checkpoint one seals");
    assert!(matches!(
        first
            .receipt()
            .verify(first_host.execution_profile(), transition.next()),
        Err(KernelError::GenesisReceiptRequiresCheckpointZero)
    ));
}

#[test]
fn genesis_and_checkpoint_resource_boundaries_fail_closed() {
    let duplicate_template = allocation_template(&[note(10, 1), note(10, 1)]);
    let duplicate_profile = execution_profile_for(&duplicate_template, 1);
    let duplicate_host = host_for_profile(duplicate_profile);
    assert!(matches!(
        duplicate_host.genesis(duplicate_template),
        Err(KernelError::DuplicateGenesisCommitment)
    ));

    let (execution_profile, state) = genesis(&[]);
    assert!(matches!(
        apply_with_host(&execution_profile, &state, &[]),
        Err(KernelError::EmptyCheckpoint)
    ));
    assert!(matches!(
        apply_with_host(
            &execution_profile,
            &state,
            &[body(1, Vec::new()), body(1, Vec::new())]
        ),
        Err(KernelError::DuplicateOrderedBody)
    ));

    let source = note(20, 1);
    let (_bounded_profile, bounded_state) = genesis(std::slice::from_ref(&source));
    let valid = transaction(&bounded_state, &[source], &[note(30, 1)], 0);
    let oversized_inputs = vec![valid.inputs()[0].clone(); MAX_INPUTS + 1];
    let error = NativeTransaction::new(
        valid.chain_domain,
        valid.profile_domain,
        valid.anchor,
        valid.public_fee,
        oversized_inputs,
        valid.outputs().to_vec(),
        valid.recovery_hashes().to_vec(),
        valid.recovery_records().to_vec(),
    )
    .expect_err("oversized safe construction rejects before hashing");
    assert_eq!(error.field, "inputs");
    assert_eq!(error.actual, MAX_INPUTS + 1);
}

#[test]
fn allocation_template_bytes_are_versioned_bounded_and_exact() {
    let allocation_template = allocation_template(&[note(0x11, 42)]);
    let bytes = allocation_template
        .to_canonical_bytes()
        .expect("template encodes");

    let mut expected = vec![1, 1, 0, 0, 0, 1, 1];
    expected.extend_from_slice(&42_u64.to_le_bytes());
    expected.extend_from_slice(&[0x11; 32]);
    expected.extend_from_slice(&[0x12; 32]);
    expected.extend_from_slice(&[0x13; 32]);
    expected.extend_from_slice(&[0x14; 32]);
    expected.extend_from_slice(&[0; 8]);
    expected.extend_from_slice(&[0xa6; RECOVERY_PAYLOAD_BYTES - 8]);
    assert_eq!(bytes, expected, "frozen allocation-template bytes changed");
    assert_eq!(
        GenesisAllocationTemplate::from_canonical_bytes(&bytes),
        Ok(allocation_template)
    );

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(matches!(
        GenesisAllocationTemplate::from_canonical_bytes(&trailing),
        Err(DecodeError::TrailingBytes { .. })
    ));

    let mut unknown_template = bytes.clone();
    unknown_template[0] = 99;
    assert!(matches!(
        GenesisAllocationTemplate::from_canonical_bytes(&unknown_template),
        Err(DecodeError::UnknownTag {
            offset: 0,
            value: 99
        })
    ));

    let mut unknown_entry = bytes.clone();
    unknown_entry[5] = 98;
    assert!(matches!(
        GenesisAllocationTemplate::from_canonical_bytes(&unknown_entry),
        Err(DecodeError::UnknownTag {
            offset: 5,
            value: 98
        })
    ));

    let mut unknown_note = bytes;
    unknown_note[6] = 97;
    assert!(matches!(
        GenesisAllocationTemplate::from_canonical_bytes(&unknown_note),
        Err(DecodeError::UnknownTag {
            offset: 6,
            value: 97
        })
    ));

    let mut oversized_wire = vec![1];
    oversized_wire.extend_from_slice(
        &u32::try_from(MAX_GENESIS_ALLOCATIONS + 1)
            .expect("test bound fits u32")
            .to_le_bytes(),
    );
    assert!(matches!(
        GenesisAllocationTemplate::from_canonical_bytes(&oversized_wire),
        Err(DecodeError::LimitExceeded {
            kind: "list",
            length,
            max: MAX_GENESIS_ALLOCATIONS,
        }) if length == MAX_GENESIS_ALLOCATIONS + 1
    ));

    let entry = GenesisAllocationTemplateEntry::new(note(1, 1), [0; RECOVERY_PAYLOAD_BYTES]);
    let local_error = GenesisAllocationTemplate::new(vec![entry; MAX_GENESIS_ALLOCATIONS + 1])
        .expect_err("local construction enforces the same bound");
    assert_eq!(local_error.actual, MAX_GENESIS_ALLOCATIONS + 1);
    assert_eq!(local_error.max, MAX_GENESIS_ALLOCATIONS);
}

#[test]
fn every_template_field_order_and_cardinality_are_profile_bound() {
    let first = note(0x21, 7);
    let second = note(0x31, 9);
    let original = allocation_template(&[first.clone(), second.clone()]);
    let execution_profile = execution_profile_for(&original, 1);
    let host = host_for_profile(execution_profile.clone());
    host.genesis(original.clone())
        .expect("the exact trusted template materializes");

    let mut mutations = Vec::new();
    let mut changed = first.clone();
    changed.value ^= 1;
    mutations.push(allocation_template(&[changed, second.clone()]));
    let mut changed = first.clone();
    changed.owner_tag = hash(0xe1);
    mutations.push(allocation_template(&[changed, second.clone()]));
    let mut changed = first.clone();
    changed.rho = hash(0xe2);
    mutations.push(allocation_template(&[changed, second.clone()]));
    let mut changed = first.clone();
    changed.randomness = hash(0xe3);
    mutations.push(allocation_template(&[changed, second.clone()]));
    let mut changed = first.clone();
    changed.nullifier_key = hash(0xe4);
    mutations.push(allocation_template(&[changed, second]));

    let mut changed_entries = original.entries().to_vec();
    let mut changed_payload = *changed_entries[0].recovery_payload();
    changed_payload[RECOVERY_PAYLOAD_BYTES - 1] ^= 1;
    changed_entries[0] = GenesisAllocationTemplateEntry::new(first.clone(), changed_payload);
    mutations.push(
        GenesisAllocationTemplate::new(changed_entries).expect("payload mutation is bounded"),
    );

    let mut reordered = original.entries().to_vec();
    reordered.swap(0, 1);
    mutations.push(GenesisAllocationTemplate::new(reordered).expect("reorder is bounded"));

    let mut added = original.entries().to_vec();
    added.push(GenesisAllocationTemplateEntry::new(
        note(0x41, 11),
        template_payload(2),
    ));
    mutations.push(GenesisAllocationTemplate::new(added).expect("addition is bounded"));

    let mut removed = original.entries().to_vec();
    removed.pop();
    mutations.push(GenesisAllocationTemplate::new(removed).expect("removal is bounded"));

    let duplicate = GenesisAllocationTemplate::new(vec![
        GenesisAllocationTemplateEntry::new(first.clone(), template_payload(0)),
        GenesisAllocationTemplateEntry::new(first, template_payload(1)),
    ])
    .expect("duplicate candidate is bounded");
    mutations.push(duplicate);

    for mutation in mutations {
        assert_template_mismatch(&execution_profile, mutation);
    }
}

#[test]
fn trusted_noncanonical_extension_cannot_match_the_canonical_candidate() {
    let allocation_template = allocation_template(&[note(0x47, 13)]);
    let mut trusted_bytes = allocation_template
        .to_canonical_bytes()
        .expect("template encodes");
    trusted_bytes.push(0);
    let execution_profile = execution_profile_for_trusted_allocation_bytes(&trusted_bytes, 1);

    assert_template_mismatch(&execution_profile, allocation_template);
}

#[test]
fn recovery_bindings_and_chain_are_derived_from_the_exact_template() {
    let allocated_note = note(0x51, 17);
    let payload = [0x7c; RECOVERY_PAYLOAD_BYTES];
    let allocation_template =
        GenesisAllocationTemplate::new(vec![GenesisAllocationTemplateEntry::new(
            allocated_note.clone(),
            payload,
        )])
        .expect("single allocation is bounded");
    let execution_profile = execution_profile_for(&allocation_template, 1);
    let chain = execution_profile.chain_domain();
    let expected_commitment = allocated_note
        .commitment(chain)
        .expect("chain-bound commitment derives");
    let host = host_for_profile(execution_profile);
    let materialized = host
        .genesis(allocation_template)
        .expect("exact template materializes");
    let (state, _) = materialized.into_parts();
    assert_eq!(
        state.live_notes().get(&expected_commitment),
        Some(&allocated_note)
    );
    assert_eq!(state.recovery_history().len(), 1);
    assert_eq!(
        state.recovery_history()[0].output_commitment,
        expected_commitment
    );
    assert_eq!(state.recovery_history()[0].payload, payload);

    let changed_template =
        GenesisAllocationTemplate::new(vec![GenesisAllocationTemplateEntry::new(
            allocated_note.clone(),
            [0x7d; RECOVERY_PAYLOAD_BYTES],
        )])
        .expect("changed allocation is bounded");
    let changed_profile = execution_profile_for(&changed_template, 1);
    assert_ne!(changed_profile.chain_domain(), chain);
    let changed_chain = changed_profile.chain_domain();
    let changed_host = host_for_profile(changed_profile);
    let changed_materialized = changed_host
        .genesis(changed_template)
        .expect("changed exact template materializes on its own derived chain");
    let (changed_state, _) = changed_materialized.into_parts();
    let changed_commitment = allocated_note
        .commitment(changed_chain)
        .expect("changed chain-bound commitment derives");
    assert_ne!(changed_commitment, expected_commitment);
    assert_eq!(
        changed_state.recovery_history()[0].output_commitment,
        changed_commitment
    );
}

#[test]
fn exact_pinning_precedes_materialization_and_accepts_maximum_total() {
    let original = allocation_template(&[note(0x61, 3)]);
    let original_profile = execution_profile_for(&original, 1);
    let duplicate = GenesisAllocationTemplate::new(vec![
        GenesisAllocationTemplateEntry::new(note(0x62, 4), template_payload(0)),
        GenesisAllocationTemplateEntry::new(note(0x62, 4), template_payload(1)),
    ])
    .expect("duplicate template is bounded");
    assert_template_mismatch(&original_profile, duplicate.clone());

    let duplicate_profile = execution_profile_for(&duplicate, 1);
    let duplicate_host = host_for_profile(duplicate_profile);
    assert!(matches!(
        duplicate_host.genesis(duplicate),
        Err(KernelError::DuplicateGenesisCommitment)
    ));

    let entries = (0..MAX_GENESIS_ALLOCATIONS)
        .map(|index| {
            GenesisAllocationTemplateEntry::new(
                indexed_note(index, u64::MAX),
                template_payload(index),
            )
        })
        .collect();
    let maximum = GenesisAllocationTemplate::new(entries).expect("exact maximum is bounded");
    let maximum_profile = execution_profile_for(&maximum, 1);
    let maximum_host = host_for_profile(maximum_profile);
    let maximum_materialized = maximum_host
        .genesis(maximum)
        .expect("maximum bounded u64 allocation total fits u128");
    let (maximum_state, _) = maximum_materialized.into_parts();
    assert_eq!(maximum_state.live_notes().len(), MAX_GENESIS_ALLOCATIONS);
    assert_eq!(
        maximum_state.native_issued(),
        (MAX_GENESIS_ALLOCATIONS as u128) * u128::from(u64::MAX)
    );
}

#[test]
fn execution_chain_mismatch_precedes_every_existing_checkpoint_error() {
    let (execution_profile, state) = genesis(&[]);
    let wrong_template = allocation_template(&[note(0xc2, 1)]);
    let wrong_execution = execution_profile_for(&wrong_template, 1);
    let other_chain = wrong_execution.chain_domain();
    let wrong_host = host_for_profile(wrong_execution);
    assert_ne!(
        other_chain,
        execution_profile.execution_profile().chain_domain()
    );

    let error = apply_with_host(&wrong_host, &state, &[])
        .expect_err("wrong execution chain rejects before the empty-batch error");
    assert_eq!(error.code(), "kernel.execution_chain_mismatch");
    match error {
        KernelError::ExecutionChainMismatch { execution, state } => {
            assert_eq!(execution, other_chain);
            assert_eq!(state, execution_profile.execution_profile().chain_domain());
        }
        other => panic!("unexpected structural error: {other}"),
    }
}

// The profile-mismatch branch remains a stable structural guard for future
// successor tokens. The current public API can only activate genesis, whose
// profile and allocation-template inputs also derive its chain; therefore an
// honest same-chain alternate `ExecutionProfile` is intentionally
// unconstructible here without the unavailable successor-activation witness.

#[test]
fn rejection_codes_are_frozen_unique_and_contiguous() {
    let codes = [
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
    ];
    for (index, code) in codes.iter().copied().enumerate() {
        assert_eq!(usize::from(code.numeric()), index + 1);
        assert!(code.code().starts_with("kernel."));
    }
    let unique = codes
        .iter()
        .map(|code| code.code())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(unique.len(), codes.len());
}

#[test]
fn frozen_checkpoint_vector_matches_cross_client_contract() {
    let source = note(0x11, 42);
    let frozen_template = allocation_template(std::slice::from_ref(&source));
    let (execution_profile, state) = genesis(std::slice::from_ref(&source));
    let spend = transaction(&state, &[source], &[note(0x55, 40)], 2);
    let transition = apply_with_host(&execution_profile, &state, &[body(0x44, vec![spend])])
        .expect("vector seals");
    let decision = &transition.decisions()[0];
    assert_eq!(
        frozen_template
            .template_hash()
            .expect("template hash")
            .to_string(),
        "9cba7b14f21829dc6295cd0b57d496c4cfc8bb435bc2bad795800758476864e0"
    );
    assert_eq!(
        execution_profile
            .execution_profile()
            .chain_domain()
            .to_string(),
        "9ef2be84fe60582a5431680ebbe5825df7ab7031c1b82a1e8a96e842fd09a1b0"
    );
    assert_eq!(
        execution_profile
            .execution_profile()
            .profile_domain()
            .to_string(),
        "4201ce445e3db11327150e6ca2476662ff05df8ccb09ae08a2d11159860ceefd"
    );
    assert_eq!(
        state.checkpoint_id().to_string(),
        "b1a38d324fa712b3f103287dc93010311261ad789a4812281e1103ea056ab426"
    );
    assert_eq!(
        state
            .state_digest()
            .expect("genesis state digest")
            .to_string(),
        "2ef63d7ade7771bb0e8463a5fe81d9eb17f8c9edf152830a53da8bbdd319ca49"
    );
    assert_eq!(decision.position, 0);
    assert_eq!(decision.body_id, VertexId::from_bytes([0x44; 32]));
    assert_eq!(decision.body_position, 0);
    assert_eq!(decision.transaction_position, 0);
    assert_eq!(decision.outcome, Outcome::Accepted);
    assert_eq!(
        transition.next().body_bindings_in_checkpoint()[0].to_string(),
        "3f7e4efa275e193e3613a689415c57ef4a7105b448bdb091317d7ab2f339e090"
    );
    assert_eq!(
        transition.next().checkpoint_id().to_string(),
        "d73b26259bf405c261259122a629e4c055bc880d3aed55d5f3a824cf7594f489"
    );
    assert_eq!(
        transition
            .next()
            .state_digest()
            .expect("state digest")
            .to_string(),
        "49bbfe1b60098bb2976668b7d8b93303c92ad81b2d60a491b19b99352fd63639"
    );
    assert_eq!(
        decision.intent_id.to_string(),
        "ce73e74df2f2f9da871918301b6738250e1b71e2fd83ff0b156e7e4aa2c2da69"
    );
    assert_eq!(
        decision.instance_hash.to_string(),
        "9c97d7de40f54188522fa6fa12473373eb57eead88ecc64f156a0deb8eb09245"
    );
}
