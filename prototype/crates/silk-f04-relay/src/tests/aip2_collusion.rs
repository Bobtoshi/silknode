//! Adversarial trace for the current two-relay R2 construction.
//! This is a counterexample, not privacy acceptance or an operational fixture.
use crate::{
    aip2_claim::{ClaimPinRetention, ClaimResult, ClaimRole, PreparedScopeStore},
    aip2_profile::{PreparedProfile, ProfileExpectations},
    aip2_proof::{hex, prepare_cover_statement, semaphore_scalar},
    aip2_transport::{
        PreparedR2Context, PreparedR2Frame, colluding_b_observation, open_a, permute_at_a,
        seal_claimed_cell,
    },
    config::SignedConfig,
    frame::HpkePrivate,
    manifest::SignedManifest,
};
use hpke::Deserializable;
use serde_json::json;
use silk_sapling_f04::codec::domain_hash;
use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

struct Pins(PathBuf);
impl ClaimPinRetention for Pins {
    fn retain_claim_pin(&mut self, pin: [u8; 32]) -> ClaimResult<()> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&self.0)?;
        f.write_all(&pin)?;
        f.sync_all()?;
        Ok(())
    }
}

fn read(path: &Path, exact: usize) -> Vec<u8> {
    let meta = fs::symlink_metadata(path).expect("attack artefact metadata");
    assert!(meta.is_file());
    assert_eq!(usize::try_from(meta.len()).unwrap(), exact);
    fs::read(path).expect("attack artefact read")
}

fn text(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn cell_message(cell: &[u8; 4096]) -> [u8; 32] {
    semaphore_scalar(&domain_hash(
        "SilkNode-AIP2R2-message",
        &[&cell[..128], &cell[416..]],
    ))
}

#[test]
#[ignore = "requires preserved genuine private R2 settlement artefacts"]
fn colluding_a_b_join_source_slot_to_genuine_payment_after_permutation() {
    let root = PathBuf::from(std::env::var_os("SILK_R2_COLLUSION_ROOT").expect("input root"));
    let out = PathBuf::from(std::env::var_os("SILK_R2_COLLUSION_OUT").expect("output root"));
    fs::create_dir(&out).expect("new output root");
    fs::set_permissions(&out, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(out.join("owner")).unwrap();
    fs::set_permissions(out.join("owner"), fs::Permissions::from_mode(0o700)).unwrap();

    let expected: serde_json::Value =
        serde_json::from_slice(&read(&root.join("expected.json"), 523)).unwrap();
    assert_eq!(expected["actual_tls_inputs"], true);
    let domain = hex(expected["domain"].as_str().unwrap()).unwrap();
    let epoch = u32::try_from(expected["epoch"].as_u64().unwrap()).unwrap();
    let round = expected["round"].as_u64().unwrap();
    let role_keys = [
        hex(expected["role_keys"][0].as_str().unwrap()).unwrap(),
        hex(expected["role_keys"][1].as_str().unwrap()).unwrap(),
    ];
    let vk_hash = hex(expected["vk_hash"].as_str().unwrap()).unwrap();
    let config = SignedConfig::verify(
        &read(&root.join("config.bin"), 770),
        domain,
        7,
        epoch,
        role_keys,
    )
    .unwrap();
    let manifest = SignedManifest::verify(
        &read(&root.join("manifest.bin"), 256),
        &config,
        round,
    )
    .unwrap();
    let profile = PreparedProfile::verify(
        &read(&root.join("profile.bin"), 1312),
        &ProfileExpectations {
            domain,
            config: config.id(),
            epoch,
            cohort: 7,
            vk_hash,
            role_keys,
        },
    )
    .unwrap();
    let context = PreparedR2Context::new(&config, &manifest, &profile, vk_hash).unwrap();
    let a = HpkePrivate::from_bytes(&[71; 32]).unwrap();
    let b = HpkePrivate::from_bytes(&[72; 32]).unwrap();

    // Use the genuine wallet-produced envelope, but an attack-only consumed
    // client claim. Membership validity is intentionally irrelevant: the join
    // happens before B's proof gate and uses only unchanged ciphertext bytes.
    let envelope = read(&root.join("envelope.bin"), 2790);
    let mut payment_cell = *prepare_cover_statement(&profile, manifest.id(), round)
        .unwrap()
        .cell();
    payment_cell[8] = 1;
    payment_cell[416..3206].copy_from_slice(&envelope);
    let payment_message = cell_message(&payment_cell);
    let mut owner = PreparedScopeStore::create(
        &out.join("owner"),
        profile.claim_binding(ClaimRole::Client),
        Pins(out.join("owner.pin")),
    )
    .unwrap();
    let payment_stage1 = seal_claimed_cell(
        &context,
        owner
            .consume(round, manifest.id(), payment_message)
            .unwrap(),
        &payment_cell,
    )
    .unwrap();
    let payment_outer = payment_stage1.encapsulation();

    let covers = read(&root.join("prepared-cover-stage1.bin"), 31 * 8192);
    let mut stage2 = Vec::with_capacity(32);
    stage2.push(open_a(&context, &a, &payment_stage1).unwrap());
    for bytes in covers.chunks_exact(8192) {
        let stage1 = PreparedR2Frame::decode(bytes, &context, 1).unwrap();
        stage2.push(open_a(&context, &a, &stage1).unwrap());
    }
    let mut stage2: [PreparedR2Frame; 32] = stage2.try_into().ok().unwrap();
    let payment_inner = stage2[0].encapsulation();
    assert_eq!(
        stage2
            .iter()
            .filter(|frame| frame.encapsulation() == payment_inner)
            .count(),
        1
    );

    permute_at_a(&context, &mut stage2).unwrap();
    let b_index = stage2
        .iter()
        .position(|frame| frame.encapsulation() == payment_inner)
        .expect("unchanged payment encapsulation after A permutation");
    let (kind, observed_envelope) = colluding_b_observation(&context, &b, &stage2[b_index]).unwrap();
    let expected_envelope = domain_hash("SilkNode-AIP2R2-observed-envelope", &[&envelope]);
    assert_eq!(kind, 1);
    assert_eq!(observed_envelope, expected_envelope);

    // Honest code rejects a same-round replay/duplicate. That gate does not
    // erase the stable identifier from a malicious relay's transcript.
    let duplicate = PreparedR2Frame::decode(stage2[b_index].bytes(), &context, 2).unwrap();
    stage2[(b_index + 1) % 32] = duplicate;
    assert!(permute_at_a(&context, &mut stage2).is_err());

    let receipt = json!({
        "status": "COUNTEREXAMPLE_CONFIRMED",
        "security_property": "sender_to_payment_unlinkability_against_colluding_A_and_B",
        "property_holds": false,
        "actual_tls_input_path_previously_exercised": true,
        "genuine_wallet_envelope": true,
        "membership_acceptance": false,
        "source_slot_observed_by_A": 0,
        "payment_index_observed_by_B_after_A_permutation": b_index,
        "outer_encapsulation_observed_at_source": text(&payment_outer),
        "unchanged_inner_encapsulation_join_key": text(&payment_inner),
        "observed_payment_envelope_digest": text(&observed_envelope),
        "expected_payment_envelope_digest": text(&expected_envelope),
        "exact_join_matches": 1,
        "honest_duplicate_replay_gate_refused": true,
        "counterexample": "A records source slot to opened inner encapsulation; B records the same encapsulation to decrypted payment. A permutation preserves the join key.",
        "required_fix_class": "an independently operated middle hop that replaces the observable ciphertext relation before the final decryptor, plus omission and transcript-consistency accountability"
    });
    let receipt_path = out.join("counterexample.json");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&receipt_path)
        .unwrap();
    file.write_all(&serde_json::to_vec_pretty(&receipt).unwrap()).unwrap();
    file.sync_all().unwrap();
    println!("{}", serde_json::to_string(&receipt).unwrap());
}
