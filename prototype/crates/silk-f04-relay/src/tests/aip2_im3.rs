//! Genuine-envelope adversarial fixture for the additive IM3 correction.
//! It establishes removal of the exact R2 tag join, not total anonymity.
use crate::{
    aip2_claim::{ClaimPinRetention, ClaimResult, ClaimRole, PreparedScopeStore},
    aip2_im3::{
        IM3_ROUTE_BYTES, Im3RouteExpectations, PreparedIm3Context, PreparedIm3Frame,
        PreparedIm3Route, open_at_a, open_at_b_for_test, open_at_middle, permute_at_a,
        permute_at_middle, seal_claimed_cell,
    },
    aip2_profile::{PreparedProfile, ProfileExpectations},
    aip2_proof::{hex, prepare_cover_statement, semaphore_scalar},
    config::SignedConfig,
    frame::HpkePrivate,
    manifest::SignedManifest,
};
use ed25519_dalek::SigningKey;
use hpke::{Deserializable, Kem, Serializable, kem::X25519HkdfSha256};
use serde_json::json;
use silk_f04_node::auth::sign_role;
use silk_sapling_f04::codec::domain_hash;
use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

struct Pins(PathBuf);
impl ClaimPinRetention for Pins {
    fn retain_claim_pin(&mut self, pin: [u8; 32]) -> ClaimResult<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&self.0)?;
        file.write_all(&pin)?;
        file.sync_all()?;
        Ok(())
    }
}

fn read_exact(path: &Path, length: usize) -> Vec<u8> {
    let metadata = fs::symlink_metadata(path).expect("IM3 artefact metadata");
    assert!(metadata.is_file());
    assert_eq!(usize::try_from(metadata.len()).unwrap(), length);
    fs::read(path).expect("IM3 artefact read")
}

fn directory(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
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

fn route_bytes(
    config: &SignedConfig,
    profile: &PreparedProfile,
    middle_signing: [u8; 32],
    middle_hpke: [u8; 32],
) -> [u8; IM3_ROUTE_BYTES] {
    let mut route = [0; IM3_ROUTE_BYTES];
    route[..8].copy_from_slice(b"SNIM3R01");
    route[8..40].copy_from_slice(&config.domain());
    route[40..72].copy_from_slice(&config.id());
    route[72..104].copy_from_slice(&profile.id());
    route[104..108].copy_from_slice(&config.epoch().to_le_bytes());
    route[108..112].copy_from_slice(&config.cohort().to_le_bytes());
    route[112..144].copy_from_slice(&middle_signing);
    route[144..176].copy_from_slice(&middle_hpke);
    let label = b"SilkNode-AIP2IM3-route-sign";
    let mut signed = vec![u8::try_from(label.len()).unwrap()];
    signed.extend_from_slice(label);
    signed.extend_from_slice(&route[..192]);
    for (offset, seed) in [(192, 11), (256, 12), (320, 16)] {
        route[offset..offset + 64]
            .copy_from_slice(&sign_role(&SigningKey::from_bytes(&[seed; 32]), &signed).unwrap());
    }
    route
}

#[test]
#[ignore = "requires preserved genuine private R2 settlement artefacts"]
fn im3_removes_exact_a_b_tag_join_with_independent_middle() {
    let root = PathBuf::from(std::env::var_os("SILK_IM3_ROOT").expect("input root"));
    let out = PathBuf::from(std::env::var_os("SILK_IM3_OUT").expect("output root"));
    directory(&out);

    let expected: serde_json::Value =
        serde_json::from_slice(&read_exact(&root.join("expected.json"), 523)).unwrap();
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
        &read_exact(&root.join("config.bin"), 770),
        domain,
        7,
        epoch,
        role_keys,
    )
    .unwrap();
    let manifest = SignedManifest::verify(
        &read_exact(&root.join("manifest.bin"), 256),
        &config,
        round,
    )
    .unwrap();
    let profile = PreparedProfile::verify(
        &read_exact(&root.join("profile.bin"), 1312),
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
    let a = HpkePrivate::from_bytes(&[71; 32]).unwrap();
    let b = HpkePrivate::from_bytes(&[72; 32]).unwrap();
    let middle = HpkePrivate::from_bytes(&[73; 32]).unwrap();
    let middle_hpke: [u8; 32] = X25519HkdfSha256::sk_to_pk(&middle)
        .to_bytes()
        .as_slice()
        .try_into()
        .unwrap();
    let middle_signing = SigningKey::from_bytes(&[16; 32])
        .verifying_key()
        .to_bytes();
    let route_expectations = Im3RouteExpectations {
        middle_signing,
        middle_hpke,
    };
    let route_wire = route_bytes(&config, &profile, middle_signing, middle_hpke);
    let route = PreparedIm3Route::verify(
        &route_wire,
        &config,
        &profile,
        &route_expectations,
    )
    .unwrap();
    let context =
        PreparedIm3Context::new(&config, &manifest, &profile, vk_hash, &route).unwrap();

    let mut wrong_signature = route_wire;
    wrong_signature[320] ^= 1;
    assert!(
        PreparedIm3Route::verify(
            &wrong_signature,
            &config,
            &profile,
            &route_expectations
        )
        .is_err()
    );
    let wrong_pin = Im3RouteExpectations {
        middle_signing,
        middle_hpke: [99; 32],
    };
    assert!(PreparedIm3Route::verify(&route_wire, &config, &profile, &wrong_pin).is_err());

    let envelope = read_exact(&root.join("envelope.bin"), 2790);
    let mut cells = Vec::with_capacity(32);
    let mut payment = *prepare_cover_statement(&profile, manifest.id(), round)
        .unwrap()
        .cell();
    payment[8] = 1;
    payment[416..3206].copy_from_slice(&envelope);
    cells.push(payment);
    let cover_json: Vec<String> =
        serde_json::from_slice(&read_exact(&root.join("cells.json"), 254046)).unwrap();
    assert_eq!(cover_json.len(), 31);
    for encoded in cover_json {
        cells.push(hex::<4096>(&encoded).unwrap());
    }

    let mut stage1 = Vec::with_capacity(32);
    for (slot, cell) in cells.iter().enumerate() {
        let owner_path = out.join(format!("owner-{slot:02}"));
        directory(&owner_path);
        let mut owner = PreparedScopeStore::create(
            &owner_path,
            profile.claim_binding(ClaimRole::Client),
            Pins(out.join(format!("owner-{slot:02}.pin"))),
        )
        .unwrap();
        stage1.push(
            seal_claimed_cell(
                &context,
                owner
                    .consume(round, manifest.id(), cell_message(cell))
                    .unwrap(),
                cell,
            )
            .unwrap(),
        );
    }

    let mut altered = *stage1[0].bytes();
    altered[100] ^= 1;
    let altered = PreparedIm3Frame::decode(&altered, &context, 1).unwrap();
    assert!(open_at_a(&context, &a, &altered).is_err());

    let mut after_a: [PreparedIm3Frame; 32] = stage1
        .iter()
        .map(|frame| open_at_a(&context, &a, frame).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .ok()
        .unwrap();
    let a_payment_tag = after_a[0].encapsulation();
    let a_tags: BTreeSet<_> = after_a.iter().map(PreparedIm3Frame::encapsulation).collect();
    assert_eq!(a_tags.len(), 32);

    let mut duplicate_after_a: [PreparedIm3Frame; 32] = after_a
        .iter()
        .map(|frame| PreparedIm3Frame::decode(frame.bytes(), &context, 2).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .ok()
        .unwrap();
    duplicate_after_a[31] =
        PreparedIm3Frame::decode(duplicate_after_a[0].bytes(), &context, 2).unwrap();
    assert!(permute_at_a(&context, &mut duplicate_after_a).is_err());

    permute_at_a(&context, &mut after_a).unwrap();
    let mut altered = *after_a[0].bytes();
    altered[100] ^= 1;
    let altered = PreparedIm3Frame::decode(&altered, &context, 2).unwrap();
    assert!(open_at_middle(&context, &middle, &altered).is_err());

    let mut after_middle: [PreparedIm3Frame; 32] = after_a
        .iter()
        .map(|frame| open_at_middle(&context, &middle, frame).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .ok()
        .unwrap();
    let b_tags: BTreeSet<_> = after_middle
        .iter()
        .map(PreparedIm3Frame::encapsulation)
        .collect();
    assert_eq!(b_tags.len(), 32);
    assert!(a_tags.is_disjoint(&b_tags));
    assert!(!b_tags.contains(&a_payment_tag));

    let mut duplicate_at_b: [PreparedIm3Frame; 32] = after_middle
        .iter()
        .map(|frame| PreparedIm3Frame::decode(frame.bytes(), &context, 3).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .ok()
        .unwrap();
    duplicate_at_b[31] =
        PreparedIm3Frame::decode(duplicate_at_b[0].bytes(), &context, 3).unwrap();
    assert!(permute_at_middle(&context, &mut duplicate_at_b).is_err());

    permute_at_middle(&context, &mut after_middle).unwrap();
    let expected_envelope = domain_hash("SilkNode-AIP2IM3-observed-envelope", &[&envelope]);
    let mut payment_index = None;
    for (index, frame) in after_middle.iter().enumerate() {
        let opened = open_at_b_for_test(&context, &b, frame).unwrap();
        if opened[8] == 1 {
            assert!(payment_index.replace(index).is_none());
            assert_eq!(
                domain_hash("SilkNode-AIP2IM3-observed-envelope", &[&opened[416..3206]]),
                expected_envelope
            );
        }
    }
    let payment_index = payment_index.expect("one genuine envelope");

    let receipt = json!({
        "status": "PASS_REMOVES_EXACT_R2_STABLE_TAG_UNDER_HONEST_MIDDLE_ONLY",
        "genuine_wallet_envelope": true,
        "membership_acceptance": false,
        "anonymity_acceptance": false,
        "source_to_payment_unlinkability_proven": false,
        "independent_middle_required": true,
        "middle_independence_proven_by_fixture": false,
        "malicious_omission_accountability": false,
        "source_slot": 0,
        "payment_index_after_middle_permutation": payment_index,
        "a_visible_middle_tag": text(&a_payment_tag),
        "a_visible_tag_count": a_tags.len(),
        "b_visible_tag_count": b_tags.len(),
        "a_b_exact_tag_intersection": a_tags.intersection(&b_tags).count(),
        "observed_payment_envelope_digest": text(&expected_envelope),
        "route_id": text(&route.id()),
        "authenticated_outer_tamper_refused": true,
        "authenticated_middle_tamper_refused": true,
        "duplicate_replay_refused_at_a_and_middle": true,
        "remaining_blocker": "a malicious relay can still omit or replace an admitted client without a verifiable shuffle/inclusion mechanism"
    });
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(out.join("im3-result.json"))
        .unwrap();
    file.write_all(&serde_json::to_vec_pretty(&receipt).unwrap())
        .unwrap();
    file.sync_all().unwrap();
    println!("{}", serde_json::to_string(&receipt).unwrap());
}
