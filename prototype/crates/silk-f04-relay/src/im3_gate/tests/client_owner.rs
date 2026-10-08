//! Focused one-client fixture: reused genuine B proof, exactly ONE new C proof.
//! Historical monotonic mapping is administrative, not qualified UTC/custody.
use super::*;
use crate::{
    frame::Payload,
    im3_schedule::{Im3Schedule, Phase},
    negotiation::SelectedCut,
    schedule::QualifiedClockSample,
};
use silk_f04_node::genesis::Genesis;
use silk_sapling_f04::codec::EnvelopeView;
use std::time::UNIX_EPOCH;

fn mapping(c: &MiddleContext<'_>, lead: Duration) -> Im3Schedule {
    Im3Schedule::new(
        c.r2.round.config,
        c.r2.round.manifest.round(),
        QualifiedClockSample::from_qualified_source(
            UNIX_EPOCH + Duration::from_secs(c.r2.round.manifest.round() * 30) - lead,
            Instant::now(),
            Duration::ZERO,
        )
        .unwrap(),
    )
    .unwrap()
}
fn b_output(cell: &[u8; 4096]) -> ClientProofOutput {
    ClientProofOutput {
        nullifier: cell[128..160].try_into().unwrap(),
        proof: cell[160..416].try_into().unwrap(),
    }
}
#[allow(clippy::too_many_arguments)]
pub(super) fn run(
    c: &MiddleContext<'_>,
    root: &Path,
    out: &Path,
    a: &HpkePrivate,
    b: &HpkePrivate,
    middle: &HpkePrivate,
    verifier: &PreparedProofVerifier,
    cell: &[u8; 4096],
    envelope: &[u8],
) -> serde_json::Value {
    let genesis = Genesis::admit_local_bundle(
        &fs::read(root.join("public-genesis")).unwrap(),
        &c.r2.round.config.domain(),
        true,
    )
    .unwrap();
    let round = c.r2.round.manifest.round();
    let names = [
        "happy",
        "duplicate_b",
        "c_before_b",
        "bad_b",
        "late_b",
        "bad_c",
        "duplicate_c",
        "late_c",
        "duplicate_freeze",
    ];
    let mut stores = Vec::new();
    for name in names {
        directory(&out.join(name));
        stores.push(
            PreparedScopeStore::create(
                &out.join(name),
                c.profile.claim_binding(ClaimRole::Client),
                FilePins(out.join(format!("{name}.pin"))),
            )
            .unwrap(),
        );
    }
    let schedule = mapping(c, Duration::from_millis(5400));
    let mut owners = Vec::new();
    for store in &mut stores {
        owners.push(Some(
            PreparedClientOwner::admit(
                c,
                &schedule,
                SelectedCut::from_genesis(&genesis, c.r2.round.config, round).unwrap(),
                verifier,
                store,
                Payload::real_view(
                    &EnvelopeView::decode(envelope, &c.r2.round.config.domain()).unwrap(),
                    &c.r2.round,
                )
                .unwrap(),
            )
            .unwrap(),
        ));
    }
    // No real proof dispatch is possible before durable freeze; this case stops.
    let early_path = out.join("before_freeze");
    directory(&early_path);
    let mut early_store = PreparedScopeStore::create(
        &early_path,
        c.profile.claim_binding(ClaimRole::Client),
        Pins::default(),
    )
    .unwrap();
    let mut early = PreparedClientOwner::admit(
        c,
        &schedule,
        SelectedCut::from_genesis(&genesis, c.r2.round.config, round).unwrap(),
        verifier,
        &mut early_store,
        Payload::cover(),
    )
    .unwrap();
    assert!(early.take_b_job().is_err());
    assert!(early.freeze().is_err());
    drop(early);
    assert_eq!(fs::read(early_path.join("CURRENT")).unwrap()[9], 0);

    sleep_until(schedule.window(Phase::ClientChoice).unwrap().0 + Duration::from_millis(5));
    let msg = c.r2.check_cell(cell).unwrap();
    let expected_choice = domain_hash(
        "SilkNode-IM3-client-choice",
        &[&c.q.id(), &c.r2.round.manifest.id(), &msg],
    );
    for (name, owner) in names.iter().zip(&mut owners) {
        owner.as_mut().unwrap().freeze().unwrap();
        let snapshot = fs::read(out.join(name).join("CURRENT")).unwrap();
        assert_eq!(&snapshot[160..192], &c.r2.round.manifest.id());
        assert_eq!(&snapshot[192..224], &expected_choice);
        assert_ne!(expected_choice, msg); // not the old Bmsg-only claim
    }
    assert!(owners[8].as_mut().unwrap().freeze().is_err());
    assert!(owners[8].as_mut().unwrap().take_b_job().is_err());
    sleep_until(schedule.window(Phase::BProof).unwrap().0 + Duration::from_millis(5));
    for i in 0..8 {
        if i == 2 {
            assert!(owners[i].as_mut().unwrap().take_c_job().is_err());
            assert!(owners[i].as_mut().unwrap().take_b_job().is_err());
            continue;
        }
        let job = owners[i].as_mut().unwrap().take_b_job().unwrap();
        assert_eq!(job.statement[1], msg);
        assert_eq!(job.deadline, schedule.window(Phase::BProof).unwrap().1);
        if i == 1 {
            assert!(owners[i].as_mut().unwrap().take_b_job().is_err());
        } else if i == 3 {
            let mut output = b_output(cell);
            output.proof[0] ^= 1;
            assert!(owners[i].as_mut().unwrap().complete_b(output).is_err());
            assert!(
                owners[i]
                    .as_mut()
                    .unwrap()
                    .complete_b(b_output(cell))
                    .is_err()
            );
        } else if i != 4 {
            owners[i]
                .as_mut()
                .unwrap()
                .complete_b(b_output(cell))
                .unwrap();
        }
    }
    sleep_until(schedule.window(Phase::BSeal).unwrap().0 + Duration::from_millis(5));
    assert!(
        owners[4]
            .as_mut()
            .unwrap()
            .complete_b(b_output(cell))
            .is_err()
    );
    assert!(owners[4].as_mut().unwrap().seal_b().is_err());
    for i in [0, 5, 6, 7] {
        owners[i].as_mut().unwrap().seal_b().unwrap();
    }
    sleep_until(schedule.window(Phase::CProof).unwrap().0 + Duration::from_millis(5));
    for i in [0, 5, 6, 7] {
        let job = owners[i].as_mut().unwrap().take_c_job().unwrap();
        assert_ne!(job.statement[1], msg);
        assert_eq!(job.deadline, schedule.window(Phase::CProof).unwrap().1);
        if i == 0 {
            save(
                &out.join("statements.json"),
                &serde_json::to_vec(&vec![job.statement.map(|x| text(&x))]).unwrap(),
            );
        }
        if i == 6 {
            assert!(owners[i].as_mut().unwrap().take_c_job().is_err());
        }
    }
    // Authentic old C proof is not valid for a fresh random B ciphertext.
    let old: Vec<serde_json::Value> = serde_json::from_slice(
        &fs::read(
            PathBuf::from(std::env::var_os("SILK_IM3_GATE_REUSE").unwrap())
                .join("middle-proofs.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let old_output = || ClientProofOutput {
        nullifier: hex(old[0]["nullifier"].as_str().unwrap()).unwrap(),
        proof: hex(old[0]["proof"].as_str().unwrap()).unwrap(),
    };
    assert!(
        owners[5]
            .as_mut()
            .unwrap()
            .complete_c(old_output())
            .is_err()
    );
    assert!(owners[5].as_mut().unwrap().seal_onion().is_err());
    let start = Instant::now();
    let status = Command::new(std::env::var_os("SILK_IM3_NODE_BINARY").expect("explicit proof-helper Node binary"))
        .arg(std::env::var_os("SILK_IM3_PROOF_HELPER").unwrap())
        .arg(root)
        .arg(out)
        .arg("one-client")
        .env("UV_THREADPOOL_SIZE", "1")
        .status()
        .unwrap();
    assert!(status.success());
    assert!(start.elapsed() < Duration::from_secs(5));
    let proofs: Vec<serde_json::Value> =
        serde_json::from_slice(&fs::read(out.join("middle-proofs.json")).unwrap()).unwrap();
    assert_eq!(proofs.len(), 1);
    let proof_output = || ClientProofOutput {
        nullifier: hex(proofs[0]["nullifier"].as_str().unwrap()).unwrap(),
        proof: hex(proofs[0]["proof"].as_str().unwrap()).unwrap(),
    };
    owners[0]
        .as_mut()
        .unwrap()
        .complete_c(proof_output())
        .unwrap();
    sleep_until(schedule.window(Phase::Onion).unwrap().0 + Duration::from_millis(5));
    assert!(
        owners[7]
            .as_mut()
            .unwrap()
            .complete_c(proof_output())
            .is_err()
    );
    assert!(owners[7].as_mut().unwrap().seal_onion().is_err());
    owners[0].as_mut().unwrap().seal_onion().unwrap();
    let onion = owners[0].take().unwrap().into_onion().unwrap();
    let stage2 = open_at_a(c, a, &onion).unwrap();
    let plain = middle_plain(c, middle, &stage2);
    let recovered = open(c, 3, c.r2.round.config.hpke_keys()[1], b, &plain[416..4560]).unwrap();
    assert_eq!(recovered.as_slice(), cell);
    assert_eq!(&recovered[416..3206], envelope);
    save(&out.join("client-onion.bin"), onion.bytes());
    drop(owners);
    for store in &mut stores {
        assert!(store.consume(round, [7; 32], [8; 32]).is_err()); // changed M/Q/payment cannot reopen
    }
    drop(stores);
    for name in names {
        let pin: Digest = fs::read(out.join(format!("{name}.pin")))
            .unwrap()
            .try_into()
            .unwrap();
        let mut reopened = PreparedScopeStore::open(
            &out.join(name),
            c.profile.claim_binding(ClaimRole::Client),
            pin,
            round,
            FilePins(out.join(format!("{name}.pin"))),
        )
        .unwrap();
        assert!(reopened.consume(round, [9; 32], [10; 32]).is_err());
    }
    // A late manifest admission cannot even reach durable freeze.
    let late = mapping(c, Duration::from_millis(4900));
    let late_path = out.join("late_manifest");
    directory(&late_path);
    let mut late_store = PreparedScopeStore::create(
        &late_path,
        c.profile.claim_binding(ClaimRole::Client),
        Pins::default(),
    )
    .unwrap();
    assert!(
        PreparedClientOwner::admit(
            c,
            &late,
            SelectedCut::from_genesis(&genesis, c.r2.round.config, round).unwrap(),
            verifier,
            &mut late_store,
            Payload::cover()
        )
        .is_err()
    );
    assert_eq!(fs::read(late_path.join("CURRENT")).unwrap()[9], 0);
    additional_refusals(c, &genesis, verifier, out);
    json!({"status":"PASS_IM3_ONE_SHOT_CLIENT_PREPARATION", "genuine_B_proofs_reused":1, "new_C_proofs":1,
        "durable_choice_binds_Q_M_Bmsg":true, "exact_original_B_cell_and_envelope_recovered":true,
        "same_round_live_and_cold_replay_refused":9, "refused":["before_freeze","duplicate_freeze","duplicate_B_dispatch","C_before_B","bad_B_proof","late_B_proof","C_proof_for_other_ciphertext","duplicate_C_dispatch","late_C_proof","late_manifest","foreign_local_cut","pin_retention_failure","sticky_clock_failure"],
        "clock_qualified":false,"worker_containment_proved":false,"client_TLS_integrated":false,"node_settlement_tested":false})
}

fn additional_refusals(
    c: &MiddleContext<'_>,
    genesis: &Genesis,
    verifier: &PreparedProofVerifier,
    out: &Path,
) {
    let round = c.r2.round.manifest.round();
    let schedule = mapping(c, Duration::from_millis(5400));
    let foreign_path = out.join("foreign_cut");
    directory(&foreign_path);
    let mut foreign_store = PreparedScopeStore::create(
        &foreign_path,
        c.profile.claim_binding(ClaimRole::Client),
        Pins::default(),
    )
    .unwrap();
    assert!(
        PreparedClientOwner::admit(
            c,
            &schedule,
            SelectedCut::from_genesis(genesis, c.r2.round.config, round + 2).unwrap(),
            verifier,
            &mut foreign_store,
            Payload::cover()
        )
        .is_err()
    );
    assert_eq!(fs::read(foreign_path.join("CURRENT")).unwrap()[9], 0);

    let clock_path = out.join("clock_failure");
    directory(&clock_path);
    let mut clock_store = PreparedScopeStore::create(
        &clock_path,
        c.profile.claim_binding(ClaimRole::Client),
        FilePins(out.join("clock_failure.pin")),
    )
    .unwrap();
    let mut clock_owner = PreparedClientOwner::admit(
        c,
        &schedule,
        SelectedCut::from_genesis(genesis, c.r2.round.config, round).unwrap(),
        verifier,
        &mut clock_store,
        Payload::cover(),
    )
    .unwrap();
    let pin_path = out.join("pin_failure");
    directory(&pin_path);
    let pins = Pins::default();
    let mut pin_store = PreparedScopeStore::create(
        &pin_path,
        c.profile.claim_binding(ClaimRole::Client),
        pins.clone(),
    )
    .unwrap();
    let old_pin = pins.0.lock().unwrap().0;
    let mut pin_owner = PreparedClientOwner::admit(
        c,
        &schedule,
        SelectedCut::from_genesis(genesis, c.r2.round.config, round).unwrap(),
        verifier,
        &mut pin_store,
        Payload::cover(),
    )
    .unwrap();
    pins.0.lock().unwrap().1 = true;
    sleep_until(schedule.window(Phase::ClientChoice).unwrap().0 + Duration::from_millis(5));
    assert!(pin_owner.freeze().is_err());
    assert!(pin_owner.take_b_job().is_err());
    drop(pin_owner);
    drop(pin_store);
    assert!(
        PreparedScopeStore::open(
            &pin_path,
            c.profile.claim_binding(ClaimRole::Client),
            old_pin,
            round,
            pins
        )
        .is_err()
    );
    clock_owner.freeze().unwrap();
    let bad_sample = QualifiedClockSample::from_qualified_source(
        UNIX_EPOCH + Duration::from_secs(round * 30),
        Instant::now(),
        Duration::ZERO,
    )
    .unwrap();
    assert!(schedule.observe_clock(&bad_sample).is_err());
    assert!(clock_owner.take_b_job().is_err());
    assert!(clock_owner.freeze().is_err());
    assert!(schedule.observe_clock(&bad_sample).is_err());
    drop(clock_owner);
    assert!(clock_store.consume(round, [8; 32], [9; 32]).is_err());
}
