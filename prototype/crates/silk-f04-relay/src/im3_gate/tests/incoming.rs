//! Multiplexed administrative incoming-link fault fixture, not role/cap qualification.
use super::*;
use crate::{
    config::Endpoint,
    tls::{SetupStep, WireObservation},
};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use std::net::{Ipv6Addr, SocketAddr, TcpListener, TcpStream};

pub(super) fn cancel_failure(c: &MiddleContext<'_>, root: &Path, out: &Path) -> serde_json::Value {
    let tls = PathBuf::from(std::env::var_os("SILK_IM3_C_TLS").unwrap());
    let (mut a, mut c_rx) = pairs(
        c.q.endpoint(),
        &root.join("tls/root.der"),
        &tls.join("c.der"),
        &tls.join("c-key.der"),
        1,
    )
    .pop()
    .unwrap();
    let (mut c_tx, mut b_rx) = pairs(
        c.r2.round.config.endpoints()[1],
        &root.join("tls/root.der"),
        &root.join("tls/leaf-1.der"),
        &root.join("tls/leaf-1-key.der"),
        1,
    )
    .pop()
    .unwrap();
    let (mut fragment_tx, mut fragment_rx): (Vec<_>, Vec<_>) = pairs(
        c.r2.round.config.endpoints()[1],
        &root.join("tls/root.der"),
        &root.join("tls/leaf-1.der"),
        &root.join("tls/leaf-1-key.der"),
        4,
    )
    .into_iter()
    .unzip();
    let round = c.r2.round.manifest.round();
    let now = Instant::now();
    let sample = crate::schedule::QualifiedClockSample::from_qualified_source(
        std::time::UNIX_EPOCH + Duration::from_secs(round * 30) - Duration::from_secs(11),
        now,
        Duration::ZERO,
    )
    .unwrap();
    let schedule = Im3Schedule::new(c.r2.round.config, round, sample).unwrap();
    let guard = Im3Guard::arm(&schedule).unwrap();
    let cp = out.join("C");
    let bp = out.join("B");
    directory(&cp);
    directory(&bp);
    let mut cs =
        PreparedScopeStore::create(&cp, c.claim_binding(), FilePins(out.join("C.pin"))).unwrap();
    let mut bs = PreparedScopeStore::create(
        &bp,
        c.profile.claim_binding(ClaimRole::Exit),
        FilePins(out.join("B.pin")),
    )
    .unwrap();
    let fragment_paths: Vec<_> = (1..=4)
        .map(|i| {
            let path = out.join(format!("B-fragment-{i}"));
            directory(&path);
            path
        })
        .collect();
    let mut fragment_stores: Vec<_> = fragment_paths
        .iter()
        .enumerate()
        .map(|(i, path)| {
            PreparedScopeStore::create(
                path,
                c.profile.claim_binding(ClaimRole::Exit),
                FilePins(out.join(format!("B-fragment-{}.pin", i + 1))),
            )
            .unwrap()
        })
        .collect();
    let mut c_owner =
        ReceivingMiddleOwner::begin(c, &mut cs, &schedule, &guard, &mut c_rx, &mut c_tx).unwrap();
    let mut b_owner = ReceivingExitOwner::begin(c, &mut bs, &schedule, &guard, &mut b_rx).unwrap();
    let mut fragment_owners: Vec<_> = fragment_stores
        .iter_mut()
        .zip(fragment_rx.iter_mut())
        .map(|(store, rx)| ReceivingExitOwner::begin(c, store, &schedule, &guard, rx).unwrap())
        .collect();
    sleep_until(schedule.at(-8_000_000_000).unwrap());
    assert!(!b_owner.poll().unwrap());
    for owner in &mut fragment_owners {
        assert!(!owner.poll().unwrap());
    }
    sleep_until(schedule.at(17_500_000_000).unwrap());
    assert!(c_owner.poll().is_err());
    assert!(
        !c_owner
            .poll_cancel(&SigningKey::from_bytes(&[16; 32]))
            .unwrap()
    );
    let mut b_cancelled = false;
    while Instant::now() < schedule.at(20_500_000_000).unwrap() {
        if c_owner
            .poll_cancel(&SigningKey::from_bytes(&[16; 32]))
            .unwrap()
        {
            assert!(c_owner.take_wire_observation().is_some());
            break;
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    while Instant::now() < schedule.at(20_500_000_000).unwrap() {
        match b_owner.poll() {
            Err(Error::Unavailable("IM3 C cancelled")) => {
                b_cancelled = true;
                break;
            }
            Ok(false) => std::thread::sleep(Duration::from_micros(100)),
            other => panic!("unexpected B cancel state: {:?}", other.err()),
        }
    }
    assert!(b_cancelled);
    let cancel = super::super::control::sign(
        c,
        Im3Kind::Cancel,
        Im3Role::C,
        [[0; 32]; 7],
        &SigningKey::from_bytes(&[16; 32]),
    )
    .unwrap();
    for (i, tx) in fragment_tx.iter_mut().enumerate() {
        tx.queue(
            RecordSize::Control,
            cancel.bytes(),
            schedule.at(20_500_000_000).unwrap(),
        )
        .unwrap();
        assert_eq!(tx.write_prefix_for_test(i + 1).unwrap(), i + 1);
        assert!(!fragment_owners[i].poll().unwrap());
    }
    for tx in &mut fragment_tx {
        while !tx.write_step().unwrap() {
            assert!(Instant::now() < schedule.at(20_500_000_000).unwrap());
        }
    }
    for owner in &mut fragment_owners {
        loop {
            match owner.poll() {
                Err(Error::Unavailable("IM3 C cancelled")) => break,
                Ok(false) => {
                    assert!(Instant::now() < schedule.at(20_500_000_000).unwrap());
                    std::thread::sleep(Duration::from_micros(100));
                }
                other => panic!("fragmented valid CANCEL not accepted: {:?}", other.err()),
            }
        }
    }
    assert!(
        b_owner
            .verify(
                &HpkePrivate::from_bytes(&[72; 32]).unwrap(),
                &PreparedProofVerifier::from_canonical_vk(
                    &fs::read(root.join("vk-canonical.json")).unwrap(),
                    hex::<32>(
                        serde_json::from_slice::<serde_json::Value>(
                            &fs::read(root.join("expected.json")).unwrap()
                        )
                        .unwrap()["vk_hash"]
                            .as_str()
                            .unwrap()
                    )
                    .unwrap()
                )
                .unwrap(),
                None
            )
            .is_err()
    );
    drop(c_owner);
    drop(fragment_owners);
    drop(cs);
    drop(bs);
    drop(fragment_stores);
    drop(guard);
    for (path, role, pin) in [
        (cp, ClaimRole::Middle, "C.pin"),
        (bp, ClaimRole::Exit, "B.pin"),
    ] {
        let bytes: Digest = fs::read(out.join(pin)).unwrap().try_into().unwrap();
        let mut cold = PreparedScopeStore::open(
            &path,
            c.profile.claim_binding(role),
            bytes,
            round,
            FilePins(out.join(pin)),
        )
        .unwrap();
        assert!(
            cold.consume(round, c.r2.round.manifest.id(), [9; 32])
                .is_err()
        );
    }
    for (i, path) in fragment_paths.iter().enumerate() {
        let pin = out.join(format!("B-fragment-{}.pin", i + 1));
        let bytes: Digest = fs::read(&pin).unwrap().try_into().unwrap();
        let mut cold = PreparedScopeStore::open(
            path,
            c.profile.claim_binding(ClaimRole::Exit),
            bytes,
            round,
            FilePins(pin),
        )
        .unwrap();
        assert!(
            cold.consume(round, c.r2.round.manifest.id(), [9; 32])
                .is_err()
        );
    }
    let _ = a.quarantine();
    json!({"status":"PASS_C_FIXED_WINDOW_CANCEL_B_AUTHENTICATED_REFUSAL",
        "B_output_cells":0,"cold_old_round_refused":6,"fragmented_valid_cancel_headers":4,"new_proofs":0,
        "irreversible_C_disclosure":false,"fixed_window":true})
}

pub(super) fn proof_cancel_failure(
    c: &MiddleContext<'_>,
    root: &Path,
    out: &Path,
    frames: &[MiddleFrame; 32],
    key: &HpkePrivate,
    verifier: &PreparedProofVerifier,
) -> serde_json::Value {
    let tls = PathBuf::from(std::env::var_os("SILK_IM3_C_TLS").unwrap());
    let (mut a, mut c_rx) = pairs(
        c.q.endpoint(),
        &root.join("tls/root.der"),
        &tls.join("c.der"),
        &tls.join("c-key.der"),
        1,
    )
    .pop()
    .unwrap();
    let (mut c_tx, mut b_rx) = pairs(
        c.r2.round.config.endpoints()[1],
        &root.join("tls/root.der"),
        &root.join("tls/leaf-1.der"),
        &root.join("tls/leaf-1-key.der"),
        1,
    )
    .pop()
    .unwrap();
    let mut malformed = copied(c, frames);
    let mut plain = middle_plain(c, key, &malformed[0]);
    plain[160] ^= 1; // Authenticated C frame, invalid genuine proof.
    malformed[0] = rewritten(c, plain.as_ref());
    let round = c.r2.round.manifest.round();
    let sample = crate::schedule::QualifiedClockSample::from_qualified_source(
        std::time::UNIX_EPOCH + Duration::from_secs(round * 30) - Duration::from_secs(11),
        Instant::now(),
        Duration::ZERO,
    )
    .unwrap();
    let schedule = Im3Schedule::new(c.r2.round.config, round, sample).unwrap();
    let guard = Im3Guard::arm(&schedule).unwrap();
    let cp = out.join("C-proof");
    let bp = out.join("B-proof");
    directory(&cp);
    directory(&bp);
    let mut cs =
        PreparedScopeStore::create(&cp, c.claim_binding(), FilePins(out.join("C-proof.pin")))
            .unwrap();
    let mut bs = PreparedScopeStore::create(
        &bp,
        c.profile.claim_binding(ClaimRole::Exit),
        FilePins(out.join("B-proof.pin")),
    )
    .unwrap();
    let mut c_owner =
        ReceivingMiddleOwner::begin(c, &mut cs, &schedule, &guard, &mut c_rx, &mut c_tx).unwrap();
    let mut b_owner = ReceivingExitOwner::begin(c, &mut bs, &schedule, &guard, &mut b_rx).unwrap();
    sleep_until(schedule.at(-8_000_000_000).unwrap());
    assert!(!b_owner.poll().unwrap());
    sleep_until(schedule.at(15_500_000_000).unwrap());
    for (i, frame) in malformed.iter().enumerate() {
        let (start, end) = schedule.relay_slot(false, i as u8).unwrap();
        sleep_until(start);
        a.queue(RecordSize::Cell, frame.bytes(), end).unwrap();
        while !a.write_step().unwrap() {
            assert!(Instant::now() < end);
            c_owner.poll().unwrap();
            std::thread::sleep(Duration::from_micros(100));
        }
        c_owner.poll().unwrap();
    }
    sleep_until(schedule.at(15_750_000_000).unwrap());
    a.queue(
        RecordSize::Control,
        &ready_bytes(c, &malformed),
        schedule.at(16_000_000_000).unwrap(),
    )
    .unwrap();
    while !a.write_step().unwrap() {
        c_owner.poll().unwrap();
        std::thread::sleep(Duration::from_micros(100));
    }
    while !c_owner.poll().unwrap() {
        assert!(Instant::now() < schedule.at(17_500_000_000).unwrap());
        std::thread::sleep(Duration::from_micros(100));
    }
    sleep_until(schedule.at(17_500_000_000).unwrap());
    let (error, mut failed) = match c_owner.verify_or_cancel(key, verifier) {
        Ok(_) => panic!("invalid C proof admitted"),
        Err(v) => v,
    };
    assert!(matches!(error, Error::Invalid("IM3 C membership")));
    assert!(!failed.poll(&SigningKey::from_bytes(&[16; 32])).unwrap());
    while !failed.poll(&SigningKey::from_bytes(&[16; 32])).unwrap() {
        assert!(Instant::now() < schedule.at(20_500_000_000).unwrap());
        std::thread::sleep(Duration::from_micros(100));
    }
    assert!(failed.take_wire_observation().is_some());
    loop {
        match b_owner.poll() {
            Err(Error::Unavailable("IM3 C cancelled")) => break,
            Ok(false) => {
                assert!(Instant::now() < schedule.at(20_500_000_000).unwrap());
                std::thread::sleep(Duration::from_micros(100));
            }
            other => panic!("bad proof B CANCEL: {:?}", other.err()),
        }
    }
    drop(failed);
    drop(b_owner);
    drop(cs);
    drop(bs);
    drop(guard);
    for (path, pin, role) in [
        (cp, "C-proof.pin", ClaimRole::Middle),
        (bp, "B-proof.pin", ClaimRole::Exit),
    ] {
        let bytes: Digest = fs::read(out.join(pin)).unwrap().try_into().unwrap();
        let mut cold = PreparedScopeStore::open(
            &path,
            c.profile.claim_binding(role),
            bytes,
            round,
            FilePins(out.join(pin)),
        )
        .unwrap();
        assert!(
            cold.consume(round, c.r2.round.manifest.id(), [9; 32])
                .is_err()
        );
    }
    let _ = a.quarantine();
    json!({"status":"PASS_BAD_GENUINE_C_PROOF_CANCELS_ORIGINAL_B",
        "authenticated_C_frames":32,"new_proofs":0,"B_output_cells":0,
        "C_disclosure_decided":false,"cold_old_round_refused":2})
}

pub(super) fn ingress_cancel_failure(
    c: &MiddleContext<'_>,
    root: &Path,
    out: &Path,
) -> serde_json::Value {
    let tls = PathBuf::from(std::env::var_os("SILK_IM3_C_TLS").unwrap());
    let (_clients, ingress_inputs): (Vec<_>, Vec<_>) = pairs(
        c.r2.round.config.endpoints()[0],
        &root.join("tls/root.der"),
        &root.join("tls/leaf-0.der"),
        &root.join("tls/leaf-0-key.der"),
        32,
    )
    .into_iter()
    .unzip();
    let mut ingress_inputs: [Transport; 32] = ingress_inputs.try_into().ok().unwrap();
    let (mut a_tx, mut c_rx) = pairs(
        c.q.endpoint(),
        &root.join("tls/root.der"),
        &tls.join("c.der"),
        &tls.join("c-key.der"),
        1,
    )
    .pop()
    .unwrap();
    let (mut c_tx, mut b_rx) = pairs(
        c.r2.round.config.endpoints()[1],
        &root.join("tls/root.der"),
        &root.join("tls/leaf-1.der"),
        &root.join("tls/leaf-1-key.der"),
        1,
    )
    .pop()
    .unwrap();
    let (mut fragment_a_tx, mut fragment_c_rx): (Vec<_>, Vec<_>) = pairs(
        c.q.endpoint(),
        &root.join("tls/root.der"),
        &tls.join("c.der"),
        &tls.join("c-key.der"),
        4,
    )
    .into_iter()
    .unzip();
    let (mut fragment_c_tx, _fragment_b_rx): (Vec<_>, Vec<_>) = pairs(
        c.r2.round.config.endpoints()[1],
        &root.join("tls/root.der"),
        &root.join("tls/leaf-1.der"),
        &root.join("tls/leaf-1-key.der"),
        4,
    )
    .into_iter()
    .unzip();
    let round = c.r2.round.manifest.round();
    let sample = crate::schedule::QualifiedClockSample::from_qualified_source(
        std::time::UNIX_EPOCH + Duration::from_secs(round * 30) - Duration::from_secs(11),
        Instant::now(),
        Duration::ZERO,
    )
    .unwrap();
    let schedule = Im3Schedule::new(c.r2.round.config, round, sample).unwrap();
    let mut guard = Im3Guard::arm(&schedule).unwrap();
    let sequence_path = out.join("A-failure-sequence");
    directory(&sequence_path);
    let sequence_pin_path = out.join("A-failure-sequence.pin");
    let mut sequence = Im3RoundSequence::create(
        &sequence_path,
        c.profile,
        FilePins(sequence_pin_path.clone()),
    )
    .unwrap();
    let attempt = sequence.begin(c, &schedule, &mut guard).unwrap();
    let cp = out.join("C-A-cancel");
    let bp = out.join("B-A-cancel");
    directory(&cp);
    directory(&bp);
    let mut cs =
        PreparedScopeStore::create(&cp, c.claim_binding(), FilePins(out.join("C-A-cancel.pin")))
            .unwrap();
    let mut bs = PreparedScopeStore::create(
        &bp,
        c.profile.claim_binding(ClaimRole::Exit),
        FilePins(out.join("B-A-cancel.pin")),
    )
    .unwrap();
    let fragment_paths: Vec<_> = (1..=4)
        .map(|i| {
            let path = out.join(format!("C-A-fragment-{i}"));
            directory(&path);
            path
        })
        .collect();
    let mut fragment_stores: Vec<_> = fragment_paths
        .iter()
        .enumerate()
        .map(|(i, path)| {
            PreparedScopeStore::create(
                path,
                c.claim_binding(),
                FilePins(out.join(format!("C-A-fragment-{}.pin", i + 1))),
            )
            .unwrap()
        })
        .collect();
    let mut ingress = ReceivingIngressOwner::begin(
        c,
        &schedule,
        attempt.parts().2,
        &mut ingress_inputs,
        &mut a_tx,
    )
    .unwrap();
    let mut middle = ReceivingMiddleOwner::begin(
        c,
        &mut cs,
        &schedule,
        attempt.parts().2,
        &mut c_rx,
        &mut c_tx,
    )
    .unwrap();
    let mut exit =
        ReceivingExitOwner::begin(c, &mut bs, &schedule, attempt.parts().2, &mut b_rx).unwrap();
    let mut fragment_owners: Vec<_> = fragment_stores
        .iter_mut()
        .zip(fragment_c_rx.iter_mut())
        .zip(fragment_c_tx.iter_mut())
        .map(|((store, rx), tx)| {
            ReceivingMiddleOwner::begin(c, store, &schedule, attempt.parts().2, rx, tx).unwrap()
        })
        .collect();
    sleep_until(schedule.at(-8_000_000_000).unwrap());
    assert!(!ingress.poll().unwrap());
    assert!(!exit.poll().unwrap());
    sleep_until(schedule.at(15_000_000_000).unwrap());
    assert!(ingress.poll().is_err()); // All32 original client links are empty.
    assert!(
        !ingress
            .poll_cancel(&SigningKey::from_bytes(&[11; 32]))
            .unwrap()
    );
    while !ingress
        .poll_cancel(&SigningKey::from_bytes(&[11; 32]))
        .unwrap()
    {
        assert!(Instant::now() < schedule.at(16_000_000_000).unwrap());
        std::thread::sleep(Duration::from_micros(100));
    }
    assert!(ingress.take_cancel_wire_observation().is_some());
    loop {
        match middle.poll() {
            Err(Error::Unavailable("IM3 A cancelled")) => break,
            Ok(false) => {
                assert!(Instant::now() < schedule.at(16_000_000_000).unwrap());
                std::thread::sleep(Duration::from_micros(100));
            }
            other => panic!("A CANCEL not authenticated at C: {:?}", other.err()),
        }
    }
    let cancel = super::super::control::sign(
        c,
        Im3Kind::Cancel,
        Im3Role::A,
        [[0; 32]; 7],
        &SigningKey::from_bytes(&[11; 32]),
    )
    .unwrap();
    for (i, tx) in fragment_a_tx.iter_mut().enumerate() {
        tx.queue(
            RecordSize::Control,
            cancel.bytes(),
            schedule.at(16_000_000_000).unwrap(),
        )
        .unwrap();
        assert_eq!(tx.write_prefix_for_test(i + 1).unwrap(), i + 1);
        assert!(!fragment_owners[i].poll().unwrap());
    }
    for tx in &mut fragment_a_tx {
        while !tx.write_step().unwrap() {
            assert!(Instant::now() < schedule.at(16_000_000_000).unwrap());
        }
    }
    for owner in &mut fragment_owners {
        loop {
            match owner.poll() {
                Err(Error::Unavailable("IM3 A cancelled")) => break,
                Ok(false) => {
                    assert!(Instant::now() < schedule.at(16_000_000_000).unwrap());
                    std::thread::sleep(Duration::from_micros(100));
                }
                other => panic!("fragmented A CANCEL not authenticated: {:?}", other.err()),
            }
        }
    }
    assert!(
        !middle
            .poll_cancel(&SigningKey::from_bytes(&[16; 32]))
            .unwrap()
    );
    while !middle
        .poll_cancel(&SigningKey::from_bytes(&[16; 32]))
        .unwrap()
    {
        assert!(Instant::now() < schedule.at(20_500_000_000).unwrap());
        std::thread::sleep(Duration::from_micros(100));
    }
    assert!(middle.take_wire_observation().is_some());
    loop {
        match exit.poll() {
            Err(Error::Unavailable("IM3 C cancelled")) => break,
            Ok(false) => {
                assert!(Instant::now() < schedule.at(20_500_000_000).unwrap());
                std::thread::sleep(Duration::from_micros(100));
            }
            other => panic!("C CANCEL not authenticated at B: {:?}", other.err()),
        }
    }
    drop(ingress);
    drop(middle);
    drop(exit);
    drop(fragment_owners);
    drop(fragment_stores);
    attempt.abort().unwrap();
    drop(guard);
    let mut next_manifest = *c.r2.round.manifest.bytes();
    next_manifest[44..52].copy_from_slice(&(round + 2).to_le_bytes());
    let mut signed_body = c.r2.round.config.id().to_vec();
    signed_body.extend_from_slice(&next_manifest[..128]);
    next_manifest[128..192].copy_from_slice(&sign(11, "SilkNode-F0-round", &signed_body));
    next_manifest[192..256].copy_from_slice(&sign(12, "SilkNode-F0-round", &signed_body));
    let next_manifest =
        SignedManifest::verify(&next_manifest, c.r2.round.config, round + 2).unwrap();
    let next_context = MiddleContext::new(
        c.r2.round.config,
        &next_manifest,
        c.profile,
        c.claim_binding().vk_hash,
        c.q,
    )
    .unwrap();
    let (_next_clients, next_inputs): (Vec<_>, Vec<_>) = pairs(
        c.r2.round.config.endpoints()[0],
        &root.join("tls/root.der"),
        &root.join("tls/leaf-0.der"),
        &root.join("tls/leaf-0-key.der"),
        32,
    )
    .into_iter()
    .unzip();
    let mut next_inputs: [Transport; 32] = next_inputs.try_into().ok().unwrap();
    let (mut next_a_tx, mut next_c_rx) = pairs(
        c.q.endpoint(),
        &root.join("tls/root.der"),
        &tls.join("c.der"),
        &tls.join("c-key.der"),
        1,
    )
    .pop()
    .unwrap();
    let (mut next_c_tx, mut next_b_rx) = pairs(
        c.r2.round.config.endpoints()[1],
        &root.join("tls/root.der"),
        &root.join("tls/leaf-1.der"),
        &root.join("tls/leaf-1-key.der"),
        1,
    )
    .pop()
    .unwrap();
    let next_sample = crate::schedule::QualifiedClockSample::from_qualified_source(
        std::time::UNIX_EPOCH + Duration::from_secs((round + 2) * 30) - Duration::from_secs(11),
        Instant::now(),
        Duration::ZERO,
    )
    .unwrap();
    let next_schedule = Im3Schedule::new(c.r2.round.config, round + 2, next_sample).unwrap();
    let mut next_guard = Im3Guard::arm(&next_schedule).unwrap();
    let next_attempt = sequence
        .begin(&next_context, &next_schedule, &mut next_guard)
        .unwrap();
    let mut next_ingress = ReceivingIngressOwner::begin(
        &next_context,
        &next_schedule,
        next_attempt.parts().2,
        &mut next_inputs,
        &mut next_a_tx,
    )
    .unwrap();
    let mut next_middle = ReceivingMiddleOwner::begin(
        &next_context,
        &mut cs,
        &next_schedule,
        next_attempt.parts().2,
        &mut next_c_rx,
        &mut next_c_tx,
    )
    .unwrap();
    let mut next_exit = ReceivingExitOwner::begin(
        &next_context,
        &mut bs,
        &next_schedule,
        next_attempt.parts().2,
        &mut next_b_rx,
    )
    .unwrap();
    sleep_until(next_schedule.at(-8_000_000_000).unwrap());
    assert!(!next_ingress.poll().unwrap());
    assert!(!next_exit.poll().unwrap());
    sleep_until(next_schedule.at(15_000_000_000).unwrap());
    assert!(next_ingress.poll().is_err());
    while !next_ingress
        .poll_cancel(&SigningKey::from_bytes(&[11; 32]))
        .unwrap()
    {
        assert!(Instant::now() < next_schedule.at(16_000_000_000).unwrap());
        std::thread::sleep(Duration::from_micros(100));
    }
    loop {
        match next_middle.poll() {
            Err(Error::Unavailable("IM3 A cancelled")) => break,
            Ok(false) => {
                assert!(Instant::now() < next_schedule.at(16_000_000_000).unwrap());
                std::thread::sleep(Duration::from_micros(100));
            }
            other => panic!("second-round A CANCEL: {:?}", other.err()),
        }
    }
    while !next_middle
        .poll_cancel(&SigningKey::from_bytes(&[16; 32]))
        .unwrap()
    {
        assert!(Instant::now() < next_schedule.at(20_500_000_000).unwrap());
        std::thread::sleep(Duration::from_micros(100));
    }
    loop {
        match next_exit.poll() {
            Err(Error::Unavailable("IM3 C cancelled")) => break,
            Ok(false) => {
                assert!(Instant::now() < next_schedule.at(20_500_000_000).unwrap());
                std::thread::sleep(Duration::from_micros(100));
            }
            other => panic!("second-round C CANCEL: {:?}", other.err()),
        }
    }
    drop(next_ingress);
    drop(next_middle);
    drop(next_exit);
    next_attempt.abort().unwrap();
    drop(next_guard);
    drop(cs);
    drop(bs);
    let sequence_pin = sequence.pin();
    assert_eq!(fs::read(&sequence_pin_path).unwrap(), sequence_pin);
    drop(sequence);
    let reopened_sequence = Im3RoundSequence::open(
        &sequence_path,
        c.profile,
        sequence_pin,
        round + 2,
        FilePins(sequence_pin_path),
    )
    .unwrap();
    assert!(reopened_sequence.earliest_round() >= round + 5);
    drop(reopened_sequence);
    for (path, pin, role) in [
        (cp, "C-A-cancel.pin", ClaimRole::Middle),
        (bp, "B-A-cancel.pin", ClaimRole::Exit),
    ] {
        let bytes: Digest = fs::read(out.join(pin)).unwrap().try_into().unwrap();
        let mut cold = PreparedScopeStore::open(
            &path,
            c.profile.claim_binding(role),
            bytes,
            round + 2,
            FilePins(out.join(pin)),
        )
        .unwrap();
        assert!(
            cold.consume(round, c.r2.round.manifest.id(), [9; 32])
                .is_err()
        );
        assert!(
            cold.consume(round + 2, next_manifest.id(), [9; 32])
                .is_err()
        );
    }
    for (i, path) in fragment_paths.iter().enumerate() {
        let pin = out.join(format!("C-A-fragment-{}.pin", i + 1));
        let bytes: Digest = fs::read(&pin).unwrap().try_into().unwrap();
        let mut cold =
            PreparedScopeStore::open(path, c.claim_binding(), bytes, round, FilePins(pin)).unwrap();
        assert!(
            cold.consume(round, c.r2.round.manifest.id(), [9; 32])
                .is_err()
        );
    }
    json!({"status":"PASS_A_TO_C_TO_B_FIXED_FAILURE_CANCEL",
        "A_input_cells":0,"C_output_cells":0,"B_output_cells":0,
        "fragmented_A_CANCEL_headers":[1,2,3,4],
        "cold_old_round_refused":8,"durable_sequence_abort_terminal":true,
        "next_even_round_original_links_cancelled":round+2,
        "cold_sequence_old_round_refused":true,"new_proofs":0})
}

pub(super) fn initial_phase_failure(
    c: &MiddleContext<'_>,
    root: &Path,
    out: &Path,
    key: &HpkePrivate,
    verifier: &PreparedProofVerifier,
) -> serde_json::Value {
    let (mut tx, mut rx) = pairs(
        c.r2.round.config.endpoints()[1],
        &root.join("tls/root.der"),
        &root.join("tls/leaf-1.der"),
        &root.join("tls/leaf-1-key.der"),
        1,
    )
    .pop()
    .unwrap();
    let round = c.r2.round.manifest.round();
    let now = Instant::now();
    let sample = crate::schedule::QualifiedClockSample::from_qualified_source(
        std::time::UNIX_EPOCH + Duration::from_secs(round * 30) - Duration::from_secs(11),
        now,
        Duration::ZERO,
    )
    .unwrap();
    let schedule = Im3Schedule::new(c.r2.round.config, round, sample).unwrap();
    let guard = Im3Guard::arm(&schedule).unwrap();
    let path = out.join("initial-phase-failure");
    directory(&path);
    let mut store =
        PreparedScopeStore::create(&path, c.claim_binding(), FilePins(out.join("pin"))).unwrap();
    let owner = TimedMiddleOwner::begin(c, &mut store, &schedule, &guard, &mut tx).unwrap();
    assert!(matches!(
        owner.verify(key, verifier),
        Err(Error::Unavailable("IM3 fixed phase missed"))
    ));
    assert!(
        tx.queue(
            RecordSize::Control,
            &[0; 512],
            Instant::now() + Duration::from_secs(1)
        )
        .is_err()
    );
    let end = Instant::now() + Duration::from_secs(1);
    rx.expect(RecordSize::Cell, end).unwrap();
    let mut steps = 0;
    loop {
        let (result, o) = rx.read_step_observed();
        steps += 1;
        assert_eq!(o.bytes, 0);
        assert!(!o.record_complete);
        if matches!(result, Err(Error::Unavailable("TLS read EOF"))) {
            assert!(o.failed);
            break;
        }
        assert!(result.unwrap().is_none());
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_micros(100));
    }
    assert_eq!(fs::read(path.join("CURRENT")).unwrap()[10], 0);
    let pin = store.pin();
    drop(store);
    drop(guard);
    let mut cold = PreparedScopeStore::open(
        &path,
        c.claim_binding(),
        pin,
        round,
        FilePins(out.join("pin")),
    )
    .unwrap();
    assert!(
        cold.consume(round, c.r2.round.manifest.id(), c.choice())
            .is_err()
    );
    json!({"status":"PASS_INITIAL_VERIFY_FAILURE_QUARANTINES_B","initial_phase_check_refused":true,
        "original_B_transport_poisoned":true,"B_zero_byte_eof":true,"read_steps":steps,
        "disclosure_decided":false,"cold_reopen_old_round_refused":true,"new_proofs":0,
        "full_output_fixture_repeated":false,"qualified_clock":false,"anonymity_proven":false})
}

pub(super) fn pairs(
    ep: Endpoint,
    ca: &Path,
    cert: &Path,
    key: &Path,
    count: usize,
) -> Vec<(Transport, Transport)> {
    let address = SocketAddr::new(Ipv6Addr::from(ep.address).into(), ep.port);
    let fd = rustix::net::socket(
        rustix::net::AddressFamily::INET6,
        rustix::net::SocketType::STREAM,
        Some(rustix::net::ipproto::TCP),
    )
    .unwrap();
    rustix::net::sockopt::set_socket_reuseaddr(&fd, true).unwrap();
    rustix::net::bind(&fd, &address).unwrap();
    rustix::net::listen(&fd, 32).unwrap();
    let listener = TcpListener::from(fd);
    (0..count)
        .map(|_| {
            let mut roots = RootCertStore::empty();
            roots
                .add(CertificateDer::from(fs::read(ca).unwrap()))
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(3);
            let client = TcpStream::connect(address).unwrap();
            let server = listener.accept().unwrap().0;
            let mut setup = [
                Some(Transport::client_setup(client, ep, roots, deadline).unwrap()),
                Some(
                    Transport::server_setup(
                        server,
                        ep,
                        vec![CertificateDer::from(fs::read(cert).unwrap())],
                        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(fs::read(key).unwrap())),
                        deadline,
                    )
                    .unwrap(),
                ),
            ];
            let mut done = [None, None];
            while done.iter().any(Option::is_none) {
                assert!(Instant::now() < deadline);
                for i in 0..2 {
                    if let Some(s) = setup[i].take() {
                        match s.poll().unwrap() {
                            SetupStep::Pending(s) => setup[i] = Some(s),
                            SetupStep::Established(t) => done[i] = Some(t),
                        }
                    }
                }
                std::thread::sleep(Duration::from_micros(100));
            }
            (done[0].take().unwrap(), done[1].take().unwrap())
        })
        .collect()
}
// Same-execution fixture: the first one or two slots come from distinct
// client processes, never recreated here. Remaining slots are administrative.
pub(super) fn external_prefix_pairs(
    ep: Endpoint,
    ca: &Path,
    cert: &Path,
    key: &Path,
    ready: &Path,
    external_count: usize,
) -> (Vec<Option<Transport>>, [Transport; 32]) {
    assert!((1..=2).contains(&external_count));
    let address = SocketAddr::new(Ipv6Addr::from(ep.address).into(), ep.port);
    let listener = TcpListener::bind(address).unwrap();
    listener.set_nonblocking(true).unwrap();
    save(ready, b"original A listener; external prefix reserved\n");
    let accept_end = Instant::now() + Duration::from_secs(10);
    let mut clients: Vec<Option<Transport>> = Vec::with_capacity(32);
    let mut servers = Vec::with_capacity(32);
    for _ in 0..external_count {
        let socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < accept_end);
                    std::thread::sleep(Duration::from_micros(500));
                }
                Err(e) => panic!("original fixture accept: {e}"),
            }
        };
        let end = Instant::now() + Duration::from_secs(3);
        let mut pending = Transport::server_setup(
            socket,
            ep,
            vec![CertificateDer::from(fs::read(cert).unwrap())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(fs::read(key).unwrap())),
            end,
        )
        .unwrap();
        let external = loop {
            assert!(Instant::now() < end);
            match pending.poll().unwrap() {
                SetupStep::Established(link) => break link,
                SetupStep::Pending(next) => pending = next,
            }
            std::thread::sleep(Duration::from_micros(100));
        };
        clients.push(None);
        servers.push(external);
    }
    for _ in external_count..32 {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(fs::read(ca).unwrap()))
            .unwrap();
        let client = TcpStream::connect(address).unwrap();
        let server = listener.accept().unwrap().0;
        let end = Instant::now() + Duration::from_secs(3);
        let mut pending = [
            Some(Transport::client_setup(client, ep, roots, end).unwrap()),
            Some(
                Transport::server_setup(
                    server,
                    ep,
                    vec![CertificateDer::from(fs::read(cert).unwrap())],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(fs::read(key).unwrap())),
                    end,
                )
                .unwrap(),
            ),
        ];
        let mut done = [None, None];
        while done.iter().any(Option::is_none) {
            assert!(Instant::now() < end);
            for i in 0..2 {
                if let Some(p) = pending[i].take() {
                    match p.poll().unwrap() {
                        SetupStep::Pending(next) => pending[i] = Some(next),
                        SetupStep::Established(link) => done[i] = Some(link),
                    }
                }
            }
            std::thread::sleep(Duration::from_micros(100));
        }
        clients.push(done[0].take());
        servers.push(done[1].take().unwrap());
    }
    (clients, servers.try_into().ok().unwrap())
}
fn observe(
    v: &mut Vec<serde_json::Value>,
    surface: &str,
    origin: Instant,
    o: WireObservation,
    case: &str,
) {
    let mut row = wire_json(surface, origin, o);
    row["case"] = json!(case);
    v.push(row);
}
#[allow(clippy::too_many_arguments)]
pub(super) fn run(
    c: &MiddleContext<'_>,
    root: &Path,
    out: &Path,
    frames: &[MiddleFrame; 32],
    key: &HpkePrivate,
    b_key: &HpkePrivate,
    verifier: &PreparedProofVerifier,
    envelope: &[u8],
    reuse: bool,
) -> serde_json::Value {
    let names = [
        "complete",
        "missing_cell",
        "duplicate",
        "wrong_context",
        "missing_ready",
        "extra",
        "partial",
        "late_ready",
        "bad_proof",
    ];
    let tls = PathBuf::from(std::env::var_os("SILK_IM3_C_TLS").unwrap());
    let (mut a_senders, mut a_inputs): (Vec<_>, Vec<_>) = pairs(
        c.q.endpoint(),
        &root.join("tls/root.der"),
        &tls.join("c.der"),
        &tls.join("c-key.der"),
        names.len(),
    )
    .into_iter()
    .unzip();
    let (mut b_outputs, mut b_receivers): (Vec<_>, Vec<_>) = pairs(
        c.r2.round.config.endpoints()[1],
        &root.join("tls/root.der"),
        &root.join("tls/leaf-1.der"),
        &root.join("tls/leaf-1-key.der"),
        names.len(),
    )
    .into_iter()
    .unzip();
    let mut bad_frames = copied(c, frames);
    let mut plain = middle_plain(c, key, &bad_frames[0]);
    plain[160] ^= 1;
    bad_frames[0] = rewritten(c, plain.as_ref());
    let round = c.r2.round.manifest.round();
    let monotonic = Instant::now();
    let sample = crate::schedule::QualifiedClockSample::from_qualified_source(
        std::time::UNIX_EPOCH + Duration::from_secs(round * 30) - Duration::from_secs(11),
        monotonic,
        Duration::ZERO,
    )
    .unwrap();
    let schedule = Im3Schedule::new(c.r2.round.config, round, sample).unwrap();
    let guard = Im3Guard::arm(&schedule).unwrap();
    let origin = schedule.at(0).unwrap();
    let mut stores: Vec<_> = names
        .iter()
        .map(|name| {
            let path = out.join(name);
            directory(&path);
            PreparedScopeStore::create(
                &path,
                c.claim_binding(),
                FilePins(out.join(format!("{name}.pin"))),
            )
            .unwrap()
        })
        .collect();
    let mut owners: Vec<Option<_>> = stores
        .iter_mut()
        .zip(a_inputs.iter_mut())
        .zip(b_outputs.iter_mut())
        .map(|((store, rx), tx)| {
            Some(ReceivingMiddleOwner::begin(c, store, &schedule, &guard, rx, tx).unwrap())
        })
        .collect();
    // Arming and signed-context selection predate the earliest receive envelope.
    let mut progress = vec![0u8; names.len()];
    let mut queued = vec![false; names.len()];
    let mut ready_sent = vec![false; names.len()];
    let mut extra_sent = false;
    let mut failed = vec![false; names.len()];
    let mut observations = Vec::new();
    sleep_until(schedule.at(15_500_000_000).unwrap());
    while Instant::now() < schedule.at(17_500_000_000).unwrap() {
        for i in 0..names.len() {
            if !failed[i] {
                if progress[i] < 32 && !(i == 1 && progress[i] == 31) && i != 6 {
                    let j = progress[i];
                    let (start, end) = schedule.relay_slot(false, j).unwrap();
                    if Instant::now() >= start {
                        if !queued[i] {
                            let mut bytes = *(if i == 8 {
                                &bad_frames[usize::from(j)]
                            } else {
                                &frames[if i == 2 && j == 31 { 0 } else { usize::from(j) }]
                            })
                            .bytes();
                            if i == 3 && j == 0 {
                                bytes[20] ^= 1;
                            }
                            a_senders[i].queue(RecordSize::Cell, &bytes, end).unwrap();
                            queued[i] = true;
                        }
                        let (result, o) = a_senders[i].write_step_observed();
                        observe(&mut observations, "A_write", origin, o, names[i]);
                        if result.unwrap() {
                            progress[i] += 1;
                            queued[i] = false;
                        }
                    }
                } else if i == 6 && progress[i] == 0 {
                    a_senders[i]
                        .queue(
                            RecordSize::Cell,
                            frames[0].bytes(),
                            schedule.at(15_507_812_500).unwrap(),
                        )
                        .unwrap();
                    assert_eq!(a_senders[i].write_prefix_for_test(5).unwrap(), 5);
                    progress[i] = 1;
                }
                if progress[i] == 32
                    && !ready_sent[i]
                    && i != 4
                    && i != 7
                    && Instant::now() >= schedule.at(15_750_000_000).unwrap()
                {
                    a_senders[i]
                        .queue(
                            RecordSize::Control,
                            &ready_bytes(c, if i == 8 { &bad_frames } else { frames }),
                            schedule.at(16_000_000_000).unwrap(),
                        )
                        .unwrap();
                    let (result, o) = a_senders[i].write_step_observed();
                    observe(&mut observations, "A_ready_write", origin, o, names[i]);
                    assert!(result.unwrap());
                    ready_sent[i] = true;
                }
                if i == 5
                    && ready_sent[i]
                    && !extra_sent
                    && Instant::now() >= schedule.at(16_000_000_000).unwrap()
                {
                    a_senders[i]
                        .queue(
                            RecordSize::Cell,
                            frames[0].bytes(),
                            schedule.at(16_250_000_000).unwrap(),
                        )
                        .unwrap();
                    let (result, o) = a_senders[i].write_step_observed();
                    observe(&mut observations, "A_extra_write", origin, o, names[i]);
                    assert!(result.unwrap());
                    extra_sent = true;
                }
                let owner = owners[i].as_mut().unwrap();
                let result = owner.poll();
                if let Some(o) = owner.take_wire_observation() {
                    observe(&mut observations, "C_read", origin, o, names[i]);
                }
                if result.is_err() {
                    assert_ne!(i, 0);
                    failed[i] = true;
                }
            }
        }
        assert!(observations.len() < 200_000);
        std::thread::sleep(Duration::from_micros(100));
    }
    a_senders[7]
        .queue(
            RecordSize::Control,
            &ready_bytes(c, frames),
            schedule.at(18_000_000_000).unwrap(),
        )
        .unwrap();
    let (result, o) = a_senders[7].write_step_observed();
    observe(&mut observations, "A_late_ready_write", origin, o, names[7]);
    assert!(result.unwrap());
    // No omission/partial/late readiness can be completed at or after cutoff.
    for i in 1..names.len() {
        if !failed[i] && i != 8 {
            assert!(owners[i].as_mut().unwrap().poll().is_err());
            failed[i] = true;
        }
        assert!(owners[i].take().unwrap().verify(key, verifier).is_err());
        b_receivers[i]
            .expect(RecordSize::Cell, schedule.at(22_000_000_000).unwrap())
            .unwrap();
        loop {
            let (result, o) = b_receivers[i].read_step_observed();
            assert_eq!(o.bytes, 0);
            assert!(!o.record_complete);
            observe(&mut observations, "B_refusal_read", origin, o, names[i]);
            if matches!(result, Err(Error::Unavailable("TLS read EOF"))) {
                break;
            }
            assert!(result.unwrap().is_none());
            assert!(Instant::now() < schedule.at(18_500_000_000).unwrap());
            std::thread::sleep(Duration::from_micros(100));
        }
        let snapshot = fs::read(out.join(names[i]).join("CURRENT")).unwrap();
        assert_eq!(snapshot[10], 0);
    }
    let verified = owners[0].take().unwrap().verify(key, verifier).unwrap();
    drop(owners);
    b_receivers[0]
        .expect(RecordSize::Cell, schedule.at(22_000_000_000).unwrap())
        .unwrap();
    sleep_until(schedule.window(Phase::CDecision).unwrap().0);
    let mut disclosure = verified.decide().unwrap();
    let snapshot = fs::read(out.join("complete/CURRENT")).unwrap();
    assert_eq!(snapshot[10], 1);
    let mut finished = false;
    let mut received = Vec::new();
    while !finished || received.len() < 32 {
        assert!(Instant::now() < schedule.at(22_000_000_000).unwrap());
        if !finished {
            let result = disclosure.poll();
            if let Some(o) = disclosure.take_wire_observation() {
                observe(&mut observations, "C_write", origin, o, "complete");
            }
            finished = result.unwrap();
        }
        if received.len() < 32 {
            let (result, o) = b_receivers[0].read_step_observed();
            observe(&mut observations, "B_read", origin, o, "complete");
            if let Some(bytes) = result.unwrap() {
                received.push(MiddleFrame::decode(&bytes, c, 3).unwrap());
                if received.len() < 32 {
                    b_receivers[0]
                        .expect(RecordSize::Cell, schedule.at(22_000_000_000).unwrap())
                        .unwrap();
                }
            }
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    let mut real = 0;
    for f in received {
        let p = open(
            c,
            3,
            c.r2.round.config.hpke_keys()[1],
            b_key,
            &f.bytes()[64..4208],
        )
        .unwrap();
        if p[8] == 1 {
            real += 1;
            assert_eq!(&p[416..3206], envelope);
        }
    }
    assert_eq!(real, 1);
    drop(disclosure);
    drop(guard);
    drop(stores);
    // Fresh typed store reconstruction, using independently retained file pins.
    // Consumed failed inputs and disclosure-decided success both refuse old round.
    for name in names {
        let pin: Digest = fs::read(out.join(format!("{name}.pin")))
            .unwrap()
            .try_into()
            .unwrap();
        let mut cold = PreparedScopeStore::open(
            &out.join(name),
            c.claim_binding(),
            pin,
            round,
            FilePins(out.join(format!("{name}.pin"))),
        )
        .unwrap();
        assert!(
            cold.consume(round, c.r2.round.manifest.id(), c.choice())
                .is_err()
        );
    }
    save(
        &out.join("socket-observations.json"),
        &serde_json::to_vec(&observations).unwrap(),
    );
    json!({"status":"PASS_INCOMING_TLS_COMPLETE_MIDDLE_GATE","new_C_proofs":if reuse{0}else{32},
        "reused_B_proofs":32,"output_records":32,"real_envelope_count":real,
        "incoming_armed_before_early_envelope":true,"refused_cases":&names[1..],
        "cold_reopen_old_round_refused":9,"durable_disclosure_before_B_write":true,
        "qualified_clock":false,"independent_roles":false,"socket_caps_qualified":false,
        "manifest_socket_fanout_integrated":false,"node_settlement_tested":false,"anonymity_proven":false})
}
