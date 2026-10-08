//! Two actual original-link failure rounds through one retained runner.
//! Fixture authority and clock are deliberately not independent qualification.
use super::*;
use crate::tls::{RecordSize, Transport};

struct FixtureAdmission;
impl Im3RoleAdmission for FixtureAdmission {
    fn admit(&mut self, _: &MiddleContext<'_>) -> Result<()> {
        Ok(())
    }
}
struct FixtureClock;
impl Im3ClockSource for FixtureClock {
    fn sample(&mut self, c: &MiddleContext<'_>) -> Result<crate::schedule::QualifiedClockSample> {
        crate::schedule::QualifiedClockSample::from_qualified_source(
            std::time::UNIX_EPOCH + Duration::from_secs(c.r2.round.manifest.round() * 30)
                - Duration::from_secs(11),
            Instant::now(),
            Duration::ZERO,
        )
    }
}

pub(super) fn original_cancel(c: &MiddleContext<'_>, root: &Path, out: &Path) -> serde_json::Value {
    let tls = PathBuf::from(std::env::var_os("SILK_IM3_C_TLS").unwrap());
    let first_round = c.r2.round.manifest.round();
    let next_manifest = sequence::manifest(c, first_round + 2);
    let next_context = MiddleContext::new(
        c.r2.round.config,
        &next_manifest,
        c.profile,
        c.claim_binding().vk_hash,
        c.q,
    )
    .unwrap();
    let sequence_path = out.join("runner-sequence");
    let c_path = out.join("runner-C");
    let b_path = out.join("runner-B");
    for path in [&sequence_path, &c_path, &b_path] {
        directory(path);
    }
    let sequence_pin_path = out.join("runner-sequence.pin");
    let c_pin_path = out.join("runner-C.pin");
    let b_pin_path = out.join("runner-B.pin");
    let mut runner = Im3RoundRunner::create(
        &sequence_path,
        c.profile,
        FilePins(sequence_pin_path.clone()),
        FixtureAdmission,
        FixtureClock,
    )
    .unwrap();
    let mut c_store =
        PreparedScopeStore::create(&c_path, c.claim_binding(), FilePins(c_pin_path.clone()))
            .unwrap();
    let mut b_store = PreparedScopeStore::create(
        &b_path,
        c.profile.claim_binding(ClaimRole::Exit),
        FilePins(b_pin_path.clone()),
    )
    .unwrap();
    for context in [c, &next_context] {
        let (_clients, inputs): (Vec<Transport>, Vec<Transport>) = incoming::pairs(
            context.r2.round.config.endpoints()[0],
            &root.join("tls/root.der"),
            &root.join("tls/leaf-0.der"),
            &root.join("tls/leaf-0-key.der"),
            32,
        )
        .into_iter()
        .unzip();
        let mut inputs: [Transport; 32] = inputs.try_into().ok().unwrap();
        let (mut a_to_c, mut c_from_a) = incoming::pairs(
            context.q.endpoint(),
            &root.join("tls/root.der"),
            &tls.join("c.der"),
            &tls.join("c-key.der"),
            1,
        )
        .pop()
        .unwrap();
        let (mut c_to_b, mut b_from_c) = incoming::pairs(
            context.r2.round.config.endpoints()[1],
            &root.join("tls/root.der"),
            &root.join("tls/leaf-1.der"),
            &root.join("tls/leaf-1-key.der"),
            1,
        )
        .pop()
        .unwrap();
        runner
            .run_round(context, |ports| {
                let schedule = ports.schedule();
                let mut a = ports.ingress(&mut inputs, &mut a_to_c)?;
                let mut middle = ports.middle(&mut c_store, &mut c_from_a, &mut c_to_b)?;
                let mut b = ports.exit(&mut b_store, &mut b_from_c)?;
                sleep_until(schedule.at(-8_000_000_000)?);
                assert!(!a.poll()?);
                assert!(!b.poll()?);
                sleep_until(schedule.at(15_000_000_000)?);
                assert!(a.poll().is_err());
                while !a.poll_cancel(&SigningKey::from_bytes(&[11; 32]))? {
                    assert!(Instant::now() < schedule.at(16_000_000_000)?);
                    std::thread::sleep(Duration::from_micros(100));
                }
                loop {
                    match middle.poll() {
                        Err(Error::Unavailable("IM3 A cancelled")) => break,
                        Ok(false) => {
                            assert!(Instant::now() < schedule.at(16_000_000_000)?);
                            std::thread::sleep(Duration::from_micros(100));
                        }
                        other => panic!("A to C runner cancel: {:?}", other.err()),
                    }
                }
                while !middle.poll_cancel(&SigningKey::from_bytes(&[16; 32]))? {
                    assert!(Instant::now() < schedule.at(20_500_000_000)?);
                    std::thread::sleep(Duration::from_micros(100));
                }
                loop {
                    match b.poll() {
                        Err(Error::Unavailable("IM3 C cancelled")) => break,
                        Ok(false) => {
                            assert!(Instant::now() < schedule.at(20_500_000_000)?);
                            std::thread::sleep(Duration::from_micros(100));
                        }
                        other => panic!("C to B runner cancel: {:?}", other.err()),
                    }
                }
                drop(a);
                drop(middle);
                drop(b);
                Ok(Im3RoundTerminal::Abort)
            })
            .unwrap();
    }
    let sequence_pin = runner.pin();
    assert_eq!(fs::read(&sequence_pin_path).unwrap(), sequence_pin);
    drop(runner);
    drop(c_store);
    drop(b_store);
    let reopened = Im3RoundRunner::open(
        &sequence_path,
        c.profile,
        sequence_pin,
        first_round + 2,
        FilePins(sequence_pin_path),
        FixtureAdmission,
        FixtureClock,
    )
    .unwrap();
    assert!(reopened.earliest_round() >= first_round + 5);
    drop(reopened);
    for (path, pin, role) in [
        (c_path, c_pin_path, ClaimRole::Middle),
        (b_path, b_pin_path, ClaimRole::Exit),
    ] {
        let latest = fs::read(&pin).unwrap().try_into().unwrap();
        let mut cold = PreparedScopeStore::open(
            &path,
            c.profile.claim_binding(role),
            latest,
            first_round + 2,
            FilePins(pin),
        )
        .unwrap();
        assert!(
            cold.consume(first_round, c.r2.round.manifest.id(), [9; 32])
                .is_err()
        );
        assert!(
            cold.consume(first_round + 2, next_manifest.id(), [9; 32])
                .is_err()
        );
    }
    json!({"status":"PASS_RUNNER_TWO_ORIGINAL_A_C_B_CANCEL_ROUNDS",
        "rounds":[first_round,first_round+2],"A_input_cells":0,
        "B_output_cells":0,"C_output_cells":0,"signed_A_and_C_cancel_each_round":true,
        "runner_abort_terminal_each_round":true,"cold_old_round_refused":true,
        "new_proofs":0,"new_work":0,"qualified_clock":false})
}

/// C sees one retained genuine stage-2 cell followed by only four encrypted
/// bytes of the next Cell record. No A owner is constructed here: this is the
/// receiver's partial-stream/C-to-B failure path, not A freeze/train coverage.
pub(super) fn partial_incoming_stream(
    c: &MiddleContext<'_>,
    root: &Path,
    out: &Path,
) -> serde_json::Value {
    let tls = PathBuf::from(std::env::var_os("SILK_IM3_C_TLS").unwrap());
    let frame_path = PathBuf::from(std::env::var_os("SILK_IM3_ACTUAL_STAGE2").unwrap());
    let stage2 = fs::read(frame_path).unwrap();
    assert_eq!(stage2.len(), FRAME_BYTES);
    MiddleFrame::decode(&stage2, c, 2).unwrap();
    let (mut a_tx, mut c_rx) = incoming::pairs(
        c.q.endpoint(),
        &root.join("tls/root.der"),
        &tls.join("c.der"),
        &tls.join("c-key.der"),
        1,
    )
    .pop()
    .unwrap();
    let (mut c_tx, mut b_rx) = incoming::pairs(
        c.r2.round.config.endpoints()[1],
        &root.join("tls/root.der"),
        &root.join("tls/leaf-1.der"),
        &root.join("tls/leaf-1-key.der"),
        1,
    )
    .pop()
    .unwrap();
    let sequence_path = out.join("partial-runner-sequence");
    let c_path = out.join("partial-runner-C");
    let b_path = out.join("partial-runner-B");
    for path in [&sequence_path, &c_path, &b_path] {
        directory(path);
    }
    let mut runner = Im3RoundRunner::create(
        &sequence_path,
        c.profile,
        FilePins(out.join("partial-runner-sequence.pin")),
        FixtureAdmission,
        FixtureClock,
    )
    .unwrap();
    let mut c_store = PreparedScopeStore::create(
        &c_path,
        c.claim_binding(),
        FilePins(out.join("partial-runner-C.pin")),
    )
    .unwrap();
    let mut b_store = PreparedScopeStore::create(
        &b_path,
        c.profile.claim_binding(ClaimRole::Exit),
        FilePins(out.join("partial-runner-B.pin")),
    )
    .unwrap();
    runner
        .run_round(c, |ports| {
            let schedule = ports.schedule();
            let mut middle = ports.middle(&mut c_store, &mut c_rx, &mut c_tx)?;
            let mut b = ports.exit(&mut b_store, &mut b_rx)?;
            sleep_until(schedule.at(-8_000_000_000)?);
            assert!(!b.poll()?);
            sleep_until(schedule.relay_slot(false, 0)?.0);
            a_tx.queue(RecordSize::Cell, &stage2, schedule.relay_slot(false, 0)?.1)?;
            while !a_tx.write_step()? {
                assert!(Instant::now() < schedule.relay_slot(false, 0)?.1);
            }
            loop {
                if middle.poll()? {
                    panic!("partial C stream became complete");
                }
                if middle
                    .take_wire_observation()
                    .is_some_and(|o| o.record_complete)
                {
                    break;
                }
                assert!(Instant::now() < schedule.relay_slot(false, 1)?.0);
                std::thread::sleep(Duration::from_micros(100));
            }
            sleep_until(schedule.relay_slot(false, 1)?.0);
            a_tx.queue(RecordSize::Cell, &stage2, schedule.relay_slot(false, 1)?.1)?;
            assert_eq!(a_tx.write_prefix_for_test(4)?, 4);
            assert!(!middle.poll()?);
            assert!(
                !middle
                    .take_wire_observation()
                    .is_some_and(|o| o.record_complete)
            );
            sleep_until(schedule.at(17_500_000_000)?);
            assert!(middle.poll().is_err());
            while !middle.poll_cancel(&SigningKey::from_bytes(&[16; 32]))? {
                assert!(Instant::now() < schedule.at(20_500_000_000)?);
                std::thread::sleep(Duration::from_micros(100));
            }
            loop {
                match b.poll() {
                    Err(Error::Unavailable("IM3 C cancelled")) => break,
                    Ok(false) => {
                        assert!(Instant::now() < schedule.at(20_500_000_000)?);
                        std::thread::sleep(Duration::from_micros(100));
                    }
                    other => panic!("partial C to B runner cancel: {:?}", other.err()),
                }
            }
            drop(middle);
            drop(b);
            a_tx.quarantine()?;
            Ok(Im3RoundTerminal::Abort)
        })
        .unwrap();
    assert_eq!(fs::read(c_path.join("CURRENT")).unwrap()[10], 0);
    assert_eq!(fs::read(b_path.join("CURRENT")).unwrap()[10], 0);
    assert_eq!(fs::read(sequence_path.join("CURRENT")).unwrap()[10], 1);
    json!({"status":"PASS_RUNNER_PARTIAL_INCOMING_CANCELS_ORIGINAL_B",
        "first_genuine_stage2_cells":1,"second_TLS_record_prefix_bytes":4,
        "B_output_cells":0,"C_output_cells":0,"signed_C_cancel":true,
        "new_proofs":0,"new_work":0,"A_train_owner_exercised":false,
        "qualified_clock":false})
}
