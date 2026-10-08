//! Durable successive-round fence only; no fixture clock or synthetic release
//! is promoted to operational qualification.
use super::*;
use std::{cell::Cell, rc::Rc};

struct FixtureAdmission(Rc<Cell<bool>>);
impl Im3RoleAdmission for FixtureAdmission {
    fn admit(&mut self, _: &MiddleContext<'_>) -> Result<()> {
        if self.0.get() {
            Ok(())
        } else {
            Err(Error::Unavailable("fixture role admission refused"))
        }
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

pub(super) fn manifest(c: &MiddleContext<'_>, round: u64) -> SignedManifest {
    let mut bytes = *c.r2.round.manifest.bytes();
    bytes[44..52].copy_from_slice(&round.to_le_bytes());
    let mut body = c.r2.round.config.id().to_vec();
    body.extend_from_slice(&bytes[..128]);
    bytes[128..192].copy_from_slice(&sign(11, "SilkNode-F0-round", &body));
    bytes[192..256].copy_from_slice(&sign(12, "SilkNode-F0-round", &body));
    SignedManifest::verify(&bytes, c.r2.round.config, round).unwrap()
}
fn schedule(c: &MiddleContext<'_>) -> Im3Schedule {
    let round = c.r2.round.manifest.round();
    let sample = crate::schedule::QualifiedClockSample::from_qualified_source(
        std::time::UNIX_EPOCH + Duration::from_secs(round * 30) - Duration::from_secs(11),
        Instant::now(),
        Duration::ZERO,
    )
    .unwrap();
    Im3Schedule::new(c.r2.round.config, round, sample).unwrap()
}
pub(super) fn run(c: &MiddleContext<'_>, out: &Path) -> serde_json::Value {
    let round = c.r2.round.manifest.round();
    let path = out.join("round-sequence");
    let pin_path = out.join("round-sequence.pin");
    directory(&path);
    let mut sequence =
        Im3RoundSequence::create(&path, c.profile, FilePins(pin_path.clone())).unwrap();
    let first = schedule(c);
    let mut first_guard = Im3Guard::arm(&first).unwrap();
    let attempt = sequence.begin(c, &first, &mut first_guard).unwrap();
    let (bound, mapped, native) = attempt.parts();
    assert_eq!(bound.r2.round.manifest.id(), c.r2.round.manifest.id());
    native.check(mapped).unwrap();
    attempt.abort().unwrap();
    drop(first_guard);

    let m2 = manifest(c, round + 2);
    let c2 = MiddleContext::new(
        c.r2.round.config,
        &m2,
        c.profile,
        c.claim_binding().vk_hash,
        c.q,
    )
    .unwrap();
    let second = schedule(&c2);
    let mut second_guard = Im3Guard::arm(&second).unwrap();
    let pending = sequence.begin(&c2, &second, &mut second_guard).unwrap();
    drop(pending); // Crash-equivalent: no terminal write and no replay permit.
    drop(second_guard);

    let m3 = manifest(c, round + 4);
    let c3 = MiddleContext::new(
        c.r2.round.config,
        &m3,
        c.profile,
        c.claim_binding().vk_hash,
        c.q,
    )
    .unwrap();
    let third = schedule(&c3);
    let mut third_guard = Im3Guard::arm(&third).unwrap();
    assert!(sequence.begin(&c3, &third, &mut third_guard).is_err());
    drop(third_guard);

    let pin = sequence.pin();
    assert_eq!(fs::read(&pin_path).unwrap(), pin);
    drop(sequence);
    assert!(
        Im3RoundSequence::open(&path, c.profile, pin, round, FilePins(pin_path.clone())).is_err()
    );
    let mut wrong_pin = pin;
    wrong_pin[0] ^= 1;
    assert!(
        Im3RoundSequence::open(
            &path,
            c.profile,
            wrong_pin,
            round + 4,
            FilePins(pin_path.clone()),
        )
        .is_err()
    );
    let mut reopened =
        Im3RoundSequence::open(&path, c.profile, pin, round + 4, FilePins(pin_path.clone()))
            .unwrap();
    assert!(reopened.earliest_round() >= round + 7);
    let m4 = manifest(c, round + 8);
    let c4 = MiddleContext::new(
        c.r2.round.config,
        &m4,
        c.profile,
        c.claim_binding().vk_hash,
        c.q,
    )
    .unwrap();
    let fourth = schedule(&c4);
    let mut fourth_guard = Im3Guard::arm(&fourth).unwrap();
    reopened
        .begin(&c4, &fourth, &mut fourth_guard)
        .unwrap()
        .abort()
        .unwrap();
    drop(fourth_guard);

    let runner_path = out.join("round-runner");
    let runner_pin = out.join("round-runner.pin");
    directory(&runner_path);
    let allowed = Rc::new(Cell::new(false));
    let mut runner = Im3RoundRunner::create(
        &runner_path,
        c.profile,
        FilePins(runner_pin.clone()),
        FixtureAdmission(Rc::clone(&allowed)),
        FixtureClock,
    )
    .unwrap();
    let initial_pin = runner.pin();
    assert!(runner.run_round(c, |_| unreachable!()).is_err());
    assert_eq!(runner.pin(), initial_pin); // Admission refusal precedes claim.
    allowed.set(true);
    for context in [c, &c2] {
        runner
            .run_round(context, |ports| {
                let (bound, mapped, native) = ports.parts();
                native.check(mapped)?;
                assert_eq!(bound.r2.round.manifest.id(), context.r2.round.manifest.id());
                Ok(Im3RoundTerminal::Abort)
            })
            .unwrap();
    }
    assert!(
        runner
            .run_round(&c3, |_| Err(Error::Unavailable("fixture driver failure")))
            .is_err()
    );
    assert!(runner.run_round(&c4, |_| unreachable!()).is_err());
    let runner_last_pin = runner.pin();
    assert_eq!(fs::read(&runner_pin).unwrap(), runner_last_pin);
    drop(runner);
    let reopened_runner = Im3RoundRunner::open(
        &runner_path,
        c.profile,
        runner_last_pin,
        round + 4,
        FilePins(runner_pin),
        FixtureAdmission(allowed),
        FixtureClock,
    )
    .unwrap();
    assert!(reopened_runner.earliest_round() >= round + 7);
    json!({"status":"PASS_DURABLE_IM3_SUCCESSIVE_ROUND_FENCE",
        "first_aborted_round":round,"next_admitted_even_round":round+2,
        "dropped_round_blocked_live":round+2,"blocked_next_live_round":round+4,
        "stale_restart_and_wrong_pin_refused":true,
        "runner_admission_precedes_claim":true,"runner_two_terminal_rounds":true,
        "runner_failed_driver_blocks_hot_next":true,
        "cold_restart_round":round+4,"next_cold_admitted_even_round":round+8,
        "new_proofs":0,"new_work":0,"network_links":0,"qualified_clock":false})
}
