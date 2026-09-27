//! Bounded local failed transcript checks; no signature/release acceptance.
use super::*;
use crate::{
    schedule::QualifiedClockSample,
    tests::{certificates, relay_test_config, tls::pair},
};
use std::time::UNIX_EPOCH;

fn schedule(at_millis: u64) -> Rc<Schedule> {
    let config = relay_test_config();
    Rc::new(
        Schedule::new(
            &config,
            6000,
            QualifiedClockSample::from_qualified_source(
                UNIX_EPOCH + Duration::from_millis(180_000_000 + at_millis),
                Instant::now(),
                Duration::ZERO,
            )
            .unwrap(),
        )
        .unwrap(),
    )
}

#[test]
fn omitted_failed_cells_yield_to_original_control_slot_without_new_deadline() {
    let temp = tempfile::tempdir().unwrap();
    let certs = temp.path().join("tls");
    certificates::generate(&certs, 1);
    let (mut sender, mut link) = pair(&certs);
    let schedule = schedule(13_500);
    let cutoff = schedule.at(14_000_000_000).unwrap();
    link.expect(RecordSize::Cell, cutoff).unwrap();
    sender
        .queue(RecordSize::Control, &[0; 512], cutoff)
        .unwrap();
    while !sender.write_step().unwrap() {
        std::thread::sleep(Duration::from_micros(100));
    }
    let mut drain = ExitInputDrain::new(schedule, [link.id(), 0, 0, 0], 0, false, [false; 3]);
    while !drain.a_done() {
        assert!(Instant::now() < cutoff);
        drain.poll_a(&mut link).unwrap();
        if let Some((_, deadline)) = link.selected_read() {
            assert_eq!(deadline, cutoff);
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    assert_eq!(drain.cells, 0);
    assert_eq!(link.receive_progress(), ReceiveProgress::Idle);
    assert!(link.selected_read().is_none());
}

#[test]
fn consumed_ack_is_not_discarded_twice_and_original_cutoff_refuses_excess() {
    let temp = tempfile::tempdir().unwrap();
    let certs = temp.path().join("tls");
    certificates::generate(&certs, 1);
    let (mut sender, mut link) = pair(&certs);
    let schedule = schedule(17_800);
    let cutoff = schedule.at(18_000_000_000).unwrap();
    // Physical prior consumption is the cursor input; this remaining record
    // cannot be consumed as another original ACK or count as valid evidence.
    sender
        .queue(RecordSize::Control, &[0; 512], cutoff)
        .unwrap();
    while !sender.write_step().unwrap() {
        std::thread::sleep(Duration::from_micros(100));
    }
    let mut drain = ExitInputDrain::new(
        schedule,
        [0, link.id(), 0, 0],
        32,
        true,
        [true, false, false],
    );
    drain.poll_ack(&mut link, 0, cutoff).unwrap();
    assert!(link.selected_read().is_none());
    std::thread::sleep(cutoff.saturating_duration_since(Instant::now()));
    assert!(drain.poll_ack(&mut link, 0, cutoff).is_err());
    assert!(link.has_extra_bytes().unwrap());
}
