//! Local real-TLS ownership regression, not native/qualified relay acceptance.
use super::*;
use crate::{
    input::AdmittedSession,
    schedule::QualifiedClockSample,
    tests::{certificates, tls::pair},
};
use std::time::UNIX_EPOCH;

#[test]
fn failed_input_keeps_consumption_cursor_and_quarantines_partial_or_extra() {
    let temp = tempfile::tempdir().unwrap();
    let certs = temp.path().join("tls");
    certificates::generate(&certs, 1);
    let pairs: [_; 3] = std::array::from_fn(|_| pair(&certs));
    let config = crate::tests::relay_test_config();
    // Synthetic clock mapping only for this local parser/state test: the
    // immutable +9.5 cutoff is 500ms away, not a claimed UTC qualification.
    let sample = QualifiedClockSample::from_qualified_source(
        UNIX_EPOCH + Duration::from_secs(180_009),
        Instant::now(),
        Duration::ZERO,
    )
    .unwrap();
    let schedule = Rc::new(Schedule::new(&config, 6000, sample).unwrap());
    let cutoff = schedule.at(9_500_000_000).unwrap();
    let mut sessions = Sessions::new(&config);
    let mut senders = Vec::new();
    for (i, (mut client, mut server)) in pairs.into_iter().enumerate() {
        client.queue(RecordSize::Cell, &[0; 8192], cutoff).unwrap();
        while !client.write_step().unwrap() {
            std::thread::sleep(Duration::from_micros(100));
        }
        server.expect(RecordSize::Cell, cutoff).unwrap();
        if i == 0 {
            while server.read_step().unwrap().is_none() {
                std::thread::sleep(Duration::from_micros(100));
            }
            // Actual first record consumed before hypothetical semantic failure.
            // The drainer must not consume this extra record as the first one.
            client.queue(RecordSize::Cell, &[0; 8192], cutoff).unwrap();
            while !client.write_step().unwrap() {
                std::thread::sleep(Duration::from_micros(100));
            }
        } else if i == 1 {
            // Exact parser first consumes the five-byte header, not the body.
            while server.receive_progress() == ReceiveProgress::WaitingZeroBytes {
                assert!(server.read_step().unwrap().is_none());
                std::thread::sleep(Duration::from_micros(100));
            }
            assert!(matches!(
                server.receive_progress(),
                ReceiveProgress::Partial { .. }
            ));
        }
        sessions
            .insert(AdmittedSession {
                transport: server,
                token: [u8::try_from(i).unwrap(); 32],
                config: config.id(),
                slot: u8::try_from(i).unwrap(),
            })
            .unwrap();
        senders.push(client);
    }
    let mut received = [false; 32];
    received[0] = true;
    let mut failed = FailedSessions::new(sessions, schedule, [true; 32], received, None);
    assert_eq!(failed.sessions.unavailable_slots(), 0b010);
    while !failed.poll().unwrap() {
        std::thread::sleep(
            failed
                .next_wake()
                .unwrap()
                .saturating_duration_since(Instant::now()),
        );
    }
    assert!(failed.received[0] && failed.received[2]);
    let sessions = failed.finish().unwrap();
    assert_eq!(sessions.unavailable_slots(), 0b011);
    assert_eq!(
        sessions.entries[2].transport.receive_progress(),
        ReceiveProgress::Idle
    );
    assert!(!sessions.failed); // Round-local failure did not clear/set epoch identity admission.
    assert_eq!(senders.len(), 3); // Peers stay open until all cutoff checks complete.
}
