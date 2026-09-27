//! Local lifecycle state/TLS checks; no new native relay or qualified-clock run.
use super::*;
use crate::v1::{
    Phase, RefCell, Roster, Round, WriteStatusV1,
    tests::{Clock, fixture::Fixture, owner},
};
use silk_f04_relay::tls::{RecordSize, SetupStep, Transport};
use std::time::{Duration, Instant};

fn finish_setup(process: &mut ProcessV1, f: &Fixture, clock: &Clock) -> Transport {
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut server = Some(f.accept_setup(deadline));
    let mut ready = None;
    while process.pending.iter().any(Option::is_some) || ready.is_none() {
        assert!(Instant::now() < deadline);
        process.poll(&clock.sample()).unwrap();
        if let Some(setup) = server.take() {
            match setup.poll().unwrap() {
                SetupStep::Pending(setup) => server = Some(setup),
                SetupStep::Established(link) => ready = Some(link),
            }
        }
    }
    ready.unwrap()
}

#[test]
fn client_lifecycle_repair_retains_claim_clock_slot_and_future_eligibility() {
    let f = Fixture::new();
    let clock = Clock::at(25_000);
    let original = Rc::new(clock.schedule(&f.config));
    let mut client = owner(&f, None);
    client.highest = Some(6000);
    client.last_closed = Some(Rc::clone(&original));
    let mut process = ProcessV1::new(client);
    let (future, _, _) = f.next_config();
    let foreign_clock = Clock::for_round(8640, -9_000);
    assert!(
        process
            .admit(
                f.config.id(),
                Schedule::new(&future, 8640, foreign_clock.sample()).unwrap(),
                LocalViewV1::Genesis(Rc::clone(&f.genesis)),
                None
            )
            .is_err()
    );
    assert_eq!(process.highest, Some(6000));
    process.repair(f.config.id(), &clock.sample()).unwrap();
    assert!(process.repair(f.config.id(), &clock.sample()).is_err());
    let mut remote = finish_setup(&mut process, &f, &clock);
    remote
        .expect(RecordSize::Join, original.at(28_000_000_000).unwrap())
        .unwrap();
    let join = loop {
        if let Some(bytes) = remote.read_step().unwrap() {
            break bytes;
        }
    };
    let roster = Roster::verify(f.hashes, &f.config).unwrap();
    let hash = roster.verify_join(&join, &f.config).unwrap();
    let repaired = process.clients[0].as_ref().unwrap();
    assert_eq!(repaired.slot, roster.slot(&hash).unwrap());
    assert_eq!(repaired.eligible, 6002);
    assert_eq!(process.highest, Some(6000));
    assert!(repaired.link.is_some());
    assert!(Rc::ptr_eq(
        repaired.last_closed.as_ref().unwrap(),
        &original
    ));
    assert!(process.repair(f.config.id(), &clock.sample()).is_err());
    // Eligibility-only unit probes use their own synthetic future mappings.
    let early = Clock::for_round(6001, -9_000);
    let schedule = Schedule::new(&f.config, 6001, early.sample()).unwrap();
    assert!(
        process
            .admit(
                f.config.id(),
                schedule,
                LocalViewV1::Genesis(Rc::clone(&f.genesis)),
                None
            )
            .is_err()
    );
    let later = Clock::for_round(6002, -9_000);
    let schedule = Schedule::new(&f.config, 6002, later.sample()).unwrap();
    process
        .admit(
            f.config.id(),
            schedule,
            LocalViewV1::Genesis(Rc::clone(&f.genesis)),
            None,
        )
        .unwrap();
    assert_eq!(process.highest, Some(6002));
    assert!(
        process.clients[0]
            .as_ref()
            .unwrap()
            .rounds
            .iter()
            .flatten()
            .next()
            .unwrap()
            .offer
            .is_none()
    );
}

#[test]
fn client_lifecycle_old_missing_snapshot_cannot_close_a_new_connection() {
    let f = Fixture::new();
    let (new_link, remote) = f.pair();
    let mut client = owner(&f, Some(new_link));
    let fresh = Rc::clone(client.link.as_ref().unwrap());
    let clock = Clock::at(22_001);
    client.rounds[0] = Some(Round {
        schedule: Rc::new(clock.schedule(&f.config)),
        link: None,
        view: LocalViewV1::Genesis(Rc::clone(&f.genesis)),
        offer: None,
        phase: Phase::Waiting,
    });
    client.poll(&clock.sample()).unwrap();
    assert!(Rc::ptr_eq(client.link.as_ref().unwrap(), &fresh));
    assert!(!remote.has_extra_bytes().unwrap());
    assert_eq!(client.take_outcome().unwrap().status, WriteStatusV1::Silent);
    assert!(client.last_closed.is_some()); // Outcome consumption does not revoke window.
    let (old, _old_remote) = f.pair();
    let mut old_snapshot = Some(Rc::new(RefCell::new(old)));
    let old_identity = Rc::clone(old_snapshot.as_ref().unwrap());
    crate::v1::close_snapshot(&mut old_snapshot, &mut client.link);
    assert!(old_snapshot.is_none());
    assert_eq!(
        old_identity.borrow().receive_progress(),
        silk_f04_relay::tls::ReceiveProgress::Failed
    );
    assert!(Rc::ptr_eq(client.link.as_ref().unwrap(), &fresh));
    assert_ne!(
        fresh.borrow().receive_progress(),
        silk_f04_relay::tls::ReceiveProgress::Failed
    );
}

#[test]
fn client_lifecycle_epoch_uses_original_q_minus_two_and_preserves_global_limits() {
    let f = Fixture::new();
    let (next, hashes, roots) = f.next_config();
    let profile = ClientProfile::new(next.endpoints()[0], f.roots()).unwrap();
    let original_round = u64::from(next.epoch()) * 2880 - 2;
    let clock = Clock::for_round(original_round, 500);
    let schedule = Rc::new(Schedule::new(&f.config, original_round, clock.sample()).unwrap());
    let mut client = owner(&f, None);
    client.highest = Some(original_round);
    client.rounds[0] = Some(Round {
        schedule: Rc::clone(&schedule),
        link: None,
        view: LocalViewV1::Genesis(Rc::clone(&f.genesis)),
        offer: None,
        phase: Phase::Finished(WriteStatusV1::Silent),
    });
    let mut process = ProcessV1::new(client);
    process
        .prepare_next(
            next.bytes(),
            roots,
            hashes,
            Zeroizing::new([16; 32]),
            profile.clone(),
            &clock.sample(),
        )
        .unwrap();
    assert!(
        process
            .prepare_next(
                next.bytes(),
                roots,
                hashes,
                Zeroizing::new([16; 32]),
                profile,
                &clock.sample()
            )
            .is_err()
    );
    let mut remote = finish_setup(&mut process, &f, &clock);
    remote
        .expect(RecordSize::Join, schedule.at(30_000_000_000).unwrap())
        .unwrap();
    let join = loop {
        if let Some(bytes) = remote.read_step().unwrap() {
            break bytes;
        }
    };
    let roster = Roster::verify(hashes, &next).unwrap();
    let hash = roster.verify_join(&join, &next).unwrap();
    let new = process
        .clients
        .iter()
        .flatten()
        .find(|c| c.config.id() == next.id())
        .unwrap();
    assert_eq!(new.slot, roster.slot(&hash).unwrap());
    assert_ne!(new.slot, process.clients[0].as_ref().unwrap().slot);
    assert_eq!(process.highest, Some(original_round));
    assert_eq!(new.highest, None);
    assert!(Rc::ptr_eq(
        &process.clients[0].as_ref().unwrap().rounds[0]
            .as_ref()
            .unwrap()
            .schedule,
        &schedule
    ));
    // Global bounds are checked before another per-epoch owner could reset them.
    process.clients[1].as_mut().unwrap().outcomes[0] = Some(OutcomeV1 {
        round: original_round - 1,
        status: WriteStatusV1::Silent,
    });
    assert_eq!(process.occupied(), 2);
    let later = Clock::for_round(original_round + 1, -9_000);
    assert!(
        process
            .admit(
                f.config.id(),
                Schedule::new(&f.config, original_round + 1, later.sample()).unwrap(),
                LocalViewV1::Genesis(Rc::clone(&f.genesis)),
                None
            )
            .is_err()
    );
    assert_eq!(process.highest, Some(original_round));
    assert_eq!(process.take_outcome().unwrap().round, original_round - 1);
}
