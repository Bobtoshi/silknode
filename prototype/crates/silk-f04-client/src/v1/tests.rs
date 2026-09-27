//! Focused local/synthetic-clock checks, not valid payments or qualified UTC.
#![allow(clippy::missing_panics_doc)]
use super::*;
use silk_f04_relay::frame::{open_a, open_b};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
pub(super) mod fixture;
use fixture::Fixture;

pub(super) struct Clock {
    mono: Instant,
    utc: SystemTime,
}
impl Clock {
    pub(super) fn at(offset_ms: i64) -> Self {
        Self::for_round(6000, offset_ms)
    }
    pub(super) fn for_round(round: u64, offset_ms: i64) -> Self {
        let origin = UNIX_EPOCH + Duration::from_secs(round * 30);
        Self {
            mono: Instant::now(),
            utc: if offset_ms < 0 {
                origin - Duration::from_millis(offset_ms.unsigned_abs())
            } else {
                origin + Duration::from_millis(offset_ms.unsigned_abs())
            },
        }
    }
    pub(super) fn sample(&self) -> QualifiedClockSample {
        let now = Instant::now();
        QualifiedClockSample::from_qualified_source(
            self.utc + now.duration_since(self.mono),
            now,
            Duration::from_millis(1),
        )
        .unwrap()
    }
    pub(super) fn schedule(&self, config: &SignedConfig) -> Schedule {
        Schedule::new(config, 6000, self.sample()).unwrap()
    }
}

#[test]
fn client_enrollment_owns_actual_tcp_tls_join_and_derives_roster_slot() {
    use silk_f04_relay::tls::{ClientProfile, SetupStep};
    let f = Fixture::new();
    let profile = ClientProfile::new(f.config.endpoints()[0], f.roots()).unwrap();
    // Refusal is before connect, including a late setup and an unknown token.
    let late = Clock::for_round(5760, -29_000);
    assert!(
        EnrollmentV1::start(
            Rc::clone(&f.config),
            f.hashes,
            Zeroizing::new([0; 32]),
            profile.clone(),
            late.sample()
        )
        .is_err()
    );
    let clock = Clock::for_round(5760, -45_000);
    assert!(
        EnrollmentV1::start(
            Rc::clone(&f.config),
            f.hashes,
            Zeroizing::new([201; 32]),
            profile.clone(),
            clock.sample()
        )
        .is_err()
    );
    let mut pending = Some(
        EnrollmentV1::start(
            Rc::clone(&f.config),
            f.hashes,
            Zeroizing::new([0; 32]),
            profile,
            clock.sample(),
        )
        .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut server = Some(f.accept_setup(deadline));
    let mut connected = None;
    let mut remote = None;
    while connected.is_none() || remote.is_none() {
        assert!(Instant::now() < deadline);
        if let Some(enrollment) = pending.take() {
            match enrollment.poll(&clock.sample()).unwrap() {
                EnrollmentProgressV1::Pending(enrollment) => pending = Some(enrollment),
                EnrollmentProgressV1::Joined(client) => connected = Some(client),
            }
        }
        if let Some(setup) = server.take() {
            match setup.poll().unwrap() {
                SetupStep::Pending(setup) => server = Some(setup),
                SetupStep::Established(link) => remote = Some(link),
            }
        }
    }
    let mut remote = remote.unwrap();
    remote.expect(RecordSize::Join, deadline).unwrap();
    let join = loop {
        if let Some(bytes) = remote.read_step().unwrap() {
            break bytes;
        }
    };
    let roster = Roster::verify(f.hashes, &f.config).unwrap();
    let hash = roster.verify_join(&join, &f.config).unwrap();
    assert_eq!(connected.as_ref().unwrap().slot, roster.slot(&hash).unwrap());
    assert!(!remote.has_extra_bytes().unwrap());
}
pub(super) fn owner(f: &Fixture, link: Option<Transport>) -> ClientV1 {
    let (join, slot) =
        super::enrollment::enrollment_bytes(&f.config, f.hashes, Zeroizing::new([0; 32])).unwrap();
    ClientV1 {
        config: Rc::clone(&f.config),
        slot,
        link: link.map(|link| Rc::new(RefCell::new(link))),
        profile: ClientProfile::new(f.config.endpoints()[0], f.roots()).unwrap(),
        join,
        eligible: 5760,
        last_closed: None,
        highest: None,
        rounds: std::array::from_fn(|_| None),
        outcomes: [None, None],
    }
}
fn round(f: &Fixture, clock: &Clock, phase: Phase) -> Round {
    Round {
        schedule: Rc::new(clock.schedule(&f.config)),
        link: None,
        view: LocalViewV1::Genesis(Rc::clone(&f.genesis)),
        offer: None,
        phase,
    }
}

#[test]
fn client_selection_preserves_exact_bytes_or_fresh_cover_for_each_binding_mismatch() {
    let f = Fixture::new();
    let manifest = f.manifest();
    let context = RoundContext::new(&f.config, &manifest).unwrap();
    let original = f.envelope();
    let payload = select_payload(Some(Zeroizing::new(original)), f.config.domain(), &context);
    assert_eq!(payload.real_bytes(), Some(&original));
    let frame = client_cell(&context, &payload).unwrap();
    assert_eq!(
        open_b(&context, &f.b, &open_a(&context, &f.a, &frame).unwrap())
            .unwrap()
            .real_bytes(),
        Some(&original)
    );
    // N, c, Kc and Rc independently mismatch; no altered envelope is transmitted.
    for at in [12, 44, 52, 1798] {
        let mut altered = original;
        altered[at] ^= 1;
        let cover = select_payload(Some(Zeroizing::new(altered)), f.config.domain(), &context);
        assert!(!cover.is_real());
        let frame = client_cell(&context, &cover).unwrap();
        assert!(
            !open_b(&context, &f.b, &open_a(&context, &f.a, &frame).unwrap())
                .unwrap()
                .is_real()
        );
    }
    let first = client_cell(&context, &select_payload(None, f.config.domain(), &context)).unwrap();
    let second = client_cell(&context, &select_payload(None, f.config.domain(), &context)).unwrap();
    assert_ne!(
        first.encapsulation().unwrap(),
        second.encapsulation().unwrap()
    );
}

#[test]
fn client_manifest_uses_its_own_local_cut_then_selects_cover_not_offer_cut() {
    let f = Fixture::new();
    let clock = Clock::at(100);
    let (mut client, mut server) = f.pair();
    let deadline = clock.schedule(&f.config).at(1_000_000_000).unwrap();
    client.expect(RecordSize::Manifest, deadline).unwrap();
    server
        .queue(RecordSize::Manifest, f.manifest().bytes(), deadline)
        .unwrap();
    while !server.write_step().unwrap() {}
    let mut attempt = round(&f, &clock, Phase::Reading);
    let mut different_cut = f.envelope();
    different_cut[44] = 1; // Offered cut differs, M's genesis cut is genuinely admitted.
    attempt.offer = Some(Zeroizing::new(different_cut));
    while matches!(attempt.phase, Phase::Reading) {
        attempt.poll(&f.config, 0, &mut client).unwrap();
    }
    let Phase::Selected(frame, real) = &attempt.phase else {
        panic!("not selected")
    };
    assert!(!real);
    assert!(attempt.offer.is_none());
    let manifest = f.manifest();
    let context = RoundContext::new(&f.config, &manifest).unwrap();
    assert!(
        !open_b(&context, &f.b, &open_a(&context, &f.a, frame).unwrap())
            .unwrap()
            .is_real()
    );
}

#[test]
fn client_bad_signature_or_foreign_local_cut_never_selects_a_cell() {
    let f = Fixture::new();
    for foreign_cut in [false, true] {
        let clock = Clock::at(100);
        let (mut client, mut server) = f.pair();
        let mut bytes = *f.manifest().bytes();
        if foreign_cut {
            bytes[60] ^= 1;
            f.sign_manifest(&mut bytes);
        } else {
            bytes[128] ^= 1;
        }
        let mut attempt = round(&f, &clock, Phase::Reading);
        attempt.offer = Some(Zeroizing::new(f.envelope()));
        let deadline = attempt.schedule.at(1_000_000_000).unwrap();
        client.expect(RecordSize::Manifest, deadline).unwrap();
        server
            .queue(RecordSize::Manifest, &bytes, deadline)
            .unwrap();
        while !server.write_step().unwrap() {}
        loop {
            if attempt.poll(&f.config, 0, &mut client).is_err() {
                break;
            }
            assert!(matches!(attempt.phase, Phase::Reading));
        }
        attempt.fail();
        assert!(matches!(
            attempt.phase,
            Phase::Finished(WriteStatusV1::Silent)
        ));
        assert!(attempt.offer.is_none());
        assert!(!server.has_extra_bytes().unwrap());
    }
}

#[test]
fn client_selected_record_writes_once_and_failure_cannot_turn_it_into_cover() {
    let f = Fixture::new();
    let manifest = f.manifest();
    let context = RoundContext::new(&f.config, &manifest).unwrap();
    let frame = client_cell(
        &context,
        &select_payload(
            Some(Zeroizing::new(f.envelope())),
            f.config.domain(),
            &context,
        ),
    )
    .unwrap();
    let expected = *frame.bytes();
    let (mut client, mut server) = f.pair();
    let clock = Clock::at(1010);
    let mut attempt = round(&f, &clock, Phase::Selected(frame, true));
    attempt.poll(&f.config, 0, &mut client).unwrap(); // Encrypt once, no write yet.
    assert!(matches!(attempt.phase, Phase::Writing(true)));
    server
        .expect(
            RecordSize::Cell,
            attempt.schedule.at(1_250_000_000).unwrap(),
        )
        .unwrap();
    while !matches!(attempt.phase, Phase::Finished(_)) {
        attempt.poll(&f.config, 0, &mut client).unwrap();
    }
    let received = loop {
        if let Some(bytes) = server.read_step().unwrap() {
            break bytes;
        }
    };
    assert_eq!(&received[..], &expected);
    for _ in 0..3 {
        attempt.poll(&f.config, 0, &mut client).unwrap();
    }
    assert!(!server.has_extra_bytes().unwrap());
    assert!(matches!(
        attempt.phase,
        Phase::Finished(WriteStatusV1::RealWriteComplete)
    ));
    let mut uncertain = round(&f, &clock, Phase::Writing(true));
    uncertain.fail();
    uncertain.fail();
    assert!(matches!(
        uncertain.phase,
        Phase::Finished(WriteStatusV1::WriteUncertain)
    ));
}

#[test]
fn client_admission_is_once_only_and_outcomes_wait_for_fixed_cleanup() {
    let f = Fixture::new();
    let clock = Clock::at(-9000);
    let mut client = owner(&f, None);
    client
        .admit_bytes(
            clock.schedule(&f.config),
            LocalViewV1::Genesis(Rc::clone(&f.genesis)),
            Some(Zeroizing::new(f.envelope())),
        )
        .unwrap();
    assert!(
        client
            .admit_bytes(
                clock.schedule(&f.config),
                LocalViewV1::Genesis(Rc::clone(&f.genesis)),
                None
            )
            .is_err()
    );
    client.poll(&clock.sample()).unwrap(); // Missing connection => silent, not retry.
    assert!(client.take_outcome().is_none());
    let active = client.rounds.iter().flatten().next().unwrap();
    assert!(active.offer.is_none());
    assert!(matches!(
        active.phase,
        Phase::Finished(WriteStatusV1::Silent)
    ));
    // Isolated cleanup-boundary unit state, not a claim of a real 30-second run.
    let clock = Clock::at(22_001);
    client.rounds[0] = Some(round(&f, &clock, Phase::Finished(WriteStatusV1::Silent)));
    client.poll(&clock.sample()).unwrap();
    assert_eq!(
        client.take_outcome(),
        Some(OutcomeV1 {
            round: 6000,
            status: WriteStatusV1::Silent
        })
    );
    assert!(client.take_outcome().is_none());
    assert!(client.rounds.iter().all(Option::is_none));
    let clock = Clock::at(1_001);
    let (mut link, server) = f.pair();
    let mut late = round(&f, &clock, Phase::Waiting);
    assert!(late.poll(&f.config, 0, &mut link).is_err());
    late.fail();
    assert!(matches!(late.phase, Phase::Finished(WriteStatusV1::Silent)));
    assert!(!server.has_extra_bytes().unwrap());
}
