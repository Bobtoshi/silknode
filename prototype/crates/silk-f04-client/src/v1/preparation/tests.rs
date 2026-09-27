//! Scheduling/ownership checks only: no transfer proof or work is generated.
#![allow(clippy::missing_panics_doc)]
use super::*;
use crate::v1::{
    LocalViewV1, Phase, Round,
    tests::{Clock, fixture::Fixture, owner},
};
use silk_f04_relay::{
    frame::{Frame, Payload, RoundContext, client_cell, open_a, open_b},
    tls::RecordSize,
};
use silk_f04_wallet::journal::intents::IntentStatus;
use std::{rc::Rc, sync::mpsc, time::Instant};

fn receipt() -> IntentReceipt {
    IntentReceipt {
        address_head: [1; 32],
        intent_head: [2; 32],
        status: IntentStatus::Reserved,
    }
}

#[test]
fn preparation_types_cross_worker_without_moving_node() {
    fn send<T: Send>() {}
    fn sync<T: Sync>() {}
    send::<ReadyWalletView<'_>>();
    send::<&mut IntentJournal<'_, '_>>();
    sync::<SaplingParameters>();
}

#[test]
fn preparation_preserves_receipt_when_driver_fails_and_never_retries() {
    let (release, wait) = mpsc::sync_channel(1);
    let mut drives = 0;
    let report = run_scoped(
        move || {
            wait.recv_timeout(Duration::from_secs(2)).unwrap();
            Ok(receipt())
        },
        || {
            drives += 1;
            release.try_send(()).unwrap();
            Err(DriveError::Unavailable("synthetic clock unavailable"))
        },
    );
    let receipt = report.wallet.unwrap();
    assert_eq!(receipt.intent_head, [2; 32]);
    assert!(report.first_drive_error.is_some());
    assert_eq!(drives, 1);

    let report = run_scoped(
        || Err(WalletError::Unavailable("synthetic preparation refusal")),
        || Ok(()),
    );
    assert!(report.wallet.is_err());
    let report = run_scoped(|| panic!("synthetic wallet worker panic"), || Ok(()));
    assert!(report.wallet.is_err());
}

#[test]
fn preparation_blocked_worker_does_not_stop_actual_fixed_cover_write() {
    let f = Fixture::new();
    let manifest = f.manifest();
    let context = RoundContext::new(&f.config, &manifest).unwrap();
    let frame = client_cell(&context, &Payload::cover()).unwrap();
    let expected = *frame.bytes();
    let (link, mut remote) = f.pair();
    let mut client = owner(&f, Some(link));
    let clock = Clock::at(1010 + i64::from(client.slot) * 250);
    let schedule = clock.schedule(&f.config);
    remote
        .expect(
            RecordSize::Cell,
            schedule
                .at(1_250_000_000 + i64::from(client.slot) * 250_000_000)
                .unwrap(),
        )
        .unwrap();
    // Prepared genuine cover at the established send boundary. This isolated
    // clock state does not claim another elapsed30-second lifecycle acceptance.
    client.rounds[0] = Some(Round {
        schedule: Rc::new(schedule),
        link: client.link.as_ref().map(Rc::clone),
        view: LocalViewV1::Genesis(Rc::clone(&f.genesis)),
        offer: None,
        phase: Phase::Selected(frame, false),
    });
    let mut process = ProcessV1::new(client);
    let (release, wait) = mpsc::sync_channel(1);
    let mut received = None;
    let deadline = Instant::now() + Duration::from_secs(2);
    let report = run_scoped(
        move || {
            wait.recv_timeout(Duration::from_secs(2)).unwrap();
            Ok(receipt()) // Intentionally late; only a receipt can cross back.
        },
        || {
            assert!(Instant::now() < deadline);
            process.poll(&clock.sample())?;
            if received.is_none()
                && let Some(bytes) = remote.read_step()?
            {
                received = Some(bytes);
                release.try_send(()).unwrap();
            }
            Ok(())
        },
    );
    assert!(report.wallet.is_ok());
    assert!(report.first_drive_error.is_none());
    let bytes = received.unwrap();
    assert_eq!(&bytes[..], &expected);
    let delivered = Frame::decode(&bytes, &context, 1, 0).unwrap();
    assert!(
        !open_b(&context, &f.b, &open_a(&context, &f.a, &delivered).unwrap())
            .unwrap()
            .is_real()
    );
    assert!(process.take_outcome().is_none()); // +22 has not arrived.
    assert!(!remote.has_extra_bytes().unwrap());
    // No exported offer was available to replace the already-selected cover.
}
