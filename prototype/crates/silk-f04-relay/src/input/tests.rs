//! Real TLS/HPKE collection with a synthetic clock/context, not native anonymity.
use super::*;
use crate::{
    frame::generate_hpke_key,
    manifest::SignedManifest,
    message,
    negotiation::Manifested,
    schedule::Schedule,
    tests::{certificates, relay_test_config, tls::pair},
};
use ed25519_dalek::SigningKey;
use silk_f04_node::auth::sign_role;
use std::time::{Duration, UNIX_EPOCH};

fn context() -> (Rc<SignedConfig>, SignedManifest, Rc<HpkePrivate>) {
    let initial = relay_test_config();
    let (a, ap) = generate_hpke_key().unwrap();
    let (_, bp) = generate_hpke_key().unwrap();
    let keys = [31, 32].map(|n| SigningKey::from_bytes(&[n; 32]));
    let mut bytes = *initial.bytes();
    bytes[128..160].copy_from_slice(&ap);
    bytes[160..192].copy_from_slice(&bp);
    let signed = message("SilkNode-F0-config-sign", &[&bytes[..642]]);
    for i in 0..2 {
        bytes[642 + 64 * i..706 + 64 * i].copy_from_slice(&sign_role(&keys[i], &signed).unwrap());
    }
    let config = Rc::new(
        SignedConfig::verify(
            &bytes,
            initial.domain(),
            3,
            2,
            keys.each_ref().map(|k| k.verifying_key().to_bytes()),
        )
        .unwrap(),
    );
    let mut manifest = [0; 256];
    manifest[..8].copy_from_slice(b"SNRNDF03");
    manifest[8..40].copy_from_slice(&config.domain());
    manifest[40..44].copy_from_slice(&3_u32.to_le_bytes());
    manifest[44..52].copy_from_slice(&6000_u64.to_le_bytes());
    let signed = message("SilkNode-F0-round", &[&config.id(), &manifest[..128]]);
    for i in 0..2 {
        manifest[128 + 64 * i..192 + 64 * i]
            .copy_from_slice(&sign_role(&keys[i], &signed).unwrap());
    }
    let manifest = SignedManifest::verify(&manifest, &config, 6000).unwrap();
    (config, manifest, Rc::new(a))
}

#[test]
fn actual_strict_tls_collection_seals_only_after_all_32_hpke_cells() {
    let temp = tempfile::tempdir().unwrap();
    let certs = temp.path().join("tls");
    certificates::generate(&certs, 1);
    let (config, manifest, key) = context();
    let cells: Vec<_> = (0..32)
        .map(|_| {
            client_cell(
                &crate::frame::RoundContext::new(&config, &manifest).unwrap(),
                &Payload::cover(),
            )
            .unwrap()
        })
        .collect();
    let pairs: Vec<_> = (0..32).map(|_| pair(&certs)).collect();
    // The setup is deliberately synthetic. Only the following actual transport,
    // framing/HPKE/completion/seal path is under test, not UTC qualification.
    let sample = QualifiedClockSample::from_qualified_source(
        UNIX_EPOCH + Duration::from_secs(180_000),
        Instant::now(),
        Duration::ZERO,
    )
    .unwrap();
    let schedule = Rc::new(Schedule::new(&config, 6000, sample).unwrap());
    let bound = ManifestRound::new(
        Rc::clone(&config),
        Manifested::input_fixture(manifest),
        Rc::clone(&schedule),
    )
    .unwrap();
    let mut sessions = Sessions::new(&config);
    sessions.delivery_round = Some(6000);
    sessions.delivered_manifest = Some(bound.manifest().id());
    let mut senders = Vec::new();
    for (slot, (client, server)) in pairs.into_iter().enumerate() {
        sessions
            .insert(AdmittedSession {
                transport: server,
                token: [u8::try_from(slot).unwrap(); 32],
                config: config.id(),
                slot: u8::try_from(slot).unwrap(),
            })
            .unwrap();
        senders.push(client);
    }
    let mut input = InputCollector::new_strict(sessions, Rc::clone(&bound), key).unwrap();
    // Before any reads, a fabricated output count cannot mint provenance.
    assert!(
        input
            .completed_slots
            .finish(32, 32, config.id(), bound.manifest().id(), 6000)
            .is_err()
    );
    std::thread::sleep(
        schedule
            .at(8_000_000_000)
            .unwrap()
            .saturating_duration_since(Instant::now()),
    );
    let cutoff = schedule.at(9_500_000_000).unwrap();
    for (sender, cell) in senders.iter_mut().zip(&cells) {
        sender
            .queue(RecordSize::Cell, cell.bytes(), cutoff)
            .unwrap();
        while !sender.write_step().unwrap() {
            std::thread::sleep(Duration::from_micros(100));
        }
    }
    while input.output.len() != 32 {
        input.poll().unwrap();
        std::thread::sleep(Duration::from_micros(100));
    }
    assert!(
        input
            .completed_slots
            .finish(32, 32, config.id(), bound.manifest().id(), 6000)
            .is_ok()
    );
    std::thread::sleep(cutoff.saturating_duration_since(Instant::now()));
    let (sessions, strict) = input.seal_strict().unwrap();
    assert_eq!(sessions.len(), 32);
    let (batch, _completion) = strict
        .into_bound(config.id(), bound.manifest().id(), 6000)
        .unwrap();
    assert_eq!(batch.admitted(), 32);
    assert_eq!(batch.frames().len(), 32);
}
