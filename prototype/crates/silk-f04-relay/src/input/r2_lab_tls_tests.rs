//! Actual local TLS Join/fanout/32-input test. Synthetic signed M and invalid
//! membership proof bytes deliberately isolate A; no B verification, population,
//! epoch admission, genuine proof, operational clock or settlement is claimed.
use super::*;
use crate::{
    aip2_claim::{ClaimPinRetention, ClaimResult, ClaimRole, PreparedScopeStore},
    aip2_profile::ProfileExpectations,
    aip2_proof::{hex, prepare_cover_statement},
    aip2_transport::{PreparedR2Context, seal_claimed_cell},
    config::{Endpoint, Roster, SignedConfig},
    frame::generate_hpke_key,
    input::{Enrolling, Enrollment, ManifestDelivery},
    manifest::SignedManifest,
    message,
    negotiation::Manifested,
    schedule::{Schedule, functional_utc},
    tests::{certificates, epoch_config},
    tls::{SetupStep, Transport, spki_pin},
};
use ed25519_dalek::SigningKey;
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use silk_f04_node::auth::sign_role;
use silk_sapling_f04::codec::domain_hash;
use std::{
    net::{Ipv6Addr, TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::Path,
    time::Duration,
};

struct Pins;
impl ClaimPinRetention for Pins {
    fn retain_claim_pin(&mut self, _: Digest) -> ClaimResult<()> {
        Ok(())
    }
}
fn sleep_until(at: Instant) {
    std::thread::sleep(at.saturating_duration_since(Instant::now()));
}
fn pair(listener: &TcpListener, certs: &Path, endpoint: Endpoint) -> (Transport, Transport) {
    let cert = CertificateDer::from(certificates::leaf_der(certs, 0));
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certificates::private_key_der(
        certs, 0,
    )));
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(certificates::root_der(certs)))
        .unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let server = listener.accept().unwrap().0;
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut pending = [
        Some(Transport::client_setup(client, endpoint, roots, deadline).unwrap()),
        Some(Transport::server_setup(server, endpoint, vec![cert], key, deadline).unwrap()),
    ];
    let mut ready = [None, None];
    while ready.iter().any(Option::is_none) {
        assert!(Instant::now() < deadline);
        for i in 0..2 {
            if let Some(setup) = pending[i].take() {
                match setup.poll().unwrap() {
                    SetupStep::Pending(next) => pending[i] = Some(next),
                    SetupStep::Established(link) => ready[i] = Some(link),
                }
            }
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    (ready[0].take().unwrap(), ready[1].take().unwrap())
}
fn profile(config: &SignedConfig, keys: &[SigningKey; 2], vk_hash: Digest) -> PreparedProfile {
    let expected = ProfileExpectations {
        domain: config.domain(),
        config: config.id(),
        epoch: config.epoch(),
        cohort: config.cohort(),
        vk_hash,
        role_keys: keys.each_ref().map(|k| k.verifying_key().to_bytes()),
    };
    let mut p = [0; 1312];
    p[..8].copy_from_slice(b"SNAIP004");
    p[8..40].copy_from_slice(&expected.domain);
    p[40..72].copy_from_slice(&expected.config);
    p[72..76].copy_from_slice(&expected.epoch.to_le_bytes());
    p[76..80].copy_from_slice(&expected.cohort.to_le_bytes());
    let first = u64::from(expected.epoch) * 2880;
    p[80..88].copy_from_slice(&first.to_le_bytes());
    p[88..96].copy_from_slice(&(first + 2880).to_le_bytes());
    p[96..128].copy_from_slice(&vk_hash);
    // Existing cross-language root of the public scalars 1..=32. This is NOT a
    // usable membership credential or a trusted key/ceremony fixture.
    p[128..160].copy_from_slice(
        &hex::<32>("2ac136f871e2d83be9f7d93b8689865e5603d76d02185da93291e3fba44520b2").unwrap(),
    );
    for i in 0..32 {
        p[191 + 32 * i] = (i + 1) as u8;
    }
    let signed = message("SilkNode-AIP2R2-profile-sign", &[&p[..1184]]);
    for i in 0..2 {
        p[1184 + 64 * i..1248 + 64 * i].copy_from_slice(&sign_role(&keys[i], &signed).unwrap());
    }
    PreparedProfile::verify(&p, &expected).unwrap()
}

// Explicitly selected: this test waits for an actual host-UTC round and uses
// native RoundGuard timers. Ordinary unit runs must not silently incur that wait.
#[test]
#[ignore = "VPS-only actual TLS/UTC collector; run explicitly under native resource containment"]
fn actual_tls_join_fanout_and_all32_outer_cells_mint_one_receipt() {
    let temp = tempfile::tempdir().unwrap();
    let certs = temp.path().join("tls");
    certificates::generate(&certs, 1);
    let listener = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
    // Leave at least 14 seconds for bounded 32-session setup before the original
    // -10 guard deadline; no shifted UTC, rebasing or test-only clock bypass.
    let now = functional_utc().unwrap().as_secs();
    let round_number = (now + 54) / 30;
    let epoch = u32::try_from(round_number / 2880).unwrap();
    let initial = epoch_config(epoch);
    let keys = [31, 32].map(|n| SigningKey::from_bytes(&[n; 32]));
    let (a_key, a_public) = generate_hpke_key().unwrap();
    let (_, b_public) = generate_hpke_key().unwrap();
    let mut bytes = *initial.bytes();
    bytes[128..160].copy_from_slice(&a_public);
    bytes[160..192].copy_from_slice(&b_public);
    bytes[192..208].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
    bytes[208..210].copy_from_slice(&listener.local_addr().unwrap().port().to_le_bytes());
    bytes[242..274].copy_from_slice(
        &spki_pin(&CertificateDer::from(certificates::leaf_der(&certs, 0))).unwrap(),
    );
    let signed = message("SilkNode-F0-config-sign", &[&bytes[..642]]);
    for i in 0..2 {
        bytes[642 + 64 * i..706 + 64 * i].copy_from_slice(&sign_role(&keys[i], &signed).unwrap());
    }
    let config = Rc::new(
        SignedConfig::verify(
            &bytes,
            initial.domain(),
            3,
            epoch,
            keys.each_ref().map(|k| k.verifying_key().to_bytes()),
        )
        .unwrap(),
    );
    let mut hashes = std::array::from_fn(|i| domain_hash("SilkNode-F0-token", &[&[i as u8; 32]]));
    hashes.sort_unstable();
    let roster = Roster::verify(hashes, &config).unwrap();
    let vk_hash = [0x91; 32];
    let profile = profile(&config, &keys, vk_hash);
    let schedule = Rc::new(Schedule::functional_fixture(&config, round_number).unwrap());
    let setup_end = schedule.at(-10_000_000_000).unwrap();
    let mut sessions = Sessions::new(&config);
    let mut senders = Vec::new();
    for token in 0..32_u8 {
        let (mut client, server) = pair(&listener, &certs, config.endpoints()[0]);
        let mut join = [0; 128];
        join[..8].copy_from_slice(b"SNJOIN03");
        join[8..40].copy_from_slice(&config.domain());
        join[40..44].copy_from_slice(&config.cohort().to_le_bytes());
        join[44..48].copy_from_slice(&epoch.to_le_bytes());
        join[48..80].fill(token);
        let slot = roster
            .slot(&roster.verify_join(&join, &config).unwrap())
            .unwrap();
        let join_end = setup_end.min(Instant::now() + Duration::from_secs(5));
        client.queue(RecordSize::Join, &join, join_end).unwrap();
        while !client.write_step().unwrap() {
            std::thread::sleep(Duration::from_micros(100));
        }
        let mut enrolling = Enrolling::new(server, join_end).unwrap();
        loop {
            match enrolling.poll(&config, &roster).unwrap() {
                Enrollment::Pending(next) => enrolling = next,
                Enrollment::Admitted(session) => {
                    sessions.insert(session).unwrap();
                    break;
                }
            }
            std::thread::sleep(Duration::from_micros(100));
        }
        senders.push((slot, client));
    }
    drop(listener);
    senders.sort_by_key(|(slot, _)| *slot);
    let guard = Rc::new(RoundGuard::arm(&schedule).unwrap());
    let mut m = [0; 256];
    m[..8].copy_from_slice(b"SNRNDF03");
    m[8..40].copy_from_slice(&config.domain());
    m[40..44].copy_from_slice(&config.cohort().to_le_bytes());
    m[44..52].copy_from_slice(&round_number.to_le_bytes());
    let signed = message("SilkNode-F0-round", &[&config.id(), &m[..128]]);
    for i in 0..2 {
        m[128 + 64 * i..192 + 64 * i].copy_from_slice(&sign_role(&keys[i], &signed).unwrap());
    }
    let manifest = SignedManifest::verify(&m, &config, round_number).unwrap();
    let round = ManifestRound::new(
        Rc::clone(&config),
        Manifested::input_fixture(manifest),
        Rc::clone(&schedule),
    )
    .unwrap();
    let context = PreparedR2Context::new(&config, round.manifest(), &profile, vk_hash).unwrap();
    let statement = prepare_cover_statement(&profile, round.manifest().id(), round_number).unwrap();
    let mut frames = Vec::new();
    for i in 0..32 {
        let path = temp.path().join(format!("scope-{i}"));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut store =
            PreparedScopeStore::create(&path, profile.claim_binding(ClaimRole::Client), Pins)
                .unwrap();
        let mut cell = *statement.cell();
        cell[159] = (i + 1) as u8;
        // Intentionally zero/INVALID proof. A cannot and must not open B or mint
        // membership authority merely from 32 actual authenticated TLS records.
        let claim = store
            .consume(round_number, round.manifest().id(), statement.message())
            .unwrap();
        frames.push(seal_claimed_cell(&context, claim, &cell).unwrap());
    }
    let mut delivery = ManifestDelivery::new(sessions, Rc::clone(&round)).unwrap();
    sleep_until(schedule.at(-8_000_000_000).unwrap());
    for (_, sender) in &mut senders {
        sender
            .expect(RecordSize::Manifest, schedule.at(-7_000_000_000).unwrap())
            .unwrap();
    }
    while !delivery.poll().unwrap() {
        std::thread::sleep(Duration::from_micros(500));
    }
    for (_, sender) in &mut senders {
        loop {
            if let Some(received) = sender.read_step().unwrap() {
                assert_eq!(received.as_slice(), &m);
                break;
            }
            std::thread::sleep(Duration::from_micros(100));
        }
    }
    let sessions = delivery.finish().unwrap();
    let mut collector = R2InputCollectorLab::new(
        sessions,
        Rc::clone(&round),
        &profile,
        vk_hash,
        Rc::new(a_key),
        Rc::clone(&guard),
    )
    .unwrap();
    assert!(
        collector
            .slots
            .finish(32, 32, config.id(), round.manifest().id(), round_number)
            .is_err()
    );
    let mut sent = 0;
    while Instant::now() < schedule.at(INPUT_END).unwrap() {
        if sent < 32
            && Instant::now()
                >= schedule
                    .at(1_000_000_000 + sent as i64 * 200_000_000)
                    .unwrap()
        {
            let deadline = schedule
                .at(1_200_000_000 + sent as i64 * 200_000_000)
                .unwrap();
            senders[sent]
                .1
                .queue(RecordSize::Cell, frames[sent].bytes(), deadline)
                .unwrap();
            while !senders[sent].1.write_step().unwrap() {
                std::thread::sleep(Duration::from_micros(100));
            }
            sent += 1;
        }
        // Leave the original barrier to seal; no post-cutoff read or extra peek.
        if Instant::now() < schedule.at(INPUT_END).unwrap() {
            collector.poll().unwrap();
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(sent, 32);
    assert_eq!(collector.output.len(), 32);
    let (sessions, collected) = collector.seal().unwrap();
    assert_eq!(sessions.len(), 32);
    let (same_round, received, id, same_guard, _completion) = collected.into_bound();
    assert!(Rc::ptr_eq(&same_round, &round));
    assert!(Rc::ptr_eq(&same_guard, &guard));
    assert_eq!(received.len(), 32);
    assert_eq!(id, prepared_a_batch_id(&context, &received).unwrap());
    assert!(
        received
            .iter()
            .all(|f| PreparedR2Frame::decode(f.bytes(), &context, 2).is_ok())
    );
    guard.check().unwrap();
    drop(same_guard);
    drop(guard);
}
