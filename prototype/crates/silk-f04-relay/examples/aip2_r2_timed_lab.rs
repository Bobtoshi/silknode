//! One explicit same-operator/private-network R2 PAYMENT round, not activation.
//! Historical precomputed path or explicit actual TLS collection path. Neither
//! mode establishes independent clients, qualified clocks or operational admission.
#[allow(dead_code)]
#[path = "../../silk-node/tests/support/private_relay_test_certificates.rs"]
mod certificates;
use ed25519_dalek::SigningKey;
use hpke::Deserializable;
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use silk_f04_node::genesis::Genesis;
use silk_f04_relay::{
    aip2_claim::{ClaimPinRetention, ClaimResult, ClaimRole, PreparedScopeStore},
    aip2_profile::{PreparedProfile, ProfileExpectations},
    aip2_proof::{PreparedProofVerifier, hex},
    aip2_transport::{PreparedR2Context, PreparedR2Frame},
    config::{Roster, SignedConfig},
    control::Role,
    exit::{ExitProgress, ExitRound},
    frame::HpkePrivate,
    handoff::v1::ProducerInboxV1,
    input::{Enrolling, Enrollment, ManifestDelivery, Sessions, r2_lab::R2InputCollectorLab},
    journal::Journal,
    lane::BControlLane,
    negotiation::{AProposal, Manifested, SelectedCut},
    owner::{DurableJournal, Identity, ManifestRound, PinRetention},
    producer::ProducerRound,
    resources::RoleResources,
    runtime::RoundGuard,
    schedule::{Schedule, functional_utc},
    source::{SourceProgress, SourceRound},
    tls::{Listener, RecordSize, ServerProfile, SetupStep, Transport, spki_pin},
};
use silk_sapling_f04::{codec::Envelope, parameters::SaplingVerificationKeys};
use std::{
    fs,
    io::Write,
    net::{Ipv6Addr, SocketAddr, TcpStream},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    rc::Rc,
    thread,
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const TICK: Duration = Duration::from_micros(500);
fn write_new(p: &Path, b: &[u8]) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(p)?;
    f.write_all(b)?;
    f.sync_all()?;
    fs::File::open(p.parent().ok_or("parent")?)?.sync_all()?;
    Ok(())
}
fn directory(p: &Path) -> Result<()> {
    fs::create_dir(p)?;
    fs::set_permissions(p, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
fn read(p: &Path, cap: u64) -> Result<Vec<u8>> {
    let m = fs::symlink_metadata(p)?;
    if !m.is_file() || m.len() > cap {
        return Err("lab bounded regular file".into());
    }
    Ok(fs::read(p)?)
}
struct Pins(PathBuf);
impl Pins {
    fn persist(&mut self, pin: [u8; 32]) -> std::io::Result<()> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&self.0)?;
        f.write_all(&pin)?;
        f.sync_all()?;
        fs::File::open(self.0.parent().unwrap())?.sync_all()
    }
}
impl PinRetention for Pins {
    fn retain(&mut self, pin: [u8; 32]) -> silk_f04_relay::Result<()> {
        Ok(self.persist(pin)?)
    }
}
impl ClaimPinRetention for Pins {
    fn retain_claim_pin(&mut self, pin: [u8; 32]) -> ClaimResult<()> {
        Ok(self.persist(pin)?)
    }
}
struct Public {
    config: Rc<SignedConfig>,
    profile: Rc<PreparedProfile>,
    verifier: Rc<PreparedProofVerifier>,
    genesis: Rc<Genesis>,
    roots: RootCertStore,
    round: u64,
}
impl Public {
    fn load(root: &Path) -> Result<Self> {
        let e: serde_json::Value =
            serde_json::from_slice(&read(&root.join("expected.json"), 4096)?)?;
        let domain = hex(e["domain"].as_str().ok_or("N")?)?;
        let epoch = u32::try_from(e["epoch"].as_u64().ok_or("epoch")?)?;
        let round = e["round"].as_u64().ok_or("round")?;
        let role_keys = [
            hex(e["role_keys"][0].as_str().ok_or("A")?)?,
            hex(e["role_keys"][1].as_str().ok_or("B")?)?,
        ];
        let config = Rc::new(SignedConfig::verify(
            &read(&root.join("config.bin"), 770)?,
            domain,
            7,
            epoch,
            role_keys,
        )?);
        let vk_hash = hex(e["vk_hash"].as_str().ok_or("VK")?)?;
        let profile = Rc::new(PreparedProfile::verify(
            &read(&root.join("profile.bin"), 1312)?,
            &ProfileExpectations {
                domain,
                config: config.id(),
                epoch,
                cohort: 7,
                vk_hash,
                role_keys,
            },
        )?);
        let verifier = Rc::new(PreparedProofVerifier::from_canonical_vk(
            &read(&root.join("vk-canonical.json"), 16384)?,
            vk_hash,
        )?);
        // Existing private/valueless public genesis, separately re-admitted by
        // every actor. A sender's M or a caller's arbitrary root is not a cut.
        let genesis = Rc::new(Genesis::admit_local_bundle(
            &read(&root.join("public-genesis"), 8 * 1024 * 1024)?,
            &domain,
            true,
        )?);
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(read(
            &root.join("tls/root.der"),
            16384,
        )?))?;
        Ok(Self {
            config,
            profile,
            verifier,
            genesis,
            roots,
            round,
        })
    }
    fn identity(&self, role: Role) -> Result<Identity> {
        Ok(Identity::new(
            SigningKey::from_bytes(&[11 + role as u8; 32]),
            role,
            &self.config,
        )?)
    }
    fn listener(&self, root: &Path, role: Role, resources: &RoleResources) -> Result<Listener> {
        let i = role as usize;
        let cert = CertificateDer::from(read(&root.join(format!("tls/leaf-{i}.der")), 16384)?);
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(read(
            &root.join(format!("tls/leaf-{i}-key.der")),
            16384,
        )?));
        Ok(Listener::bounded(
            ServerProfile::new(self.config.endpoints()[i], vec![cert], key)?,
            resources,
        )?)
    }
    fn connect(&self, role: Role, deadline: Instant) -> Result<Transport> {
        let ep = self.config.endpoints()[role as usize];
        let address = SocketAddr::new(Ipv6Addr::from(ep.address).into(), ep.port);
        let socket = TcpStream::connect_timeout(&address, Duration::from_secs(3))?;
        Ok(Transport::client(
            socket,
            ep,
            self.roots.clone(),
            deadline.min(Instant::now() + Duration::from_secs(5)),
        )?)
    }
}
fn accept(listener: &Listener, deadline: Instant) -> Result<Transport> {
    loop {
        if Instant::now() >= deadline {
            return Err("setup deadline".into());
        }
        if let Some(mut setup) =
            listener.accept(deadline.min(Instant::now() + Duration::from_secs(5)))?
        {
            loop {
                match setup.poll()? {
                    SetupStep::Pending(next) => setup = next,
                    SetupStep::Established(t) => return Ok(t),
                }
                thread::sleep(TICK);
            }
        }
        thread::sleep(TICK);
    }
}
fn wait(schedule: &Schedule, offset: i64) -> Result<()> {
    let at = schedule.at(offset)?;
    while Instant::now() < at {
        thread::sleep(
            at.saturating_duration_since(Instant::now())
                .min(Duration::from_millis(10)),
        );
    }
    Ok(())
}
fn send(
    t: &mut Transport,
    s: &Schedule,
    size: RecordSize,
    b: &[u8],
    start: i64,
    end: i64,
) -> Result<()> {
    wait(s, start)?;
    s.in_window(start, end)?;
    t.queue(size, b, s.at(end)?)?;
    while !t.write_step()? {
        thread::sleep(TICK);
    }
    s.completed_before(end)?;
    Ok(())
}
fn receive(
    t: &mut Transport,
    s: &Schedule,
    size: RecordSize,
    start: i64,
    end: i64,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    wait(s, start)?;
    t.expect(size, s.at(end)?)?;
    loop {
        if let Some(b) = t.read_step()? {
            s.completed_before(end)?;
            return Ok(b);
        }
        thread::sleep(TICK);
    }
}
fn journal(root: &Path, p: &Public, role: Role) -> Result<DurableJournal<Pins>> {
    let path = root.join(format!("journal-{}", role as u8));
    directory(&path)?;
    Ok(DurableJournal::new(
        Journal::create(
            &path,
            p.config.domain(),
            7,
            role,
            functional_utc()?.as_secs() / 30,
        )?,
        Pins(root.join(format!("journal-pin-{}", role as u8))),
    )?)
}
fn actor(root: &Path, role: Role) -> Result<()> {
    // Schedule/guard outlive all secret-bearing round actors on error as well.
    let schedule;
    let guard;
    let p = Public::load(root)?;
    let actual_input = std::env::var("SILK_R2_ACTUAL_INPUT_HANDOFF").as_deref() == Ok("1");
    if actual_input {
        let expected: serde_json::Value =
            serde_json::from_slice(&read(&root.join("expected.json"), 4096)?)?;
        if expected["actual_tls_inputs"] != true
            || std::env::var_os("SILK_R2_FIXTURE_OFFSET").is_some()
        {
            return Err(
                "actual-input path requires its signed roster and actual unshifted host UTC".into(),
            );
        }
    }
    let identity = p.identity(role)?;
    // Cold-open quarantine is +3 rounds. Create the live journal EARLY, then
    // keep this same owner; never lie about UTC or reopen it closer to T0.
    let mut held_journal = if matches!(role, Role::A | Role::B) {
        Some(journal(root, &p, role)?)
    } else {
        None
    };
    while p.round * 30 > functional_utc()?.as_secs() + 55 {
        thread::sleep(Duration::from_millis(100));
    }
    schedule = Rc::new(Schedule::functional_fixture(&p.config, p.round)?);
    let setup_end = schedule.at(-10_000_000_000)?;
    let resources = RoleResources::new(role)?;
    match role {
        Role::A => {
            let mut j = held_journal.take().ok_or("live A journal")?;
            let sessions = if actual_input {
                let raw = read(&root.join("roster-public.bin"), 1024)?;
                if raw.len() != 1024 {
                    return Err("actual Join roster size".into());
                }
                let hashes: Vec<[u8; 32]> = raw
                    .chunks_exact(32)
                    .map(|v| v.try_into().expect("32"))
                    .collect();
                let roster = Roster::verify(
                    hashes.try_into().map_err(|_| "32 roster hashes")?,
                    &p.config,
                )?;
                let listener = p.listener(root, Role::A, &resources)?;
                write_new(&root.join("listening-a-input"), b"lab actual input")?;
                let mut sessions = Sessions::new(&p.config);
                // Exactly32 attempts, no replacements. The public deterministic
                // local tokens are not independent users or epoch qualification.
                for _ in 0..32 {
                    let link = accept(&listener, setup_end)?;
                    let mut joining = Enrolling::new(
                        link,
                        setup_end.min(Instant::now() + Duration::from_secs(5)),
                    )?;
                    loop {
                        match joining.poll(&p.config, &roster)? {
                            Enrollment::Pending(next) => joining = next,
                            Enrollment::Admitted(session) => {
                                sessions.insert(session)?;
                                break;
                            }
                        }
                        thread::sleep(TICK);
                    }
                }
                drop(listener);
                Some(sessions)
            } else {
                None
            };
            while !root.join("listening-b").exists() {
                thread::sleep(TICK);
                if Instant::now() >= setup_end {
                    return Err("B setup missing".into());
                }
            }
            let mut b = p.connect(Role::B, setup_end)?;
            guard = Rc::new(RoundGuard::arm(&schedule)?);
            wait(&schedule, -10_000_000_000)?;
            let proposal = AProposal::begin(
                SelectedCut::from_genesis(&p.genesis, &p.config, p.round)?,
                &p.config,
                &schedule,
                &identity,
                &mut j,
                functional_utc()?.as_secs() / 30,
            )?;
            send(
                &mut b,
                &schedule,
                RecordSize::Control,
                proposal.control().bytes(),
                -10_000_000_000,
                -9_000_000_000,
            )?;
            let response = receive(
                &mut b,
                &schedule,
                RecordSize::Control,
                -9_000_000_000,
                -8_000_000_000,
            )?;
            let manifested = proposal.finish(&response, &p.config, &schedule, &mut j)?;
            if manifested.manifest().bytes() != read(&root.join("manifest.bin"), 256)?.as_slice() {
                return Err("actual negotiated manifest differs from proof statement".into());
            }
            let round = ManifestRound::new(Rc::clone(&p.config), manifested, Rc::clone(&schedule))?;
            let vk = p.profile.claim_binding(ClaimRole::Client).vk_hash;
            let mut collected_sessions = None;
            let mut a = if let Some(sessions) = sessions {
                let mut delivery = ManifestDelivery::new(sessions, Rc::clone(&round))?;
                wait(&schedule, -8_000_000_000)?;
                while !delivery.poll()? {
                    guard.check()?;
                    thread::sleep(TICK);
                }
                let sessions = delivery.finish()?;
                let mut collector = R2InputCollectorLab::new(
                    sessions,
                    round,
                    &p.profile,
                    vk,
                    Rc::new(HpkePrivate::from_bytes(&[71; 32])?),
                    Rc::clone(&guard),
                )?;
                let cutoff = schedule.at(9_500_000_000)?;
                while Instant::now() < cutoff {
                    collector.poll()?;
                    thread::sleep(TICK);
                }
                let (_held_sessions, collected) = collector.seal()?;
                // Keep source connections until the original outcome, not a
                // close-induced substitute for honest completion at the barrier.
                // The receipt and source-free shuffled batch alone cross to egress.
                let a = SourceRound::from_collected_r2_lab(collected, &b)?;
                write_new(
                    &root.join("actual-input-collected"),
                    b"32 actual TLS outer-HPKE completions, proof validity only at B",
                )?;
                // Retain the session owner alongside egress below.
                collected_sessions = Some(_held_sessions);
                a
            } else {
                let c = PreparedR2Context::new(&p.config, round.manifest(), &p.profile, vk)?;
                let raw = read(&root.join("prepared-r2-stage2.bin"), 32 * 8192)?;
                if raw.len() != 32 * 8192 {
                    return Err("complete handoff".into());
                }
                let frames: Vec<_> = raw
                    .chunks_exact(8192)
                    .map(|b| PreparedR2Frame::decode(b, &c, 2))
                    .collect::<silk_f04_relay::Result<_>>()?;
                wait(&schedule, 9_500_000_000)?;
                SourceRound::new_r2_lab(
                    round,
                    &p.profile,
                    vk,
                    frames.try_into().map_err(|_| "32")?,
                    Rc::clone(&guard),
                    &b,
                )?
            };
            loop {
                guard.check()?;
                if a.poll(&mut b, &identity, &mut j)? == SourceProgress::AuthorizedWritten {
                    break;
                }
                thread::sleep(TICK);
            }
            wait(&schedule, 22_000_000_000)?;
            drop(a);
            drop(collected_sessions);
            guard.check()?;
            write_new(
                &root.join("a-result.json"),
                &serde_json::to_vec(
                    &serde_json::json!({"status":"SEALED_AUTH_WRITTEN_LAB","decision":format!("{:?}",j.decision(p.round)),"qualified":false}),
                )?,
            )?;
        }
        Role::B => {
            let mut j = held_journal.take().ok_or("live B journal")?;
            let params =
                PathBuf::from(std::env::var_os("SILK_F04_PARAMETER_DIR").ok_or("parameters")?);
            let keys = Rc::new(SaplingVerificationKeys::load(
                &params.join("sapling-spend.params"),
                &params.join("sapling-output.params"),
            )?);
            let listener = p.listener(root, role, &resources)?;
            for i in [2, 3, 4] {
                while !root.join(format!("listening-{i}")).exists() {
                    thread::sleep(TICK);
                    if Instant::now() >= setup_end {
                        return Err("producer setup missing".into());
                    }
                }
            }
            let mut producers = [
                p.connect(Role::P0, setup_end)?,
                p.connect(Role::P1, setup_end)?,
                p.connect(Role::P2, setup_end)?,
            ];
            // A may start its bounded TLS handshake only once B is ready to
            // accept it. A listening socket alone is not that readiness.
            write_new(&root.join("listening-b"), b"lab")?;
            let mut a = accept(&listener, setup_end)?;
            drop(listener);
            let claim_path = root.join("exit-timed-positive");
            directory(&claim_path)?;
            let pins: Box<dyn ClaimPinRetention> = Box::new(Pins(root.join("exit-timed-pin")));
            let claims = PreparedScopeStore::create(
                &claim_path,
                p.profile.claim_binding(ClaimRole::Exit),
                pins,
            )?;
            guard = Rc::new(RoundGuard::arm(&schedule)?);
            let cut = SelectedCut::from_genesis(&p.genesis, &p.config, p.round)?;
            let proposal = receive(
                &mut a,
                &schedule,
                RecordSize::Control,
                -10_000_000_000,
                -9_000_000_000,
            )?;
            let (response, manifested) = Manifested::answer(
                cut,
                &proposal,
                &p.config,
                &schedule,
                &identity,
                &mut j,
                functional_utc()?.as_secs() / 30,
            )?;
            send(
                &mut a,
                &schedule,
                RecordSize::Control,
                response.bytes(),
                -9_000_000_000,
                -8_000_000_000,
            )?;
            for producer in &mut producers {
                send(
                    producer,
                    &schedule,
                    RecordSize::Manifest,
                    manifested.manifest().bytes(),
                    -8_000_000_000,
                    -7_000_000_000,
                )?;
            }
            let round = ManifestRound::new(Rc::clone(&p.config), manifested, Rc::clone(&schedule))?;
            let mut lane = BControlLane::new(Rc::clone(&round), &a)?;
            let key = Rc::new(HpkePrivate::from_bytes(&[72; 32])?);
            let mut exit = ExitRound::new_r2_lab(
                round,
                key,
                keys,
                Rc::clone(&p.profile),
                Rc::clone(&p.verifier),
                claims,
                Rc::clone(&guard),
                &a,
                &producers,
            )?;
            wait(&schedule, 9_000_000_000)?;
            loop {
                guard.check()?;
                let progress = exit.poll(&mut a, &mut producers, &identity, &mut j, &mut lane)?;
                if std::env::var_os("SILK_R2_LAB_CRASH_RELEASE").is_some()
                    && j.decision(p.round)
                        == Some(silk_f04_relay::journal::Decision::ReleaseDecided)
                {
                    // CommitRelease returned with its durable pin retained;
                    // no subsequent poll (hence NO new key write) is allowed.
                    // External controller must observe and actually SIGKILL B.
                    write_new(
                        &root.join("crash-release-boundary"),
                        b"RELEASE_DECIDED_BEFORE_FIRST_KEY_WRITE",
                    )?;
                    loop {
                        guard.check()?;
                        thread::sleep(TICK);
                    }
                }
                if progress == ExitProgress::ReleasedWritten {
                    break;
                }
                thread::sleep(TICK);
            }
            drop(exit);
            guard.check()?;
            write_new(
                &root.join("b-result.json"),
                &serde_json::to_vec(
                    &serde_json::json!({"status":"RELEASE_WRITTEN_LAB","decision":format!("{:?}",j.decision(p.round)),"qualified":false}),
                )?,
            )?;
        }
        Role::P0 | Role::P1 | Role::P2 => {
            let listener = p.listener(root, role, &resources)?;
            write_new(&root.join(format!("listening-{}", role as u8)), b"lab")?;
            let mut t = accept(&listener, setup_end)?;
            drop(listener);
            guard = Rc::new(RoundGuard::arm(&schedule)?);
            let mut producer = ProducerRound::new(
                Rc::clone(&p.config),
                Rc::clone(&schedule),
                role,
                SelectedCut::from_genesis(&p.genesis, &p.config, p.round)?,
                &t,
            )?;
            wait(&schedule, -10_000_000_000)?;
            while Instant::now() < schedule.at(22_000_000_000)? {
                guard.check()?;
                producer.poll(&mut t, &identity)?;
                thread::sleep(TICK);
            }
            // The node offer must originate in this producer's completed release,
            // not a body manufactured from the controller's expected payment.
            let batch = producer.take_released_batch_v1()?;
            let expected_delivery = batch.delivery();
            let mut inbox = ProducerInboxV1::new(p.config.domain(), 7, role)?;
            inbox.offer(batch)?;
            let (delivery, offer) = inbox.take_next().ok_or("missing actual producer offer")?;
            if delivery != expected_delivery
                || delivery.round != p.round
                || delivery.config != p.config.id()
                || delivery.producer != role
                || offer.payload_bytes() != 2790
                || inbox.take_next().is_some()
            {
                return Err("actual producer offer context/count".into());
            }
            let body = offer.encode_local()?;
            let decoded = silk_f04_node::carriage::Body::decode(&body, &p.config.domain())?;
            let [payment] = decoded.representations() else {
                return Err("expected one actual producer payment".into());
            };
            if payment.as_slice() != read(&root.join("envelope.bin"), 2790)?.as_slice() {
                return Err("released payment not exact original".into());
            }
            let envelope = Envelope::decode(payment, &p.config.domain())?;
            write_new(
                &root.join(format!("producer-{}-payment.bin", role as u8)),
                envelope.bytes(),
            )?;
            write_new(
                &root.join(format!("p{}-offer.local", role as u8 - 2)),
                &body,
            )?;
            if producer.take_released_batch_v1().is_ok() {
                return Err("duplicate handoff".into());
            }
            guard.check()?;
            write_new(
                &root.join(format!("p{}-result.json", role as u8 - 2)),
                b"{\"status\":\"EXACT_PAYMENT_RECEIVED_ONCE_LAB\",\"producer_inbox_consumed\":true,\"qualified\":false}",
            )?;
        }
    }
    Ok(())
}
fn setup(root: &Path) -> Result<()> {
    let tls = root.join("tls");
    certificates::generate(&tls, 5);
    write_new(&tls.join("root.der"), &certificates::root_der(&tls))?;
    let mut pins = Vec::new();
    for i in 0..5 {
        let cert = certificates::leaf_der(&tls, i);
        pins.push(hex_string(&spki_pin(&CertificateDer::from(cert.clone()))?));
        // Generator already created exact leaf DER and protected PKCS8 files.
    }
    write_new(&root.join("tls-pins.json"), &serde_json::to_vec(&pins)?)?;
    Ok(())
}
fn preflight(root: &Path) -> Result<()> {
    let p = Public::load(root)?;
    let state = silk_f04_node::state::BranchState::genesis(&p.genesis)?;
    let cut = state.cuts().first().ok_or("genesis cut")?;
    let m = silk_f04_relay::manifest::SignedManifest::verify(
        &read(&root.join("manifest.bin"), 256)?,
        &p.config,
        p.round,
    )?;
    let e = Envelope::decode(&read(&root.join("envelope.bin"), 2790)?, &p.config.domain())?;
    if cut.index != e.cut_index()
        || cut.id != e.cut_id()
        || cut.root != e.anchor()
        || m.bytes()[52..60] != e.cut_index().to_le_bytes()
        || m.bytes()[60..92] != cut.id
        || m.bytes()[92..124] != cut.root
    {
        return Err(
            "genuine payment must match actual genesis cut before any new proof jobs".into(),
        );
    }
    let params = PathBuf::from(std::env::var_os("SILK_F04_PARAMETER_DIR").ok_or("parameters")?);
    let keys = SaplingVerificationKeys::load(
        &params.join("sapling-spend.params"),
        &params.join("sapling-output.params"),
    )?;
    let view = silk_sapling_f04::codec::EnvelopeView::decode(e.bytes(), &p.config.domain())?;
    silk_sapling_f04::crypto::verify_borrowed(&view, &keys)?;
    println!(
        "PASS actual public genesis cut and existing genuine Sapling payment; zero new proofs"
    );
    Ok(())
}
fn hex_string(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}
fn cold(root: &Path) -> Result<()> {
    let p = Public::load(root)?;
    let utc = functional_utc()?.as_secs() / 30;
    for (i, role, decision) in [
        (0, Role::A, silk_f04_relay::journal::Decision::SealedAuth),
        (1, Role::B, silk_f04_relay::journal::Decision::Finalized),
    ] {
        let path = root.join(format!("journal-{i}"));
        let before = read(&path.join("CURRENT"), 4096)?;
        let pin: [u8; 32] = read(&root.join(format!("journal-pin-{i}")), 32)?
            .try_into()
            .map_err(|_| "pin")?;
        let mut wrong = pin;
        wrong[0] ^= 1;
        if Journal::open(&path, p.config.domain(), 7, role, wrong, utc).is_ok()
            || read(&path.join("CURRENT"), 4096)? != before
        {
            return Err("cold wrong-pin mutation/adoption".into());
        }
        let mut j = Journal::open(&path, p.config.domain(), 7, role, pin, utc)?;
        Pins(root.join(format!("journal-pin-{i}"))).persist(j.pin())?;
        if j.decision(p.round) != Some(decision) || j.earliest_round() <= p.round {
            return Err("cold terminal/future fence".into());
        }
        let current = read(&path.join("CURRENT"), 4096)?;
        let m = read(&root.join("manifest.bin"), 256)?;
        if j.begin(&p.config, p.round, m[..128].try_into()?, utc)
            .is_ok()
            || j.delivery(p.round, true).is_ok()
            || j.abort(p.round).is_ok()
            || read(&path.join("CURRENT"), 4096)? != current
        {
            return Err("cold old release authority or mutation".into());
        }
        let latest = j.pin();
        drop(j);
        let j = Journal::open(&path, p.config.domain(), 7, role, latest, utc)?;
        if j.decision(p.round) != Some(decision) {
            return Err("second cold-open lost retained terminal pin".into());
        }
        Pins(root.join(format!("journal-pin-{i}"))).persist(j.pin())?;
    }
    let path = root.join("exit-timed-positive");
    let pin: [u8; 32] = read(&root.join("exit-timed-pin"), 32)?
        .try_into()
        .map_err(|_| "claim pin")?;
    let before = read(&path.join("CURRENT"), 512)?;
    let mut store = PreparedScopeStore::open(
        &path,
        p.profile.claim_binding(ClaimRole::Exit),
        pin,
        utc,
        Pins(root.join("exit-timed-pin")),
    )?;
    if store.consume(p.round, [0x97; 32], [0x98; 32]).is_ok()
        || read(&path.join("CURRENT"), 512)? != before
    {
        return Err("cold consumed profile/round reopened".into());
    }
    let params = PathBuf::from(std::env::var_os("SILK_F04_PARAMETER_DIR").ok_or("parameters")?);
    let keys = SaplingVerificationKeys::load(
        &params.join("sapling-spend.params"),
        &params.join("sapling-output.params"),
    )?;
    let original = read(&root.join("envelope.bin"), 2790)?;
    for i in [2, 3, 4] {
        let bytes = read(&root.join(format!("producer-{i}-payment.bin")), 2790)?;
        if bytes != original {
            return Err("cold receiver exact bytes".into());
        }
        let e = silk_sapling_f04::codec::EnvelopeView::decode(&bytes, &p.config.domain())?;
        silk_sapling_f04::crypto::verify_borrowed(&e, &keys)?;
    }
    write_new(&root.join("cold-result.json"),b"{\"status\":\"PASS_COLD_FENCES_AND_EXACT_RECEIVER_CRYPTO_ONLY\",\"old_release_authority\":false,\"new_proofs\":0,\"wallet_settlement\":false}")?;
    Ok(())
}
fn cold_crash(root: &Path) -> Result<()> {
    let p = Public::load(root)?;
    if read(&root.join("crash-release-boundary"), 64)? != b"RELEASE_DECIDED_BEFORE_FIRST_KEY_WRITE"
    {
        return Err("actual external crash boundary missing".into());
    }
    let path = root.join("journal-1");
    let pin: [u8; 32] = read(&root.join("journal-pin-1"), 32)?
        .try_into()
        .map_err(|_| "pin")?;
    let utc = functional_utc()?.as_secs() / 30;
    let mut j = Journal::open(&path, p.config.domain(), 7, Role::B, pin, utc)?;
    Pins(root.join("journal-pin-1")).persist(j.pin())?;
    if j.decision(p.round) != Some(silk_f04_relay::journal::Decision::DeliveryUnknown)
        || j.earliest_round() <= p.round
    {
        return Err("crash cold-open irreversible/future fence".into());
    }
    let current = read(&path.join("CURRENT"), 4096)?;
    let m = read(&root.join("manifest.bin"), 256)?;
    if j.begin(&p.config, p.round, m[..128].try_into()?, utc)
        .is_ok()
        || j.abort(p.round).is_ok()
        || j.delivery(p.round, true).is_ok()
        || read(&path.join("CURRENT"), 4096)? != current
    {
        return Err("crash cold-open minted old authority".into());
    }
    let path = root.join("exit-timed-positive");
    let pin: [u8; 32] = read(&root.join("exit-timed-pin"), 32)?
        .try_into()
        .map_err(|_| "claim pin")?;
    let current = read(&path.join("CURRENT"), 512)?;
    let mut claims = PreparedScopeStore::open(
        &path,
        p.profile.claim_binding(ClaimRole::Exit),
        pin,
        utc,
        Pins(root.join("exit-timed-pin")),
    )?;
    if claims.consume(p.round, [0x97; 32], [0x98; 32]).is_ok()
        || read(&path.join("CURRENT"), 512)? != current
    {
        return Err("crash cold-open restored consumed scope".into());
    }
    for i in [2, 3, 4] {
        if root.join(format!("producer-{i}-payment.bin")).exists() {
            return Err("crash fixture unexpectedly handed off payment".into());
        }
    }
    write_new(&root.join("cold-crash-result.json"),b"{\"status\":\"PASS_CRASH_RELEASE_FENCE_ONLY\",\"decision\":\"DeliveryUnknown\",\"old_release_authority\":false,\"new_proofs\":0,\"wallet_settlement\":false}")?;
    Ok(())
}
fn cover_sources(root: &Path) -> Result<()> {
    let p = Public::load(root)?;
    let e: serde_json::Value = serde_json::from_slice(&read(&root.join("expected.json"), 4096)?)?;
    if e["actual_tls_inputs"] != true || std::env::var_os("SILK_R2_FIXTURE_OFFSET").is_some() {
        return Err("explicit actual-input public fixture, unshifted host UTC".into());
    }
    let schedule = Schedule::functional_fixture(&p.config, p.round)?;
    let tokens: serde_json::Value =
        serde_json::from_slice(&read(&root.join("tokens-public.json"), 8192)?)?;
    if tokens.as_array().ok_or("tokens")?.len() != 32 {
        return Err("exact32 public fixture tokens".into());
    }
    let m = silk_f04_relay::manifest::SignedManifest::verify(
        &read(&root.join("manifest.bin"), 256)?,
        &p.config,
        p.round,
    )?;
    let context = PreparedR2Context::new(
        &p.config,
        &m,
        &p.profile,
        p.profile.claim_binding(ClaimRole::Client).vk_hash,
    )?;
    let raw = read(&root.join("prepared-cover-stage1.bin"), 31 * 8192)?;
    if raw.len() != 31 * 8192 {
        return Err("exact31 precomputed cover inputs, no client0 frame".into());
    }
    let frames: Vec<_> = raw
        .chunks_exact(8192)
        .map(|b| PreparedR2Frame::decode(b, &context, 1))
        .collect::<silk_f04_relay::Result<_>>()?;
    // Outside the active [-10,+30] phase domain: preserve the same immutable
    // round mapping rather than requesting an unsupported Schedule::at value.
    let setup_at = schedule.at(-10_000_000_000)?.checked_sub(Duration::from_secs(15))
        .ok_or("pre-round setup origin underflow")?;
    thread::sleep(setup_at.saturating_duration_since(Instant::now()));
    let mut links = Vec::with_capacity(31);
    for slot in 1..32 {
        if tokens[slot]["slot"] != slot {
            return Err("fixed token slot order".into());
        }
        let mut link = p.connect(Role::A, schedule.at(-10_000_000_000)?)?;
        let token: [u8; 32] = hex(tokens[slot]["token"].as_str().ok_or("token")?)?;
        let mut join = [0; 128];
        join[..8].copy_from_slice(b"SNJOIN03");
        join[8..40].copy_from_slice(&p.config.domain());
        join[40..44].copy_from_slice(&p.config.cohort().to_le_bytes());
        join[44..48].copy_from_slice(&p.config.epoch().to_le_bytes());
        join[48..80].copy_from_slice(&token);
        link.queue(
            RecordSize::Join,
            &join,
            schedule
                .at(-10_000_000_000)?
                .min(Instant::now() + Duration::from_secs(5)),
        )?;
        while !link.write_step()? {
            thread::sleep(TICK);
        }
        link.expect(RecordSize::Manifest, schedule.at(-5_000_000_000)?)?;
        links.push(link);
    }
    wait(&schedule, -8_000_000_000)?;
    for link in &mut links {
        loop {
            if let Some(received) = link.read_step()? {
                if received.as_slice() != m.bytes() {
                    return Err("cover source actual delivered M mismatch".into());
                }
                break;
            }
            thread::sleep(TICK);
        }
        schedule.completed_before(-5_000_000_000)?;
    }
    for (i, (link, frame)) in links.iter_mut().zip(&frames).enumerate() {
        let start = 1_000_000_000 + (i as i64 + 1) * 200_000_000;
        send(
            link,
            &schedule,
            RecordSize::Cell,
            frame.bytes(),
            start,
            start + 200_000_000,
        )?;
    }
    wait(&schedule, 22_000_000_000)?;
    write_new(
        &root.join("cover-sources-result.json"),
        &serde_json::to_vec(&serde_json::json!({
        "status":"31_PRECOMPUTED_GENUINE_COVERS_WRITTEN_OVER_ACTUAL_JOIN_TLS",
        "connections":31,"precomputed_proofs":31,"timed_client_proofs":0,
        "independent_participants":false,"epoch_admission":false,"operational":false}))?,
    )?;
    Ok(())
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 || args[1] != "--unqualified-functional-lab" {
        return Err("explicit unqualified functional lab MODE ROOT required".into());
    }
    // Explicit bounded SIMULATED protocol UTC for exact reusable cipher fixtures.
    // Native monotonic/CPU time and TLS certificate time are never shifted.
    if let Ok(offset) = std::env::var("SILK_R2_FIXTURE_OFFSET") {
        silk_f04_relay::schedule::initialize_functional_offset(offset.parse()?)?;
    }
    let root = Path::new(&args[3]);
    match args[2].as_str() {
        "setup" => setup(root),
        "preflight" => preflight(root),
        "cold" => cold(root),
        "cold-crash" => cold_crash(root),
        "cover-sources" => cover_sources(root),
        "a" => actor(root, Role::A),
        "b" => actor(root, Role::B),
        "p0" => actor(root, Role::P0),
        "p1" => actor(root, Role::P1),
        "p2" => actor(root, Role::P2),
        _ => Err("unknown lab mode".into()),
    }
}
fn main() {
    if let Err(e) = run() {
        eprintln!("R2 operator lab STOP: {e}");
        std::process::exit(1);
    }
}
