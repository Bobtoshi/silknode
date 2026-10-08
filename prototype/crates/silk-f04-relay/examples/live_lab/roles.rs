use super::{Result, files};
use ed25519_dalek::SigningKey;
use hpke::Deserializable;
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use silk_f04_node::genesis::Genesis;
use silk_f04_relay::{
    Error,
    config::{Endpoint, Roster, SignedConfig},
    control::Role,
    exit::{ExitProgress, ExitRound},
    frame::{HpkePrivate, Payload, RoundContext, client_cell},
    handoff::v1::ProducerInboxV1,
    input::{Enrolling, Enrollment, InputCollector, ManifestDelivery, Sessions},
    journal::Journal,
    lane::BControlLane,
    negotiation::{AProposal, Manifested, SelectedCut},
    owner::{DurableJournal, Identity, ManifestRound},
    producer::ProducerRound,
    resources::RoleResources,
    runtime::RoundGuard,
    schedule::{Schedule, functional_utc},
    source::{SourceProgress, SourceRound},
    tls::{
        ClientProfile, ConnectStep, Connecting, Listener, RecordSize, ServerProfile, Setup,
        SetupStep, Transport,
    },
};
use silk_sapling_f04::{codec::Envelope, parameters::SaplingVerificationKeys};
use std::{
    net::{Ipv6Addr, SocketAddr, TcpStream},
    path::{Path, PathBuf},
    rc::Rc,
    thread,
    time::{Duration, Instant},
};

const PUBLIC: &str = "/work/public";
const SECRET: &str = "/work/secrets";
const STORE: &str = "/work/store";
const PINS: &str = "/work/pins";
pub const TICK: Duration = Duration::from_micros(500);

pub struct Public {
    pub(super) config: Rc<SignedConfig>,
    genesis: Rc<Genesis>,
    roots: RootCertStore,
    root: PathBuf,
    secret_root: PathBuf,
}
impl Public {
    fn load(round: u64) -> Result<Self> {
        Self::load_paths(round, Path::new(PUBLIC), Path::new(SECRET))
    }
    pub(super) fn load_next(round: u64) -> Result<Self> {
        Self::load_paths(
            round,
            &Path::new(PUBLIC).join("next"),
            &Path::new(SECRET).join("next"),
        )
    }
    fn load_paths(round: u64, root: &Path, secret: &Path) -> Result<Self> {
        let domain = files::exact::<32>(&root.join("domain"))?;
        let pins = files::exact::<64>(&root.join("roots"))?;
        let config_bytes = files::exact::<770>(&root.join("config"))?;
        let config = SignedConfig::verify(
            config_bytes.as_ref(),
            *domain,
            0,
            u32::try_from(round / 2880)?,
            [pins[..32].try_into()?, pins[32..].try_into()?],
        )?;
        let genesis = Genesis::admit_local_bundle(
            &files::read(&root.join("genesis"), 8 * 1024 * 1024)?,
            &domain,
            true,
        )?;
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(
            files::read(&root.join("ca.der"), 16 * 1024)?.to_vec(),
        ))?;
        Ok(Self {
            config: Rc::new(config),
            genesis: Rc::new(genesis),
            roots,
            root: root.to_path_buf(),
            secret_root: secret.to_path_buf(),
        })
    }
    pub(super) fn identity(&self, role: Role) -> Result<Identity> {
        let seed = files::exact::<32>(&self.secret_root.join("signing"))?;
        Ok(Identity::new(
            SigningKey::from_bytes(&seed),
            role,
            &self.config,
        )?)
    }
    pub(super) fn owned_cut(&self, round: u64) -> Result<SelectedCut<'static>> {
        Ok(SelectedCut::from_owned_genesis(
            Rc::clone(&self.genesis),
            &self.config,
            round,
        )?)
    }
    pub(super) fn owner_schedule(&self, round: u64) -> Result<Schedule> {
        Ok(Schedule::functional_fixture(&self.config, round)?)
    }
    fn roster(&self) -> Result<Roster> {
        Ok(Roster::verify(self.roster_hashes()?, &self.config)?)
    }
    pub(super) fn roster_hashes(&self) -> Result<[[u8; 32]; 32]> {
        let bytes = files::exact::<1024>(&self.secret_root.join("roster"))?;
        Ok(std::array::from_fn(|i| {
            bytes[i * 32..(i + 1) * 32]
                .try_into()
                .expect("fixed roster")
        }))
    }
    pub(super) fn config_roots(&self) -> Result<[[u8; 32]; 2]> {
        let bytes = files::exact::<64>(&self.root.join("roots"))?;
        Ok([bytes[..32].try_into()?, bytes[32..].try_into()?])
    }
    pub(super) fn hpke(&self) -> Result<HpkePrivate> {
        Ok(HpkePrivate::from_bytes(
            files::exact::<32>(&self.secret_root.join("hpke"))?.as_ref(),
        )?)
    }
    pub(super) fn tokens(&self) -> Result<zeroize::Zeroizing<[u8; 1024]>> {
        files::exact::<1024>(&self.secret_root.join("tokens"))
    }
    pub(super) fn client_profile(&self, role: Role) -> Result<ClientProfile> {
        Ok(ClientProfile::new(
            self.config.endpoints()[role as usize],
            self.roots.clone(),
        )?)
    }
    fn connect(&self, role: Role, deadline: Instant) -> Result<Transport> {
        let deadline = setup_step_deadline(deadline);
        let endpoint = self.config.endpoints()[role as usize];
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or("setup deadline")?;
        let socket =
            TcpStream::connect_timeout(&address(endpoint), remaining.min(Duration::from_secs(3)))?;
        Ok(Transport::client(
            socket,
            endpoint,
            self.roots.clone(),
            deadline,
        )?)
    }
    fn connect_bounded(
        &self,
        peer: Role,
        deadline: Instant,
        resources: &RoleResources,
    ) -> Result<Transport> {
        let deadline = setup_step_deadline(deadline);
        let profile =
            ClientProfile::new(self.config.endpoints()[peer as usize], self.roots.clone())?;
        let mut connecting = Connecting::with_resources(profile, deadline, resources)?;
        loop {
            match connecting.poll()? {
                ConnectStep::Pending(pending) => connecting = pending,
                ConnectStep::Handshaking(setup) => return Self::complete_setup(setup),
            }
            thread::sleep(TICK);
        }
    }
    fn listener(&self, role: Role, resources: &RoleResources) -> Result<Listener> {
        let listener = self.lifecycle_listener(role, resources)?;
        files::write_new(&Path::new(STORE).join("listening"), b"functional-only\n")?;
        Ok(listener)
    }
    pub(super) fn lifecycle_listener(
        &self,
        role: Role,
        resources: &RoleResources,
    ) -> Result<Listener> {
        let name = super::setup::ROLES[role as usize];
        let certificate = CertificateDer::from(
            files::read(&self.root.join(format!("{name}.der")), 16384)?.to_vec(),
        );
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            files::read(&self.secret_root.join("tls.der"), 16384)?.to_vec(),
        ));
        let profile = ServerProfile::new(
            self.config.endpoints()[role as usize],
            vec![certificate],
            key,
        )?;
        let listener = Listener::bounded(profile, resources)?;
        Ok(listener)
    }
    fn accept(listener: &Listener, deadline: Instant) -> Result<Transport> {
        // Baseline functional setup retains its existing fixed per-attempt cap.
        loop {
            // No accepted socket exists on an empty poll. Once accepted, its
            // <=5s deadline is immutable through TLS and the original Join.
            if let Some(setup) = listener.accept(setup_step_deadline(deadline))? {
                return Self::complete_setup(setup);
            }
            thread::sleep(TICK);
        }
    }
    fn complete_setup(mut setup: Setup) -> Result<Transport> {
        loop {
            match setup.poll()? {
                SetupStep::Pending(pending) => setup = pending,
                SetupStep::Established(transport) => return Ok(transport),
            }
            thread::sleep(TICK);
        }
    }
}

pub fn run(
    role: &str,
    round: u64,
    sustained: bool,
    failed_first: bool,
    lifecycle: bool,
) -> Result<()> {
    if !cfg!(target_os = "linux") {
        return Err(Error::Unavailable("native Linux runtime required").into());
    }
    let public = Public::load(round)?;
    if sustained
        && !lifecycle
        && !public
            .config
            .contains_round(round.checked_add(2).ok_or("round overflow")?)
    {
        return Err("three-round fixture cannot cross an epoch".into());
    }
    println!(
        "role={role} round={round} functional_only=true independent_custody=false qualified_utc=false epoch_lifecycle=false"
    );
    match role {
        "a" => source(&public, round, sustained, failed_first, lifecycle),
        "b" => exit(&public, round, sustained, failed_first, lifecycle),
        "p0" => producer(&public, round, Role::P0, sustained, failed_first, lifecycle),
        "p1" => producer(&public, round, Role::P1, sustained, failed_first, lifecycle),
        "p2" => producer(&public, round, Role::P2, sustained, failed_first, lifecycle),
        "clients" => clients(&public, round, sustained, failed_first, lifecycle),
        _ => Err(Error::Unavailable("unknown fixture role").into()),
    }
}
fn address(endpoint: Endpoint) -> SocketAddr {
    SocketAddr::new(
        Ipv6Addr::from(endpoint.address).to_canonical(),
        endpoint.port,
    )
}
fn utc_round() -> Result<u64> {
    Ok(functional_utc()?.as_secs() / 30)
}
fn setup_deadline(round: u64) -> Result<Instant> {
    let end = Duration::from_secs(
        round
            .checked_mul(30)
            .and_then(|r| r.checked_sub(15))
            .ok_or("setup overflow")?,
    );
    let left = end
        .checked_sub(functional_utc()?)
        .ok_or("setup already closed")?;
    Ok(Instant::now() + left)
}
// The overall pre-round setup window is NOT a renewable per-socket allowance.
// Each one-shot handshake/Join has its own bounded original <=5s deadline.
fn setup_step_deadline(overall: Instant) -> Instant {
    overall.min(Instant::now() + Duration::from_secs(5))
}
pub fn round_schedule(public: &Public, round: u64) -> Result<Schedule> {
    while utc_round()?.checked_add(2).ok_or("clock overflow")? < round {
        thread::sleep(Duration::from_millis(100));
    }
    Ok(Schedule::functional_fixture(&public.config, round)?)
}
fn journal(public: &Public, role: Role, round: u64) -> Result<DurableJournal<files::Pins>> {
    let path = Path::new(STORE).join("journal");
    files::directory(&path)?;
    let journal = Journal::create_with_host_margin(
        &path,
        Path::new("/work/margin"),
        public.config.domain(),
        public.config.cohort(),
        role,
        utc_round()?,
    )?;
    if round < journal.earliest_round() {
        return Err(Error::Unavailable("fresh journal high-water floor").into());
    }
    Ok(DurableJournal::new(
        journal,
        files::Pins::new(Path::new(PINS)),
    )?)
}
fn hpke_key() -> Result<HpkePrivate> {
    Ok(HpkePrivate::from_bytes(
        files::exact::<32>(&Path::new(SECRET).join("hpke"))?.as_ref(),
    )?)
}
fn wait_until(schedule: &Schedule, offset: i64) -> Result<()> {
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
    transport: &mut Transport,
    schedule: &Schedule,
    size: RecordSize,
    bytes: &[u8],
    start: i64,
    end: i64,
) -> Result<()> {
    wait_until(schedule, start)?;
    schedule.in_window(start, end)?;
    transport.queue(size, bytes, schedule.at(end)?)?;
    while !transport.write_step()? {
        thread::sleep(TICK);
    }
    schedule.completed_before(end)?;
    Ok(())
}
fn receive(
    transport: &mut Transport,
    schedule: &Schedule,
    size: RecordSize,
    start: i64,
    end: i64,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    wait_until(schedule, start)?;
    transport.expect(size, schedule.at(end)?)?;
    loop {
        if let Some(bytes) = transport.read_step()? {
            schedule.completed_before(end)?;
            return Ok(bytes);
        }
        thread::sleep(TICK);
    }
}

#[allow(clippy::needless_late_init, clippy::too_many_lines)] // Retain one-round fixture and explicit owner branch; guards survive error cleanup.
fn source(
    public: &Public,
    round: u64,
    sustained: bool,
    failed_first: bool,
    lifecycle: bool,
) -> Result<()> {
    // Declaration order keeps the guard armed through ALL later owners' drops,
    // including error returns. The schedule itself outlives the guard.
    let schedule;
    let guard;
    let identity = public.identity(Role::A)?;
    let key = Rc::new(hpke_key()?);
    let mut journal = journal(public, Role::A, round)?;
    let roster = public.roster()?;
    let resources = RoleResources::new(Role::A)?;
    let listener = public.listener(Role::A, &resources)?;
    let deadline = setup_deadline(round)?;
    let mut b = public.connect_bounded(Role::B, deadline, &resources)?;
    let mut sessions = Sessions::new(&public.config);
    for _ in 0..32 {
        let mut enrollment = Enrolling::new(
            Public::accept(&listener, deadline)?,
            setup_step_deadline(deadline),
        )?;
        loop {
            match enrollment.poll(&public.config, &roster)? {
                Enrollment::Admitted(session) => {
                    sessions.insert(session)?;
                    break;
                }
                Enrollment::Pending(pending) => {
                    enrollment = pending;
                    thread::sleep(TICK);
                }
            }
        }
    }
    if lifecycle {
        let owner = silk_f04_relay::source_owner::SourceOwner::new(
            Rc::clone(&public.config),
            identity,
            key,
            sessions,
            b,
            journal,
        )?;
        return super::lifecycle::drive(
            public,
            round,
            Role::A,
            Rc::new(listener),
            super::lifecycle::Relay::Source(owner),
        );
    }
    drop(listener);
    if sustained {
        return super::owners::drive(
            public,
            round,
            "a",
            failed_first,
            silk_f04_relay::source_owner::SourceOwner::new(
                Rc::clone(&public.config),
                identity,
                key,
                sessions,
                b,
                journal,
            )?,
        );
    }
    schedule = Rc::new(round_schedule(public, round)?);
    guard = RoundGuard::arm(&schedule)?;
    let cut = SelectedCut::from_genesis(&public.genesis, &public.config, round)?;
    wait_until(&schedule, -10_000_000_000)?;
    schedule.observe_functional_clock()?;
    let proposal = AProposal::begin(
        cut,
        &public.config,
        &schedule,
        &identity,
        &mut journal,
        utc_round()?,
    )?;
    send(
        &mut b,
        &schedule,
        RecordSize::Control,
        proposal.control().bytes(),
        -10_000_000_000,
        -9_000_000_000,
    )?;
    let reply = receive(
        &mut b,
        &schedule,
        RecordSize::Control,
        -10_000_000_000,
        -8_000_000_000,
    )?;
    let manifested = proposal.finish(&reply, &public.config, &schedule, &mut journal)?;
    let bound = ManifestRound::new(Rc::clone(&public.config), manifested, Rc::clone(&schedule))?;
    let mut delivery = ManifestDelivery::new(sessions, Rc::clone(&bound))?;
    while !delivery.poll()? {
        thread::sleep(TICK);
    }
    let sessions = delivery.finish()?;
    let mut input = InputCollector::new(sessions, Rc::clone(&bound), Rc::clone(&key))?;
    let mut health = Instant::now();
    while Instant::now() < schedule.at(9_500_000_000)? {
        clock_tick(&mut health, || input.observe_functional_clock())?;
        match input.poll() {
            Ok(()) => (),
            Err(Error::Unavailable("relay observation barrier closed")) => break,
            Err(error) => return Err(error.into()),
        }
        thread::sleep(TICK);
    }
    let (sessions, batch) = input.seal()?;
    let admitted = batch.admitted();
    let mut source = SourceRound::new(bound, batch, &b)?;
    loop {
        guard.check()?;
        clock_tick(&mut health, || source.observe_functional_clock())?;
        if source.poll(&mut b, &identity, &mut journal)? == SourceProgress::AuthorizedWritten {
            break;
        }
        thread::sleep(TICK);
    }
    wait_until(&schedule, 22_000_000_000)?;
    drop(source);
    drop(sessions);
    drop(key);
    guard.check()?;
    println!(
        "role=a authorized_write_complete=true admitted_inputs={admitted} journal={:?} functional_only=true",
        journal.decision(round)
    );
    Ok(())
}

#[allow(clippy::needless_late_init, clippy::too_many_lines)] // Keep original native guard lifetime and explicit owner branches together.
fn exit(
    public: &Public,
    round: u64,
    sustained: bool,
    failed_first: bool,
    lifecycle: bool,
) -> Result<()> {
    let schedule;
    let guard;
    let identity = public.identity(Role::B)?;
    let key = Rc::new(hpke_key()?);
    let mut journal = journal(public, Role::B, round)?;
    let keys = Rc::new(SaplingVerificationKeys::load(
        Path::new("/work/parameters/sapling-spend.params"),
        Path::new("/work/parameters/sapling-output.params"),
    )?);
    let resources = RoleResources::new(Role::B)?;
    let listener = public.listener(Role::B, &resources)?;
    let deadline = setup_deadline(round)?;
    let mut producers = [
        public.connect_bounded(Role::P0, deadline, &resources)?,
        public.connect_bounded(Role::P1, deadline, &resources)?,
        public.connect_bounded(Role::P2, deadline, &resources)?,
    ];
    let mut a = Public::accept(&listener, deadline)?;
    if lifecycle {
        let owner = silk_f04_relay::exit_owner::ExitOwner::new(
            Rc::clone(&public.config),
            identity,
            key,
            keys,
            a,
            producers,
            journal,
        )?;
        return super::lifecycle::drive(
            public,
            round,
            Role::B,
            Rc::new(listener),
            super::lifecycle::Relay::Exit(owner),
        );
    }
    drop(listener);
    if sustained {
        return super::owners::drive(
            public,
            round,
            "b",
            failed_first,
            silk_f04_relay::exit_owner::ExitOwner::new(
                Rc::clone(&public.config),
                identity,
                key,
                keys,
                a,
                producers,
                journal,
            )?,
        );
    }
    schedule = Rc::new(round_schedule(public, round)?);
    guard = RoundGuard::arm(&schedule)?;
    let cut = SelectedCut::from_genesis(&public.genesis, &public.config, round)?;
    let proposal = receive(
        &mut a,
        &schedule,
        RecordSize::Control,
        -10_000_000_000,
        -9_000_000_000,
    )?;
    schedule.observe_functional_clock()?;
    let (response, manifested) = Manifested::answer(
        cut,
        &proposal,
        &public.config,
        &schedule,
        &identity,
        &mut journal,
        utc_round()?,
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
    let bound = ManifestRound::new(Rc::clone(&public.config), manifested, Rc::clone(&schedule))?;
    let mut lane = BControlLane::new(Rc::clone(&bound), &a)?;
    let mut exit = ExitRound::new(bound, Rc::clone(&key), Rc::clone(&keys), &a, &producers)?;
    let mut health = Instant::now();
    loop {
        guard.check()?;
        clock_tick(&mut health, || exit.observe_functional_clock())?;
        if exit.poll(&mut a, &mut producers, &identity, &mut journal, &mut lane)?
            == ExitProgress::ReleasedWritten
        {
            break;
        }
        thread::sleep(TICK);
    }
    drop(exit);
    drop(key);
    guard.check()?;
    println!(
        "role=b release_writes_complete=true journal={:?} functional_only=true",
        journal.decision(round)
    );
    Ok(())
}

#[allow(clippy::needless_late_init)] // Declaration order keeps native guard through error cleanup.
fn producer(
    public: &Public,
    round: u64,
    role: Role,
    sustained: bool,
    failed_first: bool,
    lifecycle: bool,
) -> Result<()> {
    let schedule;
    let guard;
    let identity = public.identity(role)?;
    let resources = RoleResources::new(role)?;
    let listener = public.listener(role, &resources)?;
    let mut transport = Public::accept(&listener, setup_deadline(round)?)?;
    if lifecycle {
        let owner = silk_f04_relay::producer_owner::ProducerOwner::new_functional(
            Rc::clone(&public.config),
            identity,
            role,
            transport,
        )?;
        return super::lifecycle::drive(
            public,
            round,
            role,
            Rc::new(listener),
            super::lifecycle::Relay::Producer(owner),
        );
    }
    drop(listener);
    if sustained {
        // Derive the cold floor at actual bootstrap, before waiting for admission.
        let owner = silk_f04_relay::producer_owner::ProducerOwner::new_functional(
            Rc::clone(&public.config),
            identity,
            role,
            transport,
        )?;
        return super::owners::drive(
            public,
            round,
            super::setup::ROLES[role as usize],
            failed_first,
            owner,
        );
    }
    schedule = Rc::new(round_schedule(public, round)?);
    guard = RoundGuard::arm(&schedule)?;
    let cut = SelectedCut::from_genesis(&public.genesis, &public.config, round)?;
    let mut producer = ProducerRound::new(
        Rc::clone(&public.config),
        Rc::clone(&schedule),
        role,
        cut,
        &transport,
    )?;
    // The native lease is already armed. Do not spend its original CPU budget
    // polling an impossible manifest phase throughout the pre-round setup gap.
    // Waiting consumes wall time normally and neither timer is reset afterward.
    wait_until(&schedule, -10_000_000_000)?;
    let mut health = Instant::now();
    while Instant::now() < schedule.at(22_000_000_000)? {
        guard.check()?;
        clock_tick(&mut health, || schedule.observe_functional_clock())?;
        producer.poll(&mut transport, &identity)?;
        thread::sleep(TICK);
    }
    let batch = producer.take_released_batch_v1()?;
    let mut inbox = ProducerInboxV1::new(public.config.domain(), public.config.cohort(), role)?;
    inbox.offer(batch)?;
    let (delivery, offer) = inbox.take_next().ok_or("no actual released offer")?;
    if delivery.round != round || offer.payload_bytes() != 2790 || inbox.take_next().is_some() {
        return Err("unexpected released offer context/count".into());
    }
    let body = offer.encode_local()?;
    let decoded = silk_f04_node::carriage::Body::decode(&body, &public.config.domain())?;
    let [payment] = decoded.representations() else {
        return Err("expected exactly one actual delivered payment".into());
    };
    let name = super::setup::ROLES[role as usize];
    files::write_new(
        &Path::new(STORE).join(format!("{name}-payment-2790")),
        payment,
    )?;
    files::write_new(&Path::new(STORE).join(format!("{name}-offer.local")), &body)?;
    drop(decoded);
    drop(body);
    drop(inbox);
    drop(producer);
    guard.check()?;
    println!("role={name} genuine_received_batch=true real_payloads=1 functional_only=true");
    Ok(())
}

#[allow(clippy::needless_late_init)] // Declaration order keeps native guard through error cleanup.
fn clients(
    public: &Public,
    round: u64,
    sustained: bool,
    failed_first: bool,
    lifecycle: bool,
) -> Result<()> {
    let schedule;
    let guard;
    let tokens = files::exact::<1024>(&Path::new(SECRET).join("tokens"))?;
    let payment = files::exact::<2790>(&Path::new(SECRET).join("payment-2790"))?;
    let envelope = Envelope::decode(payment.as_ref(), &public.config.domain())?;
    let deadline = setup_deadline(round)?;
    let mut connections = Vec::with_capacity(32);
    for token in tokens.chunks_exact(32) {
        let mut a = public.connect(Role::A, deadline)?;
        let mut join = zeroize::Zeroizing::new([0; 128]);
        join[..8].copy_from_slice(b"SNJOIN03");
        join[8..40].copy_from_slice(&public.config.domain());
        join[40..44].copy_from_slice(&public.config.cohort().to_le_bytes());
        join[44..48].copy_from_slice(&public.config.epoch().to_le_bytes());
        join[48..80].copy_from_slice(token);
        a.queue(
            RecordSize::Join,
            join.as_ref(),
            setup_step_deadline(deadline),
        )?;
        while !a.write_step()? {
            thread::sleep(TICK);
        }
        connections.push(a);
    }
    if lifecycle {
        return super::lifecycle_clients::drive(public, round, &envelope, connections);
    }
    if sustained {
        return clients_owned(public, round, &envelope, failed_first, connections);
    }
    schedule = Rc::new(round_schedule(public, round)?);
    guard = RoundGuard::arm(&schedule)?;
    let mut frames = Vec::with_capacity(32);
    let mut manifest_id = None;
    for (i, a) in connections.iter_mut().enumerate() {
        schedule.observe_functional_clock()?;
        let bytes = receive(
            a,
            &schedule,
            RecordSize::Manifest,
            -9_000_000_000,
            1_000_000_000,
        )?;
        let manifest = SelectedCut::from_genesis(&public.genesis, &public.config, round)?
            .admit_signed(&bytes, &public.config, &schedule)?;
        if manifest_id.is_some_and(|id| id != manifest.id()) {
            return Err("clients received conflicting manifests".into());
        }
        manifest_id = Some(manifest.id());
        let context = RoundContext::new(&public.config, &manifest)?;
        let payload = if i == 0 {
            Payload::real(&envelope, &context)?
        } else {
            Payload::cover()
        };
        frames.push(client_cell(&context, &payload)?);
        schedule.completed_before(1_000_000_000)?;
    }
    for (i, (a, frame)) in connections.iter_mut().zip(&frames).enumerate() {
        schedule.observe_functional_clock()?;
        let start = 1_000_000_000 + i64::try_from(i)? * 250_000_000;
        send(
            a,
            &schedule,
            RecordSize::Cell,
            frame.bytes(),
            start,
            start + 250_000_000,
        )?;
    }
    wait_until(&schedule, 22_000_000_000)?;
    drop(frames);
    drop(connections);
    guard.check()?;
    println!(
        "role=clients sessions=32 genuine_covers=31 real_payloads=1 honest_participants_unproven=true functional_only=true"
    );
    Ok(())
}

fn clock_tick(
    next: &mut Instant,
    observe: impl FnOnce() -> silk_f04_relay::Result<()>,
) -> Result<()> {
    if Instant::now() >= *next {
        observe()?;
        *next = Instant::now() + Duration::from_millis(250);
    }
    Ok(())
}

fn clients_owned(
    public: &Public,
    first: u64,
    envelope: &Envelope,
    failed_first: bool,
    connections: Vec<Transport>,
) -> Result<()> {
    struct ClientRounds {
        // Connections and any selected ciphertext drop before native leases.
        links: Vec<Transport>,
        leases: [Option<(Rc<Schedule>, RoundGuard)>; 2],
    }
    let mut owner = ClientRounds {
        links: connections,
        leases: [None, None],
    };
    let schedule = Rc::new(round_schedule(public, first)?);
    let guard = RoundGuard::arm(&schedule)?;
    owner.leases[0] = Some((schedule, guard));
    for offset in 0..3 {
        let index = offset % 2;
        let schedule = Rc::clone(
            &owner.leases[index]
                .as_ref()
                .ok_or("missing client native lease")?
                .0,
        );
        clients_round(
            public,
            &schedule,
            envelope,
            offset == 0 && !failed_first,
            offset == 0 && failed_first,
            &mut owner.links,
        )?;
        if offset < 2 {
            wait_until(&schedule, 19_000_000_000)?;
            let next = Rc::new(public.owner_schedule(schedule.round() + 1)?);
            let guard = RoundGuard::arm(&next)?;
            owner.leases[1 - index] = Some((next, guard));
        }
        wait_until(&schedule, 22_000_000_000)?;
        let (_, guard) = owner.leases[index]
            .take()
            .ok_or("missing closed client lease")?;
        guard.check()?;
        println!(
            "role=clients round={} owner_cleanup_complete=true real_payloads={} same_connections=true",
            schedule.round(),
            u8::from(offset == 0 && !failed_first)
        );
    }
    println!(
        "role=clients three_round_owner_success=true functional_only=true epoch_lifecycle=false honest_participants_unproven=true"
    );
    Ok(())
}

fn clients_round(
    public: &Public,
    schedule: &Schedule,
    envelope: &Envelope,
    first: bool,
    omit: bool,
    connections: &mut [Transport],
) -> Result<()> {
    let mut frames = Vec::with_capacity(32);
    let mut manifest_id = None;
    for (i, a) in connections.iter_mut().enumerate() {
        schedule.observe_functional_clock()?;
        let bytes = receive(
            a,
            schedule,
            RecordSize::Manifest,
            -9_000_000_000,
            1_000_000_000,
        )?;
        let manifest =
            public
                .owned_cut(schedule.round())?
                .admit_signed(&bytes, &public.config, schedule)?;
        if manifest_id.is_some_and(|id| id != manifest.id()) {
            return Err("clients received conflicting owner manifests".into());
        }
        manifest_id = Some(manifest.id());
        if omit {
            continue;
        } // Explicit first-round unavailability fixture; no payment/proof retry.
        let context = RoundContext::new(&public.config, &manifest)?;
        let payload = if first && i == 0 {
            Payload::real(envelope, &context)?
        } else {
            Payload::cover()
        };
        frames.push(client_cell(&context, &payload)?);
        schedule.completed_before(1_000_000_000)?;
    }
    for (i, (a, frame)) in connections.iter_mut().zip(&frames).enumerate() {
        schedule.observe_functional_clock()?;
        let start = 1_000_000_000 + i64::try_from(i)? * 250_000_000;
        send(
            a,
            schedule,
            RecordSize::Cell,
            frame.bytes(),
            start,
            start + 250_000_000,
        )?;
    }
    Ok(())
}
