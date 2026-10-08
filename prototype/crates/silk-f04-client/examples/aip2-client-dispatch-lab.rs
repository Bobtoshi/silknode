//! One actual-UTC local proof+TLS source experiment, not epoch Join, A collection,
//! complete cohort, producer release, settlement, custody or operational admission.
use hpke::Deserializable;
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use silk_f04_client::v1::{
    LocalViewV1, WriteStatusV1,
    r2_lab::{ClientRoundLab, ProofOutputLab},
};
use silk_f04_node::genesis::Genesis;
use silk_f04_relay::{
    aip2_claim::{ClaimPinRetention, ClaimResult, ClaimRole, PreparedScopeStore},
    aip2_profile::{PreparedProfile, ProfileExpectations},
    aip2_proof::hex,
    aip2_transport::{PreparedR2Context, PreparedR2Frame, open_a},
    config::SignedConfig,
    control::Role,
    frame::HpkePrivate,
    manifest::SignedManifest,
    resources::RoleResources,
    schedule::Schedule,
    tls::{Listener, RecordSize, ServerProfile, SetupStep, Transport},
};
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
use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const TICK: Duration = Duration::from_micros(500);
fn read(p: &Path, cap: u64) -> Result<Vec<u8>> {
    let m = fs::symlink_metadata(p)?;
    if !m.is_file() || m.len() > cap {
        return Err("bounded fixture file".into());
    }
    Ok(fs::read(p)?)
}
fn text(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
fn save(p: &Path, v: &serde_json::Value) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(p)?;
    f.write_all(&serde_json::to_vec(v)?)?;
    f.sync_all()?;
    fs::File::open(p.parent().ok_or("parent")?)?.sync_all()?;
    Ok(())
}
struct Pins(PathBuf);
impl ClaimPinRetention for Pins {
    fn retain_claim_pin(&mut self, pin: [u8; 32]) -> ClaimResult<()> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&self.0)?;
        f.write_all(&pin)?;
        f.sync_all()?;
        fs::File::open(self.0.parent().unwrap())?.sync_all()?;
        Ok(())
    }
}
struct Public {
    config: Rc<SignedConfig>,
    profile: PreparedProfile,
    genesis: Rc<Genesis>,
    round: u64,
    vk: Vec<u8>,
    hash: [u8; 32],
    roots: RootCertStore,
}
impl Public {
    fn load(root: &Path) -> Result<Self> {
        let e: serde_json::Value =
            serde_json::from_slice(&read(&root.join("expected.json"), 4096)?)?;
        let domain = hex(e["domain"].as_str().ok_or("N")?)?;
        let keys = [
            hex(e["role_keys"][0].as_str().ok_or("A")?)?,
            hex(e["role_keys"][1].as_str().ok_or("B")?)?,
        ];
        let epoch = u32::try_from(e["epoch"].as_u64().ok_or("epoch")?)?;
        let config = Rc::new(SignedConfig::verify(
            &read(&root.join("config.bin"), 770)?,
            domain,
            7,
            epoch,
            keys,
        )?);
        let hash = hex(e["vk_hash"].as_str().ok_or("VK")?)?;
        let profile = PreparedProfile::verify(
            &read(&root.join("profile.bin"), 1312)?,
            &ProfileExpectations {
                domain,
                config: config.id(),
                epoch,
                cohort: 7,
                vk_hash: hash,
                role_keys: keys,
            },
        )?;
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
            genesis,
            round: e["round"].as_u64().ok_or("round")?,
            hash,
            vk: read(&root.join("vk-canonical.json"), 16384)?,
            roots,
        })
    }
}
fn wait(s: &Schedule, offset: i64) -> Result<()> {
    while Instant::now() < s.at(offset)? {
        thread::sleep(TICK);
    }
    Ok(())
}
fn server(root: &Path, late: bool) -> Result<()> {
    let p = Public::load(root)?;
    let s = Schedule::functional_fixture(&p.config, p.round)?;
    let cert = CertificateDer::from(read(&root.join("tls/leaf-0.der"), 16384)?);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(read(
        &root.join("tls/leaf-0-key.der"),
        16384,
    )?));
    let resources = RoleResources::new(Role::A)?;
    let listener = Listener::bounded(
        ServerProfile::new(p.config.endpoints()[0], vec![cert], key)?,
        &resources,
    )?;
    save(
        &root.join("server-listening.json"),
        &serde_json::json!({"ready":true}),
    )?;
    let deadline = s.at(-9_000_000_000)?;
    let mut pending = loop {
        if Instant::now() >= deadline {
            return Err("server setup deadline".into());
        }
        if let Some(setup) = listener.accept(deadline)? {
            break setup;
        }
        thread::sleep(TICK);
    };
    let mut link = loop {
        match pending.poll()? {
            SetupStep::Pending(next) => pending = next,
            SetupStep::Established(link) => break link,
        }
        thread::sleep(TICK);
    };
    let manifest = read(&root.join("manifest.bin"), 256)?;
    wait(&s, if late { -4_900_000_000 } else { -8_000_000_000 })?;
    link.queue(
        RecordSize::Manifest,
        &manifest,
        s.at(if late { -4_000_000_000 } else { -7_000_000_000 })?,
    )?;
    while !link.write_step()? {
        thread::sleep(TICK);
    }
    if late {
        save(
            &root.join("server-result.json"),
            &serde_json::json!({"late_manifest_fixture":true,"no_cell_expected":true}),
        )?;
        return Ok(());
    }
    wait(&s, 1_000_000_000)?;
    link.expect(RecordSize::Cell, s.at(9_500_000_000)?)?;
    let bytes = loop {
        if let Some(bytes) = link.read_step()? {
            break bytes;
        }
        thread::sleep(TICK);
    };
    let received = Instant::now();
    let m = SignedManifest::verify(&manifest, &p.config, p.round)?;
    let context = PreparedR2Context::new(&p.config, &m, &p.profile, p.hash)?;
    let frame = PreparedR2Frame::decode(&bytes, &context, 1)?;
    // The private known fixture A key only. Opening B before its full32 gate
    // is deliberately NOT provided by this one-client receiver.
    let a = HpkePrivate::from_bytes(&[71; 32])?;
    let inner = open_a(&context, &a, &frame)?;
    save(
        &root.join("server-result.json"),
        &serde_json::json!({"status":"ONE_ACTUAL_TLS_CELL_OUTER_HPKE_OPENED",
        "received_offset_seconds":received.duration_since(s.at(0)?).as_secs_f64(),
        "stage2_bytes":inner.bytes().len(),"complete_cohort":false,"join_admission":false}),
    )?;
    Ok(())
}
fn relative(at: Option<Instant>, origin: Instant) -> Option<f64> {
    at.map(|t| {
        if t >= origin {
            t.duration_since(origin).as_secs_f64()
        } else {
            -origin.duration_since(t).as_secs_f64()
        }
    })
}
fn client(root: &Path, real: bool, expect_failure: bool, enrolled: bool) -> Result<()> {
    let p = Public::load(root)?;
    let s = Schedule::functional_fixture(&p.config, p.round)?;
    if enrolled {
        let e: serde_json::Value =
            serde_json::from_slice(&read(&root.join("expected.json"), 4096)?)?;
        if e["actual_tls_inputs"] != true || !real || expect_failure {
            return Err("explicit actual-input real-client context".into());
        }
        // Setup is outside Schedule::at's active [-10,+30] phase domain.
        // Derive the earlier wait from the SAME immutable origin; never rebase
        // a protocol deadline or invent an extended active-round phase.
        let setup_at = s.at(-10_000_000_000)?.checked_sub(Duration::from_secs(15))
            .ok_or("pre-round setup origin underflow")?;
        thread::sleep(setup_at.saturating_duration_since(Instant::now()));
    }
    let ep = p.config.endpoints()[0];
    let address = SocketAddr::new(Ipv6Addr::from(ep.address).into(), ep.port);
    let socket = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    let mut link = Transport::client(
        socket,
        ep,
        p.roots.clone(),
        s.at(-9_000_000_000)?
            .min(Instant::now() + Duration::from_secs(3)),
    )?;
    if enrolled {
        let tokens: serde_json::Value =
            serde_json::from_slice(&read(&root.join("tokens-public.json"), 8192)?)?;
        if tokens[0]["slot"] != 0 {
            return Err("actual client fixed slot0".into());
        }
        let token: [u8; 32] = hex(tokens[0]["token"].as_str().ok_or("public token")?)?;
        let raw = read(&root.join("roster-public.bin"), 1024)?;
        if raw.len() != 1024 {
            return Err("public fixture roster size".into());
        }
        let hashes: Vec<[u8; 32]> = raw
            .chunks_exact(32)
            .map(|b| b.try_into().expect("32"))
            .collect();
        let roster = silk_f04_relay::config::Roster::verify(
            hashes.try_into().map_err(|_| "32 roster")?,
            &p.config,
        )?;
        let mut join = [0; 128];
        join[..8].copy_from_slice(b"SNJOIN03");
        join[8..40].copy_from_slice(&p.config.domain());
        join[40..44].copy_from_slice(&p.config.cohort().to_le_bytes());
        join[44..48].copy_from_slice(&p.config.epoch().to_le_bytes());
        join[48..80].copy_from_slice(&token);
        if roster.slot(&roster.verify_join(&join, &p.config)?)? != 0 {
            return Err("actual slot mismatch".into());
        }
        let deadline = s
            .at(-10_000_000_000)?
            .min(Instant::now() + Duration::from_secs(5));
        link.queue(RecordSize::Join, &join, deadline)?;
        while !link.write_step()? {
            thread::sleep(TICK);
        }
    }
    let dir = root.join("client-scope");
    fs::create_dir(&dir)?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    let mut store = PreparedScopeStore::create(
        &dir,
        p.profile.claim_binding(ClaimRole::Client),
        Pins(root.join("client-pin")),
    )?;
    let members: serde_json::Value =
        serde_json::from_slice(&read(&root.join("members-public.json"), 8192)?)?;
    let commitment = hex(members[0]["commitment"].as_str().ok_or("member")?)?;
    let offer = if real {
        Some(Zeroizing::new(
            read(&root.join("envelope.bin"), 2790)?
                .try_into()
                .map_err(|_| "envelope")?,
        ))
    } else {
        None
    };
    let mut owner = ClientRoundLab::new_exposed_fixture_lab(
        Rc::clone(&p.config),
        s,
        &p.profile,
        &p.vk,
        p.hash,
        commitment,
        LocalViewV1::Genesis(Rc::clone(&p.genesis)),
        0,
        link,
        &mut store,
        offer,
    )?;
    let origin = owner.at_lab(0)?;
    let mut jobs = 0;
    let mut result_seen = false;
    let mut failure = None;
    let outcome = loop {
        if failure.is_none() {
            if let Err(e) = owner.poll() {
                failure = Some(e.to_string());
            }
        }
        if failure.is_none() {
            if let Some(job) = owner.take_job()? {
                jobs += 1;
                if jobs != 1 {
                    return Err("second proof dispatch".into());
                }
                // Read native monotonic BEFORE Instant, giving a conservative
                // absolute deadline for the independently contained exec guardian.
                let mono = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
                let native =
                    Duration::new(u64::try_from(mono.tv_sec)?, u32::try_from(mono.tv_nsec)?);
                let remaining = job
                    .deadline
                    .checked_duration_since(Instant::now())
                    .ok_or("expired dispatch")?;
                let deadline = native
                    .checked_add(remaining)
                    .ok_or("native deadline overflow")?;
                save(
                    &root.join("job-request.json"),
                    &serde_json::json!({"root":text(&job.root),"message":text(&job.message),"scope":text(&job.scope),
                "profile":text(&job.profile),"manifest":text(&job.manifest),"round":job.round,
                "absolute_monotonic_ns":deadline.as_nanos().to_string()}),
                )?;
            }
        }
        if failure.is_none() && !result_seen && root.join("worker-result.json").exists() {
            result_seen = true;
            let output: serde_json::Value =
                serde_json::from_slice(&read(&root.join("worker-result.json"), 8192)?)?;
            let result = owner.complete_job(ProofOutputLab {
                nullifier: hex(output["nullifier"].as_str().ok_or("nullifier")?)?,
                packed_proof: hex(output["packed_proof"].as_str().ok_or("proof")?)?,
            });
            if let Err(e) = result {
                failure = Some(e.to_string());
            }
        }
        if let Some(outcome) = owner.take_outcome()? {
            break outcome;
        }
        thread::sleep(TICK);
    };
    let t = owner.timing_lab();
    let status = match outcome.status {
        WriteStatusV1::RealWriteComplete => "REAL_WRITE_COMPLETE",
        WriteStatusV1::CoverWriteComplete => "COVER_WRITE_COMPLETE",
        WriteStatusV1::Silent => "SILENT",
        WriteStatusV1::WriteUncertain => "WRITE_UNCERTAIN",
    };
    save(
        &root.join("client-result.json"),
        &serde_json::json!({"status":status,"round":p.round,"jobs":jobs,"failure":failure,
        "manifest":relative(t.manifest,origin),"claimed":relative(t.claimed,origin),"dispatch":relative(t.dispatched,origin),
        "proof":relative(t.proof,origin),"frame":relative(t.frame,origin),"write":relative(t.write,origin),
        "actual_utc":true,"operational":false,"actual_tls_join":enrolled,"join_admission":false,"new_wallet_proof":false}),
    )?;
    if owner.take_outcome()?.is_some() {
        return Err("outcome replay".into());
    }
    drop(owner);
    if jobs > 0 && store.consume(p.round, [99; 32], [98; 32]).is_ok() {
        return Err("consumed scope reopened".into());
    }
    let expected = if expect_failure {
        WriteStatusV1::Silent
    } else if real {
        WriteStatusV1::RealWriteComplete
    } else {
        WriteStatusV1::CoverWriteComplete
    };
    if outcome.status != expected {
        return Err(format!("unexpected client result {status}").into());
    }
    Ok(())
}
fn main() {
    let result = (|| -> Result<()> {
        let args: Vec<_> = std::env::args().collect();
        if args.len() != 5 || args[1] != "--unqualified-functional-lab" {
            return Err("explicit lab flag/mode/root/case required".into());
        }
        if !matches!(
            args[4].as_str(),
            "real" | "cover" | "late-manifest" | "bad-proof"
        ) {
            return Err("unknown case".into());
        }
        let root = Path::new(&args[3]);
        let late = args[4] == "late-manifest";
        match args[2].as_str() {
            "server" => server(root, late),
            "client" => client(
                root,
                args[4] == "real",
                late || args[4] == "bad-proof",
                false,
            ),
            "client-enrolled" => client(
                root,
                args[4] == "real",
                late || args[4] == "bad-proof",
                true,
            ),
            _ => Err("unknown mode".into()),
        }
    })();
    if let Err(e) = result {
        eprintln!("client lab refused: {e}");
        std::process::exit(1);
    }
}
