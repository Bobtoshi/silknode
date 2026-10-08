//! Actual ordinary wallet offer and original TLS, with two external contained
//! workers. Same-host functional fixture only; not role/custody qualification.
use super::*;
use ed25519_dalek::{Signer, SigningKey};
use hpke::{Deserializable, Kem, Serializable, kem::X25519HkdfSha256};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use silk_f04_node::genesis::Genesis;
use silk_f04_relay::{
    aip2_claim::{ClaimResult, PreparedScopeStore},
    aip2_profile::ProfileExpectations,
    aip2_proof::hex,
    frame::HpkePrivate,
    im3_gate::{MiddlePins, open_at_a},
    tls::{SetupStep, spki_pin},
};
use silk_f04_wallet::{
    backup,
    journal::{
        Journal,
        intents::{IntentReceipt, IntentStatus},
    },
};
use silk_sapling_f04::codec::domain_hash;
use std::{
    fs,
    io::Write,
    net::{Ipv6Addr, SocketAddr, TcpListener, TcpStream},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

fn save(p: &Path, bytes: &[u8]) {
    save_checked(p, bytes).unwrap();
}
fn save_checked(p: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(p)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    fs::File::open(p.parent().unwrap())?.sync_all()
}
fn text(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
fn wait(at: Instant) {
    std::thread::sleep(at.saturating_duration_since(Instant::now()));
}
fn dir(p: &Path) {
    fs::create_dir(p).unwrap();
    fs::set_permissions(p, fs::Permissions::from_mode(0o700)).unwrap();
}
struct Pins(PathBuf);
impl ClaimPinRetention for Pins {
    fn retain_claim_pin(&mut self, pin: [u8; 32]) -> ClaimResult<()> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&self.0)?;
        f.write_all(&pin)?;
        f.sync_all()?;
        fs::File::open(self.0.parent().unwrap())?.sync_all()?;
        Ok(())
    }
}
fn q(config: &SignedConfig, profile: &PreparedProfile, tls: [u8; 32]) -> PreparedQ {
    let private = HpkePrivate::from_bytes(&[73; 32]).unwrap();
    let hpke: [u8; 32] = X25519HkdfSha256::sk_to_pk(&private)
        .to_bytes()
        .as_slice()
        .try_into()
        .unwrap();
    let mut b = [0; 512];
    b[..8].copy_from_slice(b"SNIM3P01");
    b[8..40].copy_from_slice(&config.domain());
    b[40..72].copy_from_slice(&config.id());
    b[72..104].copy_from_slice(&profile.id());
    b[104..108].copy_from_slice(&config.epoch().to_le_bytes());
    b[108..112].copy_from_slice(&config.cohort().to_le_bytes());
    let first = u64::from(config.epoch()) * 2880;
    b[112..120].copy_from_slice(&first.to_le_bytes());
    b[120..128].copy_from_slice(&(first + 2880).to_le_bytes());
    let signing = SigningKey::from_bytes(&[16; 32]).verifying_key().to_bytes();
    b[128..160].copy_from_slice(&signing);
    b[160..192].copy_from_slice(&hpke);
    b[192..224].copy_from_slice(&tls);
    b[239] = 1;
    b[240..242].copy_from_slice(&31005u16.to_le_bytes());
    b[244..276].copy_from_slice(&domain_hash("SilkNode-IM3-policy", &[b"IM3-60-v1"]));
    for (at, seed) in [(320, 11), (384, 16), (448, 12)] {
        let label = b"SilkNode-IM3-profile-sign";
        let mut message = vec![label.len() as u8];
        message.extend_from_slice(label);
        message.extend_from_slice(&b[..320]);
        b[at..at + 64].copy_from_slice(
            &SigningKey::from_bytes(&[seed; 32])
                .sign(&message)
                .to_bytes(),
        );
    }
    PreparedQ::verify(&b, config, profile, &MiddlePins { signing, hpke, tls }).unwrap()
}
fn pair(config: &SignedConfig, root: &Path) -> (Transport, Transport) {
    let ep = config.endpoints()[0];
    let addr = SocketAddr::new(Ipv6Addr::from(ep.address).into(), ep.port);
    let listener = TcpListener::bind(addr).unwrap();
    let client = TcpStream::connect(addr).unwrap();
    let server = listener.accept().unwrap().0;
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(
            fs::read(root.join("tls/root.der")).unwrap(),
        ))
        .unwrap();
    let end = Instant::now() + Duration::from_secs(3);
    let mut pending = [
        Some(Transport::client_setup(client, ep, roots, end).unwrap()),
        Some(
            Transport::server_setup(
                server,
                ep,
                vec![CertificateDer::from(
                    fs::read(root.join("tls/leaf-0.der")).unwrap(),
                )],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    fs::read(root.join("tls/leaf-0-key.der")).unwrap(),
                )),
                end,
            )
            .unwrap(),
        ),
    ];
    let mut done = [None, None];
    while done.iter().any(Option::is_none) {
        assert!(Instant::now() < end);
        for i in 0..2 {
            if let Some(p) = pending[i].take() {
                match p.poll().unwrap() {
                    SetupStep::Pending(p) => pending[i] = Some(p),
                    SetupStep::Established(t) => done[i] = Some(t),
                }
            }
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    (done[0].take().unwrap(), done[1].take().unwrap())
}
// Explicit same-execution fixture only. The relay already owns/listens on A;
// this side establishes one client link once, with no reconnect/retry loop.
fn external_client(config: &SignedConfig, root: &Path) -> Transport {
    let ep = config.endpoints()[0];
    let addr = SocketAddr::new(Ipv6Addr::from(ep.address).into(), ep.port);
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(
            fs::read(root.join("tls/root.der")).unwrap(),
        ))
        .unwrap();
    let end = Instant::now() + Duration::from_secs(3);
    let mut setup =
        Transport::client_setup(TcpStream::connect(addr).unwrap(), ep, roots, end).unwrap();
    loop {
        assert!(Instant::now() < end);
        match setup.poll().unwrap() {
            SetupStep::Established(link) => return link,
            SetupStep::Pending(next) => setup = next,
        }
        std::thread::sleep(Duration::from_micros(100));
    }
}
fn offer(wallet: &Path, margin: &Path) -> SavedOfferV1 {
    // Existing valueless fixture only; key never enters the client owner or worker.
    let pins = fs::read(wallet.join("wallet-pins-before-export")).unwrap();
    assert_eq!(pins.len(), 96);
    let domain = pins[..32].try_into().unwrap();
    let password = "PUBLIC CANONICAL RUNTIME TEST PASSWORD";
    let key = backup::load(&wallet.join("encrypted-key"), domain, password).unwrap();
    let mut journal = Journal::open(
        &wallet.join("wallet"),
        margin,
        &key,
        password,
        pins[32..64].try_into().unwrap(),
    )
    .unwrap();
    let mut intents = journal.intents(pins[64..96].try_into().unwrap()).unwrap();
    assert_eq!(
        intents.receipt().unwrap().status,
        IntentStatus::MayHaveEscaped
    );
    let mut retain = |receipt: &IntentReceipt| {
        let mut next = Vec::from(domain);
        next.extend_from_slice(&receipt.address_head);
        next.extend_from_slice(&receipt.intent_head);
        save(&wallet.join("wallet-pins-after-handoff"), &next);
        Ok(())
    };
    intents
        .offer_saved(pins[64..96].try_into().unwrap(), &mut retain)
        .unwrap()
}
fn job(
    out: &Path,
    role: &str,
    request: ClientProofJob,
    profile: [u8; 32],
    manifest: [u8; 32],
    round: u64,
    b_message: [u8; 32],
    slot: u8,
    member_index: u8,
) -> Result<ClientProofOutput> {
    let native = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    let stamp = Duration::new(
        native.tv_sec.try_into().unwrap(),
        native.tv_nsec.try_into().unwrap(),
    );
    let deadline = stamp
        + request
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or(Error::Unavailable("IM3 original worker deadline"))?;
    let [root, message, scope] = request.statement;
    let folder = out.join(role);
    save_checked(&folder.join("job-request.json"), &serde_json::to_vec(&serde_json::json!({"root":text(&root),"message":text(&message),"scope":text(&scope),
        "profile":text(&profile),"manifest":text(&manifest),"round":round,"b_message":text(&b_message),
        "slot":slot,"member_index":member_index,"absolute_monotonic_ns":deadline.as_nanos().to_string()})).map_err(|_| Error::Invalid("IM3 worker request encoding"))?)?;
    let result = folder.join("worker-result.json");
    while !result.exists() {
        if Instant::now() >= request.deadline {
            return Err(Error::Unavailable("IM3 original worker deadline"));
        }
        std::thread::sleep(Duration::from_micros(500));
    }
    let v: serde_json::Value = serde_json::from_slice(&fs::read(result)?)
        .map_err(|_| Error::Invalid("IM3 worker output encoding"))?;
    if v["role"] != role || v["new_proofs"] != 1 || v["precomputed"] != false
        || v["slot"] != slot || v["member_index"] != member_index
        || v["manifest"] != text(&manifest) || v["round"] != round
    {
        return Err(Error::Invalid("IM3 worker output binding"));
    }
    Ok(ClientProofOutput {
        nullifier: hex(v["nullifier"].as_str().ok_or(Error::Invalid("IM3 worker nullifier"))?)
            .map_err(|_| Error::Invalid("IM3 worker nullifier"))?,
        proof: hex(v["packed_proof"].as_str().ok_or(Error::Invalid("IM3 worker proof"))?)
            .map_err(|_| Error::Invalid("IM3 worker proof"))?,
    })
}

#[test]
#[ignore = "explicit VPS fixture wallet, original TLS, externally contained two workers"]
fn ordinary_wallet_original_tls_and_two_workers() {
    // Fixture identity is explicit. A second client must not silently reuse
    // slot zero's credential merely because it has a separate output folder.
    let slot: u8 = std::env::var("SILK_IM3_CLIENT_SLOT")
        .unwrap_or_else(|_| "0".into())
        .parse()
        .unwrap();
    let member_index: u8 = std::env::var("SILK_IM3_CLIENT_MEMBER_INDEX")
        .unwrap_or_else(|_| "0".into())
        .parse()
        .unwrap();
    assert!(slot < 32 && member_index < 32);
    assert!(slot == 0 || std::env::var_os("SILK_IM3_CLIENT_MEMBER_INDEX").is_some());
    let cover = std::env::var_os("SILK_IM3_CLIENT_COVER").is_some();
    silk_f04_relay::schedule::initialize_functional_offset(
        std::env::var("SILK_IM3_CLIENT_FIXTURE_OFFSET_SECONDS")
            .unwrap()
            .parse()
            .unwrap(),
    )
    .unwrap();
    let root = PathBuf::from(std::env::var_os("SILK_IM3_CLIENT_TLS_ROOT").unwrap());
    let out = PathBuf::from(std::env::var_os("SILK_IM3_CLIENT_TLS_OUT").unwrap());
    let wallet = PathBuf::from(std::env::var_os("SILK_IM3_CLIENT_TLS_WALLET").unwrap());
    let e: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("expected.json")).unwrap()).unwrap();
    let domain = hex(e["domain"].as_str().unwrap()).unwrap();
    let round = e["round"].as_u64().unwrap();
    let cohort = u32::try_from(e["cohort"].as_u64().unwrap()).unwrap();
    let keys = [
        hex(e["role_keys"][0].as_str().unwrap()).unwrap(),
        hex(e["role_keys"][1].as_str().unwrap()).unwrap(),
    ];
    let config = Rc::new(
        SignedConfig::verify(
            &fs::read(root.join("config.bin")).unwrap(),
            domain,
            cohort,
            e["epoch"].as_u64().unwrap().try_into().unwrap(),
            keys,
        )
        .unwrap(),
    );
    let vk_hash = hex(e["vk_hash"].as_str().unwrap()).unwrap();
    let profile = PreparedProfile::verify(
        &fs::read(root.join("profile.bin")).unwrap(),
        &ProfileExpectations {
            domain,
            config: config.id(),
            epoch: config.epoch(),
            cohort,
            vk_hash,
            role_keys: keys,
        },
    )
    .unwrap();
    let verifier = PreparedProofVerifier::from_canonical_vk(
        &fs::read(root.join("vk-canonical.json")).unwrap(),
        vk_hash,
    )
    .unwrap();
    let overlay = q(
        &config,
        &profile,
        spki_pin(&CertificateDer::from(
            fs::read(root.join("tls/c.der")).unwrap(),
        ))
        .unwrap(),
    );
    save(&out.join("q.bin"), overlay.bytes());
    let genesis = Rc::new(
        Genesis::admit_local_bundle(
            &fs::read(root.join("public-genesis")).unwrap(),
            &domain,
            true,
        )
        .unwrap(),
    );
    let offer = if cover { None } else { Some(offer(&wallet, &out)) };
    let expected = if cover {
        None
    } else {
        Some(fs::read(wallet.join("payment-2790")).unwrap())
    };
    let external = std::env::var_os("SILK_IM3_CLIENT_EXTERNAL_A").is_some();
    let (client, mut server) = if external {
        (external_client(&config, &root), None)
    } else {
        let (client, server) = pair(&config, &root);
        (client, Some(server))
    };
    let schedule = Im3Schedule::functional_fixture(&config, round).unwrap();
    let origin = schedule.at(0).unwrap();
    let client_slot_end = schedule.client_slot(slot).unwrap().1;
    let offsets = |t: Instant| {
        if t >= origin {
            (t - origin).as_secs_f64()
        } else {
            -(origin - t).as_secs_f64()
        }
    };
    let choice = out.join("client-scope");
    dir(&choice);
    let mut store = PreparedScopeStore::create(
        &choice,
        profile.claim_binding(ClaimRole::Client),
        Pins(out.join("client-pin")),
    )
    .unwrap();
    let mut session = OriginalClientLab::begin(
        Rc::clone(&config),
        schedule,
        &profile,
        &overlay,
        verifier,
        LocalViewV1::Genesis(genesis),
        &mut store,
        slot,
        client,
        offer,
    )
    .unwrap();
    if external {
        save(&out.join("original-link-ready"), b"original client link established\n");
    }
    if let Some(server) = &mut server {
        wait(origin - Duration::from_secs(8));
        let end = origin - Duration::from_secs(7);
        server
            .queue(
                RecordSize::Manifest,
                &fs::read(root.join("manifest.bin")).unwrap(),
                end,
            )
            .unwrap();
        while !server.write_step().unwrap() {
            assert!(Instant::now() < end);
            std::thread::sleep(Duration::from_micros(100));
        }
    }
    let mut observations = Vec::new();
    // No record can be read before this fixed opening. Avoid repeated host
    // clock captures in an idle pre-phase; wake and enforce the original guard.
    wait(origin - Duration::from_secs(8));
    while !session.poll_manifest().unwrap() {
        if let Some(o) = session.take_wire_observation() {
            observations.push(serde_json::json!({"surface":"client_manifest_read","connection":o.connection,"start":offsets(o.started),"end":offsets(o.completed),"bytes":o.bytes,"complete":o.record_complete,"failed":o.failed}));
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    if let Some(o) = session.take_wire_observation() {
        observations.push(serde_json::json!({"surface":"client_manifest_read","connection":o.connection,"start":offsets(o.started),"end":offsets(o.completed),"bytes":o.bytes,"complete":o.record_complete,"failed":o.failed}));
    }
    let manifest = SignedManifest::verify(
        &fs::read(root.join("manifest.bin")).unwrap(),
        &config,
        round,
    )
    .unwrap();
    let context = MiddleContext::new(&config, &manifest, &profile, vk_hash, &overlay).unwrap();
    session.run(|stream| {
        wait(origin-Duration::from_secs(5)); stream.freeze()?;
        wait(origin-Duration::from_millis(4500)); let b=stream.take_b_job()?; let b_message=b.statement[1];
        stream.complete_b(job(&out,"B",b,profile.id(),manifest.id(),round,b_message,slot,member_index)?)?;
        wait(origin+Duration::from_millis(500));stream.seal_b()?;
        wait(origin+Duration::from_secs(1));let c=stream.take_c_job()?;
        stream.complete_c(job(&out,"C",c,profile.id(),manifest.id(),round,b_message,slot,member_index)?)?;
        wait(origin+Duration::from_secs(6));stream.seal_onion()?;
        // Administrative test visibility only; production exposes no onion bytes.
        let onion_hash=domain_hash("IM3-test-original-onion",&[stream.frame.as_ref().unwrap().bytes()]);
        let cutoff=client_slot_end;
        if let Some(server) = &mut server { server.expect(RecordSize::Cell,cutoff)?; }
        loop {
            let done=stream.poll_write()?;
            if let Some(o)=stream.take_wire_observation() { observations.push(serde_json::json!({"surface":"client_write","connection":o.connection,"start":offsets(o.started),"end":offsets(o.completed),"bytes":o.bytes,"complete":o.record_complete,"failed":o.failed})); }
            if done { break; } std::thread::sleep(Duration::from_micros(100));
        }
        if let Some(server) = &mut server {
        let received = loop {
        let (r, o) = server.read_step_observed();
        observations.push(serde_json::json!({"surface":"A_read","connection":o.connection,"start":offsets(o.started),"end":offsets(o.completed),"bytes":o.bytes,"complete":o.record_complete,"failed":o.failed}));
        if let Some(bytes) = r? {
            break bytes;
        }
        assert!(Instant::now() < cutoff);
        std::thread::sleep(Duration::from_micros(100));
        };
        assert_eq!(
        domain_hash("IM3-test-original-onion", &[&received]),
        onion_hash
    );
    let onion = MiddleFrame::decode(&received, &context, 1).unwrap();
    let a = HpkePrivate::from_bytes(&[71; 32]).unwrap();
    let stage2 = open_at_a(&context, &a, &onion).unwrap();
    save(&out.join("stage2-from-actual-client.bin"), stage2.bytes());
        }
        // External A receives and opens this exact original write itself; no
        // onion/stage2 file or supplied acknowledgement bridges the processes.
        save(&out.join("original-onion-commitment"), &onion_hash);
        while !stream.poll_cleanup()? { std::thread::sleep(Duration::from_millis(5)); }
        Ok(())
    }).unwrap();
    save(
        &out.join("wire-observations.json"),
        &serde_json::to_vec(&observations).unwrap(),
    );
    let cover_message = original_cover_message(&profile, manifest.id(), round);
    assert_eq!(cover, cover_message == read_b_message(&out));
    if let Some(expected) = expected {
        assert_eq!(expected, fs::read(root.join("envelope.bin")).unwrap());
    }
    drop(store);
    let pin = fs::read(out.join("client-pin"))
        .unwrap()
        .try_into()
        .unwrap();
    let mut cold = PreparedScopeStore::open(
        &choice,
        profile.claim_binding(ClaimRole::Client),
        pin,
        round,
        Pins(out.join("client-pin")),
    )
    .unwrap();
    assert!(cold.consume(round, [7; 32], [8; 32]).is_err());
    let result = serde_json::json!({"status":if cover {"PASS_COVER_ORIGINAL_TLS_TWO_WORKERS"} else {"PASS_ORDINARY_WALLET_ORIGINAL_TLS_TWO_WORKERS"},"new_B_proofs":1,"new_C_proofs":1,"fixed_slot":slot,"member_index":member_index,"cold_round_replay_refused":true,
        "ordinary_SavedOfferV1":!cover,"original_connection_held_until_cleanup":true,"qualified_clock":false,"independent_custody":false,"complete_cohort":false,"settlement":false,
        "external_original_A":external,"same_original_onion_received":!external,"same_execution_relay_receipt_required":external});
    save(
        &out.join("client-result.json"),
        &serde_json::to_vec(&result).unwrap(),
    );
    println!("{result}");
}
fn original_cover_message(p: &PreparedProfile, m: [u8; 32], r: u64) -> [u8; 32] {
    silk_f04_relay::aip2_proof::prepare_cover_statement(p, m, r)
        .unwrap()
        .message()
}
fn read_b_message(out: &Path) -> [u8; 32] {
    let v: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("B/job-request.json")).unwrap()).unwrap();
    hex(v["message"].as_str().unwrap()).unwrap()
}

#[test]
#[ignore = "explicit private fresh-context fixture; read-only, no wallet or claim"]
fn fresh_context_genesis_and_envelope_without_claim() {
    let root = PathBuf::from(std::env::var_os("SILK_IM3_CLIENT_TLS_ROOT").unwrap());
    let e: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("expected.json")).unwrap()).unwrap();
    let domain = hex(e["domain"].as_str().unwrap()).unwrap();
    let round = e["round"].as_u64().unwrap();
    let keys = [
        hex(e["role_keys"][0].as_str().unwrap()).unwrap(),
        hex(e["role_keys"][1].as_str().unwrap()).unwrap(),
    ];
    let config = SignedConfig::verify(
        &fs::read(root.join("config.bin")).unwrap(),
        domain,
        u32::try_from(e["cohort"].as_u64().unwrap()).unwrap(),
        u32::try_from(e["epoch"].as_u64().unwrap()).unwrap(),
        keys,
    )
    .unwrap();
    let manifest = SignedManifest::verify(
        &fs::read(root.join("manifest.bin")).unwrap(),
        &config,
        round,
    )
    .unwrap();
    let genesis = Rc::new(
        Genesis::admit_local_bundle(
            &fs::read(root.join("public-genesis")).unwrap(),
            &domain,
            true,
        )
        .unwrap(),
    );
    selected_cut(&LocalViewV1::Genesis(genesis), &config, &manifest).unwrap();
    let envelope = fs::read(root.join("envelope.bin")).unwrap();
    let view = silk_sapling_f04::codec::EnvelopeView::decode(&envelope, &domain).unwrap();
    silk_f04_relay::frame::Payload::real_view(
        &view,
        &RoundContext::new(&config, &manifest).unwrap(),
    )
    .unwrap();
    let context = RoundContext::new(&config, &manifest).unwrap();
    let original: [u8; ENVELOPE_BYTES] = envelope.try_into().unwrap();
    let real = Payload::client_choice(Some(Zeroizing::new(original)), &context).unwrap();
    assert_eq!(real.real_bytes(), Some(&original));
    assert!(!Payload::client_choice(None, &context).unwrap().is_real());
    // Every codec framing condition and every manifest binding remains required.
    // No malformed offer may silently become a different cover Cell.
    for at in [0, 8, 9, 10, 11, 12, 44, 52, 84, 277, 1790, 1797, 1798] {
        let mut bad = original;
        bad[at] ^= 1;
        assert!(Payload::client_choice(Some(Zeroizing::new(bad)), &context).is_err(), "{at}");
    }
    let mut same_nullifiers = original;
    same_nullifiers[213..245].copy_from_slice(&original[117..149]);
    assert!(Payload::client_choice(Some(Zeroizing::new(same_nullifiers)), &context).is_err());
    println!("PASS_FIXED_PAYLOAD_CHOICE_EXACT_REAL_COVER_AND_MALFORMED_REFUSAL");
}

#[test]
#[ignore = "explicit VPS public TLS fixture; recoverable failure only, no proofs"]
fn preparation_failure_driver_holds_original_socket_to_fixed_boundary() {
    let root = PathBuf::from(std::env::var_os("SILK_IM3_CLIENT_TLS_ROOT").unwrap());
    let e: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("expected.json")).unwrap()).unwrap();
    let domain = hex(e["domain"].as_str().unwrap()).unwrap();
    let round = e["round"].as_u64().unwrap();
    let role_keys = [
        hex(e["role_keys"][0].as_str().unwrap()).unwrap(),
        hex(e["role_keys"][1].as_str().unwrap()).unwrap(),
    ];
    let config = Rc::new(SignedConfig::verify(
        &fs::read(root.join("config.bin")).unwrap(), domain,
        e["cohort"].as_u64().unwrap().try_into().unwrap(),
        e["epoch"].as_u64().unwrap().try_into().unwrap(), role_keys,
    ).unwrap());
    let vk_hash = hex(e["vk_hash"].as_str().unwrap()).unwrap();
    let profile = PreparedProfile::verify(&fs::read(root.join("profile.bin")).unwrap(),
        &ProfileExpectations { domain, config: config.id(), epoch: config.epoch(),
            cohort: config.cohort(), vk_hash, role_keys }).unwrap();
    let verifier = PreparedProofVerifier::from_canonical_vk(
        &fs::read(root.join("vk-canonical.json")).unwrap(), vk_hash).unwrap();
    let overlay = q(&config, &profile,
        spki_pin(&CertificateDer::from(fs::read(root.join("tls/c.der")).unwrap())).unwrap());
    let genesis = Rc::new(Genesis::admit_local_bundle(
        &fs::read(root.join("public-genesis")).unwrap(), &domain, true).unwrap());
    let (client, mut server) = pair(&config, &root);
    let physical_t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 10;
    silk_f04_relay::schedule::initialize_functional_offset(
        i64::try_from(round * 30).unwrap() - i64::try_from(physical_t).unwrap()).unwrap();
    let schedule = Im3Schedule::functional_fixture(&config, round).unwrap();
    let origin = schedule.at(0).unwrap();
    let cleanup_at = schedule.at(44_000_000_000).unwrap();
    let private = tempfile::tempdir().unwrap();
    fs::set_permissions(private.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let scope = private.path().join("scope");
    dir(&scope);
    let mut store = PreparedScopeStore::create(&scope,
        profile.claim_binding(ClaimRole::Client), Pins(private.path().join("pin"))).unwrap();
    let mut session = OriginalClientLab::begin(Rc::clone(&config), schedule, &profile,
        &overlay, verifier, LocalViewV1::Genesis(genesis), &mut store, 0, client, None).unwrap();
    wait(origin - Duration::from_secs(8));
    server.queue(RecordSize::Manifest, &fs::read(root.join("manifest.bin")).unwrap(),
        origin - Duration::from_secs(7)).unwrap();
    while !server.write_step().unwrap() { std::thread::sleep(Duration::from_micros(100)); }
    while !session.poll_manifest().unwrap() { std::thread::sleep(Duration::from_micros(100)); }
    let result: Result<()> = session.run(|stream| {
        // A real admitted owner durably consumes its original choice. An
        // out-of-order C dispatch must destroy that authority immediately.
        assert!(stream.owner.is_some());
        wait(origin - Duration::from_secs(5) + Duration::from_millis(10));
        stream.freeze().unwrap();
        assert!(stream.take_c_job().is_err());
        assert!(stream.owner.is_none() && stream.frame.is_none() && stream.link.is_none());
        assert!(stream.cleanup.is_some());
        assert!(!stream.cleanup.as_mut().unwrap().poll());
        assert!(stream.freeze().is_err());
        assert!(stream.take_b_job().is_err());
        assert!(stream.take_c_job().is_err());
        assert!(stream.seal_onion().is_err());
        assert!(stream.poll_write().is_err());
        assert!(!server.has_extra_bytes().unwrap()); // still open; no Cell
        Err(Error::Unavailable("test recoverable worker failure"))
    });
    assert!(matches!(result, Err(Error::Unavailable("test recoverable worker failure"))));
    assert!(Instant::now() >= cleanup_at);
    assert!(Instant::now() < cleanup_at + Duration::from_secs(2));
    assert!(matches!(server.has_extra_bytes(), Err(Error::Unavailable("TLS peer closed"))));
    drop(store);
    let pin = fs::read(private.path().join("pin")).unwrap().try_into().unwrap();
    let mut cold = PreparedScopeStore::open(&scope,
        profile.claim_binding(ClaimRole::Client), pin, round,
        Pins(private.path().join("pin"))).unwrap();
    assert!(cold.consume(round, [7; 32], [8; 32]).is_err());
    println!("PASS_PREPARATION_AUTHORITY_DESTROYED_ORIGINAL_SOCKET_HELD_TO_T44_NO_WRITES");
}

#[test]
#[ignore = "explicit VPS public TLS fixture; no worker/proof/wallet operation"]
fn cleanup_accepts_peer_close_only_at_original_cutoff() {
    let root = PathBuf::from(std::env::var_os("SILK_IM3_CLIENT_TLS_ROOT").unwrap());
    let e: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("expected.json")).unwrap()).unwrap();
    let round = e["round"].as_u64().unwrap();
    let config = SignedConfig::verify(
        &fs::read(root.join("config.bin")).unwrap(),
        hex(e["domain"].as_str().unwrap()).unwrap(),
        7,
        e["epoch"].as_u64().unwrap().try_into().unwrap(),
        [
            hex(e["role_keys"][0].as_str().unwrap()).unwrap(),
            hex(e["role_keys"][1].as_str().unwrap()).unwrap(),
        ],
    )
    .unwrap();
    let (client, mut server) = pair(&config, &root);
    let physical_t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 43;
    silk_f04_relay::schedule::initialize_functional_offset(
        i64::try_from(round * 30).unwrap() - i64::try_from(physical_t).unwrap(),
    )
    .unwrap();
    let schedule = Im3Schedule::functional_fixture(&config, round).unwrap();
    // Isolated private post-write state, not a forged production capability or
    // a claim that this small lifecycle test exercised the genuine proof path.
    let mut stream = ClientStreamLab::<Pins> {
        owner: None,
        schedule: &schedule,
        link: Some(client),
        cleanup: None,
        cleanup_at: schedule.at(44_000_000_000).unwrap(),
        slot: 0,
        frame: None,
        queued: true,
        complete: true,
        cleaned_up: false,
        failed: false,
        observation: None,
    };
    assert!(!stream.poll_cleanup().unwrap());
    wait(schedule.at(44_000_000_000).unwrap());
    server.quarantine().unwrap();
    assert!(stream.poll_cleanup().unwrap());
    assert!(stream.poll_cleanup().unwrap());
    println!("PASS_FIXED_CLEANUP_ACCEPTS_EXPECTED_PEER_EOF_NO_PROOFS");
}
