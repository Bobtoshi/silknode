//! Genuine-proof adversarial gate fixture. Administrative test visibility of C
//! plaintext is not an exported production API or independent-custody evidence.
use super::*;
use crate::{
    aip2_claim::{ClaimError, ClaimResult},
    aip2_profile::ProfileExpectations,
    aip2_proof::hex,
};
use ed25519_dalek::SigningKey;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Clone, Default)]
struct Pins(Arc<Mutex<(Digest, bool)>>);
impl ClaimPinRetention for Pins {
    fn retain_claim_pin(&mut self, pin: Digest) -> ClaimResult<()> {
        let mut p = self.0.lock().unwrap();
        if p.1 {
            return Err(ClaimError::Unavailable("fixture pin failure"));
        }
        p.0 = pin;
        Ok(())
    }
}
fn directory(p: &Path) {
    fs::create_dir(p).unwrap();
    fs::set_permissions(p, fs::Permissions::from_mode(0o700)).unwrap();
}
fn text(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}
fn save(p: &Path, b: &[u8]) {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(p)
        .unwrap();
    f.write_all(b).unwrap();
    f.sync_all().unwrap();
}
fn sign(seed: u8, label: &'static str, b: &[u8]) -> [u8; 64] {
    silk_f04_node::auth::sign_role(&SigningKey::from_bytes(&[seed; 32]), &message(label, &[b]))
        .unwrap()
}
fn q_bytes(cfg: &SignedConfig, p: &PreparedProfile, c_key: Digest) -> [u8; 512] {
    let mut q = [0; 512];
    q[..8].copy_from_slice(b"SNIM3P01");
    q[8..40].copy_from_slice(&cfg.domain());
    q[40..72].copy_from_slice(&cfg.id());
    q[72..104].copy_from_slice(&p.id());
    q[104..108].copy_from_slice(&cfg.epoch().to_le_bytes());
    q[108..112].copy_from_slice(&cfg.cohort().to_le_bytes());
    let first = u64::from(cfg.epoch()) * 2880;
    q[112..120].copy_from_slice(&first.to_le_bytes());
    q[120..128].copy_from_slice(&(first + 2880).to_le_bytes());
    q[128..160].copy_from_slice(&SigningKey::from_bytes(&[16; 32]).verifying_key().to_bytes());
    q[160..192].copy_from_slice(&c_key);
    q[192..224].copy_from_slice(&fixture_c_tls_pin());
    q[239] = 1;
    q[240..242].copy_from_slice(&31005u16.to_le_bytes());
    q[244..276].copy_from_slice(&domain_hash("SilkNode-IM3-policy", &[b"IM3-60-v1"]));
    for (at, seed) in [(320, 11), (384, 16), (448, 12)] {
        let s = sign(seed, "SilkNode-IM3-profile-sign", &q[..320]);
        q[at..at + 64].copy_from_slice(&s);
    }
    q
}
fn fixture_c_tls_pin() -> Digest {
    if let Some(path) = std::env::var_os("SILK_IM3_C_TLS") {
        crate::tls::spki_pin(&rustls::pki_types::CertificateDer::from(
            fs::read(PathBuf::from(path).join("c.der")).unwrap(),
        ))
        .unwrap()
    } else {
        [6; 32]
    }
}
fn ready(c: &MiddleContext<'_>, frames: &[MiddleFrame]) -> PreparedAReady {
    PreparedAReady::verify(&ready_bytes(c, frames), c).unwrap()
}
fn ready_bytes(c: &MiddleContext<'_>, frames: &[MiddleFrame]) -> [u8; 512] {
    let mut b = [0; 512];
    b[..8].copy_from_slice(b"SNIM3C01");
    b[8] = 1;
    b[12..20].copy_from_slice(&c.r2.round.manifest.round().to_le_bytes());
    b[20..52].copy_from_slice(&c.r2.round.config.domain());
    b[52..84].copy_from_slice(&c.q.id());
    b[84..116].copy_from_slice(&c.r2.round.manifest.id());
    b[116..148].copy_from_slice(&c.batch_hash("SilkNode-IM3-A-batch", frames));
    b[340..344].copy_from_slice(&32u32.to_le_bytes());
    let s = sign(11, "SilkNode-IM3-control", &b[..448]);
    b[448..].copy_from_slice(&s);
    b
}
fn copied(c: &MiddleContext<'_>, frames: &[MiddleFrame]) -> Vec<MiddleFrame> {
    frames
        .iter()
        .map(|f| MiddleFrame::decode(f.bytes(), c, 2).unwrap())
        .collect()
}
fn middle_plain(
    c: &MiddleContext<'_>,
    key: &HpkePrivate,
    f: &MiddleFrame,
) -> Box<Zeroizing<[u8; 4608]>> {
    let p = open(c, 2, c.c_key(), key, &f.bytes()[64..4720]).unwrap();
    let mut b = Box::new(Zeroizing::new([0; 4608]));
    b.copy_from_slice(&p);
    b
}
fn rewritten(c: &MiddleContext<'_>, plain: &[u8; 4608]) -> MiddleFrame {
    let b = seal(c, 2, c.c_key(), plain).unwrap();
    frame(c, 2, &b).unwrap()
}

struct FilePins(PathBuf);
impl ClaimPinRetention for FilePins {
    fn retain_claim_pin(&mut self, pin: Digest) -> ClaimResult<()> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&self.0)?;
        f.write_all(&pin)?;
        f.sync_all()?;
        Ok(())
    }
}
fn crash_binding() -> PreparedClaimBinding {
    PreparedClaimBinding {
        role: ClaimRole::Middle,
        domain: [1; 32],
        config: [2; 32],
        profile: [3; 32],
        vk_hash: [4; 32],
        epoch: 0,
    }
}
#[test]
fn disclosure_crash_child() {
    let Some(path) = std::env::var_os("SILK_IM3_CRASH_DIR") else {
        return;
    };
    let path = PathBuf::from(path);
    let mut store = PreparedScopeStore::create(
        &path.join("store"),
        crash_binding(),
        FilePins(path.join("pin")),
    )
    .unwrap();
    let mut claim = store.consume(6, [5; 32], [6; 32]).unwrap();
    // The separate test-only disclosure fault selector does not affect claim.
    claim.decide_disclosure([7; 32]).unwrap();
    panic!("fault boundary not reached");
}
#[test]
fn disclosure_crashes_never_reopen_a_permutation() {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    for point in [
        "before_stage",
        "snapshot_written",
        "snapshot_fsynced",
        "snapshot_renamed",
        "directory_fsynced",
        "pin_retained",
    ] {
        let root = tempfile::tempdir().unwrap();
        directory(&root.path().join("store"));
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "im3_gate::tests::disclosure_crash_child",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("SILK_IM3_CRASH_DIR", root.path())
            .env("SILK_IM3_CRASH_POINT", point)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut reader = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            assert!(
                reader.read_line(&mut line).unwrap() > 0,
                "child exited before {point}"
            );
            if line.contains(&format!("SCOPE_CHECKPOINT {point}")) {
                break;
            }
        }
        child.kill().unwrap();
        let status = child.wait().unwrap();
        assert!(!status.success());
        let pin: Digest = fs::read(root.path().join("pin"))
            .unwrap()
            .try_into()
            .unwrap();
        let reopened = PreparedScopeStore::open(
            &root.path().join("store"),
            crash_binding(),
            pin,
            6,
            FilePins(root.path().join("pin")),
        );
        if matches!(point, "before_stage" | "pin_retained") {
            let mut store = reopened.unwrap();
            assert!(store.consume(6, [8; 32], [9; 32]).is_err());
            let bytes = fs::read(root.path().join("store/CURRENT")).unwrap();
            assert_eq!(bytes[10], u8::from(point == "pin_retained"));
            // A future round can be claimed, but cannot carry an old disclosure.
            drop(store.consume(10, [8; 32], [9; 32]).unwrap());
            let bytes = fs::read(root.path().join("store/CURRENT")).unwrap();
            assert_eq!(bytes[10], 0);
            assert_eq!(&bytes[256..288], &[0; 32]);
        } else {
            assert!(reopened.is_err(), "uncertain {point} must stop");
        }
    }
}

#[test]
#[ignore = "requires preserved genuine even-round B fixture and exactly 32 new C proofs on VPS"]
fn genuine_complete_gate_and_irreversible_disclosure() {
    let root = PathBuf::from(std::env::var_os("SILK_IM3_GATE_ROOT").unwrap());
    let out = PathBuf::from(std::env::var_os("SILK_IM3_GATE_OUT").unwrap());
    directory(&out);
    let e: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("expected.json")).unwrap()).unwrap();
    let vk_hash = hex(e["vk_hash"].as_str().unwrap()).unwrap();
    let domain = hex(e["domain"].as_str().unwrap()).unwrap();
    let epoch = u32::try_from(e["epoch"].as_u64().unwrap()).unwrap();
    let cohort = u32::try_from(e["cohort"].as_u64().unwrap()).unwrap();
    let round = e["round"].as_u64().unwrap();
    assert_eq!(round % 2, 0);
    let keys = [
        hex(e["role_keys"][0].as_str().unwrap()).unwrap(),
        hex(e["role_keys"][1].as_str().unwrap()).unwrap(),
    ];
    let cfg = SignedConfig::verify(
        &fs::read(root.join("config.bin")).unwrap(),
        domain,
        cohort,
        epoch,
        keys,
    )
    .unwrap();
    let m =
        SignedManifest::verify(&fs::read(root.join("manifest.bin")).unwrap(), &cfg, round).unwrap();
    let p = PreparedProfile::verify(
        &fs::read(root.join("profile.bin")).unwrap(),
        &ProfileExpectations {
            domain,
            config: cfg.id(),
            epoch,
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
    let a = HpkePrivate::from_bytes(&[71; 32]).unwrap();
    let b = HpkePrivate::from_bytes(&[72; 32]).unwrap();
    let middle = HpkePrivate::from_bytes(&[73; 32]).unwrap();
    let cpk: Digest = X25519HkdfSha256::sk_to_pk(&middle)
        .to_bytes()
        .as_slice()
        .try_into()
        .unwrap();
    let pins = MiddlePins {
        signing: SigningKey::from_bytes(&[16; 32]).verifying_key().to_bytes(),
        hpke: cpk,
        tls: fixture_c_tls_pin(),
    };
    let qb = q_bytes(&cfg, &p, cpk);
    let q = PreparedQ::verify(&qb, &cfg, &p, &pins).unwrap();
    let c = MiddleContext::new(&cfg, &m, &p, vk_hash, &q).unwrap();
    let mut wrong = qb;
    wrong[384] ^= 1;
    assert!(PreparedQ::verify(&wrong, &cfg, &p, &pins).is_err());
    #[cfg(feature = "functional-lab")]
    if std::env::var_os("SILK_IM3_SEQUENCE_ONLY").is_some() {
        let result = sequence::run(&c, &out);
        save(
            &out.join("sequence-result.json"),
            &serde_json::to_vec(&result).unwrap(),
        );
        println!("{result}");
        return;
    }
    #[cfg(feature = "functional-lab")]
    if std::env::var_os("SILK_IM3_RUNNER_CANCEL_ONLY").is_some() {
        let result = runner::original_cancel(&c, &root, &out);
        save(
            &out.join("runner-cancel-result.json"),
            &serde_json::to_vec(&result).unwrap(),
        );
        println!("{result}");
        return;
    }
    #[cfg(feature = "functional-lab")]
    if std::env::var_os("SILK_IM3_RUNNER_PARTIAL_ONLY").is_some() {
        let result = runner::partial_incoming_stream(&c, &root, &out);
        save(
            &out.join("runner-partial-result.json"),
            &serde_json::to_vec(&result).unwrap(),
        );
        println!("{result}");
        return;
    }
    if std::env::var_os("SILK_IM3_CONTROL_ONLY").is_some() {
        let result = control_chain::run(&c);
        save(
            &out.join("control-result.json"),
            &serde_json::to_vec_pretty(&result).unwrap(),
        );
        println!("{result}");
        return;
    }
    #[cfg(feature = "functional-lab")]
    if std::env::var_os("SILK_IM3_MANIFEST_CUTOFF_ONLY").is_some() {
        let result = manifest_admission::delayed_claim(&c, &root, &out);
        save(
            &out.join("manifest-cutoff-result.json"),
            &serde_json::to_vec_pretty(&result).unwrap(),
        );
        println!("{result}");
        return;
    }
    #[cfg(feature = "functional-lab")]
    if std::env::var_os("SILK_IM3_MANIFEST_FAILURE_ONLY").is_some() {
        let result = manifest_admission::run(&c, &root, &out);
        save(
            &out.join("manifest-refusal-result.json"),
            &serde_json::to_vec_pretty(&result).unwrap(),
        );
        println!("{result}");
        return;
    }
    #[cfg(feature = "functional-lab")]
    if std::env::var_os("SILK_IM3_PREPARE_SECOND_CLAIMS_ONLY").is_some() {
        let envelope = fs::read(root.join("envelope.bin")).unwrap();
        assert_eq!(envelope.len(), 2790);
        let statement = crate::aip2_proof::prepare_cover_statement(&p, m.id(), round).unwrap();
        let members: Vec<serde_json::Value> =
            serde_json::from_slice(&fs::read(root.join("members-public.json")).unwrap()).unwrap();
        assert_eq!(members.len(), 32);
        directory(&root.join("pins"));
        let mut claims = Vec::with_capacity(32);
        for (i, member) in members.iter().enumerate() {
            p.check_own_commitment(hex(member["commitment"].as_str().unwrap()).unwrap())
                .unwrap();
            let name = format!("client-{i:02}");
            let path = root.join(&name);
            directory(&path);
            let mut cell = *statement.cell();
            if i == 0 {
                cell[8] = 1;
                cell[416..3206].copy_from_slice(&envelope);
            }
            let message = c.r2.check_cell(&cell).unwrap();
            let mut store = PreparedScopeStore::create(
                &path,
                p.claim_binding(ClaimRole::Client),
                FilePins(root.join("pins").join(&name)),
            )
            .unwrap();
            drop(store.consume(round, m.id(), message).unwrap());
            claims.push(json!({"owner":name,"pin":text(&store.pin()),"message":text(&message)}));
        }
        let profile_sha: [u8; 32] = Sha256::digest(p.bytes()).into();
        save(
            &root.join("claims-prepared.json"),
            &serde_json::to_vec(&json!({"scope":"PUBLIC_FIXTURE_ONLY_NO_ACTIVATION",
                "profile_sha256":text(&profile_sha),"profile_id":text(&p.id()),
                "message":text(&statement.message()),"scope_scalar":text(&statement.scope()),
                "root":text(&statement.root()),"client_claims":claims,
                "actual_tls_cover_handoff":false,"claim_before_new_proof_jobs":true,
                "independent_pin_custody":false}))
            .unwrap(),
        );
        let result = json!({"status":"PREPARED_B_FIXTURE_CLAIMS_ONLY",
            "round":round,"claims":32,"slot_zero_ordinary_envelope":true,"new_proofs":0,
            "global_claim_uniqueness_proven":false,"common_B_C_owner":false});
        save(
            &out.join("second-round-claims-result.json"),
            &serde_json::to_vec(&result).unwrap(),
        );
        println!("{result}");
        return;
    }
    #[cfg(feature = "functional-lab")]
    if std::env::var_os("SILK_IM3_PREPARE_ADVERSARIAL30").is_some() {
        // The two external clients own members 0 and 1. These 30 fixture
        // adversaries are not timed honest clients, but each B and C job must
        // still share one irreversible local claim in this same process.
        let statement = crate::aip2_proof::prepare_cover_statement(&p, m.id(), round).unwrap();
        let members: Vec<serde_json::Value> =
            serde_json::from_slice(&fs::read(root.join("members-public.json")).unwrap()).unwrap();
        assert_eq!(members.len(), 32);
        let pins = root.join("pins");
        directory(&pins);
        let mut stores = Vec::with_capacity(30);
        let mut paths = Vec::with_capacity(30);
        for i in 2..32 {
            p.check_own_commitment(hex(members[i]["commitment"].as_str().unwrap()).unwrap())
                .unwrap();
            let name = format!("client-{i:02}");
            let path = root.join(&name);
            directory(&path);
            stores.push(
                PreparedScopeStore::create(
                    &path,
                    p.claim_binding(ClaimRole::Client),
                    FilePins(pins.join(&name)),
                )
                .unwrap(),
            );
            paths.push((name, path));
        }
        let claims: Vec<_> = stores
            .iter_mut()
            .map(|store| store.consume(round, m.id(), statement.message()).unwrap())
            .collect();
        let rows: Vec<_> = paths
            .iter()
            .map(|(name, _)| {
                let pin = fs::read(pins.join(name)).unwrap();
                assert_eq!(pin.len(), 32);
                json!({"owner":name,"pin":text(&pin),"message":text(&statement.message())})
            })
            .collect();
        let profile_sha: [u8; 32] = Sha256::digest(p.bytes()).into();
        save(
            &root.join("claims-prepared.json"),
            &serde_json::to_vec(&json!({"scope":"PRIVATE_ADVERSARIAL_FIXTURE_ONLY",
                "profile_sha256":text(&profile_sha),"profile_id":text(&p.id()),
                "message":text(&statement.message()),"scope_scalar":text(&statement.scope()),
                "root":text(&statement.root()),"client_claims":rows,
                "actual_tls_cover_handoff":true,"independent_pin_custody":false}))
            .unwrap(),
        );
        let node = std::env::var_os("SILK_IM3_NODE_BINARY").expect("explicit proof-helper Node binary");
        let status = Command::new(&node)
            .arg(std::env::var_os("SILK_IM3_ADVERSARIAL_B_HELPER").unwrap())
            .arg("prove-adversarial30")
            .arg(&root)
            .arg(root.join("proof-metadata.json"))
            .env("UV_THREADPOOL_SIZE", "1")
            .status()
            .unwrap();
        assert!(status.success());
        let encoded: Vec<String> =
            serde_json::from_slice(&fs::read(root.join("cells.json")).unwrap()).unwrap();
        assert_eq!(encoded.len(), 30);
        let cells: Vec<[u8; 4096]> = encoded.iter().map(|s| hex(s).unwrap()).collect();
        let pending: Vec<_> = claims
            .into_iter()
            .zip(&cells)
            .map(|(claim, cell)| PendingMiddle::from_b_cell(&c, claim, cell, &verifier).unwrap())
            .collect();
        let statements: Vec<_> = pending
            .iter()
            .map(|p| p.statement().map(|x| text(&x)))
            .collect();
        save(
            &out.join("statements.json"),
            &serde_json::to_vec(&statements).unwrap(),
        );
        let status = Command::new(&node)
            .arg(std::env::var_os("SILK_IM3_ADVERSARIAL_C_HELPER").unwrap())
            .arg(&root)
            .arg(&out)
            .arg("adversarial30")
            .env("UV_THREADPOOL_SIZE", "1")
            .status()
            .unwrap();
        assert!(status.success());
        let proofs: Vec<serde_json::Value> =
            serde_json::from_slice(&fs::read(out.join("middle-proofs.json")).unwrap()).unwrap();
        assert_eq!(proofs.len(), 30);
        let mut frames = Vec::with_capacity(30);
        for (owner, proof) in pending.into_iter().zip(&proofs) {
            let frame = owner
                .finish(
                    hex(proof["nullifier"].as_str().unwrap()).unwrap(),
                    &hex(proof["proof"].as_str().unwrap()).unwrap(),
                    &verifier,
                )
                .unwrap();
            frames.push(open_at_a(&c, &a, &frame).unwrap());
        }
        save(
            &out.join("stage2-frames.bin"),
            &frames
                .iter()
                .flat_map(|f| f.bytes().iter().copied())
                .collect::<Vec<_>>(),
        );
        let result = json!({"status":"PREPARED_30_ADVERSARIAL_B_C_MATH_ONLY",
            "round":round,"manifest":text(&m.id()),"claims":30,
            "fresh_B_proofs":30,"fresh_C_proofs":30,
            "continuous_local_B_C_claims":true,"timed_honest_clients":0,
            "independent_custody":false,"relay_or_settlement":false});
        save(
            &out.join("adversarial30-result.json"),
            &serde_json::to_vec_pretty(&result).unwrap(),
        );
        println!("{result}");
        return;
    }
    #[cfg(feature = "functional-lab")]
    if std::env::var("SILK_IM3_EXTERNAL_CLIENTS").ok().as_deref() == Some("2") {
        assert!(std::env::var_os("SILK_IM3_RELAY_PATH_ONLY").is_some());
        let retained = PathBuf::from(std::env::var_os("SILK_IM3_GATE_REUSE").unwrap());
        let bytes = fs::read(retained.join("stage2-frames.bin")).unwrap();
        assert_eq!(bytes.len(), 30 * FRAME_BYTES);
        let frames = bytes
            .chunks_exact(FRAME_BYTES)
            .map(|b| MiddleFrame::decode(b, &c, 2).unwrap())
            .collect();
        let envelope = fs::read(root.join("envelope.bin")).unwrap();
        let result = relay_path::run(&c, &root, &out, frames, &middle, &b, &verifier, &envelope);
        save(
            &out.join("relay-path-result.json"),
            &serde_json::to_vec_pretty(&result).unwrap(),
        );
        println!("{result}");
        return;
    }
    let encoded: Vec<String> =
        serde_json::from_slice(&fs::read(root.join("cells.json")).unwrap()).unwrap();
    assert_eq!(encoded.len(), 32);
    let cells: Vec<[u8; 4096]> = encoded.iter().map(|s| hex(s).unwrap()).collect();
    let envelope = fs::read(root.join("envelope.bin")).unwrap();
    assert_eq!(cells[0][416..3206], envelope);
    if std::env::var_os("SILK_IM3_CLIENT_ONLY").is_some() {
        let result = client_owner::run(
            &c, &root, &out, &a, &b, &middle, &verifier, &cells[0], &envelope,
        );
        save(
            &out.join("client-result.json"),
            &serde_json::to_vec_pretty(&result).unwrap(),
        );
        println!("{result}");
        return;
    }
    let reuse = std::env::var_os("SILK_IM3_GATE_REUSE");
    let mut frames: [MiddleFrame; 32] = if let Some(ref retained) = reuse {
        let bytes = fs::read(PathBuf::from(retained).join("stage2-frames.bin")).unwrap();
        assert_eq!(bytes.len(), 32 * FRAME_BYTES);
        bytes
            .chunks_exact(FRAME_BYTES)
            .map(|b| MiddleFrame::decode(b, &c, 2).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .ok()
            .unwrap()
    } else {
        let mut stores = Vec::new();
        for i in 0..32 {
            let path = out.join(format!("client-{i:02}"));
            directory(&path);
            stores.push(
                PreparedScopeStore::create(
                    &path,
                    p.claim_binding(ClaimRole::Client),
                    Pins::default(),
                )
                .unwrap(),
            );
        }
        let mut pending = Vec::new();
        for (store, cell) in stores.iter_mut().zip(&cells) {
            let msg = c.r2.check_cell(cell).unwrap();
            let claim = store.consume(round, m.id(), msg).unwrap();
            pending.push(PendingMiddle::from_b_cell(&c, claim, cell, &verifier).unwrap());
        }
        let statements: Vec<_> = pending
            .iter()
            .map(|p| p.statement().map(|x| text(&x)))
            .collect();
        save(
            &out.join("statements.json"),
            &serde_json::to_vec(&statements).unwrap(),
        );
        let status = Command::new(std::env::var_os("SILK_IM3_NODE_BINARY").expect("explicit proof-helper Node binary"))
            .arg(std::env::var_os("SILK_IM3_PROOF_HELPER").unwrap())
            .arg(&root)
            .arg(&out)
            .env("UV_THREADPOOL_SIZE", "1")
            .status()
            .unwrap();
        assert!(status.success());
        let proofs: Vec<serde_json::Value> =
            serde_json::from_slice(&fs::read(out.join("middle-proofs.json")).unwrap()).unwrap();
        assert_eq!(proofs.len(), 32);
        let mut frames = Vec::new();
        for (client, proof) in pending.into_iter().zip(&proofs) {
            let f = client
                .finish(
                    hex(proof["nullifier"].as_str().unwrap()).unwrap(),
                    &hex(proof["proof"].as_str().unwrap()).unwrap(),
                    &verifier,
                )
                .unwrap();
            frames.push(open_at_a(&c, &a, &f).unwrap());
        }
        frames.try_into().ok().unwrap()
    };
    permute_at_a(&c, &mut frames).unwrap();
    let fixture_bytes: Vec<_> = frames
        .iter()
        .flat_map(|f| f.bytes().iter().copied())
        .collect();
    save(&out.join("stage2-frames.bin"), &fixture_bytes);
    #[cfg(feature = "functional-lab")]
    if std::env::var_os("SILK_IM3_PREPARE_SECOND_ONLY").is_some() {
        assert!(
            reuse.is_none(),
            "second round requires fresh B and C proofs"
        );
        let result = json!({"status":"PREPARED_ROUND_BOUND_B_C_MATH_ONLY",
            "round":round,"manifest":text(&m.id()),"fresh_B_proofs":32,
            "fresh_C_proofs":32,"stage2_frames":32,"first_round_proofs_reused":false,
            "common_B_C_owner":false,"qualified_clock":false,
            "independent_custody":false,"settlement":false});
        save(
            &out.join("second-round-preparation-result.json"),
            &serde_json::to_vec(&result).unwrap(),
        );
        println!("{result}");
        return;
    }
    #[cfg(feature = "functional-lab")]
    if std::env::var_os("SILK_IM3_A_CANCEL_ONLY").is_some() {
        assert!(reuse.is_some());
        let result = incoming::ingress_cancel_failure(&c, &root, &out);
        save(
            &out.join("a-cancel-result.json"),
            &serde_json::to_vec(&result).unwrap(),
        );
        println!("{result}");
        return;
    }
    #[cfg(feature = "functional-lab")]
    if std::env::var_os("SILK_IM3_PROOF_CANCEL_ONLY").is_some() {
        assert!(reuse.is_some());
        let result = incoming::proof_cancel_failure(&c, &root, &out, &frames, &middle, &verifier);
        save(
            &out.join("proof-cancel-result.json"),
            &serde_json::to_vec(&result).unwrap(),
        );
        println!("{result}");
        return;
    }
    #[cfg(feature = "functional-lab")]
    if std::env::var_os("SILK_IM3_RELAY_PATH_ONLY").is_some() {
        assert!(reuse.is_some());
        let result = relay_path::run(&c, &root, &out, frames.into(), &middle, &b, &verifier, &envelope);
        save(
            &out.join("relay-path-result.json"),
            &serde_json::to_vec_pretty(&result).unwrap(),
        );
        println!("{result}");
        return;
    }
    #[cfg(feature = "functional-lab")]
    if std::env::var_os("SILK_IM3_PARTIAL_A_TRAIN_ONLY").is_some() {
        assert!(reuse.is_some());
        let result = relay_path::run(&c, &root, &out, frames.into(), &middle, &b, &verifier, &envelope);
        save(
            &out.join("partial-a-train-result.json"),
            &serde_json::to_vec(&result).unwrap(),
        );
        println!("{result}");
        return;
    }
    if std::env::var_os("SILK_IM3_INCOMING_FAILURE_ONLY").is_some() {
        assert!(reuse.is_some()); // focused correction generates no proofs
        let result = incoming::initial_phase_failure(&c, &root, &out, &middle, &verifier);
        save(
            &out.join("gate-result.json"),
            &serde_json::to_vec_pretty(&result).unwrap(),
        );
        println!("{result}");
        return;
    }
    if std::env::var_os("SILK_IM3_INCOMING").is_some() {
        let result = incoming::run(
            &c,
            &root,
            &out,
            &frames,
            &middle,
            &b,
            &verifier,
            &envelope,
            reuse.is_some(),
        );
        save(
            &out.join("gate-result.json"),
            &serde_json::to_vec_pretty(&result).unwrap(),
        );
        println!("{result}");
        return;
    }
    let mut cases = Vec::new();
    // Every malformed complete batch is encrypted/authenticated to C; this is
    // proof binding, not merely an AEAD corruption test.
    for case in [
        "missing",
        "replacement",
        "duplicate_frame",
        "duplicate_nullifier",
        "wrong_manifest",
        "wrong_q",
        "stale_round",
        "bad_proof",
        "wrong_ready",
        "expired",
        "pin_failure",
    ] {
        let path = out.join(case);
        directory(&path);
        let retained = Pins::default();
        let mut store =
            PreparedScopeStore::create(&path, c.claim_binding(), retained.clone()).unwrap();
        let mut batch = copied(&c, &frames);
        let signed_ready = ready(&c, &batch);
        match case {
            "missing" => {
                batch.pop();
            }
            "duplicate_frame" => {
                batch[31] = MiddleFrame::decode(batch[0].bytes(), &c, 2).unwrap();
            }
            "wrong_ready" => {
                batch.swap(0, 1);
            }
            "replacement"
            | "duplicate_nullifier"
            | "wrong_manifest"
            | "wrong_q"
            | "stale_round"
            | "bad_proof" => {
                let mut plain = middle_plain(&c, &middle, &batch[31]);
                match case {
                    "replacement" => {
                        plain[416] ^= 1;
                        plain[448] ^= 1;
                    }
                    "duplicate_nullifier" => {
                        let other = middle_plain(&c, &middle, &batch[0]);
                        plain[128..160].copy_from_slice(&other[128..160]);
                        plain[160..416].copy_from_slice(&other[160..416]);
                    }
                    "wrong_manifest" => plain[96] ^= 1,
                    "wrong_q" => plain[64] ^= 1,
                    "stale_round" => plain[16] ^= 2,
                    _ => plain[160] ^= 1,
                }
                batch[31] = rewritten(&c, plain.as_ref());
            }
            _ => (),
        }
        let signed_ready = if case == "wrong_ready" {
            signed_ready
        } else {
            ready(&c, &batch)
        };
        let mut owner = MiddleBatchOwner::begin(&c, &mut store).unwrap();
        let mut admitted = true;
        for f in &batch {
            if owner.admit(f.bytes()).is_err() {
                admitted = false;
                break;
            }
        }
        if case == "pin_failure" {
            retained.0.lock().unwrap().1 = true;
        }
        let deadline = if case == "expired" {
            Instant::now()
        } else {
            Instant::now() + Duration::from_secs(5)
        };
        if admitted {
            assert!(
                owner
                    .disclose(&middle, &verifier, signed_ready, deadline)
                    .is_err(),
                "{case}"
            );
        } else {
            drop(owner);
        }
        let state = fs::read(path.join("CURRENT")).unwrap();
        assert_eq!(state[10], u8::from(case == "pin_failure"));
        assert!(MiddleBatchOwner::begin(&c, &mut store).is_err());
        let pin = retained.0.lock().unwrap().0;
        drop(store);
        if case == "pin_failure" {
            retained.0.lock().unwrap().1 = false;
        }
        if case == "pin_failure" {
            assert!(
                PreparedScopeStore::open(&path, c.claim_binding(), pin, round, Pins::default())
                    .is_err()
            );
        } else {
            let mut reopened =
                PreparedScopeStore::open(&path, c.claim_binding(), pin, round, Pins::default())
                    .unwrap();
            assert!(MiddleBatchOwner::begin(&c, &mut reopened).is_err());
        }
        cases.push(case);
    }
    let path = out.join("complete");
    directory(&path);
    let retained = Pins::default();
    let mut store = PreparedScopeStore::create(&path, c.claim_binding(), retained.clone()).unwrap();
    let preclaim = store.pin();
    let mut owner = MiddleBatchOwner::begin(&c, &mut store).unwrap();
    for f in &frames {
        owner.admit(f.bytes()).unwrap();
    }
    let decided = owner
        .disclose(
            &middle,
            &verifier,
            ready(&c, &frames),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
    let output_hash = decided.output_hash();
    let state = fs::read(path.join("CURRENT")).unwrap();
    assert_eq!(state[10], 1);
    assert_eq!(state[256..288], output_hash);
    assert_eq!(retained.0.lock().unwrap().0, store.pin());
    let after = store.pin();
    drop(store);
    // Crash-equivalent cold owner reconstruction AFTER decision, while the old
    // output capability is withheld, cannot issue another permutation/output.
    assert!(
        PreparedScopeStore::open(&path, c.claim_binding(), preclaim, round, Pins::default())
            .is_err()
    );
    let mut reopened =
        PreparedScopeStore::open(&path, c.claim_binding(), after, round, Pins::default()).unwrap();
    assert!(MiddleBatchOwner::begin(&c, &mut reopened).is_err());
    let outputs = decided.into_frames();
    let a_tags: BTreeSet<_> = frames.iter().map(MiddleFrame::tag).collect();
    let b_tags: BTreeSet<_> = outputs.iter().map(MiddleFrame::tag).collect();
    assert!(a_tags.is_disjoint(&b_tags));
    let mut real = 0;
    for f in &outputs {
        let cell = open(&c, 3, cfg.hpke_keys()[1], &b, &f.bytes()[64..4208]).unwrap();
        if cell[8] == 1 {
            real += 1;
            assert_eq!(cell[416..3206], envelope);
        }
    }
    assert_eq!(real, 1);
    let timed = if std::env::var_os("SILK_IM3_GATE_TIMED").is_some() {
        Some(timed_socket_gate(
            &c, &root, &out, &frames, &middle, &b, &verifier, &envelope,
        ))
    } else {
        None
    };
    let result = json!({"status":"PASS_COMPLETE_GENUINE_MIDDLE_GATE_PREPARATION","new_C_proofs":if reuse.is_some(){0}else{32},
        "reused_genuine_B_proofs":32,"genuine_wallet_envelope":true,"refused_cases":cases,
        "disclosure_durable_before_capability":true,"post_disclosure_reopen_refused":true,
        "stale_pin_refused":true,"a_b_exact_tag_intersection":0,"output_count":32,
        "output_hash":text(&output_hash),"runtime_schedule_integrated":timed.is_some(),
        "socket_delivery_tested":timed.is_some(),"timed_result":timed,
        "independent_custody_proven":false,"qualified_clock":false,"anonymity_proven":false});
    save(
        &out.join("gate-result.json"),
        &serde_json::to_vec_pretty(&result).unwrap(),
    );
    println!("{result}");
}

fn sleep_until(time: Instant) {
    if let Some(left) = time.checked_duration_since(Instant::now()) {
        std::thread::sleep(left);
    }
}
fn tls_b_pairs(c: &MiddleContext<'_>, root: &Path, count: usize) -> Vec<(Transport, Transport)> {
    use crate::tls::SetupStep;
    use rustls::{
        RootCertStore,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    };
    use std::net::{Ipv6Addr, SocketAddr, TcpListener, TcpStream};
    let ep = c.r2.round.config.endpoints()[1];
    let address = SocketAddr::new(Ipv6Addr::from(ep.address).into(), ep.port);
    let listener = TcpListener::bind(address).unwrap();
    (0..count)
        .map(|_| {
            let mut roots = RootCertStore::empty();
            roots
                .add(CertificateDer::from(
                    fs::read(root.join("tls/root.der")).unwrap(),
                ))
                .unwrap();
            let cert = CertificateDer::from(fs::read(root.join("tls/leaf-1.der")).unwrap());
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                fs::read(root.join("tls/leaf-1-key.der")).unwrap(),
            ));
            let deadline = Instant::now() + Duration::from_secs(3);
            let client = TcpStream::connect(address).unwrap();
            let server = listener.accept().unwrap().0;
            let mut pending = [
                Some(Transport::client_setup(client, ep, roots, deadline).unwrap()),
                Some(Transport::server_setup(server, ep, vec![cert], key, deadline).unwrap()),
            ];
            let mut ready = [None, None];
            while ready.iter().any(Option::is_none) {
                assert!(Instant::now() < deadline);
                for i in 0..2 {
                    if let Some(setup) = pending[i].take() {
                        match setup.poll().unwrap() {
                            SetupStep::Pending(s) => pending[i] = Some(s),
                            SetupStep::Established(t) => ready[i] = Some(t),
                        }
                    }
                }
                std::thread::sleep(Duration::from_micros(100));
            }
            (ready[0].take().unwrap(), ready[1].take().unwrap())
        })
        .collect()
}
#[allow(clippy::too_many_arguments)]
fn timed_socket_gate(
    c: &MiddleContext<'_>,
    root: &Path,
    out: &Path,
    frames: &[MiddleFrame; 32],
    key: &HpkePrivate,
    b_key: &HpkePrivate,
    verifier: &PreparedProofVerifier,
    envelope: &[u8],
) -> serde_json::Value {
    use crate::schedule::QualifiedClockSample;
    use std::time::UNIX_EPOCH;
    // Separate administrative fault stores/links share the fixture mapping;
    // this is not an IM3 socket-cap or independent-role qualification run.
    let refused = [
        "missing_ready",
        "late_ready",
        "duplicate_ready",
        "invalid_ready",
        "early_ordinal",
    ];
    let mut fault_pairs = tls_b_pairs(c, root, refused.len() + 1);
    let (mut sender, mut receiver) = fault_pairs.remove(0);
    let round = c.r2.round.manifest.round();
    let monotonic = Instant::now();
    // Explicit historical-context monotonic fixture mapping, NOT qualified UTC.
    let sample = QualifiedClockSample::from_qualified_source(
        UNIX_EPOCH + Duration::from_secs(round * 30) - Duration::from_secs(11),
        monotonic,
        Duration::ZERO,
    )
    .unwrap();
    let schedule = Im3Schedule::new(c.r2.round.config, round, sample).unwrap();
    let guard = Im3Guard::arm(&schedule).unwrap();
    let path = out.join("timed");
    directory(&path);
    let mut store = PreparedScopeStore::create(&path, c.claim_binding(), Pins::default()).unwrap();
    let mut owner = TimedMiddleOwner::begin(c, &mut store, &schedule, &guard, &mut sender).unwrap();
    let mut fault_stores: Vec<_> = refused
        .iter()
        .map(|case| {
            let path = out.join(format!("timed-{case}"));
            directory(&path);
            PreparedScopeStore::create(&path, c.claim_binding(), Pins::default()).unwrap()
        })
        .collect();
    let mut fault_owners: Vec<_> = fault_stores
        .iter_mut()
        .zip(fault_pairs.iter_mut())
        .map(|(s, (tx, _))| TimedMiddleOwner::begin(c, s, &schedule, &guard, tx).unwrap())
        .collect();
    for (j, f) in frames.iter().enumerate() {
        sleep_until(schedule.relay_slot(false, j as u8).unwrap().0 - Duration::from_secs(1));
        owner.admit(f.bytes()).unwrap();
        for (i, fault) in fault_owners.iter_mut().enumerate() {
            if i == 4 && j > 0 {
                assert!(fault.admit(f.bytes()).is_err());
            } else {
                fault.admit(f.bytes()).unwrap();
            }
            if i == 4 && j == 0 {
                assert!(
                    Instant::now()
                        < schedule.relay_slot(false, 1).unwrap().0 - Duration::from_secs(1)
                );
                assert!(fault.admit(frames[1].bytes()).is_err());
            }
        }
    }
    sleep_until(schedule.at(15_750_000_000).unwrap());
    owner.admit_ready(&ready_bytes(c, frames)).unwrap();
    fault_owners[2]
        .admit_ready(&ready_bytes(c, frames))
        .unwrap();
    assert!(
        fault_owners[2]
            .admit_ready(&ready_bytes(c, frames))
            .is_err()
    );
    let mut bad_ready = ready_bytes(c, frames);
    bad_ready[511] ^= 1;
    assert!(fault_owners[3].admit_ready(&bad_ready).is_err());
    assert!(
        fault_owners[4]
            .admit_ready(&ready_bytes(c, frames))
            .is_err()
    );
    sleep_until(schedule.window(Phase::CGate).unwrap().0);
    assert!(
        fault_owners[1]
            .admit_ready(&ready_bytes(c, frames))
            .is_err()
    );
    for fault in fault_owners {
        assert!(fault.verify(key, verifier).is_err());
    }
    for (case, (_, rx)) in refused.iter().zip(&fault_pairs) {
        assert!(!rx.has_extra_bytes().unwrap());
        let snapshot = fs::read(out.join(format!("timed-{case}/CURRENT"))).unwrap();
        assert_eq!(snapshot[10], 0); // consumed, but never disclosure-decided
    }
    let verified = owner.verify(key, verifier).unwrap();
    receiver
        .expect(RecordSize::Cell, schedule.at(22_000_000_000).unwrap())
        .unwrap();
    sleep_until(schedule.window(Phase::CDecision).unwrap().0);
    let mut delivery = verified.decide().unwrap();
    let decided = fs::read(path.join("CURRENT")).unwrap();
    assert_eq!(decided[10], 1);
    let origin = schedule.at(0).unwrap();
    let mut observations = Vec::new();
    let mut received = Vec::new();
    let mut finished = false;
    while !finished || received.len() < 32 {
        assert!(Instant::now() < schedule.at(22_000_000_000).unwrap());
        if !finished {
            let result = delivery.poll();
            if let Some(o) = delivery.take_wire_observation() {
                observations.push(wire_json("C_write", origin, o));
            }
            if result.is_err() {
                save(
                    &out.join("failed-socket-observations.json"),
                    &serde_json::to_vec(&observations).unwrap(),
                );
            }
            finished = result.unwrap();
        }
        if Instant::now() >= schedule.at(19_000_000_000).unwrap() && received.len() < 32 {
            let (result, o) = receiver.read_step_observed();
            observations.push(wire_json("B_read", origin, o));
            if let Some(bytes) = result.unwrap() {
                received.push(MiddleFrame::decode(&bytes, c, 3).unwrap());
                if received.len() < 32 {
                    receiver
                        .expect(RecordSize::Cell, schedule.at(22_000_000_000).unwrap())
                        .unwrap();
                }
            }
        }
        assert!(observations.len() < 20_000);
        std::thread::sleep(Duration::from_micros(100));
    }
    assert_eq!(
        observations
            .iter()
            .filter(|o| o["surface"] == "C_write" && o["record_complete"] == true)
            .count(),
        32
    );
    assert_eq!(
        observations
            .iter()
            .filter(|o| o["surface"] == "B_read" && o["record_complete"] == true)
            .count(),
        32
    );
    let sent: usize = observations
        .iter()
        .filter(|o| o["surface"] == "C_write")
        .map(|o| o["bytes"].as_u64().unwrap() as usize)
        .sum();
    let read: usize = observations
        .iter()
        .filter(|o| o["surface"] == "B_read")
        .map(|o| o["bytes"].as_u64().unwrap() as usize)
        .sum();
    assert_eq!(sent, 32 * (FRAME_BYTES + 22));
    assert_eq!(read, sent);
    let mut real = 0;
    for f in &received {
        let p = open(
            c,
            3,
            c.r2.round.config.hpke_keys()[1],
            b_key,
            &f.bytes()[64..4208],
        )
        .unwrap();
        if p[8] == 1 {
            real += 1;
            assert_eq!(&p[416..3206], envelope);
        }
    }
    assert_eq!(real, 1);
    drop(delivery);
    drop(guard);
    // EOF is an observed failed read, rather than a queue timestamp or success.
    drop(sender);
    receiver
        .expect(RecordSize::Cell, Instant::now() + Duration::from_secs(1))
        .unwrap();
    loop {
        let (result, o) = receiver.read_step_observed();
        let failed = o.failed;
        observations.push(wire_json(
            if failed {
                "B_read_failure"
            } else {
                "B_read_pending_eof"
            },
            origin,
            o,
        ));
        if result.is_err() {
            assert!(failed);
            assert!(matches!(result, Err(Error::Unavailable("TLS read EOF"))));
            break;
        }
        assert!(result.unwrap().is_none());
        std::thread::sleep(Duration::from_micros(100));
    }
    save(
        &out.join("socket-observations.json"),
        &serde_json::to_vec(&observations).unwrap(),
    );
    json!({"status":"PASS_TIMED_GENUINE_C_GATE_TO_B_SOCKET","records":32,"wire_bytes_sent":sent,
        "wire_bytes_read":read,"observed_eof_failure":true,"qualified_clock":false,
        "ready_validated_before_freeze":true,"per_ordinal_early_admission":true,
        "timed_refused_cases":refused,"fault_links_emitted_no_bytes":true,
        "independent_roles":false,"producer_chain_integrated":false,"node_settlement_tested":false})
}
fn wire_json(surface: &str, origin: Instant, o: crate::tls::WireObservation) -> serde_json::Value {
    json!({"surface":surface,"connection":o.connection,"start_ns":o.started.duration_since(origin).as_nanos(),
        "end_ns":o.completed.duration_since(origin).as_nanos(),"bytes":o.bytes,
        "record_complete":o.record_complete,"failed":o.failed,"timestamp_kind":"local_syscall_interval"})
}
mod client_owner;
mod control_chain;
mod incoming;
#[cfg(feature = "functional-lab")]
mod manifest_admission;
#[cfg(feature = "functional-lab")]
mod runner;
#[cfg(feature = "functional-lab")]
mod sequence;

#[cfg(feature = "functional-lab")]
#[test]
#[ignore = "VPS original C and B TLS links; fixed CANCEL window; zero proofs"]
fn failed_middle_sends_authenticated_cancel_on_original_link() {
    let root = PathBuf::from(std::env::var_os("SILK_IM3_GATE_ROOT").unwrap());
    let out = PathBuf::from(std::env::var_os("SILK_IM3_GATE_OUT").unwrap());
    directory(&out);
    let e: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("expected.json")).unwrap()).unwrap();
    let keys = [
        hex(e["role_keys"][0].as_str().unwrap()).unwrap(),
        hex(e["role_keys"][1].as_str().unwrap()).unwrap(),
    ];
    let domain = hex(e["domain"].as_str().unwrap()).unwrap();
    let epoch = e["epoch"].as_u64().unwrap().try_into().unwrap();
    let cfg = SignedConfig::verify(
        &fs::read(root.join("config.bin")).unwrap(),
        domain,
        7,
        epoch,
        keys,
    )
    .unwrap();
    let p = PreparedProfile::verify(
        &fs::read(root.join("profile.bin")).unwrap(),
        &ProfileExpectations {
            domain,
            config: cfg.id(),
            epoch,
            cohort: 7,
            vk_hash: hex(e["vk_hash"].as_str().unwrap()).unwrap(),
            role_keys: keys,
        },
    )
    .unwrap();
    let middle = HpkePrivate::from_bytes(&[73; 32]).unwrap();
    let q = PreparedQ::verify(
        &q_bytes(
            &cfg,
            &p,
            X25519HkdfSha256::sk_to_pk(&middle)
                .to_bytes()
                .as_slice()
                .try_into()
                .unwrap(),
        ),
        &cfg,
        &p,
        &MiddlePins {
            signing: SigningKey::from_bytes(&[16; 32]).verifying_key().to_bytes(),
            hpke: X25519HkdfSha256::sk_to_pk(&middle)
                .to_bytes()
                .as_slice()
                .try_into()
                .unwrap(),
            tls: fixture_c_tls_pin(),
        },
    )
    .unwrap();
    let round = e["round"].as_u64().unwrap();
    let m =
        SignedManifest::verify(&fs::read(root.join("manifest.bin")).unwrap(), &cfg, round).unwrap();
    let c = MiddleContext::new(
        &cfg,
        &m,
        &p,
        hex(e["vk_hash"].as_str().unwrap()).unwrap(),
        &q,
    )
    .unwrap();
    let result = incoming::cancel_failure(&c, &root, &out);
    save(
        &out.join("cancel-result.json"),
        &serde_json::to_vec(&result).unwrap(),
    );
    println!("{result}");
}
#[cfg(feature = "functional-lab")]
mod relay_path;
