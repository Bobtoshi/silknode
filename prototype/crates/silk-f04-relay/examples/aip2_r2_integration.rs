//! Public deterministic preparation fixture; no live links, assets or release.
use ed25519_dalek::SigningKey;
use hpke::Deserializable;
use sha2::{Digest as _, Sha256};
use silk_f04_node::auth::sign_role;
use silk_f04_relay::{
    aip2_claim::*,
    aip2_profile::*,
    aip2_proof::{PreparedProofVerifier, hex, prepare_cover_statement},
    aip2_transport::*,
    config::SignedConfig,
    control::{Kind, Role, SignedControl},
    frame::{Frame, HpkePrivate, RoundContext},
    manifest::SignedManifest,
};
use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
type Any = Box<dyn std::error::Error>;
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
fn text(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn read(path: &Path, cap: u64) -> Result<Vec<u8>, Any> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_file() || m.len() > cap {
        return Err("fixture length/type".into());
    }
    Ok(fs::read(path)?)
}
fn directory(path: &Path) -> Result<(), Any> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
fn save(path: &Path, value: &serde_json::Value) -> Result<(), Any> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(&serde_json::to_vec_pretty(value)?)?;
    f.sync_all()?;
    Ok(())
}
fn owner(
    root: &Path,
    name: &str,
    binding: PreparedClaimBinding,
) -> Result<PreparedScopeStore<Pins>, Any> {
    let p = root.join(name);
    directory(&p)?;
    Ok(PreparedScopeStore::create(
        &p,
        binding,
        Pins(root.join("pins").join(name)),
    )?)
}
fn ready(c: &SignedConfig, m: &SignedManifest, hash: [u8; 32]) -> Result<SignedControl, Any> {
    let mut b = [0; 512];
    b[..8].copy_from_slice(b"SNCTLF03");
    b[8] = 1;
    b[10] = 1;
    b[12..44].copy_from_slice(&c.domain());
    b[44..76].copy_from_slice(&c.id());
    b[76..80].copy_from_slice(&c.cohort().to_le_bytes());
    b[80..88].copy_from_slice(&m.round().to_le_bytes());
    b[88..120].copy_from_slice(&m.id());
    b[120..152].copy_from_slice(&hash);
    b[248] = 32;
    let label = b"SilkNode-F0-control";
    let mut msg = vec![label.len() as u8];
    msg.extend_from_slice(label);
    msg.extend_from_slice(&b[..448]);
    b[448..].copy_from_slice(&sign_role(&SigningKey::from_bytes(&[11; 32]), &msg)?);
    Ok(SignedControl::verify(
        &b,
        c,
        m.round(),
        Kind::AReady,
        Role::A,
    )?)
}
fn frames(
    root: &Path,
    label: &str,
    c: &PreparedR2Context<'_>,
    p: &PreparedProfile,
    m: &SignedManifest,
    key: &HpkePrivate,
    cells: &[[u8; 4096]],
) -> Result<[PreparedR2Frame; 32], Any> {
    let mut f = Vec::new();
    for (i, cell) in cells.iter().enumerate() {
        // Attack fixtures are distinct fresh local owners, not reopening the
        // positive client stores or claiming operational retry permission.
        let msg = message(cell);
        let mut o = owner(
            root,
            &format!("{label}-client-{i:02}"),
            p.claim_binding(ClaimRole::Client),
        )?;
        f.push(open_a(
            c,
            key,
            &seal_claimed_cell(c, o.consume(m.round(), m.id(), msg)?, cell)?,
        )?);
    }
    Ok(f.try_into().map_err(|_| "fixture exactly32")?)
}
fn message(cell: &[u8; 4096]) -> [u8; 32] {
    use silk_f04_relay::aip2_proof::semaphore_scalar;
    use silk_sapling_f04::codec::domain_hash;
    semaphore_scalar(&domain_hash(
        "SilkNode-AIP2R2-message",
        &[&cell[..128], &cell[416..]],
    ))
}
fn run(root: &Path) -> Result<(), Any> {
    let e: serde_json::Value = serde_json::from_slice(&read(&root.join("expected.json"), 4096)?)?;
    let actual_input = std::env::var("SILK_R2_ACTUAL_INPUT_HANDOFF").as_deref() == Ok("1");
    if actual_input
        && (e["actual_tls_inputs"] != true || std::env::var_os("SILK_R2_TIMED_HANDOFF").is_some())
    {
        return Err("explicit actual-input context, no mixed handoff modes".into());
    }
    let first_client = if actual_input { 1 } else { 0 };
    let domain = hex(e["domain"].as_str().ok_or("N")?)?;
    let role_keys = [
        hex(e["role_keys"][0].as_str().ok_or("A")?)?,
        hex(e["role_keys"][1].as_str().ok_or("B")?)?,
    ];
    let vk_hash = hex(e["vk_hash"].as_str().ok_or("VK")?)?;
    let round = e["round"].as_u64().ok_or("round")?;
    let epoch = u32::try_from(e["epoch"].as_u64().ok_or("epoch")?)?;
    let config = SignedConfig::verify(
        &read(&root.join("config.bin"), 770)?,
        domain,
        7,
        epoch,
        role_keys,
    )?;
    let manifest = SignedManifest::verify(&read(&root.join("manifest.bin"), 256)?, &config, round)?;
    let pb = read(&root.join("profile.bin"), 1312)?;
    let p = PreparedProfile::verify(
        &pb,
        &ProfileExpectations {
            domain,
            config: config.id(),
            epoch,
            cohort: 7,
            vk_hash,
            role_keys,
        },
    )?;
    let c = PreparedR2Context::new(&config, &manifest, &p, vk_hash)?;
    let s = prepare_cover_statement(&p, manifest.id(), round)?;
    let verifier = PreparedProofVerifier::from_canonical_vk(
        &read(&root.join("vk-canonical.json"), 16384)?,
        vk_hash,
    )?;
    let a = HpkePrivate::from_bytes(&[71; 32])?;
    let b = HpkePrivate::from_bytes(&[72; 32])?;
    directory(&root.join("pins"))?;
    let members: serde_json::Value =
        serde_json::from_slice(&read(&root.join("members-public.json"), 8192)?)?;
    let mut owners = Vec::with_capacity(32);
    let mut pins = Vec::new();
    // The actual timed client (member0) MUST own its only original claim/job.
    // Never create/consume a parallel client0 store in the cover precomputer.
    for i in first_client..32 {
        p.check_own_commitment(hex(members[i]["commitment"].as_str().ok_or("member")?)?)?;
        owners.push(owner(
            root,
            &format!("client-{i:02}"),
            p.claim_binding(ClaimRole::Client),
        )?);
    }
    // Hold all receipts while the separately contained fixture prover runs.
    let mut claims = Vec::with_capacity(32);
    let real = if root.join("envelope.bin").exists() {
        Some(read(&root.join("envelope.bin"), 2790)?)
    } else {
        None
    };
    for (j, o) in owners.iter_mut().enumerate() {
        let i = j + first_client;
        let mut template = *s.cell();
        if i == 0 {
            if let Some(e) = &real {
                if e.len() != 2790 {
                    return Err("real envelope length".into());
                }
                template[8] = 1;
                template[416..3206].copy_from_slice(e);
            }
        }
        let msg = message(&template);
        let claim = o.consume(round, manifest.id(), msg)?;
        let pin = fs::read(root.join(format!("pins/client-{i:02}")))?;
        pins.push(serde_json::json!({"owner":format!("client-{i:02}"),"pin":text(&pin),"message":text(&msg)}));
        claims.push(claim);
    }
    save(
        &root.join("claims-prepared.json"),
        &serde_json::json!({"profile_sha256":text(&Sha256::digest(&pb)),
        "profile_id":text(&p.id()),"root":text(&s.root()),"message":text(&s.message()),"scope_scalar":text(&s.scope()),
        "client_claims":pins,"actual_tls_cover_handoff":actual_input,"claim_before_new_proof_jobs":true,"held_receipts":true,"independent_pin_custody":false}),
    )?;
    let marker = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join("claims-ready"))?;
    marker.sync_all()?;
    let hold_deadline = Instant::now() + Duration::from_secs(110);
    while !root.join("proofs-complete").exists() {
        if Instant::now() >= hold_deadline {
            return Err("fixture proof handoff deadline".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let encoded: Vec<String> = serde_json::from_slice(&read(&root.join("cells.json"), 400000)?)?;
    let cells: Vec<[u8; 4096]> = encoded.iter().map(|x| hex(x)).collect::<Result<_, _>>()?;
    if cells.len() != 32 - first_client {
        return Err("exact new genuine fixture cell count".into());
    }
    if actual_input {
        if root.join("client-00").exists() || root.join("client-scope").exists() {
            return Err("actual client0 must not have a duplicate preparatory claim".into());
        }
        let mut out = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join("prepared-cover-stage1.bin"))?;
        for (claim, cell) in claims.into_iter().zip(&cells) {
            out.write_all(seal_claimed_cell(&c, claim, cell)?.bytes())?;
        }
        out.sync_all()?;
        fs::File::open(root)?.sync_all()?;
        println!(
            "PASS 31 precomputed genuine cover stage1 cells; no client0 claim, A/B open or exit authority"
        );
        return Ok(());
    }
    let mut fs2 = Vec::new();
    let legacy = RoundContext::new(&config, &manifest)?;
    for (claim, cell) in claims.into_iter().zip(&cells) {
        let f = seal_claimed_cell(&c, claim, cell)?;
        if PreparedR2Frame::decode(&f.bytes()[..8191], &c, 1).is_ok() {
            return Err("partial R2 frame accepted".into());
        }
        let mut legacy_wire = *f.bytes();
        legacy_wire[..8].copy_from_slice(b"SNMIX003");
        legacy_wire[8..10].copy_from_slice(&3_u16.to_le_bytes());
        if PreparedR2Frame::decode(&legacy_wire, &c, 1).is_ok() {
            return Err("R2 accepted legacy frame".into());
        }
        if Frame::decode(f.bytes(), &legacy, 1, 0).is_ok() {
            return Err("legacy accepted R2".into());
        }
        let mut tampered = *f.bytes();
        tampered[100] ^= 1;
        if open_a(&c, &a, &PreparedR2Frame::decode(&tampered, &c, 1)?).is_ok() {
            return Err("tampered outer accepted".into());
        }
        fs2.push(open_a(&c, &a, &f)?);
    }
    let mut fs2: [PreparedR2Frame; 32] = fs2.try_into().map_err(|_| "32 frames")?;
    permute_at_a(&c, &mut fs2)?;
    if std::env::var("SILK_R2_TIMED_HANDOFF").as_deref() == Ok("1") {
        // ONE ciphertext under each held client claim. A new timed native exit
        // will own the only positive exit claim; do not verify/reopen it here.
        let mut out = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join("prepared-r2-stage2.bin"))?;
        for f in &fs2 {
            out.write_all(f.bytes())?;
        }
        out.sync_all()?;
        fs::File::open(root)?.sync_all()?;
        println!("PASS claimed-client HPKE handoff; no exit gate, stage or release yet");
        return Ok(());
    }
    let hash = prepared_a_batch_id(&c, &fs2)?;
    let original: Vec<Vec<u8>> = fs2.iter().map(|f| f.bytes().to_vec()).collect();
    let batch = CollectedR2Batch::collect(&c, fs2, &ready(&config, &manifest, hash)?)?;
    let mut exit = owner(root, "exit-positive", p.claim_binding(ClaimRole::Exit))?;
    let consistency = batch.exit_consistency();
    let receipt = exit.consume(round, manifest.id(), consistency)?;
    let deadline = Instant::now() + Duration::from_secs(5); // fixture only, NOT R2 qualification
    let complete = batch.verify_membership(&c, &b, &verifier, receipt, deadline)?;
    let keys = if real.is_some() {
        let params =
            std::env::var_os("SILK_F04_PARAMETER_DIR").ok_or("parameters required for REAL")?;
        let dir = Path::new(&params);
        Some(silk_sapling_f04::parameters::SaplingVerificationKeys::load(
            &dir.join("sapling-spend.params"),
            &dir.join("sapling-output.params"),
        )?)
    } else {
        None
    };
    let verified = complete.verify_sapling(&c, keys.as_ref(), deadline)?;
    if verified.count() != 32
        || verified.real_count() != usize::from(real.is_some())
        || exit.consume(round, manifest.id(), consistency).is_ok()
    {
        return Err("positive owner/count/reuse".into());
    }
    let mut refusals = Vec::new();
    for label in [
        "last-invalid-proof",
        "payload-retarget",
        "duplicate-nullifier",
        "wrong-exit-digest",
        "expired-deadline",
        "wrong-ready-hash",
        "duplicate-encapsulation",
    ] {
        let mut altered = cells.clone();
        let new_frames = if matches!(
            label,
            "last-invalid-proof" | "payload-retarget" | "duplicate-nullifier"
        ) {
            match label {
                "last-invalid-proof" => altered[31][160] ^= 1,
                "payload-retarget" => {
                    altered[31][8] = 1;
                    altered[31][416] = 1;
                }
                _ => altered[31] = altered[0],
            }
            frames(root, label, &c, &p, &manifest, &a, &altered)?
        } else {
            let mut f: Vec<_> = original
                .iter()
                .map(|f| PreparedR2Frame::decode(f, &c, 2))
                .collect::<Result<_, _>>()?;
            if label == "duplicate-encapsulation" {
                f[31] = PreparedR2Frame::decode(&original[0], &c, 2)?;
            }
            f.try_into().map_err(|_| "32")?
        };
        let bh = prepared_a_batch_id(&c, &new_frames)?;
        let result = CollectedR2Batch::collect(
            &c,
            new_frames,
            &ready(
                &config,
                &manifest,
                if label == "wrong-ready-hash" {
                    [0x99; 32]
                } else {
                    bh
                },
            )?,
        );
        if matches!(label, "wrong-ready-hash" | "duplicate-encapsulation") {
            if result.is_ok() {
                return Err(format!("accepted {label}").into());
            }
        } else {
            let batch = result?;
            let msg = if label == "wrong-exit-digest" {
                [0x98; 32]
            } else {
                batch.exit_consistency()
            };
            let mut o = owner(root, label, p.claim_binding(ClaimRole::Exit))?;
            let claim = o.consume(round, manifest.id(), msg)?;
            let deadline = if label == "expired-deadline" {
                Instant::now()
            } else {
                Instant::now() + Duration::from_secs(5)
            };
            if batch
                .verify_membership(&c, &b, &verifier, claim, deadline)
                .is_ok()
            {
                return Err(format!("accepted {label}").into());
            }
            if o.consume(round, [0x97; 32], msg).is_ok() {
                return Err("failed gate reopened".into());
            }
        }
        refusals.push(label);
    }
    for o in &mut owners {
        if o.consume(round, manifest.id(), s.message()).is_ok() {
            return Err("client ciphertext scope reopened".into());
        }
    }
    save(
        &root.join("native-r2-result.json"),
        &serde_json::json!({"status":"PASS_ENCRYPTED_PRE_RELEASE_PREPARATION_ONLY",
        "signed_configuration":text(&config.id()),"signed_manifest":text(&manifest.id()),"profile_id":text(&p.id()),
        "round":round,"genuine_membership_count":32,"double_hpke_cells":32,"verified_cover_payloads":32-usize::from(real.is_some()),"real_sapling_checks":usize::from(real.is_some()),
        "held_client_receipts_through_proof_and_hpke":true,"exit_consumed_before_decrypt_and_pairings":true,
        "binding_negatives":refusals,"legacy_rejects_r2":true,"r2_rejects_legacy":true,"partial_frame_rejected":true,"outer_tamper_rejected":true,"failed_scopes_remain_consumed":true,
        "new_proofs_generated_by_rust":0,"trusted_setup":false,"clock_delivery_qualified":false,"runtime_deadline_fit":false,
        "staging_release_path":false,"activated":false,"anonymity":"UNPROVEN"}),
    )?;
    println!("PASS encrypted R2 pre-release fixture and seven new refusals");
    Ok(())
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("explicit fresh public fixture directory required");
        std::process::exit(2);
    }
    if let Err(e) = run(Path::new(&args[1])) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
