//! Signature-valid alternate-M refusal on actual original C/B sockets. No
//! membership/Sapling proof or output ciphertext is generated in this check.
use super::*;
// The first pin is store creation; the second is the actual irreversible
// consume. Delay only that second return, after the new pin is durable.
struct DelayedConsumePin {
    file: FilePins,
    calls: usize,
    until: Instant,
}
impl ClaimPinRetention for DelayedConsumePin {
    fn retain_claim_pin(&mut self, pin: Digest) -> ClaimResult<()> {
        self.file.retain_claim_pin(pin)?;
        self.calls += 1;
        if self.calls == 2 {
            sleep_until(self.until);
        }
        Ok(())
    }
}
pub(super) fn delayed_claim(c: &MiddleContext<'_>, root: &Path, out: &Path) -> serde_json::Value {
    let tls = PathBuf::from(std::env::var_os("SILK_IM3_C_TLS").unwrap());
    let (mut a, mut input) = incoming::pairs(
        c.q.endpoint(),
        &root.join("tls/root.der"),
        &tls.join("c.der"),
        &tls.join("c-key.der"),
        1,
    )
    .pop()
    .unwrap();
    let (mut output, mut b) = incoming::pairs(
        c.r2.round.config.endpoints()[1],
        &root.join("tls/root.der"),
        &root.join("tls/leaf-1.der"),
        &root.join("tls/leaf-1-key.der"),
        1,
    )
    .pop()
    .unwrap();
    let round = c.r2.round.manifest.round();
    let physical_t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 12;
    let offset = i64::try_from(round * 30).unwrap() - i64::try_from(physical_t).unwrap();
    crate::schedule::initialize_functional_offset(offset).unwrap();
    let schedule = Im3Schedule::functional_fixture(c.r2.round.config, round).unwrap();
    let guard = Im3Guard::arm(&schedule).unwrap();
    let path = out.join("delayed-middle");
    directory(&path);
    let pin_path = out.join("delayed-middle-pin");
    let cutoff = schedule.at(-9_000_000_000).unwrap();
    let until = schedule.at(-8_900_000_000).unwrap();
    let mut store = PreparedScopeStore::create(
        &path,
        c.claim_binding(),
        DelayedConsumePin {
            file: FilePins(pin_path.clone()),
            calls: 0,
            until,
        },
    )
    .unwrap();
    assert!(Instant::now() < cutoff);
    let result =
        ManifestReceivingMiddle::begin(c, &mut store, &schedule, &guard, &mut input, &mut output);
    let returned = Instant::now();
    assert!(returned >= until);
    assert!(returned < schedule.at(-5_000_000_000).unwrap());
    assert!(
        result.is_err(),
        "late durable claim must not create manifest owner"
    );
    drop(result);
    // Rejected before arming M, and neither original link remains usable.
    assert!(input.selected_read().is_none());
    for link in [&mut input, &mut output] {
        assert!(
            link.queue(
                RecordSize::Control,
                &[0; 512],
                returned + Duration::from_secs(1)
            )
            .is_err()
        );
    }
    let mut eof_steps = [0usize; 2];
    for (i, peer) in [&mut a, &mut b].into_iter().enumerate() {
        let end = Instant::now() + Duration::from_secs(1);
        peer.expect(RecordSize::Control, end).unwrap();
        loop {
            let (r, o) = peer.read_step_observed();
            eof_steps[i] += 1;
            assert_eq!(o.bytes, 0);
            if matches!(r, Err(Error::Unavailable("TLS read EOF"))) {
                break;
            }
            assert!(r.unwrap().is_none());
            assert!(Instant::now() < end);
            std::thread::sleep(Duration::from_micros(100));
        }
    }
    let bytes = fs::read(path.join("CURRENT")).unwrap();
    assert_eq!(bytes[9], 1);
    assert_eq!(bytes[10], 0);
    let pin = store.pin();
    assert_eq!(fs::read(&pin_path).unwrap(), pin);
    drop(store);
    drop(guard);
    let mut cold =
        PreparedScopeStore::open(&path, c.claim_binding(), pin, round, FilePins(pin_path)).unwrap();
    assert!(
        cold.consume(round, c.r2.round.manifest.id(), c.choice())
            .is_err()
    );
    json!({"status":"PASS_POST_CONSUME_T_MINUS_9_CUTOFF_REFUSED",
        "pin_return_after_cutoff_ns":returned.duration_since(cutoff).as_nanos(),
        "returned_before_broader_T_minus_5_gate":true,"manifest_read_armed":false,
        "original_A_B_zero_byte_eof":true,"peer_read_steps":eof_steps,
        "claim_consumed":true,"disclosure_decided":false,"cold_round_replay_refused":true,
        "new_membership_proofs":0,"new_Sapling_components":0,"new_work":0,
        "qualified_clock":false,"anonymity_proven":false})
}
pub(super) fn run(c: &MiddleContext<'_>, root: &Path, out: &Path) -> serde_json::Value {
    let tls = PathBuf::from(std::env::var_os("SILK_IM3_C_TLS").unwrap());
    let (mut a, mut input) = incoming::pairs(
        c.q.endpoint(),
        &root.join("tls/root.der"),
        &tls.join("c.der"),
        &tls.join("c-key.der"),
        1,
    )
    .pop()
    .unwrap();
    let (mut output, mut observer) = incoming::pairs(
        c.r2.round.config.endpoints()[1],
        &root.join("tls/root.der"),
        &root.join("tls/leaf-1.der"),
        &root.join("tls/leaf-1-key.der"),
        1,
    )
    .pop()
    .unwrap();
    let round = c.r2.round.manifest.round();
    let physical_t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 12;
    let offset = i64::try_from(round * 30).unwrap() - i64::try_from(physical_t).unwrap();
    crate::schedule::initialize_functional_offset(offset).unwrap();
    let schedule = Im3Schedule::functional_fixture(c.r2.round.config, round).unwrap();
    let guard = Im3Guard::arm(&schedule).unwrap();
    let path = out.join("claimed-middle");
    directory(&path);
    let pin_path = out.join("middle-pin");
    let mut store =
        PreparedScopeStore::create(&path, c.claim_binding(), FilePins(pin_path.clone())).unwrap();
    let mut receiver =
        ManifestReceivingMiddle::begin(c, &mut store, &schedule, &guard, &mut input, &mut output)
            .unwrap();
    let mut alternate = *c.r2.round.manifest.bytes();
    alternate[92] ^= 1;
    let mut body = c.r2.round.config.id().to_vec();
    body.extend_from_slice(&alternate[..128]);
    alternate[128..192].copy_from_slice(&sign(11, "SilkNode-F0-round", &body));
    alternate[192..256].copy_from_slice(&sign(12, "SilkNode-F0-round", &body));
    assert!(SignedManifest::verify(&alternate, c.r2.round.config, round).is_ok());
    assert_ne!(alternate, c.r2.round.manifest.bytes().as_slice());
    sleep_until(schedule.at(-8_000_000_000).unwrap());
    let end = schedule.at(-7_000_000_000).unwrap();
    a.queue(RecordSize::Manifest, &alternate, end).unwrap();
    while !a.write_step().unwrap() {
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_micros(100));
    }
    let mut steps = 0;
    loop {
        let result = receiver.poll();
        steps += 1;
        if let Err(e) = result {
            assert!(matches!(
                e,
                Error::Invalid("IM3 C alternate original manifest")
            ));
            break;
        }
        assert!(!result.unwrap());
        std::thread::sleep(Duration::from_micros(100));
    }
    assert!(receiver.poll().is_err());
    assert!(receiver.receive().is_err());
    assert_eq!(fs::read(path.join("CURRENT")).unwrap()[9], 1);
    assert_eq!(fs::read(path.join("CURRENT")).unwrap()[10], 0);
    let cut = Instant::now() + Duration::from_secs(1);
    observer.expect(RecordSize::Cell, cut).unwrap();
    let mut observed_bytes = 0;
    loop {
        let (r, o) = observer.read_step_observed();
        observed_bytes += o.bytes;
        if let Err(e) = r {
            assert!(matches!(e, Error::Unavailable("TLS read EOF")));
            break;
        }
        assert!(r.unwrap().is_none());
        assert!(Instant::now() < cut);
        std::thread::sleep(Duration::from_micros(100));
    }
    assert_eq!(observed_bytes, 0);
    let pin = store.pin();
    drop(store);
    drop(guard);
    let mut cold =
        PreparedScopeStore::open(&path, c.claim_binding(), pin, round, FilePins(pin_path)).unwrap();
    assert!(
        cold.consume(round, c.r2.round.manifest.id(), c.choice())
            .is_err()
    );
    json!({"status":"PASS_SIGNATURE_VALID_ALTERNATE_M_REFUSED_ORIGINAL_C_B_LINKS_CLOSED",
        "actual_original_manifest_read_steps":steps,"B_bytes":observed_bytes,"disclosure_decided":false,
        "same_round_claim_already_consumed":true,"cold_round_replay_refused":true,
        "new_membership_proofs":0,"new_Sapling_components":0,"new_work":0,"qualified_clock":false,"anonymity_proven":false})
}
