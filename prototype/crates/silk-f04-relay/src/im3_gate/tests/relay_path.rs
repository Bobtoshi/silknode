//! Administrative multiplexed A/C/B/P fixture. Actual original sockets and gates,
//! retained genuine cover proofs; optionally the first one or two slots come
//! only from distinct live clients. NOT independent roles/custody or anonymity.
use super::*;
use silk_sapling_f04::parameters::SaplingVerificationKeys;

struct RelayAdmission;
impl Im3RoleAdmission for RelayAdmission {
    fn admit(&mut self, _: &MiddleContext<'_>) -> Result<()> {
        Ok(())
    }
}

// Administrative fixture time mapping. This is not an independently qualified
// clock: it only places the immutable logical round at this process's test T.
struct RelayClock {
    physical_t: u64,
    base_round: u64,
}
impl Im3ClockSource for RelayClock {
    fn sample(&mut self, _: &MiddleContext<'_>) -> Result<crate::schedule::QualifiedClockSample> {
        let now = std::time::SystemTime::now();
        let physical_t = std::time::UNIX_EPOCH + Duration::from_secs(self.physical_t);
        let logical_t = std::time::UNIX_EPOCH + Duration::from_secs(self.base_round * 30);
        let logical_now = match physical_t.duration_since(now) {
            Ok(remaining) => logical_t - remaining,
            Err(_) => logical_t + now.duration_since(physical_t).unwrap(),
        };
        crate::schedule::QualifiedClockSample::from_qualified_source(
            logical_now,
            Instant::now(),
            Duration::ZERO,
        )
    }
}

fn record(
    rows: &mut Vec<serde_json::Value>,
    surface: &str,
    origin: Instant,
    o: crate::tls::WireObservation,
) {
    if o.bytes > 0 || o.failed || o.record_complete {
        rows.push(json!({"surface":surface,"connection":o.connection,
            "start":if o.started>=origin {(o.started-origin).as_secs_f64()}else{-(origin-o.started).as_secs_f64()},
            "end":if o.completed>=origin {(o.completed-origin).as_secs_f64()}else{-(origin-o.completed).as_secs_f64()},
            "bytes":o.bytes,"complete":o.record_complete,"failed":o.failed}));
    }
}
pub(super) fn run(
    c: &MiddleContext<'_>,
    root: &Path,
    out: &Path,
    frames: Vec<MiddleFrame>,
    middle: &HpkePrivate,
    b: &HpkePrivate,
    verifier: &PreparedProofVerifier,
    envelope: &[u8],
) -> serde_json::Value {
    let external_count: usize = std::env::var("SILK_IM3_EXTERNAL_CLIENTS")
        .map(|n| n.parse().unwrap())
        .unwrap_or_else(|_| usize::from(std::env::var_os("SILK_IM3_EXTERNAL_CLIENT").is_some()));
    assert!(external_count <= 2);
    let external = external_count > 0;
    let all = if external_count == 2 {
        // Only the 30 adversarial slots have preprepared stage-2 frames. No
        // placeholder proof or ciphertext is made for either honest client.
        assert_eq!(frames.len(), 30);
        frames
    } else {
        let retained = PathBuf::from(std::env::var_os("SILK_IM3_ACTUAL_CLIENT_STAGE2").unwrap());
        let actual = MiddleFrame::decode(&fs::read(&retained).unwrap(), c, 2).unwrap();
        let plain = open(c, 2, c.c_key(), middle, &actual.bytes()[64..4720]).unwrap();
        let nullifier = &plain[128..160];
        let mut replaced = 0;
        let mut all = Vec::with_capacity(32);
        all.push(actual);
        for frame in frames {
            let p = open(c, 2, c.c_key(), middle, &frame.bytes()[64..4720]).unwrap();
            if &p[128..160] == nullifier {
                replaced += 1;
            } else {
                all.push(frame);
            }
        }
        assert_eq!(replaced, 1);
        assert_eq!(all.len(), 32);
        drop(plain);
        all
    };
    // Only this private fixture may recreate A wrapping around retained genuine
    // C statements. The production ingress has no raw-frame injection API.
    let onions: Vec<_> = (0..32)
        .map(|i| {
            if i < external_count {
                return None;
            }
            let fixture_index = if external_count == 2 { i - 2 } else { i };
            let f = &all[fixture_index];
            let mut plain = Zeroizing::new([0; 5120]);
            plain[..4720].copy_from_slice(&f.bytes()[..4720]);
            Some(
                frame(
                    c,
                    1,
                    &seal(c, 1, c.r2.round.config.hpke_keys()[0], plain.as_ref()).unwrap(),
                )
                .unwrap(),
            )
        })
        .collect();
    let tls = PathBuf::from(std::env::var_os("SILK_IM3_C_TLS").unwrap());
    let (mut clients, mut server) = if external {
        incoming::external_prefix_pairs(
            c.r2.round.config.endpoints()[0],
            &root.join("tls/root.der"),
            &root.join("tls/leaf-0.der"),
            &root.join("tls/leaf-0-key.der"),
            &out.join("original-A-ready"),
            external_count,
        )
    } else {
        let (clients, server): (Vec<_>, Vec<_>) = incoming::pairs(
            c.r2.round.config.endpoints()[0],
            &root.join("tls/root.der"),
            &root.join("tls/leaf-0.der"),
            &root.join("tls/leaf-0-key.der"),
            32,
        )
        .into_iter()
        .unzip();
        (
            clients.into_iter().map(Some).collect::<Vec<_>>(),
            server.try_into().ok().unwrap(),
        )
    };
    let (mut ac, mut crx) = incoming::pairs(
        c.q.endpoint(),
        &root.join("tls/root.der"),
        &tls.join("c.der"),
        &tls.join("c-key.der"),
        1,
    )
    .pop()
    .unwrap();
    let (mut cb, mut brx) = incoming::pairs(
        c.r2.round.config.endpoints()[1],
        &root.join("tls/root.der"),
        &root.join("tls/leaf-1.der"),
        &root.join("tls/leaf-1-key.der"),
        1,
    )
    .pop()
    .unwrap();
    let params = PathBuf::from(std::env::var_os("SILK_F04_PARAMETER_DIR").unwrap());
    let keys = SaplingVerificationKeys::load(
        &params.join("sapling-spend.params"),
        &params.join("sapling-output.params"),
    )
    .unwrap();
    let (ab_client, ab_server) = incoming::pairs(
        c.r2.round.config.endpoints()[1],
        &root.join("tls/root.der"),
        &root.join("tls/leaf-1.der"),
        &root.join("tls/leaf-1-key.der"),
        1,
    )
    .pop()
    .unwrap();
    let mut bp_links = Vec::with_capacity(3);
    let mut p_links = Vec::with_capacity(3);
    for i in 0..3 {
        let (tx, rx) = incoming::pairs(
            c.r2.round.config.endpoints()[i + 2],
            &root.join("tls/root.der"),
            &root.join(format!("tls/leaf-{}.der", i + 2)),
            &root.join(format!("tls/leaf-{}-key.der", i + 2)),
            1,
        )
        .pop()
        .unwrap();
        bp_links.push(tx);
        p_links.push(rx);
    }
    let a_signing = SigningKey::from_bytes(&[11; 32]);
    let b_signing = SigningKey::from_bytes(&[12; 32]);
    let p_signing: [SigningKey; 3] =
        std::array::from_fn(|i| SigningKey::from_bytes(&[13 + u8::try_from(i).unwrap(); 32]));
    let round = c.r2.round.manifest.round();
    let physical_t = if external {
        std::env::var("SILK_IM3_RELAY_FIXTURE_T")
            .unwrap()
            .parse::<u64>()
            .unwrap()
    } else {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 12
    };
    let offset = i64::try_from(round * 30).unwrap() - i64::try_from(physical_t).unwrap();
    let sequence_path = out.join("round-sequence");
    directory(&sequence_path);
    let mut runner = Im3RoundRunner::create(
        &sequence_path,
        c.profile,
        FilePins(out.join("round-sequence.pin")),
        RelayAdmission,
        RelayClock {
            physical_t,
            base_round: round,
        },
    )
    .unwrap();
    let mut partial_result = None;
    let mut success_result = None;
    let cp = out.join("middle-scope");
    let bp = out.join("exit-scope");
    let mp = out.join("ingress-manifest-scope");
    let ap = out.join("authorization-scope");
    let rp = out.join("release-scope");
    let p_claim_roles = [
        ClaimRole::Im3Producer0,
        ClaimRole::Im3Producer1,
        ClaimRole::Im3Producer2,
    ];
    let p_paths: [PathBuf; 3] = std::array::from_fn(|i| out.join(format!("producer-{i}-scope")));
    runner.run_round(c, |ports| {
    let schedule = ports.schedule();
    let origin = schedule.at(0).unwrap();
    directory(&cp);
    directory(&bp);
    directory(&mp);
    let mut ms = PreparedScopeStore::create(
        &mp,
        c.profile.claim_binding(ClaimRole::Im3Ingress),
        FilePins(out.join("ingress-manifest-pin")),
    )
    .unwrap();
    let mut cs =
        PreparedScopeStore::create(&cp, c.claim_binding(), FilePins(out.join("middle-pin")))
            .unwrap();
    let mut bs = PreparedScopeStore::create(
        &bp,
        c.profile.claim_binding(ClaimRole::Exit),
        FilePins(out.join("exit-pin")),
    )
    .unwrap();
    directory(&ap);
    directory(&rp);
    let mut auth_store = PreparedScopeStore::create(
        &ap,
        c.profile.claim_binding(ClaimRole::Im3Authorization),
        FilePins(out.join("authorization-pin")),
    )
    .unwrap();
    let mut release_store = PreparedScopeStore::create(
        &rp,
        c.profile.claim_binding(ClaimRole::Im3Release),
        FilePins(out.join("release-pin")),
    )
    .unwrap();
    let p_roles = [Im3Role::P0, Im3Role::P1, Im3Role::P2];
    let mut p_stores: Vec<_> = (0..3)
        .map(|i| {
            directory(&p_paths[i]);
            PreparedScopeStore::create(
                &p_paths[i],
                c.profile.claim_binding(p_claim_roles[i]),
                FilePins(out.join(format!("producer-{i}-pin"))),
            )
            .unwrap()
        })
        .collect();
    let a_reservation = ports.authorization(&mut auth_store, ab_client, &a_signing).unwrap();
    let [bp0, bp1, bp2]: [Transport; 3] = bp_links.try_into().ok().unwrap();
    let b_reservation = ports.release(
        &mut release_store,
        [ab_server, bp0, bp1, bp2],
        &b_signing,
    ).unwrap();
    let mut producers: Vec<_> = p_stores
        .iter_mut()
        .zip(p_links)
        .enumerate()
        .map(|(i, (store, link))| {
            ports.producer(store, link, p_roles[i], &p_signing[i]).unwrap()
        })
        .collect();
    let mut fanout = ports.manifest_fanout(&mut ms, &mut server, &mut ac).unwrap();
    let mut admission = ports.manifest_middle(&mut cs, &mut crx, &mut cb).unwrap();
    let mut exit = ports.exit(&mut bs, &mut brx).unwrap();
    let mut observations = Vec::new();
    for client in clients.iter_mut().flatten() {
        client
            .expect(RecordSize::Manifest, schedule.at(-5_000_000_000).unwrap())
            .unwrap();
    }
    let mut manifests = [false; 32];
    // The distinct client checks M itself; its manifest receipt is joined by
    // the controller, never injected here as an admission acknowledgement.
    for admitted in manifests.iter_mut().take(external_count) {
        *admitted = true;
    }
    let mut manifest_cursor = 0;
    // All owners/claims are already bound. Sleeping until the immutable first
    // manifest write neither renews the native lease nor widens any deadline.
    sleep_until(schedule.at(-8_000_000_000).unwrap());
    loop {
        assert!(Instant::now() < schedule.at(-5_000_000_000).unwrap());
        let done = fanout.poll().unwrap();
        if let Some((lane, o)) = fanout.take_wire_observation() {
            record(
                &mut observations,
                if lane == 32 {
                    "A_original_C_manifest_write"
                } else {
                    "A_original_client_manifest_write"
                },
                origin,
                o,
            );
        }
        let admitted = admission.poll().unwrap();
        if let Some((_, o)) = admission.take_wire_observation() {
            record(&mut observations, "C_original_A_manifest_read", origin, o);
        }
        if !manifests[manifest_cursor] {
            let (r, o) = clients[manifest_cursor]
                .as_mut()
                .unwrap()
                .read_step_observed();
            record(&mut observations, "fixture_client_manifest_read", origin, o);
            if let Some(bytes) = r.unwrap() {
                let m = SignedManifest::verify(&bytes, c.r2.round.config, round).unwrap();
                assert_eq!(m.bytes(), c.r2.round.manifest.bytes());
                manifests[manifest_cursor] = true;
            }
        }
        manifest_cursor = (manifest_cursor + 1) % 32;
        if done && admitted && manifests.iter().all(|v| *v) {
            break;
        }
        std::thread::sleep(Duration::from_micros(500));
    }
    let mut ingress = fanout.receive().unwrap();
    let mut middle_owner = admission.receive().unwrap();
    let manifest_now = Instant::now();
    let manifest_complete = if manifest_now >= origin {
        (manifest_now - origin).as_secs_f64()
    } else {
        -(origin - manifest_now).as_secs_f64()
    };
    let mut send = external_count;
    let mut queued = false;
    sleep_until(schedule.at(6_000_000_000).unwrap());
    // Reserve before -5, arm before +19, and never widen TLS's unchanged
    // maximum of 30 seconds from actual record selection to cutoff.
    exit.poll().unwrap();
    for producer in &mut producers {
        producer.poll().unwrap();
    }
    while Instant::now() < schedule.at(15_000_000_000).unwrap() {
        if send < 32 {
            let (start, end) = schedule.client_slot(u8::try_from(send).unwrap()).unwrap();
            if Instant::now() >= start {
                assert!(Instant::now() < end);
                if !queued {
                    clients[send]
                        .as_mut()
                        .unwrap()
                        .queue(
                            RecordSize::Cell,
                            onions[send].as_ref().unwrap().bytes(),
                            end,
                        )
                        .unwrap();
                    queued = true;
                }
                let (r, o) = clients[send].as_mut().unwrap().write_step_observed();
                record(&mut observations, "fixture_client_write", origin, o);
                if r.unwrap() {
                    send += 1;
                    queued = false;
                }
            }
        }
        ingress.poll().unwrap();
        if let Some((source, o)) = ingress.take_wire_observation() {
            let before = observations.len();
            record(&mut observations, "A_original_client_read", origin, o);
            if observations.len() > before {
                observations.last_mut().unwrap()["source_slot"] = json!(source);
            }
        }
        std::thread::sleep(Duration::from_micros(500));
    }
    assert_eq!(send, 32);
    for slot in 0..external_count {
        // This commitment is made from the bytes actually read by A before
        // A-open/permutation, not from a client file or retained stage2.
        let name = if slot == 0 {
            "received-original-onion-commitment".to_string()
        } else {
            format!("received-original-onion-commitment-{slot}")
        };
        save(
            &out.join(name),
            &domain_hash(
                "IM3-test-original-onion",
                &[ingress.fixture_original(u8::try_from(slot).unwrap())],
            ),
        );
    }
    let train = ingress
        .freeze(
            &HpkePrivate::from_bytes(&[71; 32]).unwrap(),
            &SigningKey::from_bytes(&[11; 32]),
        )
        .unwrap();
    let mut authorizer = a_reservation.bind(train).unwrap();
    if std::env::var_os("SILK_IM3_PARTIAL_A_TRAIN_ONLY").is_some() {
        sleep_until(schedule.relay_slot(false, 0).unwrap().0);
        loop {
            assert!(Instant::now() < schedule.relay_slot(false, 0).unwrap().1);
            assert!(!authorizer.poll().unwrap());
            if authorizer
                .take_wire_observation()
                .is_some_and(|(lane, o)| lane == 1 && o.record_complete)
            {
                break;
            }
            std::thread::sleep(Duration::from_micros(100));
        }
        loop {
            assert!(!middle_owner.poll().unwrap());
            if middle_owner
                .take_wire_observation()
                .is_some_and(|o| o.record_complete)
            {
                break;
            }
            assert!(Instant::now() < schedule.relay_slot(false, 1).unwrap().0);
            std::thread::sleep(Duration::from_micros(100));
        }
        // This is the actual frozen A train owner, not a caller-written cell.
        // Dropping it closes the original output after one complete Cell.
        drop(authorizer);
        loop {
            match middle_owner.poll() {
                Err(_) => break,
                Ok(false) => {
                    assert!(Instant::now() < schedule.at(17_500_000_000).unwrap());
                    std::thread::sleep(Duration::from_micros(100));
                }
                Ok(true) => panic!("partial A train became complete C input"),
            }
        }
        while !middle_owner
            .poll_cancel(&SigningKey::from_bytes(&[16; 32]))
            .unwrap()
        {
            assert!(Instant::now() < schedule.at(20_500_000_000).unwrap());
            std::thread::sleep(Duration::from_micros(100));
        }
        loop {
            match exit.poll() {
                Err(Error::Unavailable("IM3 C cancelled")) => break,
                Ok(false) => {
                    assert!(Instant::now() < schedule.at(20_500_000_000).unwrap());
                    std::thread::sleep(Duration::from_micros(100));
                }
                other => panic!("partial A train B cancel: {:?}", other.err()),
            }
        }
        drop(middle_owner);
        drop(exit);
        drop(b_reservation);
        drop(producers);
        for client in clients.iter_mut().flatten() {
            client.quarantine().unwrap();
        }
        partial_result = Some(json!({"status":"PASS_ACTUAL_A_PARTIAL_TRAIN_C_TO_B_CANCEL",
            "actual_A_train_cells_sent":1,"C_output_cells":0,"B_output_cells":0,
            "signed_C_cancel":true,"durable_sequence_abort_terminal":true,
            "new_proofs":0,"new_work":0,"qualified_clock":false}));
        return Ok(Im3RoundTerminal::Abort);
    }
    while Instant::now() < schedule.at(17_500_000_000).unwrap() {
        authorizer.poll().unwrap();
        if let Some((lane, o)) = authorizer.take_wire_observation() {
            record(
                &mut observations,
                if lane == 1 {
                    "A_original_C_write"
                } else {
                    "A_original_B_control"
                },
                origin,
                o,
            );
        }
        middle_owner.poll().unwrap();
        if let Some(o) = middle_owner.take_wire_observation() {
            record(&mut observations, "C_original_A_read", origin, o);
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    let verified = middle_owner.verify(middle, verifier).unwrap();
    sleep_until(schedule.at(19_250_000_000).unwrap());
    let mut disclosure = verified.decide().unwrap();
    assert_eq!(fs::read(cp.join("CURRENT")).unwrap()[10], 1);
    let mut data_done = false;
    let mut ready_done = false;
    while Instant::now() < schedule.at(22_000_000_000).unwrap() {
        if !data_done {
            data_done = disclosure.poll().unwrap();
        } else if !ready_done {
            ready_done = disclosure
                .poll_ready(c, &SigningKey::from_bytes(&[16; 32]))
                .unwrap();
        }
        if let Some(o) = disclosure.take_wire_observation() {
            record(&mut observations, "C_original_B_write", origin, o);
        }
        exit.poll().unwrap();
        if let Some(o) = exit.take_wire_observation() {
            record(&mut observations, "B_original_C_read", origin, o);
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    assert!(data_done && ready_done);
    let verified = exit.verify(b, verifier, Some(&keys)).unwrap();
    assert_eq!(verified.count(), 32);
    assert_eq!(verified.real_count(), 1);
    assert!(verified.fixture_matches(envelope));
    let b_complete = (Instant::now() - origin).as_secs_f64();
    assert!(b_complete < 23.75);
    let stage = verified.stage(c, &b_signing).unwrap();
    assert_eq!(stage.real_count(), 1);
    assert!(crate::frame::Frame::decode(stage.frames()[0].bytes(), &c.r2.round, 3, 0).is_err());
    let mut releasing = b_reservation.bind(stage).unwrap();
    let mut carriage_done = false;
    let mut carriage_at = 0.0;
    while Instant::now() < schedule.at(44_000_000_000).unwrap() {
        authorizer.poll().expect("actual A authorization cycle");
        if let Some((lane, o)) = authorizer.take_wire_observation() {
            record(
                &mut observations,
                if lane == 1 {
                    "A_original_C_write"
                } else {
                    "A_original_B_control"
                },
                origin,
                o,
            );
        }
        releasing.poll().expect("actual B release cycle");
        if let Some((lane, o)) = releasing.take_wire_observation() {
            let surface = format!("B_original_control_lane_{lane}");
            record(&mut observations, &surface, origin, o);
        }
        for (i, producer) in producers.iter_mut().enumerate() {
            producer.poll().expect("actual producer full release");
            if let Some((_, o)) = producer.take_wire_observation() {
                let surface = format!("P{i}_original_B_control");
                record(&mut observations, &surface, origin, o);
            }
        }
        if !carriage_done && Instant::now() >= schedule.at(43_000_000_000).unwrap() {
            for (i, producer) in producers.iter_mut().enumerate() {
                let release = producer
                    .take_released()
                    .expect("actual all32 opened release");
                let role = [
                    crate::control::Role::P0,
                    crate::control::Role::P1,
                    crate::control::Role::P2,
                ][i];
                assert_eq!(release.delivery().producer, role);
                let mut inbox = crate::handoff::v1::ProducerInboxV1::new(
                    c.r2.round.config.domain(),
                    c.r2.round.config.cohort(),
                    role,
                )
                .unwrap();
                inbox.offer(release).unwrap();
                assert_eq!(inbox.payload_bytes(), 2790);
                let (_, offer) = inbox.take_next().unwrap();
                assert!(inbox.take_next().is_none());
                let body = offer.encode_local().unwrap();
                assert_eq!(&body[20..], envelope);
                save(&out.join(format!("producer-{i}-local-offer.bin")), &body);
            }
            carriage_at = (Instant::now() - origin).as_secs_f64();
            carriage_done = true;
        }
        // The slowest fixed train here has31.25ms slots; a2ms coordinator
        // cadence still services all three original writes inside each slot.
        // Avoid spending the shared fixture guard on idle socket peeks. This
        // neither raises a role's native cap nor changes any deadline.
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(carriage_done);
    assert!(authorizer.poll().unwrap());
    assert!(releasing.poll().unwrap());
    for producer in &mut producers {
        assert!(producer.poll().unwrap());
    }
    assert!(disclosure.poll_cleanup().unwrap());
    drop(producers);
    drop(authorizer);
    let completed = releasing.into_completed().unwrap();
    drop(disclosure);
    save(
        &out.join("relay-wire-observations.json"),
        &serde_json::to_vec(&observations).unwrap(),
    );
    success_result = Some(json!({"status":"PASS_ACTUAL32_A_C_B_THREE_PRODUCER_FULL_CHAIN_RELEASE_ORDINARY_CARRIAGE",
        "physical_T_utc":physical_t,"immutable_fixture_offset_seconds":offset,"original_client_links":32,
        "retained_original_wallet_client_stage2":!external,"fresh_client_dispatch_in_this_run":external,
        "external_client_count":external_count,
        "fresh_client_proofs_generated_in_external_workers":2*external_count,
        "native_relay_new_proofs":0,"new_proofs":0,"new_work":0,"A_C_train_and_ready":true,"C_B_train_and_complete_A_C_chain":true,
        "C_disclosure_durable_before_B_write":true,"B_membership_before_Sapling":true,
        "exact_existing_payment_at_B":true,"B_complete_offset_seconds":b_complete,
        "cold_middle_and_exit_round_replay_refused":true,"held_until_cleanup":true,
        "multiplexed_admin_guard_not_independent_role_qualification":true,"qualified_clock":false,
        "independent_custody":false,"anonymity_proven":false,"producer_staging":true,"settlement":false,
        "producer_full_chain_ACKs":3,"actual_A_authorization":true,"durable_B_release_before_key":true,
        "original_signed_manifest_all32_clients_and_C":true,"manifest_complete_offset_seconds":manifest_complete,
        "all32_client_manifest_read_receipts_in_this_process":!external,
        "external_original_client_manifest_receipt_required":external,
        "C_same_claim_manifest_through_complete_gate":true,"cold_A_manifest_round_refused":true,
        "all_three_ordinary_offers_exact_payment":true,"ordinary_carriage_offset_seconds":carriage_at,
        "durable_sequence_release_terminal":true,"next_even_round_admitted_and_aborted":round+2,
        "cold_sequence_old_round_refused":true,
        "cold_authorization_release_and_three_producer_rounds_refused":true,
        "full_chain_through_runner_ports":true}));
    Ok(Im3RoundTerminal::Release(completed))
    }).unwrap();
    if let Some(result) = partial_result {
        return result;
    }
    let mut next_manifest = *c.r2.round.manifest.bytes();
    next_manifest[44..52].copy_from_slice(&(round + 2).to_le_bytes());
    let mut signed_body = c.r2.round.config.id().to_vec();
    signed_body.extend_from_slice(&next_manifest[..128]);
    next_manifest[128..192].copy_from_slice(&sign(11, "SilkNode-F0-round", &signed_body));
    next_manifest[192..256].copy_from_slice(&sign(12, "SilkNode-F0-round", &signed_body));
    let next_manifest =
        SignedManifest::verify(&next_manifest, c.r2.round.config, round + 2).unwrap();
    let next_context = MiddleContext::new(
        c.r2.round.config,
        &next_manifest,
        c.profile,
        c.claim_binding().vk_hash,
        c.q,
    )
    .unwrap();
    runner
        .run_round(&next_context, |_| Ok(Im3RoundTerminal::Abort))
        .unwrap();
    let sequence_pin = runner.pin();
    assert_eq!(
        fs::read(out.join("round-sequence.pin")).unwrap(),
        sequence_pin
    );
    drop(runner);
    let reopened_sequence = Im3RoundRunner::open(
        &sequence_path,
        c.profile,
        sequence_pin,
        round + 2,
        FilePins(out.join("round-sequence.pin")),
        RelayAdmission,
        RelayClock {
            physical_t,
            base_round: round,
        },
    )
    .unwrap();
    assert!(reopened_sequence.earliest_round() >= round + 5);
    drop(reopened_sequence);
    for (path, pin, binding) in [
        (&cp, out.join("middle-pin"), c.claim_binding()),
        (
            &mp,
            out.join("ingress-manifest-pin"),
            c.profile.claim_binding(ClaimRole::Im3Ingress),
        ),
        (
            &bp,
            out.join("exit-pin"),
            c.profile.claim_binding(ClaimRole::Exit),
        ),
        (
            &ap,
            out.join("authorization-pin"),
            c.profile.claim_binding(ClaimRole::Im3Authorization),
        ),
        (
            &rp,
            out.join("release-pin"),
            c.profile.claim_binding(ClaimRole::Im3Release),
        ),
    ] {
        let latest = fs::read(&pin).unwrap().try_into().unwrap();
        let mut cold =
            PreparedScopeStore::open(path, binding, latest, round, FilePins(pin)).unwrap();
        assert!(cold
            .consume(round, c.r2.round.manifest.id(), [9; 32])
            .is_err());
    }
    for (i, path) in p_paths.iter().enumerate() {
        let pin = out.join(format!("producer-{i}-pin"));
        let latest = fs::read(&pin).unwrap().try_into().unwrap();
        let mut cold = PreparedScopeStore::open(
            path,
            c.profile.claim_binding(p_claim_roles[i]),
            latest,
            round,
            FilePins(pin),
        )
        .unwrap();
        assert!(cold
            .consume(round, c.r2.round.manifest.id(), [9; 32])
            .is_err());
    }
    success_result.expect("runner release result")
}
