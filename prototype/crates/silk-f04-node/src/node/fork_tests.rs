//! Bounded genuine valueless fork over isolated copies, not default activation.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{fs, path::PathBuf};
static RETAINED_ROLLBACKS: AtomicUsize = AtomicUsize::new(0);

fn fixture_digest(name: &str) -> Digest {
    hex::decode(std::env::var(name).unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

fn fixture_open(
    root: &Path,
    margin: &Path,
    genesis: Genesis,
    parameters: &SaplingParameters,
    pin: Digest,
) -> Node {
    if std::env::var("SILK_F04_EXTENDED_PROFILE_GATE").as_deref() == Ok("1") {
        let limits = crate::capacity::HistoryLimitsV1::for_vertices(8192).unwrap();
        let node =
            Node::open_retained_pinned_with_limits(root, margin, genesis, parameters, pin, limits)
                .unwrap();
        assert_eq!(node.history_limits(), limits);
        assert_eq!(
            node.history_capacity().unwrap().vertices_remaining,
            8192 - node.vertex_count()
        );
        node
    } else {
        Node::open_retained_pinned(root, margin, genesis, parameters, pin).unwrap()
    }
}

fn reconcile(node: &mut Node) {
    for _ in 0..8 {
        if node.status().unwrap() == Status::Ready {
            return;
        }
        if std::env::var("SILK_F04_RETAINED_MUTATION_GATE").as_deref() == Ok("1") {
            let step = node
                .core
                .prepare_step(&JobBudget::checkpoint().unwrap())
                .unwrap();
            if step.rollback && step.state.checkpoint_index() > 0 {
                assert_eq!(step.state.retained_payload_layout(), [true; 6]);
                assert_eq!(step.state.staged_payload_counts(), [0; 6]);
                RETAINED_ROLLBACKS.fetch_add(1, Ordering::SeqCst);
            }
        }
        node.advance().unwrap();
    }
    panic!("bounded fork reconciliation did not finish");
}

fn mine_external(
    node: &mut Node,
    root: &Path,
    parents: Sg0ParentSetV1,
    tag: u8,
    work: &mut crate::carriage::WorkEngine,
) -> Candidate {
    let head = node.local_head().unwrap();
    let count = node.vertex_count();
    let state = node.core.state.manifest();
    let template = node
        .prepare_mining_current(
            Body::new(&node.genesis().domain(), &[]).unwrap(),
            [tag; 32],
            [80 + tag; 32],
            Some(parents),
        )
        .unwrap();
    assert!(!root.join("ACTIVE_JOB").exists());
    assert_eq!(node.local_head().unwrap(), head);
    assert_eq!(node.vertex_count(), count);
    assert_eq!(node.core.state.manifest(), state);
    let started = std::time::Instant::now();
    for nonce in 0..64 {
        let candidate = work.evaluate_nonce(&template, nonce).unwrap();
        println!(
            "external_tag={tag}; evaluated_nonce={nonce}; search_seconds={}",
            started.elapsed().as_secs_f64()
        );
        assert!(!root.join("ACTIVE_JOB").exists());
        assert_eq!(node.local_head().unwrap(), head);
        assert_eq!(node.vertex_count(), count);
        if let Some(candidate) = candidate {
            return candidate;
        }
    }
    panic!("bounded external nonce range exhausted; no retry");
}

#[test]
#[ignore = "isolated original copy only; profiles parent preparation and verifies one existing work record, mines nothing"]
fn parent_preparation_and_existing_work_profile() {
    assert_eq!(std::env::var("SILK_F04_ISOLATED_LAB").as_deref(), Ok("1"));
    let root = PathBuf::from(std::env::var_os("SILK_F04_FORK_FIXTURE_PARENT").unwrap()).join("a");
    let margin = PathBuf::from(std::env::var_os("SILK_F04_HOST_MARGIN").unwrap());
    let parameter_dir = PathBuf::from(std::env::var_os("SILK_F04_PARAMETER_DIR").unwrap());
    let pin = fixture_digest("SILK_F04_ANCESTRY_NATIVE_PIN");
    let domain = fixture_digest("SILK_F04_NONEMPTY_DOMAIN");
    let source = fixture_digest("SILK_F04_NONEMPTY_GENESIS_HASH");
    let bytes = fs::read(root.join(format!("{}.obj", hex::encode(source)))).unwrap();
    assert_eq!(raw_hash(&bytes), source);
    let genesis = Genesis::admit_local_bundle(&bytes, &domain, true).unwrap();
    let parameters = SaplingParameters::load(
        &parameter_dir.join("sapling-spend.params"),
        &parameter_dir.join("sapling-output.params"),
    )
    .unwrap();
    let node =
        Node::open_retained_pinned(&root, &margin, genesis.clone(), &parameters, pin).unwrap();
    let order = node
        .core
        .order
        .eligible(&JobBudget::checkpoint().unwrap())
        .unwrap();
    let parents = Sg0ParentSetV1::vertices(vec![order[14]]).unwrap();
    let started = std::time::Instant::now();
    let facts = crate::parent::PrefixCache::new(&genesis)
        .unwrap()
        .derive(
            &node.core.graph,
            &parents,
            &genesis,
            &JobBudget::vertex().unwrap(),
        )
        .unwrap();
    println!(
        "parent_preparation_seconds={}; required_work={}",
        started.elapsed().as_secs_f64(),
        facts.work
    );
    let loaded = node
        .core
        .graph
        .load_for_execution(order[15], &genesis, &JobBudget::checkpoint().unwrap())
        .unwrap();
    let mut work = crate::carriage::WorkEngine::default();
    for phase in ["cold", "warm"] {
        let started = std::time::Instant::now();
        work.verify(loaded.candidate(), &facts, &genesis).unwrap();
        println!(
            "existing_work_verification_{phase}_seconds={}",
            started.elapsed().as_secs_f64()
        );
    }
    println!("new_vertices=0; new_proofs=0; original_work_reverified=true");
}

#[test]
#[ignore = "new retained mutation/rollback gate; authenticated saved public fork carriers only, no mining/proof generation"]
fn retained_payment_mutation_and_real_fork_rollback_saved_carriers() {
    assert_eq!(
        std::env::var("SILK_F04_RETAINED_MUTATION_GATE").as_deref(),
        Ok("1")
    );
    assert_eq!(
        std::env::var("SILK_F04_REUSE_SAVED_SIBLING").as_deref(),
        Ok("1")
    );
    assert_eq!(
        std::env::var("SILK_F04_REUSE_SAVED_MERGE").as_deref(),
        Ok("1")
    );
    RETAINED_ROLLBACKS.store(0, Ordering::SeqCst);
    genuine_fork_merge_reorganises_checkpoint_and_reopens_identically();
    assert!(RETAINED_ROLLBACKS.load(Ordering::SeqCst) > 0);
    println!(
        "retained_payment_mutation=true; retained_real_fork_rollback=true; rollback_original_payloads_materialized=false; authenticated_existing_carriers_only=true; newly_mined=0; newly_generated_proofs=0; two_receivers_same_host=true; same_process_cold_reopen=true; separate_process_cold_success=false"
    );
}

#[test]
#[ignore = "explicit larger local profile over only authenticated existing SMALL history; no beyond4096 native claim or mining"]
fn explicit_profile_create_replay_payment_fork_and_repeat_saved_carriers() {
    assert_eq!(
        std::env::var("SILK_F04_EXTENDED_PROFILE_GATE").as_deref(),
        Ok("1")
    );
    retained_payment_mutation_and_real_fork_rollback_saved_carriers();
    println!(
        "selected_local_vertex_limit=8192; native_history_above4096=false; default_unchanged=true; source_profile_imported=false; newly_mined=0; newly_generated_proofs=0"
    );
}

#[test]
#[ignore = "isolated authenticated 16/15-vertex copies; two new empty-body vertices, externally enforced remaining original 120s/3GB bound"]
fn genuine_fork_merge_reorganises_checkpoint_and_reopens_identically() {
    assert_eq!(std::env::var("SILK_F04_ISOLATED_LAB").as_deref(), Ok("1"));
    let root = PathBuf::from(std::env::var_os("SILK_F04_FORK_FIXTURE_PARENT").unwrap());
    let margin = PathBuf::from(std::env::var_os("SILK_F04_HOST_MARGIN").unwrap());
    let parameter_dir = PathBuf::from(std::env::var_os("SILK_F04_PARAMETER_DIR").unwrap());
    let pin = fixture_digest("SILK_F04_ANCESTRY_NATIVE_PIN");
    let b_pin = fixture_digest("SILK_F04_FORK_B_PIN");
    let old_checkpoint = fixture_digest("SILK_F04_NONEMPTY_CHECKPOINT");
    let domain = fixture_digest("SILK_F04_NONEMPTY_DOMAIN");
    let genesis_source = fixture_digest("SILK_F04_NONEMPTY_GENESIS_HASH");
    let genesis_bytes = fs::read(
        root.join("a")
            .join(format!("{}.obj", hex::encode(genesis_source))),
    )
    .unwrap();
    assert_eq!(raw_hash(&genesis_bytes), genesis_source);
    // An independently pinned historical, valueless test-role premise only.
    let genesis = Genesis::admit_local_bundle(&genesis_bytes, &domain, true).unwrap();
    let parameters = SaplingParameters::load(
        &parameter_dir.join("sapling-spend.params"),
        &parameter_dir.join("sapling-output.params"),
    )
    .unwrap();
    let a_root = root.join("a");
    let b_root = root.join("b");
    if std::env::var("SILK_F04_EXTENDED_PROFILE_GATE").as_deref() == Ok("1") {
        let limits = crate::capacity::HistoryLimitsV1::for_vertices(8192).unwrap();
        let empty_root = root.join("profile-create");
        let empty =
            Node::create_with_limits(&empty_root, &margin, genesis.clone(), limits).unwrap();
        assert_eq!(empty.history_limits(), limits);
        assert_eq!(
            empty.core.state.manifest(),
            BranchState::genesis(&genesis).unwrap().manifest()
        );
        let empty_pin = empty.local_head().unwrap();
        drop(empty);
        assert_eq!(
            fixture_open(
                &empty_root,
                &margin,
                genesis.clone(),
                &parameters,
                empty_pin
            )
            .vertex_count(),
            0
        );
    }
    if std::env::var("SILK_F04_EXTENDED_PROFILE_GATE").as_deref() == Ok("1") {
        let too_small = crate::capacity::HistoryLimitsV1::for_vertices(8).unwrap();
        let head = fs::read(a_root.join("HEAD")).unwrap();
        assert!(matches!(
            Node::open_retained_pinned_with_limits(
                &a_root,
                &margin,
                genesis.clone(),
                &parameters,
                pin,
                too_small
            ),
            Err(Error::Unavailable("retained local resource profile"))
        ));
        assert_eq!(fs::read(a_root.join("HEAD")).unwrap(), head);
        assert!(!a_root.join("ACTIVE_JOB").exists());
        assert!(!a_root.join("ACTIVE_REPLAY").exists());
    }
    let mut a = fixture_open(&a_root, &margin, genesis.clone(), &parameters, pin);
    let mut b = fixture_open(&b_root, &margin, genesis.clone(), &parameters, b_pin);
    let original = a
        .core
        .order
        .eligible(&JobBudget::checkpoint().unwrap())
        .unwrap();
    assert_eq!(original.len(), 16);
    assert_eq!(a.core.state.checkpoint_id(), old_checkpoint);
    assert_eq!(b.vertex_count(), 15);
    assert_eq!(b.core.state.checkpoint_index(), 1);
    if std::env::var("SILK_F04_RETAINED_MUTATION_GATE").as_deref() == Ok("1") {
        let prior = a
            .core
            .retained_history_for_test()
            .find(|state| state.checkpoint_index() == 1)
            .unwrap()
            .clone();
        let bodies = original[8..16]
            .iter()
            .map(|id| {
                a.core
                    .graph
                    .load_for_execution(*id, &genesis, &JobBudget::checkpoint().unwrap())
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let batch = bodies
            .iter()
            .map(Arc::as_ref)
            .collect::<Vec<_>>()
            .try_into()
            .ok()
            .unwrap();
        let scratch = prior
            .execute(batch, &JobBudget::checkpoint().unwrap())
            .unwrap();
        let accepted = scratch
            .outcomes
            .iter()
            .filter(|outcome| **outcome == crate::state::EffectOutcome::Accepted)
            .count();
        assert_eq!(scratch.state.manifest(), a.core.state.manifest());
        assert_eq!(scratch.state.retained_payload_layout(), [true; 6]);
        assert_eq!(
            &scratch.state.staged_payload_counts()[2..],
            &[accepted * 2, accepted, 8, 8]
        );
        prior
            .qualify_ledger_checked(&JobBudget::checkpoint().unwrap())
            .unwrap();
    }
    let second = Candidate::decode(&a.export_range(15, 1).unwrap()[0], &genesis).unwrap();
    assert_eq!(VertexId::from_bytes(second.id), original[15]);
    let parents = Sg0ParentSetV1::vertices(vec![original[14]]).unwrap();
    assert_eq!(second.header.parents, parents);
    println!("phase=external-mine-first-or-reuse; payment_proofs_generated=0");
    let mut work = crate::carriage::WorkEngine::default();
    let first = if std::env::var("SILK_F04_REUSE_SAVED_SIBLING").as_deref() == Ok("1") {
        // Only public full carrier bytes from preserved evidence, never a failed
        // node owner or a validity cache. Both ordinary receivers verify anew.
        let bytes = fs::read(root.join("first.vertex")).unwrap();
        assert_eq!(
            raw_hash(&bytes),
            fixture_digest("SILK_F04_SAVED_SIBLING_HASH")
        );
        let candidate = Candidate::decode(&bytes, &genesis).unwrap();
        assert_eq!(candidate.header.parents, parents);
        assert!(candidate.body.representations().is_empty());
        candidate
    } else {
        let candidate = mine_external(&mut a, &a_root, parents, 1, &mut work);
        fs::write(root.join("first.vertex"), candidate.encode()).unwrap();
        candidate
    };
    fs::write(root.join("second.vertex"), second.encode()).unwrap();
    assert_ne!(first.id, second.id);
    let a_head = a.local_head().unwrap();
    let mut forged = first.encode();
    forged[56 + 448..56 + 456].copy_from_slice(&(first.header.work + 1).to_be_bytes());
    assert!(matches!(
        a.ingest(&forged, &parameters),
        Err(Error::Invalid(_))
    ));
    let mut forged = first.encode();
    *forged.last_mut().unwrap() ^= 1;
    assert!(matches!(
        a.ingest(&forged, &parameters),
        Err(Error::Invalid(_))
    ));
    assert_eq!(a.local_head().unwrap(), a_head);
    assert_eq!(a.vertex_count(), 16);
    assert!(!a_root.join("ACTIVE_JOB").exists());
    // A already received the old sibling. B first executes the new sibling.
    assert_eq!(
        b.ingest(&first.encode(), &parameters).unwrap(),
        Ingress::Admitted
    );
    reconcile(&mut b);
    let b_fork_checkpoint = b.core.state.checkpoint_id();
    assert_ne!(b_fork_checkpoint, old_checkpoint);
    assert_eq!(
        a.ingest(&first.encode(), &parameters).unwrap(),
        Ingress::Admitted
    );
    reconcile(&mut a);
    assert_eq!(
        b.ingest(&second.encode(), &parameters).unwrap(),
        Ingress::Admitted
    );
    reconcile(&mut b);
    assert_eq!(a.vertex_count(), 17);
    assert_eq!(b.vertex_count(), 17);
    assert_eq!(a.core.state.manifest(), b.core.state.manifest());
    assert!(
        a.core.state.checkpoint_id() != old_checkpoint
            || b.core.state.checkpoint_id() != b_fork_checkpoint
    );
    let mut merge_ids = vec![
        VertexId::from_bytes(first.id),
        VertexId::from_bytes(second.id),
    ];
    merge_ids.sort_unstable();
    let merge_parents = Sg0ParentSetV1::vertices(merge_ids).unwrap();
    println!("phase=external-mine-merge; new_vertices=1");
    let merge = if std::env::var("SILK_F04_REUSE_SAVED_MERGE").as_deref() == Ok("1") {
        let bytes = fs::read(root.join("merge.vertex")).unwrap();
        assert_eq!(
            raw_hash(&bytes),
            fixture_digest("SILK_F04_SAVED_MERGE_HASH")
        );
        let candidate = Candidate::decode(&bytes, &genesis).unwrap();
        assert_eq!(candidate.header.parents, merge_parents);
        assert!(candidate.body.representations().is_empty());
        candidate
    } else {
        let candidate = mine_external(&mut a, &a_root, merge_parents, 3, &mut work);
        fs::write(root.join("merge.vertex"), candidate.encode()).unwrap();
        candidate
    };
    println!("phase=receive-merge; new_vertices=2");
    assert_eq!(merge.header.parents.ordinary_parents().len(), 2);
    for node in [&mut a, &mut b] {
        assert_eq!(
            node.ingest(&merge.encode(), &parameters).unwrap(),
            Ingress::Admitted
        );
        reconcile(node);
        assert_eq!(node.vertex_count(), 18);
        assert_eq!(node.core.state.checkpoint_index(), 2);
        assert_eq!(&node.state().unwrap().executed()[..15], &original[..15]);
    }
    let a_order = a
        .core
        .graph
        .order(&JobBudget::checkpoint().unwrap())
        .unwrap();
    let b_order = b
        .core
        .graph
        .order(&JobBudget::checkpoint().unwrap())
        .unwrap();
    assert_eq!(a_order, b_order);
    assert_eq!(a_order.selected_tip(), Some(VertexId::from_bytes(merge.id)));
    let expected_order = a
        .core
        .order
        .bytes(&JobBudget::checkpoint().unwrap())
        .unwrap();
    assert_eq!(
        expected_order,
        b.core
            .order
            .bytes(&JobBudget::checkpoint().unwrap())
            .unwrap()
    );
    let expected_state = a.core.state.manifest();
    assert_eq!(expected_state, b.core.state.manifest());
    // Independent execution from genesis, not either receiver's saved checkpoint.
    let mut reference = BranchState::genesis(&genesis).unwrap();
    for interval in a_order.eligible_order()[..16].chunks_exact(8) {
        let bodies: Vec<_> = interval
            .iter()
            .map(|id| {
                a.core
                    .graph
                    .load_for_execution(*id, &genesis, &JobBudget::checkpoint().unwrap())
                    .unwrap()
            })
            .collect();
        let batch: [&crate::graph::VerifiedVertex; 8] = bodies
            .iter()
            .map(Arc::as_ref)
            .collect::<Vec<_>>()
            .try_into()
            .ok()
            .unwrap();
        reference = reference
            .execute(batch, &JobBudget::checkpoint().unwrap())
            .unwrap()
            .state;
    }
    assert_eq!(reference.manifest(), expected_state);
    let a_export = a.export_range(0, 32).unwrap();
    let b_export = b.export_range(0, 32).unwrap();
    // Admission ordinals differ by design; compare exact full carriers by ID.
    let mut a_export: Vec<_> = a_export
        .into_iter()
        .map(|bytes| (Candidate::decode(&bytes, &genesis).unwrap().id, bytes))
        .collect();
    let mut b_export: Vec<_> = b_export
        .into_iter()
        .map(|bytes| (Candidate::decode(&bytes, &genesis).unwrap().id, bytes))
        .collect();
    a_export.sort();
    b_export.sort();
    assert_eq!(a_export, b_export);
    let a_head = a.local_head().unwrap();
    let b_head = b.local_head().unwrap();
    fs::write(root.join("expected.state"), &expected_state).unwrap();
    fs::write(root.join("expected.order"), &expected_order).unwrap();
    fs::write(root.join("a.pin"), hex::encode(a_head)).unwrap();
    fs::write(root.join("b.pin"), hex::encode(b_head)).unwrap();
    drop(a);
    drop(b);
    println!("phase=cold-reopen; new_vertices=2");
    for (path, head) in [(&a_root, a_head), (&b_root, b_head)] {
        let mut node = fixture_open(path, &margin, genesis.clone(), &parameters, head);
        assert_eq!(node.status().unwrap(), Status::Ready);
        assert_eq!(node.core.state.manifest(), expected_state);
        assert_eq!(
            node.core
                .order
                .bytes(&JobBudget::checkpoint().unwrap())
                .unwrap(),
            expected_order
        );
        assert_eq!(
            node.core
                .graph
                .order(&JobBudget::checkpoint().unwrap())
                .unwrap(),
            a_order
        );
        for candidate in [&first, &second, &merge] {
            assert_eq!(
                node.ingest(&candidate.encode(), &parameters).unwrap(),
                Ingress::AlreadyKnown
            );
            assert_eq!(node.local_head().unwrap(), head);
            assert_eq!(node.core.state.manifest(), expected_state);
        }
    }
    println!(
        "genuine_siblings=2; genuine_two_parent_merge=true; opposite_ingress_order=true; executed_checkpoint_reorganised=true; cold_replay_parity=true; exact_repeat_no_new_credit=true; new_vertices=2; payment_proofs_generated=0; valuable_assets=false"
    );
}

#[test]
#[ignore = "second process only after successful genuine fork fixture; no mining"]
fn genuine_fork_second_process_cold_parity() {
    assert_eq!(std::env::var("SILK_F04_ISOLATED_LAB").as_deref(), Ok("1"));
    let root = PathBuf::from(std::env::var_os("SILK_F04_FORK_FIXTURE_PARENT").unwrap());
    let margin = PathBuf::from(std::env::var_os("SILK_F04_HOST_MARGIN").unwrap());
    let parameter_dir = PathBuf::from(std::env::var_os("SILK_F04_PARAMETER_DIR").unwrap());
    let domain = fixture_digest("SILK_F04_NONEMPTY_DOMAIN");
    let source = fixture_digest("SILK_F04_NONEMPTY_GENESIS_HASH");
    let bytes = fs::read(root.join("a").join(format!("{}.obj", hex::encode(source)))).unwrap();
    assert_eq!(raw_hash(&bytes), source);
    let genesis = Genesis::admit_local_bundle(&bytes, &domain, true).unwrap();
    let parameters = SaplingParameters::load(
        &parameter_dir.join("sapling-spend.params"),
        &parameter_dir.join("sapling-output.params"),
    )
    .unwrap();
    for owner in ["a", "b"] {
        let head = hex::decode(fs::read(root.join(format!("{owner}.pin"))).unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let mut node = Node::open_retained_pinned(
            &root.join(owner),
            &margin,
            genesis.clone(),
            &parameters,
            head,
        )
        .unwrap();
        assert_eq!(node.vertex_count(), 18);
        assert_eq!(node.status().unwrap(), Status::Ready);
        assert_eq!(
            node.core.state.manifest(),
            fs::read(root.join("expected.state")).unwrap()
        );
        assert_eq!(
            node.core
                .order
                .bytes(&JobBudget::checkpoint().unwrap())
                .unwrap(),
            fs::read(root.join("expected.order")).unwrap()
        );
        for name in ["first.vertex", "second.vertex", "merge.vertex"] {
            assert_eq!(
                node.ingest(&fs::read(root.join(name)).unwrap(), &parameters)
                    .unwrap(),
                Ingress::AlreadyKnown
            );
            assert_eq!(node.local_head().unwrap(), head);
        }
    }
    println!("fresh_process_cold_parity=true; new_vertices=0; payment_proofs_generated=0");
}
