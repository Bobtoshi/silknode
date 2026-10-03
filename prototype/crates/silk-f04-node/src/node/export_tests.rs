//! Original durable source export after full fresh replay, on an isolated COPY.
use super::*;
use std::{collections::BTreeMap, fs, path::PathBuf};

#[test]
#[ignore = "requires isolated COPY of the authenticated sixteen-vertex nonempty lineage and canonical parameters"]
fn disk_detach_nonempty_native_replay_execution_and_refusal_preserve_original_state() {
    assert_eq!(std::env::var("SILK_F04_ISOLATED_LAB").as_deref(), Ok("1"));
    let root = PathBuf::from(std::env::var_os("SILK_F04_SOURCE_NATIVE_STORE").unwrap());
    let margin = PathBuf::from(std::env::var_os("SILK_F04_HOST_MARGIN").unwrap());
    let parameter_dir = PathBuf::from(std::env::var_os("SILK_F04_PARAMETER_DIR").unwrap());
    let pin: Digest = hex::decode(std::env::var("SILK_F04_ANCESTRY_NATIVE_PIN").unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let checkpoint: Digest = hex::decode(std::env::var("SILK_F04_NONEMPTY_CHECKPOINT").unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let domain: Digest = hex::decode(std::env::var("SILK_F04_NONEMPTY_DOMAIN").unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let genesis_source: Digest =
        hex::decode(std::env::var("SILK_F04_NONEMPTY_GENESIS_HASH").unwrap())
            .unwrap()
            .try_into()
            .unwrap();
    let genesis_bytes =
        fs::read(root.join(format!("{}.obj", hex::encode(genesis_source)))).unwrap();
    assert_eq!(raw_hash(&genesis_bytes), genesis_source);
    // Explicitly accepted valueless historical test-role premise ONLY. This
    // independently supplied fixture pin does not alter any node default or
    // allow a received bundle to select its own genesis domain.
    let genesis = Genesis::admit_local_bundle(&genesis_bytes, &domain, true).unwrap();
    let original: BTreeMap<_, _> = fs::read_dir(&root)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            (
                path.file_name().unwrap().to_owned(),
                raw_hash(&fs::read(path).unwrap()),
            )
        })
        .collect();
    let parameters = SaplingParameters::load(
        &parameter_dir.join("sapling-spend.params"),
        &parameter_dir.join("sapling-output.params"),
    )
    .unwrap();
    let mut node = Node::open_retained_pinned(&root, &margin, genesis, &parameters, pin).unwrap();
    assert_eq!(node.core.graph.len(), 16);
    assert_eq!(node.core.status, Status::Ready);
    assert_eq!(node.core.state.checkpoint_index(), 2);
    assert_eq!(node.core.state.checkpoint_id(), checkpoint);
    assert_eq!(node.core.state.private_counters(), (58, 2));
    assert_eq!(node.core.state.leaves(), 7);
    let index_pages = node.core.graph.retained_index_pages();
    assert_eq!(index_pages.len(), 1);
    let completed = node.core.state.clone();
    assert_eq!(completed.retained_recovery_pages().len(), 1);
    assert!(
        completed
            .retained_set_pages()
            .iter()
            .all(|pages| pages.len() == 1)
    );
    assert!(node.state_view.get().is_none());
    assert!(
        completed
            .retained_history_pages()
            .iter()
            .all(|pages| pages.len() == 1)
    );
    let snapshot = node.state().unwrap().clone();
    assert!(snapshot.retained_recovery_pages().is_empty());
    assert!(snapshot.retained_set_pages().iter().all(Vec::is_empty));
    assert!(snapshot.retained_history_pages().iter().all(Vec::is_empty));
    assert_eq!(snapshot.accepted_outputs().len(), 2);
    assert_eq!(snapshot.executed().len(), 16);
    assert_eq!(snapshot.economic_ledger().reward_records.len(), 16);
    assert_eq!(snapshot.recovery().len(), 7);
    assert_eq!(snapshot.manifest(), completed.manifest());
    // Public snapshots remain resident and safely cloneable. Clearing this
    // test-only view simulates a first snapshot request, which must report I/O
    // rather than mint a fallback. Existing immutable snapshots remain valid.
    let recovery_path = root.join(format!(
        "{}.obj",
        hex::encode(completed.retained_recovery_pages()[0])
    ));
    let recovery_held = recovery_path.with_extension("held");
    fs::rename(&recovery_path, &recovery_held).unwrap();
    node.state_view.take();
    assert!(matches!(node.state(), Err(Error::Io(_))));
    assert!(node.state_view.get().is_none());
    assert_eq!(snapshot.recovery().len(), 7);
    assert_eq!(node.core.state.manifest(), completed.manifest());
    assert_eq!(node.local_head().unwrap(), pin);
    fs::rename(&recovery_held, &recovery_path).unwrap();
    for id in completed
        .retained_set_pages()
        .into_iter()
        .flatten()
        .chain(completed.retained_history_pages().into_iter().flatten())
    {
        let path = root.join(format!("{}.obj", hex::encode(id)));
        let held = path.with_extension("held");
        fs::rename(&path, &held).unwrap();
        node.state_view.take();
        assert!(matches!(node.state(), Err(Error::Io(_))));
        assert!(node.state_view.get().is_none());
        if id == completed.retained_history_pages()[2][0] {
            assert!(matches!(
                node.core
                    .reconciliation_generations(&JobBudget::checkpoint().unwrap()),
                Err(Error::Io(_))
            ));
        }
        assert_eq!(node.core.state.manifest(), completed.manifest());
        assert_eq!(node.local_head().unwrap(), pin);
        fs::rename(&held, &path).unwrap();
    }
    let ids = node.core.order.eligible_order().to_vec();
    let prior = node
        .core
        .retained_history_for_test()
        .find(|state| state.checkpoint_index() == 1)
        .unwrap()
        .clone();
    assert_eq!(prior.retained_recovery_pages().len(), 1);
    assert!(
        prior
            .retained_set_pages()
            .iter()
            .all(|pages| pages.len() == 1)
    );
    let second_bodies = ids[8..16]
        .iter()
        .map(|id| {
            node.core
                .graph
                .load_for_execution(*id, &node.core.genesis, &JobBudget::checkpoint().unwrap())
                .unwrap()
        })
        .collect::<Vec<_>>();
    let batch: [&crate::graph::VerifiedVertex; 8] = second_bodies
        .iter()
        .map(Arc::as_ref)
        .collect::<Vec<_>>()
        .try_into()
        .ok()
        .unwrap();
    let replayed = prior
        .execute(batch, &JobBudget::checkpoint().unwrap())
        .unwrap();
    assert_eq!(replayed.state.manifest(), completed.manifest());
    assert!(
        prior
            .retained_history_pages()
            .iter()
            .all(|pages| pages.len() == 1)
    );
    // Scratch rollback uses genuine retained state and receiver parent order;
    // it is not native fork/reorg admission or durable checkpoint publication.
    let complete_order = node.core.order.clone();
    node.core.order = node
        .core
        .graph
        .parent_order(
            &Sg0ParentSetV1::vertices(vec![ids[7]]).unwrap(),
            &JobBudget::checkpoint().unwrap(),
        )
        .unwrap();
    assert_eq!(node.core.order.eligible_order().len(), 8);
    node.core.status = Status::NeedsReconcile;
    let rollback = node
        .core
        .prepare_step(&JobBudget::checkpoint().unwrap())
        .unwrap();
    assert!(rollback.rollback);
    assert_eq!(rollback.state.manifest(), prior.manifest());
    let prior_page = root.join(format!(
        "{}.obj",
        hex::encode(prior.retained_recovery_pages()[0])
    ));
    let prior_held = prior_page.with_extension("held");
    fs::rename(&prior_page, &prior_held).unwrap();
    assert!(matches!(
        prior.execute(batch, &JobBudget::checkpoint().unwrap()),
        Err(Error::Io(_))
    ));
    assert!(matches!(
        node.core.prepare_step(&JobBudget::checkpoint().unwrap()),
        Err(Error::Io(_))
    ));
    assert_eq!(node.core.state.manifest(), completed.manifest());
    assert_eq!(node.local_head().unwrap(), pin);
    fs::rename(&prior_held, &prior_page).unwrap();
    for id in prior.retained_set_pages().into_iter().flatten() {
        let path = root.join(format!("{}.obj", hex::encode(id)));
        let held = path.with_extension("held");
        fs::rename(&path, &held).unwrap();
        assert!(matches!(
            prior.execute(batch, &JobBudget::checkpoint().unwrap()),
            Err(Error::Io(_))
        ));
        assert!(matches!(
            node.core.prepare_step(&JobBudget::checkpoint().unwrap()),
            Err(Error::Io(_))
        ));
        assert!(matches!(
            completed.delta_checked(
                &prior,
                &replayed.outcomes,
                false,
                Some(&JobBudget::checkpoint().unwrap())
            ),
            Err(Error::Io(_))
        ));
        assert_eq!(node.core.state.manifest(), completed.manifest());
        assert_eq!(node.local_head().unwrap(), pin);
        fs::rename(&held, &path).unwrap();
    }
    for (kind, pages) in prior.retained_history_pages().into_iter().enumerate() {
        for id in pages {
            let path = root.join(format!("{}.obj", hex::encode(id)));
            let held = path.with_extension("held");
            fs::rename(&path, &held).unwrap();
            assert!(matches!(
                prior.execute(batch, &JobBudget::checkpoint().unwrap()),
                Err(Error::Io(_))
            ));
            assert!(matches!(
                node.core.prepare_step(&JobBudget::checkpoint().unwrap()),
                Err(Error::Io(_))
            ));
            if kind == 2 {
                assert!(matches!(
                    completed.delta_checked(
                        &prior,
                        &replayed.outcomes,
                        false,
                        Some(&JobBudget::checkpoint().unwrap())
                    ),
                    Err(Error::Io(_))
                ));
            }
            assert_eq!(node.core.state.manifest(), completed.manifest());
            assert_eq!(node.local_head().unwrap(), pin);
            fs::rename(&held, &path).unwrap();
        }
    }
    node.core.order = complete_order;
    node.core.status = Status::Ready;
    let exports = node.export_range(0, 32).unwrap();
    assert_eq!(exports.len(), 16);
    let mut representations = 0;
    let mut accepted_effects = std::collections::BTreeSet::new();
    let mut first_nonempty = None;
    for (position, id) in ids.iter().enumerate() {
        let loaded = node
            .core
            .graph
            .load_for_execution(*id, &node.core.genesis, &JobBudget::checkpoint().unwrap())
            .unwrap();
        let retained = node.core.graph.get(*id).unwrap();
        let header = node
            .core
            .graph
            .header(*id, &node.core.genesis, &JobBudget::checkpoint().unwrap())
            .unwrap();
        assert_eq!(header.bytes, loaded.candidate().header.bytes);
        assert!(!std::ptr::eq(header.as_ref(), &loaded.candidate().header));
        let source = retained.source_id().unwrap();
        assert_eq!(
            loaded.retained_record().unwrap(),
            fs::read(root.join(format!("{}.obj", hex::encode(source)))).unwrap()
        );
        assert!(!std::ptr::eq(
            crate::graph::GraphEntry::graph_info(loaded.as_ref()),
            crate::graph::GraphEntry::graph_info(retained),
        ));
        assert_eq!(
            loaded.envelopes().len(),
            loaded.candidate().body.representations().len()
        );
        for (verified, original_bytes) in loaded
            .envelopes()
            .iter()
            .zip(loaded.candidate().body.representations())
        {
            let envelope = verified.envelope();
            let effect = envelope.effect_id();
            if snapshot.contains_effect(&effect) {
                accepted_effects.insert(effect);
                for nf in envelope.nullifiers() {
                    assert!(snapshot.contains_nullifier(&nf));
                }
            }
            assert_eq!(
                verified.envelope().bytes().as_slice(),
                original_bytes.as_slice()
            );
        }
        representations += loaded.envelopes().len();
        if !loaded.envelopes().is_empty() {
            first_nonempty.get_or_insert((position, source, loaded.candidate().encode()));
        }
        // No full loaded carrier survives this iteration in the retained graph.
    }
    assert!(representations >= 3);
    assert_eq!(accepted_effects.len(), 2);
    let (position, source, repeated) = first_nonempty.unwrap();
    assert!(
        position < 8,
        "fixture must contain a nonempty first checkpoint carrier"
    );
    assert_eq!(
        node.ingest(&repeated, &parameters).unwrap(),
        Ingress::AlreadyKnown
    );
    assert_eq!(node.local_head().unwrap(), pin);
    assert_eq!(node.core.state.manifest(), completed.manifest());
    // Exercise both real scratch reducers, not a new durable checkpoint/reorg.
    node.core.state = Arc::new(BranchState::genesis(&node.core.genesis).unwrap());
    node.core.status = Status::NeedsReconcile;
    let first = node
        .core
        .prepare_step(&JobBudget::checkpoint().unwrap())
        .unwrap();
    assert_eq!(first.state.checkpoint_index(), 1);
    node.core.publish_step(first).unwrap();
    let second = node
        .core
        .prepare_step(&JobBudget::checkpoint().unwrap())
        .unwrap();
    assert_eq!(second.state.manifest(), completed.manifest());
    assert_eq!(
        second.state.checkpoint_bytes(),
        completed.checkpoint_bytes()
    );
    let parent = crate::parent::replay_source_for_test(
        &node.core.graph,
        &node.core.genesis,
        &ids,
        &JobBudget::checkpoint().unwrap(),
    )
    .unwrap();
    assert_eq!(parent.manifest(), completed.manifest());
    assert_eq!(parent.accepted_outputs(), snapshot.accepted_outputs());
    assert_eq!(
        parent.economic_ledger().reward_records,
        snapshot.economic_ledger().reward_records
    );
    assert_eq!(parent.executed(), snapshot.executed());
    assert_eq!(parent.checkpoint_bytes(), completed.checkpoint_bytes());
    node.core.state = Arc::new(BranchState::genesis(&node.core.genesis).unwrap());
    node.core.status = Status::NeedsReconcile;
    let scratch_manifest = node.core.state.manifest();
    let path = root.join(format!("{}.obj", hex::encode(source)));
    let held = path.with_extension("held");
    fs::rename(&path, &held).unwrap();
    assert!(matches!(node.begin_ingest(&repeated), Err(Error::Io(_))));
    assert!(matches!(
        node.core.graph.header(
            ids[position],
            &node.core.genesis,
            &JobBudget::checkpoint().unwrap()
        ),
        Err(Error::Io(_))
    ));
    assert!(node.export_range(0, 16).is_err());
    assert!(
        node.core
            .prepare_step(&JobBudget::checkpoint().unwrap())
            .is_err()
    );
    assert!(
        crate::parent::replay_source_for_test(
            &node.core.graph,
            &node.core.genesis,
            &ids,
            &JobBudget::checkpoint().unwrap(),
        )
        .is_err()
    );
    assert_eq!(node.core.state.manifest(), scratch_manifest);
    assert_eq!(node.core.graph.len(), 16);
    assert_eq!(node.core.status, Status::NeedsReconcile);
    assert_eq!(node.local_head().unwrap(), pin);
    fs::rename(&held, &path).unwrap();
    assert_eq!(node.export_range(0, 32).unwrap(), exports);
    let accepted_genesis = node.core.genesis.as_ref().clone();
    let index_path = root.join(format!("{}.obj", hex::encode(index_pages[0])));
    let index_held = index_path.with_extension("held");
    fs::rename(&index_path, &index_held).unwrap();
    assert!(matches!(
        node.core.graph.get(ids[position]),
        Err(Error::Io(_))
    ));
    assert!(matches!(node.begin_ingest(&repeated), Err(Error::Io(_))));
    assert!(
        node.core
            .graph
            .order(&JobBudget::checkpoint().unwrap())
            .is_err()
    );
    assert!(
        node.core
            .graph
            .header(
                ids[position],
                &node.core.genesis,
                &JobBudget::checkpoint().unwrap()
            )
            .is_err()
    );
    assert!(
        node.core
            .prepare_step(&JobBudget::checkpoint().unwrap())
            .is_err()
    );
    assert_eq!(node.core.graph.len(), 16);
    assert_eq!(node.core.state.manifest(), scratch_manifest);
    assert_eq!(node.local_head().unwrap(), pin);
    fs::rename(&index_held, &index_path).unwrap();
    drop(node);
    // A damaged auxiliary page is NOT damaged original HEAD lineage. A fresh
    // reopen must stop, never fall back to PREVIOUS and expose an older ledger.
    let set_path = root.join(format!("{}.obj", hex::encode(index_pages[0])));
    let set_bytes = fs::read(&set_path).unwrap();
    let mut damaged = set_bytes.clone();
    *damaged.last_mut().unwrap() ^= 1;
    fs::write(&set_path, damaged).unwrap();
    assert!(matches!(
        Node::open_retained_pinned(&root, &margin, accepted_genesis, &parameters, pin),
        Err(Error::Unavailable("retained vertex index page damaged"))
    ));
    assert_eq!(
        fs::read(root.join("HEAD")).unwrap(),
        hex::encode(pin).as_bytes()
    );
    assert!(root.join("ACTIVE_REPLAY").exists());
    fs::write(&set_path, set_bytes).unwrap();
    for (name, hash) in original {
        assert_eq!(raw_hash(&fs::read(root.join(name)).unwrap()), hash);
    }
    println!(
        "retained_vertices=16; fresh_full_replay=true; nonempty_representations={representations}; graph_entries_compact=true; full_graph_headers_disk_backed=true; owned_original_header_reads_exact=true; vertex_index_disk_backed=true; missing_index_refuses_get_repeat_order_header_and_execution=true; damaged_index_cold_replay_stops_without_previous_fallback=true; recovery_history_disk_backed=true; nullifier_and_effect_sets_disk_backed=true; executed_reward_output_link_histories_disk_backed=true; public_snapshot_resident=true; missing_ledger_pages_refuse_first_snapshot_execution_and_scratch_rollback=true; missing_executed_page_refuses_prefix_and_forward_delta=true; exact_owned_crypto_bodies=true; original_two_checkpoint_economic_state=true; checkpoint_and_parent_scratch_exact=true; missing_nonempty_source_refuses_header_and_reducers_without_publication=true; source_bytes_unchanged=true; native_reorg=false; mined=0; new_proofs=0"
    );
}

#[test]
#[ignore = "requires isolated COPY of a genuine eight-vertex corpus and canonical parameters"]
fn disk_source_native_fresh_replay_exports_exact_originals_and_missing_last_refuses() {
    assert_eq!(std::env::var("SILK_F04_ISOLATED_LAB").as_deref(), Ok("1"));
    let root = PathBuf::from(std::env::var_os("SILK_F04_SOURCE_NATIVE_STORE").unwrap());
    let margin = PathBuf::from(std::env::var_os("SILK_F04_HOST_MARGIN").unwrap());
    let parameter_dir = PathBuf::from(std::env::var_os("SILK_F04_PARAMETER_DIR").unwrap());
    let pin: Digest = hex::decode(std::env::var("SILK_F04_ANCESTRY_NATIVE_PIN").unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let original: BTreeMap<_, _> = fs::read_dir(&root)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            (
                path.file_name().unwrap().to_owned(),
                raw_hash(&fs::read(path).unwrap()),
            )
        })
        .collect();
    let parameters = SaplingParameters::load(
        &parameter_dir.join("sapling-spend.params"),
        &parameter_dir.join("sapling-output.params"),
    )
    .unwrap();
    let node = Node::open_retained_pinned(
        &root,
        &margin,
        crate::genesis::public_testnet_v1::genesis().unwrap(),
        &parameters,
        pin,
    )
    .unwrap();
    assert_eq!(node.core.graph.len(), 8);
    assert_eq!(node.core.status, Status::Ready);
    let expected: Vec<_> = node
        .core
        .graph
        .vertices()
        .map(|v| {
            node.core
                .graph
                .load_for_execution(
                    VertexId::from_bytes(v.id()),
                    &node.core.genesis,
                    &JobBudget::checkpoint().unwrap(),
                )
                .unwrap()
                .candidate()
                .encode()
        })
        .collect();
    assert_eq!(node.export_range(0, 32).unwrap(), expected);
    assert_eq!(node.export_range(3, 2).unwrap(), expected[3..5]);
    assert!(node.export_range(8, 1).unwrap().is_empty());
    // Resolve only the exact already-verified last source in this disposable copy.
    let record = node
        .core
        .graph
        .vertices()
        .last()
        .unwrap()
        .source_id()
        .and_then(|id| fs::read(root.join(format!("{}.obj", hex::encode(id)))).map_err(Error::from))
        .unwrap();
    let path = root.join(format!("{}.obj", hex::encode(raw_hash(&record))));
    let held = path.with_extension("held");
    fs::rename(&path, &held).unwrap();
    assert!(node.export_range(0, 8).is_err());
    assert_eq!(node.local_head().unwrap(), pin);
    assert_eq!(node.core.status, Status::Ready);
    fs::rename(&held, &path).unwrap();
    assert_eq!(node.export_range(0, 8).unwrap(), expected);
    drop(node);
    for (name, hash) in original {
        assert_eq!(raw_hash(&fs::read(root.join(name)).unwrap()), hash);
    }
    println!(
        "retained_vertices=8; full_replay=true; original_export_bytes=true; missing_last_refuses_whole_range=true; resident_fallback=false; source_bytes_unchanged=true; mined=0"
    );
}

#[test]
#[ignore = "requires isolated COPY of a genuine eight-vertex corpus and canonical parameters"]
fn disk_execution_native_checkpoint_and_parent_scratch_refuse_missing_source_without_publication() {
    assert_eq!(std::env::var("SILK_F04_ISOLATED_LAB").as_deref(), Ok("1"));
    let root = PathBuf::from(std::env::var_os("SILK_F04_SOURCE_NATIVE_STORE").unwrap());
    let margin = PathBuf::from(std::env::var_os("SILK_F04_HOST_MARGIN").unwrap());
    let parameter_dir = PathBuf::from(std::env::var_os("SILK_F04_PARAMETER_DIR").unwrap());
    let pin: Digest = hex::decode(std::env::var("SILK_F04_ANCESTRY_NATIVE_PIN").unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let original: BTreeMap<_, _> = fs::read_dir(&root)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            (
                path.file_name().unwrap().to_owned(),
                raw_hash(&fs::read(path).unwrap()),
            )
        })
        .collect();
    let parameters = SaplingParameters::load(
        &parameter_dir.join("sapling-spend.params"),
        &parameter_dir.join("sapling-output.params"),
    )
    .unwrap();
    let mut node = Node::open_retained_pinned(
        &root,
        &margin,
        crate::genesis::public_testnet_v1::genesis().unwrap(),
        &parameters,
        pin,
    )
    .unwrap();
    assert_eq!(node.core.graph.len(), 8);
    let repeated = node.export_range(7, 1).unwrap().pop().unwrap();
    assert_eq!(
        node.ingest(&repeated, &parameters).unwrap(),
        Ingress::AlreadyKnown
    );
    assert_eq!(node.local_head().unwrap(), pin);
    let completed = node.core.state.clone();
    let ids = node.core.order.eligible_order().to_vec();
    for id in &ids {
        let loaded = node
            .core
            .graph
            .load_for_execution(*id, &node.core.genesis, &JobBudget::checkpoint().unwrap())
            .unwrap();
        let resident = node.core.graph.get(*id).unwrap();
        assert!(!std::ptr::eq(
            crate::graph::GraphEntry::graph_info(loaded.as_ref()),
            crate::graph::GraphEntry::graph_info(resident)
        ));
        assert_eq!(
            loaded.retained_record().unwrap(),
            fs::read(root.join(format!(
                "{}.obj",
                hex::encode(resident.source_id().unwrap())
            )))
            .unwrap()
        );
        assert_eq!(
            loaded.envelopes().len(),
            loaded.candidate().body.representations().len()
        );
    }
    // Scratch reconstruction exercises the real reducers over genuine records;
    // it is not a new live transition, native reorg, mined history or cap evidence.
    node.core.state = Arc::new(BranchState::genesis(&node.core.genesis).unwrap());
    node.core.status = Status::NeedsReconcile;
    let scratch_digest = node.core.state.digest();
    let step = node
        .core
        .prepare_step(&JobBudget::checkpoint().unwrap())
        .unwrap();
    assert_eq!(step.state.digest(), completed.digest());
    assert_eq!(step.state.checkpoint_id(), completed.checkpoint_id());
    let parent = crate::parent::replay_source_for_test(
        &node.core.graph,
        &node.core.genesis,
        &ids,
        &JobBudget::checkpoint().unwrap(),
    )
    .unwrap();
    assert_eq!(parent.digest(), completed.digest());
    assert_eq!(parent.checkpoint_id(), completed.checkpoint_id());
    let record = node
        .core
        .graph
        .vertices()
        .last()
        .unwrap()
        .source_id()
        .and_then(|id| fs::read(root.join(format!("{}.obj", hex::encode(id)))).map_err(Error::from))
        .unwrap();
    let path = root.join(format!("{}.obj", hex::encode(raw_hash(&record))));
    let held = path.with_extension("held");
    fs::rename(&path, &held).unwrap();
    assert!(matches!(node.begin_ingest(&repeated), Err(Error::Io(_))));
    assert!(
        node.core
            .prepare_step(&JobBudget::checkpoint().unwrap())
            .is_err()
    );
    assert!(
        crate::parent::replay_source_for_test(
            &node.core.graph,
            &node.core.genesis,
            &ids,
            &JobBudget::checkpoint().unwrap()
        )
        .is_err()
    );
    assert_eq!(node.core.state.digest(), scratch_digest);
    assert_eq!(node.core.graph.len(), 8);
    assert_eq!(node.local_head().unwrap(), pin);
    assert_eq!(node.core.status, Status::NeedsReconcile);
    fs::rename(&held, &path).unwrap();
    drop(node);
    for (name, hash) in original {
        assert_eq!(raw_hash(&fs::read(root.join(name)).unwrap()), hash);
    }
    println!(
        "retained_vertices=8; full_replay=true; graph_entries_compact=true; owned_disk_bodies=true; exact_repeat_already_known=true; missing_source_known_repeat_is_io=true; checkpoint_and_parent_scratch_exact=true; missing_source_refuses_both=true; resident_fallback=false; no_publication=true; native_reorg=false; source_bytes_unchanged=true; mined=0"
    );
}
