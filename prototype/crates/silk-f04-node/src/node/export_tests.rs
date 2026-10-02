//! Original durable source export after full fresh replay, on an isolated COPY.
use super::*;
use std::{collections::BTreeMap, fs, path::PathBuf};

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
