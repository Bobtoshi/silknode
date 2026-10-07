//! One affected-path replay of a COPY of a locally authenticated retained corpus.
//! No mining, new proofs, networking, wallet operation or over-limit claim.
use super::*;
use std::{collections::BTreeMap, fs, path::PathBuf};

fn immutable_inputs(root: &Path) -> BTreeMap<String, Digest> {
    fs::read_dir(root)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_str().unwrap().to_owned();
            (name, raw_hash(&fs::read(path).unwrap()))
        })
        .collect()
}

#[test]
#[ignore = "isolated synthetic over-count header and canonical public parameters; no replay/mining/proofs"]
fn generation_horizon_public_open_refuses_before_any_replay_marker_or_write() {
    assert_eq!(std::env::var("SILK_F04_ISOLATED_LAB").as_deref(), Ok("1"));
    let root = PathBuf::from(std::env::var_os("SILK_F04_GENERATION_BOUNDARY_ROOT").unwrap());
    let margin = PathBuf::from(std::env::var_os("SILK_F04_HOST_MARGIN").unwrap());
    let parameter_dir = PathBuf::from(std::env::var_os("SILK_F04_PARAMETER_DIR").unwrap());
    assert!(!root.exists());
    let genesis = crate::genesis::public_testnet_v1::genesis().unwrap();
    let parameters = SaplingParameters::load(
        &parameter_dir.join("sapling-spend.params"),
        &parameter_dir.join("sapling-output.params"),
    )
    .unwrap();
    let mut store = Store::create(&root, &margin).unwrap();
    // One deliberately synthetic intact header, not 20,001 valid generations.
    // Counts can refuse the public open, never establish lineage or validity.
    let header = Record {
        kind: 0,
        status: 0,
        sequence: crate::capacity::HistoryLimitsV1::REFERENCE.generations(),
        previous: [0; 32],
        domain: genesis.domain(),
        clock: 0,
        data: raw_hash(b"synthetic over-count header"),
        state: [0; 32],
        order: [0; 32],
        checkpoint: [0; 32],
        vertices: 0,
    };
    let pin = store
        .commit(&[b"synthetic over-count header"], &header.encode())
        .unwrap();
    drop(store);
    let original = immutable_inputs(&root);
    assert!(!root.join("ACTIVE_REPLAY").exists());
    assert!(!root.join("ACTIVE_JOB").exists());
    let error = Node::open_retained_pinned(&root, &margin, genesis, &parameters, pin)
        .err()
        .expect("zero-based sequence equal to the count limit must refuse");
    assert!(matches!(
        error,
        Error::Unavailable("retained local resource profile")
    ));
    assert!(!root.join("ACTIVE_REPLAY").exists());
    assert!(!root.join("ACTIVE_JOB").exists());
    assert_eq!(immutable_inputs(&root), original);
    println!(
        "synthetic_header_sequence=20000; claimed_record_count=20001; public_open_refused=true; no_replay_marker=true; all_store_bytes_unchanged=true; replay_executed=false; work=0; proofs=0"
    );
}

#[test]
#[ignore = "requires isolated COPY of a genuine locally retained eight-vertex corpus and canonical parameters"]
fn disk_ancestry_native_cold_replay_preserves_source_and_corrupt_auxiliary_stops() {
    assert_eq!(std::env::var("SILK_F04_ISOLATED_LAB").as_deref(), Ok("1"));
    let root = PathBuf::from(std::env::var_os("SILK_F04_ANCESTRY_NATIVE_STORE").unwrap());
    let margin = PathBuf::from(std::env::var_os("SILK_F04_HOST_MARGIN").unwrap());
    let parameter_dir = PathBuf::from(std::env::var_os("SILK_F04_PARAMETER_DIR").unwrap());
    let pin: Digest = hex::decode(std::env::var("SILK_F04_ANCESTRY_NATIVE_PIN").unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let checkpoint: Digest =
        hex::decode(std::env::var("SILK_F04_ANCESTRY_NATIVE_CHECKPOINT").unwrap())
            .unwrap()
            .try_into()
            .unwrap();
    let state: Digest = hex::decode(std::env::var("SILK_F04_ANCESTRY_NATIVE_STATE").unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let original = immutable_inputs(&root);
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
    assert_eq!(node.core.state.executed_len(), 8);
    assert_eq!(node.local_head().unwrap(), pin);
    assert_eq!(node.core.state.checkpoint_id(), checkpoint);
    assert_eq!(node.core.state.digest(), state);
    assert_eq!(node.core.status, Status::Ready);
    assert!(node.core.graph.retained_ancestry_pages() > 0);
    drop(node);
    for (name, hash) in &original {
        assert_eq!(raw_hash(&fs::read(root.join(name)).unwrap()), *hash);
    }
    let page = fs::read_dir(&root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.extension().is_some_and(|ext| ext == "obj")
                && fs::read(path).unwrap().starts_with(b"SNF04AP1")
        })
        .expect("new durable ancestry page");
    let mut changed = fs::read(&page).unwrap();
    changed[48] ^= 1;
    fs::write(&page, changed).unwrap();
    let error = Node::open_retained(
        &root,
        &margin,
        crate::genesis::public_testnet_v1::genesis().unwrap(),
        &parameters,
    )
    .err()
    .expect("damaged auxiliary page must stop");
    assert!(matches!(
        error,
        Error::Unavailable("retained ancestry page publication failed")
    ));
    assert!(!storage_integrity_failure(&error));
    for (name, hash) in &original {
        assert_eq!(raw_hash(&fs::read(root.join(name)).unwrap()), *hash);
    }
    assert!(
        fs::read_dir(&root)
            .unwrap()
            .any(|entry| entry.unwrap().file_name() == "ACTIVE_REPLAY")
    );
    println!(
        "retained_vertices=8; full_replay=true; source_bytes_unchanged=true; corrupt_auxiliary_stop=true; previous_head_fallback=false; mined=0"
    );
}
