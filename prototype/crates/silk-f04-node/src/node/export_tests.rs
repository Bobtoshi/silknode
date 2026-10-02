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
        .map(|v| v.candidate().encode())
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
        .retained_record()
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
