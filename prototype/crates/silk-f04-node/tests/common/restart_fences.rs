//! Explicit file-state fixtures over genuine history, NOT process-kill/power-loss tests.
use sha2::{Digest as _, Sha256};
use silk_f04_node::{
    Digest, Error,
    genesis::Genesis,
    node::{Node, NodeStatus},
};
use silk_sapling_f04::parameters::SaplingParameters;
use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

fn new_file(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
fn marker(root: &Path, name: &str, bytes: &[u8]) {
    let id = hex::encode(Sha256::digest(bytes));
    new_file(&root.join(format!("{id}.obj")), bytes);
    File::open(root).unwrap().sync_all().unwrap();
    new_file(&root.join(name), id.as_bytes());
    File::open(root).unwrap().sync_all().unwrap();
}
fn checkpoint_marker(g: &Genesis, base: Digest, count: u64) -> Vec<u8> {
    let mut bytes = Vec::from(b"SNF04CJ1".as_slice());
    bytes.extend_from_slice(&g.domain());
    bytes.extend_from_slice(&base);
    bytes.extend_from_slice(&count.to_le_bytes());
    bytes.extend_from_slice(&[75; 16]); // PUBLIC local fixture nonce, not a production attempt.
    bytes
}
fn snapshot(root: &Path) -> Vec<(String, Digest)> {
    let mut files = std::fs::read_dir(root)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (
                entry.file_name().to_str().unwrap().to_owned(),
                Sha256::digest(std::fs::read(entry.path()).unwrap()).into(),
            )
        })
        .collect::<Vec<_>>();
    files.sort();
    files
}
fn before_first_checkpoint(
    root: &Path,
    margin: &Path,
    g: &Genesis,
    p: &SaplingParameters,
    records: &[Vec<u8>],
) -> Node {
    assert_eq!(records.len(), 8);
    let mut node = Node::create(root, margin, g.clone()).unwrap();
    for bytes in records {
        node.ingest(bytes, p).unwrap();
    }
    assert_eq!(node.status().unwrap(), NodeStatus::NeedsReconcile);
    assert!(node.state().is_err());
    node
}
pub fn verify(lab: &Path, margin: &Path, g: &Genesis, p: &SaplingParameters, records: &[Vec<u8>]) {
    let root = lab.join("checkpoint-terminal-fixture");
    let mut node = before_first_checkpoint(&root, margin, g, p, records);
    let base = node.local_head().unwrap();
    node.advance().unwrap();
    assert_eq!(node.status().unwrap(), NodeStatus::Ready);
    let complete = node.local_head().unwrap();
    let checkpoint = node.state().unwrap().checkpoint_bytes().to_vec();
    drop(node);
    let original = snapshot(&root);
    let wrong = super::common::fixture(&[1]).genesis;
    assert!(matches!(
        Node::open_retained_pinned(&root, margin, wrong, p, complete),
        Err(Error::Unavailable("retained generation context"))
    ));
    assert_eq!(snapshot(&root), original);
    // Emulate durable HEAD publication followed by loss before terminal closure.
    marker(&root, "ACTIVE_JOB", &checkpoint_marker(g, base, 8));
    let node = Node::open_retained_pinned(&root, margin, g.clone(), p, complete).unwrap();
    assert_eq!(node.state().unwrap().checkpoint_bytes(), checkpoint);
    assert_eq!(node.local_head().unwrap(), complete);
    assert!(!root.join("ACTIVE_JOB").exists());
    assert!(!root.join("ACTIVE_REPLAY").exists());
    drop(node);
    // A retained replay's lost execution state is never silently replenished.
    let mut replay = Vec::from(b"SNF04RJ1".as_slice());
    replay.extend_from_slice(&g.domain());
    replay.extend_from_slice(&complete);
    replay.extend_from_slice(&[76; 16]);
    marker(&root, "ACTIVE_REPLAY", &replay);
    let retained = snapshot(&root);
    for _ in 0..2 {
        assert!(matches!(
            Node::open_retained_pinned(&root, margin, g.clone(), p, complete),
            Err(Error::Paused(
                "interrupted retained replay requires explicit bounded authority"
            ))
        ));
        assert_eq!(snapshot(&root), retained);
    }
    let root = lab.join("checkpoint-uncommitted-fixture");
    let node = before_first_checkpoint(&root, margin, g, p, records);
    let base = node.local_head().unwrap();
    drop(node);
    marker(&root, "ACTIVE_JOB", &checkpoint_marker(g, base, 8));
    let retained = snapshot(&root);
    for _ in 0..2 {
        assert!(matches!(
            Node::open_retained_pinned(&root, margin, g.clone(), p, base),
            Err(Error::Paused(
                "uncommitted local job requires explicit bounded authority"
            ))
        ));
        assert_eq!(snapshot(&root), retained);
    }
    // Even a valid PREVIOUS must not repair a malformed head under an unresolved
    // checkpoint job. Preserve all original bytes in this task-owned fixture.
    std::fs::rename(root.join("HEAD"), root.join("fixture-retained-head")).unwrap();
    new_file(&root.join("HEAD"), b"malformed head fixture");
    let retained = snapshot(&root);
    for _ in 0..2 {
        assert!(matches!(
            Node::open_retained(&root, margin, g.clone(), p),
            Err(Error::Paused(
                "uncommitted local job requires explicit bounded authority"
            ))
        ));
        assert_eq!(snapshot(&root), retained);
    }
    let root = lab.join("checkpoint-previous-repair-fixture");
    let mut node = before_first_checkpoint(&root, margin, g, p, records);
    node.advance().unwrap();
    let previous = node.local_head().unwrap();
    let checkpoint = node.state().unwrap().checkpoint_bytes().to_vec();
    node.flush_clock().unwrap();
    drop(node);
    std::fs::rename(root.join("HEAD"), root.join("fixture-retained-head")).unwrap();
    new_file(&root.join("HEAD"), b"malformed head fixture");
    let node = Node::open_retained(&root, margin, g.clone(), p).unwrap();
    assert!(node.recovered_previous());
    assert_eq!(node.local_head().unwrap(), previous);
    assert_eq!(node.state().unwrap().checkpoint_bytes(), checkpoint);
    assert!(!root.join("ACTIVE_REPLAY").exists());
    println!("checkpoint_replay_file_state_fixtures=true;actual_process_crash=false");
}
