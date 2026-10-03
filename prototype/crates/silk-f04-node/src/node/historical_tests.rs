//! Explicitly gated larger public fixture acceptance. Compiled, NOT run by default.
//! No historical node store, wallet material or saved validity is imported.
use super::*;
use crate::{history::PublicHistoryV1, sync::RangeBatchV1};
use sha2::{Digest as _, Sha256};
use std::{fs, os::unix::fs::MetadataExt, path::PathBuf};

const GENESIS: &str = "35c55cca9487f71a0a89d182cfbc3db9d546d2f5c5f9cca20c4aa7483c15caf9";
const DOMAIN: &str = "8c0325387abf1c5ae3bbc8a02e91fc87fedfbde653e94343ea79152287d1b466";
const MANIFEST: &str = "c0a8902985b35bdf8ad152d8d959104842db05ca5aec418bcaaa8bd14c622d2d";
const SOURCE: &str = "800874e5cd2b51b47ddb803bea7b25559c7bec2f752bec04411afe29ad69af81";
const CHECKPOINT: &str = "efbd7a79bdc8b07eb7ebfe67a1af5dd9a592114314c76e09f91c6e1603efd2da";
const STATE: &str = "072370e3cd5553f436d40ed27ddede303f6f1e23c2f1a64407df46566dd7996e";

fn digest(value: &str) -> Digest {
    hex::decode(value).unwrap().try_into().unwrap()
}
fn inputs() -> (
    PathBuf,
    PathBuf,
    Genesis,
    PublicHistoryV1,
    SaplingParameters,
) {
    // This flag documents the test boundary; only the separately reviewed outer
    // runtime can enforce aggregate resources or authorize running this test.
    assert_eq!(
        std::env::var("SILK_F04_LARGER_HISTORY_NATIVE").as_deref(),
        Ok("1")
    );
    let source = PathBuf::from(std::env::var_os("SILK_F04_PUBLIC_HISTORY_ROOT").unwrap());
    let root = PathBuf::from(std::env::var_os("SILK_F04_LARGER_HISTORY_STORE").unwrap());
    let margin = PathBuf::from(std::env::var_os("SILK_F04_HOST_MARGIN").unwrap());
    let meta = fs::symlink_metadata(&root).unwrap();
    assert!(meta.is_dir() && meta.mode() & 0o777 == 0o700);
    // The reviewed outer runner creates this exact task UID; never run as root.
    assert_eq!(meta.uid(), 1000);
    assert_ne!(meta.dev(), margin.metadata().unwrap().dev());
    assert!(fs2::total_space(&root).unwrap() <= 1024 * 1024 * 1024);
    assert!(fs2::available_space(&margin).unwrap() >= 4 * 1024 * 1024 * 1024);
    let bytes = fs::read(source.join("genesis.bundle")).unwrap();
    assert!(bytes.len() <= 8 * 1024 * 1024);
    assert_eq!(raw_hash(&bytes), digest(GENESIS));
    // Exact independently pinned historical valueless test-role premise only.
    let genesis = Genesis::admit_local_bundle(&bytes, &digest(DOMAIN), true).unwrap();
    let history =
        PublicHistoryV1::open(&source, digest(MANIFEST), Arc::new(genesis.clone())).unwrap();
    assert_eq!(history.len(), 3080);
    assert_eq!(history.source_head(), digest(SOURCE));
    assert_eq!(history.claimed_checkpoint(), digest(CHECKPOINT));
    assert_eq!(history.claimed_state(), digest(STATE));
    let parameters = PathBuf::from(std::env::var_os("SILK_F04_PARAMETER_DIR").unwrap());
    let parameters = SaplingParameters::load(
        &parameters.join("sapling-spend.params"),
        &parameters.join("sapling-output.params"),
    )
    .unwrap();
    (root, margin, genesis, history, parameters)
}

// Exact derived public ordered collections, not an imported ledger or wallet key.
fn public_ledger(node: &Node) -> Digest {
    let state = node.state().unwrap();
    let mut hash = Sha256::new();
    hash.update(b"silknode-larger-history-test-ledger-v1");
    hash.update(state.digest());
    hash.update((state.executed().len() as u64).to_le_bytes());
    for id in state.executed() {
        hash.update(id.as_bytes());
    }
    hash.update((state.recovery().len() as u64).to_le_bytes());
    for row in state.recovery() {
        hash.update(row.as_slice());
    }
    hash.update((state.accepted_outputs().len() as u64).to_le_bytes());
    for row in state.accepted_outputs() {
        hash.update(row.effect);
        hash.update(row.first_position.to_le_bytes());
        for commitment in row.commitments {
            hash.update(commitment);
        }
    }
    hash.finalize().into()
}
fn assert_complete(node: &Node) {
    assert_eq!(node.vertex_count(), 3080);
    assert_eq!(node.status().unwrap(), Status::Ready);
    assert!(!node.recovered_previous());
    // Only AFTER mandatory ordinary work/proof/parent/order/ledger execution.
    assert_eq!(raw_hash(&node.core.state.manifest()), digest(STATE));
    let state = node.state().unwrap();
    assert_eq!(state.executed().len(), 3080);
    assert_eq!(state.checkpoint_index(), 385);
    assert_eq!(state.checkpoint_id(), digest(CHECKPOINT));
    assert_eq!(state.eligible_cut().index, 1);
    assert_eq!(state.leaves(), 6);
    assert_eq!(state.private_counters(), (298, 2));
    assert_eq!(state.accepted_outputs().len(), 2);
    let capacity = node.history_capacity().unwrap();
    assert_eq!(capacity.vertices_remaining, 4096 - 3080);
    assert!(capacity.generations_remaining > capacity.admission_generations);
}

#[test]
#[ignore = "NEEDS exact independent outer execution approval; 3080 genuine historical records through ordinary receiver; NO mining or proof generation"]
fn historical_public_ranges_ingest_and_reconcile_fresh_node() {
    let (root, margin, genesis, history, parameters) = inputs();
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    let started = std::time::Instant::now();
    let mut node = Node::create(&root.join("node"), &margin, genesis).unwrap();
    for start in (0..history.len()).step_by(32) {
        let bytes = history.read_range(start, 32).unwrap();
        let range = RangeBatchV1::decode(&bytes, start, history.len()).unwrap();
        for carrier in range.carriers() {
            assert_eq!(
                node.ingest(carrier, &parameters).unwrap(),
                Ingress::Admitted
            );
            // Hard finite bound, never an unbounded retry loop or raised budget.
            for _ in 0..386 {
                if node.status().unwrap() == Status::Ready {
                    break;
                }
                node.advance().unwrap();
            }
            assert_eq!(node.status().unwrap(), Status::Ready);
            assert!(!root.join("node/ACTIVE_JOB").exists());
        }
        println!(
            "ingress_vertices={}; elapsed_seconds={}",
            node.vertex_count(),
            started.elapsed().as_secs_f64()
        );
    }
    assert_complete(&node);
    let order = node
        .core
        .order
        .bytes(&JobBudget::checkpoint().unwrap())
        .unwrap();
    let ledger = public_ledger(&node);
    let head = node.local_head().unwrap();
    // No historical source HEAD is accepted as this fresh node's own local pin.
    assert_ne!(head, history.source_head());
    fs::write(root.join("derived-head.hex"), hex::encode(head)).unwrap();
    fs::write(
        root.join("derived-order.hex"),
        hex::encode(raw_hash(&order)),
    )
    .unwrap();
    fs::write(root.join("derived-ledger.hex"), hex::encode(ledger)).unwrap();
    println!(
        "fresh_head={}; order_sha256={}; public_ledger_sha256={}; vertices=3080; checkpoints=385; new_work_records=0; new_payment_proofs=0; no_wallet_recovery_claim=true",
        hex::encode(head),
        hex::encode(raw_hash(&order)),
        hex::encode(ledger)
    );
    // A separate OS process must use independently frozen output pins, not read
    // arbitrary HEAD/expected files from inside the tested store itself.
}

#[test]
#[ignore = "separate process AFTER successful authorized fresh ingestion; pins frozen outside store; full cold native replay, NO mining"]
fn historical_public_history_second_process_cold_parity() {
    let (root, margin, genesis, history, parameters) = inputs();
    let pin = |name: &str| digest(&std::env::var(name).unwrap());
    let head = pin("SILK_F04_LARGER_HISTORY_NEW_HEAD");
    let order = pin("SILK_F04_LARGER_HISTORY_NEW_ORDER");
    let ledger = pin("SILK_F04_LARGER_HISTORY_NEW_LEDGER");
    assert_ne!(head, history.source_head());
    let mut node =
        Node::open_retained_pinned(&root.join("node"), &margin, genesis, &parameters, head)
            .unwrap();
    assert_complete(&node);
    assert_eq!(
        raw_hash(
            &node
                .core
                .order
                .bytes(&JobBudget::checkpoint().unwrap())
                .unwrap()
        ),
        order
    );
    assert_eq!(public_ledger(&node), ledger);
    for start in [0, 3072] {
        let bytes = history.read_range(start, 1).unwrap();
        let range = RangeBatchV1::decode(&bytes, start, history.len()).unwrap();
        assert_eq!(
            node.ingest(range.carriers()[0], &parameters).unwrap(),
            Ingress::AlreadyKnown
        );
        assert_eq!(node.local_head().unwrap(), head);
        assert_eq!(public_ledger(&node), ledger);
        assert!(!root.join("node/ACTIVE_JOB").exists());
    }
    println!(
        "cold_process_replay_parity=true; vertices=3080; checkpoints=385; original_claimed_state_derived=true; exact_repeat_no_new_credit=true; new_work_records=0; new_payment_proofs=0; no_wallet_recovery_claim=true"
    );
}
