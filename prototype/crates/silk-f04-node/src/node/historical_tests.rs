//! Explicitly gated larger public fixture acceptance. Compiled, NOT run by default.
//! No historical node store, wallet material or saved validity is imported.
use super::*;
use crate::history::PublicHistoryV1;
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
#[ignore = "new selective reducer path ONLY; fresh24 existing genuine carriers, no mining/proofs"]
fn selective_empty_checkpoint_native_24_retains_private_pages() {
    let (root, margin, genesis, history, parameters) = inputs();
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    let mut node = Node::create(&root.join("node"), &margin, genesis).unwrap();
    let bytes = history.read_range(0, 24).unwrap();
    let range = history.decode_range(&bytes, 0, 24).unwrap();
    for carrier in range.carriers() {
        assert_eq!(
            node.ingest(carrier, &parameters).unwrap(),
            Ingress::Admitted
        );
        for _ in 0..4 {
            if node.status().unwrap() == Status::Ready {
                break;
            }
            node.advance().unwrap();
        }
        assert_eq!(node.status().unwrap(), Status::Ready);
    }
    assert_eq!(node.core.state.checkpoint_index(), 3);
    let ids = node
        .core
        .order
        .eligible(&JobBudget::checkpoint().unwrap())
        .unwrap();
    let prior = node
        .core
        .retained_history_for_test()
        .find(|state| state.checkpoint_index() == 2)
        .unwrap()
        .clone();
    let bodies = ids[16..24]
        .iter()
        .map(|id| {
            node.core
                .graph
                .load_for_execution(*id, &node.core.genesis, &JobBudget::checkpoint().unwrap())
                .unwrap()
        })
        .collect::<Vec<_>>();
    assert!(bodies.iter().all(|vertex| vertex.envelopes().is_empty()));
    let batch = bodies
        .iter()
        .map(Arc::as_ref)
        .collect::<Vec<_>>()
        .try_into()
        .ok()
        .unwrap();
    let replayed = prior
        .execute(batch, &JobBudget::checkpoint().unwrap())
        .unwrap();
    assert_eq!(replayed.state.manifest(), node.core.state.manifest());
    assert_eq!(
        replayed.state.retained_recovery_pages(),
        prior.retained_recovery_pages()
    );
    assert!(!prior.retained_recovery_pages().is_empty());
    assert_eq!(
        replayed.state.retained_set_pages(),
        prior.retained_set_pages()
    );
    assert_eq!(
        replayed.state.retained_history_pages()[0],
        prior.retained_history_pages()[0]
    );
    assert_eq!(
        replayed.state.retained_history_pages(),
        prior.retained_history_pages()
    );
    assert!(!root.join("node/ACTIVE_JOB").exists());
    assert!(!root.join("node/ACTIVE_REPLAY").exists());
    println!(
        "selective_empty_checkpoint_native=true; vertices=24; checkpoints=3; admitted_empty_batch=true; exact_original_manifest=true; all_payload_prefix_pages_remain_retained=true; newly_derived_rows_staged=true; new_work=0; new_proofs=0; separate_cold_success=false; native_reorg=false"
    );
}

#[test]
#[ignore = "changed ancestry-root native boundary ONLY; fresh 520 existing genuine carriers, isolated outer limits, no mining/proofs"]
fn extensible_ancestry_native_520_fresh_node() {
    assert_eq!(
        std::env::var("SILK_F04_EXTENSIBLE_ANCESTRY_NATIVE").as_deref(),
        Ok("1")
    );
    let (root, margin, genesis, history, parameters) = inputs();
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    let mut node = Node::create(&root.join("node"), &margin, genesis).unwrap();
    const PREFIX: usize = 520;
    let started = std::time::Instant::now();
    for start in (0..PREFIX).step_by(32) {
        let count = (PREFIX - start).min(32);
        let bytes = history.read_range(start, count).unwrap();
        let range = history.decode_range(&bytes, start, count).unwrap();
        for carrier in range.carriers() {
            let ordinal = node.vertex_count();
            let ingress = node.ingest(carrier, &parameters);
            if let Err(error) = &ingress {
                eprintln!(
                    "extensible_ancestry_refused_ordinal={ordinal}; error={error:?}; original_budget_failure={:?}",
                    node.admission_budget_failure()
                );
            }
            assert_eq!(ingress.unwrap(), Ingress::Admitted);
            for _ in 0..66 {
                if node.status().unwrap() == Status::Ready {
                    break;
                }
                node.advance().unwrap();
            }
            assert_eq!(node.status().unwrap(), Status::Ready);
            assert!(!root.join("node/ACTIVE_JOB").exists());
        }
        println!(
            "extensible_ancestry_vertices={}; elapsed_seconds={}",
            node.vertex_count(),
            started.elapsed().as_secs_f64()
        );
    }
    assert_eq!(node.vertex_count(), PREFIX);
    assert_eq!(node.core.state.executed_len(), PREFIX);
    assert_eq!(node.core.state.checkpoint_index(), 65);
    assert!(!node.recovered_previous());
    let directory_pages = node.core.graph.retained_directory_pages();
    for page in directory_pages {
        let bytes = fs::read(root.join("node").join(format!("{}.obj", hex::encode(page)))).unwrap();
        assert_eq!(&bytes[..8], b"SNF04DP2");
    }
    assert!(fs::read_dir(root.join("node")).unwrap().any(|entry| {
        let path = entry.unwrap().path();
        path.extension().is_some_and(|ext| ext == "obj")
            && fs::read(path).unwrap().starts_with(b"SNF04AD2")
    }));
    let order = node
        .core
        .order
        .bytes(&JobBudget::checkpoint().unwrap())
        .unwrap();
    let ledger = public_ledger(&node);
    let head = node.local_head().unwrap();
    for (name, value) in [
        ("head", head),
        ("order", raw_hash(&order)),
        ("ledger", ledger),
        ("checkpoint", node.core.state.checkpoint_id()),
        ("state", node.core.state.digest()),
    ] {
        fs::write(root.join(format!("derived-{name}.hex")), hex::encode(value)).unwrap();
    }
    println!(
        "extensible_ancestry_fresh_head={}; order_sha256={}; public_ledger_sha256={}; vertices=520; checkpoints=65; new_work_records=0; new_payment_proofs=0; new_directory_root_format=true; whole_core_beyond4096=false",
        hex::encode(head),
        hex::encode(raw_hash(&order)),
        hex::encode(ledger)
    );
}

#[test]
#[ignore = "separate pinned cold process for the new 520-carrier ancestry root boundary ONLY; no retries/old owners/mining/proofs"]
fn extensible_ancestry_native_520_separate_cold_process() {
    assert_eq!(
        std::env::var("SILK_F04_EXTENSIBLE_ANCESTRY_NATIVE").as_deref(),
        Ok("1")
    );
    let (root, margin, genesis, _, parameters) = inputs();
    let pin = digest(&std::env::var("SILK_F04_EXTENSIBLE_EXPECTED_HEAD").unwrap());
    let node =
        Node::open_retained_pinned(&root.join("node"), &margin, genesis, &parameters, pin).unwrap();
    assert_eq!(node.vertex_count(), 520);
    assert_eq!(node.status().unwrap(), Status::Ready);
    assert_eq!(node.core.state.executed_len(), 520);
    assert_eq!(node.core.state.checkpoint_index(), 65);
    assert!(!node.recovered_previous());
    let order = node
        .core
        .order
        .bytes(&JobBudget::checkpoint().unwrap())
        .unwrap();
    let ledger = public_ledger(&node);
    for (name, actual) in [
        ("HEAD", node.local_head().unwrap()),
        ("ORDER", raw_hash(&order)),
        ("LEDGER", ledger),
        ("CHECKPOINT", node.core.state.checkpoint_id()),
        ("STATE", node.core.state.digest()),
    ] {
        assert_eq!(
            actual,
            digest(&std::env::var(format!("SILK_F04_EXTENSIBLE_EXPECTED_{name}")).unwrap())
        );
    }
    assert!(!root.join("node/ACTIVE_JOB").exists());
    assert!(!root.join("node/ACTIVE_REPLAY").exists());
    println!(
        "extensible_ancestry_cold_head={}; order_sha256={}; public_ledger_sha256={}; vertices=520; checkpoints=65; exact_fresh_semantic_replay=true; new_work_records=0; new_payment_proofs=0; whole_core_beyond4096=false",
        hex::encode(pin),
        hex::encode(raw_hash(&order)),
        hex::encode(ledger)
    );
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
        let range = history.decode_range(&bytes, start, 32).unwrap();
        for carrier in range.carriers() {
            let ordinal = node.vertex_count();
            let ingress = node.ingest(carrier, &parameters);
            if let Err(error) = &ingress {
                eprintln!(
                    "ingress_refused_ordinal={ordinal}; carrier_sha256={}; error={error:?}; first_cooperative_budget_failure={:?}",
                    hex::encode(raw_hash(carrier)),
                    node.admission_budget_failure()
                );
            }
            assert_eq!(ingress.unwrap(), Ingress::Admitted);
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
#[ignore = "NEEDS exact independent outer execution approval; fresh 1361-carrier diagnostic prefix only, original budgets, NO mining/proof generation or failed-store reopen"]
fn historical_foreground_diagnostic_prefix_1361_fresh_node() {
    assert_eq!(
        std::env::var("SILK_F04_FOREGROUND_PREFIX_DIAGNOSTIC").as_deref(),
        Ok("1")
    );
    let (root, margin, genesis, history, parameters) = inputs();
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    let started = std::time::Instant::now();
    let mut node = Node::create(&root.join("node"), &margin, genesis).unwrap();
    const PREFIX: usize = 1361;
    for start in (0..PREFIX).step_by(32) {
        let bytes = history.read_range(start, (PREFIX - start).min(32)).unwrap();
        let range = history
            .decode_range(&bytes, start, (PREFIX - start).min(32))
            .unwrap();
        for carrier in range.carriers() {
            let ordinal = node.vertex_count();
            let ingress = node.ingest(carrier, &parameters);
            if let Err(error) = &ingress {
                eprintln!(
                    "diagnostic_prefix_refused_ordinal={ordinal}; carrier_sha256={}; error={error:?}; first_cooperative_budget_failure={:?}",
                    hex::encode(raw_hash(carrier)),
                    node.admission_budget_failure()
                );
            }
            assert_eq!(ingress.unwrap(), Ingress::Admitted);
            for _ in 0..171 {
                if node.status().unwrap() == Status::Ready {
                    break;
                }
                node.advance().unwrap();
            }
            assert_eq!(node.status().unwrap(), Status::Ready);
            assert!(!root.join("node/ACTIVE_JOB").exists());
        }
        println!(
            "diagnostic_prefix_vertices={}; elapsed_seconds={}",
            node.vertex_count(),
            started.elapsed().as_secs_f64()
        );
    }
    assert_eq!(node.vertex_count(), PREFIX);
    assert_eq!(node.state().unwrap().checkpoint_index(), 170);
    assert_eq!(node.state().unwrap().executed().len(), 1360);
    println!(
        "diagnostic_prefix_complete_vertices=1361; checkpoints=170; fresh_head={}; original_vertices_horizon=4096; larger3080_acceptance=false; cold_process_replay=false; new_work_records=0; new_payment_proofs=0",
        hex::encode(node.local_head().unwrap())
    );
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
        let range = history.decode_range(&bytes, start, 1).unwrap();
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

#[test]
#[ignore = "bounded task-owned four-carrier resume fixture only; no mining/new proofs"]
fn historical_received_prefix_interruption_and_local_resume_hint() {
    assert_eq!(
        std::env::var("SILK_F04_RESUME_PREFIX_NATIVE").as_deref(),
        Ok("1")
    );
    let (root, margin, genesis, history, parameters) = inputs();
    let mut node = Node::create(&root.join("node"), &margin, genesis.clone()).unwrap();
    let bytes = history.read_range(0, 4).unwrap();
    assert!(
        history
            .decode_range(&bytes[..bytes.len() - 1], 0, 4)
            .is_err()
    );
    assert_eq!(history.admitted_prefix(&node).unwrap(), 0);
    let range = history.decode_range(&bytes, 0, 4).unwrap();
    for carrier in range.carriers() {
        assert_eq!(
            node.ingest(carrier, &parameters).unwrap(),
            Ingress::Admitted
        );
        for _ in 0..386 {
            if node.status().unwrap() == Status::Ready {
                break;
            }
            node.advance().unwrap();
        }
        assert_eq!(node.status().unwrap(), Status::Ready);
    }
    assert_eq!(node.vertex_count(), 4);
    assert_eq!(history.admitted_prefix(&node).unwrap(), 4);
    let head = node.local_head().unwrap();
    let corpus =
        std::path::PathBuf::from(std::env::var_os("SILK_F04_PUBLIC_HISTORY_ROOT").unwrap());
    let manifest = fs::read(corpus.join("history.manifest")).unwrap();
    let client = root.join("client-manifest");
    fs::create_dir(&client).unwrap();
    let mut reordered = manifest.clone();
    const HEADER: usize = 176;
    const ROW: usize = 68;
    for index in 0..ROW {
        reordered.swap(HEADER + ROW + index, HEADER + 8 * ROW + index);
    }
    fs::write(client.join("history.manifest"), &reordered).unwrap();
    let changed =
        PublicHistoryV1::open(&client, raw_hash(&reordered), Arc::new(genesis.clone())).unwrap();
    assert_eq!(changed.admitted_prefix(&node).unwrap(), 1);
    let mut conflicting = manifest;
    conflicting[HEADER + 32..HEADER + 64].fill(0);
    fs::write(client.join("history.manifest"), &conflicting).unwrap();
    let changed =
        PublicHistoryV1::open(&client, raw_hash(&conflicting), Arc::new(genesis)).unwrap();
    assert!(matches!(
        changed.admitted_prefix(&node),
        Err(Error::Invalid(_))
    ));
    assert_eq!(node.local_head().unwrap(), head);
    assert!(!root.join("node/ACTIVE_JOB").exists());
    println!(
        "resume_receiver_head={}; admitted_prefix=4; source_total=3080; reordered_prefix=1; partial_response_no_credit=true; known_conflict_refused=true; new_work_records=0; new_payment_proofs=0; two_host_transport=false",
        hex::encode(head)
    );
}

#[test]
#[ignore = "separate process for successful four-carrier fixture only; no failed-owner reopen"]
fn historical_received_prefix_cold_resume_and_fresh_source_refusal() {
    assert_eq!(
        std::env::var("SILK_F04_RESUME_PREFIX_NATIVE").as_deref(),
        Ok("1")
    );
    let (root, margin, genesis, history, parameters) = inputs();
    let head = digest(&std::env::var("SILK_F04_RESUME_RECEIVER_HEAD").unwrap());
    let node = Node::open_retained_pinned(
        &root.join("node"),
        &margin,
        genesis.clone(),
        &parameters,
        head,
    )
    .unwrap();
    assert_eq!(node.vertex_count(), 4);
    assert_eq!(node.status().unwrap(), Status::Ready);
    assert!(!node.recovered_previous());
    assert_eq!(history.admitted_prefix(&node).unwrap(), 4);
    assert_eq!(node.local_head().unwrap(), head);
    let first = history.read_range(0, 1).unwrap();
    let range = history.decode_range(&first, 0, 1).unwrap();
    let id = Candidate::decode(range.carriers()[0], &genesis).unwrap().id;
    let mut damaged = None;
    for entry in fs::read_dir(root.join("node")).unwrap() {
        let entry = entry.unwrap();
        if entry.file_name().to_string_lossy().ends_with(".obj") {
            let bytes = fs::read(entry.path()).unwrap();
            if bytes.get(..8) == Some(b"SNF04VR1") && bytes.get(24..56) == Some(id.as_slice()) {
                assert!(damaged.replace(entry.path()).is_none());
            }
        }
    }
    let damaged = damaged.unwrap();
    let quarantine = root.join("quarantined-source");
    fs::create_dir(&quarantine).unwrap();
    fs::rename(&damaged, quarantine.join(damaged.file_name().unwrap())).unwrap();
    assert!(history.admitted_prefix(&node).is_err());
    assert_eq!(node.vertex_count(), 4);
    assert_eq!(node.local_head().unwrap(), head);
    assert!(!root.join("node/ACTIVE_JOB").exists());
    assert!(!root.join("node/ACTIVE_REPLAY").exists());
    println!(
        "cold_resume_prefix=4; receiver_head_pinned=true; fresh_source_missing_refused_after_warm_query=true; fixture_source_quarantined_recoverably=true; no_repair_or_adoption=true; two_host_transport=false; new_work_records=0; new_payment_proofs=0"
    );
}
