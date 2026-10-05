//! Separate-host native roles. Public carriers only; no imported peer stores,
//! mining, proofs, secret keys, listeners or default protocol changes.
use super::*;
use crate::sync::RangeBatchV1;
use std::{fs, path::PathBuf};

fn digest(name: &str) -> Digest {
    hex::decode(std::env::var(name).unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

fn context() -> (PathBuf, Genesis, SaplingParameters, Node) {
    assert_eq!(
        std::env::var("SILK_F04_TWO_HOST_NATIVE_GATE").as_deref(),
        Ok("1")
    );
    let root = PathBuf::from(std::env::var_os("SILK_F04_HOST_ROLE_ROOT").unwrap());
    let margin = PathBuf::from(std::env::var_os("SILK_F04_HOST_MARGIN").unwrap());
    let parameters = PathBuf::from(std::env::var_os("SILK_F04_PARAMETER_DIR").unwrap());
    let source = digest("SILK_F04_NONEMPTY_GENESIS_HASH");
    let bytes = fs::read(
        root.join("node")
            .join(format!("{}.obj", hex::encode(source))),
    )
    .unwrap();
    assert_eq!(raw_hash(&bytes), source);
    let genesis =
        Genesis::admit_local_bundle(&bytes, &digest("SILK_F04_NONEMPTY_DOMAIN"), true).unwrap();
    let parameters = SaplingParameters::load(
        &parameters.join("sapling-spend.params"),
        &parameters.join("sapling-output.params"),
    )
    .unwrap();
    let node = Node::open_retained_pinned(
        &root.join("node"),
        &margin,
        genesis.clone(),
        &parameters,
        digest("SILK_F04_HOST_LOCAL_PIN"),
    )
    .unwrap();
    assert_eq!(
        node.history_limits(),
        crate::capacity::HistoryLimitsV1::REFERENCE
    );
    (root, genesis, parameters, node)
}

fn reconcile(node: &mut Node) {
    for _ in 0..16 {
        if node.status().unwrap() == Status::Ready {
            return;
        }
        node.advance().unwrap();
    }
    panic!("bounded host reconciliation did not finish");
}

fn save(root: &Path, node: &Node) {
    assert_eq!(node.status().unwrap(), Status::Ready);
    assert!(!root.join("node/ACTIVE_JOB").exists());
    assert!(!root.join("node/ACTIVE_REPLAY").exists());
    fs::write(
        root.join("local.pin"),
        hex::encode(node.local_head().unwrap()),
    )
    .unwrap();
    fs::write(root.join("local.state"), node.core.state.manifest()).unwrap();
    fs::write(
        root.join("local.order"),
        node.core
            .order
            .bytes(&JobBudget::checkpoint().unwrap())
            .unwrap(),
    )
    .unwrap();
    println!(
        "host_role={}; vertices={}; checkpoint={}; state_sha256={}; order_sha256={}; newly_mined=0; new_proofs=0",
        std::env::var("SILK_F04_HOST_ROLE").unwrap(),
        node.vertex_count(),
        hex::encode(node.core.state.checkpoint_id()),
        hex::encode(raw_hash(&node.core.state.manifest())),
        hex::encode(raw_hash(
            &node
                .core
                .order
                .bytes(&JobBudget::checkpoint().unwrap())
                .unwrap()
        ))
    );
}

fn frame(carriers: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = vec![u8::try_from(carriers.len()).unwrap()];
    for carrier in carriers {
        bytes.extend_from_slice(&u32::try_from(carrier.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(carrier);
    }
    bytes
}

fn receive(
    node: &mut Node,
    parameters: &SaplingParameters,
    bytes: &[u8],
    start: usize,
    total: usize,
) {
    // Complete transport framing is required BEFORE the first ordinary ingress.
    // Counts and carrier identity never confer work/proof/ordering authority.
    let batch = RangeBatchV1::decode(bytes, start, total).unwrap();
    for carrier in batch.carriers() {
        let result = node.ingest(carrier, parameters).unwrap();
        assert!(matches!(result, Ingress::Admitted | Ingress::AlreadyKnown));
        reconcile(node);
    }
}

#[test]
#[ignore = "two separately isolated hosts only; existing pinned public sibling; no mining"]
fn host_native_branch() {
    let (root, genesis, parameters, mut node) = context();
    assert_eq!(node.vertex_count(), 15);
    let own = fs::read(root.join("own.vertex")).unwrap();
    assert_eq!(raw_hash(&own), digest("SILK_F04_HOST_OWN_CARRIER_HASH"));
    Candidate::decode(&own, &genesis).unwrap();
    assert_eq!(node.ingest(&own, &parameters).unwrap(), Ingress::Admitted);
    reconcile(&mut node);
    assert_eq!(node.vertex_count(), 16);
    assert_eq!(node.core.state.checkpoint_index(), 2);
    assert_eq!(node.export_range(15, 1).unwrap(), [own]);
    fs::write(
        root.join("served.range"),
        frame(&node.export_range(15, 1).unwrap()),
    )
    .unwrap();
    save(&root, &node);
}

#[test]
#[ignore = "isolated host A only; actual public sibling frame from independent host B"]
fn host_native_receive_sibling_and_serve_range() {
    let (root, _, parameters, mut node) = context();
    assert_eq!(node.vertex_count(), 16);
    let bytes = fs::read(root.join("peer.range")).unwrap();
    assert_eq!(raw_hash(&bytes), digest("SILK_F04_HOST_PEER_RANGE_HASH"));
    receive(&mut node, &parameters, &bytes, 15, 16);
    assert_eq!(node.vertex_count(), 17);
    let full = frame(&node.export_range(15, 2).unwrap());
    assert_eq!(full[0], 2);
    let first = 5 + u32::from_be_bytes(full[1..5].try_into().unwrap()) as usize;
    let cut = first + 4 + (full.len() - first - 4) / 2;
    fs::write(root.join("served.range"), &full).unwrap();
    fs::write(root.join("served.cut"), &full[..cut]).unwrap();
    save(&root, &node);
}

#[test]
#[ignore = "isolated host B only; actual truncated and complete frames exported by independent host A"]
fn host_native_cut_response_refuses_before_any_admission_then_resumes() {
    let (root, _, parameters, mut node) = context();
    assert_eq!(node.vertex_count(), 16);
    let cut = fs::read(root.join("peer.cut")).unwrap();
    let full = fs::read(root.join("peer.range")).unwrap();
    assert_eq!(raw_hash(&full), digest("SILK_F04_HOST_PEER_RANGE_HASH"));
    assert_eq!(raw_hash(&cut), digest("SILK_F04_HOST_PEER_CUT_HASH"));
    assert_eq!(cut, full[..cut.len()]);
    let first_end = 5 + u32::from_be_bytes(full[1..5].try_into().unwrap()) as usize;
    assert!(cut.len() > first_end && cut.len() < full.len());
    let first = Candidate::decode(&full[5..first_end], node.genesis()).unwrap();
    assert!(
        node.core
            .graph
            .find_checked(
                VertexId::from_bytes(first.id),
                &JobBudget::checkpoint().unwrap()
            )
            .unwrap()
            .is_none()
    );
    let head = node.local_head().unwrap();
    let state = node.core.state.manifest();
    assert!(RangeBatchV1::decode(&cut, 15, 17).is_err());
    assert_eq!(node.local_head().unwrap(), head);
    assert_eq!(node.vertex_count(), 16);
    assert_eq!(node.core.state.manifest(), state);
    assert!(!root.join("node/ACTIVE_JOB").exists());
    assert!(!root.join("node/ACTIVE_REPLAY").exists());
    receive(&mut node, &parameters, &full, 15, 17);
    assert_eq!(node.vertex_count(), 17);
    save(&root, &node);
    println!(
        "cut_after_complete_unknown_carrier=true; partial_response_grants_no_admission=true; resumed_complete_response=true; already_known_no_second_credit=true; process_crash_recovery=false"
    );
}

#[test]
#[ignore = "isolated host A only; admit existing pinned merge after real independent sibling exchange"]
fn host_native_merge_and_serve() {
    let (root, _, parameters, mut node) = context();
    assert_eq!(node.vertex_count(), 17);
    let merge = fs::read(root.join("merge.vertex")).unwrap();
    assert_eq!(raw_hash(&merge), digest("SILK_F04_HOST_MERGE_HASH"));
    assert_eq!(node.ingest(&merge, &parameters).unwrap(), Ingress::Admitted);
    reconcile(&mut node);
    assert_eq!(node.vertex_count(), 18);
    fs::write(
        root.join("served.range"),
        frame(&node.export_range(17, 1).unwrap()),
    )
    .unwrap();
    save(&root, &node);
}

#[test]
#[ignore = "isolated host B only; admit actual merge frame freshly served by independent host A"]
fn host_native_receive_merge() {
    let (root, _, parameters, mut node) = context();
    assert_eq!(node.vertex_count(), 17);
    let bytes = fs::read(root.join("peer.range")).unwrap();
    assert_eq!(raw_hash(&bytes), digest("SILK_F04_HOST_PEER_RANGE_HASH"));
    receive(&mut node, &parameters, &bytes, 17, 18);
    assert_eq!(node.vertex_count(), 18);
    save(&root, &node);
}

#[test]
#[ignore = "new cold process on each actual host; retained independent local pin only"]
fn host_native_cold_replay_and_exact_repeat() {
    let (root, _, parameters, mut node) = context();
    assert_eq!(node.vertex_count(), 18);
    let expected_state = fs::read(root.join("local.state")).unwrap();
    let expected_order = fs::read(root.join("local.order")).unwrap();
    assert_eq!(node.core.state.manifest(), expected_state);
    assert_eq!(
        node.core
            .order
            .bytes(&JobBudget::checkpoint().unwrap())
            .unwrap(),
        expected_order
    );
    let head = node.local_head().unwrap();
    for carrier in node.export_range(0, 32).unwrap() {
        assert_eq!(
            node.ingest(&carrier, &parameters).unwrap(),
            Ingress::AlreadyKnown
        );
        assert_eq!(node.local_head().unwrap(), head);
        assert_eq!(node.core.state.manifest(), expected_state);
    }
    save(&root, &node);
    println!(
        "actual_host_separate_process_cold_replay=true; original_history_reverified=true; exact_repeat_no_new_credit=true; network_anonymity=false; public_p2p_service=false"
    );
}
