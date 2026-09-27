//! Genuine-work/proof node integration. Colocated fixture roles are NOT a privacy trial.
#[path = "common/cold_cli.rs"]
mod cold_cli;
mod common;
#[path = "common/restart_fences.rs"]
mod restart_fences;
use common::fixture;
use sapling_crypto::zip32::ExtendedSpendingKey;
use silk_f04_node::{
    carriage::Body,
    node::{Ingress, Node, NodeStatus},
    scanner::{NoteStatus, scan, witness_at_cut},
};
use silk_sapling_f04::{
    codec::Envelope,
    parameters::SaplingParameters,
    wallet::{PaymentOutput, SpendInput, build_transfer},
};
use std::{path::PathBuf, time::Instant};

fn settle(node: &mut Node) {
    for _ in 0..512 {
        if node.status().unwrap() == NodeStatus::Ready {
            return;
        }
        node.advance().unwrap();
    }
    panic!("bounded reconciliation did not complete");
}

#[test]
#[ignore = "requires canonical Sapling parameters and the qualified isolated genuine-work runtime"]
fn genuine_work_atomic_effects_restart_and_full_range_sync() {
    assert_eq!(
        std::env::var("SILK_F04_ISOLATED_LAB").as_deref(),
        Ok("1"),
        "explicit qualified runtime required"
    );
    let started = Instant::now();
    let parameter_dir = PathBuf::from(std::env::var_os("SILK_F04_PARAMETER_DIR").unwrap());
    let store_parent = PathBuf::from(std::env::var_os("SILK_F04_LAB_STORE").unwrap());
    let margin = PathBuf::from(std::env::var_os("SILK_F04_HOST_MARGIN").unwrap());
    let parameters = SaplingParameters::load(
        &parameter_dir.join("sapling-spend.params"),
        &parameter_dir.join("sapling-output.params"),
    )
    .unwrap();
    let lab = tempfile::Builder::new()
        .prefix("f04-node-path-")
        .tempdir_in(&store_parent)
        .unwrap()
        .keep();
    println!("retained_lab={}; roles=colocated-test-only", lab.display());
    let f = fixture(&[10, 20, 30]);
    let mut node = Node::create(&lab.join("node-a"), &margin, f.genesis.clone()).unwrap();
    // Two identical local requests are separate attempts, neither graph credit
    // nor conflicting terminal evidence. Deterministic mining bytes stay equal.
    let empty = Body::new(&f.genesis.domain(), &[]).unwrap();
    let first_mined = node
        .mine_candidate(
            empty.clone(),
            [0; 32],
            [7; 32],
            None,
            f.genesis.timestamp() + 10,
        )
        .unwrap();
    let second_mined = node
        .mine_candidate(
            empty.clone(),
            [0; 32],
            [7; 32],
            None,
            f.genesis.timestamp() + 10,
        )
        .unwrap();
    assert_eq!(first_mined.encode(), second_mined.encode());
    assert_eq!(node.vertex_count(), 0);
    assert!(!lab.join("node-a/ACTIVE_JOB").exists());
    for _ in 0..2 {
        assert!(matches!(
            node.mine_candidate(
                empty.clone(),
                [255; 32],
                [7; 32],
                None,
                f.genesis.timestamp() + 10
            ),
            Err(silk_f04_node::Error::Invalid(_))
        ));
        assert_eq!(node.status().unwrap(), NodeStatus::Ready);
        assert!(!lab.join("node-a/ACTIVE_JOB").exists());
    }
    let recipient = ExtendedSpendingKey::master(&[81; 32]);
    let change = ExtendedSpendingKey::master(&[82; 32]);
    let cut = node.state().unwrap().eligible_cut().clone();
    let input = |i: usize| SpendInput {
        key: f.keys[i].clone(),
        note: f.notes[i].clone(),
        path: witness_at_cut(node.state().unwrap(), &cut, i as u64).unwrap(),
    };
    let outputs = |a, b| {
        [
            PaymentOutput {
                address: recipient.default_address().1,
                value: a,
            },
            PaymentOutput {
                address: change.default_address().1,
                value: b,
            },
        ]
    };
    let proving = Instant::now();
    let a = build_transfer(
        cut.reference(f.genesis.domain()),
        vec![input(0), input(1)],
        outputs(14, 15),
        &parameters,
    )
    .unwrap();
    let b = build_transfer(
        cut.reference(f.genesis.domain()),
        vec![input(1), input(2)],
        outputs(24, 25),
        &parameters,
    )
    .unwrap();
    let c = build_transfer(
        cut.reference(f.genesis.domain()),
        vec![input(2)],
        outputs(14, 15),
        &parameters,
    )
    .unwrap();
    println!("three_real_envelopes_ms={}", proving.elapsed().as_millis());
    let first = Body::new(
        &f.genesis.domain(),
        &[
            a.envelope().clone(),
            b.envelope().clone(),
            a.envelope().clone(),
            c.envelope().clone(),
        ],
    )
    .unwrap();
    for i in 1_u64..=8 {
        let body = if i == 1 {
            first.clone()
        } else {
            Body::new(&f.genesis.domain(), &[]).unwrap()
        };
        let mut reward = [0; 32];
        reward[..8].copy_from_slice(&i.to_le_bytes());
        let work = node
            .mine_candidate(body, [0; 32], reward, None, f.genesis.timestamp() + i * 10)
            .unwrap();
        let bytes = work.encode();
        if i == 1 {
            assert_eq!(node.begin_ingest(&bytes).unwrap(), Ingress::Pending);
            assert_eq!(node.vertex_count(), 0);
            assert!(node.state().is_err());
            let mut calls = 0;
            loop {
                calls += 1;
                assert!(calls <= 32);
                if node.resume_ingest(&parameters).unwrap() == Ingress::Admitted {
                    break;
                }
            }
            assert!(calls >= 3);
        } else {
            assert_eq!(node.ingest(&bytes, &parameters).unwrap(), Ingress::Admitted);
        }
        if i == 8 {
            assert_eq!(
                node.ingest(&bytes, &parameters).unwrap(),
                Ingress::AlreadyKnown
            );
            let first_bytes = node.export_range(0, 1).unwrap().remove(0);
            let mut unadmitted =
                silk_f04_node::carriage::Candidate::decode(&first_bytes, &f.genesis).unwrap();
            unadmitted.id[0] ^= 1;
            assert!(matches!(
                node.begin_ingest(&unadmitted.encode()),
                Err(silk_f04_node::Error::Paused(_))
            ));
            assert!(!lab.join("node-a/ACTIVE_JOB").exists());
        }
        settle(&mut node);
        assert_eq!(
            node.ingest(&bytes, &parameters).unwrap(),
            Ingress::AlreadyKnown
        );
    }
    let state = node.state().unwrap();
    assert_eq!(state.private_counters(), (58, 2));
    assert_eq!(state.leaves(), 7);
    let accepted_outputs = state.accepted_outputs().to_vec();
    assert_eq!(accepted_outputs.len(), 2);
    for (row, position, envelope) in [
        (&accepted_outputs[0], 3, a.envelope()),
        (&accepted_outputs[1], 5, c.envelope()),
    ] {
        assert_eq!(row.effect, envelope.effect_id());
        assert_eq!(row.first_position, position);
        assert_eq!(row.commitments, envelope.output_value_commitments());
    }
    assert!(
        accepted_outputs
            .iter()
            .all(|row| row.effect != b.envelope().effect_id())
    );
    assert_eq!(state.public_balance(&[0; 32]), (80, 0));
    let received = scan(state, recipient.to_diversifiable_full_viewing_key().fvk()).unwrap();
    assert_eq!(
        received.iter().map(|r| r.note.value().inner()).sum::<u64>(),
        28
    );
    assert!(received.iter().all(|r| r.status == NoteStatus::PendingCut));
    for r in &received {
        assert!(witness_at_cut(state, &cut, r.position).is_err());
    }
    let digest = state.digest();
    let checkpoint = state.checkpoint_id();
    node.flush_clock().unwrap();
    drop(node);
    let mut node =
        Node::open_retained(&lab.join("node-a"), &margin, f.genesis.clone(), &parameters).unwrap();
    assert!(!node.recovered_previous());
    assert_eq!(node.state().unwrap().digest(), digest);
    assert_eq!(node.state().unwrap().checkpoint_id(), checkpoint);
    assert_eq!(node.state().unwrap().accepted_outputs(), accepted_outputs);
    let mut peer = Node::create(&lab.join("node-b"), &margin, f.genesis.clone()).unwrap();
    for bytes in node.export_range(0, 32).unwrap() {
        peer.ingest(&bytes, &parameters).unwrap();
        settle(&mut peer);
    }
    assert_eq!(
        peer.state().unwrap().checkpoint_bytes(),
        node.state().unwrap().checkpoint_bytes()
    );
    // A different full representation must pass all crypto, even if its economic
    // effect is already accepted. Invalid-first never enters graph/EF/NF authority.
    let mut invalid = *a.envelope().bytes();
    invalid[2214] ^= 1;
    let invalid = Envelope::decode(&invalid, &f.genesis.domain()).unwrap();
    let bad = node
        .mine_candidate(
            Body::new(&f.genesis.domain(), &[invalid]).unwrap(),
            [0; 32],
            [99; 32],
            None,
            f.genesis.timestamp() + 90,
        )
        .unwrap();
    assert!(node.ingest(&bad.encode(), &parameters).is_err());
    assert_eq!(node.vertex_count(), 8);
    assert_eq!(node.state().unwrap().digest(), digest);
    for i in 9_u64..=16 {
        let body = if i == 9 {
            Body::new(&f.genesis.domain(), &[a.envelope().clone()]).unwrap()
        } else {
            Body::new(&f.genesis.domain(), &[]).unwrap()
        };
        let mut reward = [0; 32];
        reward[..8].copy_from_slice(&i.to_le_bytes());
        let work = node
            .mine_candidate(body, [0; 32], reward, None, f.genesis.timestamp() + i * 10)
            .unwrap();
        node.ingest(&work.encode(), &parameters).unwrap();
        settle(&mut node);
    }
    assert_eq!(node.state().unwrap().private_counters(), (58, 2));
    assert_eq!(node.state().unwrap().accepted_outputs(), accepted_outputs);
    assert_eq!(node.state().unwrap().public_balance(&[0; 32]), (160, 0));
    for bytes in node.export_range(8, 32).unwrap() {
        peer.ingest(&bytes, &parameters).unwrap();
        settle(&mut peer);
    }
    assert_eq!(
        peer.state().unwrap().checkpoint_bytes(),
        node.state().unwrap().checkpoint_bytes()
    );
    peer.flush_clock().unwrap();
    assert_eq!(peer.state().unwrap().accepted_outputs(), accepted_outputs);
    node.flush_clock().unwrap();
    // Dropping an uncompleted job must not grant it a new budget on reopen.
    let mut interrupted =
        Node::create(&lab.join("node-interrupted"), &margin, f.genesis.clone()).unwrap();
    let first_bytes = node.export_range(0, 1).unwrap().remove(0);
    assert_eq!(
        interrupted.begin_ingest(&first_bytes).unwrap(),
        Ingress::Pending
    );
    drop(interrupted);
    assert!(matches!(
        Node::open_retained(
            &lab.join("node-interrupted"),
            &margin,
            f.genesis.clone(),
            &parameters
        ),
        Err(silk_f04_node::Error::Paused(
            "uncommitted local job requires explicit bounded authority"
        ))
    ));
    restart_fences::verify(
        &lab,
        &margin,
        &f.genesis,
        &parameters,
        &node.export_range(0, 8).unwrap(),
    );
    println!(
        "node_path_ms={}; vertices=16; real_envelopes=3; burns=2; duplicate_no_fee=true; rejected_second_input_preserved=true; retained_bytes={}",
        started.elapsed().as_millis(),
        node.accounted_bytes()
    );
    let head = hex::encode(node.local_head().unwrap());
    let checkpoint = hex::encode(node.state().unwrap().checkpoint_id());
    let digest = hex::encode(node.state().unwrap().digest());
    drop(node);
    drop(peer);
    drop(parameters);
    cold_cli::verify(
        &lab,
        &margin,
        &parameter_dir,
        &f.genesis,
        &head,
        &checkpoint,
        &digest,
        &first_bytes,
    );
}
