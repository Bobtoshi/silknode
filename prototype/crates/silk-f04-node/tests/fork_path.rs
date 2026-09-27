//! Genuine conflicting branches, deep rollback and common-parent source rule.
//! Colocated valueless fixture; not privacy or every-permutation acceptance.
mod common;
use common::fixture;
use rand_core::{OsRng, RngCore};
use sapling_crypto::zip32::ExtendedSpendingKey;
use silk_f04_node::{
    Digest,
    carriage::Body,
    node::{Node, NodeStatus},
    scanner::{scan, witness_at_cut},
};
use silk_order::sg0_v1::Sg0ParentSetV1;
use silk_sapling_f04::{
    parameters::SaplingParameters,
    wallet::{PaymentOutput, SpendInput, build_transfer},
};
use silk_types::VertexId;
use std::{path::PathBuf, time::Instant};

fn key() -> ExtendedSpendingKey {
    let mut seed = [0; 32];
    OsRng.fill_bytes(&mut seed);
    ExtendedSpendingKey::master(&seed)
}
fn settle(node: &mut Node) {
    for _ in 0..512 {
        if node.status().unwrap() == NodeStatus::Ready {
            return;
        }
        assert!(node.state().is_err());
        node.advance().unwrap();
    }
    panic!("bounded reconciliation did not complete");
}
fn parity(a: &Node, b: &Node) {
    let a = a.state().unwrap();
    let b = b.state().unwrap();
    assert_eq!(a.checkpoint_bytes(), b.checkpoint_bytes());
    assert_eq!(a.digest(), b.digest());
    assert_eq!(a.executed(), b.executed());
    assert_eq!(a.recovery(), b.recovery());
    assert_eq!(a.cuts(), b.cuts());
}
fn winner(node: &Node, shared: Digest, a_only: Digest, b_only: Digest) {
    let s = node.state().unwrap();
    assert!(s.contains_nullifier(&shared));
    assert!(s.contains_nullifier(&b_only));
    assert!(!s.contains_nullifier(&a_only));
    assert_eq!(s.private_counters(), (99, 1));
    assert_eq!(s.leaves(), 3);
    assert_eq!(s.public_balance(&[10; 32]), (0, 0));
}

#[test]
#[ignore = "requires canonical parameters and the qualified isolated genuine-work runtime"]
fn genuine_fork_reorg_replaces_whole_private_state_and_merge_rederives_source() {
    assert_eq!(std::env::var("SILK_F04_ISOLATED_LAB").as_deref(), Ok("1"));
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
        .prefix("f04-fork-path-")
        .tempdir_in(store_parent)
        .unwrap()
        .keep();
    println!("retained_lab={}; roles=colocated-test-only", lab.display());
    let f = fixture(&[100]);
    let mut a = Node::create(&lab.join("node-a"), &margin, f.genesis.clone()).unwrap();
    let mut b = Node::create(&lab.join("node-b"), &margin, f.genesis.clone()).unwrap();
    let recipient_a = key();
    let recipient_b = key();
    let change = key();
    let cut = a.state().unwrap().eligible_cut().clone();
    let transfer = |recipient: &ExtendedSpendingKey, value| {
        build_transfer(
            cut.reference(f.genesis.domain()),
            vec![SpendInput {
                key: f.keys[0].clone(),
                note: f.notes[0].clone(),
                path: witness_at_cut(a.state().unwrap(), &cut, 0).unwrap(),
            }],
            [
                PaymentOutput {
                    address: recipient.default_address().1,
                    value,
                },
                PaymentOutput {
                    address: change.default_address().1,
                    value: 99 - value,
                },
            ],
            &parameters,
        )
        .unwrap()
    };
    let pay_a = transfer(&recipient_a, 40);
    let pay_b = transfer(&recipient_b, 60);
    let nfa = pay_a.envelope().nullifiers();
    let nfb = pay_b.envelope().nullifiers();
    let common: Vec<_> = nfa.iter().copied().filter(|nf| nfb.contains(nf)).collect();
    assert_eq!(common.len(), 1);
    let shared = f.notes[0]
        .nf(
            &f.keys[0].to_diversifiable_full_viewing_key().fvk().vk.nk,
            0,
        )
        .0;
    assert_eq!(common, [shared]);
    let a_only = *nfa.iter().find(|nf| **nf != shared).unwrap();
    let b_only = *nfb.iter().find(|nf| **nf != shared).unwrap();
    assert_ne!(a_only, b_only);
    let mut all_a = Vec::new();
    let mut all_b = Vec::new();
    let mut tip_a = [0; 32];
    let mut tip_b = [0; 32];
    for (node, payment, owner, length, records, tip) in [
        (&mut a, &pay_a, [10; 32], 48_u64, &mut all_a, &mut tip_a),
        (&mut b, &pay_b, [11; 32], 64_u64, &mut all_b, &mut tip_b),
    ] {
        for i in 1..=length {
            let body = Body::new(
                &f.genesis.domain(),
                if i == 1 {
                    std::slice::from_ref(payment.envelope())
                } else {
                    &[]
                },
            )
            .unwrap();
            let mut reward = [0; 32];
            reward[..8].copy_from_slice(&i.to_le_bytes());
            let work = node
                .mine_candidate(body, owner, reward, None, f.genesis.timestamp() + i * 40)
                .unwrap();
            assert_eq!(work.header.work, 1);
            *tip = work.id;
            let bytes = work.encode();
            node.ingest(&bytes, &parameters).unwrap();
            settle(node);
            records.push(bytes);
        }
        println!(
            "branch_vertices={length};checkpoint={};elapsed_ms={}",
            node.state().unwrap().checkpoint_index(),
            started.elapsed().as_millis()
        );
    }
    assert!(a.state().unwrap().contains_nullifier(&a_only));
    assert!(!a.state().unwrap().contains_nullifier(&b_only));
    assert_eq!(a.state().unwrap().public_balance(&[10; 32]).0, 480);
    let b_checkpoint = b.state().unwrap().checkpoint_id();
    let mut saw_deep = false;
    for (i, bytes) in all_b.iter().enumerate() {
        a.ingest(bytes, &parameters).unwrap();
        if a.status().unwrap() == NodeStatus::ArchiveReplay {
            saw_deep = true;
            assert!(a.state().is_err());
            assert!(
                a.mine_current(
                    Body::new(&f.genesis.domain(), &[]).unwrap(),
                    [0; 32],
                    [1; 32],
                    None
                )
                .is_err()
            );
            assert!(!lab.join("node-a/ACTIVE_JOB").exists());
        }
        settle(&mut a);
        if (i + 1) % 8 == 0 {
            println!(
                "a_received_b={};elapsed_ms={}",
                i + 1,
                started.elapsed().as_millis()
            );
        }
    }
    assert!(saw_deep);
    winner(&a, shared, a_only, b_only);
    assert_eq!(a.state().unwrap().checkpoint_id(), b_checkpoint);
    for bytes in &all_a {
        b.ingest(bytes, &parameters).unwrap();
        settle(&mut b);
        assert_eq!(b.state().unwrap().checkpoint_id(), b_checkpoint);
    }
    assert_eq!(a.vertex_count(), 112);
    assert_eq!(b.vertex_count(), 112);
    parity(&a, &b);
    assert!(
        scan(
            a.state().unwrap(),
            recipient_a.to_diversifiable_full_viewing_key().fvk()
        )
        .unwrap()
        .is_empty()
    );
    let received = scan(
        a.state().unwrap(),
        recipient_b.to_diversifiable_full_viewing_key().fvk(),
    )
    .unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].note.value().inner(), 60);
    let mut parent_ids = vec![VertexId::from_bytes(tip_a), VertexId::from_bytes(tip_b)];
    parent_ids.sort();
    let merge = a
        .mine_candidate(
            Body::new(&f.genesis.domain(), &[]).unwrap(),
            [12; 32],
            [65; 32],
            Some(Sg0ParentSetV1::vertices(parent_ids).unwrap()),
            f.genesis.timestamp() + 65 * 40,
        )
        .unwrap();
    // The nonzero B frontier is NOT common to both independent parents.
    assert_eq!(merge.header.source_index, 0);
    for node in [&mut a, &mut b] {
        node.ingest(&merge.encode(), &parameters).unwrap();
        settle(node);
    }
    for i in 66_u64..=72 {
        let mut reward = [0; 32];
        reward[..8].copy_from_slice(&i.to_le_bytes());
        let work = a
            .mine_candidate(
                Body::new(&f.genesis.domain(), &[]).unwrap(),
                [12; 32],
                reward,
                None,
                f.genesis.timestamp() + i * 40,
            )
            .unwrap();
        assert_eq!(work.header.source_index, 4);
        for node in [&mut a, &mut b] {
            node.ingest(&work.encode(), &parameters).unwrap();
            settle(node);
        }
    }
    parity(&a, &b);
    winner(&a, shared, a_only, b_only);
    assert_eq!(a.vertex_count(), 120);
    assert_eq!(a.state().unwrap().checkpoint_index(), 9);
    assert_eq!(a.state().unwrap().executed().len(), 72);
    assert_eq!(a.state().unwrap().public_balance(&[11; 32]).0, 640);
    assert_eq!(a.state().unwrap().public_balance(&[12; 32]).0, 80);
    a.flush_clock().unwrap();
    b.flush_clock().unwrap();
    let checkpoint = a.state().unwrap().checkpoint_bytes().to_vec();
    drop(a);
    drop(b);
    let a =
        Node::open_retained(&lab.join("node-a"), &margin, f.genesis.clone(), &parameters).unwrap();
    let b = Node::open_retained(&lab.join("node-b"), &margin, f.genesis, &parameters).unwrap();
    assert_eq!(a.state().unwrap().checkpoint_bytes(), checkpoint);
    parity(&a, &b);
    winner(&a, shared, a_only, b_only);
    println!(
        "fork_path_ms={};graph=120;executed=72;checkpoint=9;deep_reorg=true;no_nf_union=true;merge_common_source=true;same_process_retained_replay=true",
        started.elapsed().as_millis()
    );
}
