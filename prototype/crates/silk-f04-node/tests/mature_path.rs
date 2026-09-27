//! Genuine finite-horizon cut maturity; colocated roles are not a privacy trial.
mod common;
use common::fixture;
use rand_core::{OsRng, RngCore};
use sapling_crypto::{CommitmentTree, IncrementalWitness, MerklePath, zip32::ExtendedSpendingKey};
use silk_f04_node::{
    carriage::Body,
    node::{Node, NodeStatus},
    scanner::{NoteStatus, scan, witness_at_cut},
    state::{BranchState, Cut},
};
use silk_sapling_f04::{
    parameters::SaplingParameters,
    wallet::{PaymentOutput, SpendInput, build_transfer},
};
use std::{path::PathBuf, time::Instant};

fn settle(node: &mut Node) {
    if node.status().unwrap() != NodeStatus::Ready {
        node.advance().unwrap();
    }
    assert_eq!(node.status().unwrap(), NodeStatus::Ready);
}
fn fresh_key() -> ExtendedSpendingKey {
    let mut seed = [0; 32];
    OsRng.fill_bytes(&mut seed);
    ExtendedSpendingKey::master(&seed)
}

// Independent test-only standard witness construction deliberately has no wallet
// maturity policy. The unchanged public wallet helper must still refuse it early.
fn fixture_witness(state: &BranchState, cut: &Cut, position: u64) -> MerklePath {
    let mut tree = CommitmentTree::empty();
    let mut witness: Option<IncrementalWitness> = None;
    for (i, entry) in state
        .recovery()
        .iter()
        .take(cut.leaves as usize)
        .enumerate()
    {
        let cm = Option::<sapling_crypto::Node>::from(sapling_crypto::Node::from_bytes(
            entry[..32].try_into().unwrap(),
        ))
        .unwrap();
        tree.append(cm).unwrap();
        if let Some(w) = &mut witness {
            w.append(cm).unwrap();
        }
        if i as u64 == position {
            witness = IncrementalWitness::from_tree(tree.clone());
        }
    }
    assert_eq!(tree.size() as u64, cut.leaves);
    assert_eq!(tree.root().to_bytes(), cut.root);
    witness.unwrap().path().unwrap()
}

#[test]
#[ignore = "requires canonical parameters and qualified isolated finite-horizon genuine-work runtime"]
fn genuine_cut_one_matures_and_recipient_respends_then_recovers() {
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
        .prefix("f04-mature-path-")
        .tempdir_in(store_parent)
        .unwrap()
        .keep();
    println!("retained_lab={}; roles=colocated-test-only", lab.display());
    let f = fixture(&[100, 200]);
    let mut node = Node::create(&lab.join("node-a"), &margin, f.genesis.clone()).unwrap();
    let recipient = fresh_key();
    let change = fresh_key();
    let child_recipient = fresh_key();
    let cut0 = node.state().unwrap().eligible_cut().clone();
    let initial = build_transfer(
        cut0.reference(f.genesis.domain()),
        (0..2)
            .map(|i| SpendInput {
                key: f.keys[i].clone(),
                note: f.notes[i].clone(),
                path: witness_at_cut(node.state().unwrap(), &cut0, i as u64).unwrap(),
            })
            .collect(),
        [
            PaymentOutput {
                address: recipient.default_address().1,
                value: 149,
            },
            PaymentOutput {
                address: change.default_address().1,
                value: 150,
            },
        ],
        &parameters,
    )
    .unwrap();
    let mut child = None;
    for i in 1_u64..=3072 {
        let body = Body::new(
            &f.genesis.domain(),
            if i == 1 {
                std::slice::from_ref(initial.envelope())
            } else if i == 3065 {
                std::slice::from_ref(child.as_ref().unwrap())
            } else {
                &[]
            },
        )
        .unwrap();
        let mut reward = [0; 32];
        reward[..8].copy_from_slice(&i.to_le_bytes());
        // A historical fixture with slow timestamps keeps legitimate DAA work=1.
        // This is not a wall-clock throughput experiment or a work substitution.
        let work = node
            .mine_candidate(body, [0; 32], reward, None, f.genesis.timestamp() + i * 40)
            .unwrap();
        assert_eq!(work.header.work, 1);
        node.ingest(&work.encode(), &parameters).unwrap();
        settle(&mut node);
        if i % 128 == 0 {
            println!(
                "vertices={i}; checkpoint={}; elapsed_ms={}",
                node.state().unwrap().checkpoint_index(),
                started.elapsed().as_millis()
            );
        }
        if i == 1024 || i == 3064 {
            let state = node.state().unwrap();
            assert_eq!(state.eligible_cut().index, 0);
            let notes = scan(state, recipient.to_diversifiable_full_viewing_key().fvk()).unwrap();
            assert_eq!(notes.len(), 1);
            assert_eq!(notes[0].note.value().inner(), 149);
            assert_eq!(notes[0].status, NoteStatus::IncludedImmature);
            assert!(witness_at_cut(state, &state.cuts()[1], notes[0].position).is_err());
            assert_eq!(state.cuts()[1].leaves, 4);
            if i == 3064 {
                let cut = &state.cuts()[1];
                child = Some(
                    build_transfer(
                        cut.reference(f.genesis.domain()),
                        vec![SpendInput {
                            key: recipient.clone(),
                            note: notes[0].note.clone(),
                            path: fixture_witness(state, cut, notes[0].position),
                        }],
                        [
                            PaymentOutput {
                                address: child_recipient.default_address().1,
                                value: 70,
                            },
                            PaymentOutput {
                                address: change.default_address().1,
                                value: 78,
                            },
                        ],
                        &parameters,
                    )
                    .unwrap()
                    .envelope()
                    .clone(),
                );
            }
        }
    }
    let state = node.state().unwrap();
    assert_eq!(state.checkpoint_index(), 384);
    let cut1 = state.eligible_cut().clone();
    assert_eq!(cut1.index, 1); // eligible for the NEXT checkpoint, 385
    assert_eq!(state.private_counters(), (299, 1));
    let notes = scan(state, recipient.to_diversifiable_full_viewing_key().fvk()).unwrap();
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].status, NoteStatus::SpendableAtCut);
    let child = child.unwrap();
    assert_eq!(child.anchor(), cut1.root);
    assert_eq!(state.leaves(), 4);
    for nf in child.nullifiers() {
        assert!(!state.contains_nullifier(&nf));
    }
    witness_at_cut(state, &cut1, notes[0].position).unwrap();
    for i in 3073_u64..=3080 {
        let body = Body::new(
            &f.genesis.domain(),
            if i == 3073 {
                std::slice::from_ref(&child)
            } else {
                &[]
            },
        )
        .unwrap();
        let mut reward = [0; 32];
        reward[..8].copy_from_slice(&i.to_le_bytes());
        let work = node
            .mine_candidate(body, [0; 32], reward, None, f.genesis.timestamp() + i * 40)
            .unwrap();
        assert_eq!(work.header.work, 1);
        node.ingest(&work.encode(), &parameters).unwrap();
        settle(&mut node);
        if i < 3080 {
            assert_eq!(node.state().unwrap().checkpoint_index(), 384);
            assert_eq!(node.state().unwrap().private_counters(), (299, 1));
        }
    }
    let state = node.state().unwrap();
    assert_eq!(state.checkpoint_index(), 385);
    assert_eq!(state.private_counters(), (298, 2));
    assert_eq!(state.leaves(), 6);
    assert_eq!(state.public_balance(&[0; 32]), (30_800, 30_640));
    let mut change_values: Vec<_> = scan(state, change.to_diversifiable_full_viewing_key().fvk())
        .unwrap()
        .iter()
        .map(|n| n.note.value().inner())
        .collect();
    change_values.sort_unstable();
    assert_eq!(change_values, [78, 150]);
    assert_eq!(
        scan(state, recipient.to_diversifiable_full_viewing_key().fvk()).unwrap()[0].status,
        NoteStatus::Spent
    );
    let received = scan(
        state,
        child_recipient.to_diversifiable_full_viewing_key().fvk(),
    )
    .unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].note.value().inner(), 70);
    assert_eq!(received[0].status, NoteStatus::PendingCut);
    let expected = state.checkpoint_bytes().to_vec();
    let cuts = state.cuts().to_vec();
    node.flush_clock().unwrap();
    drop(node);
    println!(
        "mature_respended_ms={}; beginning_retained_replay",
        started.elapsed().as_millis()
    );
    let mut node =
        Node::open_retained(&lab.join("node-a"), &margin, f.genesis.clone(), &parameters).unwrap();
    assert!(!node.recovered_previous());
    assert_eq!(node.vertex_count(), 3080);
    assert_eq!(node.state().unwrap().executed().len(), 3080);
    assert_eq!(node.state().unwrap().cuts(), cuts);
    assert_eq!(node.state().unwrap().checkpoint_bytes(), expected);
    let mut peer = Node::create(&lab.join("node-b"), &margin, f.genesis.clone()).unwrap();
    for start in (0..3080).step_by(32) {
        for bytes in node.export_range(start, 32).unwrap() {
            peer.ingest(&bytes, &parameters).unwrap();
            settle(&mut peer);
        }
    }
    assert_eq!(peer.state().unwrap().checkpoint_bytes(), expected);
    assert_eq!(
        scan(
            peer.state().unwrap(),
            recipient.to_diversifiable_full_viewing_key().fvk()
        )
        .unwrap()[0]
            .status,
        NoteStatus::Spent
    );
    assert_eq!(
        scan(
            peer.state().unwrap(),
            child_recipient.to_diversifiable_full_viewing_key().fvk()
        )
        .unwrap()[0]
            .note
            .value()
            .inner(),
        70
    );
    peer.flush_clock().unwrap();
    node.flush_clock().unwrap();
    println!(
        "mature_path_ms={}; vertices=3080; checkpoint=385; fixture_recipient_respends=1; immature_effect_refused=true; same_process_retained_reopen=true; full_sync=true",
        started.elapsed().as_millis()
    );
}
