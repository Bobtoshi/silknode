//! Real two-payment reorg, not a network-privacy or valuable-asset experiment.
use super::runtime_tests::{checkpoint, checkpoint_owned};
use super::*;
use crate::journal::intents::{
    field,
    tests::{qualified_paths, save_public_fixture},
};
use crate::{backup, journal::Journal};
use silk_f04_node::{genesis::Genesis, node::NodeStatus};
use silk_sapling_f04::codec::Envelope;
use std::{os::unix::fs::PermissionsExt, path::Path, time::Instant};
const PASSWORD: &str = "PUBLIC REORG WALLET FIXTURE PASSWORD";
// Distinct canonical scalar owner: high LE byte0x0b is below modulus high0x40.
const WINNING_OWNER: Digest = [11; 32];

fn payment(
    lab: &Path,
    intents: &mut IntentJournal<'_, '_>,
    node: &mut Node,
    params: &SaplingParameters,
    recipient: &str,
    value: u64,
    distinct: bool,
) -> Envelope {
    if distinct {
        intents
            .reserve_distinct_from_node(node, recipient, value)
            .unwrap();
    } else {
        intents.reserve_from_node(node, recipient, value).unwrap();
    }
    let receipt = intents.prove_from_node(node, params).unwrap();
    let mut pins = Vec::from(receipt.address_head);
    pins.extend_from_slice(&receipt.intent_head);
    save_public_fixture(
        lab,
        if distinct {
            "payment-b-pins"
        } else {
            "payment-a-pins"
        },
        &pins,
    );
    let signed = Envelope::decode(
        &intents.release_saved_envelope(receipt.intent_head).unwrap(),
        &node.genesis().domain(),
    )
    .unwrap();
    checkpoint(node, params, Some(&signed));
    assert_eq!(
        intents.observe_from_node(node).unwrap(),
        Observation::AcceptedEffect
    );
    signed
}

fn check_old_inputs(
    intents: &mut IntentJournal<'_, '_>,
    node: &Node,
    recipient: &str,
    distinct: bool,
) {
    let before = intents.receipt().unwrap();
    let snapshot = Snapshot::new(node, intents.journal.key).unwrap();
    let inventory = snapshot.inventory(intents.journal.key).unwrap();
    assert_eq!(inventory.notes.len(), 3);
    assert!(
        inventory
            .notes
            .iter()
            .all(|note| note.status == NoteStatus::SpendableAtCut)
    );
    for position in [0, 1] {
        let inputs = snapshot.inputs(&inventory.notes, &[position]).unwrap();
        let attempted = if distinct {
            intents.reserve_distinct(snapshot.context, &inputs, recipient, 1)
        } else {
            intents.reserve(snapshot.context, &inputs, recipient, 1)
        };
        assert!(matches!(
            attempted,
            Err(Error::Unavailable(
                "historically exposed input remains reserved"
            ))
        ));
    }
    let attempted = if distinct {
        intents.reserve_distinct_from_node(node, recipient, 5)
    } else {
        intents.reserve_from_node(node, recipient, 5)
    };
    assert!(matches!(
        attempted,
        Err(Error::Unavailable(
            "insufficient spendable funding within two-input limit"
        ))
    ));
    assert_eq!(intents.receipt().unwrap().intent_head, before.intent_head);
    assert_eq!(intents.receipt().unwrap().address_head, before.address_head);
    assert_eq!(intents.exposed.len(), 2); // Real selected inputs, not either generated dummy.
}

fn save_reorg_pins(lab: &Path, intents: &IntentJournal<'_, '_>, node: &Node) {
    let receipt = intents.receipt().unwrap();
    let mut pins = Vec::from(node.genesis().domain());
    for p in [
        receipt.address_head,
        receipt.intent_head,
        node.local_head().unwrap(),
        node.state().unwrap().digest(),
    ] {
        pins.extend_from_slice(&p);
    }
    save_public_fixture(lab, "reorg-pins", &pins);
}
fn sync_winning_branch(losing: &mut Node, winning: &Node, params: &SaplingParameters) -> bool {
    let mut deep = false;
    for start in [0, 32] {
        for bytes in winning.export_range(start, 32).unwrap() {
            losing.ingest(&bytes, params).unwrap();
            if losing.status().unwrap() == NodeStatus::ArchiveReplay {
                deep = true;
                assert!(losing.state().is_err());
            }
            for _ in 0..512 {
                if losing.status().unwrap() == NodeStatus::Ready {
                    break;
                }
                losing.advance().unwrap();
            }
            assert_eq!(losing.status().unwrap(), NodeStatus::Ready);
        }
    }
    deep
}
fn verify_rollback(
    intents: &mut IntentJournal<'_, '_>,
    losing: &Node,
    winning: &Node,
    payments: [&Envelope; 2],
) {
    assert_eq!(losing.vertex_count(), 112);
    assert_eq!(
        losing.state().unwrap().executed(),
        winning.state().unwrap().executed()
    );
    assert_eq!(losing.state().unwrap().checkpoint_index(), 8);
    assert_eq!(losing.state().unwrap().private_counters(), (15, 0));
    assert_eq!(
        losing.state().unwrap().recovery(),
        winning.state().unwrap().recovery()
    );
    for signed in payments {
        assert!(!losing.state().unwrap().contains_effect(&signed.effect_id()));
        assert!(
            signed
                .nullifiers()
                .iter()
                .all(|nf| !losing.state().unwrap().contains_nullifier(nf))
        );
    }
    assert_eq!(
        intents.observe_from_node(losing).unwrap(),
        Observation::Unresolved
    );
    assert!(losing.state().unwrap().accepted_outputs().is_empty());
    assert!(
        intents
            .journal
            .key
            .outgoing_from_node(losing)
            .unwrap()
            .notes
            .is_empty()
    );
}

#[test]
#[ignore = "qualified genuine112-vertex/two-proof reorg under the node runtime"]
fn genuine_sequential_payments_keep_exposed_inputs_after_reorg() {
    let started = Instant::now();
    let (store, margin, params) = qualified_paths();
    let lab = tempfile::Builder::new()
        .prefix("f04-wallet-reorg-")
        .tempdir_in(store)
        .unwrap()
        .keep();
    std::fs::set_permissions(&lab, std::fs::Permissions::from_mode(0o700)).unwrap();
    println!("retained_lab={};roles=colocated-test-only", lab.display());
    let fixture = node_fixture::fixture_shared_key(&[6, 7, 2]);
    let mut key = WalletKey {
        domain: fixture.genesis.domain(),
        key: fixture.keys[0].clone(),
        first_use: true,
    };
    backup::save_new(&lab.join("encrypted-key"), &key, PASSWORD).unwrap();
    save_public_fixture(&lab, "public-genesis", &fixture.genesis.local_bundle());
    let mut losing = Node::create(&lab.join("losing"), &margin, fixture.genesis.clone()).unwrap();
    let mut winning = Node::create(&lab.join("winning"), &margin, fixture.genesis).unwrap();
    let recipient = silk_sapling_f04::address::encode(
        &key.domain,
        &crate::FreshKey::generate().unwrap().initial_address(),
    );
    let (mut journal, pin) =
        Journal::create_with_intents(&lab.join("wallet"), &margin, &mut key, PASSWORD).unwrap();
    let mut intents = journal.intents(pin).unwrap();
    let a = payment(
        &lab,
        &mut intents,
        &mut losing,
        &params,
        &recipient,
        5,
        false,
    );
    let b = payment(
        &lab,
        &mut intents,
        &mut losing,
        &params,
        &recipient,
        6,
        true,
    );
    assert_eq!(
        intents
            .journal
            .key
            .outgoing_from_node(&losing)
            .unwrap()
            .notes
            .len(),
        4
    );
    assert_eq!(losing.state().unwrap().accepted_outputs().len(), 2);
    for _ in 0..4 {
        checkpoint(&mut losing, &params, None);
    }
    assert_eq!(losing.vertex_count(), 48);
    println!("losing48_ms={}", started.elapsed().as_millis());
    for _ in 0..8 {
        checkpoint_owned(&mut winning, &params, None, WINNING_OWNER);
    }
    println!("winning64_ms={}", started.elapsed().as_millis());
    assert!(sync_winning_branch(&mut losing, &winning, &params));
    verify_rollback(&mut intents, &losing, &winning, [&a, &b]);
    check_old_inputs(&mut intents, &losing, &recipient, true);
    intents
        .reserve_distinct_from_node(&losing, &recipient, 1)
        .unwrap();
    assert_eq!(intents.state.plan.as_ref().unwrap().inputs[0].position, 2);
    intents.cancel_before_release().unwrap();
    check_old_inputs(&mut intents, &losing, &recipient, false);
    save_reorg_pins(&lab, &intents, &losing);
    println!(
        "wallet_reorg_ms={};genuine_payments=2;graph=112;deep_reorg=true;exclusions_survive_cancellation=true;privacy=false",
        started.elapsed().as_millis()
    );
}

#[test]
#[ignore = "separate cold process after genuine_sequential_payments_keep_exposed_inputs_after_reorg"]
fn cold_sequential_history_recovery_after_reorg() {
    let (_store, margin, parameters) = qualified_paths();
    let lab = std::path::PathBuf::from(std::env::var_os("SILK_F04_WALLET_FIXTURE").unwrap());
    let pins = std::fs::read(lab.join("reorg-pins")).unwrap();
    assert_eq!(pins.len(), 160);
    let domain = field(&pins, 0);
    let genesis = Genesis::admit_local_bundle(
        &std::fs::read(lab.join("public-genesis")).unwrap(),
        &domain,
        true,
    )
    .unwrap();
    let node = Node::open_retained_pinned(
        &lab.join("losing"),
        &margin,
        genesis,
        &parameters,
        field(&pins, 96),
    )
    .unwrap();
    assert_eq!(node.state().unwrap().digest(), field::<32>(&pins, 128));
    let key = backup::load(&lab.join("encrypted-key"), domain, PASSWORD).unwrap();
    let mut journal = Journal::open(
        &lab.join("wallet"),
        &margin,
        &key,
        PASSWORD,
        field(&pins, 32),
    )
    .unwrap();
    let mut intents = journal.intents(field(&pins, 64)).unwrap();
    assert_eq!(
        intents.receipt().unwrap().status,
        IntentStatus::CancelledBeforeRelease
    );
    let recipient = silk_sapling_f04::address::encode(&domain, &key.key.default_address().1);
    check_old_inputs(&mut intents, &node, &recipient, false);
    println!(
        "cold_pid={};complete_history=true;two_historical_exposures_preserved=true;ledger_unspent_does_not_release_exposure=true",
        std::process::id()
    );
}
