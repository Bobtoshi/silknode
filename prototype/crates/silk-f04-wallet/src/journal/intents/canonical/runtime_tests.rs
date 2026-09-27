//! Genuine local integration. Colocated wallet/node roles are not secret isolation.
use super::*;
use crate::journal::intents::{
    field,
    tests::{qualified_paths, save_public_fixture},
};
use crate::{backup, journal::Journal};
use silk_f04_node::{carriage::Body, genesis::Genesis, node::NodeStatus};
use silk_sapling_f04::codec::Envelope;
use std::{os::unix::fs::PermissionsExt, path::Path, time::Instant};

const PASSWORD: &str = "PUBLIC CANONICAL RUNTIME TEST PASSWORD";

mod live_relay;

pub(super) fn checkpoint(
    node: &mut Node,
    parameters: &SaplingParameters,
    envelope: Option<&Envelope>,
) {
    checkpoint_owned(node, parameters, envelope, [0; 32]);
}
pub(super) fn checkpoint_owned(
    node: &mut Node,
    parameters: &SaplingParameters,
    envelope: Option<&Envelope>,
    owner: Digest,
) {
    for slot in 0..8 {
        let entries = if slot == 0 {
            envelope.into_iter().cloned().collect::<Vec<_>>()
        } else {
            vec![]
        };
        let body = Body::new(&node.genesis().domain(), &entries).unwrap();
        let timestamp = node.genesis().timestamp() + 40 * (node.vertex_count() as u64 + 1);
        let candidate = node
            .mine_candidate(body, owner, [71; 32], None, timestamp)
            .unwrap();
        node.ingest(&candidate.encode(), parameters).unwrap();
        for _ in 0..512 {
            if node.status().unwrap() == NodeStatus::Ready {
                break;
            }
            node.advance().unwrap();
        }
        assert_eq!(node.status().unwrap(), NodeStatus::Ready);
    }
}

fn verify_accepted(intents: &mut IntentJournal<'_, '_>, node: &Node, signed: &Envelope) {
    assert_eq!(
        intents.observe_from_node(node).unwrap(),
        Observation::AcceptedEffect
    );
    assert!(node.state().unwrap().contains_effect(&signed.effect_id()));
    assert!(
        signed
            .nullifiers()
            .iter()
            .all(|nf| node.state().unwrap().contains_nullifier(nf))
    );
    let inventory = intents.journal.key.inventory_from_node(node).unwrap();
    assert_eq!(inventory.notes.len(), 3);
    assert_eq!(inventory.notes[0].status, NoteStatus::Spent);
    assert_eq!(inventory.notes[1].status, NoteStatus::Spent);
    assert_eq!(inventory.notes[2].status, NoteStatus::PendingCut);
    assert_eq!(inventory.notes[2].note.value().inner(), 1);
    let incoming = incoming_from_node(
        node,
        intents.journal.key.domain(),
        &sapling_crypto::keys::PreparedIncomingViewingKey::new(
            &intents
                .journal
                .key
                .key
                .to_diversifiable_full_viewing_key()
                .fvk()
                .vk
                .ivk(),
        ),
    )
    .unwrap();
    assert_eq!(incoming.notes.len(), 3);
    assert_eq!(
        incoming.notes[0].cut_status,
        silk_f04_node::scanner::IncomingCutStatus::IncludedEligible
    );
    assert_eq!(
        incoming.notes[1].cut_status,
        silk_f04_node::scanner::IncomingCutStatus::IncludedEligible
    );
    assert_eq!(
        incoming.notes[2].cut_status,
        silk_f04_node::scanner::IncomingCutStatus::PendingCut
    );
    assert!(incoming.notes.iter().all(|note| note.memo == [0; 512]));
    let outgoing = intents.journal.key.outgoing_from_node(node).unwrap();
    assert_eq!(outgoing.notes.len(), 2);
    let plan = intents.state.plan.as_ref().unwrap();
    assert!(
        outgoing
            .notes
            .iter()
            .any(|n| n.address == plan.recipient && n.note.value().inner() == 8)
    );
    assert!(
        outgoing
            .notes
            .iter()
            .any(|n| n.address == plan.change && n.note.value().inner() == 1)
    );
    assert!(
        outgoing
            .notes
            .iter()
            .all(|n| n.effect == signed.effect_id() && n.memo == [0; 512])
    );
    assert_eq!(node.state().unwrap().accepted_outputs().len(), 1);
    verify_outgoing_stream(intents, node, &outgoing);
    assert_eq!(
        intents.receipt().unwrap().status,
        IntentStatus::MayHaveEscaped
    );
    assert!(intents.cancel_before_release().is_err());
}

fn verify_outgoing_stream(
    intents: &IntentJournal<'_, '_>,
    node: &Node,
    outgoing: &OutgoingInventory,
) {
    let mut seen = 0;
    let receipt = visit_outgoing_from_node(
        node,
        intents.journal.key.domain(),
        &intents
            .journal
            .key
            .key
            .to_diversifiable_full_viewing_key()
            .fvk()
            .ovk,
        |note| {
            let prior = &outgoing.notes[seen];
            assert_eq!(note.note, prior.note);
            assert_eq!(note.address, prior.address);
            assert_eq!(note.position, prior.position);
            assert_eq!(note.effect, prior.effect);
            assert_eq!(note.memo, prior.memo);
            seen += 1;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!((receipt.walk.scanned(), receipt.walk.matched()), (2, 2));
    assert_eq!(seen, 2);
    assert_eq!(receipt.local_head, outgoing.local_head);
    assert_eq!(
        context_bytes(receipt.context),
        context_bytes(outgoing.context)
    );
    let mut failed_seen = 0;
    let incomplete = visit_outgoing_from_node(
        node,
        intents.journal.key.domain(),
        &intents
            .journal
            .key
            .key
            .to_diversifiable_full_viewing_key()
            .fvk()
            .ovk,
        |_| {
            failed_seen += 1;
            Err(silk_f04_node::Error::Paused("test outgoing sink full"))
        },
    );
    assert!(incomplete.is_err());
    assert_eq!(failed_seen, 1);
}

fn retain_accepted(lab: &Path, intents: &IntentJournal<'_, '_>, node: &Node, signed: &Envelope) {
    let receipt = intents.receipt().unwrap();
    let mut b = Vec::from(intents.journal.key.domain());
    for value in [
        receipt.address_head,
        receipt.intent_head,
        node.local_head().unwrap(),
        node.state().unwrap().digest(),
        node.state().unwrap().checkpoint_id(),
        signed.effect_id(),
        signed.envelope_id(),
    ] {
        b.extend_from_slice(&value);
    }
    assert_eq!(b.len(), 256);
    save_public_fixture(lab, "accepted-pins", &b);
}

#[test]
#[ignore = "qualified four-task node runtime; colocated roles, genuine proofs/work"]
fn genuine_canonical_reservation_acceptance() {
    let started = Instant::now();
    let (store, margin, parameters) = qualified_paths();
    let lab = tempfile::Builder::new()
        .prefix("f04-canonical-wallet-")
        .tempdir_in(store)
        .unwrap()
        .keep();
    std::fs::set_permissions(&lab, std::fs::Permissions::from_mode(0o700)).unwrap();
    println!("retained_lab={};roles=colocated-test-only", lab.display());
    let fixture = super::node_fixture::fixture_shared_key(&[6, 4]);
    let mut key = WalletKey {
        domain: fixture.genesis.domain(),
        key: fixture.keys[0].clone(),
        first_use: true,
    };
    backup::save_new(&lab.join("encrypted-key"), &key, PASSWORD).unwrap();
    save_public_fixture(&lab, "public-genesis", &fixture.genesis.local_bundle());
    let mut node = Node::create(&lab.join("node"), &margin, fixture.genesis).unwrap();
    let recipient = silk_sapling_f04::address::encode(
        &key.domain,
        &crate::FreshKey::generate().unwrap().initial_address(),
    );
    let (mut journal, pin) =
        Journal::create_with_intents(&lab.join("wallet"), &margin, &mut key, PASSWORD).unwrap();
    let mut intents = journal.intents(pin).unwrap();
    let reserved = intents.reserve_from_node(&node, &recipient, 8).unwrap();
    assert_eq!(intents.state.plan.as_ref().unwrap().inputs.len(), 2);
    checkpoint(&mut node, &parameters, None);
    assert!(intents.prove_from_node(&node, &parameters).is_err());
    assert_eq!(intents.receipt().unwrap().intent_head, reserved.intent_head);
    intents.cancel_before_release().unwrap();
    intents.reserve_from_node(&node, &recipient, 8).unwrap();
    let exposed = intents.prove_from_node(&node, &parameters).unwrap();
    let mut pins = Vec::from(intents.journal.key.domain());
    pins.extend_from_slice(&exposed.address_head);
    pins.extend_from_slice(&exposed.intent_head);
    save_public_fixture(&lab, "wallet-pins-before-export", &pins);
    let bytes = intents.release_saved_envelope(exposed.intent_head).unwrap();
    let signed = Envelope::decode(&bytes, &node.genesis().domain()).unwrap();
    assert_eq!(
        intents.observe_from_node(&node).unwrap(),
        Observation::Unresolved
    );
    checkpoint(&mut node, &parameters, Some(&signed));
    verify_accepted(&mut intents, &node, &signed);
    assert!(intents.reserve_from_node(&node, &recipient, 4).is_err());
    retain_accepted(&lab, &intents, &node, &signed);
    println!(
        "canonical_wallet_ms={};vertices={};checkpoint={};effect_accepted=true;changed_context_refused=true;relay_submission=false",
        started.elapsed().as_millis(),
        node.vertex_count(),
        node.state().unwrap().checkpoint_index()
    );
}

#[test]
#[ignore = "separate cold process after genuine_canonical_reservation_acceptance"]
fn cold_complete_node_and_wallet_recovery() {
    let (_store, margin, parameters) = qualified_paths();
    let lab = std::path::PathBuf::from(std::env::var_os("SILK_F04_WALLET_FIXTURE").unwrap());
    let pins = std::fs::read(lab.join("accepted-pins")).unwrap();
    assert_eq!(pins.len(), 256);
    let domain = field(&pins, 0);
    let genesis = Genesis::admit_local_bundle(
        &std::fs::read(lab.join("public-genesis")).unwrap(),
        &domain,
        true,
    )
    .unwrap();
    let node = Node::open_retained_pinned(
        &lab.join("node"),
        &margin,
        genesis,
        &parameters,
        field(&pins, 96),
    )
    .unwrap();
    assert_eq!(node.state().unwrap().digest(), field::<32>(&pins, 128));
    assert_eq!(
        node.state().unwrap().checkpoint_id(),
        field::<32>(&pins, 160)
    );
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
    let bytes = intents.release_saved_envelope(field(&pins, 64)).unwrap();
    let signed = Envelope::decode(&bytes, &domain).unwrap();
    assert_eq!(signed.effect_id(), field::<32>(&pins, 192));
    assert_eq!(signed.envelope_id(), field::<32>(&pins, 224));
    silk_sapling_f04::crypto::verify(signed.clone(), &parameters).unwrap();
    verify_accepted(&mut intents, &node, &signed);
    println!(
        "cold_pid={};complete_local_history=true;encrypted_key_and_pending_recovered=true;roles=colocated-test-only;multi_payment_recovery=false",
        std::process::id()
    );
}
