//! Exactly one genuine proof, one relay-delivered checkpoint, then separate cold
//! sender AND recipient recovery. These functions never substitute prep for delivery.
use super::*;

fn retained_lab() -> std::path::PathBuf {
    std::env::var_os("SILK_F04_RELAY_WALLET_FIXTURE")
        .map(std::path::PathBuf::from)
        .expect("explicit retained relay wallet fixture")
}
fn payment(path: &Path) -> [u8; 2790] {
    let bytes = std::fs::read(path).unwrap();
    bytes
        .try_into()
        .expect("one exact delivered2790-byte envelope")
}

#[test]
#[ignore = "qualified private wallet/node prep; one genuine proof, no relay claim"]
fn prepare_one_relay_payment() {
    let (store, margin, parameters) = qualified_paths();
    let lab = tempfile::Builder::new()
        .prefix("f04-relay-wallet-")
        .tempdir_in(store)
        .unwrap()
        .keep();
    std::fs::set_permissions(&lab, std::fs::Permissions::from_mode(0o700)).unwrap();
    println!(
        "retained_lab={};one_proof_only=true;relay_submission=false",
        lab.display()
    );
    let fixture = super::super::node_fixture::fixture_shared_key(&[6, 4]);
    let mut key = WalletKey {
        domain: fixture.genesis.domain(),
        key: fixture.keys[0].clone(),
        first_use: true,
    };
    backup::save_new(&lab.join("encrypted-key"), &key, PASSWORD).unwrap();
    let fresh = crate::FreshKey::generate().unwrap();
    let recipient = silk_sapling_f04::address::encode(&key.domain, &fresh.initial_address());
    let recipient_key = fresh.bind(key.domain);
    backup::save_new(
        &lab.join("recipient-encrypted-key"),
        &recipient_key,
        PASSWORD,
    )
    .unwrap();
    save_public_fixture(&lab, "public-genesis", &fixture.genesis.local_bundle());
    let node = Node::create(&lab.join("node"), &margin, fixture.genesis).unwrap();
    let (mut journal, pin) =
        Journal::create_with_intents(&lab.join("wallet"), &margin, &mut key, PASSWORD).unwrap();
    let mut intents = journal.intents(pin).unwrap();
    intents.reserve_from_node(&node, &recipient, 8).unwrap();
    assert_eq!(intents.state.plan.as_ref().unwrap().inputs.len(), 2);
    let started = Instant::now();
    let exposed = intents.prove_from_node(&node, &parameters).unwrap();
    let proof_ms = started.elapsed().as_millis();
    let mut pins = Vec::from(intents.journal.key.domain());
    pins.extend_from_slice(&exposed.address_head);
    pins.extend_from_slice(&exposed.intent_head);
    save_public_fixture(&lab, "wallet-pins-before-export", &pins);
    save_public_fixture(&lab, "node-head-before-relay", &node.local_head().unwrap());
    let bytes = intents.release_saved_envelope(exposed.intent_head).unwrap();
    assert_eq!(bytes.len(), 2790);
    assert_eq!(
        intents.receipt().unwrap().status,
        IntentStatus::MayHaveEscaped
    );
    assert_eq!(
        intents.observe_from_node(&node).unwrap(),
        Observation::Unresolved
    );
    save_public_fixture(&lab, "payment-2790", &bytes);
    println!(
        "proof_ms={proof_ms};vertices=0;checkpoint=0;exposure_durable_before_export=true;recipient_backup_retained=true;relay_submission=false"
    );
}

#[test]
#[ignore = "after actual three-producer relay delivery; one genuine settlement checkpoint"]
fn settle_exact_producer_payment() {
    let (_store, margin, parameters) = qualified_paths();
    let lab = retained_lab();
    let delivered_root = std::path::PathBuf::from(
        std::env::var_os("SILK_F04_RELAY_DELIVERED").expect("explicit producer output directory"),
    );
    let expected = payment(&lab.join("payment-2790"));
    let delivered = payment(&delivered_root.join("p0-payment-2790"));
    assert_eq!(delivered, expected);
    for name in ["p1-payment-2790", "p2-payment-2790"] {
        assert_eq!(payment(&delivered_root.join(name)), delivered);
    }
    let pins = std::fs::read(lab.join("wallet-pins-before-export")).unwrap();
    assert_eq!(pins.len(), 96);
    let domain = field(&pins, 0);
    let genesis = Genesis::admit_local_bundle(
        &std::fs::read(lab.join("public-genesis")).unwrap(),
        &domain,
        true,
    )
    .unwrap();
    let head: Digest = std::fs::read(lab.join("node-head-before-relay"))
        .unwrap()
        .try_into()
        .unwrap();
    let mut node =
        Node::open_retained_pinned(&lab.join("node"), &margin, genesis, &parameters, head).unwrap();
    assert_eq!(node.vertex_count(), 0);
    let signed = Envelope::decode(&delivered, &domain).unwrap();
    checkpoint(&mut node, &parameters, Some(&signed));
    assert_eq!(node.vertex_count(), 8);
    assert_eq!(node.state().unwrap().checkpoint_index(), 1);
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
        intents
            .release_saved_envelope(field(&pins, 64))
            .unwrap()
            .as_slice(),
        delivered.as_slice()
    );
    verify_accepted(&mut intents, &node, &signed);
    retain_accepted(&lab, &intents, &node, &signed);
    save_public_fixture(&lab, "settled-producer-payment-2790", &delivered);
    println!(
        "settlement_pid={};vertices=8;checkpoint=1;three_producer_bytes_equal=true;actual_producer_copy_settled=true;independent_custody=false",
        std::process::id()
    );
}

#[test]
#[ignore = "distinct cold process after settle_exact_producer_payment"]
fn cold_same_relay_payment_and_both_wallets() {
    let (_store, margin, parameters) = qualified_paths();
    let lab = retained_lab();
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
    let recovered = intents.release_saved_envelope(field(&pins, 64)).unwrap();
    let delivered = payment(&lab.join("settled-producer-payment-2790"));
    assert_eq!(recovered.as_slice(), delivered.as_slice());
    assert_eq!(delivered, payment(&lab.join("payment-2790")));
    let signed = Envelope::decode(&recovered, &domain).unwrap();
    assert_eq!(signed.effect_id(), field::<32>(&pins, 192));
    assert_eq!(signed.envelope_id(), field::<32>(&pins, 224));
    verify_accepted(&mut intents, &node, &signed);
    let recipient = backup::load(&lab.join("recipient-encrypted-key"), domain, PASSWORD).unwrap();
    let recovered_recipient = recipient.inventory_from_node(&node).unwrap();
    assert_eq!(recovered_recipient.notes.len(), 1);
    assert_eq!(recovered_recipient.notes[0].note.value().inner(), 8);
    assert_eq!(recovered_recipient.notes[0].status, NoteStatus::PendingCut);
    assert_eq!(recovered_recipient.notes[0].memo, [0; 512]);
    println!(
        "cold_pid={};same_exact_settled_relay_payment=true;sender_and_recipient_backups_recovered=true;recipient_pending_maturity=true;full_node_replay=true;independent_custody=false",
        std::process::id()
    );
}


// Separate explicitly contained processes call these selectors. The sender
// namespace contains no recipient backup; the recipient namespace contains no
// sender backup or intent journal. Both replay the same fresh accepted node seal.
fn im3_cold_node() -> (std::path::PathBuf, Node, Vec<u8>) {
    let (_store, margin, parameters) = qualified_paths();
    let lab = retained_lab();
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
    assert_eq!(node.status().unwrap(), NodeStatus::Ready);
    assert_eq!(node.vertex_count(), 8);
    assert_eq!(node.state().unwrap().checkpoint_index(), 1);
    assert_eq!(node.state().unwrap().digest(), field::<32>(&pins, 128));
    assert_eq!(
        node.state().unwrap().checkpoint_id(),
        field::<32>(&pins, 160)
    );
    (lab, node, pins)
}

#[test]
#[ignore = "distinct sender-only cold IM3 recovery; no recipient backup, new proof or work"]
fn cold_im3_sender_from_actual_seal() {
    let (lab, node, pins) = im3_cold_node();
    assert!(!lab.join("recipient-encrypted-key").exists());
    let domain = field(&pins, 0);
    let key = backup::load(&lab.join("encrypted-key"), domain, PASSWORD).unwrap();
    let margin = std::path::PathBuf::from(std::env::var_os("SILK_F04_HOST_MARGIN").unwrap());
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
    assert_eq!(
        bytes.as_slice(),
        payment(&lab.join("settled-producer-payment-2790")).as_slice()
    );
    let signed = Envelope::decode(&bytes, &domain).unwrap();
    assert_eq!(signed.effect_id(), field::<32>(&pins, 192));
    assert_eq!(signed.envelope_id(), field::<32>(&pins, 224));
    verify_accepted(&mut intents, &node, &signed);
    println!(
        "cold_sender_pid={};actual_im3_same_payment_and_seal=true;recipient_key_absent=true;new_proofs=0;new_work=0",
        std::process::id()
    );
}

#[test]
#[ignore = "distinct recipient-only cold IM3 recovery; no sender backup/journal, proof or work"]
fn cold_im3_recipient_from_actual_seal() {
    let (lab, node, pins) = im3_cold_node();
    assert!(!lab.join("encrypted-key").exists());
    assert!(!lab.join("wallet").exists());
    let domain = field(&pins, 0);
    let key = backup::load(&lab.join("recipient-encrypted-key"), domain, PASSWORD).unwrap();
    let delivered = payment(&lab.join("settled-producer-payment-2790"));
    let signed = Envelope::decode(&delivered, &domain).unwrap();
    assert_eq!(signed.effect_id(), field::<32>(&pins, 192));
    assert_eq!(signed.envelope_id(), field::<32>(&pins, 224));
    assert!(node.state().unwrap().contains_effect(&signed.effect_id()));
    let inventory = key.inventory_from_node(&node).unwrap();
    assert_eq!(inventory.notes.len(), 1);
    let note = &inventory.notes[0];
    assert_eq!(note.note.value().inner(), 8);
    assert_eq!(note.status, NoteStatus::PendingCut);
    assert_eq!(note.memo, [0; 512]);
    assert_eq!(inventory.local_head, node.local_head().unwrap());
    println!(
        "cold_recipient_pid={};actual_im3_same_payment_and_seal=true;sender_key_and_intent_journal_absent=true;recipient_pending_maturity=true;new_proofs=0;new_work=0",
        std::process::id()
    );
}
