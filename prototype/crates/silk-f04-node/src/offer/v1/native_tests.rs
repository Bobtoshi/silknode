//! Explicit isolated native preparation gate, never a nonce search or new proof.
use super::*;
use crate::{genesis::Genesis, wire::raw_hash};
use std::{fs, path::PathBuf};

fn digest(name: &str) -> Digest {
    hex::decode(std::env::var(name).unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

#[test]
#[ignore = "fresh authenticated public-history copy only; prepares templates, generates no work/proofs or wallet keys"]
fn saved_public_payment_offer_prepares_without_work_or_admission() {
    assert_eq!(
        std::env::var("SILK_F04_OFFER_PREPARE_GATE").as_deref(),
        Ok("1")
    );
    let root = PathBuf::from(std::env::var_os("SILK_F04_OFFER_STORE").unwrap());
    let margin = PathBuf::from(std::env::var_os("SILK_F04_HOST_MARGIN").unwrap());
    let parameter_dir = PathBuf::from(std::env::var_os("SILK_F04_PARAMETER_DIR").unwrap());
    let domain = digest("SILK_F04_NONEMPTY_DOMAIN");
    let source = digest("SILK_F04_NONEMPTY_GENESIS_HASH");
    let pin = digest("SILK_F04_OFFER_PIN");
    let bytes = fs::read(root.join(format!("{}.obj", hex::encode(source)))).unwrap();
    assert_eq!(raw_hash(&bytes), source);
    let genesis = Genesis::admit_local_bundle(&bytes, &domain, true).unwrap();
    let parameters = SaplingParameters::load(
        &parameter_dir.join("sapling-spend.params"),
        &parameter_dir.join("sapling-output.params"),
    )
    .unwrap();
    let mut node =
        Node::open_retained_pinned(&root, &margin, genesis.clone(), &parameters, pin).unwrap();
    assert_eq!(node.status().unwrap(), NodeStatus::Ready);
    assert_eq!(node.vertex_count(), 15);
    let state = node.state().unwrap().manifest();
    let carriers = node.export_range(0, 15).unwrap();
    let mut saved = Vec::new();
    for carrier in &carriers {
        let candidate = Candidate::decode(carrier, &genesis).unwrap();
        saved.extend_from_slice(candidate.body.representations());
    }
    assert!(
        !saved.is_empty(),
        "fixture must contain genuine retained payment bytes"
    );
    let unchanged = |node: &Node| {
        assert_eq!(node.status().unwrap(), NodeStatus::Ready);
        assert_eq!(node.local_head().unwrap(), pin);
        assert_eq!(node.vertex_count(), 15);
        assert_eq!(node.state().unwrap().manifest(), state);
        assert!(!root.join("ACTIVE_JOB").exists());
        assert!(!root.join("ACTIVE_REPLAY").exists());
    };
    let directory_names = || {
        let mut names: Vec<_> = fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        names.sort();
        names
    };
    let before = directory_names();
    assert!(matches!(
        LocalOfferV1::from_local_payloads(domain, vec![])
            .unwrap()
            .prepare_current(&mut node, [7; 32], [8; 32])
            .unwrap(),
        PreparedV1::NoPayment
    ));
    assert_eq!(
        directory_names(),
        before,
        "cover must create no job artifacts"
    );
    unchanged(&node);
    // Repetition exercises maximum framing, NOT valid independent payments or
    // spentness. Only the retained originals were admitted in the old fixture.
    let mut templates = Vec::new();
    for count in [1, 3, 32] {
        let selected: Vec<_> = (0..count).map(|i| saved[i % saved.len()]).collect();
        let expected = LocalOfferV1::from_local_payloads(domain, selected.clone())
            .unwrap()
            .encode_local()
            .unwrap();
        let PreparedV1::Template(template) = LocalOfferV1::decode_local(&expected, domain)
            .unwrap()
            .prepare_current(&mut node, [7; 32], [8; 32])
            .unwrap()
        else {
            panic!("nonempty offer must prepare a template");
        };
        assert_eq!(template.body().bytes(), expected);
        assert_eq!(template.body().representations(), selected);
        assert_eq!(template.header().owner, [7; 32]);
        assert_eq!(template.header().reward_nonce, [8; 32]);
        assert_eq!(template.header().bytes.len(), 592);
        unchanged(&node);
        templates.push(template);
    }
    let foreign = LocalOfferV1::from_local_payloads([72; 32], vec![]).unwrap();
    let before = directory_names();
    assert!(matches!(
        foreign.prepare_current(&mut node, [7; 32], [8; 32]),
        Err(Error::Invalid("local offer foreign node"))
    ));
    assert_eq!(directory_names(), before);
    unchanged(&node);
    drop(node);
    // Owned templates survive their preparing owner; never trusted as validity.
    assert_eq!(templates.len(), 3);
    for (template, count) in templates.iter().zip([1, 3, 32]) {
        assert_eq!(template.body().representations().len(), count);
    }
    let node = Node::open_retained_pinned(&root, &margin, genesis, &parameters, pin).unwrap();
    unchanged(&node);
    assert_eq!(node.export_range(0, 15).unwrap(), carriers);
    println!(
        "offer_prepare_native=true; template_counts=1,3,32; cover_no_job=true; foreign_no_job=true; head_state_graph_unchanged=true; same_process_cold_reopen=true; separate_process_crash=false; new_work=0; new_proofs=0; new_wallet_keys=0; relay_provenance=false; fresh_settlement=false"
    );
}
