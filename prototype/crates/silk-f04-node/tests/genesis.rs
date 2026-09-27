//! Pure canonical genesis/receipt and framing conformance, not node-work acceptance.
mod common;
use common::fixture;
use silk_f04_node::{
    Error,
    carriage::{Body, decode_parents, encode_parents},
    genesis::{Genesis, parameter_bytes},
    state::BranchState,
};
use silk_order::sg0_v1::Sg0ParentSetV1;

#[test]
fn real_encrypted_fixture_genesis_receipt_and_state_repeat_exactly() {
    let f = fixture(&[10, 20]);
    assert_eq!(f.keys.len(), 2);
    assert_eq!(f.notes.len(), 2);
    let repeated = Genesis::admit(
        &f.descriptor,
        &parameter_bytes(),
        &f.allocation,
        &f.policy,
        &f.receipt,
        true,
    )
    .unwrap();
    assert_eq!(f.genesis.domain(), repeated.domain());
    let bundle = f.genesis.local_bundle();
    let bundled = Genesis::admit_local_bundle(&bundle, &f.genesis.domain(), true).unwrap();
    assert_eq!(bundled.local_bundle(), bundle);
    assert!(Genesis::admit_local_bundle(&bundle, &[0; 32], true).is_err());
    assert!(Genesis::admit_local_bundle(&bundle, &f.genesis.domain(), false).is_err());
    let mut extra_bundle = bundle.clone();
    extra_bundle.push(0);
    assert!(Genesis::admit_local_bundle(&extra_bundle, &f.genesis.domain(), true).is_err());
    let a = BranchState::genesis(&f.genesis).unwrap();
    let b = BranchState::genesis(&repeated).unwrap();
    assert_eq!(a.checkpoint_bytes(), b.checkpoint_bytes());
    assert_eq!(a.checkpoint_bytes().len(), 136);
    assert_eq!(a.cuts(), b.cuts());
    assert_eq!(a.private_counters(), (30, 0));
    assert_eq!(a.leaves(), 2);
    let recovered =
        silk_f04_node::scanner::scan(&a, f.keys[0].to_diversifiable_full_viewing_key().fvk())
            .unwrap();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].position, 0);
    assert_eq!(recovered[0].note, f.notes[0]);
    assert_eq!(
        recovered[0].status,
        silk_f04_node::scanner::NoteStatus::SpendableAtCut
    );
    let path = silk_f04_node::scanner::witness_at_cut(&a, a.eligible_cut(), 0).unwrap();
    assert_eq!(
        path.root(sapling_crypto::Node::from_cmu(&f.notes[0].cmu()))
            .to_bytes(),
        a.root()
    );
    assert!(matches!(
        Genesis::admit(
            &f.descriptor,
            &parameter_bytes(),
            &f.allocation,
            &f.policy,
            &f.receipt,
            false
        ),
        Err(Error::Unavailable(_))
    ));
    // Context/framing first; bad received signature before remaining amount semantics.
    let mut receipt = f.receipt.clone();
    receipt[16 + 176] ^= 1;
    receipt[16 + 248 - 1] = 255;
    assert!(matches!(
        Genesis::admit(
            &f.descriptor,
            &parameter_bytes(),
            &f.allocation,
            &f.policy,
            &receipt,
            true
        ),
        Err(Error::Invalid("ED_S_RANGE"))
    ));
    receipt = f.receipt.clone();
    receipt[16 + 12] ^= 1;
    receipt[16 + 248 - 1] = 255;
    assert!(matches!(
        Genesis::admit(
            &f.descriptor,
            &parameter_bytes(),
            &f.allocation,
            &f.policy,
            &receipt,
            true
        ),
        Err(Error::Invalid("AUTH_CONTEXT_ROLE"))
    ));
    let mut parameters = parameter_bytes();
    parameters[24] ^= 1;
    assert!(
        Genesis::admit(
            &f.descriptor,
            &parameters,
            &f.allocation,
            &f.policy,
            &f.receipt,
            true
        )
        .is_err()
    );
    let mut extra = f.receipt.clone();
    extra.push(0);
    assert!(
        Genesis::admit(
            &f.descriptor,
            &parameter_bytes(),
            &f.allocation,
            &f.policy,
            &extra,
            true
        )
        .is_err()
    );
}
#[test]
fn carrier_shape_refuses_invalid_parent_enum_and_extra_body_bytes() {
    assert!(encode_parents(&Sg0ParentSetV1::Vertices(vec![])).is_err());
    let bytes = encode_parents(&Sg0ParentSetV1::Anchor).unwrap();
    assert_eq!(bytes, [0; 68]);
    assert_eq!(decode_parents(&bytes).unwrap(), Sg0ParentSetV1::Anchor);
    let b = Body::new(&[1; 32], &[]).unwrap();
    assert_eq!(
        hex::encode(b.bytes()),
        "534c4b4447424630000300000000000000000000"
    );
    let mut extra = b.bytes().to_vec();
    extra.push(0);
    assert!(Body::decode(&extra, &[1; 32]).is_err());
}

#[test]
fn parked_admission_has_no_state_authority_and_drop_keeps_restart_stop() {
    use silk_f04_node::{
        carriage::{Candidate, Header, ParentFacts},
        node::{Ingress, Node},
    };
    let f = fixture(&[10]);
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("node");
    let mut node = Node::create(&root, dir.path(), f.genesis.clone()).unwrap();
    let body = Body::new(&f.genesis.domain(), &[]).unwrap();
    // Pure framing fixture only: no proof/work is asserted and worker stays parked.
    let facts = ParentFacts {
        source_record: [0; 184],
        epoch: 1,
        daa: [0; 32],
        work: 1,
        minimum_time: f.genesis.timestamp() + 1,
        source_index: 0,
        source_checkpoint: [0; 32],
        source_j: [0; 32],
        seed: [0; 32],
        key_material: [0; 32],
    };
    let header = Header::new(
        &f.genesis,
        Sg0ParentSetV1::Anchor,
        &body,
        [0; 32],
        [0; 32],
        f.genesis.timestamp() + 1,
        &facts,
    )
    .unwrap();
    let mut proof = [0; 52];
    proof[..8].copy_from_slice(b"SLKDPOW4");
    proof[9] = 4;
    let bytes = Candidate {
        id: [1; 32],
        header,
        body,
        proof,
    }
    .encode();
    let head_before = std::fs::read(root.join("HEAD")).unwrap();
    assert_eq!(node.begin_ingest(&bytes).unwrap(), Ingress::Pending);
    assert_eq!(node.vertex_count(), 0);
    assert!(matches!(node.state(), Err(Error::Paused(_))));
    assert!(matches!(node.status(), Err(Error::Paused(_))));
    assert!(node.flush_clock().is_err());
    assert!(node.begin_ingest(&bytes).is_err());
    let marker = std::fs::read(root.join("ACTIVE_JOB")).unwrap();
    assert_eq!(marker.len(), 64);
    drop(node);
    assert_eq!(std::fs::read(root.join("HEAD")).unwrap(), head_before);
    assert_eq!(std::fs::read(root.join("ACTIVE_JOB")).unwrap(), marker);
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join("LOCK"))
        .unwrap();
    fs2::FileExt::try_lock_exclusive(&lock).unwrap();
}
