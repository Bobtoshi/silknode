//! Real primitive smoke, NOT a genesis ceremony, work-bearing node or settlement test.
//! Run explicitly with `SILK_F04_PARAMETER_DIR` and --release --ignored --nocapture.
use rand_core::{OsRng, RngCore};
use sapling_crypto::{
    CommitmentTree, IncrementalWitness, Node, Note, Rseed, value::NoteValue,
    zip32::ExtendedSpendingKey,
};
use silk_sapling_f04::{
    Error,
    codec::{ENVELOPE_BYTES, Envelope},
    crypto::{verify, verify_many},
    parameters::SaplingParameters,
    wallet::{CutReference, PaymentOutput, RecoveryOutput, SpendInput, build_transfer},
};
use std::{path::PathBuf, time::Instant};

fn key() -> ExtendedSpendingKey {
    let mut seed = [0; 32];
    OsRng.fill_bytes(&mut seed);
    ExtendedSpendingKey::master(&seed)
}
fn note(key: &ExtendedSpendingKey, value: u64) -> Note {
    let mut rseed = [0; 32];
    OsRng.fill_bytes(&mut rseed);
    key.default_address()
        .1
        .create_note(NoteValue::from_raw(value), Rseed::AfterZip212(rseed))
}

#[test]
#[ignore = "real Groth16 smoke requires the canonical public parameter files"]
#[allow(
    clippy::too_many_lines,
    reason = "One proportional real-proof smoke reuses authenticated parameters and fixtures"
)]
fn real_private_transfer_two_shapes_recovery_replay_and_exact_parallel_verification() {
    let started = Instant::now();
    let dir = PathBuf::from(
        std::env::var_os("SILK_F04_PARAMETER_DIR").expect("SILK_F04_PARAMETER_DIR required"),
    );
    let parameters = SaplingParameters::load(
        &dir.join("sapling-spend.params"),
        &dir.join("sapling-output.params"),
    )
    .unwrap();
    println!(
        "canonical full parameter identities checked; load_ms={}",
        started.elapsed().as_millis()
    );
    let sender = key();
    let recipient = key();
    let change = key();
    let initial_note = note(&sender, 10);
    let mut tree = CommitmentTree::empty();
    tree.append(Node::from_cmu(&initial_note.cmu())).unwrap();
    let witness = IncrementalWitness::from_tree(tree.clone()).unwrap();
    // Deliberately fixture-only domain/cut. No claim of accepted GD/PB/G/AP/AR or graph state.
    let cut = CutReference {
        domain: [23; 32],
        index: 0,
        id: [41; 32],
        root: tree.root().to_bytes(),
    };
    let real_input = || SpendInput {
        key: sender.clone(),
        note: initial_note.clone(),
        path: witness.path().unwrap(),
    };
    let intents = || {
        [
            PaymentOutput {
                address: recipient.default_address().1,
                value: 4,
            },
            PaymentOutput {
                address: change.default_address().1,
                value: 5,
            },
        ]
    };
    let proving = Instant::now();
    let verified = build_transfer(cut, vec![real_input()], intents(), &parameters).unwrap();
    println!(
        "one_real_plus_standard_dummy_prove_sign_roundtrip_verify_ms={}",
        proving.elapsed().as_millis()
    );
    let envelope = verified.envelope();
    assert_eq!(envelope.bytes().len(), ENVELOPE_BYTES);
    assert_eq!(envelope.anchor(), cut.root);
    assert_ne!(envelope.nullifiers()[0], envelope.nullifiers()[1]);
    let real_nf = initial_note
        .nf(&sender.to_diversifiable_full_viewing_key().fvk().vk.nk, 0)
        .0;
    assert!(envelope.nullifiers().contains(&real_nf));
    let mut recipient_total = 0;
    let mut change_total = 0;
    for (slot, bytes) in envelope.recovery().into_iter().enumerate() {
        let output = RecoveryOutput::decode(bytes).unwrap();
        if let Some((n, a, m)) = output.decrypt(recipient.to_diversifiable_full_viewing_key().fvk())
        {
            assert_eq!(a, recipient.default_address().1);
            assert_eq!(m, [0; 512]);
            recipient_total += n.value().inner();
            // The scanner's eventual NF must use canonical position, not output slot alone.
            assert_ne!(
                n.nf(
                    &recipient.to_diversifiable_full_viewing_key().fvk().vk.nk,
                    1 + slot as u64
                ),
                n.nf(
                    &recipient.to_diversifiable_full_viewing_key().fvk().vk.nk,
                    3 + slot as u64
                )
            );
        }
        if let Some((n, _, _)) = output.decrypt(change.to_diversifiable_full_viewing_key().fvk()) {
            change_total += n.value().inner();
        }
        assert!(
            output
                .decrypt(sender.to_diversifiable_full_viewing_key().fvk())
                .is_none()
        );
        let mut corrupted = bytes;
        corrupted[64] ^= 1;
        let corrupted = RecoveryOutput::decode(corrupted).unwrap();
        assert!(
            corrupted
                .decrypt(recipient.to_diversifiable_full_viewing_key().fvk())
                .is_none()
        );
        assert!(
            corrupted
                .decrypt(change.to_diversifiable_full_viewing_key().fvk())
                .is_none()
        );
    }
    assert_eq!((recipient_total, change_total), (4, 5));
    assert_eq!(recipient_total + change_total + 1, 10);
    // A copied proof cannot authorize changed N, cut index, K, ciphertext or anchor.
    for at in [
        12, 44, 52, 374, 1798, 1830, 2022, 2214, 2278, 2342, 2534, 2726,
    ] {
        let mut changed = *envelope.bytes();
        changed[at] ^= 1;
        let expected_domain: [u8; 32] = changed[12..44].try_into().unwrap();
        let decoded = Envelope::decode(&changed, &expected_domain).unwrap();
        assert!(
            verify(decoded, &parameters).is_err(),
            "changed signed/proved field at {at}"
        );
    }
    assert!(Envelope::decode(envelope.bytes(), &[24; 32]).is_err());
    let decode_start = Instant::now();
    for _ in 0..1000 {
        std::hint::black_box(Envelope::decode(envelope.bytes(), &cut.domain).unwrap());
    }
    println!("decode_1000_ms={}", decode_start.elapsed().as_millis());
    let batch_start = Instant::now();
    let serial = verify_many(vec![envelope.clone(), envelope.clone()], &parameters, 1).unwrap();
    println!(
        "two_envelope_serial_exact_ms={}",
        batch_start.elapsed().as_millis()
    );
    let batch_start = Instant::now();
    let parallel = verify_many(vec![envelope.clone(), envelope.clone()], &parameters, 2).unwrap();
    println!(
        "two_envelope_two_thread_exact_ms={}",
        batch_start.elapsed().as_millis()
    );
    for (a, b) in serial.iter().zip(&parallel) {
        assert_eq!(a.envelope().bytes(), b.envelope().bytes());
    }
    assert!(matches!(
        verify_many(vec![envelope.clone(); 33], &parameters, 1),
        Err(Error::Resource(_))
    ));
    assert!(matches!(
        verify_many(vec![], &parameters, 3),
        Err(Error::Resource(_))
    ));
    // Selection/amount refusals happen before any expensive proof construction.
    let double_spend_outputs = [
        PaymentOutput {
            address: recipient.default_address().1,
            value: 4,
        },
        PaymentOutput {
            address: change.default_address().1,
            value: 15,
        },
    ];
    assert!(matches!(
        build_transfer(
            cut,
            vec![real_input(), real_input()],
            double_spend_outputs,
            &parameters
        ),
        Err(Error::Wallet("same positioned note selected twice"))
    ));
    let mut oversized_position = real_input();
    oversized_position.path = sapling_crypto::MerklePath::from_parts(
        oversized_position.path.path_elems().to_vec(),
        incrementalmerkletree::Position::from(1_u64 << 32),
    )
    .unwrap();
    assert!(matches!(
        build_transfer(cut, vec![oversized_position], intents(), &parameters),
        Err(Error::Wallet("note position exceeds depth-32 tree"))
    ));
    let too_much = [
        PaymentOutput {
            address: recipient.default_address().1,
            value: 10,
        },
        PaymentOutput {
            address: change.default_address().1,
            value: 0,
        },
    ];
    assert!(build_transfer(cut, vec![real_input()], too_much, &parameters).is_err());
    let mut wrong_cut = cut;
    wrong_cut.root = sapling_crypto::Anchor::empty_tree().to_bytes();
    assert!(build_transfer(wrong_cut, vec![real_input()], intents(), &parameters).is_err());

    // A second genuine shape: two positive inputs and a zero-valued encrypted output.
    let second_note = note(&sender, 20);
    tree.append(Node::from_cmu(&second_note.cmu())).unwrap();
    let mut first_witness = witness;
    first_witness
        .append(Node::from_cmu(&second_note.cmu()))
        .unwrap();
    let second_witness = IncrementalWitness::from_tree(tree.clone()).unwrap();
    let cut = CutReference {
        root: tree.root().to_bytes(),
        ..cut
    };
    let proving = Instant::now();
    let two = build_transfer(
        cut,
        vec![
            SpendInput {
                key: sender.clone(),
                note: initial_note,
                path: first_witness.path().unwrap(),
            },
            SpendInput {
                key: sender,
                note: second_note,
                path: second_witness.path().unwrap(),
            },
        ],
        [
            PaymentOutput {
                address: recipient.default_address().1,
                value: 29,
            },
            PaymentOutput {
                address: change.default_address().1,
                value: 0,
            },
        ],
        &parameters,
    )
    .unwrap();
    let values: Vec<_> = two
        .envelope()
        .recovery()
        .into_iter()
        .filter_map(|bytes| {
            RecoveryOutput::decode(bytes)
                .unwrap()
                .decrypt(recipient.to_diversifiable_full_viewing_key().fvk())
                .map(|r| r.0.value().inner())
        })
        .collect();
    assert_eq!(values, vec![29]);
    println!(
        "two_real_plus_zero_output_prove_sign_roundtrip_verify_ms={}",
        proving.elapsed().as_millis()
    );
    println!(
        "primitive_smoke_total_ms={}; no carrier, settlement, genesis ceremony or node-store acceptance claimed",
        started.elapsed().as_millis()
    );
}
