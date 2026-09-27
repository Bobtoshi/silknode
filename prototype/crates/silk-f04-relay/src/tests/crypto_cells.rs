//! Genuine HPKE/AEAD with framing-only payloads, not verified Sapling payments.
use super::*;
use crate::{
    frame::{
        Frame, HpkePrivate, Payload, RoundContext, client_cell, generate_hpke_key, open_a, open_b,
        permute_stage2,
    },
    staging::{StagedBatch, a_batch_id, open_batch},
};
use silk_sapling_f04::codec::{ENVELOPE_BYTES, Envelope};
use std::collections::BTreeSet;

fn crypto_fixture() -> (Fixture, HpkePrivate, HpkePrivate) {
    let mut f = fixture();
    let (a, ap) = generate_hpke_key().unwrap();
    let (b, bp) = generate_hpke_key().unwrap();
    let mut bytes = *f.config.bytes();
    bytes[128..160].copy_from_slice(&ap);
    bytes[160..192].copy_from_slice(&bp);
    config_signature(&mut bytes, &f.keys);
    f.config = SignedConfig::verify(
        &bytes,
        f.config.domain(),
        3,
        2,
        [
            f.keys[0].verifying_key().to_bytes(),
            f.keys[1].verifying_key().to_bytes(),
        ],
    )
    .unwrap();
    let mut bytes = *f.manifest.bytes();
    let msg = message("SilkNode-F0-round", &[&f.config.id(), &bytes[..128]]);
    bytes[128..192].copy_from_slice(&sign_role(&f.keys[0], &msg).unwrap());
    bytes[192..].copy_from_slice(&sign_role(&f.keys[1], &msg).unwrap());
    f.manifest = SignedManifest::verify(&bytes, &f.config, 6000).unwrap();
    (f, a, b)
}
fn unverified_envelope(f: &Fixture, index: u8) -> Envelope {
    let mut bytes = [0; ENVELOPE_BYTES];
    bytes[..8].copy_from_slice(b"SNPRV003");
    bytes[8] = 3;
    bytes[12..44].copy_from_slice(&f.config.domain());
    bytes[44..52].copy_from_slice(&f.manifest.bytes()[52..60]);
    bytes[52..84].copy_from_slice(&f.manifest.bytes()[60..92]);
    bytes[84] = 2;
    bytes[117..149].fill(index);
    bytes[213..245].fill(index + 64);
    bytes[277] = 2;
    bytes[1790..1798].copy_from_slice(&1_i64.to_le_bytes());
    bytes[1798..1830].copy_from_slice(&f.manifest.bytes()[92..124]);
    Envelope::decode(&bytes, &f.config.domain()).unwrap()
}
fn release_chain(
    f: &Fixture,
    ah: Digest,
    batch: &StagedBatch,
) -> (
    SignedControl,
    SignedControl,
    [SignedControl; 3],
    SignedControl,
    SignedControl,
) {
    let mut bytes = prefix(f);
    bytes[120..152].copy_from_slice(&ah);
    bytes[248] = 32; // Synthetic sessions, never a count of honest humans.
    let a = sign_control(bytes, f, Kind::AReady, Role::A);
    let mut bytes = *a.bytes();
    bytes[152..184].copy_from_slice(&batch.id());
    bytes[184..216].copy_from_slice(&a.id());
    bytes[256..288].copy_from_slice(&batch.key_commit());
    let b = sign_control(bytes, f, Kind::BReady, Role::B);
    let acks = [Role::P0, Role::P1, Role::P2].map(|role| {
        let mut bytes = *b.bytes();
        bytes[216..248].copy_from_slice(&b.id());
        sign_control(bytes, f, Kind::Ack, role)
    });
    let mut bytes = *acks[0].bytes();
    for (i, ack) in acks.iter().enumerate() {
        bytes[320 + 32 * i..352 + 32 * i].copy_from_slice(&ack.id());
    }
    for (i, value) in FENCE.iter().enumerate() {
        bytes[416 + 8 * i..424 + 8 * i].copy_from_slice(&value.to_le_bytes());
    }
    let auth = sign_control(bytes, f, Kind::Authorize, Role::A);
    let mut bytes = *auth.bytes();
    bytes[288..320].copy_from_slice(batch.fixture_key());
    let release = sign_control(bytes, f, Kind::Release, Role::B);
    (a, b, acks, auth, release)
}

#[test]
fn producer_handoff_filters_covers_and_preserves_exact_real_order() {
    use crate::handoff::v1::{ProducerInboxV1, ReleasedBatchV1};
    use silk_f04_node::{carriage::Body, offer::v1::LocalOfferV1};
    let f = fixture();
    let context = RoundContext::new(&f.config, &f.manifest).unwrap();
    let expected = [
        unverified_envelope(&f, 9),
        unverified_envelope(&f, 2),
        unverified_envelope(&f, 17),
    ];
    let batch = std::array::from_fn(|i| match i {
        1 => Payload::real(&expected[0], &context).unwrap(),
        8 => Payload::real(&expected[1], &context).unwrap(),
        30 => Payload::real(&expected[2], &context).unwrap(),
        _ => Payload::cover(),
    });
    // Private framing-only constructor, not a claim that this test ran a relay.
    let released = ReleasedBatchV1::from_completed(&f.config, &f.manifest, Role::P0, batch);
    let mut queue = ProducerInboxV1::new(f.config.domain(), f.config.cohort(), Role::P0).unwrap();
    queue.offer(released).unwrap();
    assert_eq!(queue.payload_bytes(), 3 * ENVELOPE_BYTES);
    let (delivery, offer) = queue.take_next().unwrap();
    assert_eq!(delivery.manifest, f.manifest.id());
    assert_eq!(delivery.config, f.config.id());
    let encoded = offer.encode_local().unwrap();
    assert_eq!(
        encoded,
        Body::new(&f.config.domain(), &expected).unwrap().bytes()
    );
    assert_eq!(
        LocalOfferV1::decode_local(&encoded, f.config.domain())
            .unwrap()
            .payload_bytes(),
        3 * ENVELOPE_BYTES
    );
    assert_eq!(queue.payload_bytes(), 0);
    assert!(queue.take_next().is_none());
}

#[test]
fn producer_handoff_has_one_two_batch_queue_and_no_replay_or_auto_requeue() {
    use crate::handoff::v1::{ProducerInboxV1, ReleasedBatchV1};
    let f = fixture();
    let context = RoundContext::new(&f.config, &f.manifest).unwrap();
    let batch = |round: u64, producer: Role, real: bool| {
        let mut manifest = *f.manifest.bytes();
        manifest[44..52].copy_from_slice(&round.to_le_bytes());
        let msg = message("SilkNode-F0-round", &[&f.config.id(), &manifest[..128]]);
        manifest[128..192].copy_from_slice(&sign_role(&f.keys[0], &msg).unwrap());
        manifest[192..].copy_from_slice(&sign_role(&f.keys[1], &msg).unwrap());
        let manifest = SignedManifest::verify(&manifest, &f.config, round).unwrap();
        ReleasedBatchV1::from_completed(
            &f.config,
            &manifest,
            producer,
            std::array::from_fn(|i| {
                if real {
                    Payload::real(&unverified_envelope(&f, u8::try_from(i).unwrap()), &context)
                        .unwrap()
                } else {
                    Payload::cover()
                }
            }),
        )
    };
    assert!(ProducerInboxV1::new(f.config.domain(), 3, Role::A).is_err());
    let mut queue = ProducerInboxV1::new(f.config.domain(), 3, Role::P0).unwrap();
    assert!(queue.offer(batch(6000, Role::P1, true)).is_err());
    queue.offer(batch(6000, Role::P0, true)).unwrap();
    queue.offer(batch(6001, Role::P0, true)).unwrap();
    assert_eq!(queue.payload_bytes(), 64 * ENVELOPE_BYTES);
    assert!(queue.offer(batch(6002, Role::P0, true)).is_err());
    assert_eq!(queue.take_next().unwrap().0.round, 6000);
    assert!(queue.offer(batch(6002, Role::P0, true)).is_err());
    assert!(queue.offer(batch(6000, Role::P0, true)).is_err());
    assert_eq!(queue.take_next().unwrap().0.round, 6001);
    assert!(queue.take_next().is_none());
    queue.offer(batch(6003, Role::P0, false)).unwrap();
    assert_eq!(queue.payload_bytes(), 0);
    let (_, cover) = queue.take_next().unwrap();
    assert_eq!(cover.encode_local().unwrap().len(), 20);
}

#[test]
fn real_hpke_fixed_frames_context_authentication_and_fresh_encapsulation() {
    let (f, a, b) = crypto_fixture();
    let context = RoundContext::new(&f.config, &f.manifest).unwrap();
    let unverified = unverified_envelope(&f, 1);
    let payload = Payload::real(&unverified, &context).unwrap();
    let first = client_cell(&context, &payload).unwrap();
    let second = client_cell(&context, &payload).unwrap();
    assert_ne!(
        first.encapsulation().unwrap(),
        second.encapsulation().unwrap()
    );
    assert_eq!(first.bytes().len(), 8192);
    assert!(first.bytes()[4720..].iter().all(|b| *b == 0));
    let inner = open_a(&context, &a, &first).unwrap();
    assert!(inner.bytes()[4208..].iter().all(|b| *b == 0));
    let recovered = open_b(&context, &b, &inner).unwrap();
    assert_eq!(recovered.real_bytes(), Some(unverified.bytes()));
    assert!(open_a(&context, &b, &first).is_err());
    let mut altered = *first.bytes();
    altered[100] ^= 1;
    let changed = Frame::decode(&altered, &context, 1, 0).unwrap();
    assert!(open_a(&context, &a, &changed).is_err());
    altered = *first.bytes();
    altered[8191] = 1;
    assert!(Frame::decode(&altered, &context, 1, 0).is_err());
    assert!(Frame::decode(&first.bytes()[..8191], &context, 1, 0).is_err());
    assert!(Frame::decode(first.bytes(), &context, 1, 1).is_err());
    let cover = client_cell(&context, &Payload::cover()).unwrap();
    assert!(
        !open_b(&context, &b, &open_a(&context, &a, &cover).unwrap())
            .unwrap()
            .is_real()
    );
}

#[test]
fn complete_double_permutation_staging_and_signed_release_chain() {
    let (f, a, b) = crypto_fixture();
    let context = RoundContext::new(&f.config, &f.manifest).unwrap();
    let mut expected = BTreeSet::new();
    let mut frames: [Frame; 32] = std::array::from_fn(|i| {
        let payload = if i < 8 {
            let envelope = unverified_envelope(&f, u8::try_from(i).unwrap());
            expected.insert(envelope.bytes().to_vec());
            Payload::real(&envelope, &context).unwrap()
        } else {
            Payload::cover()
        };
        open_a(&context, &a, &client_cell(&context, &payload).unwrap()).unwrap()
    });
    let encapsulations: BTreeSet<_> = frames
        .iter()
        .map(|frame| frame.encapsulation().unwrap())
        .collect();
    assert_eq!(encapsulations.len(), 32);
    permute_stage2(&context, &mut frames).unwrap();
    assert_eq!(
        frames
            .iter()
            .map(|frame| frame.encapsulation().unwrap())
            .collect::<BTreeSet<_>>(),
        encapsulations
    );
    let ah = a_batch_id(&context, &frames).unwrap();
    let payloads = frames
        .each_ref()
        .map(|frame| open_b(&context, &b, frame).unwrap());
    let batch = StagedBatch::seal(&context, payloads).unwrap();
    let (ar, br, acks, auth, release) = release_chain(&f, ah, &batch);
    let authorization =
        check_authorization(&f.manifest, &ar, &br, [&acks[0], &acks[1], &acks[2]], &auth).unwrap();
    let evidence = check_release(&authorization, &release).unwrap();
    let opened = open_batch(&context, &evidence, batch.frames()).unwrap();
    let actual: BTreeSet<_> = opened
        .iter()
        .filter_map(Payload::real_bytes)
        .map(|b| b.to_vec())
        .collect();
    assert_eq!(actual, expected);
    assert_eq!(opened.iter().filter(|p| p.is_real()).count(), 8);
    assert_eq!(opened.iter().filter(|p| !p.is_real()).count(), 24);
    let mut changed: [Frame; 32] = std::array::from_fn(|i| {
        Frame::decode(
            batch.frames()[i].bytes(),
            &context,
            3,
            u32::try_from(i).unwrap(),
        )
        .unwrap()
    });
    changed.swap(0, 1);
    assert!(open_batch(&context, &evidence, &changed).is_err());
    // No duplicate encapsulation gains another batch position.
    frames[1] = Frame::decode(frames[0].bytes(), &context, 2, 0).unwrap();
    assert!(permute_stage2(&context, &mut frames).is_err());
}
