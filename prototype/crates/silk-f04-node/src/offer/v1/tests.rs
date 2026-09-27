//! Framing/admission-gate units only: no proofs, work or new recovery run.
use super::*;
use silk_sapling_f04::codec::Envelope;
const DOMAIN: Digest = [71; 32];
fn envelope(index: u8) -> [u8; ENVELOPE_BYTES] {
    let mut bytes = [0; ENVELOPE_BYTES];
    bytes[..8].copy_from_slice(b"SNPRV003");
    bytes[8] = 3;
    bytes[12..44].copy_from_slice(&DOMAIN);
    bytes[52..84].fill(91);
    bytes[84] = 2;
    bytes[117..149].fill(index);
    bytes[213..245].fill(index + 64);
    bytes[277] = 2;
    bytes[1790..1798].copy_from_slice(&1_i64.to_le_bytes());
    bytes[1798..1830].fill(92);
    bytes
}
#[test]
fn local_offer_exact_order_and_codec_match_ordinary_body() {
    for count in [1, 3, 32] {
        let raw: Vec<_> = (0..count).rev().map(envelope).collect();
        let original: Vec<_> = raw
            .iter()
            .map(|bytes| Envelope::decode(bytes, &DOMAIN).unwrap())
            .collect();
        let expected = Body::new(&DOMAIN, &original).unwrap();
        let offer = LocalOfferV1::from_local_payloads(DOMAIN, raw).unwrap();
        assert_eq!(offer.payload_bytes(), usize::from(count) * ENVELOPE_BYTES);
        let bytes = offer.encode_local().unwrap();
        assert_eq!(&bytes, expected.bytes());
        let decoded = LocalOfferV1::decode_local(&bytes, DOMAIN).unwrap();
        let body = decoded
            .into_body(DOMAIN, NodeStatus::Ready)
            .unwrap()
            .unwrap();
        assert_eq!(body.bytes(), expected.bytes());
        assert_eq!(body.representations(), expected.representations());
    }
}
#[test]
fn local_offer_cover_is_no_work_and_unready_or_foreign_node_is_refused() {
    let cover = LocalOfferV1::from_local_payloads(DOMAIN, vec![]).unwrap();
    let encoded = cover.encode_local().unwrap();
    assert_eq!(encoded.len(), 20);
    assert!(
        LocalOfferV1::decode_local(&encoded, DOMAIN)
            .unwrap()
            .into_body(DOMAIN, NodeStatus::Ready)
            .unwrap()
            .is_none()
    );
    for status in [NodeStatus::NeedsReconcile, NodeStatus::ArchiveReplay] {
        let offer = LocalOfferV1::from_local_payloads(DOMAIN, vec![envelope(1)]).unwrap();
        assert!(matches!(
            offer.into_body(DOMAIN, status),
            Err(Error::Paused(_))
        ));
    }
    let offer = LocalOfferV1::from_local_payloads(DOMAIN, vec![envelope(1)]).unwrap();
    assert!(matches!(
        offer.into_body([72; 32], NodeStatus::Ready),
        Err(Error::Invalid(_))
    ));
}
#[test]
fn local_offer_limits_and_domain_are_checked_before_any_work() {
    assert!(LocalOfferV1::from_local_payloads(DOMAIN, vec![envelope(1); 33]).is_err());
    assert!(LocalOfferV1::from_local_payloads([72; 32], vec![envelope(1)]).is_err());
    let bytes = LocalOfferV1::from_local_payloads(DOMAIN, vec![envelope(1)])
        .unwrap()
        .encode_local()
        .unwrap();
    assert!(LocalOfferV1::decode_local(&bytes, [72; 32]).is_err());
    assert!(LocalOfferV1::decode_local(&bytes[..bytes.len() - 1], DOMAIN).is_err());
    assert!(LocalOfferV1::decode_local(&vec![0; 89_301], DOMAIN).is_err());
}

#[test]
fn local_offer_discards_unreported_input_vector_capacity() {
    let mut oversized = Vec::with_capacity(4096);
    oversized.push(envelope(1));
    assert!(oversized.capacity() > 32);
    let offer = LocalOfferV1::from_local_payloads(DOMAIN, oversized).unwrap();
    // Boxed slice has an exact retained allocation layout, not spare Vec capacity.
    assert_eq!(std::mem::size_of_val(&*offer.envelopes), ENVELOPE_BYTES);
    assert_eq!(offer.payload_bytes(), ENVELOPE_BYTES);
    assert_eq!(offer.encode_local().unwrap().len(), 20 + ENVELOPE_BYTES);
}
