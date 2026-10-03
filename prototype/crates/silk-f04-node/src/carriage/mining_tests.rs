//! Pure template/transcript checks; synthetic hashes are never admitted or PoW evidence.
use super::*;
#[path = "../../tests/common/mod.rs"]
mod common;

fn input(work: u64) -> (Header, Body, Arc<Genesis>, ParentFacts) {
    let genesis = Arc::new(common::fixture(&[10]).genesis);
    let body = Body::new(&genesis.domain(), &[]).unwrap();
    let mut facts = crate::parent::PrefixCache::new(&genesis)
        .unwrap()
        .derive(
            &crate::graph::DurableGraph::default(),
            &Sg0ParentSetV1::Anchor,
            &genesis,
            &JobBudget::vertex().unwrap(),
        )
        .unwrap();
    facts.work = work;
    let header = Header::new(
        &genesis,
        Sg0ParentSetV1::Anchor,
        &body,
        [0; 32],
        [7; 32],
        genesis.timestamp() + 10,
        &facts,
    )
    .unwrap();
    (header, body, genesis, facts)
}

#[test]
fn owned_template_preserves_exact_legacy_candidate_bytes() {
    let (header, body, genesis, facts) = input(1);
    let template = MiningTemplate::new(&header, body.clone(), genesis.clone(), &facts).unwrap();
    assert_eq!(template.header().bytes, header.bytes);
    assert_eq!(template.body().bytes(), body.bytes());
    for nonce in [0, 7, u64::MAX] {
        // Original candidate construction, with a synthetic hash for framing only.
        let hash = [1; 32];
        let mut proof = [0; 52];
        proof[..8].copy_from_slice(b"SLKDPOW4");
        proof[9] = 4;
        proof[12..20].copy_from_slice(&nonce.to_be_bytes());
        proof[20..].copy_from_slice(&hash);
        let expected = Candidate {
            id: vertex_id(&header, &proof, &genesis, facts.key_material).unwrap(),
            header: header.clone(),
            body: body.clone(),
            proof,
        };
        let candidate = template.candidate(nonce, hash).unwrap().unwrap();
        assert_eq!(candidate.encode(), expected.encode());
        assert_eq!(
            Candidate::decode(&candidate.encode(), &genesis)
                .unwrap()
                .encode(),
            expected.encode()
        );
    }
}

#[test]
fn rejected_nonce_has_no_candidate_or_credit() {
    let (header, body, genesis, facts) = input(5);
    let template = MiningTemplate::new(&header, body, genesis, &facts).unwrap();
    assert!(template.candidate(0, [255; 32]).unwrap().is_none());
    let candidate = template.candidate(u64::MAX, [0; 32]).unwrap().unwrap();
    assert_eq!(&candidate.proof[12..20], &u64::MAX.to_be_bytes());
}

#[test]
fn template_does_not_accept_unmatched_facts_or_body() {
    let (header, body, genesis, mut facts) = input(5);
    facts.work = 6;
    assert!(MiningTemplate::new(&header, body.clone(), genesis.clone(), &facts).is_err());
    let mut changed = header;
    changed.bytes[176] ^= 1;
    assert!(MiningTemplate::new(&changed, body, genesis, &facts).is_err());
}
