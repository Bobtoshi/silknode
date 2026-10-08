//! Exact signature/chain tests only; synthetic aggregate hashes confer no batch.
use super::*;
use crate::im3_gate::control::{key_commit, sign};
use ed25519_dalek::Signer;

fn signed(c: &MiddleContext<'_>, k: Im3Kind, r: Im3Role, f: [Digest; 7]) -> Im3Control {
    let seed = match r {
        Im3Role::A => 11,
        Im3Role::C => 16,
        Im3Role::B => 12,
        Im3Role::P0 => 13,
        Im3Role::P1 => 14,
        Im3Role::P2 => 15,
    };
    sign(c, k, r, f, &SigningKey::from_bytes(&[seed; 32])).unwrap()
}
fn ready(c: &MiddleContext<'_>) -> Im3ReadyChain {
    let a = signed(
        c,
        Im3Kind::AReady,
        Im3Role::A,
        [
            [1; 32], [0; 32], [0; 32], [0; 32], [0; 32], [0; 32], [0; 32],
        ],
    );
    let middle = signed(
        c,
        Im3Kind::CReady,
        Im3Role::C,
        [[1; 32], [2; 32], [0; 32], a.id(), [0; 32], [0; 32], [0; 32]],
    );
    let b = signed(
        c,
        Im3Kind::BReady,
        Im3Role::B,
        [
            [1; 32],
            [2; 32],
            [3; 32],
            middle.id(),
            key_commit(c, &[4; 32]),
            [0; 32],
            [0; 32],
        ],
    );
    Im3ReadyChain::verify(c, a, middle, b).unwrap()
}
fn acks(c: &MiddleContext<'_>) -> Im3AckChain {
    let ready = ready(c);
    let b = &ready.b;
    let f = [
        b.field(116),
        b.field(148),
        b.field(180),
        b.id(),
        b.field(244),
        [0; 32],
        [0; 32],
    ];
    let acks = [Im3Role::P0, Im3Role::P1, Im3Role::P2].map(|r| signed(c, Im3Kind::Ack, r, f));
    Im3AckChain::verify(c, ready, acks).unwrap()
}
fn auth(c: &MiddleContext<'_>) -> Im3Authorization {
    let chain = acks(c);
    let b = &chain.ready.b;
    let f = [
        b.field(116),
        b.field(148),
        b.field(180),
        b.id(),
        b.field(244),
        [0; 32],
        chain.evidence_digest(),
    ];
    let a = signed(c, Im3Kind::Authorize, Im3Role::A, f);
    Im3Authorization::verify(c, chain, a).unwrap()
}
pub(super) fn run(c: &MiddleContext<'_>) -> serde_json::Value {
    let authorization = auth(c);
    let a = &authorization.control;
    let release = signed(
        c,
        Im3Kind::Release,
        Im3Role::B,
        [
            a.field(116),
            a.field(148),
            a.field(180),
            a.id(),
            a.field(244),
            [4; 32],
            a.field(308),
        ],
    );
    let release = Im3Release::verify(c, authorization, release).unwrap();
    assert_eq!(release.control()[276..308], [4; 32]);
    let mut refusals = 0;
    // Authentic signatures on semantically invalid chains must still fail.
    for wrong in 0..3 {
        let chain = ready(c);
        let mut f = [
            chain.c.field(116),
            chain.c.field(148),
            [0; 32],
            chain.a.id(),
            [0; 32],
            [0; 32],
            [0; 32],
        ];
        if wrong == 0 {
            f[0] = [8; 32];
        } else if wrong == 1 {
            f[3] = [8; 32];
        } else {
            f[1] = [8; 32];
        }
        let middle = signed(c, Im3Kind::CReady, Im3Role::C, f);
        assert!(Im3ReadyChain::verify(c, chain.a, middle, chain.b).is_err());
        refusals += 1;
    }
    for wrong in 0..5 {
        let chain = acks(c);
        let mut acks = chain.acks;
        if wrong == 0 {
            acks.swap(0, 1);
        } else if wrong == 1 {
            acks[1] = Im3Control::verify(acks[0].bytes(), c).unwrap();
        } else {
            let b = &chain.ready.b;
            let mut f = [
                b.field(116),
                b.field(148),
                b.field(180),
                b.id(),
                b.field(244),
                [0; 32],
                [0; 32],
            ];
            f[wrong - 2] = [9; 32];
            acks[2] = signed(c, Im3Kind::Ack, Im3Role::P2, f);
        }
        assert!(Im3AckChain::verify(c, chain.ready, acks).is_err());
        refusals += 1;
    }
    for wrong in 0..3 {
        let chain = acks(c);
        let b = &chain.ready.b;
        let mut f = [
            b.field(116),
            b.field(148),
            b.field(180),
            b.id(),
            b.field(244),
            [0; 32],
            chain.evidence_digest(),
        ];
        f[[3, 4, 6][wrong]] = [8; 32];
        let a = signed(c, Im3Kind::Authorize, Im3Role::A, f);
        assert!(Im3Authorization::verify(c, chain, a).is_err());
        refusals += 1;
    }
    for wrong in 0..4 {
        let authorization = auth(c);
        let a = &authorization.control;
        let mut f = [
            a.field(116),
            a.field(148),
            a.field(180),
            a.id(),
            a.field(244),
            [4; 32],
            a.field(308),
        ];
        f[[0, 3, 5, 6][wrong]] = [8; 32];
        let r = signed(c, Im3Kind::Release, Im3Role::B, f);
        assert!(Im3Release::verify(c, authorization, r).is_err());
        refusals += 1;
    }
    // Re-sign malformed bodies, so the canonicality tests do not just test a
    // broken signature. Includes every unpopulated/mandatory field in A_READY.
    let a = ready(c).a;
    let key = SigningKey::from_bytes(&[11; 32]);
    for at in [
        0, 8, 9, 10, 12, 20, 52, 84, 148, 180, 212, 244, 276, 308, 340, 344, 447,
    ] {
        let mut b = *a.bytes();
        b[at] ^= 1;
        let sig = key
            .sign(&message("SilkNode-IM3-control", &[&b[..448]]))
            .to_bytes();
        b[448..].copy_from_slice(&sig);
        assert!(Im3Control::verify(&b, c).is_err(), "canonical field {at}");
        refusals += 1;
    }
    let mut b = *a.bytes();
    b[116..148].fill(0);
    let sig = key
        .sign(&message("SilkNode-IM3-control", &[&b[..448]]))
        .to_bytes();
    b[448..].copy_from_slice(&sig);
    assert!(Im3Control::verify(&b, c).is_err());
    refusals += 1;
    assert!(Im3Control::verify(&a.bytes()[..511], c).is_err());
    refusals += 1;
    let cancel = signed(c, Im3Kind::Cancel, Im3Role::C, [[0; 32]; 7]);
    assert!(
        Im3ReadyChain::verify(
            c,
            Im3Control::verify(a.bytes(), c).unwrap(),
            cancel,
            ready(c).b
        )
        .is_err()
    );
    refusals += 1;
    json!({"status":"PASS_IM3_CANONICAL_FULL_SIGNED_CHAIN_ONLY","refusals":refusals,
        "actual_batch":false,"new_proofs":0,"new_work":0,"legacy_authorization_conversion":false,
        "qualified_clock":false,"anonymity_proven":false,"settlement":false})
}
