//! Public deterministic codec fixtures, never enrollment/independent operators.
use super::*;
use config::{Roster, SignedConfig};
use control::{FENCE, Kind, Role, SignedControl, check_authorization, check_release};
use ed25519_dalek::SigningKey;
use manifest::SignedManifest;
use silk_f04_node::auth::sign_role;
use silk_sapling_f04::codec::domain_hash;

mod crypto_cells;
#[cfg(unix)]
pub mod tls;

#[cfg(unix)]
#[path = "../../silk-node/tests/support/private_relay_test_certificates.rs"]
pub mod certificates;

pub fn relay_test_config() -> SignedConfig {
    fixture().config
}

pub fn epoch_config(epoch: u32) -> SignedConfig {
    let f = fixture();
    let mut bytes = *f.config.bytes();
    let first = u64::from(epoch) * 2880;
    bytes[44..48].copy_from_slice(&epoch.to_le_bytes());
    bytes[48..56].copy_from_slice(&first.to_le_bytes());
    bytes[56..64].copy_from_slice(&(first + 2880).to_le_bytes());
    let flat: Vec<_> = f.hashes.iter().flatten().copied().collect();
    bytes[602..634].copy_from_slice(&domain_hash(
        "SilkNode-F0-roster",
        &[
            &f.config.domain(),
            &f.config.cohort().to_le_bytes(),
            &epoch.to_le_bytes(),
            &flat,
        ],
    ));
    config_signature(&mut bytes, &f.keys);
    SignedConfig::verify(
        &bytes,
        f.config.domain(),
        f.config.cohort(),
        epoch,
        [
            f.keys[0].verifying_key().to_bytes(),
            f.keys[1].verifying_key().to_bytes(),
        ],
    )
    .unwrap()
}

#[test]
#[cfg(unix)]
fn closed_live_journal_slots_survive_successor_until_explicit_retirement() {
    use journal::{Decision, Journal};
    use std::os::unix::fs::PermissionsExt;
    let f = fixture();
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut journal =
        Journal::create(directory.path(), f.config.domain(), 3, Role::A, 5997).unwrap();
    let mut body: [u8; 128] = f.manifest.bytes()[..128].try_into().unwrap();
    journal.begin(&f.config, 6000, &body, 5999).unwrap();
    journal.manifested(&f.manifest).unwrap();
    assert_eq!(
        journal.cancel_live(&f.config, 6000).unwrap(),
        f.manifest.id()
    );
    body[44..52].copy_from_slice(&6001_u64.to_le_bytes());
    journal.begin(&f.config, 6001, &body, 6000).unwrap();
    assert_eq!(journal.decision(6000), Some(Decision::Abort));
    assert_eq!(journal.decision(6001), Some(Decision::Open));
    assert_eq!(journal.cancel_live(&f.config, 6001).unwrap(), [0; 32]);
    let pinned = journal.pin();
    body[44..52].copy_from_slice(&6002_u64.to_le_bytes());
    assert!(journal.begin(&f.config, 6002, &body, 6001).is_err());
    assert_eq!(journal.pin(), pinned);
    journal.retire_live(&f.config, 6000).unwrap();
    assert_eq!(journal.pin(), pinned); // Volatile retirement retains terminal bytes.
    assert!(journal.cancel_live(&f.config, 6000).is_err());
    journal.begin(&f.config, 6002, &body, 6001).unwrap();
    assert_eq!(journal.decision(6001), Some(Decision::Abort));
    let pin = journal.pin();
    drop(journal);
    let mut recovered =
        Journal::open(directory.path(), f.config.domain(), 3, Role::A, pin, 6002).unwrap();
    assert_eq!(recovered.decision(6002), Some(Decision::Abort));
    let recovered_pin = recovered.pin();
    assert!(recovered.cancel_live(&f.config, 6002).is_err());
    assert!(recovered.retire_live(&f.config, 6002).is_err());
    assert_eq!(recovered.pin(), recovered_pin);
}

struct Fixture {
    keys: [SigningKey; 5],
    config: SignedConfig,
    manifest: SignedManifest,
    hashes: [Digest; 32],
}
fn config_signature(bytes: &mut [u8; 770], keys: &[SigningKey; 5]) {
    let msg = message("SilkNode-F0-config-sign", &[&bytes[..642]]);
    assert_eq!(msg.len(), 666);
    bytes[642..706].copy_from_slice(&sign_role(&keys[0], &msg).unwrap());
    bytes[706..].copy_from_slice(&sign_role(&keys[1], &msg).unwrap());
}
fn fixture() -> Fixture {
    let keys =
        std::array::from_fn(|i| SigningKey::from_bytes(&[u8::try_from(i + 31).unwrap(); 32]));
    let n = [71; 32];
    let mut hashes = std::array::from_fn(|i| {
        domain_hash("SilkNode-F0-token", &[&[u8::try_from(i).unwrap(); 32]])
    });
    hashes.sort_unstable();
    let mut flat = [0; 1024];
    for (i, hash) in hashes.iter().enumerate() {
        flat[i * 32..(i + 1) * 32].copy_from_slice(hash);
    }
    let roster = domain_hash(
        "SilkNode-F0-roster",
        &[&n, &3_u32.to_le_bytes(), &2_u32.to_le_bytes(), &flat],
    );
    let mut bytes = [0; 770];
    bytes[..8].copy_from_slice(b"SNCFGF03");
    bytes[8..40].copy_from_slice(&n);
    bytes[40..44].copy_from_slice(&3_u32.to_le_bytes());
    bytes[44..48].copy_from_slice(&2_u32.to_le_bytes());
    bytes[48..56].copy_from_slice(&5760_u64.to_le_bytes());
    bytes[56..64].copy_from_slice(&8640_u64.to_le_bytes());
    for (i, key) in keys[..2].iter().enumerate() {
        bytes[64 + 32 * i..96 + 32 * i].copy_from_slice(&key.verifying_key().to_bytes());
    }
    for (i, key) in keys.iter().enumerate() {
        let start = 192 + 82 * i;
        bytes[start + 15] = 1;
        bytes[start + 16..start + 18]
            .copy_from_slice(&u16::try_from(31000 + i).unwrap().to_le_bytes());
        bytes[start + 18..start + 50].copy_from_slice(&key.verifying_key().to_bytes());
        bytes[start + 50..start + 82].fill(u8::try_from(i + 1).unwrap());
    }
    bytes[128..160].fill(81); // Codec fixture only; not an HPKE session.
    bytes[160..192].fill(82);
    bytes[602..634].copy_from_slice(&roster);
    bytes[634..638].copy_from_slice(&500_u32.to_le_bytes());
    bytes[638..640].copy_from_slice(&[8, 32]);
    config_signature(&mut bytes, &keys);
    let config = SignedConfig::verify(
        &bytes,
        n,
        3,
        2,
        [
            keys[0].verifying_key().to_bytes(),
            keys[1].verifying_key().to_bytes(),
        ],
    )
    .unwrap();
    let mut manifest = [0; 256];
    manifest[..8].copy_from_slice(b"SNRNDF03");
    manifest[8..40].copy_from_slice(&n);
    manifest[40..44].copy_from_slice(&3_u32.to_le_bytes());
    manifest[44..52].copy_from_slice(&6000_u64.to_le_bytes());
    manifest[60..92].fill(91);
    manifest[92..124].fill(92);
    let msg = message("SilkNode-F0-round", &[&config.id(), &manifest[..128]]);
    assert_eq!(msg.len(), 178);
    manifest[128..192].copy_from_slice(&sign_role(&keys[0], &msg).unwrap());
    manifest[192..].copy_from_slice(&sign_role(&keys[1], &msg).unwrap());
    let manifest = SignedManifest::verify(&manifest, &config, 6000).unwrap();
    Fixture {
        keys,
        config,
        manifest,
        hashes,
    }
}
fn sign_control(mut bytes: [u8; 512], fixture: &Fixture, kind: Kind, role: Role) -> SignedControl {
    bytes[8] = kind as u8;
    bytes[9] = role as u8;
    let msg = message("SilkNode-F0-control", &[&bytes[..448]]);
    assert_eq!(msg.len(), 468);
    bytes[448..].copy_from_slice(&sign_role(&fixture.keys[role as usize], &msg).unwrap());
    SignedControl::verify(&bytes, &fixture.config, 6000, kind, role).unwrap()
}
fn prefix(f: &Fixture) -> [u8; 512] {
    let mut bytes = [0; 512];
    bytes[..8].copy_from_slice(b"SNCTLF03");
    bytes[10] = 1;
    bytes[12..44].copy_from_slice(&f.config.domain());
    bytes[44..76].copy_from_slice(&f.config.id());
    bytes[76..80].copy_from_slice(&f.config.cohort().to_le_bytes());
    bytes[80..88].copy_from_slice(&6000_u64.to_le_bytes());
    bytes[88..120].copy_from_slice(&f.manifest.id());
    bytes
}
#[test]
fn exact_configuration_roster_join_and_error_order() {
    let f = fixture();
    let roots = [
        f.keys[0].verifying_key().to_bytes(),
        f.keys[1].verifying_key().to_bytes(),
    ];
    let verify = |bytes: &[u8]| SignedConfig::verify(bytes, f.config.domain(), 3, 2, roots);
    assert_eq!(
        f.config.id(),
        domain_hash("SilkNode-F0-config", &[&f.config.bytes()[..642]])
    );
    let roster = Roster::verify(f.hashes, &f.config).unwrap();
    let mut join = [0; 128];
    join[..8].copy_from_slice(b"SNJOIN03");
    join[8..40].copy_from_slice(&f.config.domain());
    join[40..44].copy_from_slice(&3_u32.to_le_bytes());
    join[44..48].copy_from_slice(&2_u32.to_le_bytes());
    join[48..80].fill(7);
    assert_eq!(
        roster.verify_join(&join, &f.config).unwrap(),
        domain_hash("SilkNode-F0-token", &[&[7; 32]])
    );
    join[48..80].fill(255);
    assert!(roster.verify_join(&join, &f.config).is_err());
    join[80] = 1;
    assert!(matches!(
        roster.verify_join(&join, &f.config),
        Err(Error::Invalid("AUTH_ENCODING"))
    ));
    let mut changed = *f.config.bytes();
    changed[634] ^= 1; // Semantic mismatch, but old signature must fail first.
    assert!(matches!(verify(&changed), Err(Error::Auth(_))));
    config_signature(&mut changed, &f.keys);
    assert!(matches!(
        verify(&changed),
        Err(Error::Invalid("AUTH_SEMANTICS"))
    ));
    changed[640] = 1;
    assert!(matches!(
        verify(&changed),
        Err(Error::Invalid("AUTH_ENCODING"))
    ));
    let mut changed = *f.config.bytes();
    changed[64] ^= 1;
    assert!(matches!(
        verify(&changed),
        Err(Error::Invalid("AUTH_CONTEXT_ROLE"))
    ));
    let mut changed = *f.config.bytes();
    changed[128] ^= 1;
    config_signature(&mut changed, &f.keys);
    let other = verify(&changed).unwrap();
    join[80] = 0;
    join[48..80].fill(7);
    assert!(matches!(
        roster.verify_join(&join, &other),
        Err(Error::Invalid("AUTH_CONTEXT_ROLE"))
    ));
    let mut repeated = f.hashes;
    repeated[1] = repeated[0];
    assert!(Roster::verify(repeated, &f.config).is_err());
}

#[test]
fn complete_authorization_and_release_require_all_signed_references() {
    let f = fixture();
    let mut bytes = prefix(&f);
    bytes[120..152].fill(10);
    bytes[248] = 8;
    let a = sign_control(bytes, &f, Kind::AReady, Role::A);
    let mut bytes = *a.bytes();
    bytes[152..184].fill(11);
    bytes[184..216].copy_from_slice(&a.id());
    let key = [14; 32];
    bytes[256..288].copy_from_slice(&domain_hash(
        "SilkNode-F0-release-key",
        &[&f.config.id(), &f.manifest.id(), &key],
    ));
    let b = sign_control(bytes, &f, Kind::BReady, Role::B);
    let acks = [Role::P0, Role::P1, Role::P2].map(|role| {
        let mut bytes = *b.bytes();
        bytes[216..248].copy_from_slice(&b.id());
        sign_control(bytes, &f, Kind::Ack, role)
    });
    let mut bytes = *acks[0].bytes();
    for (i, ack) in acks.iter().enumerate() {
        bytes[320 + 32 * i..352 + 32 * i].copy_from_slice(&ack.id());
    }
    for (i, value) in FENCE.iter().enumerate() {
        bytes[416 + 8 * i..424 + 8 * i].copy_from_slice(&value.to_le_bytes());
    }
    let auth = sign_control(bytes, &f, Kind::Authorize, Role::A);
    let evidence =
        check_authorization(&f.manifest, &a, &b, [&acks[0], &acks[1], &acks[2]], &auth).unwrap();
    let mut bytes = *auth.bytes();
    bytes[288..320].copy_from_slice(&key);
    let release = sign_control(bytes, &f, Kind::Release, Role::B);
    let released = check_release(&evidence, &release).unwrap();
    #[cfg(unix)]
    journal_restart_boundary(
        &f,
        &control::prepare_authorization(&f.manifest, &a, &b, [&acks[0], &acks[1], &acks[2]])
            .unwrap(),
        &evidence,
        &released,
    );
    assert!(
        check_authorization(&f.manifest, &a, &b, [&acks[1], &acks[0], &acks[2]], &auth).is_err()
    );
    let mut changed = *auth.bytes();
    changed[320] ^= 1;
    let unrelated = sign_control(changed, &f, Kind::Authorize, Role::A);
    assert!(
        check_authorization(
            &f.manifest,
            &a,
            &b,
            [&acks[0], &acks[1], &acks[2]],
            &unrelated
        )
        .is_err()
    );
    let mut changed = *release.bytes();
    changed[288] ^= 1;
    let wrong_key = sign_control(changed, &f, Kind::Release, Role::B);
    assert!(check_release(&evidence, &wrong_key).is_err());
    assert!(matches!(
        SignedControl::verify(a.bytes(), &f.config, 6000, Kind::AReady, Role::B),
        Err(Error::Invalid("AUTH_CONTEXT_ROLE"))
    ));
    let mut bytes = prefix(&f);
    bytes[10] = 0;
    let cancel = sign_control(bytes, &f, Kind::Cancel, Role::A);
    assert!(
        check_authorization(&f.manifest, &a, &b, [&acks[0], &acks[1], &acks[2]], &cancel).is_err()
    );
}

#[cfg(unix)]
fn journal_restart_boundary(
    f: &Fixture,
    prepared: &control::PreparedAuthorization,
    evidence: &control::AuthorizationEvidence<'_>,
    released: &control::ReleaseEvidence<'_>,
) {
    use journal::{Decision, Journal};
    use std::os::unix::fs::PermissionsExt;
    for role in [Role::A, Role::B] {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let n = f.config.domain();
        let mut journal = Journal::create(directory.path(), n, 3, role, 5997).unwrap();
        let original_pin = journal.pin();
        assert_eq!(journal.earliest_round(), 6000);
        journal
            .begin(
                &f.config,
                6000,
                f.manifest.bytes()[..128].try_into().unwrap(),
                5999,
            )
            .unwrap();
        assert!(
            journal
                .begin(
                    &f.config,
                    6000,
                    f.manifest.bytes()[..128].try_into().unwrap(),
                    5999
                )
                .is_err()
        );
        journal.manifested(&f.manifest).unwrap();
        if role == Role::A {
            journal.seal_a(prepared).unwrap();
        } else {
            journal.freeze_b(evidence).unwrap();
            journal.release_decided(released).unwrap();
        }
        assert!(journal.abort(6000).is_err());
        let pin = journal.pin();
        drop(journal);
        let before = std::fs::read(directory.path().join("CURRENT")).unwrap();
        assert_eq!(before.len(), 4096);
        assert!(Journal::open(directory.path(), n, 3, role, original_pin, 6000).is_err());
        assert_eq!(
            std::fs::read(directory.path().join("CURRENT")).unwrap(),
            before
        );
        let mut recovered = Journal::open(directory.path(), n, 3, role, pin, 6000).unwrap();
        assert_eq!(recovered.earliest_round(), 6003);
        assert_eq!(
            recovered.decision(6000),
            Some(if role == Role::A {
                Decision::SealedAuth
            } else {
                Decision::DeliveryUnknown
            })
        );
        assert!(recovered.seal_a(prepared).is_err());
        assert!(recovered.release_decided(released).is_err());
        assert!(recovered.delivery(6000, true).is_err());
        assert!(recovered.abort(6000).is_err());
        let pin = recovered.pin();
        // A partial interrupted publication is residue, never an adoptable next head.
        std::fs::write(directory.path().join("STAGE"), [0; 32]).unwrap();
        let bytes = std::fs::read(directory.path().join("CURRENT")).unwrap();
        assert!(recovered.manifested(&f.manifest).is_err());
        assert_eq!(
            std::fs::read(directory.path().join("CURRENT")).unwrap(),
            bytes
        );
        drop(recovered);
        assert!(Journal::open(directory.path(), n, 3, role, pin, 6001).is_err());
    }
}

#[test]
fn nested_manifest_requires_outer_then_nested_signature_before_semantics() {
    let f = fixture();
    for (kind, role, sig) in [
        (Kind::ManifestA, Role::A, 128),
        (Kind::ManifestB, Role::B, 192),
    ] {
        let mut bytes = prefix(&f);
        bytes[88..216].copy_from_slice(&f.manifest.bytes()[..128]);
        bytes[216..280].copy_from_slice(&f.manifest.bytes()[sig..sig + 64]);
        let good = sign_control(bytes, &f, kind, role);
        assert_eq!(
            good.id(),
            domain_hash("SilkNode-F0-control-id", &[good.bytes()])
        );
        let mut changed = *good.bytes();
        changed[88] ^= 1;
        assert!(matches!(
            SignedControl::verify(&changed, &f.config, 6000, kind, role),
            Err(Error::Invalid("AUTH_ENCODING"))
        ));
        let mut changed = *good.bytes();
        changed[96] ^= 1; // Nested N semantics bad and nested signature invalid.
        let msg = message("SilkNode-F0-control", &[&changed[..448]]);
        changed[448..].copy_from_slice(&sign_role(&f.keys[role as usize], &msg).unwrap());
        assert!(matches!(
            SignedControl::verify(&changed, &f.config, 6000, kind, role),
            Err(Error::Auth(_))
        ));
        let msg = message("SilkNode-F0-round", &[&f.config.id(), &changed[88..216]]);
        changed[216..280].copy_from_slice(&sign_role(&f.keys[role as usize], &msg).unwrap());
        let msg = message("SilkNode-F0-control", &[&changed[..448]]);
        changed[448..].copy_from_slice(&sign_role(&f.keys[role as usize], &msg).unwrap());
        assert!(matches!(
            SignedControl::verify(&changed, &f.config, 6000, kind, role),
            Err(Error::Invalid("AUTH_SEMANTICS"))
        ));
    }
}

#[test]
fn cancel_status_is_semantic_after_signature_not_framing() {
    let f = fixture();
    let mut bytes = prefix(&f);
    bytes[10] = 0;
    let good = sign_control(bytes, &f, Kind::Cancel, Role::A);
    for status in [1, 2, 255] {
        let mut changed = *good.bytes();
        changed[10] = status;
        assert!(matches!(
            SignedControl::verify(&changed, &f.config, 6000, Kind::Cancel, Role::A),
            Err(Error::Auth(_))
        ));
        let msg = message("SilkNode-F0-control", &[&changed[..448]]);
        changed[448..].copy_from_slice(&sign_role(&f.keys[0], &msg).unwrap());
        assert!(matches!(
            SignedControl::verify(&changed, &f.config, 6000, Kind::Cancel, Role::A),
            Err(Error::Invalid("AUTH_SEMANTICS"))
        ));
    }
}
