//! Exact core profile checks, using the exact existing core Ed predicate.
use super::*;
use crate::aip2_proof::{domain_hash, hex};
use ed25519_dalek::{Signer, SigningKey};

fn expected() -> ProfileExpectations {
    ProfileExpectations {
        domain: [0x41; 32],
        config: [0x42; 32],
        epoch: 0,
        cohort: 7,
        vk_hash: hex("4bfb5cfded94426c4e6cfba10eadd61b0f98657847407cc6ff515254426c4ad7").unwrap(),
        role_keys: [
            SigningKey::from_bytes(&[11; 32]).verifying_key().to_bytes(),
            SigningKey::from_bytes(&[12; 32]).verifying_key().to_bytes(),
        ],
    }
}
fn sign(bytes: &mut [u8; PROFILE_BYTES]) {
    let label = b"SilkNode-AIP2R2-profile-sign";
    let mut msg = vec![label.len() as u8];
    msg.extend_from_slice(label);
    msg.extend_from_slice(&bytes[..1184]);
    for (i, seed) in [11, 12].into_iter().enumerate() {
        bytes[1184 + i * 64..1248 + i * 64]
            .copy_from_slice(&SigningKey::from_bytes(&[seed; 32]).sign(&msg).to_bytes());
    }
}
fn fixture() -> [u8; PROFILE_BYTES] {
    let e = expected();
    let mut p = [0; PROFILE_BYTES];
    p[..8].copy_from_slice(b"SNAIP004");
    p[8..40].copy_from_slice(&e.domain);
    p[40..72].copy_from_slice(&e.config);
    p[76..80].copy_from_slice(&e.cohort.to_le_bytes());
    p[88..96].copy_from_slice(&2880_u64.to_le_bytes());
    p[96..128].copy_from_slice(&e.vk_hash);
    // Cross-language reference from pinned poseidon-lite, not this Rust code.
    p[128..160].copy_from_slice(
        &hex::<32>("2ac136f871e2d83be9f7d93b8689865e5603d76d02185da93291e3fba44520b2").unwrap(),
    );
    for i in 0..32 {
        p[191 + 32 * i] = (i + 1) as u8;
    }
    sign(&mut p);
    p
}
#[test]
fn profile_exact_signed_root_and_binding() {
    let p = fixture();
    let checked = PreparedProfile::verify(&p, &expected()).unwrap();
    assert_eq!(checked.bytes(), &p);
    assert_eq!(checked.root(), p[128..160]);
    let mut own = [0; 32];
    own[31] = 7;
    checked.check_own_commitment(own).unwrap();
    use crate::aip2_claim::{ClaimPinRetention, ClaimResult, ClaimRole, PreparedScopeStore};
    struct Pins;
    impl ClaimPinRetention for Pins {
        fn retain_claim_pin(&mut self, _: [u8; 32]) -> ClaimResult<()> {
            Ok(())
        }
    }
    use std::os::unix::fs::PermissionsExt;
    let path = std::env::temp_dir().join(format!("aip2-profile-binding-{}", std::process::id()));
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let binding = checked.claim_binding(ClaimRole::Client);
    assert_eq!(binding.profile, checked.id());
    let mut store = PreparedScopeStore::create(&path, binding, Pins).unwrap();
    assert!(store.consume(5, [9; 32], [10; 32]).is_ok());
    assert!(store.consume(5, [11; 32], [12; 32]).is_err());
}
#[test]
fn profile_canonical_group_refusals_even_when_resigned() {
    for offset in [160, 128] {
        let mut p = fixture();
        p[offset..offset + 32].copy_from_slice(
            &hex::<32>("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001").unwrap(),
        );
        sign(&mut p);
        assert!(PreparedProfile::verify(&p, &expected()).is_err());
    }
    for mode in 0..4 {
        let mut p = fixture();
        match mode {
            0 => p[160..192].fill(0),
            1 => p[223] = 1,
            2 => {
                p[191] = 2;
                p[223] = 1;
            }
            _ => p[128..160].fill(0),
        }
        sign(&mut p);
        assert!(PreparedProfile::verify(&p, &expected()).is_err());
    }
}
#[test]
fn profile_recomputes_all_five_levels() {
    let mut p = fixture();
    p[1183] = 33;
    sign(&mut p);
    assert_eq!(
        PreparedProfile::verify(&p, &expected()).err().unwrap().0,
        "recomputed group root"
    );
    p = fixture();
    p[159] ^= 1;
    sign(&mut p);
    assert!(PreparedProfile::verify(&p, &expected()).is_err());
}
#[test]
fn profile_no_member_or_scalar_alias() {
    let p = PreparedProfile::verify(&fixture(), &expected()).unwrap();
    assert!(p.check_own_commitment([0; 32]).is_err());
    let mut absent = [0; 32];
    absent[31] = 33;
    assert!(p.check_own_commitment(absent).is_err());
    assert!(p.check_own_commitment([255; 32]).is_err());
}
#[test]
fn profile_wrong_context_bounds_and_key() {
    for at in [8, 40, 72, 76, 80, 88, 96] {
        let mut p = fixture();
        p[at] ^= 1;
        sign(&mut p);
        assert!(PreparedProfile::verify(&p, &expected()).is_err());
    }
    for vk_hash in [
        [0; 32],
        hex("255e1f10dd2c025ce1618c0a3cb32339dd83f5c0d4ffc4d2cbe6d5f762b3bd61").unwrap(),
        [99; 32],
    ] {
        let mut e = expected();
        e.vk_hash = vk_hash;
        assert!(PreparedProfile::verify(&fixture(), &e).is_err());
    }
}
#[test]
fn profile_strict_signatures_and_no_legacy() {
    for at in [1184, 1216, 1248, 1280] {
        let mut p = fixture();
        p[at..at + 32].fill(255);
        assert!(PreparedProfile::verify(&p, &expected()).is_err());
    }
    let mut p = fixture();
    let a = p[1184..1248].to_vec();
    let b = p[1248..].to_vec();
    p[1184..1248].copy_from_slice(&b);
    p[1248..].copy_from_slice(&a);
    assert!(PreparedProfile::verify(&p, &expected()).is_err());
    let mut e = expected();
    e.role_keys[1] = e.role_keys[0];
    assert!(PreparedProfile::verify(&fixture(), &e).is_err());
    p = fixture();
    p[..8].copy_from_slice(b"SNAIP003");
    sign(&mut p);
    assert!(PreparedProfile::verify(&p, &expected()).is_err());
    assert!(PreparedProfile::verify(&p[..1311], &expected()).is_err());
}
#[test]
fn profile_largest_epoch_exact_bounds() {
    let mut p = fixture();
    let mut e = expected();
    e.epoch = u32::MAX;
    p[72..76].copy_from_slice(&e.epoch.to_le_bytes());
    let first = u64::from(e.epoch) * 2880;
    p[80..88].copy_from_slice(&first.to_le_bytes());
    p[88..96].copy_from_slice(&(first + 2880).to_le_bytes());
    sign(&mut p);
    assert!(PreparedProfile::verify(&p, &e).is_ok());
}
#[test]
fn profile_signature_domain_and_identifier_are_exact() {
    let p = fixture();
    let checked = PreparedProfile::verify(&p, &expected()).unwrap();
    let id = domain_hash("SilkNode-AIP2R2-profile", &[&p[..1184]]);
    assert_eq!(id, checked.id());
    let mut wrong = p;
    let msg = domain_hash("SilkNode-AIP2R2-profile-sign", &[&p[..1184]]);
    wrong[1184..1248].copy_from_slice(&SigningKey::from_bytes(&[11; 32]).sign(&msg).to_bytes());
    assert!(PreparedProfile::verify(&wrong, &expected()).is_err());
}
