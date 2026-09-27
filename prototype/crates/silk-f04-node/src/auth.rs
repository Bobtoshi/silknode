//! F0.4 Appendix C pure Ed25519 individual predicate; not library-default key policy.
use crate::{Digest, Error, Result};
use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::IsIdentity,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// Canonical nonidentity prime-order point, with exact original bytes retained.
pub fn admit_role_key(bytes: &[u8]) -> Result<VerifyingKey> {
    let bytes: &Digest = bytes
        .try_into()
        .map_err(|_| Error::Invalid("ED_KEY_LENGTH"))?;
    admit_point(bytes, false)?;
    VerifyingKey::from_bytes(bytes).map_err(|_| Error::Unavailable("AUTH_LOCAL_FAILURE"))
}

fn admit_point(bytes: &Digest, is_r: bool) -> Result<EdwardsPoint> {
    let labels = if is_r {
        [
            "ED_R_Y_RANGE",
            "ED_R_NOT_CURVE",
            "ED_R_SIGN",
            "ED_R_REENCODE",
            "ED_R_IDENTITY",
            "ED_R_SUBGROUP",
        ]
    } else {
        [
            "ED_KEY_Y_RANGE",
            "ED_KEY_NOT_CURVE",
            "ED_KEY_SIGN",
            "ED_KEY_REENCODE",
            "ED_KEY_IDENTITY",
            "ED_KEY_SUBGROUP",
        ]
    };
    let mut y = *bytes;
    y[31] &= 127;
    let mut p = [255; 32];
    p[0] = 237;
    p[31] = 127;
    if y.iter().rev().cmp(p.iter().rev()) != std::cmp::Ordering::Less {
        return Err(Error::Invalid(labels[0]));
    }
    let point = CompressedEdwardsY(*bytes)
        .decompress()
        .ok_or(Error::Invalid(labels[1]))?;
    let mut one = [0; 32];
    one[0] = 1;
    let mut minus_one = p;
    minus_one[0] -= 1;
    if bytes[31] & 128 != 0 && (y == one || y == minus_one) {
        return Err(Error::Invalid(labels[2]));
    }
    if point.compress().to_bytes() != *bytes {
        return Err(Error::Invalid(labels[3]));
    }
    if point.is_identity() {
        return Err(Error::Invalid(labels[4]));
    }
    if !point.is_torsion_free() {
        return Err(Error::Invalid(labels[5]));
    }
    Ok(point)
}

/// Exact individually checked application signature, including R admission and S range.
pub fn verify_role_signature(key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    if key.len() != 32 {
        return Err(Error::Invalid("ED_KEY_LENGTH"));
    }
    let signature: &[u8; 64] = signature
        .try_into()
        .map_err(|_| Error::Invalid("ED_SIG_LENGTH"))?;
    let key = admit_role_key(key)?;
    admit_point(&signature[..32].try_into().expect("fixed signature"), true)?;
    Option::<Scalar>::from(Scalar::from_canonical_bytes(
        signature[32..].try_into().expect("fixed signature"),
    ))
    .ok_or(Error::Invalid("ED_S_RANGE"))?;
    key.verify_strict(message, &Signature::from_bytes(signature))
        .map_err(|_| Error::Invalid("ED_EQUATION"))
}

/// Ordinary deterministic pure-Ed25519 signing followed by the complete exact predicate.
/// An exceptional nonadmitted result refuses; there is no nonce/key/message retry.
pub fn sign_role(key: &SigningKey, message: &[u8]) -> Result<[u8; 64]> {
    let signature = key.sign(message).to_bytes();
    verify_role_signature(&key.verifying_key().to_bytes(), message, &signature)
        .map_err(|_| Error::Unavailable("AUTH_LOCAL_FAILURE"))?;
    Ok(signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn label(result: Result<()>) -> &'static str {
        match result {
            Ok(()) => "ED_OK",
            Err(Error::Invalid(label)) => label,
            _ => panic!("unexpected local error"),
        }
    }
    #[test]
    fn exact_error_precedence_and_noncanonical_families() {
        let sk = SigningKey::from_bytes(&[31; 32]);
        let pk = sk.verifying_key().to_bytes();
        let sig = sign_role(&sk, b"fixture").unwrap();
        assert_eq!(
            label(verify_role_signature(&[], b"fixture", &[])),
            "ED_KEY_LENGTH"
        );
        assert_eq!(
            label(verify_role_signature(&[0; 32], b"fixture", &[])),
            "ED_SIG_LENGTH"
        );
        for y in 237_u8..=255 {
            for sign in [0_u8, 128] {
                let mut point = [255; 32];
                point[0] = y;
                point[31] = 127 | sign;
                assert_eq!(label(admit_role_key(&point).map(|_| ())), "ED_KEY_Y_RANGE");
                let mut bad = sig;
                bad[..32].copy_from_slice(&point);
                bad[32..].fill(255);
                assert_eq!(
                    label(verify_role_signature(&pk, b"fixture", &bad)),
                    "ED_R_Y_RANGE"
                );
            }
        }
        for mut point in [
            [
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            [
                236, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
            ],
        ] {
            point[31] |= 128;
            assert_eq!(label(admit_role_key(&point).map(|_| ())), "ED_KEY_SIGN");
            let mut bad = sig;
            bad[..32].copy_from_slice(&point);
            assert_eq!(
                label(verify_role_signature(&pk, b"fixture", &bad)),
                "ED_R_SIGN"
            );
        }
        for torsion in curve25519_dalek::constants::EIGHT_TORSION.iter().skip(1) {
            let mixed = (curve25519_dalek::constants::ED25519_BASEPOINT_POINT + torsion)
                .compress()
                .to_bytes();
            assert_eq!(label(admit_role_key(&mixed).map(|_| ())), "ED_KEY_SUBGROUP");
            let mut bad = sig;
            bad[..32].copy_from_slice(&mixed);
            assert_eq!(
                label(verify_role_signature(&pk, b"fixture", &bad)),
                "ED_R_SUBGROUP"
            );
        }
        let mut bad = sig;
        bad[32..].copy_from_slice(
            &hex::decode("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
                .unwrap(),
        );
        assert_eq!(
            label(verify_role_signature(&pk, b"fixture", &bad)),
            "ED_S_RANGE"
        );
        assert_eq!(
            label(verify_role_signature(&pk, b"wrong message", &sig)),
            "ED_EQUATION"
        );
    }
    #[test]
    fn pure_signature_and_exact_admission() {
        let sk = SigningKey::from_bytes(&[19; 32]);
        let pk = sk.verifying_key().to_bytes();
        let sig = sign_role(&sk, b"exact application message").unwrap();
        verify_role_signature(&pk, b"exact application message", &sig).unwrap();
        assert!(verify_role_signature(&pk, b"other message", &sig).is_err());
        let mut identity = [0; 32];
        identity[0] = 1;
        assert!(admit_role_key(&identity).is_err());
        identity[31] = 128;
        assert!(admit_role_key(&identity).is_err());
        let mut noncanonical = [255; 32];
        noncanonical[0] = 237;
        noncanonical[31] = 127;
        assert!(admit_role_key(&noncanonical).is_err());
        for p in curve25519_dalek::constants::EIGHT_TORSION {
            assert!(admit_role_key(&p.compress().to_bytes()).is_err());
        }
        let mut bad = sig;
        bad[..32].fill(0);
        bad[0] = 1;
        assert!(verify_role_signature(&pk, b"exact application message", &bad).is_err());
        bad = sig;
        bad[32..].fill(255);
        assert!(verify_role_signature(&pk, b"exact application message", &bad).is_err());
    }
}
