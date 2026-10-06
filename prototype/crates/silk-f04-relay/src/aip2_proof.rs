//! Native exact-relation verification preparation. NOT ceremony approval,
//! operational admission, transport ownership, staging or release authority.
use crate::aip2_claim::{ClaimPinRetention, ClaimRole, ConsumedScope};
use crate::aip2_profile::PreparedProfile;
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInt, PrimeField};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, VerifyingKey, prepare_verifying_key};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;
use std::collections::BTreeSet;
/// A local refusal, never a successful proof or operational release decision.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("AIP2 interoperability refusal: {0}")]
    Interop(&'static str),
    #[error("exact core auth invalid: {0}")]
    Invalid(&'static str),
    #[error("exact core auth unavailable: {0}")]
    Unavailable(&'static str),
}
#[allow(non_snake_case)]
pub fn Error(label: &'static str) -> Error {
    Error::Interop(label)
}
/// Fallible interoperability operation.
pub type Result<T> = std::result::Result<T, Error>;

pub fn hex<const N: usize>(text: &str) -> Result<[u8; N]> {
    if text.len() != 2 * N {
        return Err(Error("hex length"));
    }
    let mut out = [0; N];
    fn nibble(x: u8) -> Result<u8> {
        match x {
            b'0'..=b'9' => Ok(x - b'0'),
            b'a'..=b'f' => Ok(x - b'a' + 10),
            _ => Err(Error("hex alphabet")),
        }
    }
    for (i, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        out[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(out)
}
fn be_integer(bytes: &[u8; 32]) -> BigInt<4> {
    let mut limbs = [0; 4];
    for (i, part) in bytes.chunks_exact(8).enumerate() {
        limbs[3 - i] = u64::from_be_bytes(part.try_into().expect("eight"));
    }
    BigInt(limbs)
}
fn decimal_integer(text: &str) -> Result<BigInt<4>> {
    if text.is_empty()
        || text.len() > 78
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|x| x.is_ascii_digit())
    {
        return Err(Error("noncanonical decimal"));
    }
    let mut limbs = [0_u64; 4];
    for digit in text.bytes() {
        let mut carry = u128::from(digit - b'0');
        for limb in &mut limbs {
            let value = u128::from(*limb) * 10 + carry;
            *limb = value as u64;
            carry = value >> 64;
        }
        if carry != 0 {
            return Err(Error("integer overflow"));
        }
    }
    Ok(BigInt(limbs))
}
fn fq(text: &str) -> Result<Fq> {
    Fq::from_bigint(decimal_integer(text)?).ok_or(Error("noncanonical Fq"))
}
fn fq_be(bytes: &[u8; 32]) -> Result<Fq> {
    Fq::from_bigint(be_integer(bytes)).ok_or(Error("noncanonical Fq"))
}
fn fr_be(bytes: &[u8; 32]) -> Result<Fr> {
    Fr::from_bigint(be_integer(bytes)).ok_or(Error("noncanonical Fr"))
}
fn g1(x: Fq, y: Fq) -> Result<G1Affine> {
    let point = G1Affine::new_unchecked(x, y);
    if point.is_zero() || !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve()
    {
        return Err(Error("G1 curve/subgroup/identity"));
    }
    Ok(point)
}
fn g2(x: Fq2, y: Fq2) -> Result<G2Affine> {
    let point = G2Affine::new_unchecked(x, y);
    if point.is_zero() || !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve()
    {
        return Err(Error("G2 curve/subgroup/identity"));
    }
    Ok(point)
}
fn json_g1(values: &[String]) -> Result<G1Affine> {
    if values.len() != 3 || values[2] != "1" {
        return Err(Error("G1 affine encoding"));
    }
    g1(fq(&values[0])?, fq(&values[1])?)
}
fn json_g2(values: &[Vec<String>]) -> Result<G2Affine> {
    if values.len() != 3 || values.iter().any(|x| x.len() != 2) || values[2] != ["1", "0"] {
        return Err(Error("G2 affine encoding"));
    }
    g2(
        Fq2::new(fq(&values[0][0])?, fq(&values[0][1])?),
        Fq2::new(fq(&values[1][0])?, fq(&values[1][1])?),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonKey {
    protocol: String,
    curve: String,
    #[serde(rename = "nPublic")]
    public: usize,
    vk_alpha_1: Vec<String>,
    vk_beta_2: Vec<Vec<String>>,
    vk_gamma_2: Vec<Vec<String>>,
    vk_delta_2: Vec<Vec<String>>,
    vk_alphabeta_12: Vec<Vec<Vec<String>>>,
    #[serde(rename = "IC")]
    ic: Vec<Vec<String>>,
}

/// A byte-pinned mathematical verifier. A pin does NOT approve its ceremony.
/// Shared by the optional core preparation module and the isolated native lab.
pub struct PreparedProofVerifier {
    key: PreparedVerifyingKey<Bn254>,
    hash: [u8; 32],
}
impl PreparedProofVerifier {
    pub(crate) const fn key_hash(&self) -> [u8; 32] {
        self.hash
    }
    /// Require exact standalone canonical snarkjs VK bytes and a locally chosen
    /// hash. Reject the old Semaphore relation even if caller pins its hash.
    pub fn from_canonical_vk(bytes: &[u8], expected: [u8; 32]) -> Result<Self> {
        if bytes.len() > 16384 {
            return Err(Error("VK size"));
        }
        let old = hex::<32>("255e1f10dd2c025ce1618c0a3cb32339dd83f5c0d4ffc4d2cbe6d5f762b3bd61")?;
        if expected == old {
            return Err(Error("historical VK forbidden"));
        }
        if <[u8; 32]>::from(Sha256::digest(bytes)) != expected {
            return Err(Error("VK hash"));
        }
        let value: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|_| Error("VK JSON"))?;
        if serde_json::to_vec(&value).map_err(|_| Error("VK JSON"))? != bytes {
            return Err(Error("VK not canonical or duplicate keys"));
        }
        let parsed: JsonKey = serde_json::from_value(value).map_err(|_| Error("VK schema"))?;
        if parsed.protocol != "groth16"
            || parsed.curve != "bn128"
            || parsed.public != 4
            || parsed.ic.len() != 5
        {
            return Err(Error("VK protocol/curve/public count"));
        }
        if parsed.vk_alphabeta_12.len() != 2
            || parsed
                .vk_alphabeta_12
                .iter()
                .any(|row| row.len() != 3 || row.iter().any(|pair| pair.len() != 2))
        {
            return Err(Error("VK pairing encoding"));
        }
        // snarkjs exports this cache, but arkworks recomputes the pairing from
        // checked alpha/beta points. Never use peer-supplied cached pairing math.
        for row in parsed.vk_alphabeta_12 {
            for pair in row {
                for coefficient in pair {
                    fq(&coefficient)?;
                }
            }
        }
        let key = VerifyingKey {
            alpha_g1: json_g1(&parsed.vk_alpha_1)?,
            beta_g2: json_g2(&parsed.vk_beta_2)?,
            gamma_g2: json_g2(&parsed.vk_gamma_2)?,
            delta_g2: json_g2(&parsed.vk_delta_2)?,
            gamma_abc_g1: parsed
                .ic
                .iter()
                .map(|point| json_g1(point))
                .collect::<Result<_>>()?,
        };
        Ok(Self {
            key: prepare_verifying_key(&key),
            hash: expected,
        })
    }
    /// Genuine pairing verification over four locally bound inputs. The cover
    /// context selects root, proof-validates the cell nullifier and recomputes
    /// message/scope. Canonical point checks precede pairing.
    pub fn verify(&self, packed: &[u8; 256], inputs: &[[u8; 32]; 4]) -> Result<()> {
        let mut coordinates = Vec::with_capacity(8);
        for bytes in packed.chunks_exact(32) {
            coordinates.push(fq_be(bytes.try_into().expect("32"))?);
        }
        let proof = Proof::<Bn254> {
            a: g1(coordinates[0], coordinates[1])?,
            // Upstream packing swaps each G2 pair; restore native c0/c1.
            b: g2(
                Fq2::new(coordinates[3], coordinates[2]),
                Fq2::new(coordinates[5], coordinates[4]),
            )?,
            c: g1(coordinates[6], coordinates[7])?,
        };
        let public = inputs.iter().map(fr_be).collect::<Result<Vec<_>>>()?;
        match Groth16::<Bn254>::verify_proof(&self.key, &proof, &public) {
            Ok(true) => Ok(()),
            _ => Err(Error("Groth16 verification")),
        }
    }
}

pub(crate) fn domain_hash(label: &str, parts: &[&[u8]]) -> [u8; 32] {
    assert!(label.is_ascii() && label.len() < 256);
    let mut hash = Sha256::new();
    hash.update([label.len() as u8]);
    hash.update(label.as_bytes());
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}
/// Strict Fr encoding check; never reduce aliases.
pub fn canonical_scalar(bytes: &[u8; 32]) -> Result<()> {
    fr_be(bytes).map(|_| ())
}
/// Fixed Semaphore conversion: Keccak BE256, right shift eight, exactly once.
pub fn semaphore_scalar(integer: &[u8; 32]) -> [u8; 32] {
    let digest = Keccak256::digest(integer);
    let mut result = [0; 32];
    result[1..].copy_from_slice(&digest[..31]);
    result
}
/// Local cover witness statement before proof/nullifier insertion. NOT a cell
/// that can be sent, accepted, encrypted for release or treated as verified.
pub struct PreparedCoverStatement {
    cell: [u8; 4096],
    root: [u8; 32],
    message: [u8; 32],
    scope: [u8; 32],
}
impl PreparedCoverStatement {
    /// Unproved cover skeleton, with zero nullifier/proof and no payload.
    pub fn cell(&self) -> &[u8; 4096] {
        &self.cell
    }
    /// Exact locally recomputed message for durable client consumption.
    pub const fn message(&self) -> [u8; 32] {
        self.message
    }
    /// Common locally recomputed scope, independent of manifest/message/member.
    pub const fn scope(&self) -> [u8; 32] {
        self.scope
    }
    /// Locally recomputed group root.
    pub const fn root(&self) -> [u8; 32] {
        self.root
    }
}
/// Build the one fixed cover statement from checked P and local M/round.
/// This preparation does not create a membership proof or accept a ceremony.
pub fn prepare_cover_statement(
    profile: &PreparedProfile,
    manifest: [u8; 32],
    round: u64,
) -> Result<PreparedCoverStatement> {
    let p = profile.bytes();
    let first = u64::from_le_bytes(p[80..88].try_into().expect("eight"));
    let last = u64::from_le_bytes(p[88..96].try_into().expect("eight"));
    if manifest == [0; 32] || round < first || round >= last {
        return Err(Error("cover context/bounds"));
    }
    let mut cell = [0; 4096];
    cell[..8].copy_from_slice(b"SNZKP004");
    cell[16..24].copy_from_slice(&round.to_le_bytes());
    cell[24..56].copy_from_slice(&p[8..40]);
    cell[56..60].copy_from_slice(&p[76..80]);
    cell[60..64].copy_from_slice(&p[72..76]);
    cell[64..96].copy_from_slice(&profile.id());
    cell[96..128].copy_from_slice(&manifest);
    let scope = semaphore_scalar(&domain_hash(
        "SilkNode-AIP2R2-scope",
        &[
            &p[8..40],
            &p[40..72],
            &profile.id(),
            &p[76..80],
            &p[72..76],
            &round.to_le_bytes(),
        ],
    ));
    let message = semaphore_scalar(&domain_hash(
        "SilkNode-AIP2R2-message",
        &[&cell[..128], &cell[416..]],
    ));
    Ok(PreparedCoverStatement {
        cell,
        root: profile.root(),
        message,
        scope,
    })
}
/// Opaque complete native-verified cover cohort. No payload/member labels,
/// Clone/Deserialize/public constructor, staging or release conversion.
/// This is preparation, NOT an accepted operational profile or anonymity result.
pub struct PreparedAnonymousCohort {
    nullifiers: BTreeSet<[u8; 32]>,
}
impl PreparedAnonymousCohort {
    /// Consume the actual exit receipt by value. Bind its role/N/C/P/VK/epoch,
    /// original round/M/message and verifier pin to checked P; then verify all
    /// 32 actual proofs and distinct canonical nullifiers. Any error leaves the
    /// owner's consumed round consumed. No Sapling work or partial output.
    pub fn verify_cover<P: ClaimPinRetention>(
        verifier: &PreparedProofVerifier,
        profile: &PreparedProfile,
        claim: ConsumedScope<'_, P>,
        cells: &[[u8; 4096]],
    ) -> Result<Self> {
        if claim.binding() != profile.claim_binding(ClaimRole::Exit)
            || verifier.hash != claim.binding().vk_hash
        {
            return Err(Error("profile/exit claim/verifier binding"));
        }
        let statement = prepare_cover_statement(profile, claim.manifest(), claim.round())?;
        if statement.message() != claim.message() {
            return Err(Error("consumed cover message"));
        }
        if cells.len() != 32 {
            return Err(Error("incomplete anonymous cohort"));
        }
        let mut nullifiers = BTreeSet::new();
        for cell in cells {
            if cell[..128] != statement.cell[..128] || cell[416..].iter().any(|byte| *byte != 0) {
                return Err(Error("signed-profile cover/context/padding"));
            }
            let nullifier: [u8; 32] = cell[128..160].try_into().expect("32");
            fr_be(&nullifier)?;
            if !nullifiers.insert(nullifier) {
                return Err(Error("duplicate round nullifier"));
            }
            verifier.verify(
                cell[160..416].try_into().expect("256"),
                &[
                    statement.root,
                    nullifier,
                    statement.message,
                    statement.scope,
                ],
            )?;
        }
        Ok(Self { nullifiers })
    }
    /// Verified cover count only. No route to producer payload or release.
    pub fn count(&self) -> usize {
        self.nullifiers.len()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decimal_refusals() {
        for s in ["", "00", "01", "+1", "-1", "1\n", " 1", "1.0"] {
            assert!(decimal_integer(s).is_err());
        }
    }
    #[test]
    fn decimal_overflow() {
        assert!(decimal_integer(&"9".repeat(78)).is_err());
    }
    #[test]
    fn field_not_reduced() {
        assert!(
            fq("21888242871839275222246405745257275088696311157297823662689037894645226208583")
                .is_err()
        );
    }
    #[test]
    fn scalar_not_reduced() {
        assert!(
            fr_be(
                &hex::<32>("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001")
                    .unwrap()
            )
            .is_err()
        );
    }
    #[test]
    fn point_identity_refused() {
        assert!(g1(Fq::from(0), Fq::from(0)).is_err());
        assert!(g2(Fq2::from(0), Fq2::from(0)).is_err());
    }
    #[test]
    fn noncurve_refused() {
        assert!(g1(Fq::from(1), Fq::from(1)).is_err());
    }
    #[test]
    fn non_subgroup_g2_refused() {
        let point = (1_u64..100)
            .find_map(|x| {
                G2Affine::get_point_from_x_unchecked(Fq2::new(Fq::from(x), Fq::from(0)), false)
                    .filter(|p| !p.is_in_correct_subgroup_assuming_on_curve())
            })
            .expect("twist point outside subgroup");
        assert!(point.is_on_curve());
        assert!(g2(point.x, point.y).is_err());
    }
    #[test]
    fn hex_refusals() {
        assert!(hex::<1>("FF").is_err());
        assert!(hex::<1>("0").is_err());
        assert!(hex::<1>("gg").is_err());
    }
    #[test]
    fn old_key_forbidden() {
        assert!(
            PreparedProofVerifier::from_canonical_vk(
                b"{}",
                hex("255e1f10dd2c025ce1618c0a3cb32339dd83f5c0d4ffc4d2cbe6d5f762b3bd61").unwrap()
            )
            .is_err()
        );
    }
    #[test]
    fn hash_checked_before_key() {
        assert!(PreparedProofVerifier::from_canonical_vk(b"{}", [0; 32]).is_err());
    }
}
