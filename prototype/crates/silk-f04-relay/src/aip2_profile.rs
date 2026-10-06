//! Strict R2 co-signed profile preparation, not setup acceptance or activation.
//! Recompute the complete exact-five-level root locally before exposing a binding.
use ark_bn254::Fr;
use ark_ff::{BigInt, BigInteger, Field, PrimeField};
use sha2::{Digest as _, Sha256};

#[path = "aip2_poseidon_constants.rs"]
mod constants;

/// Exact immutable R2 profile length.
pub const PROFILE_BYTES: usize = 1312;
const BODY: usize = 1184;
const OLD_VK: [u8; 32] = [
    0x25, 0x5e, 0x1f, 0x10, 0xdd, 0x2c, 0x02, 0x5c, 0xe1, 0x61, 0x8c, 0x0a, 0x3c, 0xb3, 0x23, 0x39,
    0xdd, 0x83, 0xf5, 0xc0, 0xd4, 0xff, 0xc4, 0xd2, 0xcb, 0xe6, 0xd5, 0xf7, 0x62, 0xb3, 0xbd, 0x61,
];

/// Local immutable expectations, not data selected from the incoming profile.
/// The key pin identifies bytes only: it cannot accept ceremony/provenance.
pub struct ProfileExpectations {
    /// Ledger domain selected by the caller's configuration owner.
    pub domain: [u8; 32],
    /// Exact configuration identifier.
    pub config: [u8; 32],
    /// Expected epoch, not a peer-provided future epoch.
    pub epoch: u32,
    /// Expected cohort.
    pub cohort: u32,
    /// Locally selected new exact-relation VK hash; NOT trusted setup approval.
    pub vk_hash: [u8; 32],
    /// Already selected A and B signing keys in that order.
    pub role_keys: [[u8; 32]; 2],
}

/// No partial profile or peer-visible diagnosis is returned.
#[derive(Debug, thiserror::Error)]
#[error("AIP2 profile preparation refused: {0}")]
pub struct ProfileError(pub &'static str);
/// Fallible profile check.
pub type ProfileResult<T> = Result<T, ProfileError>;

/// Exact signatures/context/root checked, but NOT an accepted operational P.
/// No activation, staging, release, clock, custody or population conversion.
pub struct PreparedProfile {
    bytes: [u8; PROFILE_BYTES],
    id: [u8; 32],
}
impl PreparedProfile {
    /// Verify fixed encoding, independently expected context and key pin,
    /// strict individual A/B signatures, canonical sorted nonzero commitments,
    /// and the complete five-level Poseidon root. Never reduce Fr aliases.
    pub fn verify(input: &[u8], expected: &ProfileExpectations) -> ProfileResult<Self> {
        let bytes: [u8; PROFILE_BYTES] = input.try_into().map_err(|_| ProfileError("length"))?;
        if &bytes[..8] != b"SNAIP004" {
            return Err(ProfileError("version"));
        }
        if expected.domain == [0; 32]
            || expected.config == [0; 32]
            || expected.vk_hash == [0; 32]
            || expected.vk_hash == OLD_VK
            || expected.role_keys[0] == expected.role_keys[1]
            || bytes[8..40] != expected.domain
            || bytes[40..72] != expected.config
            || bytes[72..76] != expected.epoch.to_le_bytes()
            || bytes[76..80] != expected.cohort.to_le_bytes()
            || bytes[96..128] != expected.vk_hash
        {
            return Err(ProfileError("local context/key pin"));
        }
        let first = u64::from(expected.epoch) * 2880;
        if bytes[80..88] != first.to_le_bytes() || bytes[88..96] != (first + 2880).to_le_bytes() {
            return Err(ProfileError("epoch bounds"));
        }
        let label = b"SilkNode-AIP2R2-profile-sign";
        let mut signed = vec![label.len() as u8];
        signed.extend_from_slice(label);
        signed.extend_from_slice(&bytes[..BODY]);
        if !crate::aip2_signature(&expected.role_keys[0], &signed, &bytes[BODY..BODY + 64])
            || !crate::aip2_signature(&expected.role_keys[1], &signed, &bytes[BODY + 64..])
        {
            return Err(ProfileError("A/B strict signatures"));
        }
        let declared: [u8; 32] = bytes[128..160].try_into().expect("fixed root");
        scalar(&declared)?;
        if declared == [0; 32] {
            return Err(ProfileError("zero root"));
        }
        let mut leaves = [Fr::from(0_u64); 32];
        let mut previous = [0; 32];
        for (i, chunk) in bytes[160..BODY].chunks_exact(32).enumerate() {
            let commitment: [u8; 32] = chunk.try_into().expect("fixed commitment");
            if commitment <= previous {
                return Err(ProfileError("zero/duplicate/unsorted commitments"));
            }
            leaves[i] = scalar(&commitment)?;
            previous = commitment;
        }
        let mut count = 32;
        for _ in 0..5 {
            for i in 0..count / 2 {
                leaves[i] = poseidon_pair(leaves[2 * i], leaves[2 * i + 1]);
            }
            count /= 2;
        }
        if encode(leaves[0]) != declared {
            return Err(ProfileError("recomputed group root"));
        }
        let label = b"SilkNode-AIP2R2-profile";
        let mut hash = Sha256::new();
        hash.update([label.len() as u8]);
        hash.update(label);
        hash.update(&bytes[..BODY]);
        Ok(Self {
            bytes,
            id: hash.finalize().into(),
        })
    }
    /// Public exact co-signed bytes, never private credentials or member indices.
    pub const fn bytes(&self) -> &[u8; PROFILE_BYTES] {
        &self.bytes
    }
    /// Identifier hashes only the unsigned body in the fixed R2 domain.
    pub const fn id(&self) -> [u8; 32] {
        self.id
    }
    /// Locally recomputed canonical complete-group root.
    pub fn root(&self) -> [u8; 32] {
        self.bytes[128..160].try_into().expect("fixed root")
    }
    /// Client must establish its own locally generated commitment occurs once
    /// before durable pin/ack. Does not create proof or reveal an index at B.
    pub fn check_own_commitment(&self, own: [u8; 32]) -> ProfileResult<()> {
        scalar(&own)?;
        if own == [0; 32]
            || self.bytes[160..BODY]
                .chunks_exact(32)
                .filter(|v| *v == own)
                .count()
                != 1
        {
            return Err(ProfileError("own commitment absent"));
        }
        Ok(())
    }
    /// Preparation binding only. The caller must separately enforce one profile
    /// per epoch, durable pin/all-32 ack, setup, clock and schedule acceptance.
    #[cfg(unix)]
    pub fn claim_binding(
        &self,
        role: crate::aip2_claim::ClaimRole,
    ) -> crate::aip2_claim::PreparedClaimBinding {
        crate::aip2_claim::PreparedClaimBinding {
            role,
            domain: self.bytes[8..40].try_into().expect("fixed domain"),
            config: self.bytes[40..72].try_into().expect("fixed config"),
            profile: self.id,
            vk_hash: self.bytes[96..128].try_into().expect("fixed VK"),
            epoch: u32::from_le_bytes(self.bytes[72..76].try_into().expect("fixed epoch")),
        }
    }
}
fn scalar(bytes: &[u8; 32]) -> ProfileResult<Fr> {
    let mut limbs = [0; 4];
    for (i, part) in bytes.chunks_exact(8).enumerate() {
        limbs[3 - i] = u64::from_be_bytes(part.try_into().expect("eight"));
    }
    Fr::from_bigint(BigInt(limbs)).ok_or(ProfileError("noncanonical scalar"))
}
fn encode(value: Fr) -> [u8; 32] {
    value
        .into_bigint()
        .to_bytes_be()
        .try_into()
        .expect("BN254 fixed 32 bytes")
}
fn poseidon_pair(left: Fr, right: Fr) -> Fr {
    let mut state = [Fr::from(0_u64), left, right];
    for round in 0..65 {
        for (i, value) in state.iter_mut().enumerate() {
            *value += constants::C[3 * round + i];
            if round < 4 || round >= 61 || i == 0 {
                *value = value.square().square() * *value;
            }
        }
        let old = state;
        for (i, value) in state.iter_mut().enumerate() {
            *value = constants::M[i].iter().zip(old).map(|(m, x)| *m * x).sum();
        }
    }
    state[0]
}

#[cfg(test)]
mod tests;
