//! Version-two `RandomX` production-candidate proof suite.

use crate::{DerivedWork, MAX_LOCAL_MINING_ATTEMPTS, WorkSubject};
use silk_gate2::Hash32;
use silk_randomx::{RandomXError, RandomXV2Vm};
use thiserror::Error;

const PROOF_MAGIC: [u8; 8] = *b"SLKPOW\0\0";
const TRANSCRIPT_DOMAIN: &[u8] = b"SilkNode/PoW/RandomX-v2.0.1/Transcript/v2\0";
const WORK_KEY_DOMAIN: &[u8] = b"SilkNode/PoW/RandomX-v2.0.1/WorkKey/v1";
const HASH_FIELDS: usize = 14;
const U64_FIELDS: usize = 5;

/// Canonical proof-wire version for the `RandomX` v2 suite.
pub const RANDOMX_V2_PROOF_VERSION: u16 = 2;
/// Semantic suite version committed into every proof and job.
pub const RANDOMX_V2_SUITE_VERSION: u16 = 2;
/// Highest DAA difficulty accepted by the bounded candidate profile.
pub const MAX_RANDOMX_V2_DIFFICULTY: u64 = 1_000_000;
/// Exact canonical byte length of one `RandomX` v2 proof.
pub const RANDOMX_V2_PROOF_BYTES: usize = 8 + 2 + 2 + 4 + HASH_FIELDS * 32 + U64_FIELDS * 8;

/// SHA-256 identifier of `SilkNode/PoW/RandomX-v2.0.1/Suite/v2`.
pub const RANDOMX_V2_SUITE_ID: Hash32 = [
    0x8e, 0x8c, 0xe4, 0xfd, 0xba, 0xe0, 0x87, 0x0b, 0x13, 0xf5, 0x97, 0xbf, 0x5e, 0xd0, 0xf4, 0x5a,
    0x88, 0x9c, 0x93, 0x10, 0xb2, 0x23, 0xea, 0x71, 0x69, 0x3b, 0x33, 0x23, 0xf4, 0xc3, 0xba, 0xe8,
];

/// SHA-256 identifier of the checked 256-bit target policy.
pub const RANDOMX_V2_TARGET_POLICY_ID: Hash32 = [
    0x23, 0x34, 0x4f, 0x66, 0x6c, 0x81, 0x84, 0x5d, 0x1c, 0x26, 0xeb, 0xd3, 0x63, 0x25, 0x2e, 0x45,
    0x92, 0x25, 0x5c, 0x76, 0x40, 0x33, 0x48, 0x15, 0x65, 0x27, 0xf3, 0x21, 0x02, 0x3d, 0xe2, 0xe2,
];

/// A canonical unsigned 256-bit big-endian integer.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Uint256([u8; 32]);

impl Uint256 {
    /// The exact zero value.
    pub const ZERO: Self = Self([0; 32]);
    /// The greatest unsigned 256-bit value.
    pub const MAX: Self = Self([u8::MAX; 32]);

    /// Construct an exact canonical integer from big-endian bytes.
    #[must_use]
    pub const fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Construct an integer from a bounded `u64`.
    #[must_use]
    pub const fn from_u64(value: u64) -> Self {
        let mut bytes = [0_u8; 32];
        let encoded = value.to_be_bytes();
        let mut index = 0;
        while index < 8 {
            bytes[24 + index] = encoded[index];
            index += 1;
        }
        Self(bytes)
    }

    /// Return the exact canonical big-endian bytes.
    #[must_use]
    pub const fn to_be_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Returns whether this value is zero.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        let mut index = 0;
        while index < self.0.len() {
            if self.0[index] != 0 {
                return false;
            }
            index += 1;
        }
        true
    }

    /// Adds two exact values, returning `None` on unsigned overflow.
    #[must_use]
    pub fn checked_add(self, other: Self) -> Option<Self> {
        let mut result = [0_u8; 32];
        let mut carry = false;
        for index in (0..32).rev() {
            let (partial, carry_a) = self.0[index].overflowing_add(other.0[index]);
            let (sum, carry_b) = partial.overflowing_add(u8::from(carry));
            result[index] = sum;
            carry = carry_a || carry_b;
        }
        (!carry).then_some(Self(result))
    }

    /// Subtracts two exact values, returning `None` on unsigned underflow.
    #[must_use]
    pub fn checked_sub(self, other: Self) -> Option<Self> {
        let mut result = [0_u8; 32];
        let mut borrow = false;
        for index in (0..32).rev() {
            let (partial, borrow_a) = self.0[index].overflowing_sub(other.0[index]);
            let (difference, borrow_b) = partial.overflowing_sub(u8::from(borrow));
            result[index] = difference;
            borrow = borrow_a || borrow_b;
        }
        (!borrow).then_some(Self(result))
    }

    /// Divides by a nonzero `u64`, returning the exact quotient and remainder.
    #[must_use]
    pub fn checked_div_rem_u64(self, divisor: u64) -> Option<(Self, u64)> {
        if divisor == 0 {
            return None;
        }
        let divisor = u128::from(divisor);
        let mut remainder = 0_u128;
        let mut quotient = [0_u8; 32];
        for (index, chunk) in self.0.chunks_exact(8).enumerate() {
            let limb = u64::from_be_bytes(chunk.try_into().ok()?);
            let dividend = (remainder << 64) | u128::from(limb);
            let quotient_limb = u64::try_from(dividend / divisor).ok()?;
            remainder = dividend % divisor;
            quotient[index * 8..(index + 1) * 8].copy_from_slice(&quotient_limb.to_be_bytes());
        }
        Some((Self(quotient), u64::try_from(remainder).ok()?))
    }

    /// Return a `u64` only when no high bit would be discarded.
    #[must_use]
    pub fn checked_to_u64(self) -> Option<u64> {
        if self.0[..24].iter().any(|byte| *byte != 0) {
            return None;
        }
        self.0[24..].try_into().ok().map(u64::from_be_bytes)
    }
}

/// Derive the unique full 256-bit target for one bounded DAA difficulty.
fn target_for_difficulty(difficulty: u64) -> Result<Uint256, RandomXV2WorkError> {
    if difficulty == 0 || difficulty > MAX_RANDOMX_V2_DIFFICULTY {
        return Err(RandomXV2WorkError::DifficultyOutOfBounds);
    }
    let divisor = u128::from(difficulty);
    let mut remainder = 0_u128;
    let mut target = [0_u8; 32];
    for (index, limb) in [u64::MAX; 4].into_iter().enumerate() {
        let dividend = (remainder << 64) | u128::from(limb);
        let quotient = u64::try_from(dividend / divisor)
            .map_err(|_| RandomXV2WorkError::ArithmeticOverflow)?;
        remainder = dividend % divisor;
        target[index * 8..(index + 1) * 8].copy_from_slice(&quotient.to_be_bytes());
    }
    Ok(Uint256(target))
}

/// Derive the unique full 256-bit target for one bounded DAA difficulty.
///
/// # Errors
///
/// Rejects zero or difficulty above [`MAX_RANDOMX_V2_DIFFICULTY`].
pub fn randomx_v2_target_for_difficulty(difficulty: u64) -> Result<Uint256, RandomXV2WorkError> {
    target_for_difficulty(difficulty)
}

/// Complete receiver-derived, non-nonce commitments for one `RandomX` proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RandomXWorkSubjectV2 {
    chain_domain: Hash32,
    profile_domain: Hash32,
    vertex_id: Hash32,
    body_id: Hash32,
    body_digest: Hash32,
    parent_set_digest: Hash32,
    daa_policy_id: Hash32,
    difficulty: Uint256,
    target: Uint256,
    target_policy_id: Hash32,
    work_key_id: Hash32,
    seed_commitment: Hash32,
    logical_time: u64,
    epoch: u64,
    key_epoch: u64,
    seed_epoch: u64,
}

impl RandomXWorkSubjectV2 {
    /// Bind a verified body subject to receiver-derived vertex, DAA, time, and key state.
    ///
    /// # Errors
    ///
    /// Rejects zero time/epoch, a future seed, or difficulty outside the suite bound.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        body: &WorkSubject,
        vertex_id: Hash32,
        daa_policy_id: Hash32,
        difficulty: u64,
        logical_time: u64,
        epoch: u64,
        work_key_id: Hash32,
        key_epoch: u64,
        seed_epoch: u64,
        seed_commitment: Hash32,
    ) -> Result<Self, RandomXV2WorkError> {
        if logical_time == 0 || epoch == 0 || seed_epoch >= epoch {
            return Err(RandomXV2WorkError::InvalidContext);
        }
        let target = target_for_difficulty(difficulty)?;
        Ok(Self {
            chain_domain: body.chain_domain(),
            profile_domain: body.profile_domain(),
            vertex_id,
            body_id: body.body_id(),
            body_digest: body.body_digest(),
            parent_set_digest: body.parent_set_digest(),
            daa_policy_id,
            difficulty: Uint256::from_u64(difficulty),
            target,
            target_policy_id: RANDOMX_V2_TARGET_POLICY_ID,
            work_key_id,
            seed_commitment,
            logical_time,
            epoch,
            key_epoch,
            seed_epoch,
        })
    }

    /// Return the bound chain domain.
    #[must_use]
    pub const fn chain_domain(&self) -> Hash32 {
        self.chain_domain
    }
    /// Return the bound execution-profile domain.
    #[must_use]
    pub const fn profile_domain(&self) -> Hash32 {
        self.profile_domain
    }
    /// Return the receiver-derived vertex identity.
    #[must_use]
    pub const fn vertex_id(&self) -> Hash32 {
        self.vertex_id
    }
    /// Return the exact body identity.
    #[must_use]
    pub const fn body_id(&self) -> Hash32 {
        self.body_id
    }
    /// Return the exact canonical body digest.
    #[must_use]
    pub const fn body_digest(&self) -> Hash32 {
        self.body_digest
    }
    /// Return the canonical parent-VertexId commitment.
    #[must_use]
    pub const fn parent_set_digest(&self) -> Hash32 {
        self.parent_set_digest
    }
    /// Return the receiver-selected DAA policy identifier.
    #[must_use]
    pub const fn daa_policy_id(&self) -> Hash32 {
        self.daa_policy_id
    }
    /// Return the exact 256-bit difficulty.
    #[must_use]
    pub const fn difficulty(&self) -> Uint256 {
        self.difficulty
    }
    /// Return the exact checked 256-bit target.
    #[must_use]
    pub const fn target(&self) -> Uint256 {
        self.target
    }
    /// Return the exact target-policy identifier.
    #[must_use]
    pub const fn target_policy_id(&self) -> Hash32 {
        self.target_policy_id
    }
    /// Return the receiver-derived work-key identifier.
    #[must_use]
    pub const fn work_key_id(&self) -> Hash32 {
        self.work_key_id
    }
    /// Return the delayed history seed commitment.
    #[must_use]
    pub const fn seed_commitment(&self) -> Hash32 {
        self.seed_commitment
    }
    /// Return the canonical logical timestamp.
    #[must_use]
    pub const fn logical_time(&self) -> u64 {
        self.logical_time
    }
    /// Return the canonical DAG epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
    /// Return the deterministic key epoch.
    #[must_use]
    pub const fn key_epoch(&self) -> u64 {
        self.key_epoch
    }
    /// Return the sufficiently old seed epoch, with zero denoting formal genesis.
    #[must_use]
    pub const fn seed_epoch(&self) -> u64 {
        self.seed_epoch
    }
}

/// Safe `RandomX` v2 evaluator fixed to one receiver-derived public key.
#[derive(Debug)]
pub struct RandomXV2Algorithm {
    work_key_id: Hash32,
    vm: RandomXV2Vm,
}

impl RandomXV2Algorithm {
    /// Initialize a genuine v2 evaluator for exact 32-byte key material.
    ///
    /// # Errors
    ///
    /// Returns an allocation/backend error from the narrow `RandomX` wrapper.
    pub fn new(key_material: Hash32) -> Result<Self, RandomXV2WorkError> {
        let work_key_id = randomx_v2_work_key_id(key_material);
        let vm = RandomXV2Vm::new(&key_material).map_err(RandomXV2WorkError::Backend)?;
        Ok(Self { work_key_id, vm })
    }

    /// Return the identifier uniquely derived from this evaluator's key bytes.
    #[must_use]
    pub const fn work_key_id(&self) -> Hash32 {
        self.work_key_id
    }

    pub(crate) fn hash(&mut self, transcript: &[u8]) -> Result<Hash32, RandomXV2WorkError> {
        self.vm
            .calculate_hash(transcript)
            .map_err(RandomXV2WorkError::Backend)
    }
}

/// Derive the sole work-key identifier for exact public `RandomX` key material.
#[must_use]
pub fn randomx_v2_work_key_id(key_material: Hash32) -> Hash32 {
    framed_sha256(WORK_KEY_DOMAIN, &[&key_material])
}

/// Canonical `RandomX` v2 proof carrying all consensus commitments and its result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RandomXV2ProofEnvelope {
    suite_id: Hash32,
    suite_version: u16,
    chain_domain: Hash32,
    profile_domain: Hash32,
    vertex_id: Hash32,
    body_id: Hash32,
    body_digest: Hash32,
    parent_set_digest: Hash32,
    daa_policy_id: Hash32,
    difficulty: Uint256,
    target: Uint256,
    target_policy_id: Hash32,
    work_key_id: Hash32,
    seed_commitment: Hash32,
    logical_time: u64,
    epoch: u64,
    key_epoch: u64,
    seed_epoch: u64,
    nonce: u64,
    proof_hash: Hash32,
}

impl RandomXV2ProofEnvelope {
    /// Strictly decode one exact proof without granting work authority.
    ///
    /// # Errors
    ///
    /// Rejects wrong length, framing, flags, proof version, or suite version.
    pub fn decode_unverified(bytes: &[u8]) -> Result<UnverifiedRandomXV2Proof, RandomXV2WorkError> {
        if bytes.len() != RANDOMX_V2_PROOF_BYTES {
            return Err(RandomXV2WorkError::InvalidProofLength);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.array::<8>()? != PROOF_MAGIC {
            return Err(RandomXV2WorkError::InvalidProofMagic);
        }
        if decoder.u16()? != RANDOMX_V2_PROOF_VERSION {
            return Err(RandomXV2WorkError::UnsupportedProofVersion);
        }
        let suite_version = decoder.u16()?;
        if suite_version != RANDOMX_V2_SUITE_VERSION {
            return Err(RandomXV2WorkError::UnsupportedSuiteVersion);
        }
        if decoder.u32()? != 0 {
            return Err(RandomXV2WorkError::InvalidProofFlags);
        }
        let proof = Self {
            suite_id: decoder.hash32()?,
            suite_version,
            chain_domain: decoder.hash32()?,
            profile_domain: decoder.hash32()?,
            vertex_id: decoder.hash32()?,
            body_id: decoder.hash32()?,
            body_digest: decoder.hash32()?,
            parent_set_digest: decoder.hash32()?,
            daa_policy_id: decoder.hash32()?,
            difficulty: Uint256(decoder.hash32()?),
            target: Uint256(decoder.hash32()?),
            target_policy_id: decoder.hash32()?,
            work_key_id: decoder.hash32()?,
            seed_commitment: decoder.hash32()?,
            logical_time: decoder.u64()?,
            epoch: decoder.u64()?,
            key_epoch: decoder.u64()?,
            seed_epoch: decoder.u64()?,
            nonce: decoder.u64()?,
            proof_hash: decoder.hash32()?,
        };
        decoder.finish()?;
        Ok(UnverifiedRandomXV2Proof(proof))
    }

    /// Return exact canonical proof bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = self.wire_without_hash();
        bytes.extend_from_slice(&self.proof_hash);
        debug_assert_eq!(bytes.len(), RANDOMX_V2_PROOF_BYTES);
        bytes
    }

    fn transcript_bytes(&self) -> Vec<u8> {
        let wire = self.wire_without_hash();
        let mut bytes = Vec::with_capacity(TRANSCRIPT_DOMAIN.len() + wire.len());
        bytes.extend_from_slice(TRANSCRIPT_DOMAIN);
        bytes.extend_from_slice(&wire);
        bytes
    }

    fn wire_without_hash(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(RANDOMX_V2_PROOF_BYTES - 32);
        bytes.extend_from_slice(&PROOF_MAGIC);
        bytes.extend_from_slice(&RANDOMX_V2_PROOF_VERSION.to_le_bytes());
        bytes.extend_from_slice(&self.suite_version.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&self.suite_id);
        bytes.extend_from_slice(&self.chain_domain);
        bytes.extend_from_slice(&self.profile_domain);
        bytes.extend_from_slice(&self.vertex_id);
        bytes.extend_from_slice(&self.body_id);
        bytes.extend_from_slice(&self.body_digest);
        bytes.extend_from_slice(&self.parent_set_digest);
        bytes.extend_from_slice(&self.daa_policy_id);
        bytes.extend_from_slice(&self.difficulty.0);
        bytes.extend_from_slice(&self.target.0);
        bytes.extend_from_slice(&self.target_policy_id);
        bytes.extend_from_slice(&self.work_key_id);
        bytes.extend_from_slice(&self.seed_commitment);
        bytes.extend_from_slice(&self.logical_time.to_le_bytes());
        bytes.extend_from_slice(&self.epoch.to_le_bytes());
        bytes.extend_from_slice(&self.key_epoch.to_le_bytes());
        bytes.extend_from_slice(&self.seed_epoch.to_le_bytes());
        bytes.extend_from_slice(&self.nonce.to_le_bytes());
        bytes
    }

    /// Return the suite identifier.
    #[must_use]
    pub const fn suite_id(&self) -> Hash32 {
        self.suite_id
    }
    /// Return the suite version.
    #[must_use]
    pub const fn suite_version(&self) -> u16 {
        self.suite_version
    }
    /// Return the bound chain domain.
    #[must_use]
    pub const fn chain_domain(&self) -> Hash32 {
        self.chain_domain
    }
    /// Return the bound profile domain.
    #[must_use]
    pub const fn profile_domain(&self) -> Hash32 {
        self.profile_domain
    }
    /// Return the bound receiver-derived vertex identity.
    #[must_use]
    pub const fn vertex_id(&self) -> Hash32 {
        self.vertex_id
    }
    /// Return the bound body identity.
    #[must_use]
    pub const fn body_id(&self) -> Hash32 {
        self.body_id
    }
    /// Return the canonical body digest.
    #[must_use]
    pub const fn body_digest(&self) -> Hash32 {
        self.body_digest
    }
    /// Return the canonical parent commitment.
    #[must_use]
    pub const fn parent_set_digest(&self) -> Hash32 {
        self.parent_set_digest
    }
    /// Return the DAA policy identifier.
    #[must_use]
    pub const fn daa_policy_id(&self) -> Hash32 {
        self.daa_policy_id
    }
    /// Return the checked 256-bit difficulty.
    #[must_use]
    pub const fn difficulty(&self) -> Uint256 {
        self.difficulty
    }
    /// Return the checked 256-bit target.
    #[must_use]
    pub const fn target(&self) -> Uint256 {
        self.target
    }
    /// Return the target policy identifier.
    #[must_use]
    pub const fn target_policy_id(&self) -> Hash32 {
        self.target_policy_id
    }
    /// Return the key identifier.
    #[must_use]
    pub const fn work_key_id(&self) -> Hash32 {
        self.work_key_id
    }
    /// Return the delayed seed commitment.
    #[must_use]
    pub const fn seed_commitment(&self) -> Hash32 {
        self.seed_commitment
    }
    /// Return the logical time.
    #[must_use]
    pub const fn logical_time(&self) -> u64 {
        self.logical_time
    }
    /// Return the DAG epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
    /// Return the key epoch.
    #[must_use]
    pub const fn key_epoch(&self) -> u64 {
        self.key_epoch
    }
    /// Return the delayed seed epoch.
    #[must_use]
    pub const fn seed_epoch(&self) -> u64 {
        self.seed_epoch
    }
    /// Return the nonce.
    #[must_use]
    pub const fn nonce(&self) -> u64 {
        self.nonce
    }
    /// Return the claimed `RandomX` result.
    #[must_use]
    pub const fn proof_hash(&self) -> Hash32 {
        self.proof_hash
    }
}

/// A decoded `RandomX` proof with no work authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnverifiedRandomXV2Proof(RandomXV2ProofEnvelope);

impl UnverifiedRandomXV2Proof {
    /// Borrow untrusted claims for diagnostics only.
    #[must_use]
    pub const fn decoded(&self) -> &RandomXV2ProofEnvelope {
        &self.0
    }
}

/// A `RandomX` proof promoted after complete receiver-side reconstruction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRandomXV2Work {
    proof: RandomXV2ProofEnvelope,
    canonical_bytes: Vec<u8>,
    derived_work: DerivedWork,
}

impl VerifiedRandomXV2Work {
    /// Borrow the fully verified proof.
    #[must_use]
    pub const fn proof(&self) -> &RandomXV2ProofEnvelope {
        &self.proof
    }
    /// Return the exact canonical proof bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
    /// Return receiver-derived bounded work.
    #[must_use]
    pub const fn derived_work(&self) -> DerivedWork {
        self.derived_work
    }
    /// Return the independently recomputed `RandomX` hash.
    #[must_use]
    pub const fn work_hash(&self) -> Hash32 {
        self.proof.proof_hash
    }
    /// Return the bound body identity.
    #[must_use]
    pub const fn body_id(&self) -> Hash32 {
        self.proof.body_id
    }
}

/// Independently verify one canonical `RandomX` proof against receiver-derived state.
///
/// # Errors
///
/// Rejects framing, suite, context, body, parent, DAA, target, key, nonce-result,
/// backend, or full 256-bit work mismatch.
pub fn verify_randomx_v2(
    algorithm: &mut RandomXV2Algorithm,
    subject: &RandomXWorkSubjectV2,
    canonical_proof: &[u8],
) -> Result<VerifiedRandomXV2Work, RandomXV2WorkError> {
    let proof = RandomXV2ProofEnvelope::decode_unverified(canonical_proof)?.0;
    validate_claims(algorithm, subject, &proof)?;
    let actual = algorithm.hash(&proof.transcript_bytes())?;
    if actual != proof.proof_hash {
        return Err(RandomXV2WorkError::ProofHashMismatch);
    }
    if Uint256::from_be_bytes(actual) > subject.target {
        return Err(RandomXV2WorkError::InsufficientWork);
    }
    let work = subject
        .difficulty
        .checked_to_u64()
        .filter(|value| *value != 0 && *value <= MAX_RANDOMX_V2_DIFFICULTY)
        .ok_or(RandomXV2WorkError::WorkOverflow)?;
    Ok(VerifiedRandomXV2Work {
        canonical_bytes: proof.canonical_bytes(),
        proof,
        derived_work: DerivedWork(work),
    })
}

/// Search exactly one bounded nonce range with genuine `RandomX` v2.
///
/// # Errors
///
/// Rejects zero/excessive/overflowing ranges, backend failure, or exhaustion.
pub fn mine_randomx_v2(
    algorithm: &mut RandomXV2Algorithm,
    subject: &RandomXWorkSubjectV2,
    start_nonce: u64,
    nonce_count: u64,
) -> Result<VerifiedRandomXV2Work, RandomXV2WorkError> {
    validate_nonce_range(start_nonce, nonce_count)?;
    if algorithm.work_key_id != subject.work_key_id {
        return Err(RandomXV2WorkError::WorkKeyMismatch);
    }
    for offset in 0..nonce_count {
        let nonce = start_nonce
            .checked_add(offset)
            .ok_or(RandomXV2WorkError::NonceRangeOverflow)?;
        let mut proof = proof_from_subject(subject, nonce, [0; 32]);
        proof.proof_hash = algorithm.hash(&proof.transcript_bytes())?;
        if Uint256::from_be_bytes(proof.proof_hash) <= subject.target {
            return verify_randomx_v2(algorithm, subject, &proof.canonical_bytes());
        }
    }
    Err(RandomXV2WorkError::MiningExhausted)
}

const fn proof_from_subject(
    subject: &RandomXWorkSubjectV2,
    nonce: u64,
    proof_hash: Hash32,
) -> RandomXV2ProofEnvelope {
    RandomXV2ProofEnvelope {
        suite_id: RANDOMX_V2_SUITE_ID,
        suite_version: RANDOMX_V2_SUITE_VERSION,
        chain_domain: subject.chain_domain,
        profile_domain: subject.profile_domain,
        vertex_id: subject.vertex_id,
        body_id: subject.body_id,
        body_digest: subject.body_digest,
        parent_set_digest: subject.parent_set_digest,
        daa_policy_id: subject.daa_policy_id,
        difficulty: subject.difficulty,
        target: subject.target,
        target_policy_id: subject.target_policy_id,
        work_key_id: subject.work_key_id,
        seed_commitment: subject.seed_commitment,
        logical_time: subject.logical_time,
        epoch: subject.epoch,
        key_epoch: subject.key_epoch,
        seed_epoch: subject.seed_epoch,
        nonce,
        proof_hash,
    }
}

fn validate_claims(
    algorithm: &RandomXV2Algorithm,
    subject: &RandomXWorkSubjectV2,
    proof: &RandomXV2ProofEnvelope,
) -> Result<(), RandomXV2WorkError> {
    if proof.suite_id != RANDOMX_V2_SUITE_ID {
        return Err(RandomXV2WorkError::SuiteMismatch);
    }
    if proof.chain_domain != subject.chain_domain {
        return Err(RandomXV2WorkError::ChainDomainMismatch);
    }
    if proof.profile_domain != subject.profile_domain {
        return Err(RandomXV2WorkError::ProfileDomainMismatch);
    }
    if proof.vertex_id != subject.vertex_id {
        return Err(RandomXV2WorkError::VertexIdMismatch);
    }
    if proof.body_id != subject.body_id || proof.body_digest != subject.body_digest {
        return Err(RandomXV2WorkError::BodyMismatch);
    }
    if proof.parent_set_digest != subject.parent_set_digest {
        return Err(RandomXV2WorkError::ParentSetMismatch);
    }
    if proof.daa_policy_id != subject.daa_policy_id
        || proof.logical_time != subject.logical_time
        || proof.epoch != subject.epoch
    {
        return Err(RandomXV2WorkError::DifficultyContextMismatch);
    }
    if proof.difficulty != subject.difficulty {
        return Err(RandomXV2WorkError::DifficultyMismatch);
    }
    if proof.target != subject.target
        || target_for_difficulty(
            subject
                .difficulty
                .checked_to_u64()
                .ok_or(RandomXV2WorkError::WorkOverflow)?,
        )? != subject.target
    {
        return Err(RandomXV2WorkError::TargetMismatch);
    }
    if proof.target_policy_id != RANDOMX_V2_TARGET_POLICY_ID {
        return Err(RandomXV2WorkError::TargetPolicyMismatch);
    }
    if proof.work_key_id != subject.work_key_id || algorithm.work_key_id != subject.work_key_id {
        return Err(RandomXV2WorkError::WorkKeyMismatch);
    }
    if proof.key_epoch != subject.key_epoch
        || proof.seed_epoch != subject.seed_epoch
        || proof.seed_commitment != subject.seed_commitment
    {
        return Err(RandomXV2WorkError::KeyScheduleMismatch);
    }
    Ok(())
}

fn validate_nonce_range(start: u64, count: u64) -> Result<(), RandomXV2WorkError> {
    if count == 0 || count > MAX_LOCAL_MINING_ATTEMPTS {
        return Err(RandomXV2WorkError::NonceCountOutOfBounds);
    }
    start
        .checked_add(count - 1)
        .ok_or(RandomXV2WorkError::NonceRangeOverflow)?;
    Ok(())
}

fn framed_sha256(domain: &[u8], fields: &[&[u8]]) -> Hash32 {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(
        u64::try_from(domain.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(domain);
    hasher.update(
        u64::try_from(fields.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for field in fields {
        hasher.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

/// Structural, commitment, target, key-schedule, backend, and mining failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RandomXV2WorkError {
    /// Proof bytes differ from the exact v2 length.
    #[error("randomx_work.invalid_proof_length")]
    InvalidProofLength,
    /// Proof framing magic differs.
    #[error("randomx_work.invalid_proof_magic")]
    InvalidProofMagic,
    /// Proof wire version is unsupported.
    #[error("randomx_work.unsupported_proof_version")]
    UnsupportedProofVersion,
    /// `RandomX` suite version is unsupported.
    #[error("randomx_work.unsupported_suite_version")]
    UnsupportedSuiteVersion,
    /// Reserved proof flags are nonzero.
    #[error("randomx_work.invalid_proof_flags")]
    InvalidProofFlags,
    /// Proof suite identifier differs.
    #[error("randomx_work.suite_mismatch")]
    SuiteMismatch,
    /// Chain domain differs.
    #[error("randomx_work.chain_domain_mismatch")]
    ChainDomainMismatch,
    /// Profile domain differs.
    #[error("randomx_work.profile_domain_mismatch")]
    ProfileDomainMismatch,
    /// Receiver-derived vertex identity differs.
    #[error("randomx_work.vertex_id_mismatch")]
    VertexIdMismatch,
    /// Body identity or exact-byte commitment differs.
    #[error("randomx_work.body_mismatch")]
    BodyMismatch,
    /// Canonical parent commitment differs.
    #[error("randomx_work.parent_set_mismatch")]
    ParentSetMismatch,
    /// DAA policy, timestamp, or epoch differs.
    #[error("randomx_work.difficulty_context_mismatch")]
    DifficultyContextMismatch,
    /// Checked 256-bit difficulty differs.
    #[error("randomx_work.difficulty_mismatch")]
    DifficultyMismatch,
    /// Difficulty is zero or above the bounded DAA cap.
    #[error("randomx_work.difficulty_out_of_bounds")]
    DifficultyOutOfBounds,
    /// Checked 256-bit target differs.
    #[error("randomx_work.target_mismatch")]
    TargetMismatch,
    /// Target policy identifier differs.
    #[error("randomx_work.target_policy_mismatch")]
    TargetPolicyMismatch,
    /// Work key differs from receiver-derived material.
    #[error("randomx_work.work_key_mismatch")]
    WorkKeyMismatch,
    /// Key epoch, seed epoch, or seed commitment differs.
    #[error("randomx_work.key_schedule_mismatch")]
    KeyScheduleMismatch,
    /// Context contains zero/future timing or another invalid relation.
    #[error("randomx_work.invalid_context")]
    InvalidContext,
    /// Claimed proof result differs from genuine `RandomX` recomputation.
    #[error("randomx_work.proof_hash_mismatch")]
    ProofHashMismatch,
    /// Full 256-bit `RandomX` result exceeds the target.
    #[error("randomx_work.insufficient_work")]
    InsufficientWork,
    /// Derived work cannot fit the existing bounded selection model.
    #[error("randomx_work.work_overflow")]
    WorkOverflow,
    /// Checked target arithmetic overflowed unexpectedly.
    #[error("randomx_work.arithmetic_overflow")]
    ArithmeticOverflow,
    /// Nonce count is zero or above the existing local cap.
    #[error("randomx_work.nonce_count_out_of_bounds")]
    NonceCountOutOfBounds,
    /// Nonce range overflows `u64`.
    #[error("randomx_work.nonce_range_overflow")]
    NonceRangeOverflow,
    /// No target-satisfying nonce was found in the assigned range.
    #[error("randomx_work.mining_exhausted")]
    MiningExhausted,
    /// The narrow `RandomX` wrapper rejected allocation or input.
    #[error(transparent)]
    Backend(#[from] RandomXError),
    /// Canonical bytes ended early or contained trailing material.
    #[error("randomx_work.codec")]
    Codec,
}

impl RandomXV2WorkError {
    /// Return a stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidProofLength => "randomx_work.invalid_proof_length",
            Self::InvalidProofMagic => "randomx_work.invalid_proof_magic",
            Self::UnsupportedProofVersion => "randomx_work.unsupported_proof_version",
            Self::UnsupportedSuiteVersion => "randomx_work.unsupported_suite_version",
            Self::InvalidProofFlags => "randomx_work.invalid_proof_flags",
            Self::SuiteMismatch => "randomx_work.suite_mismatch",
            Self::ChainDomainMismatch => "randomx_work.chain_domain_mismatch",
            Self::ProfileDomainMismatch => "randomx_work.profile_domain_mismatch",
            Self::VertexIdMismatch => "randomx_work.vertex_id_mismatch",
            Self::BodyMismatch => "randomx_work.body_mismatch",
            Self::ParentSetMismatch => "randomx_work.parent_set_mismatch",
            Self::DifficultyContextMismatch => "randomx_work.difficulty_context_mismatch",
            Self::DifficultyMismatch => "randomx_work.difficulty_mismatch",
            Self::DifficultyOutOfBounds => "randomx_work.difficulty_out_of_bounds",
            Self::TargetMismatch => "randomx_work.target_mismatch",
            Self::TargetPolicyMismatch => "randomx_work.target_policy_mismatch",
            Self::WorkKeyMismatch => "randomx_work.work_key_mismatch",
            Self::KeyScheduleMismatch => "randomx_work.key_schedule_mismatch",
            Self::InvalidContext => "randomx_work.invalid_context",
            Self::ProofHashMismatch => "randomx_work.proof_hash_mismatch",
            Self::InsufficientWork => "randomx_work.insufficient_work",
            Self::WorkOverflow => "randomx_work.work_overflow",
            Self::ArithmeticOverflow => "randomx_work.arithmetic_overflow",
            Self::NonceCountOutOfBounds => "randomx_work.nonce_count_out_of_bounds",
            Self::NonceRangeOverflow => "randomx_work.nonce_range_overflow",
            Self::MiningExhausted => "randomx_work.mining_exhausted",
            Self::Backend(error) => match error {
                RandomXError::EmptyKey => "randomx.empty_key",
                RandomXError::InputBounds => "randomx.input_bounds",
                RandomXError::CacheAllocation => "randomx.cache_allocation",
                RandomXError::VmAllocation => "randomx.vm_allocation",
            },
            Self::Codec => "randomx_work.codec",
        }
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], RandomXV2WorkError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(RandomXV2WorkError::Codec)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(RandomXV2WorkError::Codec)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], RandomXV2WorkError> {
        self.take(N)?
            .try_into()
            .map_err(|_| RandomXV2WorkError::Codec)
    }

    fn hash32(&mut self) -> Result<Hash32, RandomXV2WorkError> {
        self.array()
    }
    fn u16(&mut self) -> Result<u16, RandomXV2WorkError> {
        Ok(u16::from_le_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, RandomXV2WorkError> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, RandomXV2WorkError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    const fn finish(self) -> Result<(), RandomXV2WorkError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(RandomXV2WorkError::Codec)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_width_target_division_is_canonical() {
        assert_eq!(target_for_difficulty(1).unwrap(), Uint256([0xff; 32]));
        assert_eq!(
            target_for_difficulty(2).unwrap(),
            Uint256([
                0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff,
            ])
        );
        assert_eq!(
            target_for_difficulty(0),
            Err(RandomXV2WorkError::DifficultyOutOfBounds)
        );
    }

    #[test]
    fn uint256_checked_arithmetic_and_small_division_are_exact() {
        assert_eq!(
            Uint256::from_u64(2).checked_add(Uint256::from_u64(3)),
            Some(Uint256::from_u64(5))
        );
        assert_eq!(
            Uint256::from_u64(5).checked_sub(Uint256::from_u64(3)),
            Some(Uint256::from_u64(2))
        );
        assert_eq!(Uint256::MAX.checked_add(Uint256::from_u64(1)), None);
        assert_eq!(Uint256::ZERO.checked_sub(Uint256::from_u64(1)), None);
        let (quotient, remainder) = Uint256::MAX.checked_div_rem_u64(3).unwrap();
        assert_eq!(quotient.to_be_bytes(), [0x55; 32]);
        assert_eq!(remainder, 0);
        assert_eq!(Uint256::MAX.checked_div_rem_u64(0), None);
    }
}
