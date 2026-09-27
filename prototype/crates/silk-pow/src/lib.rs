#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![allow(clippy::module_name_repetitions)]

//! Private, synthetic proof-of-work admission primitives.
//!
//! This crate deliberately does **not** select `SilkNode`'s production proof of
//! work, difficulty policy, fork choice, consensus, finality, rewards, or
//! issuance. It freezes one small proof envelope and a replaceable verifier
//! boundary so the local no-value prototype can exercise mining, persistence,
//! and peer revalidation without granting work claims to callers.

pub mod dag_randomx_v3;
mod mining_job;
mod randomx_job_v2;
mod randomx_v2;

pub use mining_job::{
    MAX_MINING_JOB_BYTES, MAX_MINING_JOB_EPOCH_SPAN, MAX_MINING_RESULT_BYTES,
    MINING_JOB_FIXED_BYTES, MINING_JOB_VERSION, MINING_RESULT_FIXED_BYTES, MINING_RESULT_VERSION,
    MiningJobContextV1, MiningJobError, MiningJobV1, MiningNonceRangeV1, MiningResultKindV1,
    MiningWorkerResultV1, SYNTHETIC_TARGET_POLICY_ID, UnverifiedMiningJobV1,
    UnverifiedMiningWorkerResultV1, VerifiedMiningJobV1, execute_mining_job,
};
pub use randomx_job_v2::{
    AcceptedRandomXMiningResultV2, BoundedRandomXMiningCoordinatorV2, MAX_RANDOMX_MINING_JOB_BYTES,
    MAX_RANDOMX_MINING_JOBS, MAX_RANDOMX_MINING_RESULT_BYTES, RANDOMX_MINING_JOB_VERSION,
    RANDOMX_MINING_RESULT_VERSION, RandomXMiningJobError, RandomXMiningJobV2,
    RandomXMiningResultKindV2, RandomXMiningResultV2, UnverifiedRandomXMiningJobV2,
    UnverifiedRandomXMiningResultV2, VerifiedRandomXMiningJobV2, execute_randomx_mining_job_v2,
    verify_randomx_mining_result_v2,
};
pub use randomx_v2::{
    MAX_RANDOMX_V2_DIFFICULTY, RANDOMX_V2_PROOF_BYTES, RANDOMX_V2_PROOF_VERSION,
    RANDOMX_V2_SUITE_ID, RANDOMX_V2_SUITE_VERSION, RANDOMX_V2_TARGET_POLICY_ID, RandomXV2Algorithm,
    RandomXV2ProofEnvelope, RandomXV2WorkError, RandomXWorkSubjectV2, Uint256,
    UnverifiedRandomXV2Proof, VerifiedRandomXV2Work, mine_randomx_v2,
    randomx_v2_target_for_difficulty, randomx_v2_work_key_id, verify_randomx_v2,
};

use sha2::{Digest, Sha256};
use silk_gate2::{
    CanonicalDecode, CanonicalEncode, Hash32, MAX_BODY_BYTES, MAX_PARENTS, OrderedBodyV2,
};
use thiserror::Error;

const PROOF_MAGIC: [u8; 8] = *b"SLKPOW\0\0";
const PARENT_SET_DOMAIN: &[u8] = b"SilkNode/SyntheticWork/ParentSet/v1";
const OPAQUE_PARENT_SET_DOMAIN: &[u8] = b"SilkNode/SyntheticWork/OpaqueParentSet/v1";
const SHA256_WORK_DOMAIN: &[u8] = b"SilkNode/SyntheticWork/Sha256/v1";
const FRAMED_HASH_PREFIX: &[u8] = b"SilkNode-PoW-Framed-Hash-v1\0";
const FIELD_COUNT: usize = 6;
const HASH_FIELDS_BYTES: usize = FIELD_COUNT * 32;

/// Frozen synthetic work-proof wire version.
pub const WORK_PROOF_VERSION: u16 = 1;
/// Exact canonical byte length of a version-one work proof.
pub const WORK_PROOF_BYTES: usize = PROOF_MAGIC.len() + 2 + HASH_FIELDS_BYTES + (3 * 8);
/// Highest difficulty accepted by the bounded synthetic target policy.
pub const MAX_SYNTHETIC_DIFFICULTY: u64 = 1_000_000;
/// Highest number of nonce attempts accepted by one local mining call.
pub const MAX_LOCAL_MINING_ATTEMPTS: u64 = 1_000_000;

/// Semantic identifier for the deterministic synthetic SHA-256 backend.
///
/// This identifier describes only the private test backend and is not a
/// production algorithm selection.
pub const SYNTHETIC_SHA256_ALGORITHM_ID: Hash32 = [
    0xef, 0xf5, 0xbc, 0xe2, 0x6d, 0x67, 0xf8, 0xdf, 0x15, 0xed, 0x65, 0x7b, 0xd2, 0xa2, 0x7b, 0x31,
    0xce, 0xbe, 0x68, 0x2b, 0xbe, 0xb2, 0x6e, 0xac, 0xf0, 0x1a, 0x52, 0x70, 0x6e, 0xf7, 0xf8, 0x9d,
];

/// Exact context that a synthetic work proof must bind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkContext {
    chain_domain: Hash32,
    profile_domain: Hash32,
}

/// Version-explicit alias for the frozen synthetic work context.
pub type WorkContextV1 = WorkContext;

impl WorkContext {
    /// Creates an exact chain/profile work context.
    #[must_use]
    pub const fn new(chain_domain: Hash32, profile_domain: Hash32) -> Self {
        Self {
            chain_domain,
            profile_domain,
        }
    }

    /// Returns the bound chain domain.
    #[must_use]
    pub const fn chain_domain(&self) -> Hash32 {
        self.chain_domain
    }

    /// Returns the bound profile domain.
    #[must_use]
    pub const fn profile_domain(&self) -> Hash32 {
        self.profile_domain
    }
}

/// Canonical, version-one work-header/proof envelope.
///
/// Decoding this type proves only structural validity. Call [`verify_work`]
/// before using its claimed nonce or difficulty.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkProofEnvelopeV1 {
    algorithm_id: Hash32,
    chain_domain: Hash32,
    profile_domain: Hash32,
    body_id: Hash32,
    body_digest: Hash32,
    parent_set_digest: Hash32,
    difficulty: u64,
    target: u64,
    nonce: u64,
}

impl WorkProofEnvelopeV1 {
    /// Strictly decodes one exact version-one proof without granting authority.
    ///
    /// # Errors
    ///
    /// Returns an error for the wrong size, magic, or version.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<UnverifiedWorkProof, WorkError> {
        Self::decode_unverified(bytes)
    }

    /// Strictly decodes one exact version-one proof without granting authority.
    ///
    /// # Errors
    ///
    /// Returns an error for the wrong size, magic, or version.
    pub fn decode_unverified(bytes: &[u8]) -> Result<UnverifiedWorkProof, WorkError> {
        if bytes.len() != WORK_PROOF_BYTES {
            return Err(WorkError::InvalidProofLength);
        }

        let mut decoder = FixedDecoder::new(bytes);
        if decoder.array::<8>()? != PROOF_MAGIC {
            return Err(WorkError::InvalidProofMagic);
        }
        if decoder.u16()? != WORK_PROOF_VERSION {
            return Err(WorkError::UnsupportedProofVersion);
        }

        let envelope = Self {
            algorithm_id: decoder.array()?,
            chain_domain: decoder.array()?,
            profile_domain: decoder.array()?,
            body_id: decoder.array()?,
            body_digest: decoder.array()?,
            parent_set_digest: decoder.array()?,
            difficulty: decoder.u64()?,
            target: decoder.u64()?,
            nonce: decoder.u64()?,
        };
        decoder.finish()?;
        Ok(UnverifiedWorkProof(envelope))
    }

    /// Returns the exact canonical bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(WORK_PROOF_BYTES);
        bytes.extend_from_slice(&PROOF_MAGIC);
        bytes.extend_from_slice(&WORK_PROOF_VERSION.to_le_bytes());
        bytes.extend_from_slice(&self.algorithm_id);
        bytes.extend_from_slice(&self.chain_domain);
        bytes.extend_from_slice(&self.profile_domain);
        bytes.extend_from_slice(&self.body_id);
        bytes.extend_from_slice(&self.body_digest);
        bytes.extend_from_slice(&self.parent_set_digest);
        bytes.extend_from_slice(&self.difficulty.to_le_bytes());
        bytes.extend_from_slice(&self.target.to_le_bytes());
        bytes.extend_from_slice(&self.nonce.to_le_bytes());
        debug_assert_eq!(bytes.len(), WORK_PROOF_BYTES);
        bytes
    }

    /// Returns the algorithm identifier claimed by the envelope.
    #[must_use]
    pub const fn algorithm_id(&self) -> Hash32 {
        self.algorithm_id
    }

    /// Returns the bound chain domain.
    #[must_use]
    pub const fn chain_domain(&self) -> Hash32 {
        self.chain_domain
    }

    /// Returns the bound profile domain.
    #[must_use]
    pub const fn profile_domain(&self) -> Hash32 {
        self.profile_domain
    }

    /// Returns the bound body identifier.
    #[must_use]
    pub const fn body_id(&self) -> Hash32 {
        self.body_id
    }

    /// Returns the SHA-256 digest of the exact canonical body bytes.
    #[must_use]
    pub const fn body_digest(&self) -> Hash32 {
        self.body_digest
    }

    /// Returns the domain-separated digest of the canonical ordered parents.
    #[must_use]
    pub const fn parent_set_digest(&self) -> Hash32 {
        self.parent_set_digest
    }

    /// Returns the claimed synthetic difficulty.
    #[must_use]
    pub const fn difficulty(&self) -> u64 {
        self.difficulty
    }

    /// Returns the claimed target, which verification recomputes.
    #[must_use]
    pub const fn target(&self) -> u64 {
        self.target
    }

    /// Returns the claimed nonce.
    #[must_use]
    pub const fn nonce(&self) -> u64 {
        self.nonce
    }
}

/// Version-explicit alias used by persistence and transport adapters.
pub type SyntheticWorkProofV1 = WorkProofEnvelopeV1;

/// A structurally decoded proof that has not passed contextual verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnverifiedWorkProof(WorkProofEnvelopeV1);

impl UnverifiedWorkProof {
    /// Borrows the decoded fields for diagnostics and validation.
    #[must_use]
    pub const fn decoded(&self) -> &WorkProofEnvelopeV1 {
        &self.0
    }
}

/// A replaceable, bounded work-evaluation backend.
///
/// Node configuration chooses the trusted backend for an algorithm identifier.
/// Implementations receive only a fixed-size canonical proof transcript and
/// return its digest; target comparison and derived work remain in this crate.
pub trait WorkAlgorithm {
    /// Returns the exact semantic algorithm-suite identifier.
    ///
    /// The identifier commits to both hashing and target/work policy so either
    /// can be replaced without changing node, DAG, persistence, or transport
    /// interfaces.
    fn algorithm_id(&self) -> Hash32;

    /// Derives the sole target accepted for one difficulty parameter.
    ///
    /// # Errors
    ///
    /// Rejects difficulty outside this algorithm suite's bounded policy.
    fn target_for_difficulty(&self, difficulty: u64) -> Result<u64, WorkError>;

    /// Derives work after the exact target and digest have been verified.
    ///
    /// # Errors
    ///
    /// Rejects a target/difficulty pair outside this algorithm suite's policy.
    fn derive_work(&self, difficulty: u64, target: u64) -> Result<u64, WorkError>;

    /// Evaluates one fixed-size canonical work transcript.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot evaluate the transcript. The
    /// caller has already enforced [`WORK_PROOF_BYTES`].
    fn digest(&self, canonical_proof: &[u8]) -> Result<Hash32, WorkError>;
}

/// Deterministic CPU SHA-256 reference backend for private synthetic tests.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SyntheticSha256;

impl WorkAlgorithm for SyntheticSha256 {
    fn algorithm_id(&self) -> Hash32 {
        SYNTHETIC_SHA256_ALGORITHM_ID
    }

    fn target_for_difficulty(&self, difficulty: u64) -> Result<u64, WorkError> {
        canonical_target(difficulty)
    }

    fn derive_work(&self, difficulty: u64, target: u64) -> Result<u64, WorkError> {
        if canonical_target(difficulty)? != target {
            return Err(WorkError::NonCanonicalTarget);
        }
        Ok(difficulty)
    }

    fn digest(&self, canonical_proof: &[u8]) -> Result<Hash32, WorkError> {
        if canonical_proof.len() != WORK_PROOF_BYTES {
            return Err(WorkError::InvalidProofLength);
        }
        framed_hash(SHA256_WORK_DOMAIN, &[canonical_proof])
    }
}

/// Opaque work derived only after complete proof verification.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DerivedWork(u64);

impl DerivedWork {
    /// Returns the verified synthetic work value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A proof promoted only after exact body, context, policy, and hash checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedWorkProof {
    envelope: WorkProofEnvelopeV1,
    canonical_bytes: Vec<u8>,
    digest: Hash32,
    score: u64,
    derived_work: DerivedWork,
}

impl VerifiedWorkProof {
    /// Borrows the verified proof envelope.
    #[must_use]
    pub const fn proof(&self) -> &WorkProofEnvelopeV1 {
        &self.envelope
    }

    /// Borrows the verified envelope.
    #[must_use]
    pub const fn envelope(&self) -> &WorkProofEnvelopeV1 {
        &self.envelope
    }

    /// Borrows the exact canonical proof bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Returns the backend work digest.
    #[must_use]
    pub const fn digest(&self) -> Hash32 {
        self.digest
    }

    /// Returns the backend work hash.
    #[must_use]
    pub const fn work_hash(&self) -> Hash32 {
        self.digest
    }

    /// Returns the compared 64-bit score derived from the digest.
    #[must_use]
    pub const fn score(&self) -> u64 {
        self.score
    }

    /// Returns work derived from the verified canonical difficulty.
    #[must_use]
    pub const fn derived_work(&self) -> DerivedWork {
        self.derived_work
    }

    /// Returns the exact verified body identifier.
    #[must_use]
    pub const fn body_id(&self) -> Hash32 {
        self.envelope.body_id
    }
}

/// Validates and freezes all non-nonce work bindings for one canonical body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkSubject {
    context: WorkContext,
    body_id: Hash32,
    body_digest: Hash32,
    parent_set_digest: Hash32,
}

impl WorkSubject {
    /// Builds a subject from exact canonical body bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the body is oversized, malformed, non-canonical, or
    /// belongs to another profile domain.
    pub fn from_canonical_body_bytes(
        context: WorkContext,
        canonical_body: &[u8],
    ) -> Result<Self, WorkError> {
        if canonical_body.len() > MAX_BODY_BYTES {
            return Err(WorkError::BodyTooLarge);
        }
        let body = OrderedBodyV2::from_canonical_bytes(canonical_body)
            .map_err(|_| WorkError::InvalidCanonicalBody)?;
        let reencoded = body
            .canonical_bytes()
            .map_err(|_| WorkError::InvalidCanonicalBody)?;
        if reencoded != canonical_body {
            return Err(WorkError::InvalidCanonicalBody);
        }
        Self::from_validated_body(context, &body, canonical_body)
    }

    /// Builds a subject from a body by first deriving its canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-canonical parent set, an oversized body, or
    /// a profile mismatch.
    pub fn from_body(context: WorkContext, body: &OrderedBodyV2) -> Result<Self, WorkError> {
        let canonical = body
            .canonical_bytes()
            .map_err(|_| WorkError::InvalidCanonicalBody)?;
        if canonical.len() > MAX_BODY_BYTES {
            return Err(WorkError::BodyTooLarge);
        }
        Self::from_validated_body(context, body, &canonical)
    }

    /// Builds a work subject for an independently validated opaque body.
    ///
    /// This successor-only seam binds the complete canonical body bytes and a
    /// strictly sorted set of parent identifiers without interpreting the
    /// body's private execution payload. Callers remain responsible for
    /// validating the body codec and its derived identifier first.
    ///
    /// # Errors
    ///
    /// Returns an error for an oversized body, too many parents, or a parent
    /// list that is duplicated or not in strict canonical order.
    pub fn from_opaque_body_v1(
        context: WorkContext,
        body_id: Hash32,
        canonical_body: &[u8],
        parents: &[Hash32],
    ) -> Result<Self, WorkError> {
        if canonical_body.len() > MAX_BODY_BYTES {
            return Err(WorkError::BodyTooLarge);
        }
        if parents.len() > MAX_PARENTS {
            return Err(WorkError::TooManyParents);
        }
        if parents.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(WorkError::InvalidParentSet);
        }
        let parent_count = u32::try_from(parents.len()).map_err(|_| WorkError::LengthOverflow)?;
        let mut parent_bytes = Vec::with_capacity(4 + parents.len() * 32);
        parent_bytes.extend_from_slice(&parent_count.to_le_bytes());
        for parent in parents {
            parent_bytes.extend_from_slice(parent);
        }
        let parent_set_digest = framed_hash(OPAQUE_PARENT_SET_DOMAIN, &[&parent_bytes])?;
        Ok(Self {
            context,
            body_id,
            body_digest: Sha256::digest(canonical_body).into(),
            parent_set_digest,
        })
    }

    fn from_validated_body(
        context: WorkContext,
        body: &OrderedBodyV2,
        canonical_body: &[u8],
    ) -> Result<Self, WorkError> {
        if body.namespace.profile_domain != context.profile_domain {
            return Err(WorkError::ProfileMismatch);
        }
        if body.namespace.parents.len() > MAX_PARENTS {
            return Err(WorkError::TooManyParents);
        }
        if body
            .namespace
            .parents
            .iter()
            .any(|parent| parent.profile_domain != context.profile_domain)
        {
            return Err(WorkError::ParentProfileMismatch);
        }

        let parent_bytes = body
            .namespace
            .parents
            .canonical_bytes()
            .map_err(|_| WorkError::InvalidParentSet)?;
        let parent_set_digest = framed_hash(PARENT_SET_DOMAIN, &[&parent_bytes])?;

        Ok(Self {
            context,
            body_id: body.body_id,
            body_digest: Sha256::digest(canonical_body).into(),
            parent_set_digest,
        })
    }

    /// Returns the exact body identifier.
    #[must_use]
    pub const fn body_id(&self) -> Hash32 {
        self.body_id
    }

    /// Returns the exact canonical body digest.
    #[must_use]
    pub const fn body_digest(&self) -> Hash32 {
        self.body_digest
    }

    /// Returns the canonical ordered-parent-set digest.
    #[must_use]
    pub const fn parent_set_digest(&self) -> Hash32 {
        self.parent_set_digest
    }

    /// Returns the exact chain domain used to derive this subject.
    #[must_use]
    pub const fn chain_domain(&self) -> Hash32 {
        self.context.chain_domain
    }

    /// Returns the exact profile domain used to derive this subject.
    #[must_use]
    pub const fn profile_domain(&self) -> Hash32 {
        self.context.profile_domain
    }
}

/// Computes the sole canonical target for a bounded synthetic difficulty.
///
/// # Errors
///
/// Returns an error when difficulty is zero or above the synthetic cap.
pub const fn canonical_target(difficulty: u64) -> Result<u64, WorkError> {
    if difficulty == 0 || difficulty > MAX_SYNTHETIC_DIFFICULTY {
        return Err(WorkError::DifficultyOutOfBounds);
    }
    Ok(u64::MAX / difficulty)
}

/// Strictly verifies a proof against exact canonical body bytes and context.
///
/// # Errors
///
/// Returns an error for malformed bytes, context/body/parent/algorithm
/// mismatches, a non-canonical target, or insufficient work.
pub fn verify_work(
    algorithm: &dyn WorkAlgorithm,
    context: WorkContext,
    canonical_body: &[u8],
    canonical_proof: &[u8],
) -> Result<VerifiedWorkProof, WorkError> {
    let subject = WorkSubject::from_canonical_body_bytes(context, canonical_body)?;
    verify_subject_work(algorithm, &subject, canonical_proof)
}

/// Convenience name for strict proof verification at body admission.
///
/// # Errors
///
/// Returns the same failures as [`verify_work`].
pub fn verify_body_work(
    algorithm: &dyn WorkAlgorithm,
    context: WorkContext,
    canonical_body: &[u8],
    canonical_proof: &[u8],
) -> Result<VerifiedWorkProof, WorkError> {
    verify_work(algorithm, context, canonical_body, canonical_proof)
}

/// Strictly verifies a proof against a prevalidated work subject.
///
/// # Errors
///
/// Returns an error for malformed bytes, binding mismatch, a non-canonical
/// target, or insufficient work.
pub fn verify_subject_work(
    algorithm: &dyn WorkAlgorithm,
    subject: &WorkSubject,
    canonical_proof: &[u8],
) -> Result<VerifiedWorkProof, WorkError> {
    let unverified = WorkProofEnvelopeV1::decode_unverified(canonical_proof)?;
    let envelope = unverified.0;

    if envelope.algorithm_id != algorithm.algorithm_id() {
        return Err(WorkError::AlgorithmMismatch);
    }
    if envelope.chain_domain != subject.context.chain_domain {
        return Err(WorkError::ChainDomainMismatch);
    }
    if envelope.profile_domain != subject.context.profile_domain {
        return Err(WorkError::ProfileMismatch);
    }
    if envelope.body_id != subject.body_id {
        return Err(WorkError::BodyIdMismatch);
    }
    if envelope.body_digest != subject.body_digest {
        return Err(WorkError::BodyDigestMismatch);
    }
    if envelope.parent_set_digest != subject.parent_set_digest {
        return Err(WorkError::ParentSetMismatch);
    }

    let target = algorithm.target_for_difficulty(envelope.difficulty)?;
    if envelope.target != target {
        return Err(WorkError::NonCanonicalTarget);
    }
    let bytes = envelope.canonical_bytes();
    let digest = algorithm.digest(&bytes)?;
    let score_bytes: [u8; 8] = digest
        .get(..8)
        .ok_or(WorkError::AlgorithmFailure)?
        .try_into()
        .map_err(|_| WorkError::AlgorithmFailure)?;
    let score = u64::from_be_bytes(score_bytes);
    if score > target {
        return Err(WorkError::InsufficientWork);
    }

    let derived_work = DerivedWork(algorithm.derive_work(envelope.difficulty, target)?);
    Ok(VerifiedWorkProof {
        envelope,
        canonical_bytes: bytes,
        digest,
        score,
        derived_work,
    })
}

/// Searches a bounded, deterministic nonce range for one synthetic proof.
///
/// # Errors
///
/// Returns an error for invalid difficulty, zero or excessive attempts, nonce
/// range overflow, backend failure, or exhaustion of the requested range.
pub fn mine_local(
    algorithm: &dyn WorkAlgorithm,
    subject: &WorkSubject,
    difficulty: u64,
    start_nonce: u64,
    max_attempts: u64,
) -> Result<VerifiedWorkProof, WorkError> {
    let target = algorithm.target_for_difficulty(difficulty)?;
    if max_attempts == 0 || max_attempts > MAX_LOCAL_MINING_ATTEMPTS {
        return Err(WorkError::MiningAttemptsOutOfBounds);
    }
    let last_offset = max_attempts
        .checked_sub(1)
        .ok_or(WorkError::MiningAttemptsOutOfBounds)?;
    start_nonce
        .checked_add(last_offset)
        .ok_or(WorkError::NonceRangeOverflow)?;

    for offset in 0..max_attempts {
        let nonce = start_nonce
            .checked_add(offset)
            .ok_or(WorkError::NonceRangeOverflow)?;
        let envelope = WorkProofEnvelopeV1 {
            algorithm_id: algorithm.algorithm_id(),
            chain_domain: subject.context.chain_domain,
            profile_domain: subject.context.profile_domain,
            body_id: subject.body_id,
            body_digest: subject.body_digest,
            parent_set_digest: subject.parent_set_digest,
            difficulty,
            target,
            nonce,
        };
        let bytes = envelope.canonical_bytes();
        match verify_subject_work(algorithm, subject, &bytes) {
            Ok(verified) => return Ok(verified),
            Err(WorkError::InsufficientWork) => {}
            Err(error) => return Err(error),
        }
    }
    Err(WorkError::MiningExhausted)
}

/// Builds a body subject and searches a bounded deterministic nonce range.
///
/// # Errors
///
/// Returns body-validation, target-policy, nonce-range, backend, or exhaustion
/// failures from [`WorkSubject::from_canonical_body_bytes`] and [`mine_local`].
pub fn mine_body_work(
    algorithm: &dyn WorkAlgorithm,
    context: WorkContext,
    canonical_body: &[u8],
    difficulty: u64,
    start_nonce: u64,
    max_attempts: u64,
) -> Result<VerifiedWorkProof, WorkError> {
    let subject = WorkSubject::from_canonical_body_bytes(context, canonical_body)?;
    mine_local(algorithm, &subject, difficulty, start_nonce, max_attempts)
}

fn framed_hash(domain: &[u8], parts: &[&[u8]]) -> Result<Hash32, WorkError> {
    let domain_len = u32::try_from(domain.len()).map_err(|_| WorkError::LengthOverflow)?;
    let part_count = u32::try_from(parts.len()).map_err(|_| WorkError::LengthOverflow)?;
    let mut digest = Sha256::new();
    digest.update(FRAMED_HASH_PREFIX);
    digest.update(domain_len.to_le_bytes());
    digest.update(domain);
    digest.update(part_count.to_le_bytes());
    for part in parts {
        let length = u32::try_from(part.len()).map_err(|_| WorkError::LengthOverflow)?;
        digest.update(length.to_le_bytes());
        digest.update(part);
    }
    Ok(digest.finalize().into())
}

struct FixedDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> FixedDecoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], WorkError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(WorkError::LengthOverflow)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(WorkError::InvalidProofLength)?;
        self.offset = end;
        value.try_into().map_err(|_| WorkError::InvalidProofLength)
    }

    fn u16(&mut self) -> Result<u16, WorkError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, WorkError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    const fn finish(self) -> Result<(), WorkError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(WorkError::InvalidProofLength)
        }
    }
}

/// Structural, binding, policy, verification, and mining failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WorkError {
    /// Proof bytes do not have the sole canonical length.
    #[error("work.invalid_proof_length")]
    InvalidProofLength,
    /// Proof magic is not recognized.
    #[error("work.invalid_proof_magic")]
    InvalidProofMagic,
    /// Proof version is not supported.
    #[error("work.unsupported_proof_version")]
    UnsupportedProofVersion,
    /// A bounded length calculation overflowed.
    #[error("work.length_overflow")]
    LengthOverflow,
    /// Canonical body bytes exceed the Gate 2 bound.
    #[error("work.body_too_large")]
    BodyTooLarge,
    /// Body bytes are malformed or not canonical.
    #[error("work.invalid_canonical_body")]
    InvalidCanonicalBody,
    /// The canonical parent set is malformed or unordered.
    #[error("work.invalid_parent_set")]
    InvalidParentSet,
    /// Parent count exceeds the frozen Gate 2 bound.
    #[error("work.too_many_parents")]
    TooManyParents,
    /// A parent belongs to another profile.
    #[error("work.parent_profile_mismatch")]
    ParentProfileMismatch,
    /// The configured algorithm does not match the proof.
    #[error("work.algorithm_mismatch")]
    AlgorithmMismatch,
    /// The proof binds another chain domain.
    #[error("work.chain_domain_mismatch")]
    ChainDomainMismatch,
    /// The body or proof binds another profile domain.
    #[error("work.profile_mismatch")]
    ProfileMismatch,
    /// The proof binds another body identifier.
    #[error("work.body_id_mismatch")]
    BodyIdMismatch,
    /// The proof binds other canonical body bytes.
    #[error("work.body_digest_mismatch")]
    BodyDigestMismatch,
    /// The proof binds another canonical ordered parent set.
    #[error("work.parent_set_mismatch")]
    ParentSetMismatch,
    /// Difficulty is zero or above the synthetic cap.
    #[error("work.difficulty_out_of_bounds")]
    DifficultyOutOfBounds,
    /// The supplied target is not uniquely derived from difficulty.
    #[error("work.non_canonical_target")]
    NonCanonicalTarget,
    /// The digest score is above the canonical target.
    #[error("work.insufficient_work")]
    InsufficientWork,
    /// Requested attempts are zero or exceed the local cap.
    #[error("work.mining_attempts_out_of_bounds")]
    MiningAttemptsOutOfBounds,
    /// The requested nonce range would overflow.
    #[error("work.nonce_range_overflow")]
    NonceRangeOverflow,
    /// No valid nonce exists in the requested bounded range.
    #[error("work.mining_exhausted")]
    MiningExhausted,
    /// A configured backend could not evaluate the bounded transcript.
    #[error("work.algorithm_failure")]
    AlgorithmFailure,
}

impl WorkError {
    /// Returns the stable machine-facing diagnostic code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidProofLength => "work.invalid_proof_length",
            Self::InvalidProofMagic => "work.invalid_proof_magic",
            Self::UnsupportedProofVersion => "work.unsupported_proof_version",
            Self::LengthOverflow => "work.length_overflow",
            Self::BodyTooLarge => "work.body_too_large",
            Self::InvalidCanonicalBody => "work.invalid_canonical_body",
            Self::InvalidParentSet => "work.invalid_parent_set",
            Self::TooManyParents => "work.too_many_parents",
            Self::ParentProfileMismatch => "work.parent_profile_mismatch",
            Self::AlgorithmMismatch => "work.algorithm_mismatch",
            Self::ChainDomainMismatch => "work.chain_domain_mismatch",
            Self::ProfileMismatch => "work.profile_mismatch",
            Self::BodyIdMismatch => "work.body_id_mismatch",
            Self::BodyDigestMismatch => "work.body_digest_mismatch",
            Self::ParentSetMismatch => "work.parent_set_mismatch",
            Self::DifficultyOutOfBounds => "work.difficulty_out_of_bounds",
            Self::NonCanonicalTarget => "work.non_canonical_target",
            Self::InsufficientWork => "work.insufficient_work",
            Self::MiningAttemptsOutOfBounds => "work.mining_attempts_out_of_bounds",
            Self::NonceRangeOverflow => "work.nonce_range_overflow",
            Self::MiningExhausted => "work.mining_exhausted",
            Self::AlgorithmFailure => "work.algorithm_failure",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use silk_gate2::{
        BodyNamespaceKind, BodyNamespaceV1, BoundedVec, ParentKind, ParentRefV1, SortedUniqueVec,
    };

    const ALGORITHM_OFFSET: usize = 10;
    const CHAIN_OFFSET: usize = ALGORITHM_OFFSET + 32;
    const PROFILE_OFFSET: usize = CHAIN_OFFSET + 32;
    const BODY_ID_OFFSET: usize = PROFILE_OFFSET + 32;
    const BODY_DIGEST_OFFSET: usize = BODY_ID_OFFSET + 32;
    const PARENT_SET_OFFSET: usize = BODY_DIGEST_OFFSET + 32;
    const DIFFICULTY_OFFSET: usize = PARENT_SET_OFFSET + 32;
    const TARGET_OFFSET: usize = DIFFICULTY_OFFSET + 8;
    const NONCE_OFFSET: usize = TARGET_OFFSET + 8;

    fn hash(byte: u8) -> Hash32 {
        [byte; 32]
    }

    fn context() -> WorkContext {
        WorkContext::new(hash(0x11), hash(0x22))
    }

    fn body(body_id: u8, parent_ids: &[u8]) -> OrderedBodyV2 {
        let parents = parent_ids
            .iter()
            .map(|id| ParentRefV1 {
                parent_kind: ParentKind::Body,
                parent_id: hash(*id),
                profile_domain: context().profile_domain(),
                lineage_fence_id: None,
            })
            .collect();
        OrderedBodyV2 {
            body_id: hash(body_id),
            namespace: BodyNamespaceV1 {
                namespace_kind: BodyNamespaceKind::Unfenced,
                profile_domain: context().profile_domain(),
                active_fence_id: None,
                parents: SortedUniqueVec::new(parents),
            },
            envelopes: BoundedVec::new(Vec::new()).expect("empty bounded body"),
        }
    }

    fn mined() -> (OrderedBodyV2, VerifiedWorkProof) {
        let body = body(0x40, &[0x20, 0x30]);
        let subject = WorkSubject::from_body(context(), &body).expect("subject");
        let proof = mine_local(&SyntheticSha256, &subject, 32, 0, 10_000).expect("mine");
        (body, proof)
    }

    fn mutate(bytes: &[u8], offset: usize) -> Vec<u8> {
        let mut changed = bytes.to_vec();
        changed[offset] ^= 1;
        changed
    }

    #[test]
    fn mines_and_reverifies_deterministically() {
        let (body, proof) = mined();
        let canonical_body = body.canonical_bytes().expect("body bytes");
        let verified = verify_work(
            &SyntheticSha256,
            context(),
            &canonical_body,
            proof.canonical_bytes(),
        )
        .expect("verify");

        assert_eq!(verified, proof);
        assert_eq!(verified.derived_work().get(), 32);
        assert!(verified.score() <= verified.envelope().target());
        assert_eq!(verified.canonical_bytes().len(), WORK_PROOF_BYTES);
    }

    #[test]
    fn rejects_nonce_body_parent_domain_and_target_tampering() {
        let (mined_body, proof) = mined();
        let body_bytes = mined_body.canonical_bytes().expect("body bytes");
        let proof_bytes = proof.canonical_bytes();

        let original_nonce = proof.envelope().nonce();
        let rejected_nonce = (1..=256).find_map(|offset| {
            let nonce = original_nonce.checked_add(offset)?;
            let mut changed = proof_bytes.to_vec();
            changed[NONCE_OFFSET..].copy_from_slice(&nonce.to_le_bytes());
            (verify_work(&SyntheticSha256, context(), &body_bytes, &changed)
                == Err(WorkError::InsufficientWork))
            .then_some(changed)
        });
        assert!(
            rejected_nonce.is_some(),
            "deterministic invalid nonce exists"
        );

        let other_body_bytes = body(0x40, &[0x20])
            .canonical_bytes()
            .expect("other body bytes");
        assert_eq!(
            verify_work(&SyntheticSha256, context(), &other_body_bytes, proof_bytes,),
            Err(WorkError::BodyDigestMismatch)
        );
        assert_eq!(
            verify_work(
                &SyntheticSha256,
                context(),
                &body_bytes,
                &mutate(proof_bytes, BODY_ID_OFFSET),
            ),
            Err(WorkError::BodyIdMismatch)
        );
        assert_eq!(
            verify_work(
                &SyntheticSha256,
                context(),
                &body_bytes,
                &mutate(proof_bytes, BODY_DIGEST_OFFSET),
            ),
            Err(WorkError::BodyDigestMismatch)
        );
        assert_eq!(
            verify_work(
                &SyntheticSha256,
                context(),
                &body_bytes,
                &mutate(proof_bytes, PARENT_SET_OFFSET),
            ),
            Err(WorkError::ParentSetMismatch)
        );
        assert_eq!(
            verify_work(
                &SyntheticSha256,
                context(),
                &body_bytes,
                &mutate(proof_bytes, CHAIN_OFFSET),
            ),
            Err(WorkError::ChainDomainMismatch)
        );
        assert_eq!(
            verify_work(
                &SyntheticSha256,
                context(),
                &body_bytes,
                &mutate(proof_bytes, PROFILE_OFFSET),
            ),
            Err(WorkError::ProfileMismatch)
        );
        assert_eq!(
            verify_work(
                &SyntheticSha256,
                context(),
                &body_bytes,
                &mutate(proof_bytes, TARGET_OFFSET),
            ),
            Err(WorkError::NonCanonicalTarget)
        );
    }

    #[test]
    fn rejects_algorithm_difficulty_and_structural_tampering() {
        let (body, proof) = mined();
        let body_bytes = body.canonical_bytes().expect("body bytes");
        let proof_bytes = proof.canonical_bytes();

        assert_eq!(
            verify_work(
                &SyntheticSha256,
                context(),
                &body_bytes,
                &mutate(proof_bytes, ALGORITHM_OFFSET),
            ),
            Err(WorkError::AlgorithmMismatch)
        );
        let mut zero_difficulty = proof_bytes.to_vec();
        zero_difficulty[DIFFICULTY_OFFSET..TARGET_OFFSET].fill(0);
        assert_eq!(
            verify_work(&SyntheticSha256, context(), &body_bytes, &zero_difficulty,),
            Err(WorkError::DifficultyOutOfBounds)
        );
        assert_eq!(
            WorkProofEnvelopeV1::decode_unverified(&proof_bytes[..proof_bytes.len() - 1]),
            Err(WorkError::InvalidProofLength)
        );
        let mut wrong_version = proof_bytes.to_vec();
        wrong_version[8] = 2;
        assert_eq!(
            WorkProofEnvelopeV1::decode_unverified(&wrong_version),
            Err(WorkError::UnsupportedProofVersion)
        );
    }

    #[test]
    fn enforces_target_attempt_and_nonce_boundaries() {
        assert_eq!(canonical_target(0), Err(WorkError::DifficultyOutOfBounds));
        assert_eq!(canonical_target(1), Ok(u64::MAX));
        assert_eq!(
            canonical_target(MAX_SYNTHETIC_DIFFICULTY + 1),
            Err(WorkError::DifficultyOutOfBounds)
        );

        let body = body(0x40, &[]);
        let subject = WorkSubject::from_body(context(), &body).expect("subject");
        assert_eq!(
            mine_local(&SyntheticSha256, &subject, 1, 0, 0),
            Err(WorkError::MiningAttemptsOutOfBounds)
        );
        assert_eq!(
            mine_local(
                &SyntheticSha256,
                &subject,
                1,
                0,
                MAX_LOCAL_MINING_ATTEMPTS + 1,
            ),
            Err(WorkError::MiningAttemptsOutOfBounds)
        );
        assert_eq!(
            mine_local(&SyntheticSha256, &subject, 1, u64::MAX, 2),
            Err(WorkError::NonceRangeOverflow)
        );
        assert!(mine_local(&SyntheticSha256, &subject, 1, u64::MAX, 1).is_ok());
    }

    #[test]
    fn exact_parent_order_and_profiles_are_part_of_subject_validation() {
        let valid = body(0x40, &[0x20, 0x30]);
        let mut reordered = valid.clone();
        reordered.namespace.parents.reverse();
        assert_eq!(
            WorkSubject::from_body(context(), &reordered),
            Err(WorkError::InvalidCanonicalBody)
        );

        let mut wrong_profile = valid;
        wrong_profile.namespace.parents[0].profile_domain = hash(0xff);
        assert_eq!(
            WorkSubject::from_body(context(), &wrong_profile),
            Err(WorkError::ParentProfileMismatch)
        );
    }

    #[test]
    fn opaque_work_subject_requires_canonical_bounded_parents() {
        let canonical_body = b"synthetic canonical opaque body v1";
        let body_id = hash(0x40);
        let sorted = [hash(0x20), hash(0x30)];
        assert!(
            WorkSubject::from_opaque_body_v1(context(), body_id, canonical_body, &sorted,).is_ok()
        );

        let unsorted = [hash(0x30), hash(0x20)];
        assert_eq!(
            WorkSubject::from_opaque_body_v1(context(), body_id, canonical_body, &unsorted,),
            Err(WorkError::InvalidParentSet)
        );
        let duplicate = [hash(0x20), hash(0x20)];
        assert_eq!(
            WorkSubject::from_opaque_body_v1(context(), body_id, canonical_body, &duplicate,),
            Err(WorkError::InvalidParentSet)
        );
        let too_many = vec![hash(0x20); MAX_PARENTS + 1];
        assert_eq!(
            WorkSubject::from_opaque_body_v1(context(), body_id, canonical_body, &too_many,),
            Err(WorkError::TooManyParents)
        );
    }

    #[test]
    fn opaque_work_subject_binds_body_id_parents_and_context() {
        let canonical_body = b"synthetic canonical opaque body v1";
        let body_id = hash(0x40);
        let parents = [hash(0x20), hash(0x30)];
        let subject =
            WorkSubject::from_opaque_body_v1(context(), body_id, canonical_body, &parents)
                .expect("canonical opaque subject");
        assert_eq!(
            subject,
            WorkSubject::from_opaque_body_v1(context(), body_id, canonical_body, &parents,)
                .expect("same inputs reproduce the subject")
        );

        let changed_body = WorkSubject::from_opaque_body_v1(
            context(),
            body_id,
            b"synthetic canonical opaque body v2",
            &parents,
        )
        .expect("changed opaque body");
        assert_ne!(subject.body_digest(), changed_body.body_digest());
        assert_eq!(subject.body_id(), changed_body.body_id());

        let changed_id =
            WorkSubject::from_opaque_body_v1(context(), hash(0x41), canonical_body, &parents)
                .expect("changed opaque body id");
        assert_ne!(subject.body_id(), changed_id.body_id());
        assert_eq!(subject.body_digest(), changed_id.body_digest());

        let changed_parents = WorkSubject::from_opaque_body_v1(
            context(),
            body_id,
            canonical_body,
            &[hash(0x20), hash(0x31)],
        )
        .expect("changed canonical parents");
        assert_ne!(
            subject.parent_set_digest(),
            changed_parents.parent_set_digest()
        );

        let changed_chain = WorkSubject::from_opaque_body_v1(
            WorkContext::new(hash(0x12), context().profile_domain()),
            body_id,
            canonical_body,
            &parents,
        )
        .expect("changed chain context");
        let changed_profile = WorkSubject::from_opaque_body_v1(
            WorkContext::new(context().chain_domain(), hash(0x23)),
            body_id,
            canonical_body,
            &parents,
        )
        .expect("changed profile context");

        let proof =
            mine_local(&SyntheticSha256, &subject, 1, 0, 1).expect("difficulty-one opaque proof");
        assert!(verify_subject_work(&SyntheticSha256, &subject, proof.canonical_bytes()).is_ok());
        assert_eq!(
            verify_subject_work(&SyntheticSha256, &changed_body, proof.canonical_bytes(),),
            Err(WorkError::BodyDigestMismatch)
        );
        assert_eq!(
            verify_subject_work(&SyntheticSha256, &changed_id, proof.canonical_bytes()),
            Err(WorkError::BodyIdMismatch)
        );
        assert_eq!(
            verify_subject_work(&SyntheticSha256, &changed_parents, proof.canonical_bytes(),),
            Err(WorkError::ParentSetMismatch)
        );
        assert_eq!(
            verify_subject_work(&SyntheticSha256, &changed_chain, proof.canonical_bytes(),),
            Err(WorkError::ChainDomainMismatch)
        );
        assert_eq!(
            verify_subject_work(&SyntheticSha256, &changed_profile, proof.canonical_bytes(),),
            Err(WorkError::ProfileMismatch)
        );
    }
}
