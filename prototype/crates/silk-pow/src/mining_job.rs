//! Transport-neutral, bounded synthetic mining jobs and worker results.

use super::{
    MAX_LOCAL_MINING_ATTEMPTS, SYNTHETIC_SHA256_ALGORITHM_ID, SyntheticSha256, WorkContext,
    WorkError, WorkSubject, canonical_target, framed_hash, mine_body_work,
};
use silk_gate2::{Hash32, MAX_BODY_BYTES};
use thiserror::Error;

const JOB_MAGIC: [u8; 8] = *b"SLKJOB\0\0";
const RESULT_MAGIC: [u8; 8] = *b"SLKRES\0\0";
const JOB_ID_DOMAIN: &[u8] = b"SilkNode/SyntheticMining/JobId/v1";
const JOB_HASH_FIELDS: usize = 7;
const JOB_U64_FIELDS: usize = 6;
const RESULT_RANGE_FIELDS: usize = 3;
const RESULT_KIND_NO_SOLUTION: u8 = 0;
const RESULT_KIND_PROOF_CANDIDATE: u8 = 1;
const RESULT_KIND_RESERVED_BYTES: usize = 3;

/// Frozen transport-neutral synthetic mining-job version.
pub const MINING_JOB_VERSION: u16 = 1;
/// Frozen transport-neutral synthetic mining-result version.
pub const MINING_RESULT_VERSION: u16 = 1;
/// Maximum logical epoch distance between a job epoch and its expiry.
pub const MAX_MINING_JOB_EPOCH_SPAN: u64 = 1_024;
/// Exact bytes before the canonical body in a version-one mining job.
pub const MINING_JOB_FIXED_BYTES: usize =
    JOB_MAGIC.len() + 2 + 2 + (JOB_HASH_FIELDS * 32) + (JOB_U64_FIELDS * 8) + 4;
/// Maximum canonical byte length of a version-one mining job.
pub const MAX_MINING_JOB_BYTES: usize = MINING_JOB_FIXED_BYTES + MAX_BODY_BYTES;
/// Exact bytes before an optional proof in a version-one mining result.
pub const MINING_RESULT_FIXED_BYTES: usize = RESULT_MAGIC.len()
    + 2
    + 2
    + 32
    + (RESULT_RANGE_FIELDS * 8)
    + 1
    + RESULT_KIND_RESERVED_BYTES
    + 4;
/// Maximum canonical byte length of a version-one mining result.
pub const MAX_MINING_RESULT_BYTES: usize = MINING_RESULT_FIXED_BYTES + super::WORK_PROOF_BYTES;

/// Explicit identifier for the bounded synthetic `u64::MAX / difficulty` policy.
///
/// It is the SHA-256 digest of
/// `SilkNode/SyntheticWork/TargetPolicy/v1`. This private test identifier does
/// not select a production target, difficulty adjustment, or proof-of-work
/// policy.
pub const SYNTHETIC_TARGET_POLICY_ID: Hash32 = [
    0x6c, 0x02, 0x9a, 0xea, 0x66, 0xb6, 0xc7, 0x30, 0xbe, 0xdc, 0x4c, 0x94, 0x64, 0xe4, 0xc4, 0x32,
    0x7c, 0x13, 0xab, 0x4c, 0xea, 0xd0, 0x12, 0xbc, 0x0c, 0x22, 0xf6, 0xc9, 0x54, 0x59, 0x80, 0x46,
];

/// Version-explicit chain/profile context for synthetic mining jobs.
pub type MiningJobContextV1 = WorkContext;

/// One validated, bounded inclusive synthetic nonce range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MiningNonceRangeV1 {
    start: u64,
    count: u64,
}

impl MiningNonceRangeV1 {
    /// Creates a nonempty range bounded by [`MAX_LOCAL_MINING_ATTEMPTS`].
    ///
    /// # Errors
    ///
    /// Rejects zero or excessive counts and a range whose final nonce would
    /// overflow `u64`.
    pub fn new(start: u64, count: u64) -> Result<Self, MiningJobError> {
        validate_nonce_range(start, count)?;
        Ok(Self { start, count })
    }

    /// Returns the first assigned nonce.
    #[must_use]
    pub const fn start(self) -> u64 {
        self.start
    }

    /// Returns the exact number of assigned nonces.
    #[must_use]
    pub const fn count(self) -> u64 {
        self.count
    }

    /// Returns whether a nonce is inside this exact assignment.
    #[must_use]
    pub const fn contains(self, nonce: u64) -> bool {
        match nonce.checked_sub(self.start) {
            Some(offset) => offset < self.count,
            None => false,
        }
    }
}

/// Canonical version-one assignment for one bounded synthetic nonce range.
///
/// Construction validates the body and every non-temporal binding. Decoding
/// grants no authority; callers must promote through
/// [`UnverifiedMiningJobV1::validate`] using their expected chain/profile
/// context and current logical job epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MiningJobV1 {
    algorithm_id: Hash32,
    target_policy_id: Hash32,
    chain_domain: Hash32,
    profile_domain: Hash32,
    body_id: Hash32,
    body_sha256: Hash32,
    parent_set_digest: Hash32,
    difficulty: u64,
    full_target: u64,
    job_epoch: u64,
    expires_at_epoch: u64,
    nonce_start: u64,
    nonce_count: u64,
    canonical_body: Vec<u8>,
}

impl MiningJobV1 {
    /// Creates one exact synthetic mining assignment from canonical body bytes.
    ///
    /// # Errors
    ///
    /// Rejects malformed or non-canonical bodies, invalid difficulty, inverted
    /// or excessive logical expiry, and zero, excessive, or overflowing nonce
    /// ranges.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        context: MiningJobContextV1,
        canonical_body: &[u8],
        difficulty: u64,
        job_epoch: u64,
        expires_at_epoch: u64,
        nonce_range: MiningNonceRangeV1,
    ) -> Result<Self, MiningJobError> {
        let subject = WorkSubject::from_canonical_body_bytes(context, canonical_body)?;
        let job = Self {
            algorithm_id: SYNTHETIC_SHA256_ALGORITHM_ID,
            target_policy_id: SYNTHETIC_TARGET_POLICY_ID,
            chain_domain: context.chain_domain(),
            profile_domain: context.profile_domain(),
            body_id: subject.body_id(),
            body_sha256: subject.body_digest(),
            parent_set_digest: subject.parent_set_digest(),
            difficulty,
            full_target: canonical_target(difficulty)?,
            job_epoch,
            expires_at_epoch,
            nonce_start: nonce_range.start(),
            nonce_count: nonce_range.count(),
            canonical_body: canonical_body.to_vec(),
        };
        validate_lifetime(job.job_epoch, job.expires_at_epoch, job.job_epoch)?;
        validate_nonce_range(job.nonce_start, job.nonce_count)?;
        Ok(job)
    }

    /// Strictly decodes a bounded job without granting contextual authority.
    ///
    /// # Errors
    ///
    /// Rejects an oversized, truncated, wrongly framed, unknown-version, or
    /// structurally invalid assignment.
    pub fn decode_unverified(bytes: &[u8]) -> Result<UnverifiedMiningJobV1, MiningJobError> {
        if bytes.len() < MINING_JOB_FIXED_BYTES || bytes.len() > MAX_MINING_JOB_BYTES {
            return Err(MiningJobError::InvalidJobLength);
        }
        let mut decoder = Decoder::new(bytes, MiningJobError::InvalidJobLength);
        if decoder.array::<8>()? != JOB_MAGIC {
            return Err(MiningJobError::InvalidJobMagic);
        }
        if decoder.u16()? != MINING_JOB_VERSION {
            return Err(MiningJobError::UnsupportedJobVersion);
        }
        if decoder.u16()? != 0 {
            return Err(MiningJobError::InvalidJobFlags);
        }
        let job = Self {
            algorithm_id: decoder.hash32()?,
            target_policy_id: decoder.hash32()?,
            chain_domain: decoder.hash32()?,
            profile_domain: decoder.hash32()?,
            body_id: decoder.hash32()?,
            body_sha256: decoder.hash32()?,
            parent_set_digest: decoder.hash32()?,
            difficulty: decoder.u64()?,
            full_target: decoder.u64()?,
            job_epoch: decoder.u64()?,
            expires_at_epoch: decoder.u64()?,
            nonce_start: decoder.u64()?,
            nonce_count: decoder.u64()?,
            canonical_body: {
                let length = usize::try_from(decoder.u32()?)
                    .map_err(|_| MiningJobError::InvalidJobLength)?;
                if length == 0 || length > MAX_BODY_BYTES {
                    return Err(MiningJobError::InvalidJobLength);
                }
                decoder.take(length)?.to_vec()
            },
        };
        decoder.finish()?;
        validate_nonce_range(job.nonce_start, job.nonce_count)?;
        Ok(UnverifiedMiningJobV1(job))
    }

    /// Returns the exact canonical job bytes.
    ///
    /// # Panics
    ///
    /// Panics only if the private body-length invariant is violated internally;
    /// public construction and decoding both enforce the smaller protocol cap.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(MINING_JOB_FIXED_BYTES + self.canonical_body.len());
        bytes.extend_from_slice(&JOB_MAGIC);
        bytes.extend_from_slice(&MINING_JOB_VERSION.to_le_bytes());
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        bytes.extend_from_slice(&self.algorithm_id);
        bytes.extend_from_slice(&self.target_policy_id);
        bytes.extend_from_slice(&self.chain_domain);
        bytes.extend_from_slice(&self.profile_domain);
        bytes.extend_from_slice(&self.body_id);
        bytes.extend_from_slice(&self.body_sha256);
        bytes.extend_from_slice(&self.parent_set_digest);
        bytes.extend_from_slice(&self.difficulty.to_le_bytes());
        bytes.extend_from_slice(&self.full_target.to_le_bytes());
        bytes.extend_from_slice(&self.job_epoch.to_le_bytes());
        bytes.extend_from_slice(&self.expires_at_epoch.to_le_bytes());
        bytes.extend_from_slice(&self.nonce_start.to_le_bytes());
        bytes.extend_from_slice(&self.nonce_count.to_le_bytes());
        let body_length = u32::try_from(self.canonical_body.len())
            .expect("a validated body length always fits u32");
        bytes.extend_from_slice(&body_length.to_le_bytes());
        bytes.extend_from_slice(&self.canonical_body);
        debug_assert!(bytes.len() <= MAX_MINING_JOB_BYTES);
        bytes
    }

    /// Derives the domain-separated identifier of these exact canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns a bounded length error only if the frozen framing cannot encode
    /// a job that already passed the public byte limit.
    pub fn job_id(&self) -> Result<Hash32, MiningJobError> {
        let bytes = self.canonical_bytes();
        Ok(framed_hash(JOB_ID_DOMAIN, &[&bytes])?)
    }

    /// Returns the claimed synthetic algorithm identifier.
    #[must_use]
    pub const fn algorithm_id(&self) -> Hash32 {
        self.algorithm_id
    }

    /// Returns the claimed synthetic target-policy identifier.
    #[must_use]
    pub const fn target_policy_id(&self) -> Hash32 {
        self.target_policy_id
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

    /// Returns the exact body identifier carried by the canonical body.
    #[must_use]
    pub const fn body_id(&self) -> Hash32 {
        self.body_id
    }

    /// Returns the SHA-256 digest of the exact canonical body bytes.
    #[must_use]
    pub const fn body_sha256(&self) -> Hash32 {
        self.body_sha256
    }

    /// Returns the digest of the canonical ordered parent set.
    #[must_use]
    pub const fn parent_set_digest(&self) -> Hash32 {
        self.parent_set_digest
    }

    /// Returns the bounded synthetic difficulty.
    #[must_use]
    pub const fn difficulty(&self) -> u64 {
        self.difficulty
    }

    /// Returns the full node-admission target derived from difficulty.
    #[must_use]
    pub const fn full_target(&self) -> u64 {
        self.full_target
    }

    /// Returns the logical coordinator epoch that issued this assignment.
    #[must_use]
    pub const fn job_epoch(&self) -> u64 {
        self.job_epoch
    }

    /// Returns the inclusive logical expiry epoch.
    #[must_use]
    pub const fn expires_at_epoch(&self) -> u64 {
        self.expires_at_epoch
    }

    /// Returns the first nonce in the assigned range.
    #[must_use]
    pub const fn nonce_start(&self) -> u64 {
        self.nonce_start
    }

    /// Returns the exact number of nonces in the assigned range.
    #[must_use]
    pub const fn nonce_count(&self) -> u64 {
        self.nonce_count
    }

    /// Returns the exact validated nonce assignment.
    #[must_use]
    pub const fn nonce_range(&self) -> MiningNonceRangeV1 {
        MiningNonceRangeV1 {
            start: self.nonce_start,
            count: self.nonce_count,
        }
    }

    /// Borrows the exact canonical body bytes.
    #[must_use]
    pub fn canonical_body(&self) -> &[u8] {
        &self.canonical_body
    }
}

/// A structurally decoded mining job that has no contextual authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnverifiedMiningJobV1(MiningJobV1);

impl UnverifiedMiningJobV1 {
    /// Borrows the decoded fields for diagnostics only.
    #[must_use]
    pub const fn decoded(&self) -> &MiningJobV1 {
        &self.0
    }

    /// Validates and promotes the exact job against local context and epoch.
    ///
    /// # Errors
    ///
    /// Rejects wrong algorithm, target policy, chain/profile context, body or
    /// parent binding, target, lifetime, current epoch, or nonce bounds.
    pub fn validate(
        self,
        expected_context: WorkContext,
        current_epoch: u64,
    ) -> Result<VerifiedMiningJobV1, MiningJobError> {
        let job = self.0;
        if job.algorithm_id != SYNTHETIC_SHA256_ALGORITHM_ID {
            return Err(MiningJobError::AlgorithmMismatch);
        }
        if job.target_policy_id != SYNTHETIC_TARGET_POLICY_ID {
            return Err(MiningJobError::TargetPolicyMismatch);
        }
        if job.chain_domain != expected_context.chain_domain() {
            return Err(MiningJobError::ChainDomainMismatch);
        }
        if job.profile_domain != expected_context.profile_domain() {
            return Err(MiningJobError::ProfileDomainMismatch);
        }
        let subject =
            WorkSubject::from_canonical_body_bytes(expected_context, &job.canonical_body)?;
        if job.body_id != subject.body_id() {
            return Err(MiningJobError::BodyIdMismatch);
        }
        if job.body_sha256 != subject.body_digest() {
            return Err(MiningJobError::BodyDigestMismatch);
        }
        if job.parent_set_digest != subject.parent_set_digest() {
            return Err(MiningJobError::ParentSetMismatch);
        }
        if job.full_target != canonical_target(job.difficulty)? {
            return Err(MiningJobError::NonCanonicalFullTarget);
        }
        validate_lifetime(job.job_epoch, job.expires_at_epoch, current_epoch)?;
        validate_nonce_range(job.nonce_start, job.nonce_count)?;
        let canonical_bytes = job.canonical_bytes();
        let job_id = framed_hash(JOB_ID_DOMAIN, &[&canonical_bytes])?;
        Ok(VerifiedMiningJobV1 {
            job,
            canonical_bytes,
            job_id,
        })
    }
}

/// A mining job promoted after complete local context and binding validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedMiningJobV1 {
    job: MiningJobV1,
    canonical_bytes: Vec<u8>,
    job_id: Hash32,
}

impl VerifiedMiningJobV1 {
    /// Borrows the validated job envelope.
    #[must_use]
    pub const fn job(&self) -> &MiningJobV1 {
        &self.job
    }

    /// Borrows the exact canonical job bytes that were validated.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Returns the domain-separated identifier of the validated job bytes.
    #[must_use]
    pub const fn job_id(&self) -> Hash32 {
        self.job_id
    }

    /// Returns the exact validated chain/profile context.
    #[must_use]
    pub const fn context(&self) -> WorkContext {
        WorkContext::new(self.job.chain_domain, self.job.profile_domain)
    }
}

/// The sole two bounded worker-result kinds in version one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MiningResultKindV1 {
    /// The worker exhausted only its assigned range without a full proof.
    NoSolution,
    /// The worker found one candidate for independent full-target verification.
    ProofCandidate,
}

/// Canonical transport-neutral result for one exact mining assignment.
///
/// This value is never proof authority. A coordinator must match its job,
/// epoch, range, and proof bindings and independently verify any candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MiningWorkerResultV1 {
    job_id: Hash32,
    job_epoch: u64,
    nonce_start: u64,
    nonce_count: u64,
    kind: MiningResultKindV1,
    canonical_proof: Vec<u8>,
}

impl MiningWorkerResultV1 {
    /// Creates a bounded no-solution report for one validated assignment.
    #[must_use]
    pub const fn no_solution(job: &VerifiedMiningJobV1) -> Self {
        Self {
            job_id: job.job_id,
            job_epoch: job.job.job_epoch,
            nonce_start: job.job.nonce_start,
            nonce_count: job.job.nonce_count,
            kind: MiningResultKindV1::NoSolution,
            canonical_proof: Vec::new(),
        }
    }

    /// Creates a proof-candidate report for one validated assignment.
    ///
    /// # Errors
    ///
    /// Rejects proof bytes whose length differs from the frozen proof-v1 size.
    pub fn proof_candidate(
        job: &VerifiedMiningJobV1,
        canonical_proof: &[u8],
    ) -> Result<Self, MiningJobError> {
        if canonical_proof.len() != super::WORK_PROOF_BYTES {
            return Err(MiningJobError::InvalidCandidateProofLength);
        }
        Ok(Self {
            job_id: job.job_id,
            job_epoch: job.job.job_epoch,
            nonce_start: job.job.nonce_start,
            nonce_count: job.job.nonce_count,
            kind: MiningResultKindV1::ProofCandidate,
            canonical_proof: canonical_proof.to_vec(),
        })
    }

    /// Strictly decodes a bounded result without granting proof authority.
    ///
    /// # Errors
    ///
    /// Rejects oversized, truncated, wrongly framed, unknown-version, unknown
    /// kind, invalid range, or result-kind/proof-length mismatches.
    pub fn decode_unverified(
        bytes: &[u8],
    ) -> Result<UnverifiedMiningWorkerResultV1, MiningJobError> {
        if bytes.len() < MINING_RESULT_FIXED_BYTES || bytes.len() > MAX_MINING_RESULT_BYTES {
            return Err(MiningJobError::InvalidResultLength);
        }
        let mut decoder = Decoder::new(bytes, MiningJobError::InvalidResultLength);
        if decoder.array::<8>()? != RESULT_MAGIC {
            return Err(MiningJobError::InvalidResultMagic);
        }
        if decoder.u16()? != MINING_RESULT_VERSION {
            return Err(MiningJobError::UnsupportedResultVersion);
        }
        if decoder.u16()? != 0 {
            return Err(MiningJobError::InvalidResultFlags);
        }
        let job_id = decoder.hash32()?;
        let job_epoch = decoder.u64()?;
        let nonce_start = decoder.u64()?;
        let nonce_count = decoder.u64()?;
        validate_nonce_range(nonce_start, nonce_count)?;
        let kind = match decoder.u8()? {
            RESULT_KIND_NO_SOLUTION => MiningResultKindV1::NoSolution,
            RESULT_KIND_PROOF_CANDIDATE => MiningResultKindV1::ProofCandidate,
            _ => return Err(MiningJobError::UnknownResultKind),
        };
        if decoder.array::<RESULT_KIND_RESERVED_BYTES>()? != [0; RESULT_KIND_RESERVED_BYTES] {
            return Err(MiningJobError::InvalidResultFlags);
        }
        let proof_length =
            usize::try_from(decoder.u32()?).map_err(|_| MiningJobError::InvalidResultLength)?;
        let expected_length = match kind {
            MiningResultKindV1::NoSolution => 0,
            MiningResultKindV1::ProofCandidate => super::WORK_PROOF_BYTES,
        };
        if proof_length != expected_length {
            return Err(MiningJobError::InvalidResultShape);
        }
        let canonical_proof = decoder.take(proof_length)?.to_vec();
        decoder.finish()?;
        Ok(UnverifiedMiningWorkerResultV1(Self {
            job_id,
            job_epoch,
            nonce_start,
            nonce_count,
            kind,
            canonical_proof,
        }))
    }

    /// Returns the exact canonical result bytes.
    ///
    /// # Panics
    ///
    /// Panics only if the private proof-length invariant is violated internally;
    /// public constructors and decoding enforce the fixed protocol cap.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(MINING_RESULT_FIXED_BYTES + self.canonical_proof.len());
        bytes.extend_from_slice(&RESULT_MAGIC);
        bytes.extend_from_slice(&MINING_RESULT_VERSION.to_le_bytes());
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        bytes.extend_from_slice(&self.job_id);
        bytes.extend_from_slice(&self.job_epoch.to_le_bytes());
        bytes.extend_from_slice(&self.nonce_start.to_le_bytes());
        bytes.extend_from_slice(&self.nonce_count.to_le_bytes());
        bytes.push(match self.kind {
            MiningResultKindV1::NoSolution => RESULT_KIND_NO_SOLUTION,
            MiningResultKindV1::ProofCandidate => RESULT_KIND_PROOF_CANDIDATE,
        });
        bytes.extend_from_slice(&[0; RESULT_KIND_RESERVED_BYTES]);
        let proof_length = u32::try_from(self.canonical_proof.len())
            .expect("a validated proof length always fits u32");
        bytes.extend_from_slice(&proof_length.to_le_bytes());
        bytes.extend_from_slice(&self.canonical_proof);
        debug_assert!(bytes.len() <= MAX_MINING_RESULT_BYTES);
        bytes
    }

    /// Returns the exact job identifier echoed by the worker.
    #[must_use]
    pub const fn job_id(&self) -> Hash32 {
        self.job_id
    }

    /// Returns the logical job epoch echoed by the worker.
    #[must_use]
    pub const fn job_epoch(&self) -> u64 {
        self.job_epoch
    }

    /// Returns the first nonce echoed from the assignment.
    #[must_use]
    pub const fn nonce_start(&self) -> u64 {
        self.nonce_start
    }

    /// Returns the nonce count echoed from the assignment.
    #[must_use]
    pub const fn nonce_count(&self) -> u64 {
        self.nonce_count
    }

    /// Returns the exact nonce range echoed from the assignment.
    #[must_use]
    pub const fn nonce_range(&self) -> MiningNonceRangeV1 {
        MiningNonceRangeV1 {
            start: self.nonce_start,
            count: self.nonce_count,
        }
    }

    /// Returns the decoded result kind.
    #[must_use]
    pub const fn kind(&self) -> MiningResultKindV1 {
        self.kind
    }

    /// Borrows candidate proof bytes, or returns `None` for no solution.
    #[must_use]
    pub fn canonical_proof(&self) -> Option<&[u8]> {
        match self.kind {
            MiningResultKindV1::NoSolution => None,
            MiningResultKindV1::ProofCandidate => Some(&self.canonical_proof),
        }
    }
}

/// A structurally decoded worker result that grants no proof authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnverifiedMiningWorkerResultV1(MiningWorkerResultV1);

impl UnverifiedMiningWorkerResultV1 {
    /// Borrows the decoded result for coordinator-side contextual validation.
    #[must_use]
    pub const fn decoded(&self) -> &MiningWorkerResultV1 {
        &self.0
    }

    /// Consumes the wrapper without promoting the result to proof authority.
    #[must_use]
    pub fn into_decoded(self) -> MiningWorkerResultV1 {
        self.0
    }
}

/// Validates a job and searches only its assigned nonce range on the CPU backend.
///
/// Only exact range exhaustion becomes [`MiningResultKindV1::NoSolution`]. Any
/// body, policy, range, or backend failure remains an error.
///
/// # Errors
///
/// Returns a stable mining-job or nested work error for every failure other
/// than exact bounded search exhaustion.
pub fn execute_mining_job(
    job: &VerifiedMiningJobV1,
) -> Result<MiningWorkerResultV1, MiningJobError> {
    match mine_body_work(
        &SyntheticSha256,
        job.context(),
        job.job.canonical_body(),
        job.job.difficulty,
        job.job.nonce_start,
        job.job.nonce_count,
    ) {
        Ok(proof) => MiningWorkerResultV1::proof_candidate(job, proof.canonical_bytes()),
        Err(WorkError::MiningExhausted) => Ok(MiningWorkerResultV1::no_solution(job)),
        Err(error) => Err(MiningJobError::Work(error)),
    }
}

fn validate_lifetime(
    job_epoch: u64,
    expires_at_epoch: u64,
    current_epoch: u64,
) -> Result<(), MiningJobError> {
    let span = expires_at_epoch
        .checked_sub(job_epoch)
        .ok_or(MiningJobError::ExpiryBeforeJobEpoch)?;
    if span > MAX_MINING_JOB_EPOCH_SPAN {
        return Err(MiningJobError::EpochSpanTooLarge);
    }
    if current_epoch > expires_at_epoch {
        return Err(MiningJobError::JobExpired);
    }
    if current_epoch < job_epoch {
        return Err(MiningJobError::JobEpochMismatch);
    }
    Ok(())
}

fn validate_nonce_range(nonce_start: u64, nonce_count: u64) -> Result<(), MiningJobError> {
    if nonce_count == 0 || nonce_count > MAX_LOCAL_MINING_ATTEMPTS {
        return Err(MiningJobError::NonceCountOutOfBounds);
    }
    nonce_start
        .checked_add(
            nonce_count
                .checked_sub(1)
                .ok_or(MiningJobError::NonceCountOutOfBounds)?,
        )
        .ok_or(MiningJobError::NonceRangeOverflow)?;
    Ok(())
}

/// Structural, binding, policy, logical-expiry, and worker-result failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MiningJobError {
    /// Canonical job bytes violate the explicit job-size boundary.
    #[error("mining_job.invalid_job_length")]
    InvalidJobLength,
    /// The job magic is not recognized.
    #[error("mining_job.invalid_job_magic")]
    InvalidJobMagic,
    /// The job version is not supported.
    #[error("mining_job.unsupported_job_version")]
    UnsupportedJobVersion,
    /// Job flags or reserved bytes are nonzero.
    #[error("mining_job.invalid_job_flags")]
    InvalidJobFlags,
    /// The job names another work algorithm.
    #[error("mining_job.algorithm_mismatch")]
    AlgorithmMismatch,
    /// The job names another target-policy suite.
    #[error("mining_job.target_policy_mismatch")]
    TargetPolicyMismatch,
    /// The job belongs to another chain domain.
    #[error("mining_job.chain_domain_mismatch")]
    ChainDomainMismatch,
    /// The job belongs to another profile domain.
    #[error("mining_job.profile_domain_mismatch")]
    ProfileDomainMismatch,
    /// The declared body identifier differs from the canonical body.
    #[error("mining_job.body_id_mismatch")]
    BodyIdMismatch,
    /// The declared body digest differs from the exact canonical bytes.
    #[error("mining_job.body_digest_mismatch")]
    BodyDigestMismatch,
    /// The declared parent-set digest differs from the canonical parent set.
    #[error("mining_job.parent_set_mismatch")]
    ParentSetMismatch,
    /// The full admission target is not canonical for the difficulty.
    #[error("mining_job.non_canonical_full_target")]
    NonCanonicalFullTarget,
    /// Logical expiry precedes the job epoch.
    #[error("mining_job.expiry_before_job_epoch")]
    ExpiryBeforeJobEpoch,
    /// Logical lifetime exceeds the explicit epoch-span limit.
    #[error("mining_job.epoch_span_too_large")]
    EpochSpanTooLarge,
    /// The worker's current logical epoch precedes the job epoch.
    #[error("mining_job.job_epoch_mismatch")]
    JobEpochMismatch,
    /// The worker's current logical epoch is after job expiry.
    #[error("mining_job.job_expired")]
    JobExpired,
    /// Nonce count is zero or exceeds the existing mining-attempt bound.
    #[error("mining_job.nonce_count_out_of_bounds")]
    NonceCountOutOfBounds,
    /// The assigned inclusive nonce range overflows `u64`.
    #[error("mining_job.nonce_range_overflow")]
    NonceRangeOverflow,
    /// Canonical result bytes violate the explicit result-size boundary.
    #[error("mining_job.invalid_result_length")]
    InvalidResultLength,
    /// The result magic is not recognized.
    #[error("mining_job.invalid_result_magic")]
    InvalidResultMagic,
    /// The result version is not supported.
    #[error("mining_job.unsupported_result_version")]
    UnsupportedResultVersion,
    /// Result flags or reserved bytes are nonzero.
    #[error("mining_job.invalid_result_flags")]
    InvalidResultFlags,
    /// The result kind is not recognized.
    #[error("mining_job.unknown_result_kind")]
    UnknownResultKind,
    /// Result kind and proof length do not form a canonical pair.
    #[error("mining_job.invalid_result_shape")]
    InvalidResultShape,
    /// A candidate does not contain exactly one frozen proof-v1 envelope.
    #[error("mining_job.invalid_candidate_proof_length")]
    InvalidCandidateProofLength,
    /// The existing proof-of-work boundary rejected an operation.
    #[error(transparent)]
    Work(#[from] WorkError),
}

impl MiningJobError {
    /// Returns a stable machine-facing diagnostic code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidJobLength => "mining_job.invalid_job_length",
            Self::InvalidJobMagic => "mining_job.invalid_job_magic",
            Self::UnsupportedJobVersion => "mining_job.unsupported_job_version",
            Self::InvalidJobFlags => "mining_job.invalid_job_flags",
            Self::AlgorithmMismatch => "mining_job.algorithm_mismatch",
            Self::TargetPolicyMismatch => "mining_job.target_policy_mismatch",
            Self::ChainDomainMismatch => "mining_job.chain_domain_mismatch",
            Self::ProfileDomainMismatch => "mining_job.profile_domain_mismatch",
            Self::BodyIdMismatch => "mining_job.body_id_mismatch",
            Self::BodyDigestMismatch => "mining_job.body_digest_mismatch",
            Self::ParentSetMismatch => "mining_job.parent_set_mismatch",
            Self::NonCanonicalFullTarget => "mining_job.non_canonical_full_target",
            Self::ExpiryBeforeJobEpoch => "mining_job.expiry_before_job_epoch",
            Self::EpochSpanTooLarge => "mining_job.epoch_span_too_large",
            Self::JobEpochMismatch => "mining_job.job_epoch_mismatch",
            Self::JobExpired => "mining_job.job_expired",
            Self::NonceCountOutOfBounds => "mining_job.nonce_count_out_of_bounds",
            Self::NonceRangeOverflow => "mining_job.nonce_range_overflow",
            Self::InvalidResultLength => "mining_job.invalid_result_length",
            Self::InvalidResultMagic => "mining_job.invalid_result_magic",
            Self::UnsupportedResultVersion => "mining_job.unsupported_result_version",
            Self::InvalidResultFlags => "mining_job.invalid_result_flags",
            Self::UnknownResultKind => "mining_job.unknown_result_kind",
            Self::InvalidResultShape => "mining_job.invalid_result_shape",
            Self::InvalidCandidateProofLength => "mining_job.invalid_candidate_proof_length",
            Self::Work(error) => error.code(),
        }
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
    truncated: MiningJobError,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8], truncated: MiningJobError) -> Self {
        Self {
            bytes,
            offset: 0,
            truncated,
        }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], MiningJobError> {
        let end = self.offset.checked_add(length).ok_or(self.truncated)?;
        let value = self.bytes.get(self.offset..end).ok_or(self.truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], MiningJobError> {
        self.take(N)?.try_into().map_err(|_| self.truncated)
    }

    fn hash32(&mut self) -> Result<Hash32, MiningJobError> {
        self.array()
    }

    fn u8(&mut self) -> Result<u8, MiningJobError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, MiningJobError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, MiningJobError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, MiningJobError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    const fn finish(self) -> Result<(), MiningJobError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(self.truncated)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use silk_gate2::{
        BodyNamespaceKind, BodyNamespaceV1, BoundedVec, CanonicalEncode, ParentKind, ParentRefV1,
        SortedUniqueVec,
    };

    const ALGORITHM_OFFSET: usize = 12;
    const POLICY_OFFSET: usize = ALGORITHM_OFFSET + 32;
    const CHAIN_OFFSET: usize = POLICY_OFFSET + 32;
    const PROFILE_OFFSET: usize = CHAIN_OFFSET + 32;
    const BODY_ID_OFFSET: usize = PROFILE_OFFSET + 32;
    const BODY_DIGEST_OFFSET: usize = BODY_ID_OFFSET + 32;
    const PARENT_SET_OFFSET: usize = BODY_DIGEST_OFFSET + 32;
    const DIFFICULTY_OFFSET: usize = PARENT_SET_OFFSET + 32;
    const TARGET_OFFSET: usize = DIFFICULTY_OFFSET + 8;
    const EPOCH_OFFSET: usize = TARGET_OFFSET + 8;
    const EXPIRY_OFFSET: usize = EPOCH_OFFSET + 8;
    const NONCE_START_OFFSET: usize = EXPIRY_OFFSET + 8;
    const NONCE_COUNT_OFFSET: usize = NONCE_START_OFFSET + 8;
    const BODY_LENGTH_OFFSET: usize = NONCE_COUNT_OFFSET + 8;
    const BODY_OFFSET: usize = BODY_LENGTH_OFFSET + 4;
    const RESULT_KIND_OFFSET: usize = 12 + 32 + (3 * 8);
    const RESULT_PROOF_LENGTH_OFFSET: usize = RESULT_KIND_OFFSET + 1 + RESULT_KIND_RESERVED_BYTES;

    fn hash(byte: u8) -> Hash32 {
        [byte; 32]
    }

    fn context() -> WorkContext {
        WorkContext::new(hash(0x11), hash(0x22))
    }

    fn body() -> Vec<u8> {
        let parents = vec![ParentRefV1 {
            parent_kind: ParentKind::Body,
            parent_id: hash(0x33),
            profile_domain: context().profile_domain(),
            lineage_fence_id: None,
        }];
        silk_gate2::OrderedBodyV2 {
            body_id: hash(0x44),
            namespace: BodyNamespaceV1 {
                namespace_kind: BodyNamespaceKind::Unfenced,
                profile_domain: context().profile_domain(),
                active_fence_id: None,
                parents: SortedUniqueVec::new(parents),
            },
            envelopes: BoundedVec::new(Vec::new()).expect("bounded empty body"),
        }
        .canonical_bytes()
        .expect("canonical body")
    }

    fn range(start: u64, count: u64) -> MiningNonceRangeV1 {
        MiningNonceRangeV1::new(start, count).expect("valid range")
    }

    fn job(start: u64, count: u64) -> MiningJobV1 {
        MiningJobV1::new(context(), &body(), 32, 7, 9, range(start, count)).expect("valid job")
    }

    fn validated(start: u64, count: u64) -> VerifiedMiningJobV1 {
        let bytes = job(start, count).canonical_bytes();
        MiningJobV1::decode_unverified(&bytes)
            .expect("decode")
            .validate(context(), 7)
            .expect("validate")
    }

    fn mutate(bytes: &[u8], offset: usize) -> Vec<u8> {
        let mut changed = bytes.to_vec();
        changed[offset] ^= 1;
        changed
    }

    #[test]
    fn canonical_job_round_trips_and_promotes_every_binding() {
        let original = job(100, 200);
        let bytes = original.canonical_bytes();
        assert_eq!(MINING_JOB_FIXED_BYTES, 288);
        assert_eq!(bytes.len(), MINING_JOB_FIXED_BYTES + body().len());
        assert!(bytes.len() <= MAX_MINING_JOB_BYTES);

        let unverified = MiningJobV1::decode_unverified(&bytes).expect("decode");
        assert_eq!(unverified.decoded(), &original);
        let promoted = unverified.validate(context(), 7).expect("promote");
        assert_eq!(promoted.job(), &original);
        assert_eq!(promoted.canonical_bytes(), bytes);
        assert_eq!(promoted.job_id(), original.job_id().expect("job id"));
        assert_eq!(promoted.job().algorithm_id(), SYNTHETIC_SHA256_ALGORITHM_ID);
        assert_eq!(
            promoted.job().target_policy_id(),
            SYNTHETIC_TARGET_POLICY_ID
        );
        assert_eq!(promoted.job().chain_domain(), context().chain_domain());
        assert_eq!(promoted.job().profile_domain(), context().profile_domain());
        assert_eq!(promoted.job().difficulty(), 32);
        assert_eq!(promoted.job().full_target(), canonical_target(32).unwrap());
        assert_eq!(promoted.job().job_epoch(), 7);
        assert_eq!(promoted.job().expires_at_epoch(), 9);
        assert_eq!(promoted.job().nonce_start(), 100);
        assert_eq!(promoted.job().nonce_count(), 200);
    }

    #[test]
    fn promotion_rejects_tampered_context_body_parent_policy_and_target() {
        let bytes = job(100, 200).canonical_bytes();
        let cases = [
            (ALGORITHM_OFFSET, MiningJobError::AlgorithmMismatch),
            (POLICY_OFFSET, MiningJobError::TargetPolicyMismatch),
            (CHAIN_OFFSET, MiningJobError::ChainDomainMismatch),
            (PROFILE_OFFSET, MiningJobError::ProfileDomainMismatch),
            (BODY_ID_OFFSET, MiningJobError::BodyIdMismatch),
            (BODY_DIGEST_OFFSET, MiningJobError::BodyDigestMismatch),
            (PARENT_SET_OFFSET, MiningJobError::ParentSetMismatch),
            (TARGET_OFFSET, MiningJobError::NonCanonicalFullTarget),
        ];
        for (offset, expected) in cases {
            let error = MiningJobV1::decode_unverified(&mutate(&bytes, offset))
                .expect("structural decode")
                .validate(context(), 7)
                .expect_err("tampering rejects");
            assert_eq!(error, expected);
            assert_eq!(error.code(), expected.code());
        }

        let changed_body_id = mutate(&bytes, BODY_OFFSET + 1);
        assert_eq!(
            MiningJobV1::decode_unverified(&changed_body_id)
                .unwrap()
                .validate(context(), 7),
            Err(MiningJobError::BodyIdMismatch)
        );
    }

    #[test]
    fn logical_epoch_and_nonce_bounds_fail_closed() {
        let bytes = job(100, 200).canonical_bytes();
        assert_eq!(
            MiningJobV1::decode_unverified(&bytes)
                .unwrap()
                .validate(context(), 6),
            Err(MiningJobError::JobEpochMismatch)
        );
        assert!(
            MiningJobV1::decode_unverified(&bytes)
                .unwrap()
                .validate(context(), 8)
                .is_ok()
        );
        assert_eq!(
            MiningJobV1::decode_unverified(&bytes)
                .unwrap()
                .validate(context(), 10),
            Err(MiningJobError::JobExpired)
        );

        let mut inverted = bytes.clone();
        inverted[EXPIRY_OFFSET..NONCE_START_OFFSET].copy_from_slice(&6_u64.to_le_bytes());
        assert_eq!(
            MiningJobV1::decode_unverified(&inverted)
                .unwrap()
                .validate(context(), 7),
            Err(MiningJobError::ExpiryBeforeJobEpoch)
        );

        let mut excessive = bytes;
        let expiry = 7 + MAX_MINING_JOB_EPOCH_SPAN + 1;
        excessive[EXPIRY_OFFSET..NONCE_START_OFFSET].copy_from_slice(&expiry.to_le_bytes());
        assert_eq!(
            MiningJobV1::decode_unverified(&excessive)
                .unwrap()
                .validate(context(), 7),
            Err(MiningJobError::EpochSpanTooLarge)
        );

        assert_eq!(
            MiningNonceRangeV1::new(0, 0),
            Err(MiningJobError::NonceCountOutOfBounds)
        );
        assert_eq!(
            MiningNonceRangeV1::new(u64::MAX, 2),
            Err(MiningJobError::NonceRangeOverflow)
        );
        let final_nonce = MiningNonceRangeV1::new(u64::MAX, 1).unwrap();
        assert!(final_nonce.contains(u64::MAX));
        assert!(!final_nonce.contains(u64::MAX - 1));
    }

    #[test]
    fn job_id_commits_to_exact_body_epoch_expiry_and_range() {
        let baseline = job(100, 200).job_id().unwrap();
        let changed_range = job(101, 200).job_id().unwrap();
        let changed_count = job(100, 201).job_id().unwrap();
        let changed_epoch = MiningJobV1::new(context(), &body(), 32, 8, 9, range(100, 200))
            .unwrap()
            .job_id()
            .unwrap();
        let changed_expiry = MiningJobV1::new(context(), &body(), 32, 7, 10, range(100, 200))
            .unwrap()
            .job_id()
            .unwrap();
        let mut changed_body = body();
        changed_body[1] ^= 1;
        let changed_body = MiningJobV1::new(context(), &changed_body, 32, 7, 9, range(100, 200))
            .unwrap()
            .job_id()
            .unwrap();
        let ids = [
            baseline,
            changed_range,
            changed_count,
            changed_epoch,
            changed_expiry,
            changed_body,
        ];
        for (left, left_id) in ids.iter().enumerate() {
            for right_id in &ids[left + 1..] {
                assert_ne!(left_id, right_id);
            }
        }
    }

    #[test]
    fn result_variants_round_trip_with_exact_proof_shape() {
        let assignment = validated(0, 1_000);
        let no_solution = MiningWorkerResultV1::no_solution(&assignment);
        let no_solution_bytes = no_solution.canonical_bytes();
        assert_eq!(MINING_RESULT_FIXED_BYTES, 76);
        assert_eq!(no_solution_bytes.len(), MINING_RESULT_FIXED_BYTES);
        assert_eq!(
            MiningWorkerResultV1::decode_unverified(&no_solution_bytes)
                .unwrap()
                .into_decoded(),
            no_solution
        );

        let proof = mine_body_work(
            &SyntheticSha256,
            context(),
            assignment.job().canonical_body(),
            assignment.job().difficulty(),
            assignment.job().nonce_start(),
            assignment.job().nonce_count(),
        )
        .expect("bounded proof");
        let candidate = MiningWorkerResultV1::proof_candidate(&assignment, proof.canonical_bytes())
            .expect("candidate");
        let candidate_bytes = candidate.canonical_bytes();
        assert_eq!(candidate_bytes.len(), MAX_MINING_RESULT_BYTES);
        let decoded = MiningWorkerResultV1::decode_unverified(&candidate_bytes)
            .unwrap()
            .into_decoded();
        assert_eq!(decoded, candidate);
        assert_eq!(decoded.kind(), MiningResultKindV1::ProofCandidate);
        assert_eq!(decoded.job_id(), assignment.job_id());
        assert_eq!(decoded.job_epoch(), assignment.job().job_epoch());
        assert_eq!(decoded.nonce_start(), assignment.job().nonce_start());
        assert_eq!(decoded.nonce_count(), assignment.job().nonce_count());
        assert_eq!(decoded.nonce_range(), assignment.job().nonce_range());
        assert_eq!(decoded.canonical_proof(), Some(proof.canonical_bytes()));

        assert_eq!(
            MiningWorkerResultV1::proof_candidate(&assignment, &proof.canonical_bytes()[..1]),
            Err(MiningJobError::InvalidCandidateProofLength)
        );
        let mut wrong_shape = no_solution_bytes;
        wrong_shape[RESULT_KIND_OFFSET] = RESULT_KIND_PROOF_CANDIDATE;
        assert_eq!(
            MiningWorkerResultV1::decode_unverified(&wrong_shape),
            Err(MiningJobError::InvalidResultShape)
        );
        let mut unknown_kind = candidate_bytes;
        unknown_kind[RESULT_KIND_OFFSET] = 2;
        assert_eq!(
            MiningWorkerResultV1::decode_unverified(&unknown_kind),
            Err(MiningJobError::UnknownResultKind)
        );
    }

    #[test]
    fn worker_search_is_confined_to_the_exact_assigned_range() {
        let body = body();
        let winning = mine_body_work(&SyntheticSha256, context(), &body, 32, 0, 10_000)
            .expect("deterministic winning nonce");
        let winning_nonce = winning.envelope().nonce();
        let invalid_nonce = (0..10_000)
            .find(|nonce| {
                mine_body_work(&SyntheticSha256, context(), &body, 32, *nonce, 1)
                    == Err(WorkError::MiningExhausted)
            })
            .expect("deterministic invalid nonce");

        let exhausted = validated(invalid_nonce, 1);
        let no_solution = execute_mining_job(&exhausted).expect("exhaustion is a result");
        assert_eq!(no_solution.kind(), MiningResultKindV1::NoSolution);
        assert_eq!(no_solution.canonical_proof(), None);

        let assigned_winner = validated(winning_nonce, 1);
        let candidate = execute_mining_job(&assigned_winner).expect("assigned winner");
        assert_eq!(candidate.kind(), MiningResultKindV1::ProofCandidate);
        let proof = super::super::WorkProofEnvelopeV1::decode_unverified(
            candidate.canonical_proof().expect("candidate proof"),
        )
        .expect("decode proof");
        assert_eq!(proof.decoded().nonce(), winning_nonce);
    }

    #[test]
    fn decoders_reject_versions_flags_lengths_and_trailing_bytes() {
        let job_bytes = job(0, 1).canonical_bytes();
        assert_eq!(
            MiningJobV1::decode_unverified(&job_bytes[..MINING_JOB_FIXED_BYTES - 1]),
            Err(MiningJobError::InvalidJobLength)
        );
        assert_eq!(
            MiningJobV1::decode_unverified(&mutate(&job_bytes, 8)),
            Err(MiningJobError::UnsupportedJobVersion)
        );
        assert_eq!(
            MiningJobV1::decode_unverified(&mutate(&job_bytes, 10)),
            Err(MiningJobError::InvalidJobFlags)
        );
        let mut trailing_job = job_bytes;
        trailing_job.push(0);
        assert_eq!(
            MiningJobV1::decode_unverified(&trailing_job),
            Err(MiningJobError::InvalidJobLength)
        );

        let result_bytes = MiningWorkerResultV1::no_solution(&validated(0, 1)).canonical_bytes();
        assert_eq!(
            MiningWorkerResultV1::decode_unverified(&result_bytes[..result_bytes.len() - 1]),
            Err(MiningJobError::InvalidResultLength)
        );
        assert_eq!(
            MiningWorkerResultV1::decode_unverified(&mutate(&result_bytes, 8)),
            Err(MiningJobError::UnsupportedResultVersion)
        );
        assert_eq!(
            MiningWorkerResultV1::decode_unverified(&mutate(&result_bytes, 10)),
            Err(MiningJobError::InvalidResultFlags)
        );
        let mut trailing_result = result_bytes.clone();
        trailing_result.push(0);
        assert_eq!(
            MiningWorkerResultV1::decode_unverified(&trailing_result),
            Err(MiningJobError::InvalidResultLength)
        );
        let mut nonzero_proof_length = result_bytes;
        nonzero_proof_length[RESULT_PROOF_LENGTH_OFFSET..MINING_RESULT_FIXED_BYTES]
            .copy_from_slice(&1_u32.to_le_bytes());
        assert_eq!(
            MiningWorkerResultV1::decode_unverified(&nonzero_proof_length),
            Err(MiningJobError::InvalidResultShape)
        );
    }
}
