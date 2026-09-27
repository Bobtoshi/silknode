//! Transport-neutral bounded `RandomX` v2 mining jobs and untrusted results.

use crate::{
    MAX_LOCAL_MINING_ATTEMPTS, RANDOMX_V2_PROOF_BYTES, RANDOMX_V2_SUITE_ID,
    RANDOMX_V2_SUITE_VERSION, RANDOMX_V2_TARGET_POLICY_ID, RandomXV2Algorithm,
    RandomXV2ProofEnvelope, RandomXV2WorkError, RandomXWorkSubjectV2, Uint256,
    VerifiedRandomXV2Work, mine_randomx_v2, randomx_v2_work_key_id, verify_randomx_v2,
};
use sha2::{Digest, Sha256};
use silk_gate2::{Hash32, MAX_BODY_BYTES};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const JOB_MAGIC: [u8; 8] = *b"SLKRXJ2\0";
const RESULT_MAGIC: [u8; 8] = *b"SLKRXR2\0";
const JOB_ID_DOMAIN: &[u8] = b"SilkNode/Mining/RandomX-v2.0.1/JobId/v2";
const JOB_HASH_FIELDS: usize = 14;
const JOB_U64_FIELDS: usize = 8;
const RESULT_U64_FIELDS: usize = 3;
const RESULT_NO_SOLUTION: u8 = 0;
const RESULT_CANDIDATE: u8 = 1;
const MAX_JOB_EPOCH_SPAN: u64 = 1_024;
const JOB_FIXED_BYTES: usize = 8 + 2 + 2 + 4 + JOB_HASH_FIELDS * 32 + JOB_U64_FIELDS * 8 + 4;
const RESULT_FIXED_BYTES: usize = 8 + 2 + 2 + 32 + RESULT_U64_FIELDS * 8 + 1 + 3 + 4;

/// Canonical `RandomX` mining-job wire version.
pub const RANDOMX_MINING_JOB_VERSION: u16 = 2;
/// Canonical `RandomX` mining-result wire version.
pub const RANDOMX_MINING_RESULT_VERSION: u16 = 2;
/// Maximum simultaneously registered assignments in the bounded coordinator.
pub const MAX_RANDOMX_MINING_JOBS: usize = 8;
/// Maximum canonical `RandomX` job size.
pub const MAX_RANDOMX_MINING_JOB_BYTES: usize = JOB_FIXED_BYTES + MAX_BODY_BYTES;
/// Maximum canonical `RandomX` result size.
pub const MAX_RANDOMX_MINING_RESULT_BYTES: usize = RESULT_FIXED_BYTES + RANDOMX_V2_PROOF_BYTES;

/// One canonical `RandomX` v2 assignment for an exact non-overlapping nonce range.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RandomXMiningJobV2 {
    suite_id: Hash32,
    suite_version: u16,
    target_policy_id: Hash32,
    chain_domain: Hash32,
    profile_domain: Hash32,
    vertex_id: Hash32,
    body_id: Hash32,
    body_digest: Hash32,
    parent_set_digest: Hash32,
    daa_policy_id: Hash32,
    difficulty: Uint256,
    target: Uint256,
    work_key_id: Hash32,
    seed_commitment: Hash32,
    key_material: Hash32,
    logical_time: u64,
    epoch: u64,
    key_epoch: u64,
    seed_epoch: u64,
    job_epoch: u64,
    expires_at_epoch: u64,
    nonce_start: u64,
    nonce_count: u64,
    canonical_body: Vec<u8>,
}

impl RandomXMiningJobV2 {
    /// Construct one job from receiver-derived consensus state.
    ///
    /// # Errors
    ///
    /// Rejects a body/key mismatch, invalid lifetime, or invalid nonce range.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject: &RandomXWorkSubjectV2,
        canonical_body: &[u8],
        key_material: Hash32,
        job_epoch: u64,
        expires_at_epoch: u64,
        nonce_start: u64,
        nonce_count: u64,
    ) -> Result<Self, RandomXMiningJobError> {
        validate_body(subject, canonical_body)?;
        if randomx_v2_work_key_id(key_material) != subject.work_key_id() {
            return Err(RandomXMiningJobError::WorkKeyMismatch);
        }
        validate_lifetime(job_epoch, expires_at_epoch, job_epoch)?;
        validate_range(nonce_start, nonce_count)?;
        Ok(Self {
            suite_id: RANDOMX_V2_SUITE_ID,
            suite_version: RANDOMX_V2_SUITE_VERSION,
            target_policy_id: subject.target_policy_id(),
            chain_domain: subject.chain_domain(),
            profile_domain: subject.profile_domain(),
            vertex_id: subject.vertex_id(),
            body_id: subject.body_id(),
            body_digest: subject.body_digest(),
            parent_set_digest: subject.parent_set_digest(),
            daa_policy_id: subject.daa_policy_id(),
            difficulty: subject.difficulty(),
            target: subject.target(),
            work_key_id: subject.work_key_id(),
            seed_commitment: subject.seed_commitment(),
            key_material,
            logical_time: subject.logical_time(),
            epoch: subject.epoch(),
            key_epoch: subject.key_epoch(),
            seed_epoch: subject.seed_epoch(),
            job_epoch,
            expires_at_epoch,
            nonce_start,
            nonce_count,
            canonical_body: canonical_body.to_vec(),
        })
    }

    /// Decode bounded job bytes without granting mining or consensus authority.
    ///
    /// # Errors
    ///
    /// Rejects oversized, truncated, unknown-version, or malformed bytes.
    pub fn decode_unverified(
        bytes: &[u8],
    ) -> Result<UnverifiedRandomXMiningJobV2, RandomXMiningJobError> {
        if bytes.len() < JOB_FIXED_BYTES || bytes.len() > MAX_RANDOMX_MINING_JOB_BYTES {
            return Err(RandomXMiningJobError::InvalidJobLength);
        }
        let mut decoder = Decoder::new(bytes, RandomXMiningJobError::InvalidJobLength);
        if decoder.array::<8>()? != JOB_MAGIC {
            return Err(RandomXMiningJobError::InvalidJobMagic);
        }
        if decoder.u16()? != RANDOMX_MINING_JOB_VERSION {
            return Err(RandomXMiningJobError::UnsupportedJobVersion);
        }
        let suite_version = decoder.u16()?;
        if decoder.u32()? != 0 {
            return Err(RandomXMiningJobError::InvalidJobFlags);
        }
        let job = Self {
            suite_id: decoder.hash32()?,
            suite_version,
            target_policy_id: decoder.hash32()?,
            chain_domain: decoder.hash32()?,
            profile_domain: decoder.hash32()?,
            vertex_id: decoder.hash32()?,
            body_id: decoder.hash32()?,
            body_digest: decoder.hash32()?,
            parent_set_digest: decoder.hash32()?,
            daa_policy_id: decoder.hash32()?,
            difficulty: Uint256::from_be_bytes(decoder.hash32()?),
            target: Uint256::from_be_bytes(decoder.hash32()?),
            work_key_id: decoder.hash32()?,
            seed_commitment: decoder.hash32()?,
            key_material: decoder.hash32()?,
            logical_time: decoder.u64()?,
            epoch: decoder.u64()?,
            key_epoch: decoder.u64()?,
            seed_epoch: decoder.u64()?,
            job_epoch: decoder.u64()?,
            expires_at_epoch: decoder.u64()?,
            nonce_start: decoder.u64()?,
            nonce_count: decoder.u64()?,
            canonical_body: {
                let length = usize::try_from(decoder.u32()?)
                    .map_err(|_| RandomXMiningJobError::InvalidJobLength)?;
                if length == 0 || length > MAX_BODY_BYTES {
                    return Err(RandomXMiningJobError::InvalidJobLength);
                }
                decoder.take(length)?.to_vec()
            },
        };
        decoder.finish()?;
        validate_lifetime(job.job_epoch, job.expires_at_epoch, job.job_epoch)?;
        validate_range(job.nonce_start, job.nonce_count)?;
        Ok(UnverifiedRandomXMiningJobV2(job))
    }

    /// Return exact canonical job bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(JOB_FIXED_BYTES + self.canonical_body.len());
        bytes.extend_from_slice(&JOB_MAGIC);
        bytes.extend_from_slice(&RANDOMX_MINING_JOB_VERSION.to_le_bytes());
        bytes.extend_from_slice(&self.suite_version.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        for hash in [
            self.suite_id,
            self.target_policy_id,
            self.chain_domain,
            self.profile_domain,
            self.vertex_id,
            self.body_id,
            self.body_digest,
            self.parent_set_digest,
            self.daa_policy_id,
            self.difficulty.to_be_bytes(),
            self.target.to_be_bytes(),
            self.work_key_id,
            self.seed_commitment,
            self.key_material,
        ] {
            bytes.extend_from_slice(&hash);
        }
        for value in [
            self.logical_time,
            self.epoch,
            self.key_epoch,
            self.seed_epoch,
            self.job_epoch,
            self.expires_at_epoch,
            self.nonce_start,
            self.nonce_count,
        ] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.extend_from_slice(
            &u32::try_from(self.canonical_body.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&self.canonical_body);
        bytes
    }

    /// Derive the exact domain-separated identifier of this job.
    #[must_use]
    pub fn job_id(&self) -> Hash32 {
        framed_sha256(JOB_ID_DOMAIN, &[&self.canonical_bytes()])
    }
    /// Return the assigned nonce start.
    #[must_use]
    pub const fn nonce_start(&self) -> u64 {
        self.nonce_start
    }
    /// Return the assigned nonce count.
    #[must_use]
    pub const fn nonce_count(&self) -> u64 {
        self.nonce_count
    }
    /// Return the job issue epoch.
    #[must_use]
    pub const fn job_epoch(&self) -> u64 {
        self.job_epoch
    }
    /// Return the inclusive expiry epoch.
    #[must_use]
    pub const fn expires_at_epoch(&self) -> u64 {
        self.expires_at_epoch
    }
    /// Return exact body bytes bound by the job.
    #[must_use]
    pub fn canonical_body(&self) -> &[u8] {
        &self.canonical_body
    }
}

/// A structurally decoded job with no authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnverifiedRandomXMiningJobV2(RandomXMiningJobV2);

impl UnverifiedRandomXMiningJobV2 {
    /// Borrow untrusted job fields for receiver-local reconstruction only.
    #[must_use]
    pub const fn decoded(&self) -> &RandomXMiningJobV2 {
        &self.0
    }

    /// Validate all fields against independently reconstructed state.
    ///
    /// # Errors
    ///
    /// Rejects every context, suite, key, body, target, time, and range mismatch.
    pub fn validate(
        self,
        expected: &RandomXWorkSubjectV2,
        expected_body: &[u8],
        expected_key_material: Hash32,
        current_job_epoch: u64,
    ) -> Result<VerifiedRandomXMiningJobV2, RandomXMiningJobError> {
        let job = self.0;
        validate_job_claims(&job, expected, expected_body, expected_key_material)?;
        validate_lifetime(job.job_epoch, job.expires_at_epoch, current_job_epoch)?;
        let canonical_bytes = job.canonical_bytes();
        let job_id = framed_sha256(JOB_ID_DOMAIN, &[&canonical_bytes]);
        Ok(VerifiedRandomXMiningJobV2 {
            subject: expected.clone(),
            job,
            canonical_bytes,
            job_id,
        })
    }
}

/// A mining job promoted against receiver-derived state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRandomXMiningJobV2 {
    subject: RandomXWorkSubjectV2,
    job: RandomXMiningJobV2,
    canonical_bytes: Vec<u8>,
    job_id: Hash32,
}

impl VerifiedRandomXMiningJobV2 {
    /// Borrow the validated assignment.
    #[must_use]
    pub const fn job(&self) -> &RandomXMiningJobV2 {
        &self.job
    }
    /// Borrow the independently reconstructed work subject.
    #[must_use]
    pub const fn subject(&self) -> &RandomXWorkSubjectV2 {
        &self.subject
    }
    /// Return exact validated job bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
    /// Return the exact job identifier.
    #[must_use]
    pub const fn job_id(&self) -> Hash32 {
        self.job_id
    }
}

/// Result kinds that carry no authority until coordinator verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RandomXMiningResultKindV2 {
    /// The worker reports exact assigned-range exhaustion.
    NoSolution,
    /// The worker reports one proof candidate for full independent verification.
    ProofCandidate,
}

/// Canonical untrusted result for one exact `RandomX` assignment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RandomXMiningResultV2 {
    job_id: Hash32,
    job_epoch: u64,
    nonce_start: u64,
    nonce_count: u64,
    kind: RandomXMiningResultKindV2,
    proof: Vec<u8>,
}

impl RandomXMiningResultV2 {
    /// Construct an exact no-solution result.
    #[must_use]
    pub const fn no_solution(job: &VerifiedRandomXMiningJobV2) -> Self {
        Self {
            job_id: job.job_id,
            job_epoch: job.job.job_epoch,
            nonce_start: job.job.nonce_start,
            nonce_count: job.job.nonce_count,
            kind: RandomXMiningResultKindV2::NoSolution,
            proof: Vec::new(),
        }
    }

    /// Construct one untrusted proof-candidate result.
    ///
    /// # Errors
    ///
    /// Rejects proof bytes outside the exact `RandomX` v2 proof size.
    pub fn proof_candidate(
        job: &VerifiedRandomXMiningJobV2,
        proof: &[u8],
    ) -> Result<Self, RandomXMiningJobError> {
        if proof.len() != RANDOMX_V2_PROOF_BYTES {
            return Err(RandomXMiningJobError::InvalidCandidateProofLength);
        }
        Ok(Self {
            job_id: job.job_id,
            job_epoch: job.job.job_epoch,
            nonce_start: job.job.nonce_start,
            nonce_count: job.job.nonce_count,
            kind: RandomXMiningResultKindV2::ProofCandidate,
            proof: proof.to_vec(),
        })
    }

    /// Decode bounded result bytes without granting proof authority.
    ///
    /// # Errors
    ///
    /// Rejects wrong framing, version, flags, range, kind, size, or trailing bytes.
    pub fn decode_unverified(
        bytes: &[u8],
    ) -> Result<UnverifiedRandomXMiningResultV2, RandomXMiningJobError> {
        if bytes.len() < RESULT_FIXED_BYTES || bytes.len() > MAX_RANDOMX_MINING_RESULT_BYTES {
            return Err(RandomXMiningJobError::InvalidResultLength);
        }
        let mut decoder = Decoder::new(bytes, RandomXMiningJobError::InvalidResultLength);
        if decoder.array::<8>()? != RESULT_MAGIC {
            return Err(RandomXMiningJobError::InvalidResultMagic);
        }
        if decoder.u16()? != RANDOMX_MINING_RESULT_VERSION {
            return Err(RandomXMiningJobError::UnsupportedResultVersion);
        }
        if decoder.u16()? != 0 {
            return Err(RandomXMiningJobError::InvalidResultFlags);
        }
        let job_id = decoder.hash32()?;
        let job_epoch = decoder.u64()?;
        let nonce_start = decoder.u64()?;
        let nonce_count = decoder.u64()?;
        validate_range(nonce_start, nonce_count)?;
        let kind = match decoder.u8()? {
            RESULT_NO_SOLUTION => RandomXMiningResultKindV2::NoSolution,
            RESULT_CANDIDATE => RandomXMiningResultKindV2::ProofCandidate,
            _ => return Err(RandomXMiningJobError::UnknownResultKind),
        };
        if decoder.array::<3>()? != [0; 3] {
            return Err(RandomXMiningJobError::InvalidResultFlags);
        }
        let proof_length = usize::try_from(decoder.u32()?)
            .map_err(|_| RandomXMiningJobError::InvalidResultLength)?;
        let expected = match kind {
            RandomXMiningResultKindV2::NoSolution => 0,
            RandomXMiningResultKindV2::ProofCandidate => RANDOMX_V2_PROOF_BYTES,
        };
        if proof_length != expected {
            return Err(RandomXMiningJobError::InvalidResultShape);
        }
        let proof = decoder.take(proof_length)?.to_vec();
        decoder.finish()?;
        Ok(UnverifiedRandomXMiningResultV2(Self {
            job_id,
            job_epoch,
            nonce_start,
            nonce_count,
            kind,
            proof,
        }))
    }

    /// Return exact canonical result bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(RESULT_FIXED_BYTES + self.proof.len());
        bytes.extend_from_slice(&RESULT_MAGIC);
        bytes.extend_from_slice(&RANDOMX_MINING_RESULT_VERSION.to_le_bytes());
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        bytes.extend_from_slice(&self.job_id);
        bytes.extend_from_slice(&self.job_epoch.to_le_bytes());
        bytes.extend_from_slice(&self.nonce_start.to_le_bytes());
        bytes.extend_from_slice(&self.nonce_count.to_le_bytes());
        bytes.push(match self.kind {
            RandomXMiningResultKindV2::NoSolution => RESULT_NO_SOLUTION,
            RandomXMiningResultKindV2::ProofCandidate => RESULT_CANDIDATE,
        });
        bytes.extend_from_slice(&[0; 3]);
        bytes.extend_from_slice(
            &u32::try_from(self.proof.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&self.proof);
        bytes
    }

    /// Return the echoed job identifier.
    #[must_use]
    pub const fn job_id(&self) -> Hash32 {
        self.job_id
    }
}

/// A structurally decoded result with no proof authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnverifiedRandomXMiningResultV2(RandomXMiningResultV2);

impl UnverifiedRandomXMiningResultV2 {
    /// Borrow untrusted result fields for dispatch only.
    #[must_use]
    pub const fn decoded(&self) -> &RandomXMiningResultV2 {
        &self.0
    }
}

/// A coordinator-verified result outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AcceptedRandomXMiningResultV2 {
    /// Exact assigned range exhaustion, carrying no proof authority.
    NoSolution,
    /// A candidate independently rehashed and checked against the full target.
    Candidate(Box<VerifiedRandomXV2Work>),
}

/// Execute only the range carried by one verified job.
///
/// # Errors
///
/// Returns bounded job or `RandomX` failures; only exact exhaustion is a no-solution result.
pub fn execute_randomx_mining_job_v2(
    job: &VerifiedRandomXMiningJobV2,
) -> Result<RandomXMiningResultV2, RandomXMiningJobError> {
    let mut algorithm = RandomXV2Algorithm::new(job.job.key_material)?;
    match mine_randomx_v2(
        &mut algorithm,
        &job.subject,
        job.job.nonce_start,
        job.job.nonce_count,
    ) {
        Ok(proof) => RandomXMiningResultV2::proof_candidate(job, proof.canonical_bytes()),
        Err(RandomXV2WorkError::MiningExhausted) => Ok(RandomXMiningResultV2::no_solution(job)),
        Err(error) => Err(error.into()),
    }
}

/// Independently validate one result against its exact receiver-approved job.
///
/// # Errors
///
/// Rejects stale, wrong-job, wrong-range, malformed, tampered, or invalid proof results.
pub fn verify_randomx_mining_result_v2(
    job: &VerifiedRandomXMiningJobV2,
    result: UnverifiedRandomXMiningResultV2,
    current_job_epoch: u64,
) -> Result<AcceptedRandomXMiningResultV2, RandomXMiningJobError> {
    validate_lifetime(
        job.job.job_epoch,
        job.job.expires_at_epoch,
        current_job_epoch,
    )?;
    let result = result.0;
    if result.job_id != job.job_id {
        return Err(RandomXMiningJobError::JobIdMismatch);
    }
    if result.job_epoch != job.job.job_epoch {
        return Err(RandomXMiningJobError::JobEpochMismatch);
    }
    if result.nonce_start != job.job.nonce_start || result.nonce_count != job.job.nonce_count {
        return Err(RandomXMiningJobError::NonceRangeMismatch);
    }
    match result.kind {
        RandomXMiningResultKindV2::NoSolution => Ok(AcceptedRandomXMiningResultV2::NoSolution),
        RandomXMiningResultKindV2::ProofCandidate => {
            let unverified = RandomXV2ProofEnvelope::decode_unverified(&result.proof)?;
            let nonce = unverified.decoded().nonce();
            if !range_contains(job.job.nonce_start, job.job.nonce_count, nonce) {
                return Err(RandomXMiningJobError::CandidateOutsideRange);
            }
            let mut algorithm = RandomXV2Algorithm::new(job.job.key_material)?;
            let verified = verify_randomx_v2(&mut algorithm, &job.subject, &result.proof)?;
            Ok(AcceptedRandomXMiningResultV2::Candidate(Box::new(verified)))
        }
    }
}

/// Bounded local coordinator that enforces disjoint assignments and one result per job.
#[derive(Debug)]
pub struct BoundedRandomXMiningCoordinatorV2 {
    jobs: BTreeMap<Hash32, VerifiedRandomXMiningJobV2>,
    completed: BTreeSet<Hash32>,
}

impl BoundedRandomXMiningCoordinatorV2 {
    /// Register one bounded set of exact, non-overlapping assignments.
    ///
    /// # Errors
    ///
    /// Rejects empty/excessive sets, duplicate IDs, mixed templates, or overlapping ranges.
    pub fn new(jobs: Vec<VerifiedRandomXMiningJobV2>) -> Result<Self, RandomXMiningJobError> {
        if jobs.is_empty() || jobs.len() > MAX_RANDOMX_MINING_JOBS {
            return Err(RandomXMiningJobError::JobCountOutOfBounds);
        }
        let template = jobs
            .first()
            .ok_or(RandomXMiningJobError::JobCountOutOfBounds)?;
        for job in &jobs {
            if !same_template(template, job) {
                return Err(RandomXMiningJobError::MixedJobTemplate);
            }
        }
        let mut job_ids = BTreeSet::new();
        for job in &jobs {
            if !job_ids.insert(job.job_id) {
                return Err(RandomXMiningJobError::DuplicateJob);
            }
        }
        for (index, left) in jobs.iter().enumerate() {
            for right in &jobs[index + 1..] {
                if ranges_overlap(
                    left.job.nonce_start,
                    left.job.nonce_count,
                    right.job.nonce_start,
                    right.job.nonce_count,
                )? {
                    return Err(RandomXMiningJobError::OverlappingNonceRanges);
                }
            }
        }
        let mut by_id = BTreeMap::new();
        for job in jobs {
            if by_id.insert(job.job_id, job).is_some() {
                return Err(RandomXMiningJobError::DuplicateJob);
            }
        }
        Ok(Self {
            jobs: by_id,
            completed: BTreeSet::new(),
        })
    }

    /// Validate and consume exactly one result.
    ///
    /// # Errors
    ///
    /// Rejects unknown, duplicate, stale, wrong-range, or invalid candidate results.
    pub fn accept_result(
        &mut self,
        result_bytes: &[u8],
        current_job_epoch: u64,
    ) -> Result<AcceptedRandomXMiningResultV2, RandomXMiningJobError> {
        let result = RandomXMiningResultV2::decode_unverified(result_bytes)?;
        let job_id = result.decoded().job_id;
        if self.completed.contains(&job_id) {
            return Err(RandomXMiningJobError::DuplicateResult);
        }
        let job = self
            .jobs
            .get(&job_id)
            .ok_or(RandomXMiningJobError::UnknownJob)?;
        let accepted = verify_randomx_mining_result_v2(job, result, current_job_epoch)?;
        if !self.completed.insert(job_id) {
            return Err(RandomXMiningJobError::DuplicateResult);
        }
        Ok(accepted)
    }
}

fn validate_job_claims(
    job: &RandomXMiningJobV2,
    expected: &RandomXWorkSubjectV2,
    expected_body: &[u8],
    expected_key: Hash32,
) -> Result<(), RandomXMiningJobError> {
    if job.suite_id != RANDOMX_V2_SUITE_ID || job.suite_version != RANDOMX_V2_SUITE_VERSION {
        return Err(RandomXMiningJobError::SuiteMismatch);
    }
    if job.target_policy_id != RANDOMX_V2_TARGET_POLICY_ID {
        return Err(RandomXMiningJobError::TargetPolicyMismatch);
    }
    if job.chain_domain != expected.chain_domain() {
        return Err(RandomXMiningJobError::ChainDomainMismatch);
    }
    if job.profile_domain != expected.profile_domain() {
        return Err(RandomXMiningJobError::ProfileDomainMismatch);
    }
    if job.vertex_id != expected.vertex_id() {
        return Err(RandomXMiningJobError::VertexIdMismatch);
    }
    if job.body_id != expected.body_id()
        || job.body_digest != expected.body_digest()
        || job.canonical_body != expected_body
    {
        return Err(RandomXMiningJobError::BodyMismatch);
    }
    if job.parent_set_digest != expected.parent_set_digest() {
        return Err(RandomXMiningJobError::ParentSetMismatch);
    }
    if job.daa_policy_id != expected.daa_policy_id()
        || job.logical_time != expected.logical_time()
        || job.epoch != expected.epoch()
        || job.difficulty != expected.difficulty()
    {
        return Err(RandomXMiningJobError::DifficultyMismatch);
    }
    if job.target != expected.target() {
        return Err(RandomXMiningJobError::TargetMismatch);
    }
    if job.key_material != expected_key
        || job.work_key_id != expected.work_key_id()
        || randomx_v2_work_key_id(expected_key) != expected.work_key_id()
    {
        return Err(RandomXMiningJobError::WorkKeyMismatch);
    }
    if job.key_epoch != expected.key_epoch()
        || job.seed_epoch != expected.seed_epoch()
        || job.seed_commitment != expected.seed_commitment()
    {
        return Err(RandomXMiningJobError::KeyScheduleMismatch);
    }
    validate_body(expected, expected_body)
}

fn validate_body(subject: &RandomXWorkSubjectV2, body: &[u8]) -> Result<(), RandomXMiningJobError> {
    if body.is_empty() || body.len() > MAX_BODY_BYTES {
        return Err(RandomXMiningJobError::InvalidJobLength);
    }
    let digest: Hash32 = Sha256::digest(body).into();
    if digest != subject.body_digest() {
        return Err(RandomXMiningJobError::BodyMismatch);
    }
    Ok(())
}

fn validate_lifetime(issue: u64, expiry: u64, current: u64) -> Result<(), RandomXMiningJobError> {
    let span = expiry
        .checked_sub(issue)
        .ok_or(RandomXMiningJobError::ExpiryBeforeIssue)?;
    if span > MAX_JOB_EPOCH_SPAN {
        return Err(RandomXMiningJobError::JobLifetimeTooLong);
    }
    if current < issue {
        return Err(RandomXMiningJobError::JobEpochMismatch);
    }
    if current > expiry {
        return Err(RandomXMiningJobError::StaleJob);
    }
    Ok(())
}

fn validate_range(start: u64, count: u64) -> Result<(), RandomXMiningJobError> {
    if count == 0 || count > MAX_LOCAL_MINING_ATTEMPTS {
        return Err(RandomXMiningJobError::NonceCountOutOfBounds);
    }
    start
        .checked_add(count - 1)
        .ok_or(RandomXMiningJobError::NonceRangeOverflow)?;
    Ok(())
}

fn range_contains(start: u64, count: u64, nonce: u64) -> bool {
    nonce
        .checked_sub(start)
        .is_some_and(|offset| offset < count)
}

fn ranges_overlap(
    left_start: u64,
    left_count: u64,
    right_start: u64,
    right_count: u64,
) -> Result<bool, RandomXMiningJobError> {
    validate_range(left_start, left_count)?;
    validate_range(right_start, right_count)?;
    let left_end = left_start + left_count - 1;
    let right_end = right_start + right_count - 1;
    Ok(left_start <= right_end && right_start <= left_end)
}

fn same_template(left: &VerifiedRandomXMiningJobV2, right: &VerifiedRandomXMiningJobV2) -> bool {
    left.subject == right.subject
        && left.job.canonical_body == right.job.canonical_body
        && left.job.key_material == right.job.key_material
        && left.job.job_epoch == right.job.job_epoch
        && left.job.expires_at_epoch == right.job.expires_at_epoch
}

fn framed_sha256(domain: &[u8], fields: &[&[u8]]) -> Hash32 {
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

/// `RandomX` mining-job framing, context, range, replay, and proof failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RandomXMiningJobError {
    /// Job bytes lie outside the canonical bound.
    #[error("randomx_job.invalid_job_length")]
    InvalidJobLength,
    /// Job magic differs.
    #[error("randomx_job.invalid_job_magic")]
    InvalidJobMagic,
    /// Job wire version is unsupported.
    #[error("randomx_job.unsupported_job_version")]
    UnsupportedJobVersion,
    /// Job reserved flags are nonzero.
    #[error("randomx_job.invalid_job_flags")]
    InvalidJobFlags,
    /// Suite ID or version differs.
    #[error("randomx_job.suite_mismatch")]
    SuiteMismatch,
    /// Target-policy ID differs.
    #[error("randomx_job.target_policy_mismatch")]
    TargetPolicyMismatch,
    /// Chain domain differs.
    #[error("randomx_job.chain_domain_mismatch")]
    ChainDomainMismatch,
    /// Profile domain differs.
    #[error("randomx_job.profile_domain_mismatch")]
    ProfileDomainMismatch,
    /// Receiver-derived vertex ID differs.
    #[error("randomx_job.vertex_id_mismatch")]
    VertexIdMismatch,
    /// Exact body bytes, ID, or digest differ.
    #[error("randomx_job.body_mismatch")]
    BodyMismatch,
    /// Parent-VertexId commitment differs.
    #[error("randomx_job.parent_set_mismatch")]
    ParentSetMismatch,
    /// DAA context or 256-bit difficulty differs.
    #[error("randomx_job.difficulty_mismatch")]
    DifficultyMismatch,
    /// Checked 256-bit target differs.
    #[error("randomx_job.target_mismatch")]
    TargetMismatch,
    /// Work key or exact key material differs.
    #[error("randomx_job.work_key_mismatch")]
    WorkKeyMismatch,
    /// Key epoch, seed epoch, or commitment differs.
    #[error("randomx_job.key_schedule_mismatch")]
    KeyScheduleMismatch,
    /// Expiry precedes issue.
    #[error("randomx_job.expiry_before_issue")]
    ExpiryBeforeIssue,
    /// Job lifetime exceeds the explicit bound.
    #[error("randomx_job.lifetime_too_long")]
    JobLifetimeTooLong,
    /// Current coordinator epoch precedes issue or echoed issue differs.
    #[error("randomx_job.epoch_mismatch")]
    JobEpochMismatch,
    /// Job has expired.
    #[error("randomx_job.stale")]
    StaleJob,
    /// Nonce count is zero or excessive.
    #[error("randomx_job.nonce_count_out_of_bounds")]
    NonceCountOutOfBounds,
    /// Nonce range overflows.
    #[error("randomx_job.nonce_range_overflow")]
    NonceRangeOverflow,
    /// Result bytes lie outside the canonical bound.
    #[error("randomx_job.invalid_result_length")]
    InvalidResultLength,
    /// Result magic differs.
    #[error("randomx_job.invalid_result_magic")]
    InvalidResultMagic,
    /// Result version is unsupported.
    #[error("randomx_job.unsupported_result_version")]
    UnsupportedResultVersion,
    /// Result reserved flags are nonzero.
    #[error("randomx_job.invalid_result_flags")]
    InvalidResultFlags,
    /// Result kind is unknown.
    #[error("randomx_job.unknown_result_kind")]
    UnknownResultKind,
    /// Result kind and proof length disagree.
    #[error("randomx_job.invalid_result_shape")]
    InvalidResultShape,
    /// Candidate proof has the wrong exact size.
    #[error("randomx_job.invalid_candidate_proof_length")]
    InvalidCandidateProofLength,
    /// Result names another job.
    #[error("randomx_job.id_mismatch")]
    JobIdMismatch,
    /// Result echoes another nonce range.
    #[error("randomx_job.nonce_range_mismatch")]
    NonceRangeMismatch,
    /// Candidate nonce is outside its assigned range.
    #[error("randomx_job.candidate_outside_range")]
    CandidateOutsideRange,
    /// Coordinator received no jobs or too many jobs.
    #[error("randomx_job.job_count_out_of_bounds")]
    JobCountOutOfBounds,
    /// Registered jobs do not share one exact template.
    #[error("randomx_job.mixed_template")]
    MixedJobTemplate,
    /// Registered ranges overlap.
    #[error("randomx_job.overlapping_ranges")]
    OverlappingNonceRanges,
    /// A job ID was registered twice.
    #[error("randomx_job.duplicate_job")]
    DuplicateJob,
    /// No registered job matches the result.
    #[error("randomx_job.unknown_job")]
    UnknownJob,
    /// A terminal result for this job was already accepted.
    #[error("randomx_job.duplicate_result")]
    DuplicateResult,
    /// `RandomX` proof construction or verification failed.
    #[error(transparent)]
    Work(#[from] RandomXV2WorkError),
}

impl RandomXMiningJobError {
    /// Return a stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidJobLength => "randomx_job.invalid_job_length",
            Self::InvalidJobMagic => "randomx_job.invalid_job_magic",
            Self::UnsupportedJobVersion => "randomx_job.unsupported_job_version",
            Self::InvalidJobFlags => "randomx_job.invalid_job_flags",
            Self::SuiteMismatch => "randomx_job.suite_mismatch",
            Self::TargetPolicyMismatch => "randomx_job.target_policy_mismatch",
            Self::ChainDomainMismatch => "randomx_job.chain_domain_mismatch",
            Self::ProfileDomainMismatch => "randomx_job.profile_domain_mismatch",
            Self::VertexIdMismatch => "randomx_job.vertex_id_mismatch",
            Self::BodyMismatch => "randomx_job.body_mismatch",
            Self::ParentSetMismatch => "randomx_job.parent_set_mismatch",
            Self::DifficultyMismatch => "randomx_job.difficulty_mismatch",
            Self::TargetMismatch => "randomx_job.target_mismatch",
            Self::WorkKeyMismatch => "randomx_job.work_key_mismatch",
            Self::KeyScheduleMismatch => "randomx_job.key_schedule_mismatch",
            Self::ExpiryBeforeIssue => "randomx_job.expiry_before_issue",
            Self::JobLifetimeTooLong => "randomx_job.lifetime_too_long",
            Self::JobEpochMismatch => "randomx_job.epoch_mismatch",
            Self::StaleJob => "randomx_job.stale",
            Self::NonceCountOutOfBounds => "randomx_job.nonce_count_out_of_bounds",
            Self::NonceRangeOverflow => "randomx_job.nonce_range_overflow",
            Self::InvalidResultLength => "randomx_job.invalid_result_length",
            Self::InvalidResultMagic => "randomx_job.invalid_result_magic",
            Self::UnsupportedResultVersion => "randomx_job.unsupported_result_version",
            Self::InvalidResultFlags => "randomx_job.invalid_result_flags",
            Self::UnknownResultKind => "randomx_job.unknown_result_kind",
            Self::InvalidResultShape => "randomx_job.invalid_result_shape",
            Self::InvalidCandidateProofLength => "randomx_job.invalid_candidate_proof_length",
            Self::JobIdMismatch => "randomx_job.id_mismatch",
            Self::NonceRangeMismatch => "randomx_job.nonce_range_mismatch",
            Self::CandidateOutsideRange => "randomx_job.candidate_outside_range",
            Self::JobCountOutOfBounds => "randomx_job.job_count_out_of_bounds",
            Self::MixedJobTemplate => "randomx_job.mixed_template",
            Self::OverlappingNonceRanges => "randomx_job.overlapping_ranges",
            Self::DuplicateJob => "randomx_job.duplicate_job",
            Self::UnknownJob => "randomx_job.unknown_job",
            Self::DuplicateResult => "randomx_job.duplicate_result",
            Self::Work(error) => error.code(),
        }
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
    length_error: RandomXMiningJobError,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8], length_error: RandomXMiningJobError) -> Self {
        Self {
            bytes,
            offset: 0,
            length_error,
        }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], RandomXMiningJobError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(RandomXMiningJobError::InvalidJobLength)?;
        let value = self.bytes.get(self.offset..end).ok_or(self.length_error)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], RandomXMiningJobError> {
        self.take(N)?.try_into().map_err(|_| self.length_error)
    }

    fn hash32(&mut self) -> Result<Hash32, RandomXMiningJobError> {
        self.array()
    }
    fn u8(&mut self) -> Result<u8, RandomXMiningJobError> {
        Ok(self.array::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16, RandomXMiningJobError> {
        Ok(u16::from_le_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, RandomXMiningJobError> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, RandomXMiningJobError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    const fn finish(self) -> Result<(), RandomXMiningJobError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(self.length_error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{WorkContext, WorkSubject};

    fn fixture_job(start: u64, count: u64) -> VerifiedRandomXMiningJobV2 {
        let body = b"bounded-randomx-job-body";
        let base = WorkSubject::from_opaque_body_v1(
            WorkContext::new([0x11; 32], [0x22; 32]),
            [0x33; 32],
            body,
            &[[0x44; 32]],
        )
        .expect("fixture work subject");
        let key = [0x55; 32];
        let subject = RandomXWorkSubjectV2::new(
            &base,
            [0x66; 32],
            [0x77; 32],
            1,
            10,
            1,
            randomx_v2_work_key_id(key),
            0,
            0,
            [0x88; 32],
        )
        .expect("fixture RandomX subject");
        let job =
            RandomXMiningJobV2::new(&subject, body, key, 7, 9, start, count).expect("fixture job");
        RandomXMiningJobV2::decode_unverified(&job.canonical_bytes())
            .expect("fixture job decodes")
            .validate(&subject, body, key, 7)
            .expect("fixture job validates")
    }

    #[test]
    fn jobs_and_results_reject_tamper_mismatch_stale_overlap_and_duplicate() {
        let first = fixture_job(0, 8);
        let second = fixture_job(8, 8);
        BoundedRandomXMiningCoordinatorV2::new(vec![first.clone(), second.clone()])
            .expect("disjoint assignments register");
        assert_eq!(
            BoundedRandomXMiningCoordinatorV2::new(vec![first.clone(), fixture_job(7, 8)])
                .unwrap_err(),
            RandomXMiningJobError::OverlappingNonceRanges
        );
        assert_eq!(
            BoundedRandomXMiningCoordinatorV2::new(vec![first.clone(), first.clone()]).unwrap_err(),
            RandomXMiningJobError::DuplicateJob
        );

        let mut tampered = first.canonical_bytes().to_vec();
        *tampered.last_mut().expect("job has body bytes") ^= 1;
        assert_eq!(
            RandomXMiningJobV2::decode_unverified(&tampered)
                .expect("structural body tamper decodes")
                .validate(first.subject(), first.job().canonical_body(), [0x55; 32], 7,)
                .unwrap_err(),
            RandomXMiningJobError::BodyMismatch
        );
        assert_eq!(
            RandomXMiningJobV2::decode_unverified(first.canonical_bytes())
                .expect("job decodes")
                .validate(first.subject(), first.job().canonical_body(), [0x99; 32], 7,)
                .unwrap_err(),
            RandomXMiningJobError::WorkKeyMismatch
        );
        assert_eq!(
            RandomXMiningJobV2::decode_unverified(first.canonical_bytes())
                .expect("job decodes")
                .validate(
                    first.subject(),
                    first.job().canonical_body(),
                    [0x55; 32],
                    10,
                )
                .unwrap_err(),
            RandomXMiningJobError::StaleJob
        );

        let no_solution = RandomXMiningResultV2::no_solution(&first).canonical_bytes();
        let mut coordinator = BoundedRandomXMiningCoordinatorV2::new(vec![first.clone()])
            .expect("one assignment registers");
        assert_eq!(
            coordinator
                .accept_result(&no_solution, 7)
                .expect("first terminal result is accepted"),
            AcceptedRandomXMiningResultV2::NoSolution
        );
        assert_eq!(
            coordinator.accept_result(&no_solution, 7).unwrap_err(),
            RandomXMiningJobError::DuplicateResult
        );

        let unknown = RandomXMiningResultV2::no_solution(&second).canonical_bytes();
        let mut coordinator = BoundedRandomXMiningCoordinatorV2::new(vec![first.clone()])
            .expect("one assignment registers");
        assert_eq!(
            coordinator.accept_result(&unknown, 7).unwrap_err(),
            RandomXMiningJobError::UnknownJob
        );
        let mut wrong_range = no_solution;
        wrong_range[52..60].copy_from_slice(&1_u64.to_le_bytes());
        assert_eq!(
            coordinator.accept_result(&wrong_range, 7).unwrap_err(),
            RandomXMiningJobError::NonceRangeMismatch
        );
    }
}
