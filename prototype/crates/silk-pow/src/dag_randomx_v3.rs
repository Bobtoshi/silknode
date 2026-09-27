//! Domain-separated genuine RandomX transcript for the persistent private DAG.
//!
//! Graph, body, DAA and key-source reconstruction remain receiver-owned. This
//! module verifies their complete canonical header-template binding, not peer
//! claims about any of those inputs. Its output is work evidence, not finality.

use crate::{RandomXV2Algorithm, RandomXV2WorkError, Uint256};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Maximum complete non-nonce header-template length.
pub const MAX_DAG_HEADER_TEMPLATE_BYTES_V3: usize = 4096;
/// Exact compact nonce/result encoding length, including framing.
pub const DAG_RANDOMX_PROOF_BYTES_V3: usize = 52;
/// Maximum required work of this test-only DAA profile.
pub const MAX_DAG_WORK_V3: u64 = 1_000_000;
const PROOF_MAGIC: &[u8; 8] = b"SLKDPOW3";
const TRANSCRIPT_DOMAIN: &[u8] = b"SilkNode/PrivatePersistentDAG/RandomX/v3\0";

/// Identity of the exact new transcript, target rule and pinned hash backend.
#[must_use]
pub fn dag_randomx_suite_id_v3() -> [u8; 32] {
    framed_hash(
        b"SilkNode/DAG-PoW-Suite/v3",
        &[
            b"RandomX-v2.0.1-aaafe71322df6602c21a5c72937ac284724ae561",
            TRANSCRIPT_DOMAIN,
            &dag_target_policy_id_v3(),
            b"digest-big-endian;header-template-plus-nonce;proof-v3;interpreted-light",
        ],
    )
}

/// Identity of `floor(2^256/work)-1`, with the full-range work-one case.
#[must_use]
pub fn dag_target_policy_id_v3() -> [u8; 32] {
    framed_hash(
        b"SilkNode/DAG-Target-Policy/v3",
        &[b"floor(2^256/work)-1;work=1:2^256-1;work-range:1..1000000"],
    )
}

/// Receiver-selected commitments for an already validated header template.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DagRandomXSubjectV3 {
    chain_domain: [u8; 32],
    profile_domain: [u8; 32],
    key_id: [u8; 32],
    required_work: u64,
    target: Uint256,
    header_template: Vec<u8>,
}

impl DagRandomXSubjectV3 {
    /// Bind the exact canonical header bytes reconstructed by the local node.
    ///
    /// The template must include typed parents, body/recovery/reward bindings,
    /// timestamp, DAA derivation and delayed key-source fields. It excludes
    /// nonce/result and final VertexId, avoiding a circular hash definition.
    pub fn from_validated_template(
        chain_domain: [u8; 32],
        profile_domain: [u8; 32],
        key_id: [u8; 32],
        required_work: u64,
        header_template: &[u8],
    ) -> Result<Self, DagRandomXErrorV3> {
        if header_template.is_empty() || header_template.len() > MAX_DAG_HEADER_TEMPLATE_BYTES_V3 {
            return Err(DagRandomXErrorV3::TemplateLength);
        }
        Ok(Self {
            chain_domain,
            profile_domain,
            key_id,
            required_work,
            target: dag_target_for_work_v3(required_work)?,
            header_template: header_template.to_vec(),
        })
    }

    /// Exact expected cache-key identity.
    #[must_use]
    pub const fn key_id(&self) -> [u8; 32] {
        self.key_id
    }

    /// Receiver-derived work contribution of a valid proof.
    #[must_use]
    pub const fn required_work(&self) -> u64 {
        self.required_work
    }

    /// Receiver-derived full 256-bit target.
    #[must_use]
    pub const fn target(&self) -> Uint256 {
        self.target
    }

    /// Full semantic job identity, excluding only the searched nonce.
    #[must_use]
    pub fn template_id(&self) -> [u8; 32] {
        framed_hash(b"SilkNode/DAG-Header-Template/v3", &[&self.transcript(0)])
    }

    fn transcript(&self, nonce: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(256 + self.header_template.len());
        out.extend_from_slice(TRANSCRIPT_DOMAIN);
        for digest in [
            dag_randomx_suite_id_v3(),
            dag_target_policy_id_v3(),
            self.chain_domain,
            self.profile_domain,
            self.key_id,
        ] {
            out.extend_from_slice(&digest);
        }
        out.extend_from_slice(&self.required_work.to_be_bytes());
        out.extend_from_slice(&self.target.to_be_bytes());
        // The constructor bound is far below u32::MAX.
        out.extend_from_slice(&(self.header_template.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.header_template);
        out.extend_from_slice(&nonce.to_be_bytes());
        out
    }
}

/// A strictly framed but untrusted nonce and claimed RandomX result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DagRandomXProofV3 {
    nonce: u64,
    hash: [u8; 32],
}

impl DagRandomXProofV3 {
    /// Decode without granting work authority.
    pub fn decode_untrusted(bytes: &[u8]) -> Result<Self, DagRandomXErrorV3> {
        if bytes.len() != DAG_RANDOMX_PROOF_BYTES_V3
            || &bytes[..8] != PROOF_MAGIC
            || bytes[8..12] != [0, 3, 0, 0]
        {
            return Err(DagRandomXErrorV3::ProofFraming);
        }
        Ok(Self {
            nonce: u64::from_be_bytes(
                bytes[12..20]
                    .try_into()
                    .map_err(|_| DagRandomXErrorV3::ProofFraming)?,
            ),
            hash: bytes[20..52]
                .try_into()
                .map_err(|_| DagRandomXErrorV3::ProofFraming)?,
        })
    }

    /// Exact fixed-width proof encoding.
    #[must_use]
    pub fn canonical_bytes(self) -> [u8; DAG_RANDOMX_PROOF_BYTES_V3] {
        let mut out = [0; DAG_RANDOMX_PROOF_BYTES_V3];
        out[..8].copy_from_slice(PROOF_MAGIC);
        out[8..12].copy_from_slice(&[0, 3, 0, 0]);
        out[12..20].copy_from_slice(&self.nonce.to_be_bytes());
        out[20..].copy_from_slice(&self.hash);
        out
    }

    /// Untrusted nonce claim.
    #[must_use]
    pub const fn nonce(self) -> u64 {
        self.nonce
    }

    /// Untrusted claimed hash until independently verified.
    #[must_use]
    pub const fn claimed_hash(self) -> [u8; 32] {
        self.hash
    }
}

/// Work produced only by genuine local hash evaluation and checked target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedDagRandomXWorkV3 {
    proof: DagRandomXProofV3,
    template_id: [u8; 32],
    work: Uint256,
    vertex_id: [u8; 32],
}

impl VerifiedDagRandomXWorkV3 {
    /// Exact authenticated nonce/result.
    #[must_use]
    pub const fn proof(&self) -> DagRandomXProofV3 {
        self.proof
    }
    /// Binding to the complete receiver-reconstructed template.
    #[must_use]
    pub const fn template_id(&self) -> [u8; 32] {
        self.template_id
    }
    /// Checked full-width work contribution.
    #[must_use]
    pub const fn work(&self) -> Uint256 {
        self.work
    }
    /// Identity including all non-nonce commitments, nonce and verified result.
    #[must_use]
    pub const fn vertex_id(&self) -> [u8; 32] {
        self.vertex_id
    }
}

/// Independently evaluate a canonical received proof with the pinned backend.
pub fn verify_dag_randomx_v3(
    algorithm: &mut RandomXV2Algorithm,
    subject: &DagRandomXSubjectV3,
    proof_bytes: &[u8],
) -> Result<VerifiedDagRandomXWorkV3, DagRandomXErrorV3> {
    if algorithm.work_key_id() != subject.key_id {
        return Err(DagRandomXErrorV3::KeyMismatch);
    }
    let proof = DagRandomXProofV3::decode_untrusted(proof_bytes)?;
    let actual = algorithm.hash(&subject.transcript(proof.nonce))?;
    if actual != proof.hash {
        return Err(DagRandomXErrorV3::HashMismatch);
    }
    if Uint256::from_be_bytes(actual) > subject.target {
        return Err(DagRandomXErrorV3::InsufficientWork);
    }
    Ok(promote_evaluated(subject, proof))
}

/// Evaluate exactly one nonce; cancellation and CPU scheduling belong outside.
pub fn mine_dag_randomx_nonce_v3(
    algorithm: &mut RandomXV2Algorithm,
    subject: &DagRandomXSubjectV3,
    nonce: u64,
) -> Result<VerifiedDagRandomXWorkV3, DagRandomXErrorV3> {
    if algorithm.work_key_id() != subject.key_id {
        return Err(DagRandomXErrorV3::KeyMismatch);
    }
    let hash = algorithm.hash(&subject.transcript(nonce))?;
    if Uint256::from_be_bytes(hash) > subject.target {
        return Err(DagRandomXErrorV3::InsufficientWork);
    }
    Ok(promote_evaluated(
        subject,
        DagRandomXProofV3 { nonce, hash },
    ))
}

fn promote_evaluated(
    subject: &DagRandomXSubjectV3,
    proof: DagRandomXProofV3,
) -> VerifiedDagRandomXWorkV3 {
    let template_id = subject.template_id();
    VerifiedDagRandomXWorkV3 {
        proof,
        template_id,
        work: Uint256::from_u64(subject.required_work),
        vertex_id: framed_hash(
            b"SilkNode/DAG-VertexId/v3",
            &[&template_id, &proof.canonical_bytes()],
        ),
    }
}

/// Derive the exact target with a 257-bit dividend and checked bounded divisor.
pub fn dag_target_for_work_v3(work: u64) -> Result<Uint256, DagRandomXErrorV3> {
    if !(1..=MAX_DAG_WORK_V3).contains(&work) {
        return Err(DagRandomXErrorV3::Difficulty);
    }
    if work == 1 {
        return Ok(Uint256::from_be_bytes([u8::MAX; 32]));
    }
    // Long division of the 33-byte integer 0x01 followed by 32 zeroes.
    // remainder < work <= 1_000_000, so (remainder << 8) fits u64.
    let mut remainder = 1_u64;
    let mut quotient = [0_u8; 32];
    for byte in &mut quotient {
        let dividend = remainder << 8;
        *byte = u8::try_from(dividend / work).map_err(|_| DagRandomXErrorV3::Arithmetic)?;
        remainder = dividend % work;
    }
    for byte in quotient.iter_mut().rev() {
        let (next, borrow) = byte.overflowing_sub(1);
        *byte = next;
        if !borrow {
            return Ok(Uint256::from_be_bytes(quotient));
        }
    }
    Err(DagRandomXErrorV3::Arithmetic)
}

/// Typed failures; insufficient work is a normal local nonce miss.
#[derive(Debug, Error)]
pub enum DagRandomXErrorV3 {
    /// The local nonce cursor is exhausted and must not wrap.
    #[error("dag_pow.nonce_range_overflow")]
    NonceRangeOverflow,
    /// Template is empty or exceeds the fixed operational byte bound.
    #[error("dag_pow.template_length")]
    TemplateLength,
    /// Proof framing is not the exact v3 form.
    #[error("dag_pow.proof_framing")]
    ProofFraming,
    /// Work is outside the genesis-bound test profile range.
    #[error("dag_pow.difficulty")]
    Difficulty,
    /// Checked full-target arithmetic failed.
    #[error("dag_pow.arithmetic")]
    Arithmetic,
    /// Backend cache does not have the receiver-derived key.
    #[error("dag_pow.key_mismatch")]
    KeyMismatch,
    /// Claimed hash differs from genuine evaluation.
    #[error("dag_pow.hash_mismatch")]
    HashMismatch,
    /// Correct hash did not meet the exact target.
    #[error("dag_pow.insufficient_work")]
    InsufficientWork,
    /// The genuine pinned backend failed.
    #[error("dag_pow.backend: {0}")]
    Backend(#[from] RandomXV2WorkError),
}

fn framed_hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update((domain.len() as u64).to_be_bytes());
    hash.update(domain);
    for part in parts {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_target_rounding_and_profile_bounds() {
        assert_eq!(
            dag_target_for_work_v3(1).expect("work one").to_be_bytes(),
            [255; 32]
        );
        let mut half = [255; 32];
        half[0] = 127;
        assert_eq!(
            dag_target_for_work_v3(2).expect("work two").to_be_bytes(),
            half
        );
        let mut thirds = [0x55; 32];
        thirds[31] = 0x54;
        assert_eq!(
            dag_target_for_work_v3(3).expect("work three").to_be_bytes(),
            thirds
        );
        assert!(dag_target_for_work_v3(1_000_000).is_ok());
        assert!(dag_target_for_work_v3(0).is_err());
        assert!(dag_target_for_work_v3(1_000_001).is_err());
        assert_ne!(dag_randomx_suite_id_v3(), crate::RANDOMX_V2_SUITE_ID);
        assert_ne!(
            dag_target_policy_id_v3(),
            crate::RANDOMX_V2_TARGET_POLICY_ID
        );
    }

    #[test]
    fn proof_and_subject_have_exact_noninterchangeable_framing() {
        let proof = DagRandomXProofV3 {
            nonce: u64::MAX,
            hash: [3; 32],
        };
        let bytes = proof.canonical_bytes();
        assert_eq!(
            DagRandomXProofV3::decode_untrusted(&bytes).expect("codec"),
            proof
        );
        for length in [0, 7, 8, 11, 12, 51] {
            assert!(DagRandomXProofV3::decode_untrusted(&bytes[..length]).is_err());
        }
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(DagRandomXProofV3::decode_untrusted(&trailing).is_err());
        let mut reserved = bytes;
        reserved[11] = 1;
        assert!(DagRandomXProofV3::decode_untrusted(&reserved).is_err());
        let subject =
            DagRandomXSubjectV3::from_validated_template([1; 32], [2; 32], [3; 32], 1, b"header")
                .expect("subject");
        let changed =
            DagRandomXSubjectV3::from_validated_template([1; 32], [2; 32], [3; 32], 1, b"other")
                .expect("subject");
        assert_ne!(subject.template_id(), changed.template_id());
        assert_ne!(subject.transcript(0), subject.transcript(1));
        assert!(
            DagRandomXSubjectV3::from_validated_template([1; 32], [2; 32], [3; 32], 1, &[])
                .is_err()
        );
        assert!(
            DagRandomXSubjectV3::from_validated_template(
                [1; 32],
                [2; 32],
                [3; 32],
                1,
                &vec![0; 4097]
            )
            .is_err()
        );
    }
}
