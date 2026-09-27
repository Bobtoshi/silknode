//! Stable, framed SHA-256 hashing for consensus identifiers and domains.

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    CanonicalEncode, ChainDomain, EncodeError, GenesisAllocationTemplateHash, GenesisCommitment,
    GenesisManifestTemplateHash, GenesisObjectTemplateHash, Hash32, ManifestHash, ProfileDomain,
    UnverifiedGenesisObjectDigest,
};

/// Versioned transcript prefix for all hashes produced by [`domain_hash`].
///
/// The full transcript is:
///
/// ```text
/// DOMAIN_HASH_TRANSCRIPT_V1
/// || u32_le(domain.len) || domain
/// || u32_le(parts.len)
/// || for each part: u32_le(part.len) || part
/// ```
///
/// Lengths are checked before hashing. This framing distinguishes part
/// boundaries and allows an independent implementation to reproduce IDs
/// without relying on host-language serialization.
pub const DOMAIN_HASH_TRANSCRIPT_V1: &[u8] = b"SilkNode-Domain-Hash-v1\0";

/// Domain labels used by the Gate A specification and implementation bindings.
pub mod hash_domains {
    /// Immutable network/genesis chain identity.
    pub const CHAIN: &[u8] = b"SilkNode-Chain";
    /// Replaceable protocol-profile identity.
    pub const PROTOCOL_PROFILE: &[u8] = b"SilkNode-Protocol-Profile";
    /// Chain constitution content hash.
    pub const CONSTITUTION: &[u8] = b"SilkNode-Constitution";
    /// Canonical chain-independent genesis manifest projection.
    pub const GENESIS_MANIFEST_TEMPLATE: &[u8] = b"SilkNode-Genesis-Manifest-Template";
    /// Auxiliary exact-byte binding for the genesis allocation template.
    ///
    /// The normative genesis commitment still includes the canonical template
    /// bytes directly; this diagnostic identifier is not substituted for them.
    pub const GENESIS_ALLOCATION_TEMPLATE: &[u8] = b"SilkNode-Genesis-Allocation-Template";
    /// Canonical chain-independent genesis object projection.
    pub const GENESIS_OBJECT_TEMPLATE: &[u8] = b"SilkNode-Genesis-Object-Template";
    /// Complete non-circular genesis commitment.
    pub const GENESIS_COMMITMENT: &[u8] = b"SilkNode-Genesis-Commitment";
    /// Canonical deterministic non-PoW genesis state-anchor identity.
    pub const GENESIS_OBJECT: &[u8] = b"SilkNode-Genesis-Object";
    /// Canonical protocol manifest content hash.
    pub const PROTOCOL_MANIFEST: &[u8] = b"Silk-Protocol-Manifest";
    /// Canonical consensus module identity.
    pub const CONSENSUS_MODULE: &[u8] = b"Silk-Consensus-Module";
    /// Anchor-independent transaction intent identity.
    pub const INTENT: &[u8] = b"Silk-Intent";
    /// Anchor/proof-specific transaction instance identity.
    pub const INSTANCE: &[u8] = b"Silk-Instance";
    /// Transaction effect identity.
    pub const EFFECT: &[u8] = b"Silk-Effect";
    /// Recovery-record identity.
    pub const RECOVERY_RECORD: &[u8] = b"Silk-Recovery-Record";
    /// `PoW` key derivation.
    pub const POW_KEY: &[u8] = b"Silk-PoW-Key";
    /// Profile handoff identity.
    pub const PROFILE_HANDOFF: &[u8] = b"Silk-Profile-Handoff";
    /// Profile activation-fence identity.
    pub const PROFILE_FENCE: &[u8] = b"Silk-Profile-Fence";
    /// Profile transition-anchor identity.
    pub const TRANSITION_ANCHOR: &[u8] = b"Silk-Transition-Anchor";
}

/// Failure while constructing a domain-separated hash transcript.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DomainHashError {
    /// A zero-length domain label was supplied.
    #[error("domain label must not be empty")]
    EmptyDomain,
    /// A domain, part count, or part length did not fit the canonical `u32` framing.
    #[error("{kind} length {length} exceeds the domain-hash u32 range")]
    LengthOverflow {
        /// Name of the value whose length overflowed.
        kind: &'static str,
        /// Host-side length that did not fit.
        length: usize,
    },
    /// Canonical encoding of a hashed object failed.
    #[error(transparent)]
    CanonicalEncoding(#[from] EncodeError),
}

impl DomainHashError {
    /// Returns a stable rejection code suitable for differential fixtures.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::EmptyDomain => "hash.empty_domain",
            Self::LengthOverflow { .. } => "hash.length_overflow",
            Self::CanonicalEncoding(error) => error.code(),
        }
    }
}

fn checked_len(kind: &'static str, length: usize) -> Result<[u8; 4], DomainHashError> {
    let length =
        u32::try_from(length).map_err(|_| DomainHashError::LengthOverflow { kind, length })?;
    Ok(length.to_le_bytes())
}

/// Hashes an explicitly framed sequence of byte parts with SHA-256.
///
/// `domain` should be a fixed protocol label, normally from [`hash_domains`].
/// The versioned prefix, domain, part count, and every part length are included
/// in the transcript, preventing concatenation and cross-domain ambiguity.
///
/// # Errors
///
/// Returns [`DomainHashError::EmptyDomain`] for an empty label or
/// [`DomainHashError::LengthOverflow`] if any framing length exceeds `u32`.
pub fn domain_hash(domain: &[u8], parts: &[&[u8]]) -> Result<Hash32, DomainHashError> {
    if domain.is_empty() {
        return Err(DomainHashError::EmptyDomain);
    }

    let domain_len = checked_len("domain", domain.len())?;
    let part_count = checked_len("part count", parts.len())?;

    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_HASH_TRANSCRIPT_V1);
    hasher.update(domain_len);
    hasher.update(domain);
    hasher.update(part_count);
    for part in parts {
        hasher.update(checked_len("hash part", part.len())?);
        hasher.update(part);
    }

    let digest: [u8; Hash32::LENGTH] = hasher.finalize().into();
    Ok(Hash32::new(digest))
}

/// Canonically encodes one value and hashes the resulting bytes as one framed part.
///
/// This implements specification forms such as
/// `H(domain, CanonicalEncode(value))` without exposing Rust layout.
///
/// # Errors
///
/// Returns a canonical encoding error or a domain-hash framing error.
pub fn hash_canonical<T: CanonicalEncode>(
    domain: &[u8],
    value: &T,
) -> Result<Hash32, DomainHashError> {
    let bytes = value.to_canonical_bytes()?;
    domain_hash(domain, &[&bytes])
}

/// Derives the identity of exact canonical genesis-allocation-template bytes.
///
/// This helper does not parse or bless an allocation-template schema. The
/// caller remains responsible for supplying the exact canonical bytes defined
/// by the active specification. The same byte slice must be supplied to
/// [`derive_genesis_commitment`].
///
/// # Errors
///
/// Returns a framing error if the byte length cannot be represented by the
/// version-1 domain-hash transcript.
pub fn derive_genesis_allocation_template_hash(
    canonical_allocation_template_bytes: &[u8],
) -> Result<GenesisAllocationTemplateHash, DomainHashError> {
    domain_hash(
        hash_domains::GENESIS_ALLOCATION_TEMPLATE,
        &[canonical_allocation_template_bytes],
    )
    .map(GenesisAllocationTemplateHash::new)
}

/// Derives the complete non-circular genesis commitment.
///
/// The derivation follows the specification exactly:
///
/// ```text
/// H("SilkNode-Genesis-Commitment", network_id, constitution_hash,
///   manifest_template_hash, canonical_allocation_template_bytes,
///   object_template_hash)
/// ```
///
/// The allocation template is committed as the exact supplied framed part,
/// not via [`GenesisAllocationTemplateHash`].
///
/// # Errors
///
/// Returns a framing error if any component length cannot be represented by
/// the version-1 domain-hash transcript.
pub fn derive_genesis_commitment(
    network_id: &[u8],
    constitution_hash: Hash32,
    manifest_template_hash: GenesisManifestTemplateHash,
    canonical_allocation_template_bytes: &[u8],
    object_template_hash: GenesisObjectTemplateHash,
) -> Result<GenesisCommitment, DomainHashError> {
    domain_hash(
        hash_domains::GENESIS_COMMITMENT,
        &[
            network_id,
            constitution_hash.as_bytes(),
            manifest_template_hash.as_bytes(),
            canonical_allocation_template_bytes,
            object_template_hash.as_bytes(),
        ],
    )
    .map(GenesisCommitment::new)
}

/// Derives the immutable chain domain from network identity and genesis commitment.
///
/// The derivation follows `H("SilkNode-Chain", network_id, genesis_commitment)`
/// using the version-1 framed hash transcript.
///
/// # Errors
///
/// Returns a framing error if `network_id` is too large for the canonical hash
/// transcript.
pub fn derive_chain_domain(
    network_id: &[u8],
    genesis_commitment: GenesisCommitment,
) -> Result<ChainDomain, DomainHashError> {
    domain_hash(
        hash_domains::CHAIN,
        &[network_id, genesis_commitment.as_bytes()],
    )
    .map(ChainDomain::new)
}

/// Derives a replaceable profile domain inside one immutable chain domain.
///
/// The derivation follows
/// `H("SilkNode-Protocol-Profile", chain_domain, protocol_major_le,
/// protocol_manifest_hash)` using the version-1 framed hash transcript.
///
/// # Errors
///
/// Returns a framing error if a transcript component cannot be represented.
pub fn derive_profile_domain(
    chain_domain: ChainDomain,
    protocol_major: u32,
    protocol_manifest_hash: ManifestHash,
) -> Result<ProfileDomain, DomainHashError> {
    let protocol_major = protocol_major.to_le_bytes();
    domain_hash(
        hash_domains::PROTOCOL_PROFILE,
        &[
            chain_domain.as_bytes(),
            &protocol_major,
            protocol_manifest_hash.as_bytes(),
        ],
    )
    .map(ProfileDomain::new)
}

/// Hashes bytes presented as a complete canonical genesis state anchor.
///
/// This low-level helper cannot authenticate its byte input, so it returns an
/// [`UnverifiedGenesisObjectDigest`] rather than a [`crate::GenesisId`]. The
/// genesis layer derives a `GenesisId` only from canonical bytes emitted by a
/// verified object. That object comes either from direct materialization over
/// sealed profile and verified checkpoint-zero evidence or from consuming
/// verification of a canonically decoded unverified candidate.
///
/// # Errors
///
/// Returns a framing error if the object length cannot be represented by the
/// version-1 domain-hash transcript.
pub fn derive_unverified_genesis_object_digest(
    canonical_genesis_object_bytes: &[u8],
) -> Result<UnverifiedGenesisObjectDigest, DomainHashError> {
    domain_hash(
        hash_domains::GENESIS_OBJECT,
        &[canonical_genesis_object_bytes],
    )
    .map(UnverifiedGenesisObjectDigest::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(hash: Hash32) -> String {
        hash.to_string()
    }

    #[test]
    fn frozen_domain_hash_vector() {
        let hash = domain_hash(
            b"Silk-Test-Vector",
            &[b"", b"abc", &[0x00, 0x01, 0x02, 0xff]],
        )
        .expect("vector hashes");

        // Frozen cross-client vector for DOMAIN_HASH_TRANSCRIPT_V1. Changing
        // this value is a consensus-format change, not test maintenance.
        assert_eq!(
            hex(hash),
            "e708e870b755603c57d3b8b416792576944974a0dc4121def335ae1723941431"
        );
    }

    #[test]
    fn framing_distinguishes_part_boundaries_count_order_and_domain() {
        let split_left = domain_hash(b"Silk-Test", &[b"ab", b"c"]).expect("hashes");
        let split_right = domain_hash(b"Silk-Test", &[b"a", b"bc"]).expect("hashes");
        let single = domain_hash(b"Silk-Test", &[b"abc"]).expect("hashes");
        let reversed = domain_hash(b"Silk-Test", &[b"c", b"ab"]).expect("hashes");
        let other_domain = domain_hash(b"Silk-Other", &[b"ab", b"c"]).expect("hashes");

        assert_ne!(split_left, split_right);
        assert_ne!(split_left, single);
        assert_ne!(split_left, reversed);
        assert_ne!(split_left, other_domain);
    }

    #[test]
    fn empty_domain_fails_closed_with_stable_code() {
        let error = domain_hash(b"", &[b"payload"]).expect_err("empty domain rejects");
        assert_eq!(error, DomainHashError::EmptyDomain);
        assert_eq!(error.code(), "hash.empty_domain");
    }

    #[test]
    fn canonical_hash_uses_normative_encoded_bytes() {
        let value = 0x0102_0304_u32;
        let via_helper = hash_canonical(b"Silk-Test", &value).expect("hashes");
        let explicit = domain_hash(b"Silk-Test", &[&value.to_le_bytes()]).expect("hashes");
        assert_eq!(via_helper, explicit);
    }

    #[test]
    fn chain_and_profile_derivations_are_typed_and_stable() {
        let genesis = GenesisCommitment::from_bytes([0x11; 32]);
        let chain = derive_chain_domain(b"silknode-local-gate-a", genesis).expect("chain derives");
        let manifest = ManifestHash::from_bytes([0x22; 32]);
        let profile = derive_profile_domain(chain, 7, manifest).expect("profile derives");

        assert_eq!(
            chain.to_string(),
            "e98eed37bd720bf53d8517974e81e1816ea1495d8c90e5cbf3c5291fed76c537"
        );
        assert_eq!(
            profile.to_string(),
            "a897c8740eacff9a7404274e70491b6b704d8f6699e33145762060a69550a6e8"
        );
        assert_ne!(chain.as_bytes(), profile.as_bytes());
    }

    #[test]
    fn genesis_commitment_binds_every_exact_framed_input() {
        let network = b"silknode-gate-a";
        let constitution = Hash32::new([0x11; 32]);
        let manifest = GenesisManifestTemplateHash::from_bytes([0x22; 32]);
        let allocations = b"canonical-allocation-template-v1";
        let object = GenesisObjectTemplateHash::from_bytes([0x33; 32]);
        let original =
            derive_genesis_commitment(network, constitution, manifest, allocations, object)
                .expect("genesis commitment derives");
        let original_chain =
            derive_chain_domain(network, original).expect("chain domain derives from commitment");

        let cases = [
            (
                b"silknode-gate-b".as_slice(),
                derive_genesis_commitment(
                    b"silknode-gate-b",
                    constitution,
                    manifest,
                    allocations,
                    object,
                ),
            ),
            (
                network.as_slice(),
                derive_genesis_commitment(
                    network,
                    Hash32::new([0x12; 32]),
                    manifest,
                    allocations,
                    object,
                ),
            ),
            (
                network.as_slice(),
                derive_genesis_commitment(
                    network,
                    constitution,
                    GenesisManifestTemplateHash::from_bytes([0x23; 32]),
                    allocations,
                    object,
                ),
            ),
            (
                network.as_slice(),
                derive_genesis_commitment(
                    network,
                    constitution,
                    manifest,
                    b"canonical-allocation-template-v2",
                    object,
                ),
            ),
            (
                network.as_slice(),
                derive_genesis_commitment(
                    network,
                    constitution,
                    manifest,
                    allocations,
                    GenesisObjectTemplateHash::from_bytes([0x34; 32]),
                ),
            ),
        ];

        for (changed_network, changed) in cases {
            let changed = changed.expect("changed commitment derives");
            assert_ne!(changed, original);
            assert_ne!(
                derive_chain_domain(changed_network, changed).expect("changed chain derives"),
                original_chain
            );
        }
    }

    #[test]
    fn allocation_template_hash_and_genesis_vectors_are_frozen() {
        let network = b"silknode-gate-a";
        let constitution = Hash32::new([0x11; 32]);
        let manifest = GenesisManifestTemplateHash::from_bytes([0x22; 32]);
        let allocations = b"canonical-allocation-template-v1";
        let object = GenesisObjectTemplateHash::from_bytes([0x33; 32]);
        let allocation_hash = derive_genesis_allocation_template_hash(allocations)
            .expect("allocation-template hash derives");
        let commitment =
            derive_genesis_commitment(network, constitution, manifest, allocations, object)
                .expect("genesis commitment derives");
        let chain = derive_chain_domain(network, commitment).expect("chain derives");

        assert_eq!(
            allocation_hash.to_string(),
            "185d019f6472e1a060984ee35a82f1afa0bf78c0f31266c5bc4132d5b40f255d"
        );
        assert_eq!(
            commitment.to_string(),
            "4e66cc148b40ad81d71bd299280ab11921a2b9f8586f5e9e8bc9dfb8ed3f6b83"
        );
        assert_eq!(
            chain.to_string(),
            "bdbdaa9afeb38b9aaf0eddf4256d2103c57880c03125de172f7d86931de4d0ec"
        );
    }

    #[test]
    fn genesis_object_template_domain_vector_is_frozen() {
        let object = domain_hash(
            hash_domains::GENESIS_OBJECT_TEMPLATE,
            &[b"silknode-test-object-template-v1"],
        )
        .map(GenesisObjectTemplateHash::new)
        .expect("object-template bytes hash");

        assert_eq!(
            object.to_string(),
            "290f413516b0be0589a50b3608175d3041ab3edd50ccde178faa00a1c7f5deea"
        );
    }

    #[test]
    fn allocation_template_hash_preserves_exact_boundaries() {
        let empty = derive_genesis_allocation_template_hash(b"").expect("empty template hashes");
        let one_zero =
            derive_genesis_allocation_template_hash(&[0]).expect("single-byte template hashes");
        let two_parts = domain_hash(
            hash_domains::GENESIS_ALLOCATION_TEMPLATE,
            &[b"canonical-", b"allocation-template-v1"],
        )
        .expect("two parts hash");
        let one_part = derive_genesis_allocation_template_hash(b"canonical-allocation-template-v1")
            .expect("one part hashes");
        let mutated = derive_genesis_allocation_template_hash(b"canonical-allocation-template-v2")
            .expect("mutated template hashes");

        assert_ne!(empty, one_zero);
        assert_ne!(two_parts.as_bytes(), one_part.as_bytes());
        assert_ne!(one_part, mutated);
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn transcript_length_conversion_is_checked_without_allocation() {
        let length = usize::try_from(u64::from(u32::MAX) + 1).expect("64-bit usize");
        assert_eq!(
            checked_len("fixture", length),
            Err(DomainHashError::LengthOverflow {
                kind: "fixture",
                length,
            })
        );
    }

    #[test]
    fn unverified_genesis_object_digest_domain_vector_is_frozen() {
        let object = b"canonical-non-pow-genesis-state-anchor-v1";
        let candidate = derive_unverified_genesis_object_digest(object)
            .expect("genesis-object candidate digest derives");
        assert_eq!(
            candidate.to_string(),
            "5055d36ce1a5e1f2b2e00657decc0dee9d1a156c700b862d0459a1fd8c42e894"
        );
        assert_ne!(
            candidate.into_hash(),
            domain_hash(hash_domains::GENESIS_OBJECT_TEMPLATE, &[object])
                .expect("template-domain comparison hashes")
        );
    }
}
