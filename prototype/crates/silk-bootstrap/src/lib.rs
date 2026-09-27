#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Authenticated reference from a first-layer candidate to the non-PoW genesis
//! state anchor.
//!
//! This crate closes only the reference boundary. It does not define a vertex,
//! validate proof of work, calculate work, choose a target, interpret a nonce,
//! issue a reward, or initialize issuance. Canonical bytes always decode to an
//! [`UnverifiedFirstChildAnchorReference`]. Only verification against a
//! [`PinnedGenesisAnchor`] can produce a
//! [`VerifiedFirstChildAnchorReference`].

use silk_genesis::{GenesisObject, GenesisObjectError, GenesisObjectPin};
use silk_types::{
    CanonicalDecode, CanonicalEncode, ChainDomain, DecodeError, Decoder, EncodeError, Encoder,
    GenesisId, Hash32, ManifestHash, ProfileDomain,
};
use thiserror::Error;

/// Stable top-level tag for a first-child anchor reference.
pub const FIRST_CHILD_ANCHOR_REFERENCE_TAG: u8 = 0xb0;
/// Stable wire-format version of a first-child anchor reference.
pub const FIRST_CHILD_ANCHOR_REFERENCE_VERSION: u8 = 1;
/// Exact byte length of a version-one canonical first-child anchor reference.
pub const FIRST_CHILD_ANCHOR_REFERENCE_V1_ENCODED_LENGTH: usize = 34;

/// Exact A2a-6 release identity accepted by the bootstrap boundary.
pub const A2A6_RELEASE_GENESIS_ID: GenesisId = GenesisId::new(Hash32::new([
    0x52, 0x40, 0xa3, 0x25, 0xad, 0x31, 0xa1, 0x75, 0x04, 0x9a, 0xb7, 0xd7, 0x95, 0x9c, 0x2d, 0x9d,
    0x5a, 0x52, 0x07, 0x95, 0x7d, 0x4b, 0xb6, 0x37, 0x89, 0x4d, 0x95, 0xc9, 0xa5, 0x60, 0x9d, 0x93,
]));

const FIRST_CHILD_ANCHOR_REFERENCE_TAGS: &[u8] = &[FIRST_CHILD_ANCHOR_REFERENCE_TAG];
const FIRST_CHILD_ANCHOR_REFERENCE_VERSIONS: &[u8] = &[FIRST_CHILD_ANCHOR_REFERENCE_VERSION];
const A2A6_RELEASE_GENESIS_PIN: GenesisObjectPin = GenesisObjectPin::new(A2A6_RELEASE_GENESIS_ID);

/// Failure while authenticating a first-child anchor reference.
#[derive(Debug, Error)]
pub enum BootstrapError {
    /// The supplied genesis object did not satisfy the built-in A2a-6 release pin.
    #[error(transparent)]
    Genesis(#[from] GenesisObjectError),
    /// The candidate named a different genesis object from the pinned anchor.
    #[error("first-child reference names genesis id {actual}, expected {expected}")]
    ReferenceMismatch {
        /// Genesis identity obtained from the verified object and release pin.
        expected: GenesisId,
        /// Genesis identity carried by the decoded candidate.
        actual: GenesisId,
    },
}

impl BootstrapError {
    /// Returns a stable language-neutral rejection code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Genesis(error) => error.code(),
            Self::ReferenceMismatch { .. } => "anchor.genesis_id_mismatch",
        }
    }
}

/// Authenticated initial anchor context for first-child reference validation.
///
/// The only public constructor authenticates a verified [`GenesisObject`]
/// against the built-in [`A2A6_RELEASE_GENESIS_ID`]. Raw [`GenesisId`] bytes,
/// a caller-created [`GenesisObjectPin`], or an unverified decoded genesis
/// object cannot create this token.
///
/// This token is evidence only for the narrow bootstrap-reference boundary. It
/// conveys no mining, ordering, reward, or issuance authority.
///
/// ```compile_fail
/// use silk_bootstrap::PinnedGenesisAnchor;
/// use silk_types::{ChainDomain, GenesisId, ManifestHash, ProfileDomain};
///
/// let _ = PinnedGenesisAnchor {
///     genesis_id: GenesisId::ZERO,
///     chain_domain: ChainDomain::ZERO,
///     protocol_manifest_hash: ManifestHash::ZERO,
///     profile_domain: ProfileDomain::ZERO,
/// };
/// ```
///
/// ```compile_fail
/// use silk_bootstrap::PinnedGenesisAnchor;
/// use silk_genesis::{GenesisObject, GenesisObjectPin};
///
/// fn caller_pin_cannot_choose_bootstrap_anchor(
///     object: &GenesisObject,
///     caller_pin: &GenesisObjectPin,
/// ) {
///     let _ = PinnedGenesisAnchor::bind_a2a6_release(object, caller_pin);
/// }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PinnedGenesisAnchor {
    genesis_id: GenesisId,
    chain_domain: ChainDomain,
    protocol_manifest_hash: ManifestHash,
    profile_domain: ProfileDomain,
}

impl PinnedGenesisAnchor {
    /// Authenticates a verified genesis object against the exact A2a-6 release.
    ///
    /// Context is copied only after the pin has recomputed and accepted the
    /// object's [`GenesisId`]. The resulting chain and profile values therefore
    /// come from the same verified object as the accepted identity.
    ///
    /// # Errors
    ///
    /// Returns the genesis object's encoding/hash failure or a mismatch from
    /// the built-in [`A2A6_RELEASE_GENESIS_ID`]. No caller-selected pin is
    /// accepted by this boundary.
    pub fn bind_a2a6_release(object: &GenesisObject) -> Result<Self, BootstrapError> {
        let genesis_id = A2A6_RELEASE_GENESIS_PIN.verify(object)?;
        Ok(Self {
            genesis_id,
            chain_domain: object.chain_domain(),
            protocol_manifest_hash: object.protocol_manifest_hash(),
            profile_domain: object.profile_domain(),
        })
    }

    /// Returns the exact release-pinned genesis identity.
    #[must_use]
    pub const fn genesis_id(&self) -> GenesisId {
        self.genesis_id
    }

    /// Returns the immutable chain domain committed by the verified anchor.
    #[must_use]
    pub const fn chain_domain(&self) -> ChainDomain {
        self.chain_domain
    }

    /// Returns the exact initial protocol-manifest identity.
    #[must_use]
    pub const fn protocol_manifest_hash(&self) -> ManifestHash {
        self.protocol_manifest_hash
    }

    /// Returns the exact initial profile domain.
    #[must_use]
    pub const fn profile_domain(&self) -> ProfileDomain {
        self.profile_domain
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FirstChildAnchorReferenceFields {
    genesis_id: GenesisId,
}

impl FirstChildAnchorReferenceFields {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_u8(FIRST_CHILD_ANCHOR_REFERENCE_TAG);
        encoder.write_u8(FIRST_CHILD_ANCHOR_REFERENCE_VERSION);
        self.genesis_id.encode(encoder)
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decoder.read_tag(FIRST_CHILD_ANCHOR_REFERENCE_TAGS)?;
        decoder.read_tag(FIRST_CHILD_ANCHOR_REFERENCE_VERSIONS)?;
        Ok(Self {
            genesis_id: GenesisId::decode(decoder)?,
        })
    }
}

/// Canonically decoded but unauthenticated first-child anchor reference.
///
/// This candidate exposes only canonical re-encoding and consuming
/// verification. It has no trusted identity or context getters and cannot be
/// used where a [`VerifiedFirstChildAnchorReference`] is required.
///
/// ```compile_fail
/// use silk_bootstrap::UnverifiedFirstChildAnchorReference;
///
/// fn cannot_read_unverified_identity(candidate: &UnverifiedFirstChildAnchorReference) {
///     let _ = candidate.genesis_id();
/// }
/// ```
///
/// ```compile_fail
/// use silk_bootstrap::{
///     UnverifiedFirstChildAnchorReference, VerifiedFirstChildAnchorReference,
/// };
///
/// fn cannot_promote_without_verification(
///     candidate: UnverifiedFirstChildAnchorReference,
/// ) -> VerifiedFirstChildAnchorReference {
///     candidate.into()
/// }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnverifiedFirstChildAnchorReference {
    fields: FirstChildAnchorReferenceFields,
}

impl UnverifiedFirstChildAnchorReference {
    /// Verifies the candidate against one authenticated initial anchor context.
    ///
    /// Successful verification returns a freshly constructed verified value;
    /// it never reinterprets the decoded candidate as trusted state.
    ///
    /// # Errors
    ///
    /// Returns [`BootstrapError::ReferenceMismatch`] when the candidate names a
    /// different genesis object from `anchor`.
    pub fn verify(
        self,
        anchor: &PinnedGenesisAnchor,
    ) -> Result<VerifiedFirstChildAnchorReference, BootstrapError> {
        if self.fields.genesis_id != anchor.genesis_id {
            return Err(BootstrapError::ReferenceMismatch {
                expected: anchor.genesis_id,
                actual: self.fields.genesis_id,
            });
        }
        Ok(VerifiedFirstChildAnchorReference {
            fields: FirstChildAnchorReferenceFields {
                genesis_id: anchor.genesis_id,
            },
            chain_domain: anchor.chain_domain,
            protocol_manifest_hash: anchor.protocol_manifest_hash,
            profile_domain: anchor.profile_domain,
        })
    }
}

impl CanonicalEncode for UnverifiedFirstChildAnchorReference {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.fields.encode(encoder)
    }
}

impl CanonicalDecode for UnverifiedFirstChildAnchorReference {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            fields: FirstChildAnchorReferenceFields::decode(decoder)?,
        })
    }
}

/// Authenticated reference to the exact initial non-PoW genesis anchor.
///
/// This type has no public constructor and deliberately does not implement
/// [`CanonicalDecode`]. It can be obtained only by consuming verification of an
/// [`UnverifiedFirstChildAnchorReference`] against a [`PinnedGenesisAnchor`].
/// It is not a vertex identifier and carries no proof-of-work result.
///
/// ```compile_fail
/// use silk_bootstrap::VerifiedFirstChildAnchorReference;
/// use silk_types::CanonicalDecode;
///
/// let _ = VerifiedFirstChildAnchorReference::from_canonical_bytes(&[]);
/// ```
///
/// ```compile_fail
/// use silk_bootstrap::VerifiedFirstChildAnchorReference;
/// use silk_types::VertexId;
///
/// fn cannot_become_vertex_id(reference: VerifiedFirstChildAnchorReference) -> VertexId {
///     reference.into()
/// }
/// ```
///
/// ```compile_fail
/// use silk_bootstrap::VerifiedFirstChildAnchorReference;
///
/// fn has_no_work(reference: &VerifiedFirstChildAnchorReference) {
///     let _ = reference.work();
/// }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedFirstChildAnchorReference {
    fields: FirstChildAnchorReferenceFields,
    chain_domain: ChainDomain,
    protocol_manifest_hash: ManifestHash,
    profile_domain: ProfileDomain,
}

impl VerifiedFirstChildAnchorReference {
    /// Returns the exact authenticated genesis identity named by this reference.
    #[must_use]
    pub const fn genesis_id(&self) -> GenesisId {
        self.fields.genesis_id
    }

    /// Returns the immutable chain domain of the authenticated initial context.
    #[must_use]
    pub const fn chain_domain(&self) -> ChainDomain {
        self.chain_domain
    }

    /// Returns the exact initial protocol-manifest identity.
    #[must_use]
    pub const fn protocol_manifest_hash(&self) -> ManifestHash {
        self.protocol_manifest_hash
    }

    /// Returns the exact initial profile domain.
    #[must_use]
    pub const fn profile_domain(&self) -> ProfileDomain {
        self.profile_domain
    }
}

impl CanonicalEncode for VerifiedFirstChildAnchorReference {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.fields.encode(encoder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use silk_types::{CanonicalDecode, CanonicalEncode, Hash32};

    fn id(byte: u8) -> GenesisId {
        GenesisId::new(Hash32::new([byte; Hash32::LENGTH]))
    }

    fn context(genesis_id: GenesisId) -> PinnedGenesisAnchor {
        PinnedGenesisAnchor {
            genesis_id,
            chain_domain: ChainDomain::new(Hash32::new([0x22; Hash32::LENGTH])),
            protocol_manifest_hash: ManifestHash::new(Hash32::new([0x33; Hash32::LENGTH])),
            profile_domain: ProfileDomain::new(Hash32::new([0x44; Hash32::LENGTH])),
        }
    }

    fn canonical_reference(genesis_id: GenesisId) -> Vec<u8> {
        let mut bytes = vec![
            FIRST_CHILD_ANCHOR_REFERENCE_TAG,
            FIRST_CHILD_ANCHOR_REFERENCE_VERSION,
        ];
        bytes.extend_from_slice(genesis_id.as_bytes());
        bytes
    }

    #[test]
    fn version_one_layout_is_exact() {
        let expected_id = id(0x11);
        let bytes = canonical_reference(expected_id);
        assert_eq!(bytes.len(), FIRST_CHILD_ANCHOR_REFERENCE_V1_ENCODED_LENGTH);
        assert_eq!(bytes[0], FIRST_CHILD_ANCHOR_REFERENCE_TAG);
        assert_eq!(bytes[1], FIRST_CHILD_ANCHOR_REFERENCE_VERSION);
        assert_eq!(&bytes[2..], expected_id.as_bytes());

        let candidate = UnverifiedFirstChildAnchorReference::from_canonical_bytes(&bytes)
            .expect("exact reference decodes");
        assert_eq!(
            candidate.to_canonical_bytes().expect("candidate encodes"),
            bytes
        );
    }

    #[test]
    fn every_truncation_fails_closed() {
        let bytes = canonical_reference(id(0x11));
        for end in 0..bytes.len() {
            assert!(
                UnverifiedFirstChildAnchorReference::from_canonical_bytes(&bytes[..end]).is_err(),
                "truncation at {end} unexpectedly decoded"
            );
        }
    }

    #[test]
    fn every_wrong_tag_and_version_fails_closed() {
        let bytes = canonical_reference(id(0x11));
        for (offset, expected) in [
            (0, FIRST_CHILD_ANCHOR_REFERENCE_TAG),
            (1, FIRST_CHILD_ANCHOR_REFERENCE_VERSION),
        ] {
            for value in u8::MIN..=u8::MAX {
                if value == expected {
                    continue;
                }
                let mut changed = bytes.clone();
                changed[offset] = value;
                assert!(matches!(
                    UnverifiedFirstChildAnchorReference::from_canonical_bytes(&changed),
                    Err(DecodeError::UnknownTag {
                        offset: actual_offset,
                        value: actual_value,
                    }) if actual_offset == offset && actual_value == value
                ));
            }
        }
    }

    #[test]
    fn trailing_bytes_fail_closed() {
        let bytes = canonical_reference(id(0x11));
        for suffix in [&[0_u8][..], &[0xff][..], &[0, 0xff][..]] {
            let mut changed = bytes.clone();
            changed.extend_from_slice(suffix);
            assert!(matches!(
                UnverifiedFirstChildAnchorReference::from_canonical_bytes(&changed),
                Err(DecodeError::TrailingBytes { .. })
            ));
        }
    }

    #[test]
    fn exact_match_promotes_and_copies_only_pinned_context() {
        let anchor = context(id(0x11));
        let candidate = UnverifiedFirstChildAnchorReference::from_canonical_bytes(
            &canonical_reference(anchor.genesis_id()),
        )
        .expect("candidate decodes");
        let verified = candidate.verify(&anchor).expect("exact reference verifies");

        assert_eq!(verified.genesis_id(), anchor.genesis_id());
        assert_eq!(verified.chain_domain(), anchor.chain_domain());
        assert_eq!(
            verified.protocol_manifest_hash(),
            anchor.protocol_manifest_hash()
        );
        assert_eq!(verified.profile_domain(), anchor.profile_domain());
        assert_eq!(
            verified.to_canonical_bytes().expect("verified encodes"),
            canonical_reference(anchor.genesis_id())
        );
    }

    #[test]
    fn mismatched_id_rejects_without_promoting_candidate_context() {
        let anchor = context(id(0x11));
        let candidate = UnverifiedFirstChildAnchorReference::from_canonical_bytes(
            &canonical_reference(id(0x12)),
        )
        .expect("mismatched candidate is structurally canonical");

        assert!(matches!(
            candidate.verify(&anchor),
            Err(BootstrapError::ReferenceMismatch { expected, actual })
                if expected == id(0x11) && actual == id(0x12)
        ));
    }

    #[test]
    fn every_genesis_id_byte_mutation_fails_contextual_verification() {
        let anchor = context(id(0x11));
        let original = canonical_reference(anchor.genesis_id());
        for offset in 2..original.len() {
            let mut changed = original.clone();
            changed[offset] ^= 1;
            let candidate = UnverifiedFirstChildAnchorReference::from_canonical_bytes(&changed)
                .expect("identity mutation remains structurally canonical");
            assert!(matches!(
                candidate.verify(&anchor),
                Err(BootstrapError::ReferenceMismatch { .. })
            ));
        }
    }

    #[test]
    fn cross_type_and_unframed_bytes_do_not_decode() {
        let anchor_id = id(0x11);
        let raw_id = anchor_id.as_bytes();
        let genesis_object_prefix = [0xa1, 1, 0, 0, 0, 0];
        let receipt_prefix = [1, 1, 0, 0, 0];

        assert!(UnverifiedFirstChildAnchorReference::from_canonical_bytes(raw_id).is_err());
        assert!(
            UnverifiedFirstChildAnchorReference::from_canonical_bytes(&genesis_object_prefix)
                .is_err()
        );
        assert!(
            UnverifiedFirstChildAnchorReference::from_canonical_bytes(&receipt_prefix).is_err()
        );
    }
}
