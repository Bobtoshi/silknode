#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Deterministic materialization of `SilkNode`'s non-PoW genesis state anchor.
//!
//! A [`GenesisObject`] binds the already validated genesis profile to the
//! already materialized transparent checkpoint-zero state. It is deliberately
//! distinct from a proof-of-work vertex: it has no parents, target, work,
//! timestamp, reward, or nonce, and its [`GenesisId`] is not a
//! [`silk_types::VertexId`]. The first mined child and its bootstrap `PoW` rules
//! remain a separate protocol contract.

use silk_kernel::{KernelError, MaterializedGenesis};
use silk_profile::{ExecutionProfile, GenesisObjectTemplate};
use silk_types::{
    CanonicalDecode, CanonicalEncode, ChainDomain, CheckpointId, DecodeError, Decoder,
    DomainHashError, EncodeError, Encoder, GenesisAllocationTemplateHash, GenesisCommitment,
    GenesisId, Hash32, ManifestHash, ProfileDomain, derive_unverified_genesis_object_digest,
};
use thiserror::Error;

/// Stable top-level tag for a materialized genesis object.
pub const GENESIS_OBJECT_TAG: u8 = 0xA1;
/// Stable wire-format version of the materialized genesis object.
pub const GENESIS_OBJECT_VERSION: u8 = 1;
/// Exact byte length of a version-one canonical genesis object.
pub const GENESIS_OBJECT_V1_ENCODED_LENGTH: usize = 230;

const GENESIS_OBJECT_TAGS: &[u8] = &[GENESIS_OBJECT_TAG];
const GENESIS_OBJECT_VERSIONS: &[u8] = &[GENESIS_OBJECT_VERSION];

/// A materialized-object field whose supplied value differed from recomputation.
///
/// Variant order is the fixed mismatch precedence used by
/// [`UnverifiedGenesisObject::verify`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenesisObjectField {
    /// Literal protocol major retained by the trusted genesis-object template.
    ProtocolMajor,
    /// Hash of the exact chain-independent allocation-template bytes.
    GenesisAllocationTemplateHash,
    /// Five-input non-circular genesis commitment.
    GenesisCommitment,
    /// Immutable chain domain derived from the genesis commitment.
    ChainDomain,
    /// Hash of the exact activated genesis protocol manifest.
    ProtocolManifestHash,
    /// Domain of the exact activated genesis protocol profile.
    ProfileDomain,
    /// Digest of the complete checkpoint-zero logical state.
    CheckpointZeroStateDigest,
    /// Identifier derived from the checkpoint-zero logical-state digest.
    CheckpointZeroId,
}

/// A literal template field whose final-object projection did not match.
///
/// Variant order is the fixed projection-mismatch precedence used during
/// materialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenesisObjectTemplateField {
    /// Literal protocol major differs from the trusted template.
    ProtocolMajor,
    /// Literal allocation-template hash differs from the trusted template.
    GenesisAllocationTemplateHash,
}

/// Failure to materialize or authenticate a genesis object.
#[derive(Debug, Error)]
pub enum GenesisObjectError {
    /// Checkpoint-zero or its reduced derivation receipt failed verification.
    #[error(transparent)]
    Kernel(#[from] KernelError),
    /// Canonical byte construction failed.
    #[error(transparent)]
    Encode(#[from] EncodeError),
    /// Domain-separated genesis-ID hashing failed.
    #[error(transparent)]
    Hash(#[from] DomainHashError),
    /// A final object did not project back to the retained trusted template.
    #[error("genesis object projection differs from trusted template at {field:?}")]
    TemplateProjectionMismatch {
        /// First mismatching literal field in fixed projection order.
        field: GenesisObjectTemplateField,
    },
    /// A supplied materialized object differed from deterministic recomputation.
    #[error("genesis object field {field:?} does not match recomputed value")]
    ObjectMismatch {
        /// First mismatching field in fixed materialized-object order.
        field: GenesisObjectField,
    },
    /// A fully verified object's content ID differed from an expected identity.
    #[error("genesis id {actual} does not match expected id {expected}")]
    GenesisIdMismatch {
        /// Genesis ID supplied by a generic matcher or fixed release boundary.
        expected: GenesisId,
        /// Genesis ID recomputed from the exact canonical object.
        actual: GenesisId,
    },
}

impl GenesisObjectError {
    /// Returns a stable language-neutral error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Kernel(error) => error.code(),
            Self::Encode(error) => error.code(),
            Self::Hash(error) => error.code(),
            Self::TemplateProjectionMismatch { .. } => "genesis.template_projection_mismatch",
            Self::ObjectMismatch { .. } => "genesis.object_mismatch",
            Self::GenesisIdMismatch { .. } => "genesis.id_mismatch",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GenesisObjectFields {
    protocol_major: u32,
    genesis_allocation_template_hash: GenesisAllocationTemplateHash,
    genesis_commitment: GenesisCommitment,
    chain_domain: ChainDomain,
    protocol_manifest_hash: ManifestHash,
    profile_domain: ProfileDomain,
    checkpoint_zero_state_digest: Hash32,
    checkpoint_zero_id: CheckpointId,
}

impl GenesisObjectFields {
    fn verify_template_projection(
        &self,
        template: &GenesisObjectTemplate,
    ) -> Result<(), GenesisObjectError> {
        if self.protocol_major != template.protocol_major() {
            return Err(GenesisObjectError::TemplateProjectionMismatch {
                field: GenesisObjectTemplateField::ProtocolMajor,
            });
        }
        if self.genesis_allocation_template_hash != template.genesis_allocation_template_hash() {
            return Err(GenesisObjectError::TemplateProjectionMismatch {
                field: GenesisObjectTemplateField::GenesisAllocationTemplateHash,
            });
        }
        Ok(())
    }

    fn verify_fields(&self, expected: &Self) -> Result<(), GenesisObjectError> {
        let fields = [
            (
                self.protocol_major == expected.protocol_major,
                GenesisObjectField::ProtocolMajor,
            ),
            (
                self.genesis_allocation_template_hash == expected.genesis_allocation_template_hash,
                GenesisObjectField::GenesisAllocationTemplateHash,
            ),
            (
                self.genesis_commitment == expected.genesis_commitment,
                GenesisObjectField::GenesisCommitment,
            ),
            (
                self.chain_domain == expected.chain_domain,
                GenesisObjectField::ChainDomain,
            ),
            (
                self.protocol_manifest_hash == expected.protocol_manifest_hash,
                GenesisObjectField::ProtocolManifestHash,
            ),
            (
                self.profile_domain == expected.profile_domain,
                GenesisObjectField::ProfileDomain,
            ),
            (
                self.checkpoint_zero_state_digest == expected.checkpoint_zero_state_digest,
                GenesisObjectField::CheckpointZeroStateDigest,
            ),
            (
                self.checkpoint_zero_id == expected.checkpoint_zero_id,
                GenesisObjectField::CheckpointZeroId,
            ),
        ];
        for (matches, field) in fields {
            if !matches {
                return Err(GenesisObjectError::ObjectMismatch { field });
            }
        }
        Ok(())
    }

    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_u8(GENESIS_OBJECT_TAG);
        encoder.write_u8(GENESIS_OBJECT_VERSION);
        encoder.write_u32(self.protocol_major);
        self.genesis_allocation_template_hash.encode(encoder)?;
        self.genesis_commitment.encode(encoder)?;
        self.chain_domain.encode(encoder)?;
        self.protocol_manifest_hash.encode(encoder)?;
        self.profile_domain.encode(encoder)?;
        self.checkpoint_zero_state_digest.encode(encoder)?;
        self.checkpoint_zero_id.encode(encoder)
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decoder.read_tag(GENESIS_OBJECT_TAGS)?;
        decoder.read_tag(GENESIS_OBJECT_VERSIONS)?;
        Ok(Self {
            protocol_major: decoder.read_u32()?,
            genesis_allocation_template_hash: GenesisAllocationTemplateHash::decode(decoder)?,
            genesis_commitment: GenesisCommitment::decode(decoder)?,
            chain_domain: ChainDomain::decode(decoder)?,
            protocol_manifest_hash: ManifestHash::decode(decoder)?,
            profile_domain: ProfileDomain::decode(decoder)?,
            checkpoint_zero_state_digest: Hash32::decode(decoder)?,
            checkpoint_zero_id: CheckpointId::decode(decoder)?,
        })
    }
}

/// Verified materialized state anchor for one `SilkNode` genesis.
///
/// The only public construction paths are [`GenesisObject::materialize`] and
/// [`UnverifiedGenesisObject::verify`]. Canonical bytes deliberately decode as
/// [`UnverifiedGenesisObject`], never this type. All fields remain private.
///
/// ```compile_fail
/// use silk_genesis::GenesisObject;
/// use silk_types::CanonicalDecode;
///
/// let _ = GenesisObject::from_canonical_bytes(&[]);
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenesisObject {
    fields: GenesisObjectFields,
}

impl GenesisObject {
    /// Materializes the exact non-PoW state anchor from sealed profile and
    /// checkpoint-zero evidence.
    ///
    /// The reduced receipt is verified before any of its values are consumed.
    /// The resulting object's literal projection is then compared with the
    /// exact genesis-object template retained by the sealed execution profile.
    ///
    /// # Errors
    ///
    /// Returns the first checkpoint/receipt failure, followed by the first
    /// literal template-projection mismatch in fixed field order.
    pub fn materialize(
        execution_profile: &ExecutionProfile,
        materialized_genesis: &MaterializedGenesis,
    ) -> Result<Self, GenesisObjectError> {
        let receipt = materialized_genesis.receipt();
        receipt.verify(execution_profile, materialized_genesis.state())?;

        let fields = GenesisObjectFields {
            protocol_major: execution_profile.protocol_major(),
            genesis_allocation_template_hash: execution_profile.genesis_allocation_template_hash(),
            genesis_commitment: receipt.genesis_commitment(),
            chain_domain: receipt.chain_domain(),
            protocol_manifest_hash: receipt.protocol_manifest_hash(),
            profile_domain: receipt.profile_domain(),
            checkpoint_zero_state_digest: receipt.checkpoint_zero_state_digest(),
            checkpoint_zero_id: receipt.checkpoint_zero_id(),
        };
        fields.verify_template_projection(execution_profile.genesis_object_template())?;
        Ok(Self { fields })
    }

    /// Derives the content ID of the exact canonical genesis object.
    ///
    /// This identifier belongs only to the non-PoW state anchor. It is never a
    /// proof-of-work vertex identifier, contributes no work, and creates no
    /// mining reward or mining-issuance event. The object still commits the
    /// valueless genesis allocation and its initialized `native_issued`
    /// accounting state.
    ///
    /// # Errors
    ///
    /// Returns a canonical encoding or domain-hash framing error.
    pub fn id(&self) -> Result<GenesisId, GenesisObjectError> {
        let bytes = self.to_canonical_bytes()?;
        let digest = derive_unverified_genesis_object_digest(&bytes)?;
        Ok(GenesisId::new(digest.into_hash()))
    }

    /// Returns the literal genesis protocol major.
    #[must_use]
    pub const fn protocol_major(&self) -> u32 {
        self.fields.protocol_major
    }

    /// Returns the exact allocation-template byte hash.
    #[must_use]
    pub const fn genesis_allocation_template_hash(&self) -> GenesisAllocationTemplateHash {
        self.fields.genesis_allocation_template_hash
    }

    /// Returns the non-circular genesis commitment.
    #[must_use]
    pub const fn genesis_commitment(&self) -> GenesisCommitment {
        self.fields.genesis_commitment
    }

    /// Returns the immutable chain domain.
    #[must_use]
    pub const fn chain_domain(&self) -> ChainDomain {
        self.fields.chain_domain
    }

    /// Returns the exact activated genesis manifest hash.
    #[must_use]
    pub const fn protocol_manifest_hash(&self) -> ManifestHash {
        self.fields.protocol_manifest_hash
    }

    /// Returns the exact activated genesis profile domain.
    #[must_use]
    pub const fn profile_domain(&self) -> ProfileDomain {
        self.fields.profile_domain
    }

    /// Returns the checkpoint-zero logical-state digest.
    #[must_use]
    pub const fn checkpoint_zero_state_digest(&self) -> Hash32 {
        self.fields.checkpoint_zero_state_digest
    }

    /// Returns the checkpoint-zero identifier.
    #[must_use]
    pub const fn checkpoint_zero_id(&self) -> CheckpointId {
        self.fields.checkpoint_zero_id
    }
}

impl CanonicalEncode for GenesisObject {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.fields.encode(encoder)
    }
}

/// Canonically decoded but unauthenticated genesis-object candidate.
///
/// This type exposes only canonical re-encoding and consuming verification.
/// It has no typed field getters and cannot derive a [`GenesisId`]. Successful
/// verification returns a separately constructed [`GenesisObject`] after
/// deterministic recomputation from a sealed profile and checkpoint zero.
///
/// ```compile_fail
/// use silk_genesis::UnverifiedGenesisObject;
///
/// fn cannot_derive_id(candidate: &UnverifiedGenesisObject) {
///     let _ = candidate.id();
/// }
/// ```
///
/// ```compile_fail
/// use silk_genesis::UnverifiedGenesisObject;
///
/// fn cannot_read_trusted_fields(candidate: &UnverifiedGenesisObject) {
///     let _ = candidate.chain_domain();
/// }
/// ```
///
/// ```compile_fail
/// use silk_genesis::{GenesisObjectPin, UnverifiedGenesisObject};
///
/// fn cannot_cross_pin(pin: &GenesisObjectPin, candidate: &UnverifiedGenesisObject) {
///     let _ = pin.verify(candidate);
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnverifiedGenesisObject {
    fields: GenesisObjectFields,
}

impl UnverifiedGenesisObject {
    /// Recomputes the expected object and promotes this candidate only on an
    /// exact field match.
    ///
    /// The sealed execution profile and materialized checkpoint zero are
    /// verified before candidate fields are compared. Candidate mismatches use
    /// [`GenesisObjectField`] order. The returned verified value is the freshly
    /// recomputed object rather than a reinterpretation of untrusted storage.
    ///
    /// # Errors
    ///
    /// Returns the first materialization failure or candidate-field mismatch.
    pub fn verify(
        self,
        execution_profile: &ExecutionProfile,
        materialized_genesis: &MaterializedGenesis,
    ) -> Result<GenesisObject, GenesisObjectError> {
        let expected = GenesisObject::materialize(execution_profile, materialized_genesis)?;
        self.fields.verify_fields(&expected.fields)?;
        Ok(expected)
    }
}

impl CanonicalEncode for UnverifiedGenesisObject {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.fields.encode(encoder)
    }
}

impl CanonicalDecode for UnverifiedGenesisObject {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            fields: GenesisObjectFields::decode(decoder)?,
        })
    }
}

/// Generic expected-identity matcher for one fully verified genesis object.
///
/// Constructing this value does not establish release provenance or trusted
/// configuration: any caller can choose its expected ID. A higher-level release
/// boundary must fix the expected ID independently and must not accept a
/// caller-provided `GenesisObjectPin` as release authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenesisObjectPin {
    expected_genesis_id: GenesisId,
}

impl GenesisObjectPin {
    /// Creates a generic matcher for one expected genesis object ID.
    ///
    /// This constructor records caller-chosen data; it does not make that data
    /// an official or trusted release identity.
    #[must_use]
    pub const fn new(expected_genesis_id: GenesisId) -> Self {
        Self {
            expected_genesis_id,
        }
    }

    /// Returns the expected genesis object ID.
    #[must_use]
    pub const fn expected_genesis_id(&self) -> GenesisId {
        self.expected_genesis_id
    }

    /// Checks the expected content ID of an already verified object.
    ///
    /// Unverified candidates cannot be passed to this method. They must first
    /// be promoted through [`UnverifiedGenesisObject::verify`], which performs
    /// the sealed profile, checkpoint-zero, receipt, template, and field checks.
    ///
    /// # Errors
    ///
    /// Returns a hashing error or [`GenesisObjectError::GenesisIdMismatch`].
    pub fn verify(&self, object: &GenesisObject) -> Result<GenesisId, GenesisObjectError> {
        let actual = object.id()?;
        self.verify_id(actual)?;
        Ok(actual)
    }

    fn verify_id(&self, actual: GenesisId) -> Result<(), GenesisObjectError> {
        if actual != self.expected_genesis_id {
            return Err(GenesisObjectError::GenesisIdMismatch {
                expected: self.expected_genesis_id,
                actual,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use silk_types::{domain_hash, hash_domains};

    fn hash(byte: u8) -> Hash32 {
        Hash32::new([byte; Hash32::LENGTH])
    }

    fn object() -> GenesisObject {
        GenesisObject {
            fields: object_fields(),
        }
    }

    fn object_fields() -> GenesisObjectFields {
        GenesisObjectFields {
            protocol_major: 0x0403_0201,
            genesis_allocation_template_hash: GenesisAllocationTemplateHash::new(hash(0x11)),
            genesis_commitment: GenesisCommitment::new(hash(0x22)),
            chain_domain: ChainDomain::new(hash(0x33)),
            protocol_manifest_hash: ManifestHash::new(hash(0x44)),
            profile_domain: ProfileDomain::new(hash(0x55)),
            checkpoint_zero_state_digest: hash(0x66),
            checkpoint_zero_id: CheckpointId::new(hash(0x77)),
        }
    }

    fn candidate() -> UnverifiedGenesisObject {
        UnverifiedGenesisObject {
            fields: object_fields(),
        }
    }

    fn first_mismatch(
        candidate: &UnverifiedGenesisObject,
        expected: &GenesisObject,
    ) -> GenesisObjectField {
        match candidate.fields.verify_fields(&expected.fields) {
            Err(GenesisObjectError::ObjectMismatch { field }) => field,
            other => panic!("expected exact object mismatch, received {other:?}"),
        }
    }

    fn template(
        protocol_major: u32,
        allocation_hash: GenesisAllocationTemplateHash,
    ) -> GenesisObjectTemplate {
        let mut encoder = Encoder::new();
        encoder.write_u8(0xa0);
        encoder.write_u8(1);
        encoder.write_u32(protocol_major);
        allocation_hash
            .encode(&mut encoder)
            .expect("fixed hash encodes");
        for recipe in 1_u8..=6 {
            encoder.write_fixed(&[0_u8; Hash32::LENGTH]);
            encoder.write_u8(recipe);
        }
        GenesisObjectTemplate::from_canonical_bytes(&encoder.into_bytes())
            .expect("closed fixture template decodes")
    }

    #[test]
    fn version_one_layout_is_exact_and_little_endian() {
        let bytes = object().to_canonical_bytes().expect("object encodes");
        assert_eq!(bytes.len(), GENESIS_OBJECT_V1_ENCODED_LENGTH);
        assert_eq!(&bytes[..2], &[GENESIS_OBJECT_TAG, GENESIS_OBJECT_VERSION]);
        assert_eq!(&bytes[2..6], &[1, 2, 3, 4]);
        assert_eq!(&bytes[6..38], &[0x11; 32]);
        assert_eq!(&bytes[38..70], &[0x22; 32]);
        assert_eq!(&bytes[70..102], &[0x33; 32]);
        assert_eq!(&bytes[102..134], &[0x44; 32]);
        assert_eq!(&bytes[134..166], &[0x55; 32]);
        assert_eq!(&bytes[166..198], &[0x66; 32]);
        assert_eq!(&bytes[198..230], &[0x77; 32]);
    }

    #[test]
    fn canonical_round_trip_preserves_every_field() {
        let expected = object();
        let bytes = expected.to_canonical_bytes().expect("object encodes");
        let decoded = UnverifiedGenesisObject::from_canonical_bytes(&bytes)
            .expect("object candidate decodes");
        assert_eq!(decoded.fields, expected.fields);
        assert_eq!(
            decoded.to_canonical_bytes().expect("candidate re-encodes"),
            bytes
        );
    }

    #[test]
    fn every_truncation_fails_closed() {
        let bytes = object().to_canonical_bytes().expect("object encodes");
        for end in 0..bytes.len() {
            assert!(
                UnverifiedGenesisObject::from_canonical_bytes(&bytes[..end]).is_err(),
                "truncation at {end} unexpectedly decoded"
            );
        }
    }

    #[test]
    fn trailing_bytes_fail_closed() {
        let mut bytes = object().to_canonical_bytes().expect("object encodes");
        bytes.push(0);
        assert!(matches!(
            UnverifiedGenesisObject::from_canonical_bytes(&bytes),
            Err(DecodeError::TrailingBytes {
                offset: GENESIS_OBJECT_V1_ENCODED_LENGTH,
                remaining: 1
            })
        ));
    }

    #[test]
    fn object_tag_and_version_are_independently_closed() {
        let canonical = object().to_canonical_bytes().expect("object encodes");
        for (offset, value) in [(0, 0xa0), (0, 0xa2), (1, 0), (1, 2)] {
            let mut bytes = canonical.clone();
            bytes[offset] = value;
            assert!(matches!(
                UnverifiedGenesisObject::from_canonical_bytes(&bytes),
                Err(DecodeError::UnknownTag { offset: actual, value: actual_value })
                    if actual == offset && actual_value == value
            ));
        }
    }

    #[test]
    fn genesis_id_uses_exact_object_bytes_as_one_framed_part() {
        let object = object();
        let bytes = object.to_canonical_bytes().expect("object encodes");
        let expected =
            domain_hash(hash_domains::GENESIS_OBJECT, &[&bytes]).expect("fixture hash frames");
        assert_eq!(object.id().expect("object id derives").as_hash(), &expected);
    }

    #[test]
    fn every_object_field_is_id_bound() {
        let canonical = object();
        let canonical_id = canonical.id().expect("canonical id derives");
        let bytes = canonical
            .to_canonical_bytes()
            .expect("canonical object encodes");
        for offset in [2, 6, 38, 70, 102, 134, 166, 198] {
            let mut mutated = bytes.clone();
            mutated[offset] ^= 1;
            let decoded = UnverifiedGenesisObject::from_canonical_bytes(&mutated)
                .expect("mutation stays structural");
            assert_eq!(
                decoded.to_canonical_bytes().expect("candidate re-encodes"),
                mutated
            );
            assert_ne!(
                derive_unverified_genesis_object_digest(&mutated)
                    .expect("mutated candidate digest derives")
                    .as_hash(),
                canonical_id.as_hash(),
                "field beginning at {offset} was not ID-bound"
            );
        }
    }

    #[test]
    fn candidate_mismatch_precedence_is_fixed() {
        let expected = object();
        let mut candidate = candidate();
        candidate.fields.protocol_major ^= 1;
        candidate.fields.genesis_allocation_template_hash =
            GenesisAllocationTemplateHash::new(hash(0x91));
        candidate.fields.genesis_commitment = GenesisCommitment::new(hash(0x92));
        candidate.fields.chain_domain = ChainDomain::new(hash(0x93));
        candidate.fields.protocol_manifest_hash = ManifestHash::new(hash(0x94));
        candidate.fields.profile_domain = ProfileDomain::new(hash(0x95));
        candidate.fields.checkpoint_zero_state_digest = hash(0x96);
        candidate.fields.checkpoint_zero_id = CheckpointId::new(hash(0x97));

        assert_eq!(
            first_mismatch(&candidate, &expected),
            GenesisObjectField::ProtocolMajor
        );

        candidate.fields.protocol_major = expected.fields.protocol_major;
        assert_eq!(
            first_mismatch(&candidate, &expected),
            GenesisObjectField::GenesisAllocationTemplateHash
        );
        candidate.fields.genesis_allocation_template_hash =
            expected.fields.genesis_allocation_template_hash;
        assert_eq!(
            first_mismatch(&candidate, &expected),
            GenesisObjectField::GenesisCommitment
        );
        candidate.fields.genesis_commitment = expected.fields.genesis_commitment;
        assert_eq!(
            first_mismatch(&candidate, &expected),
            GenesisObjectField::ChainDomain
        );
        candidate.fields.chain_domain = expected.fields.chain_domain;
        assert_eq!(
            first_mismatch(&candidate, &expected),
            GenesisObjectField::ProtocolManifestHash
        );
        candidate.fields.protocol_manifest_hash = expected.fields.protocol_manifest_hash;
        assert_eq!(
            first_mismatch(&candidate, &expected),
            GenesisObjectField::ProfileDomain
        );
        candidate.fields.profile_domain = expected.fields.profile_domain;
        assert_eq!(
            first_mismatch(&candidate, &expected),
            GenesisObjectField::CheckpointZeroStateDigest
        );
        candidate.fields.checkpoint_zero_state_digest =
            expected.fields.checkpoint_zero_state_digest;
        assert_eq!(
            first_mismatch(&candidate, &expected),
            GenesisObjectField::CheckpointZeroId
        );
        candidate.fields.checkpoint_zero_id = expected.fields.checkpoint_zero_id;
        assert!(candidate.fields.verify_fields(&expected.fields).is_ok());
    }

    #[test]
    fn template_projection_checks_both_literals_in_fixed_order() {
        let object = object();
        let matching = template(
            object.protocol_major(),
            object.genesis_allocation_template_hash(),
        );
        assert!(object.fields.verify_template_projection(&matching).is_ok());

        let both_wrong = template(
            object.protocol_major() ^ 1,
            GenesisAllocationTemplateHash::new(hash(0x90)),
        );
        assert!(matches!(
            object.fields.verify_template_projection(&both_wrong),
            Err(GenesisObjectError::TemplateProjectionMismatch {
                field: GenesisObjectTemplateField::ProtocolMajor
            })
        ));

        let allocation_wrong = template(
            object.protocol_major(),
            GenesisAllocationTemplateHash::new(hash(0x90)),
        );
        assert!(matches!(
            object.fields.verify_template_projection(&allocation_wrong),
            Err(GenesisObjectError::TemplateProjectionMismatch {
                field: GenesisObjectTemplateField::GenesisAllocationTemplateHash
            })
        ));
    }

    #[test]
    fn pin_reports_only_an_exact_id_mismatch() {
        let object = object();
        let actual = object.id().expect("object id derives");
        let matching = GenesisObjectPin::new(actual);
        assert_eq!(
            matching.verify(&object).expect("matching pin verifies"),
            actual
        );

        let expected = GenesisId::new(hash(0x99));
        let mismatching = GenesisObjectPin::new(expected);
        assert!(matches!(
            mismatching.verify(&object),
            Err(GenesisObjectError::GenesisIdMismatch {
                expected: error_expected,
                actual: error_actual
            }) if error_expected == expected && error_actual == actual
        ));
    }
}
