//! Fixed-size hashes and semantically distinct consensus identifiers.

use core::fmt;

use thiserror::Error;

use crate::{CanonicalDecode, CanonicalEncode, DecodeError, Decoder, EncodeError, Encoder};

/// Error returned when a fixed-size identifier is constructed from the wrong number of bytes.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("expected {expected} bytes, received {actual}")]
pub struct FixedLengthError {
    /// Required byte length.
    pub expected: usize,
    /// Supplied byte length.
    pub actual: usize,
}

/// A generic 32-byte digest.
///
/// Ordering is lexicographic byte order and is therefore suitable for canonical
/// sorted collections. Protocol fields with distinct semantics should use one
/// of the strong identifier wrappers instead of this generic type.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Hash32([u8; Self::LENGTH]);

impl Hash32 {
    /// Digest length in bytes.
    pub const LENGTH: usize = 32;

    /// The all-zero digest, for specification fields that explicitly permit a zero sentinel.
    pub const ZERO: Self = Self([0; Self::LENGTH]);

    /// Constructs a digest from exactly 32 bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }

    /// Consumes the digest and returns its bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; Self::LENGTH] {
        self.0
    }

    /// Copies a digest from a byte slice of exactly 32 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`FixedLengthError`] when the slice length is not 32.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, FixedLengthError> {
        let array = <[u8; Self::LENGTH]>::try_from(bytes).map_err(|_| FixedLengthError {
            expected: Self::LENGTH,
            actual: bytes.len(),
        })?;
        Ok(Self(array))
    }
}

impl AsRef<[u8]> for Hash32 {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl From<[u8; Self::LENGTH]> for Hash32 {
    fn from(bytes: [u8; Self::LENGTH]) -> Self {
        Self::new(bytes)
    }
}

impl TryFrom<&[u8]> for Hash32 {
    type Error = FixedLengthError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(bytes)
    }
}

impl fmt::Display for Hash32 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Hash32 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Hash32({self})")
    }
}

impl CanonicalEncode for Hash32 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_fixed(self.as_bytes());
        Ok(())
    }
}

impl CanonicalDecode for Hash32 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self::new(decoder.read_fixed()?))
    }
}

macro_rules! define_hash_identifier {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Hash32);

        impl $name {
            /// The all-zero value, only for fields whose schema explicitly permits a sentinel.
            pub const ZERO: Self = Self(Hash32::ZERO);

            /// Constructs the identifier from a generic digest.
            ///
            /// This is a representation primitive, not proof that the digest
            /// was produced by the protocol checks associated with this type.
            #[must_use]
            pub const fn new(hash: Hash32) -> Self {
                Self(hash)
            }

            /// Constructs the identifier from exactly 32 bytes.
            ///
            /// This is a representation primitive, not a validity token.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; Hash32::LENGTH]) -> Self {
                Self(Hash32::new(bytes))
            }

            /// Returns the identifier as its generic digest.
            #[must_use]
            pub const fn as_hash(&self) -> &Hash32 {
                &self.0
            }

            /// Returns the identifier bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; Hash32::LENGTH] {
                self.0.as_bytes()
            }

            /// Consumes the identifier and returns its generic digest.
            #[must_use]
            pub const fn into_hash(self) -> Hash32 {
                self.0
            }

            /// Consumes the identifier and returns its bytes.
            #[must_use]
            pub const fn into_bytes(self) -> [u8; Hash32::LENGTH] {
                self.0.into_bytes()
            }

            /// Copies the identifier from a byte slice of exactly 32 bytes.
            ///
            /// This parses the representation only; it does not authenticate
            /// the semantic provenance of the supplied bytes.
            ///
            /// # Errors
            ///
            /// Returns [`FixedLengthError`] when the slice length is not 32.
            pub fn from_slice(bytes: &[u8]) -> Result<Self, FixedLengthError> {
                Hash32::from_slice(bytes).map(Self)
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                self.as_bytes()
            }
        }

        impl From<Hash32> for $name {
            fn from(hash: Hash32) -> Self {
                Self::new(hash)
            }
        }

        impl From<$name> for Hash32 {
            fn from(identifier: $name) -> Self {
                identifier.into_hash()
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = FixedLengthError;

            fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
                Self::from_slice(bytes)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "{}({})", stringify!($name), self.0)
            }
        }

        impl CanonicalEncode for $name {
            fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
                self.0.encode(encoder)
            }
        }

        impl CanonicalDecode for $name {
            fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
                Ok(Self(Hash32::decode(decoder)?))
            }
        }
    };
}

define_hash_identifier!(
    /// Immutable identity of one network/genesis and its long-lived value domain.
    ChainDomain
);
define_hash_identifier!(
    /// Hash of the canonical chain-independent genesis manifest projection.
    GenesisManifestTemplateHash
);
define_hash_identifier!(
    /// Hash of the exact canonical chain-independent genesis allocation template.
    GenesisAllocationTemplateHash
);
define_hash_identifier!(
    /// Hash of the canonical chain-independent genesis object projection.
    GenesisObjectTemplateHash
);
define_hash_identifier!(
    /// Historical A2a-5 hash of the detached reduced genesis-receipt template.
    ///
    /// This type is deliberately distinct from [`GenesisObjectTemplateHash`].
    /// The historical digest occupied the object-template slot before A2a-6,
    /// but current genesis derivation must not accept it as that slot's value.
    /// Converting through [`Hash32`] and constructing another strong type is an
    /// explicit escape hatch rather than an implicit semantic substitution.
    ///
    /// ```compile_fail
    /// use silk_types::{
    ///     GateAGenesisReceiptTemplateHash, GenesisManifestTemplateHash, Hash32,
    ///     derive_genesis_commitment,
    /// };
    ///
    /// let historical_receipt_hash = GateAGenesisReceiptTemplateHash::ZERO;
    /// let _ = derive_genesis_commitment(
    ///     b"network",
    ///     Hash32::ZERO,
    ///     GenesisManifestTemplateHash::ZERO,
    ///     b"allocation",
    ///     historical_receipt_hash,
    /// );
    /// ```
    GateAGenesisReceiptTemplateHash
);
define_hash_identifier!(
    /// Commitment from which one immutable chain domain is derived.
    GenesisCommitment
);
define_hash_identifier!(
    /// Identity of the canonical deterministic non-PoW genesis state anchor.
    ///
    /// This type is deliberately distinct from [`VertexId`]. The genesis
    /// anchor earns no work or reward and is not an ordinary graph vertex. A
    /// value parsed or constructed from raw bytes is only a representation;
    /// trusted identity requires a verified genesis object and release pin.
    GenesisId
);
define_hash_identifier!(
    /// Domain-separated digest of bytes presented as a genesis object.
    ///
    /// This is deliberately not a [`GenesisId`]: hashing arbitrary bytes does
    /// not prove that they canonically decode or match a sealed execution
    /// profile and its materialized checkpoint zero. A `GenesisId` is derived
    /// only from canonical bytes emitted by a verified object, obtained either
    /// by direct sealed-input materialization or by consuming verification of
    /// a decoded unverified candidate. A manual raw rewrap is a representation
    /// conversion, never evidence that verification occurred.
    ///
    /// ```compile_fail
    /// use silk_types::{
    ///     GenesisId, derive_unverified_genesis_object_digest,
    /// };
    ///
    /// let candidate = derive_unverified_genesis_object_digest(b"untrusted bytes")
    ///     .expect("short input frames");
    /// let _: GenesisId = candidate;
    /// ```
    UnverifiedGenesisObjectDigest
);
define_hash_identifier!(
    /// Identity of one activated consensus-rule profile within a chain domain.
    ProfileDomain
);
define_hash_identifier!(
    /// Content identifier of a fully canonical, fully available `PoW` vertex.
    VertexId
);
define_hash_identifier!(
    /// Gate A commitment to one canonical, fully available execution body.
    BodyCommitment
);
define_hash_identifier!(
    /// Identifier of a deterministic materialized checkpoint.
    CheckpointId
);
define_hash_identifier!(
    /// Anchor-independent identifier of an authorized transaction effect.
    IntentId
);
define_hash_identifier!(
    /// Digest binding the complete public effect authorized by a transaction.
    EffectDigest
);
define_hash_identifier!(
    /// Commitment of one hidden native SILK note.
    NoteCommitment
);
define_hash_identifier!(
    /// Public, position-independent identifier consumed when a note is spent.
    Nullifier
);
define_hash_identifier!(
    /// Content hash of one canonical protocol manifest.
    ManifestHash
);
define_hash_identifier!(
    /// Semantic identity of one consensus module descriptor.
    ModuleId
);
define_hash_identifier!(
    /// Semantic identity of one activated cryptographic suite.
    SuiteId
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_order_is_lexicographic() {
        let mut low = [0_u8; 32];
        low[31] = 1;
        let mut high = [0_u8; 32];
        high[0] = 1;
        assert!(Hash32::new(low) < Hash32::new(high));
    }

    #[test]
    fn fixed_hashes_round_trip_without_length_prefix() {
        let id = VertexId::from_bytes([0xa5; 32]);
        let bytes = id.to_canonical_bytes().expect("identifier encodes");
        assert_eq!(bytes, [0xa5; 32]);
        assert_eq!(VertexId::from_canonical_bytes(&bytes), Ok(id));
    }

    #[test]
    fn fixed_hashes_reject_short_and_long_inputs() {
        assert_eq!(
            Hash32::from_slice(&[0; 31]),
            Err(FixedLengthError {
                expected: 32,
                actual: 31,
            })
        );
        assert_eq!(
            Hash32::from_slice(&[0; 33]),
            Err(FixedLengthError {
                expected: 32,
                actual: 33,
            })
        );
    }

    #[test]
    fn display_is_fixed_lowercase_hex_and_debug_retains_type() {
        let id = Nullifier::from_bytes([0xab; 32]);
        assert_eq!(id.to_string(), "ab".repeat(32));
        assert_eq!(format!("{id:?}"), format!("Nullifier({})", "ab".repeat(32)));
    }

    #[test]
    fn semantic_identifier_types_preserve_bytes_only_by_explicit_conversion() {
        let bytes = [7_u8; 32];
        let chain = ChainDomain::from_bytes(bytes);
        let profile = ProfileDomain::from(Hash32::from(chain));
        assert_eq!(chain.as_bytes(), profile.as_bytes());
        assert_eq!(profile.into_bytes(), bytes);
    }

    #[test]
    fn historical_receipt_hash_requires_an_explicit_raw_rewrap() {
        let historical = GateAGenesisReceiptTemplateHash::from_bytes([0xa5; 32]);
        let object = GenesisObjectTemplateHash::new(historical.into_hash());
        assert_eq!(object.as_bytes(), &[0xa5; 32]);
    }
}
