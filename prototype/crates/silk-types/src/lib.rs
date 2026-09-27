#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Consensus-safe primitive types for the `SilkNode` Gate A prototype.
//!
//! This crate deliberately implements a small wire-format surface:
//!
//! - integers are fixed-width and little-endian;
//! - variable-length byte strings and lists carry a little-endian `u32` length;
//! - callers must provide decode limits before allocation;
//! - set-like lists must arrive strictly sorted and unique; and
//! - top-level decoding rejects trailing bytes.
//!
//! Rust layouts, collection iteration order, and platform-sized integers never
//! enter the consensus encoding.

mod canonical;
mod domains;
mod identifiers;

pub use canonical::{
    CanonicalDecode, CanonicalEncode, CollectionError, DecodeError, Decoder, EncodeError, Encoder,
    decode_exact, validate_sorted_unique,
};
pub use domains::{
    DOMAIN_HASH_TRANSCRIPT_V1, DomainHashError, derive_chain_domain,
    derive_genesis_allocation_template_hash, derive_genesis_commitment, derive_profile_domain,
    derive_unverified_genesis_object_digest, domain_hash, hash_canonical, hash_domains,
};
pub use identifiers::{
    BodyCommitment, ChainDomain, CheckpointId, EffectDigest, FixedLengthError,
    GateAGenesisReceiptTemplateHash, GenesisAllocationTemplateHash, GenesisCommitment, GenesisId,
    GenesisManifestTemplateHash, GenesisObjectTemplateHash, Hash32, IntentId, ManifestHash,
    ModuleId, NoteCommitment, Nullifier, ProfileDomain, SuiteId, UnverifiedGenesisObjectDigest,
    VertexId,
};
