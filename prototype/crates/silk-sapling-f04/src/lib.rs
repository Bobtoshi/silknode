//! Isolated F0.4 Sapling primitives. Not an activated network or a node.
//!
//! This crate does not import the older Halo2 shielded suite. Cryptographic
//! validity alone grants no DAG work, settlement, mature-cut, or relay authority.

pub mod address;
pub mod codec;
pub mod crypto;
pub mod parameters;
pub mod wallet;

/// Public 256-bit protocol identifier (not a private key).
pub type Digest = [u8; 32];

/// Errors are local to their layer; a caller must not blame peers for resource/I/O failures.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid, noncanonical, unsupported or context-mismatched public bytes.
    #[error("invalid F0.4 encoding: {0}")]
    Encoding(&'static str),
    /// A real Sapling proof or authorization did not verify.
    #[error("Sapling verification failed: {0}")]
    Crypto(&'static str),
    /// Parameters did not match the immutable profile.
    #[error("Sapling parameter identity mismatch: {0}")]
    Parameters(&'static str),
    /// I/O failure, never a cryptographic invalidity result.
    #[error("local I/O failure: {0}")]
    Io(#[from] std::io::Error),
    /// Local capacity refusal; no partially verified result is returned.
    #[error("local resource limit: {0}")]
    Resource(&'static str),
    /// Local intent, key, witness or output round-trip mismatch.
    #[error("private transfer construction refused: {0}")]
    Wallet(&'static str),
}

/// A fallible F0.4 operation.
pub type Result<T> = std::result::Result<T, Error>;
