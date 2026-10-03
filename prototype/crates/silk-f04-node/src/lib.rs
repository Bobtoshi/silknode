//! Private, valueless F0.4 node integration. No implicit legacy-profile activation.

#[cfg(test)]
extern crate self as silk_f04_node;

pub mod address;
pub mod auth;
pub mod budget;
pub mod capacity;
pub mod carriage;
mod core;
mod deadline;
pub mod economics;
pub mod genesis;
pub mod graph;
pub mod node;
pub mod offer;
mod parent;
mod quantum;
pub mod scanner;
pub mod state;
mod store;
pub mod sync;
pub(crate) mod wire;

pub use silk_sapling_f04::Digest;
pub use silk_types::VertexId;

/// Protocol rejection is distinct from local unavailable/resource/storage failures.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Canonical protocol or authorization check failed.
    #[error("F0.4 invalid: {0}")]
    Invalid(&'static str),
    /// Local input, history, clock or processing capability is unavailable.
    #[error("F0.4 unavailable: {0}")]
    Unavailable(&'static str),
    /// Local storage or resource budget is exhausted; not peer invalidity.
    #[error("F0.4 paused: {0}")]
    Paused(&'static str),
    /// Local I/O failure.
    #[error("F0.4 I/O: {0}")]
    Io(#[from] std::io::Error),
    /// Real cryptographic primitive result (including its distinct local errors).
    #[error(transparent)]
    Sapling(#[from] silk_sapling_f04::Error),
    /// SG-0 graph derivation refused.
    #[error(transparent)]
    Order(#[from] silk_order::sg0_v1::Sg0Error),
}

/// Fallible node operation.
pub type Result<T> = std::result::Result<T, Error>;
