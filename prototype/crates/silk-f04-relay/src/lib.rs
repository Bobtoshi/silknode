//! Private F0.4 relay components. No default endpoint, activation or privacy claim.
//! Signature-checked bytes are NOT timing, readiness, custody or release authority.
pub mod config;
pub mod control;
#[cfg(unix)]
mod drain;
#[cfg(unix)]
mod driver;
#[cfg(unix)]
mod epochs;
#[cfg(unix)]
pub mod exit;
#[cfg(unix)]
pub mod exit_owner;
#[cfg(unix)]
pub mod failure;
#[cfg(unix)]
mod flow;
pub mod frame;
#[cfg(unix)]
pub mod handoff;
#[cfg(unix)]
pub mod input;
#[cfg(unix)]
pub mod journal;
#[cfg(unix)]
pub mod lane;
#[cfg(unix)]
pub mod lifecycle;
pub mod manifest;
#[cfg(unix)]
pub mod negotiation;
#[cfg(unix)]
pub mod owner;
#[cfg(unix)]
pub mod producer;
#[cfg(unix)]
pub mod producer_owner;
#[cfg(unix)]
pub mod resources;
#[cfg(unix)]
pub mod runtime;
pub mod schedule;
#[cfg(unix)]
pub mod source;
#[cfg(unix)]
pub mod source_owner;
pub mod staging;
#[cfg(unix)]
pub mod tls;

#[cfg(test)]
mod tests;

pub use silk_sapling_f04::Digest;

/// Local record failure, not a peer-visible response or consensus rejection.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Fixed framing or semantic refusal.
    #[error("F04 relay: {0}")]
    Invalid(&'static str),
    /// Local capability/resource failure, never a mathematical-invalidity claim.
    #[error("F04 relay unavailable: {0}")]
    Unavailable(&'static str),
    /// Exact admitted Appendix C predicate, preserving its ordered ED labels.
    #[error(transparent)]
    Auth(#[from] silk_f04_node::Error),
    /// Local storage/transport failure; never a peer invalidity result.
    #[error("F04 relay I/O: {0}")]
    Io(#[from] std::io::Error),
}
/// Fallible private relay component operation.
pub type Result<T> = std::result::Result<T, Error>;

fn field<const N: usize>(bytes: &[u8], at: usize) -> Result<[u8; N]> {
    bytes
        .get(at..at.checked_add(N).ok_or(Error::Invalid("AUTH_ENCODING"))?)
        .ok_or(Error::Invalid("AUTH_ENCODING"))?
        .try_into()
        .map_err(|_| Error::Invalid("AUTH_ENCODING"))
}
fn u32le(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(field(bytes, at)?))
}
fn u64le(bytes: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(field(bytes, at)?))
}
fn message(label: &'static str, parts: &[&[u8]]) -> Vec<u8> {
    let mut bytes = vec![u8::try_from(label.len()).expect("fixed ASCII label")];
    bytes.extend_from_slice(label.as_bytes());
    for part in parts {
        bytes.extend_from_slice(part);
    }
    bytes
}
