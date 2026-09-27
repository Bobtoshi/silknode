//! Private modular submission; no keys, proof generation, producer fallback or
//! automatic payment retry. Applications get the same versioned interface.
//! Native wallet/prover resource containment remains an operator responsibility;
//! relay two-second leases must not be applied to the wallet/prover process.
#[cfg(unix)]
pub mod v1;
