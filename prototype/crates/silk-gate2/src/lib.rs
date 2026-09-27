#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![allow(clippy::nursery, clippy::pedantic)]

//! Private, valueless Gate 2 transparent state-machine evidence.
//!
//! This crate implements only the frozen synthetic control contract. Public
//! note openings and Boolean authorization markers provide no ownership or
//! privacy. Eligibility and interval pins are harness capabilities, not proof
//! of work, graph order, availability, finality, or authority to issue value.

mod canonical;
mod error;
mod execute;
mod fence;
mod hashes;
mod model;
mod profile;
mod state;

pub use canonical::{
    CanonicalDecode, CanonicalEncode, Decoder, Encoder, TopLevelWire, Unverified, decode_unverified,
};
pub use error::{Error, RejectCode};
pub use execute::*;
pub use fence::*;
pub use hashes::*;
pub use model::*;
pub use profile::*;
pub use state::*;

/// NativeKernel semantic ABI implemented by this crate.
pub const NATIVE_KERNEL_ABI: u16 = 3;
/// Checkpoint semantic ABI implemented by this crate.
pub const CHECKPOINT_ABI: u16 = 4;
/// Maximum inputs in one synthetic envelope.
pub const MAX_INPUTS: usize = 16;
/// Maximum outputs in one synthetic envelope.
pub const MAX_OUTPUTS: usize = 16;
/// Maximum envelopes in one interval.
pub const MAX_ENVELOPES: usize = 4_096;
/// Maximum bodies in one interval.
pub const MAX_BODIES: usize = 1_024;
/// Maximum parents declared by one synthetic namespace.
pub const MAX_PARENTS: usize = 16;
/// Maximum active suite identifiers.
pub const MAX_ACTIVE_SUITES: usize = 4;
/// Maximum retained migration-source suites.
pub const MAX_RETAINED_SUITES: usize = 1;
/// Maximum synthetic reward bands.
pub const MAX_REWARD_BANDS: usize = 16;
/// Maximum recipient roots in one mandate.
pub const MAX_RECIPIENT_ROOTS: usize = 8;
/// Maximum application roots in one mandate.
pub const MAX_APPLICATION_ROOTS: usize = 8;
/// Maximum transparent members in one scope opening.
pub const MAX_SCOPE_MEMBERS: usize = 16;
/// Maximum uninterpreted caveat hashes (zero are accepted by this gate).
pub const MAX_POLICY_CAVEATS: usize = 16;
/// Maximum retained legacy-exit descriptors.
pub const MAX_LEGACY_EXITS: usize = 1;
/// Fixed transparent recovery payload length.
pub const RECOVERY_PAYLOAD_BYTES: usize = 128;
/// Maximum live notes in one synthetic state.
pub const MAX_LIVE_NOTES: usize = 131_072;
/// Maximum nullifiers and commitment/recovery history items.
pub const MAX_NATIVE_HISTORY: usize = 131_072;
/// Maximum accepted intents/effects.
pub const MAX_ACCEPTED_HISTORY: usize = 65_536;
/// Maximum issuance events and cursor value.
pub const MAX_ISSUANCE_EVENTS: usize = 16_384;
/// Maximum ordered body history.
pub const MAX_BODY_HISTORY: usize = 16_384;
/// Maximum accepted effects in one interval.
pub const MAX_INTERVAL_EFFECTS: usize = 4_096;
/// Maximum recovery hashes or records in one envelope.
pub const MAX_RECOVERY_ITEMS: usize = 16;
/// Maximum canonical bytes in one consensus envelope.
pub const MAX_ENVELOPE_BYTES: usize = 262_144;
/// Maximum canonical bytes in one ordered body.
pub const MAX_BODY_BYTES: usize = 16_777_216;
/// Maximum canonical bytes in one ordered interval.
pub const MAX_INTERVAL_BYTES: usize = 67_108_864;
/// Maximum canonical bytes in a native state, result, or checkpoint subject.
pub const MAX_STATE_BYTES: usize = 67_108_864;
/// Maximum canonical bytes in any top-level Gate 2 object.
pub const MAX_TOP_LEVEL_BYTES: usize = 268_435_456;
