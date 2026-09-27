#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! A deterministic, checkpoint-isolated interpreter for one native test asset.
//!
//! This is a transparent Gate A control implementation. [`TransparentWitness`]
//! exposes note openings and uses an explicit Boolean authorization marker. It
//! provides **no cryptographic privacy or ownership security** and must never be
//! used with valuable balances. Its purpose is to make ordering, checkpoint
//! isolation, nullifier uniqueness, recovery-data gating, conservation, replay,
//! and rollback behavior executable before a proof system is selected.
//!
//! Genesis and every checkpoint application pass through a sealed
//! [`TransparentExecutionHost`]. It accepts only a release-pinned
//! [`silk_profile::ExecutionProfile`] whose native-kernel and checkpoint
//! semantic module identities and ABI versions exactly match the descriptors
//! compiled into this crate. The profile also binds chain and profile identity
//! plus the trusted hash of one versioned, chain-independent, no-value
//! transparent allocation template. Successful genesis returns checkpoint zero
//! with a canonical reduced derivation receipt. A separate leaf crate binds
//! these outputs into the deterministic non-PoW genesis state anchor. These
//! checks do not attest the executing source or binary, authenticate the
//! ordering layer's body store, or validate the first mined child. Internally,
//! checkpoint fields are private: transaction evaluation receives a read-only
//! native-state view and accumulates typed effects that only the checkpoint
//! materializer can apply. This is a local capability boundary, not an
//! independent module process or second implementation.
//!
//! The crate deliberately contains no bridge, external asset, deposit, reward,
//! mandate, graph-order, or zero-knowledge machinery.

mod codec;
mod descriptor;
mod error;
mod genesis;
mod interpreter;
mod model;
mod runtime;
mod state;

pub use codec::{
    ACCEPTED_EFFECT_TAG, CHECKPOINT_STATE_TAG, CODEC_VERSION, DECISION_TAG,
    NATIVE_INTERVAL_RESULT_TAG, NATIVE_STATE_PROJECTION_TAG, NativeIntervalResult,
    NativeStateProjection, OUTCOME_TAG, TRANSITION_TAG, UnverifiedAcceptedEffect,
    UnverifiedCheckpointState, UnverifiedDecision, UnverifiedNativeIntervalResult,
    UnverifiedNativeStateProjection, UnverifiedOutcome, UnverifiedTransition,
};
pub use descriptor::{transparent_checkpoint_descriptor, transparent_native_kernel_descriptor};
pub use error::{
    CodecVerificationError, KernelError, RejectCode, StateInvariantError, UnknownRejectCode,
};
pub use genesis::{GateAGenesisReceipt, GateAGenesisReceiptField, MaterializedGenesis};
pub use interpreter::{Decision, Outcome, Transition};
pub use model::{
    GenesisAllocationTemplate, GenesisAllocationTemplateBoundError, GenesisAllocationTemplateEntry,
    NativeNote, NativeTransaction, OrderedBody, RecoveryRecord, TransactionBoundError,
    TransparentInput, TransparentOutput, TransparentWitness,
};
pub use runtime::{TransparentExecutionHost, TrustedCheckpointPin};
pub use state::{AcceptedEffect, CheckpointState};

/// Maximum transparent inputs in one Gate A transaction.
pub const MAX_INPUTS: usize = 16;
/// Maximum transparent outputs in one Gate A transaction.
pub const MAX_OUTPUTS: usize = 16;
/// Maximum transactions materialized by one kernel checkpoint call.
pub const MAX_TRANSACTIONS: usize = 4_096;
/// Maximum already ordered bodies in one checkpoint interval.
pub const MAX_ORDERED_BODIES: usize = 1_024;
/// Maximum notes in the bounded transparent test genesis.
pub const MAX_GENESIS_ALLOCATIONS: usize = 4_096;
/// Fixed payload length of one transparent recovery record.
pub const RECOVERY_PAYLOAD_BYTES: usize = 128;
