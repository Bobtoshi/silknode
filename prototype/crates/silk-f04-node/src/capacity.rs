//! Local history-capacity policy, not consensus or peer validity authority.
use crate::{Error, Result, sync::HISTORY_LIMIT_V1};

/// Existing retained-generation replay horizon, not an increased resource limit.
pub const GENERATION_LIMIT_V1: u64 = 20_000;

/// Read-only bounds for the existing reference node. Caller-supplied counts never
/// establish an admitted graph, READY state, storage capacity or work validity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryCapacityV1 {
    /// Remaining ordinary complete-generation publications.
    pub generations_remaining: u64,
    /// Remaining graph evidence positions before the existing reference horizon.
    pub vertices_remaining: usize,
    /// Conservative slots for one admission and its complete reconciliation:
    /// one admission, a possible whole-state rollback, and every full interval
    /// of eight vertices in the resulting graph. Red vertices can only reduce it.
    pub admission_generations: u64,
}

impl HistoryCapacityV1 {
    /// Reproduce the local capacity arithmetic. These are unverified counts;
    /// obtain the actual local values through `Node::history_capacity`.
    /// # Errors
    /// Refuses counts beyond the existing horizons or an inconsistent ledger cursor.
    pub fn for_counts(sequence: u64, vertices: usize, executed: usize) -> Result<Self> {
        if sequence > GENERATION_LIMIT_V1
            || vertices > HISTORY_LIMIT_V1
            || executed > vertices
            || executed % 8 != 0
        {
            return Err(Error::Unavailable("history capacity counts"));
        }
        Ok(Self {
            generations_remaining: GENERATION_LIMIT_V1 - sequence,
            vertices_remaining: HISTORY_LIMIT_V1 - vertices,
            admission_generations: 1 + u64::from(executed > 0) + (vertices as u64 + 1) / 8,
        })
    }

    /// Known reference-horizon preflight only; does not reserve disk, authorize
    /// ingress/mining or waive the ordinary verifier and original job budget.
    /// # Errors
    /// Pauses before a job if its result cannot fit and complete reconciliation.
    pub fn check_admission(&self) -> Result<()> {
        if self.vertices_remaining == 0 {
            return Err(Error::Paused("admitted-vertex reference horizon"));
        }
        self.check_generations(self.admission_generations)
    }

    /// Reproduce the remaining preferred-history publication bound. `common`
    /// is the exact shared prefix length, not merely matching graph counts.
    /// Counts are unverified; the node derives them from its admitted ordering.
    /// # Errors
    /// Refuses impossible prefix lengths, ledger cursors or reference horizons.
    pub fn reconciliation_generations(
        executed: usize,
        common: usize,
        eligible: usize,
    ) -> Result<u64> {
        if executed > HISTORY_LIMIT_V1
            || eligible > HISTORY_LIMIT_V1
            || executed % 8 != 0
            || common > executed.min(eligible)
        {
            return Err(Error::Unavailable("reconciliation capacity counts"));
        }
        Ok(if common < executed {
            1 + (eligible / 8) as u64
        } else {
            (eligible / 8 - executed / 8) as u64
        })
    }

    /// Check a known publication/reconciliation bound without changing state.
    /// # Errors
    /// Pauses at the unchanged retained-generation horizon.
    pub fn check_generations(&self, required: u64) -> Result<()> {
        if required > self.generations_remaining {
            Err(Error::Paused("generation reference horizon"))
        } else {
            Ok(())
        }
    }
}
