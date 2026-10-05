//! Local history-capacity policy, not consensus or peer validity authority.
use crate::{Error, Result, sync::HISTORY_LIMIT_V1};

/// Existing retained-generation replay horizon, not an increased resource limit.
pub const GENERATION_LIMIT_V1: u64 = 20_000;

/// Receiver-local, nonserialized resource choice. It conveys no work, proof,
/// disk reservation, runtime qualification or permission to launch a node.
/// Existing entry points retain the reference policy. Higher-profile native
/// acceptance is separate from constructing this bounded configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryLimitsV1 {
    vertices: usize,
}
impl HistoryLimitsV1 {
    /// Original release/reference defaults, unchanged.
    pub const REFERENCE: Self = Self {
        vertices: HISTORY_LIMIT_V1,
    };
    /// Construct an explicit bounded local research profile, not a peer flag.
    /// The retained-generation, object, effect, cache and CPU/wall limits stay
    /// unchanged. Every admission still reserves complete reconciliation.
    pub fn for_vertices(vertices: usize) -> Result<Self> {
        if vertices == 0 || vertices > 8192 || !vertices.is_multiple_of(8) {
            return Err(Error::Unavailable("local history resource profile"));
        }
        let limits = Self { vertices };
        limits.linear_generations()?;
        Ok(limits)
    }
    /// Maximum local admitted graph/eligible positions.
    pub const fn vertices(self) -> usize {
        self.vertices
    }
    /// Original independent generation horizon; never inferred from a peer.
    pub const fn generations(self) -> u64 {
        GENERATION_LIMIT_V1
    }
    /// Complete linear-history publications, including checkpoint zero.
    pub fn linear_generations(self) -> Result<u64> {
        let vertices = u64::try_from(self.vertices)
            .map_err(|_| Error::Unavailable("local history resource arithmetic"))?;
        vertices
            .checked_add(vertices / 8)
            .and_then(|n| n.checked_add(1))
            .filter(|n| *n <= self.generations())
            .ok_or(Error::Unavailable("local history generation envelope"))
    }
}

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
        Self::for_counts_with_limits(HistoryLimitsV1::REFERENCE, sequence, vertices, executed)
    }
    /// Same capacity preflight under an explicit local resource profile.
    pub fn for_counts_with_limits(
        limits: HistoryLimitsV1,
        sequence: u64,
        vertices: usize,
        executed: usize,
    ) -> Result<Self> {
        if sequence > limits.generations()
            || vertices > limits.vertices()
            || executed > vertices
            || executed % 8 != 0
        {
            return Err(Error::Unavailable("history capacity counts"));
        }
        Ok(Self {
            generations_remaining: limits.generations() - sequence,
            vertices_remaining: limits.vertices() - vertices,
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
        Self::reconciliation_with_limits(HistoryLimitsV1::REFERENCE, executed, common, eligible)
    }
    pub(crate) fn reconciliation_with_limits(
        limits: HistoryLimitsV1,
        executed: usize,
        common: usize,
        eligible: usize,
    ) -> Result<u64> {
        if executed > limits.vertices()
            || eligible > limits.vertices()
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_profile_is_local_closed_and_reserves_full_reconciliation() {
        let limits = HistoryLimitsV1::for_vertices(8192).unwrap();
        assert_eq!(limits.generations(), 20_000);
        assert_eq!(limits.linear_generations().unwrap(), 9217);
        assert_eq!(HistoryLimitsV1::REFERENCE.vertices(), 4096);
        for invalid in [0, 1, 4097, 8193, usize::MAX] {
            assert!(HistoryLimitsV1::for_vertices(invalid).is_err());
        }
        assert!(HistoryCapacityV1::for_counts(0, 4104, 4096).is_err());
        let counts = HistoryCapacityV1::for_counts_with_limits(limits, 0, 4104, 4096).unwrap();
        assert_eq!(counts.vertices_remaining, 4088);
        assert_eq!(counts.admission_generations, 515);
        counts.check_admission().unwrap();
        assert!(
            HistoryCapacityV1::for_counts_with_limits(limits, 19_999, 4104, 4096)
                .unwrap()
                .check_admission()
                .is_err()
        );
        assert!(
            HistoryCapacityV1::for_counts_with_limits(limits, 0, 8192, 8192)
                .unwrap()
                .check_admission()
                .is_err()
        );
        assert_eq!(
            HistoryCapacityV1::reconciliation_with_limits(limits, 4096, 4095, 4104).unwrap(),
            514
        );
        assert!(HistoryCapacityV1::reconciliation_generations(4096, 4095, 4104).is_err());
    }
}
