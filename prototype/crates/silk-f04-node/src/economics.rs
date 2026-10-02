//! Deterministic checks for the existing VALUELESS F0.4 ledgers, not new money.
//! Caller-supplied records do not establish work, SG-0 order, proof validity or
//! a canonical checkpoint. Credits and the private allocation are separate ledgers.
use crate::{Digest, Error, Result, sync::HISTORY_LIMIT_V1};
use silk_types::VertexId;

/// Existing parameter 13: nontransferable credits per executed position.
pub const PUBLIC_CREDIT_V1: u64 = 10;
/// Existing parameter 14: credit maturity in executed positions, not wall time.
pub const CREDIT_MATURITY_V1: u64 = 16;
/// Existing parameter 29: private value burned per distinct accepted effect.
pub const PRIVATE_BURN_V1: u64 = 1;

/// Borrowed, unverified accounting view. No wire format or saved validity flag.
#[derive(Clone, Copy)]
pub struct EconomicLedgerV1<'a> {
    /// Full context domain; compare with independently admitted genesis.
    pub domain: Digest,
    /// Remaining value from the trusted, admitted private allocation premise.
    pub private_pool: u64,
    /// Private value destroyed by distinct accepted effects, not transferred fees.
    pub private_burned: u64,
    /// Number of distinct accepted effects; duplicates/conflicts contribute zero.
    pub accepted_effects: u64,
    /// Nontransferable public attribution credits; never added to private supply.
    pub public_issued: u128,
    /// Receiver-derived executed order, not all admitted red/blue vertices.
    pub executed: &'a [VertexId],
    /// Existing 112-byte rows: position, vertex, owner, nonce, amount.
    pub reward_records: &'a [[u8; 112]],
}

impl EconomicLedgerV1<'_> {
    /// Check both ledgers against independently supplied genesis context/supply.
    /// This does not authenticate those inputs or the reward owner/nonce against
    /// a mined carrier; ordinary receiver admission and replay still do that.
    /// # Errors
    /// Refuses foreign context, broken conservation, inconsistent totals/cursors,
    /// changed row amounts, missing/reordered rows or wrong execution identities.
    pub fn validate(&self, expected_domain: &Digest, initial_private_pool: u64) -> Result<()> {
        EconomicCountsV1 {
            domain: self.domain,
            private_pool: self.private_pool,
            private_burned: self.private_burned,
            accepted_effects: self.accepted_effects,
            public_issued: self.public_issued,
            executed: self.executed.len(),
            rewards: self.reward_records.len(),
        }
        .validate(
            expected_domain,
            initial_private_pool,
            self.executed.iter(),
            self.reward_records.iter(),
        )
    }
}

/// Unverified counts plus streamed rows; never a validity or snapshot constructor.
pub(crate) struct EconomicCountsV1 {
    pub domain: Digest,
    pub private_pool: u64,
    pub private_burned: u64,
    pub accepted_effects: u64,
    pub public_issued: u128,
    pub executed: usize,
    pub rewards: usize,
}
impl EconomicCountsV1 {
    pub(crate) fn validate<'a>(
        &self,
        expected_domain: &Digest,
        initial_private_pool: u64,
        mut executed: impl Iterator<Item = &'a VertexId>,
        mut rewards: impl Iterator<Item = &'a [u8; 112]>,
    ) -> Result<()> {
        if self.domain != *expected_domain {
            return Err(Error::Invalid("economic ledger context"));
        }
        if self.executed > HISTORY_LIMIT_V1
            || !self.executed.is_multiple_of(8)
            || self.rewards != self.executed
            || self.accepted_effects > 50_000
            || self.accepted_effects > self.executed as u64 * 32
            || self.accepted_effects.checked_mul(PRIVATE_BURN_V1) != Some(self.private_burned)
            || self.private_pool.checked_add(self.private_burned) != Some(initial_private_pool)
            || (self.executed as u128).checked_mul(u128::from(PUBLIC_CREDIT_V1))
                != Some(self.public_issued)
        {
            return Err(Error::Invalid("economic ledger conservation/cursor"));
        }
        for index in 0..self.executed {
            let vertex = executed
                .next()
                .ok_or(Error::Invalid("economic ledger conservation/cursor"))?;
            let row = rewards
                .next()
                .ok_or(Error::Invalid("economic ledger conservation/cursor"))?;
            let position = u64::from_le_bytes(row[..8].try_into().expect("fixed reward row"));
            let amount = u64::from_le_bytes(row[104..].try_into().expect("fixed reward row"));
            if position != index as u64 + 1
                || row[8..40] != vertex.as_bytes()[..]
                || amount != PUBLIC_CREDIT_V1
            {
                return Err(Error::Invalid("economic reward lineage/amount"));
            }
        }
        if executed.next().is_some() || rewards.next().is_some() {
            return Err(Error::Invalid("economic ledger conservation/cursor"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paged_ledger_sequence_accounting_refuses_truncated_extra_or_changed_rows() {
        let ids = (1..=8_u8)
            .map(|label| VertexId::from_bytes([label; 32]))
            .collect::<Vec<_>>();
        let rows = ids
            .iter()
            .enumerate()
            .map(|(index, id)| {
                let mut row = [0; 112];
                row[..8].copy_from_slice(&u64::try_from(index + 1).unwrap().to_le_bytes());
                row[8..40].copy_from_slice(id.as_bytes());
                row[104..].copy_from_slice(&PUBLIC_CREDIT_V1.to_le_bytes());
                row
            })
            .collect::<Vec<_>>();
        let counts = EconomicCountsV1 {
            domain: [7; 32],
            private_pool: 0,
            private_burned: 0,
            accepted_effects: 0,
            public_issued: 80,
            executed: 8,
            rewards: 8,
        };
        counts
            .validate(&[7; 32], 0, ids.iter(), rows.iter())
            .unwrap();
        let view = EconomicLedgerV1 {
            domain: [7; 32],
            private_pool: 0,
            private_burned: 0,
            accepted_effects: 0,
            public_issued: 80,
            executed: &ids,
            reward_records: &rows,
        };
        view.validate(&[7; 32], 0).unwrap();
        assert!(
            counts
                .validate(&[8; 32], 0, ids.iter(), rows.iter())
                .is_err()
        );
        assert!(
            counts
                .validate(&[7; 32], 1, ids.iter(), rows.iter())
                .is_err()
        );
        for length in [0, 7] {
            assert!(
                counts
                    .validate(&[7; 32], 0, ids[..length].iter(), rows.iter())
                    .is_err()
            );
            assert!(
                counts
                    .validate(&[7; 32], 0, ids.iter(), rows[..length].iter())
                    .is_err()
            );
        }
        assert!(
            counts
                .validate(&[7; 32], 0, ids.iter().chain(ids[..1].iter()), rows.iter())
                .is_err()
        );
        assert!(
            counts
                .validate(&[7; 32], 0, ids.iter(), rows.iter().chain(rows[..1].iter()))
                .is_err()
        );
        for offset in [0, 8, 104] {
            let mut changed = rows.clone();
            changed[3][offset] ^= 1;
            assert!(
                counts
                    .validate(&[7; 32], 0, ids.iter(), changed.iter())
                    .is_err()
            );
        }
        let mut reordered = rows.clone();
        reordered.swap(0, 1);
        assert!(
            counts
                .validate(&[7; 32], 0, ids.iter(), reordered.iter())
                .is_err()
        );
    }
}
