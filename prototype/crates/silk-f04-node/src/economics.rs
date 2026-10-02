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
        if self.domain != *expected_domain {
            return Err(Error::Invalid("economic ledger context"));
        }
        if self.executed.len() > HISTORY_LIMIT_V1
            || self.executed.len() % 8 != 0
            || self.reward_records.len() != self.executed.len()
            || self.accepted_effects > 50_000
            || self.accepted_effects > self.executed.len() as u64 * 32
            || self.accepted_effects.checked_mul(PRIVATE_BURN_V1) != Some(self.private_burned)
            || self.private_pool.checked_add(self.private_burned) != Some(initial_private_pool)
            || (self.executed.len() as u128).checked_mul(u128::from(PUBLIC_CREDIT_V1))
                != Some(self.public_issued)
        {
            return Err(Error::Invalid("economic ledger conservation/cursor"));
        }
        for (index, (vertex, row)) in self.executed.iter().zip(self.reward_records).enumerate() {
            let position = u64::from_le_bytes(row[..8].try_into().expect("fixed reward row"));
            let amount = u64::from_le_bytes(row[104..].try_into().expect("fixed reward row"));
            if position != index as u64 + 1
                || row[8..40] != vertex.as_bytes()[..]
                || amount != PUBLIC_CREDIT_V1
            {
                return Err(Error::Invalid("economic reward lineage/amount"));
            }
        }
        Ok(())
    }
}
