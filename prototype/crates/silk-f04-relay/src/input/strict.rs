//! Private pre-erasure completion provenance; no legacy-batch conversion.
use super::InputBatch;
use crate::{Digest, Error, Result};

#[derive(Default)]
pub(super) struct CompletedSlots(u32);
impl CompletedSlots {
    // Production calls this only after actual cell validation and its deadline.
    pub(super) fn record(&mut self, slot: u8) -> Result<()> {
        let bit = 1_u32
            .checked_shl(u32::from(slot))
            .ok_or(Error::Invalid("A completion slot"))?;
        if self.0 & bit != 0 {
            return Err(Error::Invalid("A duplicate completion slot"));
        }
        self.0 |= bit;
        Ok(())
    }
    pub(super) fn finish(
        &self,
        sessions: usize,
        frames: usize,
        config: Digest,
        manifest: Digest,
        round: u64,
    ) -> Result<StrictCompletion> {
        if sessions != 32 || frames != 32 || self.0 != u32::MAX {
            return Err(Error::Unavailable("A strict incomplete roster"));
        }
        Ok(StrictCompletion {
            config,
            manifest,
            round,
        })
    }
}

// No public constructor, Clone, Deserialize or legacy InputBatch conversion.
pub(crate) struct StrictCompletion {
    config: Digest,
    manifest: Digest,
    round: u64,
}
impl StrictCompletion {
    fn check(&self, config: Digest, manifest: Digest, round: u64) -> Result<()> {
        if self.config != config || self.manifest != manifest || self.round != round {
            return Err(Error::Invalid("A strict completion context"));
        }
        Ok(())
    }
}

/// Source-free batch with private proof of honest A's strict local collection.
/// It proves neither participant independence nor public completeness against A.
/// A legacy batch has no conversion, even if its admitted count is 32:
/// ```compile_fail
/// use silk_f04_relay::input::{InputBatch, StrictInputBatch};
/// fn upgrade(batch: InputBatch) -> StrictInputBatch { batch.into() }
/// ```
pub struct StrictInputBatch {
    batch: InputBatch,
    completion: StrictCompletion,
}
impl StrictInputBatch {
    pub(super) fn from_collection(batch: InputBatch, completion: StrictCompletion) -> Self {
        Self { batch, completion }
    }
    pub(crate) fn into_bound(
        self,
        config: Digest,
        manifest: Digest,
        round: u64,
    ) -> Result<(InputBatch, StrictCompletion)> {
        self.completion.check(config, manifest, round)?;
        if self.batch.admitted() != 32 {
            return Err(Error::Invalid("A strict completion context"));
        }
        Ok((self.batch, self.completion))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_completion_is_bound_to_exact_config_manifest_and_round() {
        let mut slots = CompletedSlots::default();
        for slot in 0..32 {
            slots.record(slot).unwrap();
        }
        let completion = slots.finish(32, 32, [1; 32], [2; 32], 7).unwrap();
        assert!(completion.check([1; 32], [2; 32], 7).is_ok());
        assert!(completion.check([3; 32], [2; 32], 7).is_err());
        assert!(completion.check([1; 32], [3; 32], 7).is_err());
        assert!(completion.check([1; 32], [2; 32], 8).is_err());
    }
    #[test]
    fn strict_completion_requires_all_actual_distinct_slots_before_filler() {
        let mut slots = CompletedSlots::default();
        for slot in 0..31 {
            slots.record(slot).unwrap();
        }
        // A 32-frame legacy batch (31 arrivals plus filler) cannot qualify.
        assert!(slots.finish(32, 32, [1; 32], [2; 32], 7).is_err());
        assert!(slots.finish(31, 31, [1; 32], [2; 32], 7).is_err());
        assert!(slots.record(30).is_err());
        slots.record(31).unwrap();
        assert!(slots.finish(32, 32, [1; 32], [2; 32], 7).is_ok());
        assert!(slots.finish(31, 32, [1; 32], [2; 32], 7).is_err());
        assert!(slots.finish(32, 31, [1; 32], [2; 32], 7).is_err());
        assert!(slots.record(32).is_err());
    }
    #[test]
    fn missing_partial_or_invalid_slot_never_qualifies() {
        for missing in 0..32 {
            let mut slots = CompletedSlots::default();
            for slot in 0..32 {
                if slot != missing {
                    slots.record(slot).unwrap();
                }
            }
            // No completion is recorded for absent/partial/rejected input.
            assert!(slots.finish(32, 32, [1; 32], [2; 32], 7).is_err());
        }
    }
}
