//! Actual R2 TLS collection under an explicitly UNQUALIFIED original lease.
//! No public frame array/count can mint the private completion receipt. Neither
//! actual connections nor the opaque receipt establish independent participants,
//! accepted epoch Join, proof validity, setup, anonymity or operational admission.
use super::{CompletedSlots, Sessions, StrictCompletion};
use crate::{
    Digest, Error, Result,
    aip2_profile::PreparedProfile,
    aip2_transport::{
        PreparedR2Frame, PreparedR2InputContext, open_a, permute_at_a, prepared_a_batch_id,
    },
    frame::HpkePrivate,
    owner::ManifestRound,
    runtime::RoundGuard,
    tls::{ReceiveProgress, RecordSize},
};
use std::{collections::BTreeSet, rc::Rc, time::Instant};

const INPUT_END: i64 = 9_500_000_000;
const SEAL_END: i64 = 10_000_000_000;

#[cfg(all(test, target_os = "linux"))]
#[path = "r2_lab_tls_tests.rs"]
mod tls_tests;

/// Source-free, single-use result of actual full32 local collection. It carries
/// no TLS session, token, source address, slot labels or caller validity flag.
/// A precomputed array cannot upgrade into this receipt:
/// ```compile_fail
/// use silk_f04_relay::{aip2_transport::PreparedR2Frame, input::r2_lab::CollectedR2Lab};
/// fn upgrade(frames: [PreparedR2Frame; 32]) -> CollectedR2Lab { frames.into() }
/// ```
pub struct CollectedR2Lab {
    round: Rc<ManifestRound>,
    frames: [PreparedR2Frame; 32],
    id: Digest,
    guard: Rc<RoundGuard>,
    completion: StrictCompletion,
}
impl CollectedR2Lab {
    pub(crate) fn into_bound(
        self,
    ) -> (
        Rc<ManifestRound>,
        [PreparedR2Frame; 32],
        Digest,
        Rc<RoundGuard>,
        StrictCompletion,
    ) {
        (
            self.round,
            self.frames,
            self.id,
            self.guard,
            self.completion,
        )
    }
}

/// One actual delivered session set, immutable C/M/P/VK context and original
/// whole-round resource lease. No filler, replacement or partial result exists.
pub struct R2InputCollectorLab<'a> {
    sessions: Sessions,
    round: Rc<ManifestRound>,
    context: PreparedR2InputContext<'a>,
    key: Rc<HpkePrivate>,
    guard: Rc<RoundGuard>,
    completed: [bool; 32],
    known_pending: [bool; 32],
    slots: CompletedSlots,
    outer: BTreeSet<Digest>,
    inner: BTreeSet<Digest>,
    output: Vec<PreparedR2Frame>,
    failed: bool,
}
impl<'a> R2InputCollectorLab<'a> {
    /// Requires the SAME actual Join-admitted sessions returned by complete
    /// manifest fanout. This lab does not qualify that driver's epoch admission.
    /// # Errors
    /// Refuses qualified clocks, foreign/unhealthy/delivered contexts, missing
    /// slots, old partial records, late arming or a replaced/reset resource lease.
    pub fn new(
        mut sessions: Sessions,
        round: Rc<ManifestRound>,
        profile: &'a PreparedProfile,
        vk_hash: Digest,
        key: Rc<HpkePrivate>,
        guard: Rc<RoundGuard>,
    ) -> Result<Self> {
        if round.schedule.uses_qualified_source() || !guard.matches_schedule(&round.schedule) {
            return Err(Error::Unavailable("R2 input original unqualified lease"));
        }
        guard.check()?;
        round.schedule.in_window(-8_000_000_000, 1_000_000_000)?;
        round.schedule.clock_healthy()?;
        sessions.check_config(&round.config)?;
        if sessions.delivery_round != Some(round.schedule.round())
            || sessions.delivered_manifest != Some(round.manifest().id())
        {
            return Err(Error::Unavailable("R2 input original manifest delivery"));
        }
        complete_slot_inventory(sessions.entries.iter().map(|s| s.slot))?;
        let context = PreparedR2InputContext::new(Rc::clone(&round), profile, vk_hash)?;
        for session in &mut sessions.entries {
            if session.transport.receive_progress() != ReceiveProgress::Idle {
                return Err(Error::Unavailable(
                    "R2 input unavailable/old partial session",
                ));
            }
            session
                .transport
                .check_endpoint(round.config.endpoints()[0], false)?;
            session
                .transport
                .expect(RecordSize::Cell, round.schedule.at(INPUT_END)?)?;
        }
        round.schedule.completed_before(1_000_000_000)?;
        guard.check()?;
        Ok(Self {
            sessions,
            round,
            context,
            key,
            guard,
            completed: [false; 32],
            known_pending: [false; 32],
            slots: CompletedSlots::default(),
            outer: BTreeSet::new(),
            inner: BTreeSet::new(),
            output: Vec::with_capacity(32),
            failed: false,
        })
    }

    /// At most one bounded read per original session per poll. A accepts neither
    /// a caller timestamp nor already-opened/precomputed frame. B remains opaque.
    /// # Errors
    /// Any malformed, duplicate, early, partial/closed or over-budget input sticks.
    pub fn poll(&mut self) -> Result<()> {
        if self.failed {
            return Err(Error::Unavailable("R2 input stopped"));
        }
        let result = self.advance();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn advance(&mut self) -> Result<()> {
        self.guard.check()?;
        self.round.schedule.observe_functional_clock()?;
        self.round.schedule.completed_before(INPUT_END)?;
        let cutoff = self.round.schedule.at(INPUT_END)?;
        let context = self.context.context()?;
        for (i, session) in self.sessions.entries.iter_mut().enumerate() {
            if Instant::now() >= cutoff {
                break;
            }
            // The observation's COMPLETION, not a before-call timestamp,
            // decides whether a quiet completed socket can affect this barrier.
            let extra = session.transport.has_extra_bytes();
            let observed = Instant::now();
            if observed >= cutoff {
                break;
            }
            let extra = extra?;
            if self.completed[i] {
                if extra {
                    return Err(Error::Invalid("R2 duplicate/excess input"));
                }
                continue;
            }
            if extra && observed < self.round.schedule.at(earliest(session.slot)?)? {
                return Err(Error::Invalid("R2 observed early input"));
            }
            self.known_pending[i] = extra;
            if !extra {
                continue;
            }
            if let Some(bytes) = session.transport.read_step()? {
                let outer = PreparedR2Frame::decode(&bytes, &context, 1)?;
                if !self.outer.insert(outer.encapsulation()) {
                    return Err(Error::Invalid("R2 duplicate outer encapsulation"));
                }
                let inner = open_a(&context, &self.key, &outer)?;
                if !self.inner.insert(inner.encapsulation()) {
                    return Err(Error::Invalid("R2 duplicate inner encapsulation"));
                }
                self.round.schedule.completed_before(INPUT_END)?;
                self.guard.check()?;
                // Completion is minted ONLY after actual TLS consumption,
                // version/context/HPKE/uniqueness and original deadline checks.
                self.slots.record(session.slot)?;
                self.output.push(inner);
                self.completed[i] = true;
                self.known_pending[i] = false;
            }
        }
        self.guard.check()?;
        Ok(())
    }

    /// At original+9.5 freeze ONLY completed observations, erase source labels
    /// from the output and shuffle once. No post-barrier TCP peek/read is made.
    /// # Errors
    /// Refuses any failure/missing/partial slot; no filler or second seal exists.
    pub fn seal(mut self) -> Result<(Sessions, CollectedR2Lab)> {
        self.round.schedule.in_window(INPUT_END, SEAL_END)?;
        self.round.schedule.clock_healthy()?;
        self.guard.check()?;
        if self.failed
            || self.known_pending.iter().any(|p| *p)
            || self.completed.iter().any(|p| !*p)
        {
            return Err(Error::Unavailable("R2 incomplete input barrier"));
        }
        self.failed = true;
        let completion = self.slots.finish(
            self.sessions.entries.len(),
            self.output.len(),
            self.sessions.config,
            self.round.manifest().id(),
            self.round.schedule.round(),
        )?;
        let mut frames: [PreparedR2Frame; 32] = std::mem::take(&mut self.output)
            .try_into()
            .map_err(|_| Error::Unavailable("R2 full32 input"))?;
        let context = self.context.context()?;
        permute_at_a(&context, &mut frames)?;
        let id = prepared_a_batch_id(&context, &frames)?;
        self.round.schedule.completed_before(SEAL_END)?;
        self.guard.check()?;
        Ok((
            self.sessions,
            CollectedR2Lab {
                round: self.round,
                frames,
                id,
                guard: self.guard,
                completion,
            },
        ))
    }
}

// Source slot starts at+1+.2*i; receiver admits at most the combined1s clock
// skew early. It never changes the strict+9.5 completion barrier or source slot.
fn earliest(slot: u8) -> Result<i64> {
    if slot >= 32 {
        return Err(Error::Invalid("R2 input source slot"));
    }
    Ok(i64::from(slot) * 200_000_000)
}
fn complete_slot_inventory(slots: impl IntoIterator<Item = u8>) -> Result<()> {
    let mut mask = 0u32;
    let mut count = 0usize;
    for slot in slots {
        let bit = 1u32
            .checked_shl(u32::from(slot))
            .ok_or(Error::Invalid("R2 input source slot"))?;
        if mask & bit != 0 {
            return Err(Error::Invalid("R2 duplicate source slot"));
        }
        mask |= bit;
        count += 1;
    }
    if count != 32 || mask != u32::MAX {
        return Err(Error::Unavailable(
            "R2 input requires all32 actual sessions",
        ));
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_inventory_requires_every_distinct_actual_slot() {
        assert!(complete_slot_inventory(0..32).is_ok());
        assert!(complete_slot_inventory((0..32).rev()).is_ok());
        assert!(complete_slot_inventory(0..31).is_err());
        assert!(complete_slot_inventory((0..31).chain([30])).is_err());
        assert!(complete_slot_inventory((0..31).chain([32])).is_err());
        assert!(complete_slot_inventory((0..32).chain([0])).is_err());
    }
    #[test]
    fn every_missing_slot_refuses_even_when_a_public_count_would_be32() {
        for missing in 0..32 {
            let mut slots: Vec<u8> = (0..32).filter(|s| *s != missing).collect();
            assert!(complete_slot_inventory(slots.iter().copied()).is_err());
            slots.push(if missing == 0 { 1 } else { 0 });
            assert_eq!(slots.len(), 32);
            assert!(complete_slot_inventory(slots).is_err());
        }
    }
    #[test]
    fn receiver_early_bound_tracks_200ms_source_slots_not_legacy250ms() {
        for slot in 0..32 {
            assert_eq!(earliest(slot).unwrap(), i64::from(slot) * 200_000_000);
        }
        assert_eq!(earliest(31).unwrap(), 6_200_000_000);
        assert!(earliest(32).is_err());
        assert!(earliest(255).is_err());
        assert_eq!(SEAL_END - INPUT_END, 500_000_000);
    }
}
