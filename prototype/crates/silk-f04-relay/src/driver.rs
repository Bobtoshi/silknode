//! Native two-slot ownership shared by the actual role coordinators.
use crate::{
    Error, Result, config::SignedConfig, resources::RoleResources, runtime::RoundGuard,
    schedule::Schedule,
};
use std::{cell::Cell, rc::Rc, time::Instant};

pub struct RoundLease {
    pub(crate) config: Rc<SignedConfig>,
    pub(crate) resources: RoleResources,
    pub(crate) schedule: Rc<Schedule>,
    pub(crate) maintenance_claimed: Cell<bool>,
    pub(crate) epoch_claimed: Cell<bool>,
    guard: RoundGuard,
}
impl RoundLease {
    #[allow(clippy::missing_const_for_fn)]
    pub(crate) fn check(&self) -> Result<()> {
        self.guard.check()
    }
}

pub struct RoundSlot<T> {
    // Rust drops fields in declaration order: actor material always precedes
    // timer disarming, including unwinding or an owner returning early.
    pub(crate) state: T,
    pub(crate) schedule: Rc<Schedule>,
    pub(crate) lease: Rc<RoundLease>,
}
impl<T> RoundSlot<T> {
    #[allow(clippy::missing_const_for_fn)] // The Linux backend reads native clocks.
    pub(crate) fn check(&self) -> Result<()> {
        self.lease.check()
    }
    pub(crate) fn cleanup_due(&self) -> Result<bool> {
        Ok(Instant::now() >= self.schedule.at(22_000_000_000)?)
    }
    pub(crate) fn close(self, close: impl FnOnce(T, &Schedule) -> Result<()>) -> Result<()> {
        let Self {
            state,
            schedule,
            lease,
        } = self;
        // Destructuring order is not the cleanup policy: explicitly finish the
        // consumed actor and journal retirement while the original guard lives.
        close(state, &schedule)?;
        lease.check()?;
        Ok(())
    }
}
pub struct TwoRounds<T> {
    pub(crate) slots: [Option<RoundSlot<T>>; 2],
    highest: Option<u64>,
    floor: u64,
    domain: crate::Digest,
    cohort: u32,
    pub(crate) resources: RoleResources,
}
impl<T> TwoRounds<T> {
    #[cfg(feature = "functional-lab")]
    pub(crate) fn functional_snapshot(
        &self,
        journal: Option<(u64, u64)>,
        hops: impl Fn(&T) -> [u64; 4],
    ) -> crate::lifecycle::FunctionalOwnerSnapshot {
        crate::lifecycle::FunctionalOwnerSnapshot {
            floor: self.floor,
            highest: self.highest,
            journal,
            live: std::array::from_fn(|i| {
                self.slots[i]
                    .as_ref()
                    .map(|slot| crate::lifecycle::FunctionalRoundSnapshot {
                        round: slot.schedule.round(),
                        config: slot.lease.config.id(),
                        hops: hops(&slot.state),
                    })
            }),
        }
    }
    pub(crate) const fn highest(&self) -> Option<u64> {
        self.highest
    }
    pub(crate) fn live_configs(&self) -> [Option<crate::Digest>; 2] {
        std::array::from_fn(|i| self.slots[i].as_ref().map(|slot| slot.lease.config.id()))
    }
    pub(crate) const fn new(config: &SignedConfig, floor: u64, resources: RoleResources) -> Self {
        Self {
            slots: [None, None],
            highest: None,
            floor,
            domain: config.domain(),
            cohort: config.cohort(),
            resources,
        }
    }
    pub(crate) fn admit(
        &mut self,
        config: &Rc<SignedConfig>,
        schedule: Rc<Schedule>,
        begin: impl FnOnce() -> Result<T>,
    ) -> Result<()> {
        let round = schedule.round();
        if config.domain() != self.domain
            || config.cohort() != self.cohort
            || !config.contains_round(round)
            || round < self.floor
            || self.highest.is_some_and(|r| round <= r)
            || self
                .slots
                .iter()
                .flatten()
                .any(|s| s.schedule.round().checked_add(1) != Some(round))
        {
            return Err(Error::Unavailable("coordinator stale/foreign round"));
        }
        let index = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Unavailable("coordinator two-round capacity"))?;
        // Consume admission before any fallible native arm or actor construction.
        // A reconstructed same-round Schedule cannot reset this owner's lease.
        self.highest = Some(round);
        let lease = Rc::new(RoundLease {
            guard: RoundGuard::arm(&schedule)?,
            config: Rc::clone(config),
            resources: self.resources.clone(),
            schedule: Rc::clone(&schedule),
            maintenance_claimed: Cell::new(false),
            epoch_claimed: Cell::new(false),
        });
        let state = begin()?;
        self.slots[index] = Some(RoundSlot {
            state,
            schedule,
            lease,
        });
        Ok(())
    }
    pub(crate) fn ordered(&self) -> [usize; 2] {
        if self.slots[0]
            .as_ref()
            .map_or(u64::MAX, |s| s.schedule.round())
            <= self.slots[1]
                .as_ref()
                .map_or(u64::MAX, |s| s.schedule.round())
        {
            [0, 1]
        } else {
            [1, 0]
        }
    }
    pub(crate) fn lease(&self, round: u64) -> Result<Rc<RoundLease>> {
        self.slots
            .iter()
            .flatten()
            .find(|s| s.schedule.round() == round)
            .map(|s| Rc::clone(&s.lease))
            .ok_or(Error::Unavailable("setup original live round absent"))
    }
}
