//! Cumulative foreground budgets. OS aggregate enforcement is a separate runtime gate.
use crate::{
    Error, Result,
    quantum::{Gate, Usage},
};
use std::{
    cell::{Cell, RefCell},
    time::Duration,
};

/// Never reset between source search, replay, work, crypto and metadata derivation.
pub(crate) struct JobBudget {
    start: Duration,
    cpu: Duration,
    wall_limit: Duration,
    cpu_limit: Duration,
    reads: Cell<u64>,
    gate: RefCell<Option<Gate>>,
    quantum: Cell<Usage>,
}
impl JobBudget {
    pub fn vertex() -> Result<Self> {
        Self::new(Duration::from_secs(5), Duration::from_secs(2))
    }
    pub fn checkpoint() -> Result<Self> {
        Self::new(Duration::from_secs(10), Duration::from_secs(10))
    }
    #[cfg(test)]
    pub fn testing(wall: Duration) -> Result<Self> {
        Self::new(wall, Duration::from_secs(10))
    }
    pub(crate) fn new(wall_limit: Duration, cpu_limit: Duration) -> Result<Self> {
        Ok(Self {
            start: monotonic_time()?,
            cpu: cpu_time()?,
            wall_limit,
            cpu_limit,
            reads: Cell::new(0),
            gate: RefCell::new(None),
            quantum: Cell::new(Usage::default()),
        })
    }
    pub fn check(&self) -> Result<()> {
        if let Some(gate) = self.gate.borrow().as_ref() {
            gate.check_cancelled()?;
        }
        if monotonic_time()?
            .checked_sub(self.start)
            .ok_or(Error::Unavailable("monotonic clock regression"))?
            >= self.wall_limit
            || cpu_time()?
                .checked_sub(self.cpu)
                .ok_or(Error::Unavailable("process CPU clock regression"))?
                >= self.cpu_limit
        {
            Err(Error::Paused("cumulative foreground CPU/wall budget"))
        } else {
            Ok(())
        }
    }
    /// Immutable absolute baselines survive worker handoff and every yield.
    pub(crate) fn deadlines(&self) -> Result<(Duration, Duration)> {
        Ok((
            self.start
                .checked_add(self.wall_limit)
                .ok_or(Error::Unavailable("wall deadline overflow"))?,
            self.cpu
                .checked_add(self.cpu_limit)
                .ok_or(Error::Unavailable("CPU deadline overflow"))?,
        ))
    }
    pub fn graph_read(&self) -> std::result::Result<(), silk_order::sg0_v1::Sg0Error> {
        self.probe()
            .map_err(|_| silk_order::sg0_v1::Sg0Error::ResourceBudget)?;
        let reads = self.reads.get() + 1;
        self.reads.set(reads);
        if reads % 64 == 0 {
            self.check()
                .map_err(|_| silk_order::sg0_v1::Sg0Error::ResourceBudget)?;
        }
        Ok(())
    }
    pub fn attach(&mut self, gate: Gate) {
        *self.gate.get_mut() = Some(gate);
        self.quantum.set(Usage::default());
    }
    pub fn detach(&mut self) {
        self.gate.get_mut().take();
    }
    fn charge(&self, extra: Usage) -> Result<()> {
        let mut used = self.quantum.get();
        if let Some(gate) = self.gate.borrow().as_ref() {
            if !used.permits(extra) {
                self.check()?;
                gate.yield_now(used)?;
                self.check()?;
                used = Usage::default();
            }
            used.add(extra);
            self.quantum.set(used);
        }
        Ok(())
    }
    pub fn probe(&self) -> Result<()> {
        self.charge(Usage {
            probes: 1,
            ..Usage::default()
        })
    }
    pub fn source(&self) -> Result<()> {
        self.charge(Usage {
            sources: 1,
            ..Usage::default()
        })
    }
    pub fn replay(&self) -> Result<()> {
        self.charge(Usage {
            vertices: 8,
            ..Usage::default()
        })
    }
}
fn monotonic_time() -> Result<Duration> {
    clock_time(rustix::time::ClockId::Monotonic)
}
fn cpu_time() -> Result<Duration> {
    clock_time(rustix::time::ClockId::ProcessCPUTime)
}
fn clock_time(clock: rustix::time::ClockId) -> Result<Duration> {
    let t = rustix::time::clock_gettime_dynamic(rustix::time::DynamicClockId::Known(clock))
        .map_err(|_| Error::Unavailable("local budget clock"))?;
    Ok(Duration::new(
        u64::try_from(t.tv_sec).map_err(|_| Error::Unavailable("CPU clock seconds"))?,
        u32::try_from(t.tv_nsec).map_err(|_| Error::Unavailable("CPU clock nanoseconds"))?,
    ))
}

/// Receiver-local nondecreasing wall observation. It is never a consensus field.
#[derive(Clone, Copy, Debug, Default)]
pub struct LocalClock {
    high_water: u64,
}
impl LocalClock {
    /// Restore only authenticated locally retained metadata, never a peer timestamp.
    #[must_use]
    pub const fn restored(high_water: u64) -> Self {
        Self { high_water }
    }
    /// Caller supplies a validated system-wall observation; rollback does not lower W.
    pub fn observe(&mut self, validated_wall: u64) -> Result<()> {
        if validated_wall == 0 {
            return Err(Error::Paused("untrusted wall clock"));
        }
        let next = self.high_water.max(validated_wall);
        next.checked_add(15)
            .ok_or(Error::Paused("wall clock live-bound overflow"))?;
        self.high_water = next;
        Ok(())
    }
    /// A future candidate is deferred without graph credit or peer-invalid blame.
    pub fn check_new(&self, timestamp: u64) -> Result<()> {
        if self.high_water == 0 {
            return Err(Error::Paused("unobserved wall clock"));
        }
        let upper = self
            .high_water
            .checked_add(15)
            .ok_or(Error::Paused("wall clock live-bound overflow"))?;
        if timestamp > upper {
            Err(Error::Paused("future candidate deferred"))
        } else {
            Ok(())
        }
    }
    /// Ordinary mining uses a fresh wall observation, not the historical high
    /// water itself. An impossible live bound pauses; it is never clamped down.
    pub fn mining_time(&mut self, current_wall: u64, minimum_time: u64) -> Result<u64> {
        self.observe(current_wall)?;
        let chosen = current_wall.max(minimum_time);
        self.check_new(chosen)?;
        Ok(chosen)
    }
    /// Durable local-only high-water value.
    #[must_use]
    pub const fn high_water(&self) -> u64 {
        self.high_water
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn future_clock_rollback_and_overflow_are_local() {
        let mut c = LocalClock::default();
        assert!(matches!(c.check_new(1), Err(Error::Paused(_))));
        c.observe(100).unwrap();
        c.observe(90).unwrap();
        assert_eq!(c.high_water(), 100);
        c.check_new(115).unwrap();
        assert!(matches!(c.check_new(116), Err(Error::Paused(_))));
        assert!(matches!(c.observe(u64::MAX), Err(Error::Paused(_))));
        assert_eq!(c.high_water(), 100);
    }

    #[test]
    fn ordinary_mining_uses_current_wall_and_checked_parent_minimum() {
        let mut c = LocalClock::default();
        assert_eq!(c.mining_time(100, 90).unwrap(), 100);
        assert_eq!(c.mining_time(100, 100).unwrap(), 100);
        assert_eq!(c.mining_time(100, 115).unwrap(), 115);
        assert!(matches!(c.mining_time(100, 116), Err(Error::Paused(_))));
        assert_eq!(c.mining_time(90, 91).unwrap(), 91);
        assert_eq!(c.high_water(), 100);
        assert!(matches!(c.mining_time(u64::MAX, 1), Err(Error::Paused(_))));
        assert!(matches!(c.mining_time(0, 1), Err(Error::Paused(_))));
        assert_eq!(c.high_water(), 100);
    }
}
