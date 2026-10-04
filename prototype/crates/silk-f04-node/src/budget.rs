//! Cumulative foreground budgets. OS aggregate enforcement is a separate runtime gate.
use crate::{
    Error, Result,
    quantum::{Gate, Usage},
};
use std::{
    cell::{Cell, RefCell},
    sync::{Arc, Mutex},
    time::Duration,
};

/// Receiver-local diagnostic call boundary, never consensus or saved validity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionPhase {
    /// Initial canonical input decoding.
    Decode,
    /// Existing ID/full-byte lookup.
    KnownLookup,
    /// Local time, parents and horizon checks.
    Preflight,
    /// Durable attempt marker publication.
    AttemptFence,
    /// Original native deadline lease arming.
    NativeDeadline,
    /// Core canonical decoding and duplicate lookup.
    CoreDecode,
    /// Parent closure ordering.
    ParentOrder,
    /// Eligible-prefix commitments.
    ParentCommitments,
    /// Full header reads and difficulty derivation.
    ParentDifficulty,
    /// Whole ID/directory qualification for one source-frontier operation.
    ParentFrontierInventory,
    /// Delayed-key source ledger reconstruction.
    ParentSourceReplay,
    /// Delayed-key frontier/common-ancestor search.
    ParentFrontier,
    /// Final delayed-key material construction.
    ParentKey,
    /// Body stage entry and parent-fact binding.
    BodyStart,
    /// Exact native work verification, including its following budget check.
    Work,
    /// Envelope decode and cryptographic verification.
    BodyCrypto,
    /// Verified candidate parent-closure reconstruction.
    CandidateClosure,
    /// New vertex SG-0 metadata derivation.
    VertexMetadata,
    /// New preferred/eligible graph order derivation.
    GraphOrder,
    /// Reconciliation-status derivation.
    ReconciliationStatus,
    /// Complete durable generation publication.
    DurableGeneration,
    /// Derived ancestry retention.
    AncestryRetention,
    /// Exact live order retention/binding.
    OrderRetention,
    /// Live graph publication and checked directories.
    CorePublication,
    /// Accepted attempt terminal closure.
    TerminalClosure,
}

/// First cooperative expiration only. Absence does not prove success: native
/// SIGKILL, clock failure, cancellation and other errors may provide no report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmissionBudgetFailure {
    /// Call boundary active when the original budget first detected expiration.
    pub phase: AdmissionPhase,
    /// Monotonic elapsed time from the original job baseline.
    pub wall_elapsed: Duration,
    /// Process CPU elapsed time; None only if the extra wall-failure sample fails.
    pub cpu_elapsed: Option<Duration>,
    /// Original unchanged wall allowance.
    pub wall_limit: Duration,
    /// Original unchanged process-CPU allowance.
    pub cpu_limit: Duration,
    /// Whether the measured original wall threshold was reached.
    pub wall_expired: bool,
    /// CPU threshold observation; None means unavailable, not false.
    pub cpu_expired: Option<bool>,
}
struct TraceState {
    phase: AdmissionPhase,
    failure: Option<AdmissionBudgetFailure>,
}
pub(crate) struct AdmissionTrace(Mutex<TraceState>);
impl AdmissionTrace {
    pub(crate) fn failure(&self) -> Option<AdmissionBudgetFailure> {
        self.0.lock().ok().and_then(|state| state.failure)
    }
}

/// Never reset between source search, replay, work, crypto and metadata derivation.
pub(crate) struct JobBudget {
    start: Duration,
    cpu: Duration,
    wall_limit: Duration,
    cpu_limit: Duration,
    reads: Cell<u64>,
    gate: RefCell<Option<Gate>>,
    quantum: Cell<Usage>,
    trace: Option<Arc<AdmissionTrace>>,
    #[cfg(test)]
    source_calls: Cell<u64>,
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
            trace: None,
            #[cfg(test)]
            source_calls: Cell::new(0),
        })
    }
    /// Optional live diagnostics share ownership, NOT a second/reset budget.
    pub(crate) fn track_admission(&mut self) -> Arc<AdmissionTrace> {
        let trace = self.trace.get_or_insert_with(|| {
            Arc::new(AdmissionTrace(Mutex::new(TraceState {
                phase: AdmissionPhase::Decode,
                failure: None,
            })))
        });
        trace.clone()
    }
    pub(crate) fn phase(&self, phase: AdmissionPhase) {
        if let Some(trace) = &self.trace
            && let Ok(mut state) = trace.0.lock()
        {
            state.phase = phase;
        }
    }
    fn expired(&self, wall_elapsed: Duration, cpu_elapsed: Option<Duration>) -> Result<()> {
        if let Some(trace) = &self.trace
            && let Ok(mut state) = trace.0.lock()
            && state.failure.is_none()
        {
            state.failure = Some(AdmissionBudgetFailure {
                phase: state.phase,
                wall_elapsed,
                cpu_elapsed,
                wall_limit: self.wall_limit,
                cpu_limit: self.cpu_limit,
                wall_expired: wall_elapsed >= self.wall_limit,
                cpu_expired: cpu_elapsed.map(|cpu| cpu >= self.cpu_limit),
            });
        }
        Err(Error::Paused("cumulative foreground CPU/wall budget"))
    }
    pub fn check(&self) -> Result<()> {
        if let Some(gate) = self.gate.borrow().as_ref() {
            gate.check_cancelled()?;
        }
        let wall_elapsed = monotonic_time()?
            .checked_sub(self.start)
            .ok_or(Error::Unavailable("monotonic clock regression"))?;
        if wall_elapsed >= self.wall_limit {
            // Original short-circuit wall refusal stays a wall refusal even if
            // this extra diagnostic CPU sample is unavailable or regresses.
            let cpu_elapsed = self
                .trace
                .as_ref()
                .and_then(|_| cpu_time().ok())
                .and_then(|cpu| cpu.checked_sub(self.cpu));
            return self.expired(wall_elapsed, cpu_elapsed);
        }
        let cpu_elapsed = cpu_time()?
            .checked_sub(self.cpu)
            .ok_or(Error::Unavailable("process CPU clock regression"))?;
        if cpu_elapsed >= self.cpu_limit {
            return self.expired(wall_elapsed, Some(cpu_elapsed));
        }
        Ok(())
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
        #[cfg(test)]
        self.source_calls
            .set(self.source_calls.get().saturating_add(1));
        self.charge(Usage {
            sources: 1,
            ..Usage::default()
        })
    }
    #[cfg(test)]
    pub(crate) fn source_calls(&self) -> u64 {
        self.source_calls.get()
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
    fn admission_diagnostic_cpu_wall_both_and_unknown_are_not_conflated() {
        for (wall, cpu, expect_wall, expect_cpu) in [
            (Duration::from_secs(60), Duration::ZERO, false, true),
            (Duration::ZERO, Duration::from_secs(60), true, false),
            (Duration::ZERO, Duration::ZERO, true, true),
        ] {
            let mut b = JobBudget::new(wall, cpu).unwrap();
            let trace = b.track_admission();
            b.phase(AdmissionPhase::Work);
            assert!(matches!(
                b.check(),
                Err(Error::Paused("cumulative foreground CPU/wall budget"))
            ));
            let failure = trace.failure().unwrap();
            assert_eq!(failure.phase, AdmissionPhase::Work);
            assert_eq!(failure.wall_expired, expect_wall);
            assert_eq!(failure.cpu_expired, Some(expect_cpu));
            assert_eq!((failure.wall_limit, failure.cpu_limit), (wall, cpu));
        }
        // Pure refusal-recording boundary: no invented unavailable CPU sample.
        let mut b = JobBudget::new(Duration::ZERO, Duration::from_secs(60)).unwrap();
        let trace = b.track_admission();
        assert!(b.expired(Duration::ZERO, None).is_err());
        assert!(trace.failure().unwrap().wall_expired);
        assert_eq!(trace.failure().unwrap().cpu_elapsed, None);
        assert_eq!(trace.failure().unwrap().cpu_expired, None);
    }
    #[test]
    fn admission_diagnostic_first_failure_and_original_deadlines_survive_reattach() {
        let mut b = JobBudget::new(Duration::from_secs(60), Duration::ZERO).unwrap();
        let deadlines = b.deadlines().unwrap();
        let trace = b.track_admission();
        b.phase(AdmissionPhase::ParentFrontier);
        assert!(b.check().is_err());
        let first = trace.failure().unwrap();
        b.phase(AdmissionPhase::DurableGeneration);
        assert!(Arc::ptr_eq(&trace, &b.track_admission()));
        assert!(b.check().is_err());
        assert_eq!(trace.failure(), Some(first));
        assert_eq!(b.deadlines().unwrap(), deadlines);
    }
    #[test]
    fn admission_diagnostic_worker_failure_keeps_original_phase_and_budget() {
        use crate::quantum::{Job, Progress};
        let mut b = JobBudget::new(Duration::from_secs(60), Duration::from_secs(10)).unwrap();
        let trace = b.track_admission();
        let deadlines = b.deadlines().unwrap();
        let mut job = Job::start(b, |budget| {
            budget.phase(AdmissionPhase::ParentSourceReplay);
            // Test-only forced elapsed baseline. Failure recording itself stays
            // exactly the same path as an actual original-budget check refusal.
            budget.expired(Duration::from_secs(60), Some(Duration::from_secs(2)))?;
            Ok(())
        })
        .unwrap();
        let Progress::Complete(result, b) = job.advance().unwrap() else {
            panic!("complete")
        };
        assert!(matches!(
            result,
            Err(Error::Paused("cumulative foreground CPU/wall budget"))
        ));
        assert_eq!(
            trace.failure().unwrap().phase,
            AdmissionPhase::ParentSourceReplay
        );
        assert_eq!(b.deadlines().unwrap(), deadlines);
        assert_eq!(trace.failure(), b.trace.as_ref().unwrap().failure());
    }
    #[test]
    fn admission_diagnostic_no_expiry_is_not_invented_for_other_errors() {
        let mut b = JobBudget::vertex().unwrap();
        let trace = b.track_admission();
        b.phase(AdmissionPhase::BodyCrypto);
        b.check().unwrap();
        assert_eq!(trace.failure(), None);
        let mut job =
            crate::quantum::Job::start(b, |_| Err::<(), _>(Error::Invalid("synthetic refusal")))
                .unwrap();
        let crate::quantum::Progress::Complete(result, _) = job.advance().unwrap() else {
            panic!("complete")
        };
        assert!(matches!(result, Err(Error::Invalid(_))));
        assert_eq!(trace.failure(), None);
    }
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
