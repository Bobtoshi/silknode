//! Separate disabled IM3-60-v1 mapping and native whole-cycle owner.
//! No clock/path/custody qualification or socket activation is inferred.
use crate::{
    Error, Result,
    config::SignedConfig,
    runtime::RoundGuard,
    schedule::{QualifiedClockSample, Schedule},
};
use std::{
    rc::Rc,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

/// Fixed phases from the reviewed 60-second profile; windows are half-open.
#[derive(Clone, Copy)]
pub enum Phase {
    /// Original manifest fanout.
    Manifest,
    /// Client durable choice before either proof starts.
    ClientChoice,
    /// First sequential five-second proof.
    BProof,
    /// Internal B encryption; no B ciphertext export.
    BSeal,
    /// Second sequential five-second proof.
    CProof,
    /// Final C/A sealing.
    Onion,
    /// A freezes all client inputs.
    AFreeze,
    /// C verifies complete membership and privately permutes.
    CGate,
    /// Irreversible C disclosure fence.
    CDecision,
    /// C writes original B records.
    COutput,
    /// A_READY copy and C_READY.
    CReady,
    /// B membership/Sapling gate and staging.
    BGate,
    /// B readiness chain.
    BReady,
    /// Producer stage-4 copies.
    ProducerStage,
    /// Producer acknowledgements.
    Ack,
    /// B forwards all three acknowledgements.
    AckFanout,
    /// A authorization decision.
    AuthorizationDecision,
    /// Original authorization write.
    Authorization,
    /// B authorization copies.
    AuthorizationCopies,
    /// B release fence.
    ReleaseDecision,
    /// Original release writes.
    Release,
    /// Complete producer opening.
    ProducerOpen,
}
impl Phase {
    fn offsets(self) -> (i64, i64) {
        match self {
            Self::Manifest => (-8_000_000_000, -7_000_000_000),
            Self::ClientChoice => (-5_000_000_000, -4_500_000_000),
            Self::BProof => (-4_500_000_000, 500_000_000),
            Self::BSeal => (500_000_000, 1_000_000_000),
            Self::CProof => (1_000_000_000, 6_000_000_000),
            Self::Onion => (6_000_000_000, 6_500_000_000),
            Self::AFreeze => (15_000_000_000, 15_500_000_000),
            Self::CGate => (17_500_000_000, 19_250_000_000),
            Self::CDecision => (19_250_000_000, 19_500_000_000),
            Self::COutput => (20_000_000_000, 20_250_000_000),
            Self::CReady => (20_250_000_000, 20_500_000_000),
            Self::BGate => (22_000_000_000, 23_750_000_000),
            Self::BReady => (24_000_000_000, 25_000_000_000),
            Self::ProducerStage => (27_000_000_000, 28_000_000_000),
            Self::Ack => (30_000_000_000, 30_500_000_000),
            Self::AckFanout => (32_500_000_000, 32_875_000_000),
            Self::AuthorizationDecision => (34_500_000_000, 35_000_000_000),
            Self::Authorization => (35_000_000_000, 35_500_000_000),
            Self::AuthorizationCopies => (37_500_000_000, 38_000_000_000),
            Self::ReleaseDecision => (39_500_000_000, 40_000_000_000),
            Self::Release => (40_000_000_000, 40_500_000_000),
            Self::ProducerOpen => (42_000_000_000, 43_500_000_000),
        }
    }
}

/// Immutable separate even-round mapping. The old Schedule remains bounded at+30.
pub struct Im3Schedule {
    base: Schedule,
    identity: Rc<()>,
}
impl Im3Schedule {
    /// Derive one even-round origin from an independently qualified sample.
    /// Caller must establish the external 500ms clock/250ms path premises.
    pub fn new(config: &SignedConfig, round: u64, sample: QualifiedClockSample) -> Result<Self> {
        if round % 2 != 0 {
            return Err(Error::Unavailable("IM3 odd round"));
        }
        let base = Schedule::new(config, round, sample)?;
        base.at(0)?
            .checked_add(Duration::from_secs(50))
            .ok_or(Error::Unavailable("IM3 wall mapping"))?;
        Ok(Self {
            base,
            identity: Rc::new(()),
        })
    }
    /// Fixed round throughout both proof jobs, transport and settlement handoff.
    pub const fn round(&self) -> u64 {
        self.base.round()
    }
    /// Whether construction used the operator-qualified sample API; this does
    /// not itself prove that external qualification was honest.
    pub const fn uses_qualified_source(&self) -> bool {
        self.base.uses_qualified_source()
    }
    /// Explicit same-host fixture mapping only. Retains even-round and all
    /// immutable deadlines; establishes no operational clock/path premise.
    #[cfg(feature = "functional-lab")]
    pub fn functional_fixture(config: &SignedConfig, round: u64) -> Result<Self> {
        if round % 2 != 0 {
            return Err(Error::Unavailable("IM3 odd round"));
        }
        let base = Schedule::functional_fixture(config, round)?;
        base.at(0)?
            .checked_add(Duration::from_secs(50))
            .ok_or(Error::Unavailable("IM3 wall mapping"))?;
        Ok(Self {
            base,
            identity: Rc::new(()),
        })
    }
    /// Observe the original unqualified fixture clock without upgrading it.
    #[cfg(feature = "functional-lab")]
    pub fn observe_functional_clock(&self) -> Result<()> {
        self.base.observe_functional_clock()
    }
    /// Exact profile interval -10..+50; never rebase a missed deadline.
    pub fn at(&self, nanos: i64) -> Result<Instant> {
        if !(-10_000_000_000..=50_000_000_000).contains(&nanos) {
            return Err(Error::Unavailable("IM3 slot offset"));
        }
        let duration = Duration::from_nanos(nanos.unsigned_abs());
        let origin = self.base.at(0)?;
        (if nanos < 0 {
            origin.checked_sub(duration)
        } else {
            origin.checked_add(duration)
        })
        .ok_or(Error::Unavailable("IM3 slot representation"))
    }
    /// Fixed phase start/end; numerical mapping alone grants no execution lease.
    pub fn window(&self, phase: Phase) -> Result<(Instant, Instant)> {
        let (a, b) = phase.offsets();
        Ok((self.at(a)?, self.at(b)?))
    }
    /// Client i's exact .2-second slot, beginning at+7 and ending at+13.4.
    pub fn client_slot(&self, index: u8) -> Result<(Instant, Instant)> {
        if index >= 32 {
            return Err(Error::Invalid("IM3 client slot"));
        }
        let start = 7_000_000_000 + 200_000_000 * i64::from(index);
        Ok((self.at(start)?, self.at(start + 200_000_000)?))
    }
    /// A or C's fixed 32-record train. No caller-selected pacing/deadline.
    pub fn relay_slot(&self, middle: bool, index: u8) -> Result<(Instant, Instant)> {
        if index >= 32 {
            return Err(Error::Invalid("IM3 relay slot"));
        }
        let start = if middle {
            20_000_000_000
        } else {
            15_500_000_000
        } + 7_812_500 * i64::from(index);
        Ok((self.at(start)?, self.at(start + 7_812_500)?))
    }
    /// A recorded clock failure is sticky; observations cannot change origin.
    pub fn observe_clock(&self, sample: &QualifiedClockSample) -> Result<()> {
        self.base.observe_clock(sample)
    }
    /// Check recorded client clock health without a relay execution lease.
    /// External observations/qualification and worker containment remain required.
    pub fn check_client_clock(&self) -> Result<()> {
        self.base.clock_healthy()
    }
    /// Client-only clock/phase check. This is NOT the relay's two-CPU-second
    /// lease or proof-worker containment. A trusted local runner must separately
    /// enforce each job's original deadline, four CPU seconds and 1 GiB RSS.
    pub(crate) fn require_client(&self, phase: Phase) -> Result<()> {
        if !matches!(
            phase,
            Phase::ClientChoice | Phase::BProof | Phase::BSeal | Phase::CProof | Phase::Onion
        ) {
            return Err(Error::Invalid("IM3 non-client phase"));
        }
        self.base.clock_healthy()?;
        let (start, end) = self.window(phase)?;
        let now = Instant::now();
        if now < start || now >= end {
            return Err(Error::Unavailable("IM3 client fixed phase missed"));
        }
        Ok(())
    }
    pub(crate) fn client_before_choice(&self) -> Result<()> {
        self.base.clock_healthy()?;
        self.base.completed_before(-5_000_000_000).map(|_| ())
    }
    /// Refuse a phase unless the original native guard and healthy mapping agree.
    pub fn require(&self, guard: &Im3Guard, phase: Phase) -> Result<()> {
        self.check_guard(guard)?;
        let (start, end) = self.window(phase)?;
        let now = Instant::now();
        if now < start || now >= end {
            return Err(Error::Unavailable("IM3 fixed phase missed"));
        }
        Ok(())
    }
    pub(crate) fn check_guard(&self, guard: &Im3Guard) -> Result<()> {
        if !Rc::ptr_eq(&self.identity, &guard.identity) {
            return Err(Error::Unavailable("IM3 foreign lease"));
        }
        self.base.clock_healthy()?;
        guard.native.check()
    }
}
static IM3_ACTIVE: AtomicBool = AtomicBool::new(false);
struct Exclusive;
impl Drop for Exclusive {
    fn drop(&mut self) {
        IM3_ACTIVE.store(false, Ordering::Release);
    }
}
/// One process-owned active IM3 cycle. CPU/wall timers are native on Linux;
/// unsupported hosts refuse. The lease is not reset at phase/proof boundaries.
pub struct Im3Guard {
    native: RoundGuard,
    identity: Rc<()>,
    _exclusive: Exclusive,
}
impl Im3Guard {
    /// Arm once before T-10: two CPU seconds total, hard wall at T+50.
    /// Failed arming consumes this mapping; no same-schedule retry.
    pub fn arm(schedule: &Im3Schedule) -> Result<Self> {
        if IM3_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            schedule.base.budget_claimed.set(true);
            return Err(Error::Unavailable("IM3 cycle already active"));
        }
        let exclusive = Exclusive;
        let native = RoundGuard::arm_im3(&schedule.base)?;
        Ok(Self {
            native,
            identity: Rc::clone(&schedule.identity),
            _exclusive: exclusive,
        })
    }
    /// Check the same original native deadlines without granting a new allowance.
    pub fn check(&self, schedule: &Im3Schedule) -> Result<()> {
        schedule.check_guard(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    fn mapping(round: u64, lead: Duration) -> Im3Schedule {
        let now = Instant::now();
        let utc = UNIX_EPOCH + Duration::from_secs(round * 30) - lead;
        Im3Schedule::new(
            &crate::tests::epoch_config(0),
            round,
            QualifiedClockSample::from_qualified_source(utc, now, Duration::ZERO).unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn fixed_even_mapping_and_sequential_proof_windows() {
        let s = mapping(6, Duration::from_secs(11));
        let origin = s.at(0).unwrap();
        assert_eq!(
            s.window(Phase::BProof).unwrap().1 - s.window(Phase::BProof).unwrap().0,
            Duration::from_secs(5)
        );
        assert_eq!(
            s.window(Phase::CProof).unwrap().1 - s.window(Phase::CProof).unwrap().0,
            Duration::from_secs(5)
        );
        assert_eq!(
            s.client_slot(31).unwrap().1 - origin,
            Duration::from_millis(13400)
        );
        assert_eq!(
            s.relay_slot(true, 31).unwrap().1 - origin,
            Duration::from_millis(20250)
        );
        assert_eq!(
            s.window(Phase::ProducerOpen).unwrap().1 - origin,
            Duration::from_millis(43500)
        );
        assert!(s.base.at(42_000_000_000).is_err());
        assert!(s.at(50_000_000_001).is_err());
        assert!(s.client_slot(32).is_err());
        assert!(s.relay_slot(false, 32).is_err());
        let sample = QualifiedClockSample::from_qualified_source(
            SystemTime::UNIX_EPOCH + Duration::from_secs(180),
            Instant::now(),
            Duration::ZERO,
        )
        .unwrap();
        assert!(Im3Schedule::new(&crate::tests::epoch_config(0), 7, sample).is_err());
    }
    #[test]
    fn lease_is_original_exclusive_and_cannot_rearm() {
        let s = mapping(6, Duration::from_secs(11));
        let other = mapping(6, Duration::from_secs(11));
        let g = Im3Guard::arm(&s).unwrap();
        assert!(g.check(&s).is_ok());
        assert!(g.check(&other).is_err());
        assert!(Im3Guard::arm(&other).is_err());
        assert!(s.require(&g, Phase::CGate).is_err());
        drop(g);
        assert!(Im3Guard::arm(&s).is_err());
        assert!(Im3Guard::arm(&other).is_err());
        let late = mapping(6, Duration::from_secs(9));
        assert!(Im3Guard::arm(&late).is_err());
    }
    #[test]
    #[ignore = "isolated native termination child"]
    fn native_budget_child() {
        let s = mapping(6, Duration::from_millis(10100));
        let _g = Im3Guard::arm(&s).unwrap();
        if std::env::var("SILK_IM3_TIMER_MODE").unwrap() == "cpu" {
            let mut n = 1u64;
            loop {
                n = std::hint::black_box(n.wrapping_mul(6364136223846793005).wrapping_add(1));
            }
        } else {
            loop {
                std::thread::park();
            }
        }
    }
    #[test]
    #[ignore = "isolated 60-second native wall plus two-CPU-second termination checks"]
    fn native_cpu_and_wall_kill_without_phase_reset() {
        use std::os::unix::process::ExitStatusExt;
        for mode in ["cpu", "wall"] {
            let start = Instant::now();
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "im3_schedule::tests::native_budget_child",
                    "--exact",
                    "--ignored",
                    "--test-threads=1",
                ])
                .env("SILK_IM3_TIMER_MODE", mode)
                .status()
                .unwrap();
            assert_eq!(status.signal(), Some(9));
            let elapsed = start.elapsed();
            if mode == "wall" {
                assert!(elapsed >= Duration::from_secs(60) && elapsed < Duration::from_secs(65));
            } else {
                assert!(elapsed < Duration::from_secs(8));
            }
            println!("IM3 {mode} kernel termination after {elapsed:?}");
        }
    }
}
