//! Native whole-round CPU lease, not a substitute for the role cgroup profile.
//!
//! Linux kills the actual process during native crypto without a watchdog thread.
//! The caller arms before any active-round work and keeps it through terminal cleanup.
use crate::{Result, schedule::Schedule};

#[cfg(target_os = "linux")]
mod platform {
    use super::{Result, Schedule};
    use crate::Error;
    use nix::{
        sys::{
            signal::{SigEvent, SigevNotify, Signal},
            time::TimeSpec,
            timer::{Expiration, Timer, TimerSetTimeFlags},
        },
        time::ClockId,
    };
    use std::{
        marker::PhantomData,
        rc::Rc,
        sync::atomic::{AtomicU8, Ordering},
        time::{Duration, Instant},
    };

    static ACTIVE: AtomicU8 = AtomicU8::new(0);
    struct Lease;
    impl Lease {
        fn acquire() -> Result<Self> {
            ACTIVE
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                    (active < 2).then_some(active + 1)
                })
                .map_err(|_| Error::Unavailable("relay two-round native lease cap"))?;
            Ok(Self)
        }
    }
    impl Drop for Lease {
        fn drop(&mut self) {
            ACTIVE.fetch_sub(1, Ordering::AcqRel);
        }
    }

    /// One non-restarting2-CPU-second lease for the whole role round.
    ///
    /// Whole-round wall termination is at+30; every earlier fixed output/read
    /// barrier remains separately enforced by its coordinator. Two overlapping
    /// leases conservatively count the same process CPU against both, never reset
    /// allowances per phase. RSS/tasks/socket/storage caps remain native-runtime gates.
    pub struct RoundGuard {
        cpu: Option<Timer>,
        wall: Option<Timer>,
        _lease: Lease,
        round: u64,
        #[cfg(all(feature = "aip2-preparation", feature = "functional-lab"))]
        schedule_identity: Rc<()>,
        cpu_deadline: Duration,
        wall_deadline: Instant,
        #[cfg(feature = "functional-lab")]
        native_wall_deadline: Duration,
        armed: bool,
        _coordinator: PhantomData<Rc<()>>,
    }
    impl RoundGuard {
        /// Arm once on the sole coordinator before any active-round work. Even
        /// unsuccessful arming consumes this schedule's lease; no hidden retry.
        /// # Errors
        /// Refuses late/unhealthy timing, a reused schedule, excess rounds or native failure.
        pub fn arm(schedule: &Schedule) -> Result<Self> {
            Self::arm_until(schedule, schedule.at(30_000_000_000)?)
        }
        /// Separate IM3 profile; never called by the legacy driver. The CPU
        /// allowance remains the same absolute two seconds for the whole cycle.
        #[cfg(feature = "aip2-preparation")]
        pub(crate) fn arm_im3(schedule: &Schedule) -> Result<Self> {
            let end = schedule
                .at(0)?
                .checked_add(Duration::from_secs(50))
                .ok_or(Error::Unavailable("IM3 native wall representation"))?;
            Self::arm_until(schedule, end)
        }
        fn arm_until(schedule: &Schedule, wall_deadline: Instant) -> Result<Self> {
            schedule.clock_healthy()?;
            schedule.completed_before(-10_000_000_000)?;
            if schedule.budget_claimed.replace(true) {
                return Err(Error::Unavailable("relay round budget already claimed"));
            }
            let cpu_deadline = clock(rustix::time::ClockId::ProcessCPUTime)?
                .checked_add(Duration::from_secs(2))
                .ok_or(Error::Unavailable("relay CPU deadline overflow"))?;
            // Reading native monotonic BEFORE Instant gives a conservative
            // mapping, not a fresh allowance at each later phase or poll.
            let native = clock(rustix::time::ClockId::Monotonic)?;
            let remaining = wall_deadline
                .checked_duration_since(Instant::now())
                .ok_or(Error::Unavailable("relay round already expired"))?;
            let wall_absolute = native
                .checked_add(remaining)
                .ok_or(Error::Unavailable("relay wall deadline overflow"))?;
            let mut guard = Self {
                cpu: None,
                wall: None,
                _lease: Lease::acquire()?,
                round: schedule.round(),
                #[cfg(all(feature = "aip2-preparation", feature = "functional-lab"))]
                schedule_identity: Rc::clone(&schedule.lease_identity),
                cpu_deadline,
                wall_deadline,
                #[cfg(feature = "functional-lab")]
                native_wall_deadline: wall_absolute,
                armed: false,
                _coordinator: PhantomData,
            };
            guard.cpu = Some(timer(ClockId::CLOCK_PROCESS_CPUTIME_ID)?);
            guard.wall = Some(timer(ClockId::CLOCK_MONOTONIC)?);
            guard.armed = true;
            let flags = TimerSetTimeFlags::TFD_TIMER_ABSTIME;
            guard
                .cpu
                .as_mut()
                .expect("created CPU timer")
                .set(Expiration::OneShot(absolute(cpu_deadline)?), flags)
                .map_err(|_| Error::Unavailable("relay native CPU timer arm"))?;
            guard
                .wall
                .as_mut()
                .expect("created wall timer")
                .set(Expiration::OneShot(absolute(wall_absolute)?), flags)
                .map_err(|_| Error::Unavailable("relay native wall timer arm"))?;
            guard.check()?;
            // Native timer setup or preemption must not extend the arming
            // phase. The consumed claim is retained and Drop disarms on error.
            schedule.completed_before(-10_000_000_000)?;
            Ok(guard)
        }
        /// Cooperative check of the SAME absolute native deadlines. It does not
        /// replace the armed kernel timers during noninterruptible crypto work.
        /// # Errors
        /// Refuses an expired lease without rebasing either deadline.
        pub fn check(&self) -> Result<()> {
            if Instant::now() >= self.wall_deadline
                || clock(rustix::time::ClockId::ProcessCPUTime)? >= self.cpu_deadline
            {
                return Err(Error::Unavailable("relay whole-round CPU/wall budget"));
            }
            Ok(())
        }
        /// Schedule identity is local and nonserializable, not a peer permission.
        #[must_use]
        pub const fn round(&self) -> u64 {
            self.round
        }
        // Retain the original nonserializable identity even if its schedule is
        // dropped: allocator address reuse cannot substitute a fresh mapping.
        #[cfg(all(feature = "aip2-preparation", feature = "functional-lab"))]
        pub(crate) fn matches_schedule(&self, schedule: &Schedule) -> bool {
            Rc::ptr_eq(&self.schedule_identity, &schedule.lease_identity)
        }
        /// Original kernel monotonic deadline for an isolated external recorder.
        /// This read-only value cannot change the timer or admit a clock source.
        /// # Errors
        /// Unsupported platforms have no such native lease.
        #[cfg(feature = "functional-lab")]
        pub const fn native_wall_deadline(&self) -> Result<Duration> {
            Ok(self.native_wall_deadline)
        }
        fn disarm(&mut self) {
            if self.armed {
                for timer in [&mut self.cpu, &mut self.wall].into_iter().flatten() {
                    if timer
                        .set(
                            Expiration::OneShot(TimeSpec::new(0, 0)),
                            TimerSetTimeFlags::empty(),
                        )
                        .is_err()
                    {
                        std::process::abort();
                    }
                }
                self.armed = false;
            }
        }
    }
    impl Drop for RoundGuard {
        fn drop(&mut self) {
            if self.armed && std::thread::panicking() {
                std::process::abort();
            }
            self.disarm();
        }
    }
    fn timer(clock: ClockId) -> Result<Timer> {
        Timer::new(
            clock,
            SigEvent::new(SigevNotify::SigevSignal {
                signal: Signal::SIGKILL,
                si_value: 0,
            }),
        )
        .map_err(|_| Error::Unavailable("relay native timer unavailable"))
    }
    fn clock(id: rustix::time::ClockId) -> Result<Duration> {
        let t = rustix::time::clock_gettime_dynamic(rustix::time::DynamicClockId::Known(id))
            .map_err(|_| Error::Unavailable("relay native clock unavailable"))?;
        Ok(Duration::new(
            u64::try_from(t.tv_sec).map_err(|_| Error::Unavailable("relay clock seconds"))?,
            u32::try_from(t.tv_nsec).map_err(|_| Error::Unavailable("relay clock nanoseconds"))?,
        ))
    }
    fn absolute(time: Duration) -> Result<TimeSpec> {
        if time.is_zero() {
            return Err(Error::Unavailable("zero relay deadline would disarm"));
        }
        Ok(TimeSpec::new(
            i64::try_from(time.as_secs())
                .map_err(|_| Error::Unavailable("relay deadline representation"))?,
            time.subsec_nanos().into(),
        ))
    }
}
#[cfg(not(target_os = "linux"))]
mod platform {
    use super::{Result, Schedule};
    /// No fallback pretends to enforce the Linux native-round qualification.
    pub struct RoundGuard {
        round: u64,
    }
    impl RoundGuard {
        /// # Errors
        /// This platform has no qualified native relay-round backend.
        pub fn arm(schedule: &Schedule) -> Result<Self> {
            schedule.budget_claimed.set(true);
            Err(crate::Error::Unavailable(
                "native relay round guard unsupported",
            ))
        }
        #[cfg(feature = "aip2-preparation")]
        pub(crate) fn arm_im3(schedule: &Schedule) -> Result<Self> {
            Self::arm(schedule)
        }
        /// # Errors
        /// No qualified guard can be obtained on this platform.
        pub const fn check(&self) -> Result<()> {
            Err(crate::Error::Unavailable(
                "native relay round guard unsupported",
            ))
        }
        /// Bound round, if an implementation can provide a guard in the future.
        #[must_use]
        pub const fn round(&self) -> u64 {
            self.round
        }
        #[cfg(all(feature = "aip2-preparation", feature = "functional-lab"))]
        pub(crate) const fn matches_schedule(&self, _schedule: &Schedule) -> bool {
            false
        }
        /// # Errors
        /// This platform has no qualified native relay-round backend.
        #[cfg(feature = "functional-lab")]
        pub const fn native_wall_deadline(&self) -> Result<std::time::Duration> {
            Err(crate::Error::Unavailable(
                "native relay round guard unsupported",
            ))
        }
    }
}
pub use platform::RoundGuard;
