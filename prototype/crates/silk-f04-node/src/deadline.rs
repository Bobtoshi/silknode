//! Coordinator-owned native deadline lease. Never moved to a derivation worker.
//! Arm only after the durable attempt marker; its original budget is not reset.
//! Linux SIGKILL covers native calls without signal handlers or watchdog threads.
//! Marker persistence before arming and kernel scheduling latency remain separate
//! boundaries; an expired/pending signal may still kill after successful closure.
use crate::{Result, budget::JobBudget};

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
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
        sync::atomic::{AtomicBool, Ordering},
        time::Duration,
    };

    static ACTIVE: AtomicBool = AtomicBool::new(false);
    #[cfg(test)]
    static FAULT: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
    fn fault_at(stage: u8) -> Result<()> {
        #[cfg(test)]
        if FAULT.load(Ordering::Relaxed) == stage {
            return Err(Error::Unavailable("injected native timer boundary"));
        }
        let _ = stage;
        Ok(())
    }
    struct Lease;
    impl Lease {
        fn acquire() -> Result<Self> {
            ACTIVE
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| Error::Paused("another native foreground deadline is active"))?;
            Ok(Self)
        }
    }
    impl Drop for Lease {
        fn drop(&mut self) {
            ACTIVE.store(false, Ordering::Release);
        }
    }

    // Field order matters: delete both timers before releasing the process lease.
    pub(crate) struct NativeGuard {
        cpu: Option<Timer>,
        wall: Option<Timer>,
        _lease: Lease,
        armed: bool,
        _coordinator: PhantomData<Rc<()>>,
    }
    fn absolute(time: Duration) -> Result<TimeSpec> {
        let seconds = i64::try_from(time.as_secs())
            .map_err(|_| Error::Unavailable("native deadline representation"))?;
        if time.is_zero() {
            return Err(Error::Unavailable("zero native deadline would disarm"));
        }
        Ok(TimeSpec::new(seconds, time.subsec_nanos().into()))
    }
    fn timer(clock: ClockId) -> Result<Timer> {
        Timer::new(
            clock,
            SigEvent::new(SigevNotify::SigevSignal {
                signal: Signal::SIGKILL,
                si_value: 0,
            }),
        )
        .map_err(|_| Error::Unavailable("native deadline timer unavailable"))
    }
    impl NativeGuard {
        pub(crate) fn arm(budget: &JobBudget) -> Result<Self> {
            budget.check()?;
            let (wall, cpu) = budget.deadlines()?;
            let wall = absolute(wall)?;
            let cpu = absolute(cpu)?;
            let mut guard = Self {
                cpu: None,
                wall: None,
                _lease: Lease::acquire()?,
                armed: false,
                _coordinator: PhantomData,
            };
            guard.cpu = Some(timer(ClockId::CLOCK_PROCESS_CPUTIME_ID)?);
            fault_at(1)?;
            guard.wall = Some(timer(ClockId::CLOCK_MONOTONIC)?);
            fault_at(2)?;
            // Even a partial arm must go through checked disarm on every exit.
            guard.armed = true;
            let flags = TimerSetTimeFlags::TFD_TIMER_ABSTIME;
            guard
                .cpu
                .as_mut()
                .expect("created CPU timer")
                .set(Expiration::OneShot(cpu), flags)
                .map_err(|_| Error::Unavailable("native CPU deadline arming"))?;
            fault_at(3)?;
            guard
                .wall
                .as_mut()
                .expect("created wall timer")
                .set(Expiration::OneShot(wall), flags)
                .map_err(|_| Error::Unavailable("native wall deadline arming"))?;
            fault_at(4)?;
            budget.check()?;
            Ok(guard)
        }
        /// Call after terminal closure or after a failed/cancelled worker joined.
        /// Uncertain cleanup terminates even if the durable outcome already exists.
        pub(crate) fn finish(&mut self) {
            if self.armed {
                if fault_at(5).is_err() {
                    std::process::abort();
                }
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
    impl Drop for NativeGuard {
        fn drop(&mut self) {
            if self.armed && std::thread::panicking() {
                std::process::abort();
            }
            self.finish();
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::thread;

        /// Each case is a separate explicitly selected isolated child process.
        /// The runner, not this process, checks expected SIGKILL/SIGABRT exits.
        #[test]
        #[ignore = "terminating timer qualification: isolated child only"]
        fn isolated_probe() {
            assert_eq!(std::env::var("SILK_F04_ISOLATED_LAB").as_deref(), Ok("1"));
            let case = std::env::var("SILK_F04_DEADLINE_CASE").unwrap();
            let short = Duration::from_millis(200);
            let long = Duration::from_secs(5);
            match case.as_str() {
                "wall" => {
                    let b = JobBudget::new(short, long).unwrap();
                    let _guard = NativeGuard::arm(&b).unwrap();
                    thread::sleep(long);
                    panic!("native wall expiry did not terminate");
                }
                "cpu" => {
                    let b = JobBudget::new(long, short).unwrap();
                    let _guard = NativeGuard::arm(&b).unwrap();
                    // Two separately sub-limit thread charges exceed the process
                    // cap in aggregate. A per-thread timer would reach only the
                    // five-second wall fallback, which the external runner rejects.
                    thread::spawn(|| burn_thread_cpu(Duration::from_millis(120)))
                        .join()
                        .unwrap();
                    burn_thread_cpu(Duration::from_millis(120));
                    thread::sleep(long);
                    panic!("aggregate CPU expiry did not terminate");
                }
                "randomx-native" => {
                    let b = JobBudget::new(long, short).unwrap();
                    let _guard = NativeGuard::arm(&b).unwrap();
                    println!("entering_pinned_native_randomx_initializer=true");
                    let mut vm = silk_randomx::RandomXV2Vm::new(&[17; 32]).unwrap();
                    println!(
                        "native_randomx_initializer_returned=true; entering_native_hash_loop=true"
                    );
                    let stop = std::time::Instant::now() + Duration::from_secs(2);
                    while std::time::Instant::now() < stop {
                        std::hint::black_box(vm.calculate_hash(&[18; 848]).unwrap());
                    }
                    panic!("native RandomX CPU expiry did not terminate");
                }
                "past-absolute" => {
                    let b = JobBudget::new(long, long).unwrap();
                    let past = b.deadlines().unwrap().0 - Duration::from_secs(6);
                    let mut timer = timer(ClockId::CLOCK_MONOTONIC).unwrap();
                    timer
                        .set(
                            Expiration::OneShot(absolute(past).unwrap()),
                            TimerSetTimeFlags::TFD_TIMER_ABSTIME,
                        )
                        .unwrap();
                    thread::sleep(Duration::from_secs(1));
                    panic!("past absolute expiry did not terminate");
                }
                "worker-busy-wall" => {
                    let b = JobBudget::new(short, long).unwrap();
                    let _guard = NativeGuard::arm(&b).unwrap();
                    let mut worker = crate::quantum::Job::start(b, |_| {
                        thread::sleep(Duration::from_secs(2)); // no cooperative check inside
                        Ok(())
                    })
                    .unwrap();
                    let _ = worker.advance();
                    panic!("busy worker wall expiry did not terminate");
                }
                "panic" => {
                    let b = JobBudget::new(long, long).unwrap();
                    let _guard = NativeGuard::arm(&b).unwrap();
                    panic!("owned qualification panic while armed");
                }
                "disarm-failure" => {
                    let b = JobBudget::new(long, long).unwrap();
                    let mut guard = NativeGuard::arm(&b).unwrap();
                    FAULT.store(5, Ordering::Relaxed);
                    guard.finish();
                    panic!("uncertain disarm did not terminate");
                }
                "cleanup" => {
                    for stage in 1..=4 {
                        FAULT.store(stage, Ordering::Relaxed);
                        let b = JobBudget::new(short, long).unwrap();
                        assert!(NativeGuard::arm(&b).is_err());
                        FAULT.store(0, Ordering::Relaxed);
                        assert!(!ACTIVE.load(Ordering::Acquire));
                    }
                    let b = JobBudget::new(short, long).unwrap();
                    let mut guard = NativeGuard::arm(&b).unwrap();
                    let saved = b.deadlines().unwrap();
                    assert!(matches!(NativeGuard::arm(&b), Err(Error::Paused(_))));
                    assert_eq!(b.deadlines().unwrap(), saved);
                    guard.finish();
                    // Timer identities still exist until drop; finishing must
                    // not let a second job overlap their cleanup.
                    assert!(ACTIVE.load(Ordering::Acquire));
                    drop(guard);
                    assert!(!ACTIVE.load(Ordering::Acquire));
                    thread::sleep(short * 2);
                    assert!(NativeGuard::arm(&b).is_err()); // no fresh allowance
                    assert!(!ACTIVE.load(Ordering::Acquire));
                    let b = JobBudget::new(short, long).unwrap();
                    drop(NativeGuard::arm(&b).unwrap());
                    thread::sleep(short * 2);
                }
                "worker-cancel" => {
                    let b = JobBudget::new(short, long).unwrap();
                    let mut guard = NativeGuard::arm(&b).unwrap();
                    let worker = crate::quantum::Job::start(b, |_| Ok(())).unwrap();
                    drop(worker); // joined while guard is still armed
                    guard.finish();
                    drop(guard);
                    thread::sleep(short * 2);
                }
                "yielded-cancel" => {
                    let b = JobBudget::new(short, long).unwrap();
                    let mut guard = NativeGuard::arm(&b).unwrap();
                    let mut worker = crate::quantum::Job::start(b, |budget| {
                        for _ in 0..4097 {
                            budget.probe()?;
                        }
                        Ok(())
                    })
                    .unwrap();
                    assert!(matches!(
                        worker.advance().unwrap(),
                        crate::quantum::Progress::Pending(_)
                    ));
                    drop(worker);
                    guard.finish();
                    drop(guard);
                    thread::sleep(short * 2);
                }
                _ => panic!("unknown bounded deadline case"),
            }
            println!("native_deadline_case={case};complete=true");
        }
        fn burn_thread_cpu(duration: Duration) {
            let clock = || {
                let value = rustix::time::clock_gettime_dynamic(
                    rustix::time::DynamicClockId::Known(rustix::time::ClockId::ThreadCPUTime),
                )
                .unwrap();
                Duration::new(
                    value.tv_sec.try_into().unwrap(),
                    value.tv_nsec.try_into().unwrap(),
                )
            };
            let start = clock();
            let mut value = 1_u64;
            while clock() - start < duration {
                value =
                    std::hint::black_box(value.wrapping_mul(6364136223846793005).wrapping_add(1));
            }
        }
    }
}

// Portable component checks retain cumulative cooperative checks. This fallback
// is deliberately NOT a qualified native per-job runtime on other platforms.
#[cfg(not(target_os = "linux"))]
mod platform {
    use super::*;
    pub(crate) struct NativeGuard;
    impl NativeGuard {
        pub(crate) fn arm(budget: &JobBudget) -> Result<Self> {
            budget.check()?;
            let _ = budget.deadlines()?;
            Ok(Self)
        }
        pub(crate) fn finish(&mut self) {}
    }
}
pub(crate) use platform::NativeGuard;
