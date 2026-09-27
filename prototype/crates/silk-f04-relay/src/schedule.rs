//! Immutable monotonic schedule from an explicitly qualified external UTC sample.
//! This module checks supplied bounds; it cannot prove the clock source's honesty.
use crate::{Error, Result, config::SignedConfig};
use std::{
    cell::Cell,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(feature = "functional-lab")]
static FIXTURE_OFFSET: std::sync::OnceLock<i64> = std::sync::OnceLock::new();

/// Set one immutable, explicit protocol-time offset for an isolated epoch fixture.
/// This never changes certificate time or the native monotonic/CPU clocks.
/// # Errors
/// Refuses a second selection, use after a sample, or an offset beyond two days.
#[cfg(feature = "functional-lab")]
pub fn initialize_functional_offset(seconds: i64) -> Result<()> {
    if seconds.unsigned_abs() > 172_800 {
        return Err(Error::Unavailable(
            "fixture offset outside bounded two days",
        ));
    }
    FIXTURE_OFFSET
        .set(seconds)
        .map_err(|_| Error::Unavailable("fixture clock offset already fixed"))
}

/// Current functional protocol time, explicitly NOT qualified external UTC.
/// # Errors
/// Refuses host pre-epoch time or shifted time overflow/underflow.
#[cfg(feature = "functional-lab")]
pub fn functional_utc() -> Result<Duration> {
    shifted_fixture_utc(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Unavailable("fixture host UTC epoch"))?,
        *FIXTURE_OFFSET.get_or_init(|| 0),
    )
}

#[cfg(feature = "functional-lab")]
fn shifted_fixture_utc(utc: Duration, seconds: i64) -> Result<Duration> {
    let offset = Duration::from_secs(seconds.unsigned_abs());
    (if seconds >= 0 {
        utc.checked_add(offset)
    } else {
        utc.checked_sub(offset)
    })
    .ok_or(Error::Unavailable("fixture shifted UTC overflow"))
}

/// Trusted local clock input, not peer timestamps or inferred NTP qualification.
/// Caller must separately establish the stated absolute UTC error of its source.
pub struct QualifiedClockSample {
    utc: Duration,
    monotonic: Instant,
    error: Duration,
}
impl QualifiedClockSample {
    /// Admit an operator-qualified paired sample, INCLUDING capture uncertainty.
    /// Passing host wall time alone does not establish the external500ms premise.
    /// # Errors
    /// Refuses pre-epoch UTC, future monotonic sample or error exceeding500ms.
    pub fn from_qualified_source(
        utc: SystemTime,
        monotonic: Instant,
        absolute_error: Duration,
    ) -> Result<Self> {
        if absolute_error > Duration::from_millis(500) || monotonic > Instant::now() {
            return Err(Error::Unavailable("relay clock admission"));
        }
        Ok(Self {
            utc: utc
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Error::Unavailable("relay UTC epoch"))?,
            monotonic,
            error: absolute_error,
        })
    }
    /// UTC round in the qualified observation, never a peer's claimed round.
    #[must_use]
    pub const fn utc_round(&self) -> u64 {
        self.utc.as_secs() / 30
    }

    /// Conservative round bound at the actual restart, not at an earlier capture.
    /// An old qualification does not establish today's clock health. Require a
    /// sub-500ms capture and include both elapsed time and its admitted UTC error;
    /// close to a boundary this may deliberately defer eligibility by one round.
    pub(crate) fn restart_round(&self) -> Result<u64> {
        self.restart_round_at(Instant::now())
    }

    fn restart_round_at(&self, now: Instant) -> Result<u64> {
        let elapsed = now
            .checked_duration_since(self.monotonic)
            .filter(|age| *age <= Duration::from_millis(500))
            .ok_or(Error::Unavailable("stale restart clock capture"))?;
        let upper = self
            .utc
            .checked_add(elapsed)
            .and_then(|time| time.checked_add(self.error))
            .ok_or(Error::Unavailable("restart UTC bound overflow"))?;
        Ok(upper.as_secs() / 30)
    }
}

/// One mapping that never rebases during a round. Health observations can affect
/// only still-open role barriers; later failure cannot revoke a sealed decision.
pub struct Schedule {
    origin: Instant,
    sample: QualifiedClockSample,
    round: u64,
    last_observed: Cell<(Instant, Duration)>,
    clock_failed: Cell<bool>,
    pub(crate) budget_claimed: Cell<bool>,
    qualified: bool,
}
impl Schedule {
    /// Configure the fixed round once; expiry and overflow grant no grace period.
    /// # Errors
    /// Refuses wrong epoch, distant sample or unrepresentable local deadlines.
    pub fn new(config: &SignedConfig, round: u64, sample: QualifiedClockSample) -> Result<Self> {
        if !config.contains_round(round) || round.abs_diff(sample.utc_round()) > 2 {
            return Err(Error::Unavailable("relay schedule epoch/sample"));
        }
        let utc_origin = Duration::from_secs(
            round
                .checked_mul(30)
                .ok_or(Error::Unavailable("relay round overflow"))?,
        );
        let origin = if utc_origin >= sample.utc {
            sample
                .monotonic
                .checked_add(utc_origin.abs_diff(sample.utc))
        } else {
            sample
                .monotonic
                .checked_sub(sample.utc.abs_diff(utc_origin))
        }
        .ok_or(Error::Unavailable("relay monotonic origin"))?;
        origin
            .checked_sub(Duration::from_secs(10))
            .ok_or(Error::Unavailable("relay pre-round origin"))?;
        origin
            .checked_add(Duration::from_secs(30))
            .ok_or(Error::Unavailable("relay round end"))?;
        Ok(Self {
            origin,
            last_observed: Cell::new((sample.monotonic, sample.utc)),
            clock_failed: Cell::new(false),
            budget_claimed: Cell::new(false),
            qualified: true,
            sample,
            round,
        })
    }
    /// Explicit unqualified same-host fixture mapping. This feature is OFF by
    /// default; using it establishes no external UTC or epoch-lifecycle premise.
    /// # Errors
    /// Retains every ordinary numeric, epoch and immutable-deadline bound.
    #[cfg(feature = "functional-lab")]
    pub fn functional_fixture(config: &SignedConfig, round: u64) -> Result<Self> {
        let mut schedule = Self::new(config, round, fixture_sample()?)?;
        schedule.qualified = false;
        Ok(schedule)
    }
    /// Whether construction used the operator-qualified API, not proof that the
    /// external qualification was honest. False must never support live acceptance.
    #[must_use]
    pub const fn uses_qualified_source(&self) -> bool {
        self.qualified
    }
    /// Observe the same unqualified host source without upgrading its status.
    /// # Errors
    /// Refuses use on an operator-qualified schedule or a detected host clock step.
    #[cfg(feature = "functional-lab")]
    pub fn observe_functional_clock(&self) -> Result<()> {
        if self.qualified {
            return Err(Error::Unavailable(
                "unqualified clock on qualified schedule",
            ));
        }
        self.observe_clock(&fixture_sample()?)
    }
    /// Exact signed round selected at configuration.
    #[must_use]
    pub const fn round(&self) -> u64 {
        self.round
    }
    /// Immutable monotonic instant for a fixed offset, including pre-round slots.
    /// # Errors
    /// Refuses offsets outside this round's fixed -10..+30 second interval.
    pub fn at(&self, nanos: i64) -> Result<Instant> {
        if !(-10_000_000_000..=30_000_000_000).contains(&nanos) {
            return Err(Error::Unavailable("relay slot offset"));
        }
        let duration = Duration::from_nanos(nanos.unsigned_abs());
        if nanos < 0 {
            self.origin.checked_sub(duration)
        } else {
            self.origin.checked_add(duration)
        }
        .ok_or(Error::Unavailable("relay slot representation"))
    }
    /// Local completion time for a required authenticated observation. Call AFTER
    /// verification; caller-supplied arrival timestamps cannot backdate it.
    /// # Errors
    /// The closed barrier wins at the exact deadline; no500ms grace is added.
    pub fn completed_before(&self, cutoff_ns: i64) -> Result<Instant> {
        let observed = Instant::now();
        if observed >= self.at(cutoff_ns)? {
            return Err(Error::Unavailable("relay observation barrier closed"));
        }
        Ok(observed)
    }
    /// Require execution within an immutable fixed slot window.
    /// # Errors
    /// Refuses early/late execution without rebasing or retry permission.
    pub fn in_window(&self, start_ns: i64, end_ns: i64) -> Result<()> {
        let now = Instant::now();
        if start_ns >= end_ns || now < self.at(start_ns)? || now >= self.at(end_ns)? {
            return Err(Error::Unavailable("relay fixed slot missed"));
        }
        Ok(())
    }
    /// Detect a recorded clock step/error without changing any prior deadline.
    /// Both supplied samples require the same external clock qualification.
    /// # Errors
    /// Refuses rollback or discrepancy outside the two stated error intervals.
    pub fn observe_clock(&self, observation: &QualifiedClockSample) -> Result<()> {
        self.clock_healthy()?;
        // Health history advances separately from the immutable round mapping.
        // A sample within the original error envelope may still be a recorded
        // rollback relative to the most recent accepted observation.
        let (last_monotonic, last_utc) = self.last_observed.get();
        self.clock_failed.set(true);
        if observation.monotonic < last_monotonic || observation.utc < last_utc {
            return Err(Error::Unavailable("relay sequential clock regression"));
        }
        let elapsed = observation
            .monotonic
            .checked_duration_since(self.sample.monotonic)
            .ok_or(Error::Unavailable("relay monotonic regression"))?;
        let predicted = self
            .sample
            .utc
            .checked_add(elapsed)
            .ok_or(Error::Unavailable("relay UTC overflow"))?;
        if observation.utc < self.sample.utc
            || predicted.abs_diff(observation.utc) > self.sample.error + observation.error
        {
            return Err(Error::Unavailable("relay detected clock health failure"));
        }
        self.last_observed
            .set((observation.monotonic, observation.utc));
        self.clock_failed.set(false);
        Ok(())
    }
    /// Current recorded health, never a guarantee about undetected physical faults.
    /// Consumers consult this only while their own decision barrier is open.
    /// # Errors
    /// A detected failure is sticky for this schedule; there is no clock rebase.
    pub const fn clock_healthy(&self) -> Result<()> {
        if self.clock_failed.get() {
            Err(Error::Unavailable("relay recorded clock failure"))
        } else {
            Ok(())
        }
    }
}

#[cfg(feature = "functional-lab")]
fn fixture_sample() -> Result<QualifiedClockSample> {
    let monotonic = Instant::now();
    let utc = functional_utc()?;
    if monotonic.elapsed() > Duration::from_millis(1) {
        return Err(Error::Unavailable("fixture clock capture preempted"));
    }
    Ok(QualifiedClockSample {
        utc,
        monotonic,
        error: Duration::from_millis(500),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "functional-lab")]
    fn fixed_fixture_offset_preserves_subseconds_and_refuses_underflow() {
        let time = Duration::from_millis(60_123);
        assert_eq!(
            shifted_fixture_utc(time, 86_400).unwrap(),
            Duration::from_millis(86_460_123)
        );
        assert_eq!(
            shifted_fixture_utc(time, -60).unwrap(),
            Duration::from_millis(123)
        );
        assert!(shifted_fixture_utc(time, -61).is_err());
        let round = functional_utc().unwrap().as_secs() / 30;
        let config = crate::tests::epoch_config(u32::try_from(round / 2880).unwrap());
        let schedule = Schedule::functional_fixture(&config, round).unwrap();
        assert!(!schedule.uses_qualified_source());
        assert_eq!(
            schedule
                .at(30_000_000_000)
                .unwrap()
                .duration_since(schedule.at(0).unwrap()),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn restart_floor_requires_fresh_capture_and_covers_boundary_uncertainty() {
        let captured = Instant::now();
        let sample = QualifiedClockSample {
            utc: Duration::from_millis(59_400),
            monotonic: captured,
            error: Duration::from_millis(500),
        };
        assert_eq!(sample.restart_round_at(captured).unwrap(), 1);
        assert_eq!(
            sample
                .restart_round_at(captured + Duration::from_millis(100))
                .unwrap(),
            2
        );
        assert!(
            sample
                .restart_round_at(captured + Duration::from_millis(501))
                .is_err()
        );
        assert!(
            sample
                .restart_round_at(captured.checked_sub(Duration::from_nanos(1)).unwrap())
                .is_err()
        );
    }
}
