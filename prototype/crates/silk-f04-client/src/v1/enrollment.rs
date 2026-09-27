//! One actual TCP/TLS/Join attempt under the retained original setup window.
use super::{
    ClientV1, Digest, Error, Instant, QualifiedClockSample, Rc, RecordSize, RefCell, Result,
    Roster, Schedule, SignedConfig, Transport, Zeroizing,
};
use silk_f04_relay::tls::{ClientProfile, ConnectStep, Connecting, Setup, SetupStep};
use std::time::Duration;

enum Pending {
    Connecting(Connecting),
    Tls(Setup),
    Join(Transport),
}
/// One consumed connection attempt, never a payment-driven reconnect loop.
///
/// A's actual token admission still decides whether the remote session is usable;
/// successful local Join writing alone does not prove remote acceptance.
pub struct EnrollmentV1 {
    config: Rc<SignedConfig>,
    schedule: Rc<Schedule>,
    window: Window,
    eligible: u64,
    profile: ClientProfile,
    join: Zeroizing<[u8; 128]>,
    slot: u8,
    pending: Pending,
}
/// Incremental bounded setup; no blocking waits or repeated connects.
#[allow(clippy::large_enum_variant)]
pub enum EnrollmentProgressV1 {
    /// Original connection and unchanged setup deadline.
    Pending(EnrollmentV1),
    /// Actual TLS and one full Join write; no payment has been released.
    Joined(ClientV1),
}
#[derive(Clone, Copy)]
pub(super) enum Window {
    Baseline,
    Repair,
    NextEpoch,
}
impl Window {
    pub(super) fn check(self, schedule: &Schedule) -> Result<Instant> {
        let (start, end) = match self {
            Self::Baseline => {
                let before = schedule.at(-10_000_000_000)?;
                (
                    before
                        .checked_sub(Duration::from_secs(50))
                        .ok_or(Error::Unavailable("client setup start"))?,
                    before
                        .checked_sub(Duration::from_secs(20))
                        .ok_or(Error::Unavailable("client setup end"))?,
                )
            }
            Self::Repair => (schedule.at(24_000_000_000)?, schedule.at(28_000_000_000)?),
            Self::NextEpoch => (schedule.at(0)?, schedule.at(30_000_000_000)?),
        };
        if Instant::now() < start || Instant::now() >= end {
            return Err(Error::Unavailable("client epoch setup window"));
        }
        schedule.clock_healthy()?;
        Ok(end)
    }
}
impl EnrollmentV1 {
    /// Make one actual configured-A attempt in the predetermined epoch window.
    /// The caller must ensure only one owner per token (A also rejects duplicates),
    /// and enforce the wallet/prover native process budget outside this component.
    /// # Errors
    /// Refuses a foreign profile/token/roster, setup time, or connect failure.
    pub fn start(
        config: Rc<SignedConfig>,
        hashes: [Digest; 32],
        token: Zeroizing<[u8; 32]>,
        profile: ClientProfile,
        sample: QualifiedClockSample,
    ) -> Result<Self> {
        let first = u64::from(config.epoch()) * 2880;
        let schedule = Rc::new(Schedule::new(&config, first, sample)?);
        Window::Baseline.check(&schedule)?;
        let (join, slot) = enrollment_bytes(&config, hashes, token)?;
        Self::begin(
            config,
            join,
            slot,
            profile,
            schedule,
            Window::Baseline,
            first,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn begin(
        config: Rc<SignedConfig>,
        join: Zeroizing<[u8; 128]>,
        slot: u8,
        profile: ClientProfile,
        schedule: Rc<Schedule>,
        window: Window,
        eligible: u64,
    ) -> Result<Self> {
        let deadline = window.check(&schedule)?;
        if profile.endpoint() != config.endpoints()[0] {
            return Err(Error::Unavailable("client configured A profile"));
        }
        // All checks, including original window, precede the only socket attempt.
        window.check(&schedule)?;
        let pending = Pending::Connecting(Connecting::with_profile(profile.clone(), deadline)?);
        Ok(Self {
            config,
            schedule,
            window,
            eligible,
            profile,
            join,
            slot,
            pending,
        })
    }
    /// Advance only this TCP/TLS/Join with the original absolute setup deadline.
    /// # Errors
    /// Failure consumes and drops this attempt; no new socket is created on error.
    pub fn poll(mut self, sample: &QualifiedClockSample) -> Result<EnrollmentProgressV1> {
        self.schedule.observe_clock(sample)?;
        let deadline = self.window.check(&self.schedule)?;
        self.pending = match self.pending {
            Pending::Connecting(connecting) => match connecting.poll()? {
                ConnectStep::Pending(connecting) => Pending::Connecting(connecting),
                ConnectStep::Handshaking(setup) => Pending::Tls(setup),
            },
            Pending::Tls(setup) => match setup.poll()? {
                SetupStep::Pending(setup) => Pending::Tls(setup),
                SetupStep::Established(mut link) => {
                    self.window.check(&self.schedule)?;
                    link.queue(RecordSize::Join, self.join.as_ref(), deadline)?;
                    Pending::Join(link)
                }
            },
            Pending::Join(mut link) => {
                if link.write_step()? {
                    self.window.check(&self.schedule)?;
                    return Ok(EnrollmentProgressV1::Joined(ClientV1 {
                        config: self.config,
                        slot: self.slot,
                        link: Some(Rc::new(RefCell::new(link))),
                        profile: self.profile,
                        join: self.join,
                        eligible: self.eligible,
                        last_closed: None,
                        highest: None,
                        rounds: std::array::from_fn(|_| None),
                        outcomes: [None, None],
                    }));
                }
                Pending::Join(link)
            }
        };
        self.window.check(&self.schedule)?;
        Ok(EnrollmentProgressV1::Pending(self))
    }
}

#[allow(
    clippy::large_types_passed_by_value,
    reason = "Consume the fixed roster through its existing owned admission API"
)]
pub(super) fn enrollment_bytes(
    config: &SignedConfig,
    hashes: [Digest; 32],
    token: Zeroizing<[u8; 32]>,
) -> Result<(Zeroizing<[u8; 128]>, u8)> {
    let roster = Roster::verify(hashes, config)?;
    let mut join = Zeroizing::new([0; 128]);
    join[..8].copy_from_slice(b"SNJOIN03");
    join[8..40].copy_from_slice(&config.domain());
    join[40..44].copy_from_slice(&config.cohort().to_le_bytes());
    join[44..48].copy_from_slice(&config.epoch().to_le_bytes());
    join[48..80].copy_from_slice(token.as_ref());
    drop(token);
    let hash = roster.verify_join(join.as_ref(), config)?;
    Ok((join, roster.slot(&hash)?))
}
