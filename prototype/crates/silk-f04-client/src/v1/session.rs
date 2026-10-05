//! Opt-in closed ANON-SESSION-1 owner. Conditional policy, NOT anonymity proof.
//! Run on the enrollment/node owner's thread; construct a wallet worker separately.
//! No public per-round tick, wallet journal, export, repair or reconnect API exists.
use super::*;
use silk_f04_relay::tls::ClientProfile;
use std::{
    sync::mpsc::{self, Receiver, SyncSender, TrySendError},
    thread,
    time::Duration,
};

const ROUNDS: u16 = 2880;
const ROUND_NS: i64 = 30_000_000_000;
const DECISION_NS: i64 = -8_125_000_000;
const CLOSE_NS: i64 = 22_000_000_000;

/// Trusted bounded public-history owner, independent of wallet work/locks and
/// payment presence. Implementations must be separately qualified under load.
pub trait PublicViewOwnerV1 {
    /// Refresh on every fixed pump iteration, not only on payment submissions.
    /// May reuse an immutable admitted view; never fabricate a genesis fallback.
    /// # Errors
    /// A known invalid/unavailable source or a blocked deadline stops the session.
    fn refresh(&mut self, sample: &QualifiedClockSample) -> Result<Option<LocalViewV1>>;
}
/// Externally qualified paired UTC source. Host wall time alone is insufficient.
pub trait SessionClockV1 {
    /// Capture a fresh bounded sample; no payment-dependent pacing or rebasing.
    /// # Errors
    /// Missing qualification or a known clock failure stops the owner.
    fn sample(&mut self) -> Result<QualifiedClockSample>;
}

/// Preselected whole UTC epoch. Contains no shorter-duration/session repair knob.
pub struct SessionPlanV1 {
    config: Rc<SignedConfig>,
    first: u64,
}
impl SessionPlanV1 {
    /// Select the entire epoch before calling the sole baseline enrollment owner.
    /// This cannot prove selection was independent of payment intent or custody.
    /// # Errors
    /// Refuses a configuration that does not cover exactly the complete epoch.
    pub fn select(config: Rc<SignedConfig>) -> Result<Self> {
        let first = u64::from(config.epoch())
            .checked_mul(u64::from(ROUNDS))
            .ok_or(Error::Unavailable("session epoch overflow"))?;
        if !config.contains_round(first) || !config.contains_round(first + u64::from(ROUNDS) - 1) {
            return Err(Error::Unavailable("session incomplete epoch"));
        }
        Ok(Self { config, first })
    }
}

/// Bounded local interface. No journal/export handle or old queue is recovered.
pub struct SessionHandleV1 {
    offers: SyncSender<SavedOfferV1>,
    outcomes: Receiver<OutcomeV1>,
}
/// Sole pump's non-cloneable endpoints; starting another epoch requires new ones.
pub struct SessionPortsV1 {
    offers: Receiver<SavedOfferV1>,
    outcomes: SyncSender<OutcomeV1>,
}
/// Create an empty volatile one-offer/two-outcome boundary. Restart never inherits
/// old offers. Human authorization of later exports remains outside this API.
#[must_use]
pub fn session_ports_v1() -> (SessionHandleV1, SessionPortsV1) {
    let (offers, receive) = mpsc::sync_channel(1);
    let (outcomes, take) = mpsc::sync_channel(2);
    (
        SessionHandleV1 {
            offers,
            outcomes: take,
        },
        SessionPortsV1 {
            offers: receive,
            outcomes,
        },
    )
}
impl SessionHandleV1 {
    /// Consume one explicit already-exposed in-memory offer, without waiting.
    /// Not durable/global one-use, export permission, delivery or retry authority.
    /// # Errors
    /// Full/stopped owner returns the unconsumed offer; never automatically retries.
    pub fn submit_once(
        &self,
        offer: SavedOfferV1,
    ) -> std::result::Result<(), TrySendError<SavedOfferV1>> {
        self.offers.try_send(offer)
    }
    /// Drain a local fixed-time result. Slow readers may lose results when the
    /// two-entry output is full; this never backpressures the network schedule.
    #[must_use]
    pub fn take_local_outcome(&self) -> Option<OutcomeV1> {
        self.outcomes.try_recv().ok()
    }
}

/// Aggregate local policy accounting, never network delivery/settlement evidence.
#[derive(Debug, PartialEq, Eq)]
pub struct SessionReportV1 {
    /// Total preselected decisions, including suppressed decisions after failure.
    pub decisions: u16,
    /// Rounds admitted to the original client; not cells successfully sent.
    pub admitted: u16,
    /// Decisions suppressed by the terminal unhealthy transition.
    pub suppressed: u16,
    /// Owner terminated unhealthy, dropped transports/offers, and never repaired.
    pub unhealthy: bool,
}

/// Closed blocking owner, not a background service or default activation.
pub struct SessionV1;
impl SessionV1 {
    /// Own one baseline enrollment attempt and every decision/poll/cleanup for the
    /// entire 2880-round UTC epoch. Call on a dedicated preselected owner thread;
    /// `Rc` node/client custody stays there. No callback receives the Process or
    /// payment queue. Only one bounded wallet worker may be created separately.
    ///
    /// Baseline setup uses the existing q-60..q-30 window. Failure consumes this
    /// attempt. No automatic later epoch, reconnect, journal scan or re-export.
    ///
    /// Native resource containment, actual clock qualification, honest A,
    /// independently administered B and >=8 independent active honest plausible
    /// clients are external prerequisites; this function establishes none of them.
    #[allow(clippy::too_many_arguments)]
    pub fn run(
        plan: SessionPlanV1,
        hashes: [Digest; 32],
        token: Zeroizing<[u8; 32]>,
        profile: ClientProfile,
        mut clock: impl SessionClockV1,
        mut public_view: impl PublicViewOwnerV1,
        ports: SessionPortsV1,
    ) -> SessionReportV1 {
        let startup = (|| -> Result<(ClientV1, Schedule)> {
            let sample = clock.sample()?;
            let anchor = Schedule::new(&plan.config, plan.first, clock.sample()?)?;
            let mut enrollment =
                EnrollmentV1::start(Rc::clone(&plan.config), hashes, token, profile, sample)?;
            loop {
                let sample = clock.sample()?;
                anchor.observe_clock(&sample)?;
                // Unconditional public-view maintenance, even with an empty queue.
                let _ = public_view.refresh(&sample)?;
                match enrollment.poll(&sample)? {
                    EnrollmentProgressV1::Pending(next) => enrollment = next,
                    EnrollmentProgressV1::Joined(client) => return Ok((client, anchor)),
                }
                thread::sleep(Duration::from_millis(1));
            }
        })();
        let Ok((client, anchor)) = startup else {
            return SessionReportV1 {
                decisions: ROUNDS,
                admitted: 0,
                suppressed: ROUNDS,
                unhealthy: true,
            };
        };
        let process = ProcessV1::new(client);
        let mut runtime = LiveRuntime {
            plan,
            anchor,
            process: Some(process),
            clock,
            public_view,
            ports,
            sample: None,
            view: None,
        };
        pump(&mut runtime)
    }
}

// One private seam shared by the actual owner and bounded simulated fixtures.
// Offer and public-view scripts cannot choose timers or externally tick the pump.
trait Runtime {
    fn now(&self) -> i64;
    fn inspect(&mut self) -> bool;
    fn admit(&mut self, index: u16, allow_offer: bool) -> bool;
    fn poll(&mut self) -> bool;
    fn stop(&mut self);
    fn pause(&mut self);
}
fn pump(runtime: &mut impl Runtime) -> SessionReportV1 {
    let mut index = 0;
    let mut admitted = 0;
    let mut unhealthy = false;
    loop {
        // Before even checking the offer queue: fresh clock/public view health.
        if !runtime.inspect() || !runtime.poll() {
            unhealthy = true;
            break;
        }
        let now = runtime.now();
        if index < ROUNDS && now >= i64::from(index) * ROUND_NS + DECISION_NS {
            // The 125ms decision/admission interval never extends the -8 barrier.
            if now >= i64::from(index) * ROUND_NS - 8_000_000_000
                || !runtime.admit(index, index >= 8)
            {
                unhealthy = true;
                break;
            }
            index += 1;
            admitted += 1;
        }
        if index == ROUNDS && now >= i64::from(ROUNDS - 1) * ROUND_NS + CLOSE_NS {
            break;
        }
        runtime.pause();
    }
    // Terminal failure drops any provisional successor admitted 125ms before
    // its predecessor's +22 failure outcome. No data-slot escape or offer requeue.
    runtime.stop();
    SessionReportV1 {
        decisions: ROUNDS,
        admitted,
        suppressed: ROUNDS - admitted,
        unhealthy,
    }
}

struct LiveRuntime<C, V> {
    plan: SessionPlanV1,
    anchor: Schedule,
    process: Option<ProcessV1>,
    clock: C,
    public_view: V,
    ports: SessionPortsV1,
    sample: Option<QualifiedClockSample>,
    view: Option<LocalViewV1>,
}
impl<C: SessionClockV1, V: PublicViewOwnerV1> Runtime for LiveRuntime<C, V> {
    fn now(&self) -> i64 {
        let origin = self.anchor.at(0).expect("admitted anchor");
        let now = Instant::now();
        let elapsed = if now >= origin {
            now.duration_since(origin)
        } else {
            origin.duration_since(now)
        };
        let amount = i64::try_from(elapsed.as_nanos()).unwrap_or(i64::MAX);
        if now >= origin { amount } else { -amount }
    }
    fn inspect(&mut self) -> bool {
        let Ok(sample) = self.clock.sample() else {
            return false;
        };
        if self.anchor.observe_clock(&sample).is_err() {
            return false;
        }
        let Ok(view) = self.public_view.refresh(&sample) else {
            return false;
        };
        // A known invalid READY owner cannot become a payment-selected exception.
        if view.as_ref().is_some_and(|v| match v {
            LocalViewV1::Ready(node) => {
                node.genesis().domain() != self.plan.config.domain() || node.state().is_err()
            }
            LocalViewV1::Genesis(genesis) => genesis.domain() != self.plan.config.domain(),
        }) {
            return false;
        }
        self.view = view;
        self.sample = Some(sample);
        true
    }
    fn admit(&mut self, index: u16, allow_offer: bool) -> bool {
        // Absence is checked before touching any pending payment, equally for cover.
        let Some(view) = self.view.clone() else {
            return false;
        };
        let Some(sample) = self.sample.as_ref() else {
            return false;
        };
        let Ok(schedule) = self.anchor.anchored_round(
            &self.plan.config,
            self.plan.first + u64::from(index),
            sample,
        ) else {
            return false;
        };
        // Refresh may have consumed the entire decision slack; do not consume an
        // offer or start a late round in that case.
        if schedule.completed_before(-8_000_000_000).is_err() {
            return false;
        }
        let offer = if allow_offer {
            self.ports.offers.try_recv().ok()
        } else {
            None
        };
        self.process.as_mut().is_some_and(|p| {
            p.admit(self.plan.config.id(), schedule, view, offer)
                .is_ok()
        })
    }
    fn poll(&mut self) -> bool {
        let Some(process) = self.process.as_mut() else {
            return false;
        };
        let Some(sample) = self.sample.as_ref() else {
            return false;
        };
        if process.poll(sample).is_err() {
            return false;
        }
        // The pump, not the application, drains every original +22 outcome.
        while let Some(outcome) = process.take_outcome() {
            let failed = matches!(
                outcome.status,
                WriteStatusV1::Silent | WriteStatusV1::WriteUncertain
            );
            let _ = self.ports.outcomes.try_send(outcome);
            if failed {
                return false;
            }
        }
        true
    }
    fn stop(&mut self) {
        self.process = None;
        self.view = None;
        // Exactly one receive: a concurrent submitter cannot turn teardown into
        // an unbounded drain loop. Dropping the sole runtime drops the receiver.
        let _ = self.ports.offers.try_recv();
    }
    fn pause(&mut self) {
        thread::sleep(Duration::from_millis(1));
    }
}

#[cfg(test)]
mod tests;
