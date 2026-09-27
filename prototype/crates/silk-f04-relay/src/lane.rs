//! The sole established A-to-B receive cursor across adjacent round controls.
//! A frozen handoff is retained independently of successor negotiation health.
use crate::{
    Error, Result,
    config::SignedConfig,
    control::{AuthorizationEvidence, Kind, PreparedAuthorization, Role, SignedControl},
    flow::ReadSlot,
    owner::{DurableJournal, ManifestRound, PinRetention},
    schedule::Schedule,
    tls::{ReceiveProgress, RecordSize, Transport},
};
use std::{rc::Rc, time::Instant};

enum LanePhase {
    Open,
    Lost,
    Closed,
}

/// Connection-owned bounded receive lane. No caller can install readiness flags
/// or a fabricated authorization; the actual `ExitRound` binds its checked chain.
pub struct BControlLane {
    bound: Option<Rc<ManifestRound>>,
    config: Rc<SignedConfig>,
    schedule: Rc<Schedule>,
    connection_id: u64,
    expected: Option<PreparedAuthorization>,
    authorization: Option<SignedControl>,
    frozen: Option<Rc<FrozenAuthorization>>,
    reader: ReadSlot,
    lane: LanePhase,
    next_proposal: Option<SignedControl>,
    next_id: Option<crate::Digest>,
    next_failed: bool,
    current_failed: bool,
    received: u8,
}

/// One private persistently frozen handoff. Later lane loss cannot revoke it.
pub(crate) struct FrozenAuthorization {
    round: Rc<ManifestRound>,
    expected: PreparedAuthorization,
    control: SignedControl,
}
impl FrozenAuthorization {
    pub(crate) fn evidence(&self) -> Result<AuthorizationEvidence<'_>> {
        self.expected.check(&self.control)
    }
    pub(crate) const fn control(&self) -> &SignedControl {
        &self.control
    }
    pub(crate) fn matches(&self, round: &Rc<ManifestRound>) -> bool {
        Rc::ptr_eq(&self.round, round)
    }
}
impl BControlLane {
    pub(crate) fn config_id(&self) -> crate::Digest {
        self.config.id()
    }
    pub(crate) fn is_predecessor(&self, config: &SignedConfig, round: u64, a: &Transport) -> bool {
        self.config.id() == config.id()
            && self.connection_id == a.id()
            && self.schedule.round().checked_add(1) == Some(round)
    }
    pub(crate) fn round(&self) -> u64 {
        self.schedule.round()
    }
    pub(crate) fn abort_current<P: PinRetention>(
        &mut self,
        journal: &DurableJournal<P>,
    ) -> Result<()> {
        journal.check_role(Role::B)?;
        if journal.decision(self.schedule.round()) != Some(crate::journal::Decision::Abort) {
            return Err(Error::Unavailable("B lane abort not durably decided"));
        }
        self.current_failed = true;
        // B's own pre-write local failure may abort AUTH_FROZEN. This cannot
        // recall a committed release or revoke A's authorization. Keep the exact
        // receive cursor and successor metadata; only local frozen use is removed.
        self.frozen = None;
        self.authorization = None;
        self.expected = None;
        Ok(())
    }
    /// Own the late control cursor of the exact established A connection.
    /// # Errors
    /// Refuses a foreign/failed endpoint or late construction.
    pub fn new(round: Rc<ManifestRound>, a: &Transport) -> Result<Self> {
        Self::with_context(
            Rc::clone(&round.config),
            Rc::clone(&round.schedule),
            Some(round),
            a,
        )
    }
    pub(crate) fn failed(
        config: Rc<SignedConfig>,
        schedule: Rc<Schedule>,
        a: &Transport,
    ) -> Result<Self> {
        Self::with_context(config, schedule, None, a)
    }
    fn with_context(
        config: Rc<SignedConfig>,
        schedule: Rc<Schedule>,
        bound: Option<Rc<ManifestRound>>,
        a: &Transport,
    ) -> Result<Self> {
        // A failed-only lane can retain the identity of an unavailable socket;
        // it cannot bind/freeze a current authorization or rehabilitate that link.
        if bound.is_some() {
            a.check_endpoint(config.endpoints()[Role::B as usize], false)?;
        }
        schedule.completed_before(18_000_000_000)?;
        let current_failed = bound.is_none();
        Ok(Self {
            bound,
            config,
            schedule,
            connection_id: a.id(),
            expected: None,
            authorization: None,
            frozen: None,
            reader: ReadSlot::default(),
            lane: LanePhase::Open,
            next_proposal: None,
            next_id: None,
            next_failed: false,
            current_failed,
            received: 0,
        })
    }
    pub(crate) fn check_round(&self, round: &Rc<ManifestRound>, a: &Transport) -> Result<()> {
        self.check_connection(a)?;
        if self
            .bound
            .as_ref()
            .is_none_or(|bound| !Rc::ptr_eq(bound, round))
        {
            return Err(Error::Unavailable("B lane round replaced"));
        }
        Ok(())
    }
    const fn check_connection(&self, a: &Transport) -> Result<()> {
        if self.connection_id != a.id() {
            return Err(Error::Unavailable("B lane connection replaced"));
        }
        Ok(())
    }
    pub(crate) fn bind_expected(&mut self, expected: PreparedAuthorization) -> Result<()> {
        self.schedule.completed_before(18_000_000_000)?;
        if self.current_failed
            || self.bound.is_none()
            || self.expected.is_some()
            || self.frozen.is_some()
        {
            return Err(Error::Unavailable("B lane expected chain already bound"));
        }
        self.expected = Some(expected);
        Ok(())
    }
    pub(crate) fn try_freeze_current<P: PinRetention>(
        &mut self,
        journal: &mut DurableJournal<P>,
    ) -> Result<Option<Rc<FrozenAuthorization>>> {
        if self.current_failed {
            return Err(Error::Unavailable("B lane current authorization failed"));
        }
        if let Some(frozen) = &self.frozen {
            return Ok(Some(Rc::clone(frozen)));
        }
        if Instant::now() < self.schedule.at(19_750_000_000)? {
            return Ok(None);
        }
        let control = self
            .authorization
            .as_ref()
            .ok_or(Error::Unavailable("B no timely authorization"))?;
        let expected = self
            .expected
            .as_ref()
            .ok_or(Error::Unavailable("B lane expected chain absent"))?;
        let evidence = expected.check(control)?;
        journal.update(|j| j.freeze_b(&evidence))?;
        self.schedule.completed_before(20_000_000_000)?;
        let frozen = Rc::new(FrozenAuthorization {
            round: Rc::clone(
                self.bound
                    .as_ref()
                    .ok_or(Error::Unavailable("B unmanifested lane"))?,
            ),
            expected: self.expected.take().expect("checked expectation"),
            control: self.authorization.take().expect("checked authorization"),
        });
        self.frozen = Some(Rc::clone(&frozen));
        Ok(Some(frozen))
    }
    /// Take at most one actual, fully signed next-round proposal collected on the
    /// shared A connection. The outer two-slot owner still checks its local cut,
    /// journal and fixed response phase; this is NOT a configured next round.
    /// # Errors
    /// Conflicting/malformed next-round negotiation configures no real successor.
    pub fn take_next_proposal(&mut self) -> Result<Option<SignedControl>> {
        self.next_manifest_health()?;
        Ok(self.next_proposal.take())
    }
    /// Successor-only health, separate from the current irrevocable authorization.
    /// The parent checks this before relying on its next-round negotiation.
    /// # Errors
    /// Reports recorded conflict/failed next-round control receipt.
    pub const fn next_manifest_health(&self) -> Result<()> {
        if self.next_failed {
            Err(Error::Unavailable("next-round A manifest failed"))
        } else {
            Ok(())
        }
    }
    /// Read only this connection's bounded current/next control lane.
    /// # Errors
    /// Refuses current required evidence failure; successor-only faults stay separate.
    pub fn poll(&mut self, a: &mut Transport) -> Result<()> {
        let result = self.advance(a);
        if result.is_err() && self.frozen.is_none() {
            self.current_failed = true;
        }
        result
    }
    pub(crate) fn discard_poll(&mut self, a: &mut Transport) -> Result<()> {
        self.check_connection(a)?;
        if !self.current_failed || self.frozen.is_some() {
            return Err(Error::Unavailable("B discard lane not reversibly aborted"));
        }
        if self.advance(a).is_err() {
            self.lane = LanePhase::Lost;
            self.next_failed = true;
            let _ = a.quarantine();
        }
        Ok(())
    }
    #[allow(clippy::too_many_lines)] // Adjacent-round demultiplexing shares one exact TLS read.
    fn advance(&mut self, a: &mut Transport) -> Result<()> {
        self.check_connection(a)?;
        if Instant::now() < self.schedule.at(18_000_000_000)? {
            return Ok(());
        }
        let cutoff = self.schedule.at(19_750_000_000)?;
        let lane_end = self.schedule.at(21_000_000_000)?;
        if matches!(self.lane, LanePhase::Closed) {
            return Ok(());
        }
        if Instant::now() >= lane_end {
            self.lane = LanePhase::Closed;
            match a.receive_progress() {
                ReceiveProgress::Idle => (),
                ReceiveProgress::WaitingZeroBytes => {
                    if a.retire_empty(RecordSize::Control).is_err() {
                        self.next_failed = true;
                    }
                }
                _ => {
                    self.next_failed = true;
                    let _ = a.quarantine();
                }
            }
            return Ok(());
        }
        if matches!(self.lane, LanePhase::Lost) {
            return Ok(());
        }
        let queued = a.has_extra_bytes();
        if Instant::now() >= lane_end {
            return Ok(());
        }
        match queued {
            Ok(false) => return Ok(()),
            Err(_) if (self.authorization.is_some() || self.frozen.is_some()) => {
                self.lane = LanePhase::Lost;
                self.next_failed = true;
                return Ok(());
            }
            Err(error) => return Err(error),
            Ok(true) => (),
        }
        let received = self.reader.poll(
            a,
            &self.schedule,
            (18_000_000_000, 21_000_000_000),
            RecordSize::Control,
        );
        if Instant::now() >= lane_end {
            return Ok(());
        }
        let received = match received {
            Ok(received) => received,
            Err(_) if (self.authorization.is_some() || self.frozen.is_some()) => {
                self.lane = LanePhase::Lost;
                self.next_failed = true;
                let _ = a.quarantine();
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        if let Some(bytes) = received {
            self.reader = ReadSlot::default();
            self.received += 1;
            if self.received > 2 {
                self.next_failed = true;
                self.lane = LanePhase::Lost;
                let _ = a.quarantine();
                return if self.frozen.is_some() {
                    Ok(())
                } else {
                    Err(Error::Unavailable("B excess late control transcript"))
                };
            }
            let round = crate::u64le(&bytes, 80)?;
            if self.schedule.round().checked_add(1) == Some(round) {
                // +20(next -10) can arrive as early as current+19 under the
                // declared combined1s skew, before current authorization closes.
                let early = Instant::now() < self.schedule.at(19_000_000_000)?;
                let next =
                    SignedControl::verify(&bytes, &self.config, round, Kind::ManifestA, Role::A);
                if Instant::now() >= lane_end {
                    self.next_failed = true;
                    return Ok(());
                }
                match next {
                    Ok(proposal) if !early && proposal.bytes()[10] == 1 => {
                        if self.next_id.is_some_and(|id| id != proposal.id()) {
                            self.next_failed = true;
                        } else if self.next_id.is_none() {
                            self.next_id = Some(proposal.id());
                            self.next_proposal = Some(proposal);
                        }
                    }
                    _ => self.next_failed = true,
                }
                return Ok(());
            }
            // Closed-current traffic cannot reopen or veto the frozen handoff.
            if Instant::now() >= cutoff || self.current_failed {
                return Ok(());
            }
            let kind = if bytes.get(8) == Some(&(Kind::Cancel as u8)) {
                Kind::Cancel
            } else {
                Kind::Authorize
            };
            let checked: Result<SignedControl> =
                SignedControl::verify(&bytes, &self.config, self.schedule.round(), kind, Role::A);
            if Instant::now() >= cutoff {
                return Ok(());
            }
            let auth = match checked {
                Ok(control) => control,
                Err(error) => return self.invalid_optional(a, error),
            };
            if auth.kind() == Kind::Cancel {
                if self
                    .bound
                    .as_ref()
                    .is_some_and(|bound| auth.bytes()[88..120] == bound.manifest().id())
                {
                    return Err(Error::Invalid("B conflicting signed terminal decision"));
                }
                return self.invalid_optional(a, Error::Invalid("CANCEL manifest mismatch"));
            }
            let chain = self
                .expected
                .as_ref()
                .ok_or(Error::Unavailable("B lane expected chain absent"))?
                .check(&auth);
            if Instant::now() >= cutoff {
                return Ok(());
            }
            // A signature on invalid references is not a second valid terminal
            // decision. Once the required complete authorization is present,
            // optional bad evidence cannot manufacture equivocation (C.5).
            if let Err(error) = chain {
                return self.invalid_optional(a, error);
            }
            if self
                .authorization
                .as_ref()
                .is_some_and(|previous| previous.id() != auth.id())
            {
                return Err(Error::Invalid("B conflicting pre-cutoff authorization"));
            }
            if self.authorization.is_none() && self.frozen.is_none() {
                self.authorization = Some(auth);
            }
            self.reader = ReadSlot::default();
        }
        Ok(())
    }
    fn invalid_optional(&mut self, a: &mut Transport, error: Error) -> Result<()> {
        // Backend/resource/integrity failures are local STOP, not optional
        // invalid peer evidence. Preserve that distinction as backends evolve.
        if (self.authorization.is_none() && self.frozen.is_none())
            || !matches!(
                error,
                Error::Invalid(_) | Error::Auth(silk_f04_node::Error::Invalid(_))
            )
        {
            return Err(error);
        }
        self.lane = LanePhase::Lost;
        self.next_failed = true;
        let _ = a.quarantine();
        Ok(())
    }
}
