//! Actual token-bound TLS/HPKE input collection, with no source-owned egress queue.
use crate::{
    Digest, Error, Result,
    config::{Roster, SignedConfig},
    flow::WriteSlot,
    frame::{Frame, HpkePrivate, Payload, client_cell, open_a, permute_stage2},
    owner::ManifestRound,
    schedule::QualifiedClockSample,
    staging::a_batch_id,
    tls::{ReceiveProgress, RecordSize, Transport},
};
use std::{collections::BTreeSet, rc::Rc, time::Instant};
mod failed;
#[cfg(all(feature = "aip2-preparation", feature = "functional-lab"))]
pub mod r2_lab;
mod strict;
#[cfg(test)]
mod tests;
pub(crate) use failed::FailedSessions;
use strict::CompletedSlots;
pub(crate) use strict::StrictCompletion;
pub use strict::StrictInputBatch;

/// Local collection policy, chosen before any cell is collected. Neither policy
/// proves independent users or protects B against a malicious source relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputPolicy {
    /// Original minimum-eight collection, with fresh cover for missing slots.
    Legacy,
    /// Exactly 32 actual, distinct, valid roster-slot completions; no filler.
    Strict32,
}
pub(crate) enum SealedInput {
    Legacy(InputBatch),
    Strict(StrictInputBatch),
}

/// In-progress setup admission. Driver must cap simultaneous sockets and attempts.
pub struct Enrolling {
    transport: Transport,
}
impl Enrolling {
    /// Select the one fixed128-byte Join during the separately admitted setup phase.
    /// # Errors
    /// Refuses overlapping transport input or a missed original setup deadline.
    pub fn new(mut transport: Transport, deadline: Instant) -> Result<Self> {
        transport.expect(RecordSize::Join, deadline)?;
        Ok(Self { transport })
    }
    /// Poll actual TLS bytes and validate their roster/domain/epoch binding.
    /// On completion consumes this enrollment; never accepts caller-made token facts.
    /// # Errors
    /// Refuses TLS/Join failure, without admitting a source session.
    pub fn poll(mut self, config: &SignedConfig, roster: &Roster) -> Result<Enrollment> {
        if let Some(bytes) = self.transport.read_step()? {
            let token = roster.verify_join(&bytes, config)?;
            let slot = roster.slot(&token)?;
            self.transport.enrollment_complete();
            Ok(Enrollment::Admitted(AdmittedSession {
                transport: self.transport,
                slot,
                token,
                config: config.id(),
            }))
        } else {
            Ok(Enrollment::Pending(self))
        }
    }
}
/// One bounded setup poll result; neither variant proves participant honesty.
pub enum Enrollment {
    /// Incomplete fixed read with unchanged deadline.
    Pending(Enrolling),
    /// Complete TLS-authenticated roster admission.
    Admitted(AdmittedSession),
}
/// Private source association retained only at A, never attached to outgoing cells.
pub struct AdmittedSession {
    transport: Transport,
    token: Digest,
    config: Digest,
    slot: u8,
}
impl AdmittedSession {
    pub(crate) const fn slot(&self) -> u8 {
        self.slot
    }
}
/// Fixed epoch connection set. A duplicate invalidates this local epoch instance;
/// recovery requires explicit later configuration, never replacement mid-round.
pub struct Sessions {
    entries: Vec<AdmittedSession>,
    config: Digest,
    failed: bool,
    delivery_round: Option<u64>,
    delivered_manifest: Option<Digest>,
}
impl Sessions {
    pub(crate) fn check_replacements(&self, replacements: &[AdmittedSession]) -> Result<()> {
        if self.failed {
            return Err(Error::Unavailable(
                "maintenance cannot repair a failed epoch",
            ));
        }
        let mut slots = 0_u32;
        for session in replacements {
            let bit = 1 << session.slot;
            if session.config != self.config
                || slots & bit != 0
                || self.entries.iter().any(|old| {
                    old.slot == session.slot
                        && (old.token != session.token
                            || old.transport.receive_progress() != ReceiveProgress::Failed)
                })
            {
                return Err(Error::Unavailable(
                    "maintenance foreign/duplicate/healthy client",
                ));
            }
            slots |= bit;
        }
        Ok(())
    }
    pub(crate) fn replace(&mut self, replacements: Vec<AdmittedSession>) -> Result<()> {
        self.check_replacements(&replacements)?;
        for replacement in replacements {
            if let Some(index) = self.entries.iter().position(|s| s.slot == replacement.slot) {
                self.entries[index] = replacement;
            } else {
                self.entries.push(replacement);
            }
        }
        Ok(())
    }
    pub(crate) fn account(&mut self, resources: &crate::resources::RoleResources) -> Result<()> {
        for session in &mut self.entries {
            session.transport.account(resources)?;
        }
        Ok(())
    }
    pub(crate) fn repairable_slots(&self) -> u32 {
        let present = self.entries.iter().fold(0, |mask, s| mask | (1 << s.slot));
        !present | self.unavailable_slots()
    }
    pub(crate) fn check_config(&self, config: &SignedConfig) -> Result<()> {
        if self.failed || self.config != config.id() {
            return Err(Error::Unavailable("A session configuration/health"));
        }
        Ok(())
    }
    /// Empty bounded connection owner for one already accepted configuration.
    #[must_use]
    pub fn new(config: &SignedConfig) -> Self {
        Self {
            entries: Vec::with_capacity(32),
            config: config.id(),
            failed: false,
            delivery_round: None,
            delivered_manifest: None,
        }
    }
    /// Add a complete, unique actual Join. No concurrent replacement is accepted.
    /// # Errors
    /// Sticky refusal for a duplicate, wrong cfg, excess session or failed epoch.
    pub fn insert(&mut self, session: AdmittedSession) -> Result<()> {
        if self.failed
            || self.entries.len() == 32
            || session.config != self.config
            || self
                .entries
                .iter()
                .any(|other| other.token == session.token)
        {
            self.failed = true;
            return Err(Error::Invalid("A duplicate/foreign/excess session"));
        }
        self.entries.push(session);
        Ok(())
    }
    /// Session count is a connection fact, never an honest/human count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }
    /// Whether no source connection has been admitted.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// Roster slots whose original transports are unavailable. They are not
    /// silently replaced or counted as completed input in a later round.
    #[must_use]
    pub fn unavailable_slots(&self) -> u32 {
        self.entries.iter().fold(0, |mask, session| {
            mask | if session.transport.receive_progress() == ReceiveProgress::Failed {
                1 << session.slot
            } else {
                0
            }
        })
    }
}

/// Fixed -8 manifest fanout without exposing source-associated transports.
/// A dropped/failed fanout cannot be restarted for the same round.
pub struct ManifestDelivery {
    sessions: Sessions,
    round: Rc<ManifestRound>,
    slot: usize,
    writer: WriteSlot,
    complete: bool,
    claimed: bool,
    failed: bool,
}
impl ManifestDelivery {
    /// Claim exactly one delivery for this durably negotiated round.
    /// # Errors
    /// Refuses reuse, failed/foreign sessions, or late/unhealthy setup.
    pub fn new(sessions: Sessions, round: Rc<ManifestRound>) -> Result<Self> {
        let mut delivery = Self::unclaimed(sessions, round);
        delivery.claim()?;
        Ok(delivery)
    }
    pub(crate) fn unclaimed(sessions: Sessions, round: Rc<ManifestRound>) -> Self {
        Self {
            sessions,
            round,
            slot: 0,
            writer: WriteSlot::default(),
            complete: false,
            claimed: false,
            failed: false,
        }
    }
    pub(crate) fn claim(&mut self) -> Result<()> {
        if self.claimed || self.failed {
            return Err(Error::Unavailable("A manifest claim reused"));
        }
        self.failed = true;
        let manifest = self.round.manifest();
        let schedule = &self.round.schedule;
        let sessions = &mut self.sessions;
        schedule.clock_healthy()?;
        schedule.completed_before(-8_000_000_000)?;
        if sessions.failed
            || sessions.config != manifest.config()
            || manifest.round() != schedule.round()
            || sessions
                .delivery_round
                .is_some_and(|r| r >= schedule.round())
        {
            return Err(Error::Unavailable("A manifest delivery admission"));
        }
        sessions.delivery_round = Some(schedule.round());
        sessions.delivered_manifest = None;
        self.claimed = true;
        self.failed = false;
        Ok(())
    }
    /// Progress the same record at the fixed -8 slot, with a conservative one
    /// second local write deadline. There is no later retry or alternate payload.
    /// # Errors
    /// Any incomplete/failed output prevents input admission for this session set.
    pub fn poll(&mut self) -> Result<bool> {
        if self.sessions.failed || self.failed || !self.claimed {
            return Err(Error::Unavailable("A failed manifest delivery"));
        }
        let result = self.advance();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    /// Return the same connection set only after complete delivery. An incomplete
    /// or failed owner is dropped with its connections, never reused as idle.
    /// # Errors
    /// Refuses incomplete or poisoned delivery.
    pub fn finish(self) -> Result<Sessions> {
        if !self.complete || self.sessions.failed || self.failed {
            return Err(Error::Unavailable("A incomplete manifest delivery"));
        }
        Ok(self.sessions)
    }
    pub(crate) fn into_input(self, key: Rc<HpkePrivate>, policy: InputPolicy) -> InputCollector {
        let mut input = InputCollector::unarmed(self.sessions, self.round, key, policy);
        input.failed = self.failed || !self.claimed || !self.complete;
        input
    }
    pub(crate) fn into_failed(self) -> FailedSessions {
        let eligible = std::array::from_fn(|i| i < self.slot);
        FailedSessions::new(
            self.sessions,
            Rc::clone(&self.round.schedule),
            eligible,
            [false; 32],
            Some((self.slot, self.writer)),
        )
    }
    fn advance(&mut self) -> Result<bool> {
        if self.complete {
            return Ok(true);
        }
        self.round.schedule.clock_healthy()?;
        // A quarantined original connection is explicit silence, never an
        // attempt to replace it or rehabilitate its TLS sequence mid-round.
        if self.slot < self.sessions.entries.len()
            && self.sessions.entries[self.slot]
                .transport
                .receive_progress()
                == ReceiveProgress::Failed
        {
            self.slot += 1;
            self.writer = WriteSlot::default();
            return Ok(false);
        }
        if self.slot < self.sessions.entries.len()
            && self.writer.poll(
                &mut self.sessions.entries[self.slot].transport,
                &self.round.schedule,
                (-8_000_000_000, -7_000_000_000),
                RecordSize::Manifest,
                self.round.manifest().bytes(),
            )?
        {
            self.slot += 1;
            self.writer = WriteSlot::default();
        }
        if self.slot == self.sessions.entries.len() {
            self.sessions.delivered_manifest = Some(self.round.manifest().id());
            self.complete = true;
        }
        Ok(self.complete)
    }
}
/// A's sole input coordinator. Manifest negotiation/delivery precede this object;
/// it grants no manifest, authorization, journal or transport-output permission.
pub struct InputCollector {
    sessions: Sessions,
    round: Rc<ManifestRound>,
    key: Rc<HpkePrivate>,
    completed: [bool; 32],
    received: [bool; 32],
    known_pending: [bool; 32],
    outer_encapsulations: BTreeSet<Digest>,
    inner_encapsulations: BTreeSet<Digest>,
    output: Vec<Frame>,
    failed: bool,
    armed: bool,
    policy: InputPolicy,
    completed_slots: CompletedSlots,
}
impl InputCollector {
    pub(crate) fn into_source(
        self,
        batch: SealedInput,
    ) -> (Sessions, SealedInput, Rc<ManifestRound>) {
        (self.sessions, batch, self.round)
    }
    pub(crate) fn into_failed(self) -> FailedSessions {
        FailedSessions::new(
            self.sessions,
            Rc::clone(&self.round.schedule),
            [true; 32],
            self.received,
            None,
        )
    }
    /// Arm one cell receive per admitted session before the first input slot.
    /// # Errors
    /// Refuses failed/foreign epoch, wrong round, late arming or partial old reads.
    pub fn new(sessions: Sessions, round: Rc<ManifestRound>, key: Rc<HpkePrivate>) -> Result<Self> {
        let mut input = Self::unarmed(sessions, round, key, InputPolicy::Legacy);
        input.arm()?;
        Ok(input)
    }
    /// Select strict collection before arming actual transport reads. Missing,
    /// partial, invalid or duplicate cells cannot be replaced by cover.
    /// # Errors
    /// Refuses the same configuration, delivery and timing faults as `new`.
    pub fn new_strict(
        sessions: Sessions,
        round: Rc<ManifestRound>,
        key: Rc<HpkePrivate>,
    ) -> Result<Self> {
        let mut input = Self::unarmed(sessions, round, key, InputPolicy::Strict32);
        input.arm()?;
        Ok(input)
    }
    fn unarmed(
        sessions: Sessions,
        round: Rc<ManifestRound>,
        key: Rc<HpkePrivate>,
        policy: InputPolicy,
    ) -> Self {
        Self {
            sessions,
            round,
            key,
            completed: [false; 32],
            received: [false; 32],
            known_pending: [false; 32],
            outer_encapsulations: BTreeSet::new(),
            inner_encapsulations: BTreeSet::new(),
            output: Vec::with_capacity(32),
            failed: false,
            armed: false,
            policy,
            completed_slots: CompletedSlots::default(),
        }
    }
    pub(crate) fn arm(&mut self) -> Result<()> {
        if self.failed || self.armed {
            return Err(Error::Unavailable("A input arming reused/failed"));
        }
        self.failed = true;
        let schedule = &self.round.schedule;
        let context = self.round.context();
        let sessions = &mut self.sessions;
        schedule.in_window(-8_000_000_000, 1_000_000_000)?;
        schedule.clock_healthy()?;
        if sessions.failed
            || sessions.config != context.config.id()
            || schedule.round() != context.manifest.round()
            || sessions.delivery_round != Some(schedule.round())
            || sessions.delivered_manifest != Some(context.manifest.id())
        {
            return Err(Error::Unavailable("A input configuration"));
        }
        for session in &mut sessions.entries {
            if session.transport.receive_progress() == ReceiveProgress::Failed {
                continue;
            }
            session
                .transport
                .expect(RecordSize::Cell, schedule.at(9_500_000_000)?)?;
        }
        self.armed = true;
        self.failed = false;
        Ok(())
    }
    /// Record a genuinely observed qualified clock-health sample while open.
    /// # Errors
    /// Clock failure is sticky before input sealing; never rebases the schedule.
    pub fn observe_clock(&mut self, sample: &QualifiedClockSample) -> Result<()> {
        self.round.schedule.completed_before(9_500_000_000)?;
        let observed = self.round.schedule.observe_clock(sample);
        // A later observation may affect A's still-open authorization barrier,
        // but cannot retrospectively poison the already closed input set.
        self.round.schedule.completed_before(9_500_000_000)?;
        if let Err(error) = observed {
            self.failed = true;
            return Err(error);
        }
        Ok(())
    }
    /// Feature-gated fixture health observation; never upgrades UTC qualification.
    /// # Errors
    /// Applies the same immutable input barrier and sticky local failure.
    #[cfg(feature = "functional-lab")]
    pub fn observe_functional_clock(&mut self) -> Result<()> {
        self.round.schedule.completed_before(9_500_000_000)?;
        let observed = self.round.schedule.observe_functional_clock();
        self.round.schedule.completed_before(9_500_000_000)?;
        if observed.is_err() {
            self.failed = true;
        }
        observed
    }
    /// Poll at most one bounded read per session, then complete framing/outer HPKE.
    /// No B decryption, per-source egress queue, caller timestamp or validity flag.
    /// # Errors
    /// A detected malformed/duplicate/partial failure sticks; no filler repairs it.
    pub fn poll(&mut self) -> Result<()> {
        if self.failed || !self.armed {
            return Err(Error::Unavailable("A failed input round"));
        }
        self.round.schedule.completed_before(9_500_000_000)?;
        let cutoff = self.round.schedule.at(9_500_000_000)?;
        for (i, session) in self.sessions.entries.iter_mut().enumerate() {
            if Instant::now() >= cutoff {
                break;
            }
            if session.transport.receive_progress() == ReceiveProgress::Failed {
                continue;
            }
            // Stamp AFTER the nonblocking observation. Merely checking quiet
            // completed connections across the cutoff must not veto good input.
            let extra = session.transport.has_extra_bytes();
            let observed = Instant::now();
            if observed >= cutoff {
                break;
            }
            self.failed = true;
            let extra = extra?;
            if self.completed[i] {
                if extra {
                    return Err(Error::Invalid("A duplicate/excess cell"));
                }
                self.failed = false;
                continue;
            }
            // Client and A may each differ from UTC by500ms, so allow at most
            // their combined1s skew BEFORE this token's fixed +1+.25*i slot.
            // This affects only receive-phase admission, never the9.5 cutoff.
            let earliest = self
                .round
                .schedule
                .at(i64::from(session.slot) * 250_000_000)?;
            if extra && observed < earliest {
                return Err(Error::Invalid("A observed early input cell"));
            }
            self.known_pending[i] = extra;
            if !extra {
                self.failed = false;
                continue;
            }
            // Now genuinely required work is in flight. A partial read or
            // unfinished validation crossing the barrier remains a failure.
            let bytes = session.transport.read_step()?;
            if let Some(bytes) = bytes {
                // Physical consumption precedes fallible frame/HPKE checks.
                // Failed ingress must never read a second cell for this slot.
                self.received[i] = true;
                let frame = Frame::decode(&bytes, &self.round.context(), 1, 0)?;
                if !self.outer_encapsulations.insert(frame.encapsulation()?) {
                    return Err(Error::Invalid("A duplicate outer encapsulation"));
                }
                let inner = open_a(&self.round.context(), &self.key, &frame)?;
                if !self.inner_encapsulations.insert(inner.encapsulation()?) {
                    return Err(Error::Invalid("A duplicate inner encapsulation"));
                }
                self.round.schedule.completed_before(9_500_000_000)?;
                // Mint completion provenance only after the full actual TLS,
                // framing, context, HPKE, uniqueness and deadline checks.
                if self.policy == InputPolicy::Strict32 {
                    self.completed_slots.record(session.slot)?;
                }
                self.output.push(inner);
                self.completed[i] = true;
                self.known_pending[i] = false;
            }
            self.failed = false;
        }
        Ok(())
    }
    /// At +9.5 freeze ONLY already completed observations, strip source metadata,
    /// fill absent slots with genuine fresh cover and independently permute once.
    /// No post-seal peek/read can retrospectively change these input facts.
    /// # Errors
    /// Refuses partial/failed/unfinished/known queued reads or fewer than8 completions.
    pub fn seal(mut self) -> Result<(Sessions, InputBatch)> {
        if self.policy != InputPolicy::Legacy {
            return Err(Error::Unavailable("A strict input cannot downgrade"));
        }
        let SealedInput::Legacy(batch) = self.seal_owned()? else {
            unreachable!()
        };
        Ok((self.sessions, batch))
    }
    /// Freeze all 32 actual completions and consume their private provenance.
    /// This cannot upgrade a legacy collector, including one with 32 frames.
    /// # Errors
    /// Refuses legacy selection, incomplete provenance or the ordinary barriers.
    pub fn seal_strict(mut self) -> Result<(Sessions, StrictInputBatch)> {
        if self.policy != InputPolicy::Strict32 {
            return Err(Error::Unavailable("A legacy input cannot upgrade"));
        }
        let SealedInput::Strict(batch) = self.seal_owned()? else {
            unreachable!()
        };
        Ok((self.sessions, batch))
    }
    pub(crate) fn seal_owned(&mut self) -> Result<SealedInput> {
        self.round
            .schedule
            .in_window(9_500_000_000, 10_000_000_000)?;
        if self.failed || !self.armed || self.output.len() < 8 {
            return Err(Error::Unavailable("A input barrier failed"));
        }
        self.failed = true; // No second seal after any fallible work starts.
        // This transition occurs before source labels are erased or filler is
        // generated. Counts on an already assembled InputBatch are insufficient.
        let completion = if self.policy == InputPolicy::Strict32 {
            Some(self.completed_slots.finish(
                self.sessions.entries.len(),
                self.output.len(),
                self.sessions.config,
                self.round.manifest().id(),
                self.round.schedule.round(),
            )?)
        } else {
            None
        };
        for (i, session) in self.sessions.entries.iter_mut().enumerate() {
            if self.completed[i] || session.transport.receive_progress() == ReceiveProgress::Failed
            {
                continue;
            }
            if self.known_pending[i]
                || session.transport.receive_progress() != ReceiveProgress::WaitingZeroBytes
            {
                return Err(Error::Unavailable("A incomplete input at barrier"));
            }
            session.transport.retire_empty_cell()?;
        }
        let admitted =
            u8::try_from(self.output.len()).map_err(|_| Error::Unavailable("A count"))?;
        while self.policy == InputPolicy::Legacy && self.output.len() < 32 {
            let cover = client_cell(&self.round.context(), &Payload::cover())?;
            self.output
                .push(open_a(&self.round.context(), &self.key, &cover)?);
        }
        // Only bare cells cross this boundary. The permutation has no token,
        // input slot, address, source stream or real/cover annotation to preserve.
        let mut frames: [Frame; 32] = std::mem::take(&mut self.output)
            .try_into()
            .map_err(|_| Error::Unavailable("A complete batch"))?;
        permute_stage2(&self.round.context(), &mut frames)?;
        let id = a_batch_id(&self.round.context(), &frames)?;
        self.round.schedule.completed_before(10_000_000_000)?;
        let batch = InputBatch {
            frames,
            admitted,
            id,
        };
        Ok(match completion {
            Some(completion) => {
                SealedInput::Strict(StrictInputBatch::from_collection(batch, completion))
            }
            None => SealedInput::Legacy(batch),
        })
    }
}
/// Source-free complete batch; facts can feed `A_READY` only through the later driver.
pub struct InputBatch {
    frames: [Frame; 32],
    admitted: u8,
    id: Digest,
}
impl InputBatch {
    /// One immutable egress queue in independent permutation order.
    #[must_use]
    pub const fn frames(&self) -> &[Frame; 32] {
        &self.frames
    }
    /// Exact fully admitted source-session count; filler is excluded.
    #[must_use]
    pub const fn admitted(&self) -> u8 {
        self.admitted
    }
    /// Ordered complete A batch hash.
    #[must_use]
    pub const fn id(&self) -> Digest {
        self.id
    }
}
