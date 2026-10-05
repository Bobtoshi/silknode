//! A's actual batch transmission, received evidence and one-way terminal seal.
//! The outer two-slot coordinator supplies clock samples and native resource caps.
use crate::{
    Error, Result,
    control::{
        Kind, PreparedAuthorization, Role, SignedControl, check_ready_pair, prepare_authorization,
    },
    flow::{ReadSlot, WriteSlot},
    input::{InputBatch, SealedInput, StrictCompletion, StrictInputBatch},
    journal::Decision,
    owner::{DurableJournal, Identity, ManifestRound, PinRetention, prefix},
    schedule::QualifiedClockSample,
    staging::a_batch_id,
    tls::{RecordSize, Transport},
};
use std::{rc::Rc, time::Instant};

/// Local source-side completion only, not downstream delivery or settlement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceProgress {
    /// More fixed slots/observations remain; poll from the sole role coordinator.
    Pending,
    /// Irrevocable authorization was durably sealed and completely written locally.
    AuthorizedWritten,
}
enum Phase {
    Cells(usize),
    Ready,
    Evidence(usize),
    Freeze,
    Authorized,
    Written,
    Stopped,
}

/// Source-free A round state. Input source sessions are not retained here.
///
/// A single transport is passed by the owning role coordinator at each tick;
/// the same connection/role must be used for the entire round. It can be handed
/// to next-round manifest negotiation after the current scheduled write ends.
pub struct SourceRound {
    round: Rc<ManifestRound>,
    batch: InputBatch,
    ready: Option<SignedControl>,
    b_ready: Option<SignedControl>,
    acks: [Option<SignedControl>; 3],
    authorization: Option<SignedControl>,
    prepared: Option<PreparedAuthorization>,
    phase: Phase,
    failed_phase: Option<Phase>,
    writer: WriteSlot,
    reader: ReadSlot,
    health_failed: bool,
    transport_id: u64,
    // Retained for the entire strict round; never constructed from a legacy count.
    _strict_completion: Option<StrictCompletion>,
}
impl SourceRound {
    /// Bind actual sealed input to a locally cut-checked/durable manifest.
    /// # Errors
    /// Refuses changed cfg/round/batch, recorded clock failure or missed assembly.
    pub fn new(round: Rc<ManifestRound>, batch: InputBatch, transport: &Transport) -> Result<Self> {
        Self::new_bound(round, batch, None, transport)
    }
    /// Bind a strict collector's private pre-erasure provenance to this round.
    /// No legacy batch, public count or caller assertion can construct it.
    /// # Errors
    /// Refuses foreign provenance and all ordinary source admission faults.
    pub fn new_strict(
        round: Rc<ManifestRound>,
        batch: StrictInputBatch,
        transport: &Transport,
    ) -> Result<Self> {
        let (batch, completion) = batch.into_bound(
            round.config.id(),
            round.manifest().id(),
            round.schedule.round(),
        )?;
        Self::new_bound(round, batch, Some(completion), transport)
    }
    pub(crate) fn from_collector(
        round: Rc<ManifestRound>,
        batch: SealedInput,
        transport: &Transport,
    ) -> Result<Self> {
        match batch {
            SealedInput::Legacy(batch) => Self::new(round, batch, transport),
            SealedInput::Strict(batch) => Self::new_strict(round, batch, transport),
        }
    }
    fn new_bound(
        round: Rc<ManifestRound>,
        batch: InputBatch,
        completion: Option<StrictCompletion>,
        transport: &Transport,
    ) -> Result<Self> {
        let schedule = &round.schedule;
        let config = &round.config;
        schedule.in_window(9_500_000_000, 10_000_000_000)?;
        schedule.clock_healthy()?;
        transport.check_endpoint(config.endpoints()[Role::B as usize], true)?;
        let context = round.context();
        if context.manifest.round() != schedule.round()
            || batch.id() != a_batch_id(&context, batch.frames())?
        {
            return Err(Error::Invalid("A sealed batch/context"));
        }
        schedule.completed_before(10_000_000_000)?;
        Ok(Self {
            round,
            batch,
            ready: None,
            b_ready: None,
            acks: std::array::from_fn(|_| None),
            authorization: None,
            prepared: None,
            phase: Phase::Cells(0),
            failed_phase: None,
            writer: WriteSlot::default(),
            reader: ReadSlot::default(),
            health_failed: false,
            transport_id: transport.id(),
            _strict_completion: completion,
        })
    }
    /// Record qualified clock health only while A's authorization barrier is open.
    /// Later samples can affect later rounds, never revoke this round's decision.
    /// # Errors
    /// Reports a recorded pre-cutoff fault; no caller-supplied validity flag exists.
    pub fn observe_clock(&mut self, sample: &QualifiedClockSample) -> Result<()> {
        if Instant::now() >= self.round.schedule.at(18_500_000_000)? {
            return Ok(());
        }
        let result = self.round.schedule.observe_clock(sample);
        if Instant::now() < self.round.schedule.at(18_500_000_000)? && result.is_err() {
            self.health_failed = true;
            return result;
        }
        Ok(())
    }
    /// Feature-gated host observation with the same irreversible A cutoff.
    /// # Errors
    /// A detected still-open fault sticks; after the cutoff it cannot revoke A.
    #[cfg(feature = "functional-lab")]
    pub fn observe_functional_clock(&mut self) -> Result<()> {
        if Instant::now() >= self.round.schedule.at(18_500_000_000)? {
            return Ok(());
        }
        let result = self.round.schedule.observe_functional_clock();
        if Instant::now() < self.round.schedule.at(18_500_000_000)? && result.is_err() {
            self.health_failed = true;
            return result;
        }
        Ok(())
    }
    /// Advance bounded actual I/O, never waiting, rebasing or selecting a source queue.
    ///
    /// On error the parent must quarantine any failed transport and service the
    /// remaining failure slots with CANCEL where the established link is usable.
    /// A durable authorization is NEVER replaced by such failure controls.
    /// # Errors
    /// Stops on any malformed/late/missing observation, durability or transport fault.
    pub fn poll<P: PinRetention>(
        &mut self,
        transport: &mut Transport,
        identity: &Identity,
        journal: &mut DurableJournal<P>,
    ) -> Result<SourceProgress> {
        identity.check(&self.round.config, Role::A)?;
        journal.check_role(Role::A)?;
        if transport.id() != self.transport_id {
            return Err(Error::Unavailable("A connection replaced during round"));
        }
        if matches!(self.phase, Phase::Stopped) {
            return Err(Error::Unavailable("A round stopped"));
        }
        let result = self.advance(transport, identity, journal);
        if result.is_err() {
            self.failed_phase = Some(std::mem::replace(&mut self.phase, Phase::Stopped));
            // Never revoke SEALED_AUTH, including post-fsync signing/time failures.
            if journal.decision(self.round.schedule.round()) == Some(Decision::Open) {
                journal.update(|j| j.abort(self.round.schedule.round()))?;
            }
        }
        result
    }
    /// Erase the failed data batch and retain only live-abort failure-slot service.
    /// Irrevocable authorization and uncertain persistence yield no CANCEL.
    /// # Errors
    /// Requires an actual stopped, still-live reversible round.
    pub fn into_failure<P: PinRetention>(
        self,
        identity: &Identity,
        journal: &mut DurableJournal<P>,
    ) -> Result<crate::failure::FailedControls> {
        let (next, previous_is_control) = match self.failed_phase {
            Some(Phase::Cells(_)) => (0, false),
            Some(Phase::Ready) => (0, true),
            Some(Phase::Evidence(_) | Phase::Freeze) => (1, false),
            Some(Phase::Authorized) => (1, true),
            _ => return Err(Error::Unavailable("A no reversible failed phase")),
        };
        let cancel = journal.cancel_live(&self.round.config, &self.round.schedule, identity)?;
        Ok(crate::failure::FailedControls::source(
            Rc::clone(&self.round.schedule),
            cancel,
            next,
            self.writer,
            previous_is_control,
            self.transport_id,
        ))
    }
    pub(crate) fn into_committed_failure<P: PinRetention>(
        self,
        journal: &DurableJournal<P>,
    ) -> Result<crate::failure::CommittedWrite> {
        journal.check_role(Role::A)?;
        if self.failed_phase.is_none()
            || journal.decision(self.round.schedule.round()) != Some(Decision::SealedAuth)
        {
            return Err(Error::Unavailable("A no irreversible failed decision"));
        }
        Ok(crate::failure::CommittedWrite::new(
            self.writer,
            0,
            vec![self.transport_id],
        ))
    }
    #[allow(clippy::too_many_lines)] // Keep the ordered single-coordinator phases together.
    fn advance<P: PinRetention>(
        &mut self,
        transport: &mut Transport,
        identity: &Identity,
        journal: &mut DurableJournal<P>,
    ) -> Result<SourceProgress> {
        if !matches!(self.phase, Phase::Authorized | Phase::Written) && self.health_failed {
            return Err(Error::Unavailable("A frozen local health failure"));
        }
        match self.phase {
            Phase::Cells(i) => {
                let start = 10_000_000_000
                    + i64::try_from(i).map_err(|_| Error::Invalid("A slot"))? * 31_250_000;
                if self.writer.poll(
                    transport,
                    &self.round.schedule,
                    (start, start + 31_250_000),
                    RecordSize::Cell,
                    self.batch.frames()[i].bytes(),
                )? {
                    self.writer = WriteSlot::default();
                    self.phase = if i == 31 {
                        Phase::Ready
                    } else {
                        Phase::Cells(i + 1)
                    };
                }
            }
            Phase::Ready => {
                if self.ready.is_none() {
                    // Reached only after all32 actual fixed-slot writes completed.
                    let mut body = prefix(
                        &self.round.config,
                        self.round.schedule.round(),
                        self.round.manifest().id(),
                    );
                    body[120..152].copy_from_slice(&self.batch.id());
                    body[248] = self.batch.admitted();
                    self.ready = Some(identity.control(
                        &self.round.config,
                        self.round.schedule.round(),
                        Kind::AReady,
                        &body,
                    )?);
                }
                if self.writer.poll(
                    transport,
                    &self.round.schedule,
                    (11_000_000_000, 14_000_000_000),
                    RecordSize::Control,
                    self.ready
                        .as_ref()
                        .ok_or(Error::Unavailable("A readiness absent"))?
                        .bytes(),
                )? {
                    self.writer = WriteSlot::default();
                    self.phase = Phase::Evidence(0);
                }
            }
            Phase::Evidence(i) => {
                let (kind, role, start) = if i == 0 {
                    (Kind::BReady, Role::B, 13_000_000_000)
                } else {
                    (
                        Kind::Ack,
                        [Role::P0, Role::P1, Role::P2][i - 1],
                        17_000_000_000
                            + i64::try_from(i - 1).map_err(|_| Error::Invalid("A ACK slot"))?
                                * 125_000_000,
                    )
                };
                if let Some(bytes) = self.reader.poll(
                    transport,
                    &self.round.schedule,
                    (start, 18_500_000_000),
                    RecordSize::Control,
                )? {
                    let actual_kind = if bytes.get(8) == Some(&(Kind::Cancel as u8)) {
                        Kind::Cancel
                    } else {
                        kind
                    };
                    let control = SignedControl::verify(
                        &bytes,
                        &self.round.config,
                        self.round.schedule.round(),
                        actual_kind,
                        if actual_kind == Kind::Cancel {
                            Role::B
                        } else {
                            role
                        },
                    )?;
                    if control.kind() == Kind::Cancel {
                        if control.bytes()[88..120] != self.round.manifest().id() {
                            return Err(Error::Invalid("A CANCEL manifest mismatch"));
                        }
                        return Err(Error::Unavailable("A received pre-seal CANCEL"));
                    }
                    if i == 0 {
                        check_ready_pair(self.round.manifest(), self.a()?, &control)?;
                    }
                    self.round.schedule.completed_before(18_500_000_000)?;
                    if i == 0 {
                        self.b_ready = Some(control);
                    } else {
                        self.acks[i - 1] = Some(control);
                    }
                    if i == 3 {
                        self.prepared = Some(prepare_authorization(
                            self.round.manifest(),
                            self.a()?,
                            self.b()?,
                            self.ack_refs()?,
                        )?);
                        self.round.schedule.completed_before(18_500_000_000)?;
                    }
                    self.reader = ReadSlot::default();
                    self.phase = if i == 3 {
                        Phase::Freeze
                    } else {
                        Phase::Evidence(i + 1)
                    };
                }
            }
            Phase::Freeze => {
                if Instant::now() < self.round.schedule.at(18_500_000_000)? {
                    let extra = transport.has_extra_bytes();
                    if Instant::now() < self.round.schedule.at(18_500_000_000)? && extra? {
                        return Err(Error::Invalid("A excess pre-seal evidence"));
                    }
                    return Ok(SourceProgress::Pending);
                }
                self.round
                    .schedule
                    .in_window(18_500_000_000, 19_000_000_000)?;
                let prepared = self
                    .prepared
                    .take()
                    .ok_or(Error::Unavailable("A complete pre-cutoff chain absent"))?;
                // The complete chain was checked BEFORE the18.5 barrier; there
                // is no post-cutoff semantic validation or evidence backdating.
                journal.update(|j| j.seal_a(&prepared))?;
                self.round.schedule.completed_before(19_000_000_000)?;
                self.authorization = Some(identity.control(
                    &self.round.config,
                    self.round.schedule.round(),
                    Kind::Authorize,
                    prepared.body(),
                )?);
                self.round.schedule.completed_before(19_000_000_000)?;
                self.phase = Phase::Authorized;
            }
            Phase::Authorized => {
                let control = self
                    .authorization
                    .as_ref()
                    .ok_or(Error::Unavailable("A missing sealed control"))?;
                if self.writer.poll(
                    transport,
                    &self.round.schedule,
                    (19_000_000_000, 19_750_000_000),
                    RecordSize::Control,
                    control.bytes(),
                )? {
                    self.phase = Phase::Written;
                    return Ok(SourceProgress::AuthorizedWritten);
                }
            }
            Phase::Written => return Ok(SourceProgress::AuthorizedWritten),
            Phase::Stopped => return Err(Error::Unavailable("A round stopped")),
        }
        Ok(SourceProgress::Pending)
    }
    fn a(&self) -> Result<&SignedControl> {
        self.ready
            .as_ref()
            .ok_or(Error::Unavailable("A readiness absent"))
    }
    fn b(&self) -> Result<&SignedControl> {
        self.b_ready
            .as_ref()
            .ok_or(Error::Unavailable("B readiness absent"))
    }
    fn ack_refs(&self) -> Result<[&SignedControl; 3]> {
        Ok([
            self.acks[0]
                .as_ref()
                .ok_or(Error::Unavailable("P0 ACK absent"))?,
            self.acks[1]
                .as_ref()
                .ok_or(Error::Unavailable("P1 ACK absent"))?,
            self.acks[2]
                .as_ref()
                .ok_or(Error::Unavailable("P2 ACK absent"))?,
        ])
    }
}
