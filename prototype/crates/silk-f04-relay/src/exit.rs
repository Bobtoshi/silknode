//! B's single actual ingress, fixed three-producer fanout and irreversible release.
//! Native resource admission and the two-round/epoch owner remain outside this state.
use crate::{
    Error, Result,
    control::{Kind, Role, SignedControl, check_release, prepare_authorization},
    flow::{ReadSlot, WriteSlot},
    frame::{Frame, HpkePrivate},
    journal::Decision,
    lane::{BControlLane, FrozenAuthorization},
    owner::{DurableJournal, Identity, ManifestRound, PinRetention},
    schedule::QualifiedClockSample,
    staging::{StagedBatch, VerifiedExitBatch},
    tls::{ReceiveProgress, RecordSize, Transport},
};
use silk_sapling_f04::parameters::SaplingVerificationKeys;
use std::{rc::Rc, time::Instant};

/// B's local operational result, not simultaneous receipt or ledger settlement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitProgress {
    /// Continue from the same source-free role coordinator.
    Pending,
    /// All fixed release writes completed and retained round key material was erased.
    ReleasedWritten,
}
enum Phase {
    Cells(usize),
    AReady,
    #[cfg(all(feature = "aip2-preparation", feature = "functional-lab"))]
    R2Freeze,
    ReadyA,
    ReadyProducers(usize),
    Staging(usize, usize),
    Acks(usize),
    ForwardA(usize),
    ForwardProducers(usize, usize),
    Authorization,
    AuthCopies(usize),
    CommitRelease,
    Release(usize),
    Erase,
    Finished,
    Stopped,
}

/// One B round owns its complete batch, key and signed release privately.
///
/// The parent passes the SAME established A and ordered P0/P1/P2 connections at
/// every tick; no reconnect, per-source egress task or precommit release accessor exists.
pub struct ExitRound {
    round: Rc<ManifestRound>,
    key: Rc<HpkePrivate>,
    keys: Rc<SaplingVerificationKeys>,
    connection_ids: [u64; 4],
    incoming: Vec<Frame>,
    staged: Option<StagedBatch>,
    a_ready: Option<SignedControl>,
    b_ready: Option<SignedControl>,
    acks: [Option<SignedControl>; 3],
    authorization: Option<Rc<FrozenAuthorization>>,
    release: Option<SignedControl>,
    phase: Phase,
    failed_phase: Option<Phase>,
    reader: ReadSlot,
    writer: WriteSlot,
    health_failed: bool,
    first_key_started: bool,
    received_cells: u8,
    received_ready: bool,
    received_acks: [bool; 3],
    #[cfg(all(feature = "aip2-preparation", feature = "functional-lab"))]
    r2: Option<LabR2Exit>,
}
#[cfg(all(feature = "aip2-preparation", feature = "functional-lab"))]
struct LabR2Exit {
    profile: Rc<crate::aip2_profile::PreparedProfile>,
    verifier: Rc<crate::aip2_proof::PreparedProofVerifier>,
    claims: crate::aip2_claim::PreparedScopeStore<Box<dyn crate::aip2_claim::ClaimPinRetention>>,
    guard: Rc<crate::runtime::RoundGuard>,
    incoming: Vec<crate::aip2_transport::PreparedR2Frame>,
    batch: Option<crate::aip2_transport::CollectedR2Batch>,
}
impl ExitRound {
    /// Bind the exact locally manifested context and already established topology.
    /// # Errors
    /// Refuses wrong phase/round/clock, endpoint roles or a failed connection.
    pub fn new(
        round: Rc<ManifestRound>,
        key: Rc<HpkePrivate>,
        keys: Rc<SaplingVerificationKeys>,
        a: &Transport,
        producers: &[impl std::borrow::Borrow<Transport>; 3],
    ) -> Result<Self> {
        let producers = producers.each_ref().map(std::borrow::Borrow::borrow);
        let config = &round.config;
        let schedule = &round.schedule;
        schedule.in_window(-8_000_000_000, 9_000_000_000)?;
        schedule.clock_healthy()?;
        let context = round.context();
        if context.manifest.round() != schedule.round() {
            return Err(Error::Invalid("B round context"));
        }
        a.check_endpoint(config.endpoints()[Role::B as usize], false)?;
        for (i, p) in producers.iter().enumerate() {
            p.check_endpoint(config.endpoints()[i + 2], true)?;
        }
        Ok(Self {
            round,
            key,
            keys,
            connection_ids: [
                a.id(),
                producers[0].id(),
                producers[1].id(),
                producers[2].id(),
            ],
            incoming: Vec::with_capacity(32),
            staged: None,
            a_ready: None,
            b_ready: None,
            acks: std::array::from_fn(|_| None),
            authorization: None,
            release: None,
            phase: Phase::Cells(0),
            failed_phase: None,
            reader: ReadSlot::default(),
            writer: WriteSlot::default(),
            health_failed: false,
            first_key_started: false,
            received_cells: 0,
            received_ready: false,
            received_acks: [false; 3],
            #[cfg(all(feature = "aip2-preparation", feature = "functional-lab"))]
            r2: None,
        })
    }
    /// Default-off operator lab only: unaccepted setup and unqualified time.
    /// Keeps the ORIGINAL pre-round native lease through release/erasure. There
    /// is no operational-profile admission or CPU reset at the +12 gate.
    /// # Errors
    /// Refuses qualified schedules, foreign profile/verifier/lease or topology.
    #[cfg(all(feature = "aip2-preparation", feature = "functional-lab"))]
    #[allow(clippy::too_many_arguments)]
    pub fn new_r2_lab(
        round: Rc<ManifestRound>,
        key: Rc<HpkePrivate>,
        keys: Rc<SaplingVerificationKeys>,
        profile: Rc<crate::aip2_profile::PreparedProfile>,
        verifier: Rc<crate::aip2_proof::PreparedProofVerifier>,
        claims: crate::aip2_claim::PreparedScopeStore<
            Box<dyn crate::aip2_claim::ClaimPinRetention>,
        >,
        guard: Rc<crate::runtime::RoundGuard>,
        a: &Transport,
        producers: &[impl std::borrow::Borrow<Transport>; 3],
    ) -> Result<Self> {
        if round.schedule.uses_qualified_source() || !guard.matches_schedule(&round.schedule) {
            return Err(Error::Unavailable(
                "R2 lab unqualified original lease required",
            ));
        }
        guard.check()?;
        crate::aip2_transport::PreparedR2Context::new(
            &round.config,
            round.manifest(),
            &profile,
            verifier.key_hash(),
        )?;
        let mut exit = Self::new(round, key, keys, a, producers)?;
        exit.r2 = Some(LabR2Exit {
            profile,
            verifier,
            claims,
            guard,
            incoming: Vec::with_capacity(32),
            batch: None,
        });
        Ok(exit)
    }
    fn ingress_end(&self) -> i64 {
        #[cfg(all(feature = "aip2-preparation", feature = "functional-lab"))]
        if self.r2.is_some() {
            return 12_000_000_000;
        }
        14_000_000_000
    }
    fn ingress_width(&self) -> i64 {
        #[cfg(all(feature = "aip2-preparation", feature = "functional-lab"))]
        if self.r2.is_some() {
            return 7_812_500;
        }
        31_250_000
    }
    /// Record B's OWN clock health until the first key-write barrier; never consult
    /// A's later clock/link health as a revocation of received authorization.
    /// # Errors
    /// Detected B health failure sticks before key release; later delivery is uncertain.
    pub fn observe_clock(&mut self, sample: &QualifiedClockSample) -> Result<()> {
        if matches!(self.phase, Phase::Erase | Phase::Finished | Phase::Stopped) {
            return Ok(());
        }
        let result = self.round.schedule.observe_clock(sample);
        if result.is_err() {
            self.health_failed = true;
        }
        result
    }
    /// Feature-gated B-local observation, never an A-health revocation predicate.
    /// # Errors
    /// A detected B fault stops prewrite release or makes started delivery uncertain.
    #[cfg(feature = "functional-lab")]
    pub fn observe_functional_clock(&mut self) -> Result<()> {
        if matches!(self.phase, Phase::Erase | Phase::Finished | Phase::Stopped) {
            return Ok(());
        }
        let result = self.round.schedule.observe_functional_clock();
        if result.is_err() {
            self.health_failed = true;
        }
        result
    }
    /// Advance bounded nonblocking role I/O with fixed connection order and slots.
    /// On error the parent services still-usable failed-round CANCEL slots and
    /// quarantines failed transports; it cannot obtain/retry this round's key.
    /// # Errors
    /// Precommit failure aborts. Postcommit failure records delivery-unknown, not abort.
    pub fn poll<P: PinRetention>(
        &mut self,
        a: &mut Transport,
        producers: &mut [impl std::borrow::BorrowMut<Transport>; 3],
        identity: &Identity,
        journal: &mut DurableJournal<P>,
        lane: &mut BControlLane,
    ) -> Result<ExitProgress> {
        let mut producers = producers.each_mut().map(std::borrow::BorrowMut::borrow_mut);
        lane.check_round(&self.round, a)?;
        identity.check(&self.round.config, Role::B)?;
        journal.check_role(Role::B)?;
        if [
            a.id(),
            producers[0].id(),
            producers[1].id(),
            producers[2].id(),
        ] != self.connection_ids
        {
            return Err(Error::Unavailable("B connection replaced during round"));
        }
        if matches!(self.phase, Phase::Stopped) {
            return Err(Error::Unavailable("B round stopped"));
        }
        let result = self
            .advance(a, &mut producers, identity, journal, lane)
            .and_then(|progress| {
                if matches!(
                    self.phase,
                    Phase::AuthCopies(_) | Phase::CommitRelease | Phase::Release(_) | Phase::Erase
                ) {
                    lane.poll(a)?;
                }
                Ok(progress)
            });
        if result.is_err() {
            self.failed_phase = Some(std::mem::replace(&mut self.phase, Phase::Stopped));
            self.release = None;
            self.staged = None;
            match journal.decision(self.round.schedule.round()) {
                Some(Decision::Open | Decision::AuthFrozen) => {
                    journal.update(|j| j.abort(self.round.schedule.round()))?;
                }
                Some(Decision::ReleaseDecided) => {
                    journal.update(|j| j.delivery(self.round.schedule.round(), false))?;
                }
                _ => (),
            }
        }
        result
    }
    /// Consume an actually failed reversible round into bounded scheduled
    /// cancellation. Batch and key owners are dropped; committed release cannot
    /// create this service or be converted to Abort.
    /// # Errors
    /// Refuses irreversible/nonfailed state or uncertain journal/pin continuity.
    pub fn into_failure<P: PinRetention>(
        self,
        identity: &Identity,
        journal: &mut DurableJournal<P>,
    ) -> Result<crate::failure::FailedControls> {
        let (next, lane, control) = match self.failed_phase {
            #[cfg(all(feature = "aip2-preparation", feature = "functional-lab"))]
            Some(Phase::R2Freeze) => (0, 0, false),
            Some(Phase::Cells(_) | Phase::AReady) => (0, 0, false),
            Some(Phase::ReadyA) => (0, 0, true),
            Some(Phase::ReadyProducers(i)) => (1 + i, 1 + i / 2, true),
            Some(Phase::Staging(_, p)) => (7, 1 + p, false),
            Some(Phase::Acks(_)) => (7, 0, false),
            Some(Phase::ForwardA(i)) => (7 + i, 0, true),
            Some(Phase::ForwardProducers(i, p)) => (10 + i * 3 + p, 1 + p, true),
            Some(Phase::Authorization) => (19, 0, false),
            Some(Phase::AuthCopies(p)) => (19 + p, 1 + p, true),
            Some(Phase::CommitRelease) => (22, 0, false),
            _ => return Err(Error::Unavailable("B no reversible failed phase")),
        };
        let cancel = journal.cancel_live(&self.round.config, &self.round.schedule, identity)?;
        #[cfg(all(feature = "aip2-preparation", feature = "functional-lab"))]
        let guard = self.r2.as_ref().map(|r2| Rc::clone(&r2.guard));
        let controls = crate::failure::FailedControls::exit(
            Rc::clone(&self.round.schedule),
            cancel,
            next,
            self.writer,
            lane,
            control,
            self.connection_ids,
        );
        #[cfg(all(feature = "aip2-preparation", feature = "functional-lab"))]
        let controls = controls.retain_r2_lease(guard);
        Ok(controls)
    }
    pub(crate) fn input_drain(&self) -> crate::drain::ExitInputDrain {
        crate::drain::ExitInputDrain::new(
            Rc::clone(&self.round.schedule),
            self.connection_ids,
            self.received_cells,
            self.received_ready,
            self.received_acks,
        )
    }
    pub(crate) fn into_committed_failure<P: PinRetention>(
        self,
        journal: &DurableJournal<P>,
    ) -> Result<crate::failure::CommittedWrite> {
        journal.check_role(Role::B)?;
        if !matches!(
            journal.decision(self.round.schedule.round()),
            Some(Decision::DeliveryUnknown | Decision::Finalized)
        ) {
            return Err(Error::Unavailable("B no irreversible failed decision"));
        }
        let lane = match self.failed_phase {
            Some(Phase::Release(producer)) => 1 + producer,
            Some(Phase::CommitRelease | Phase::Erase) => 0,
            _ => return Err(Error::Unavailable("B no committed failed phase")),
        };
        #[cfg(all(feature = "aip2-preparation", feature = "functional-lab"))]
        let guard = self.r2.as_ref().map(|r2| Rc::clone(&r2.guard));
        let service =
            crate::failure::CommittedWrite::new(self.writer, lane, self.connection_ids.to_vec());
        #[cfg(all(feature = "aip2-preparation", feature = "functional-lab"))]
        let service = service.retain_r2_lease(guard);
        Ok(service)
    }
    #[allow(clippy::too_many_lines)]
    fn advance<P: PinRetention>(
        &mut self,
        a: &mut Transport,
        producers: &mut [&mut Transport; 3],
        identity: &Identity,
        journal: &mut DurableJournal<P>,
        lane: &mut BControlLane,
    ) -> Result<ExitProgress> {
        #[cfg(all(feature = "aip2-preparation", feature = "functional-lab"))]
        if let Some(r2) = &self.r2 {
            r2.guard.check()?;
        }
        if self.health_failed && !matches!(self.phase, Phase::Erase | Phase::Finished) {
            return Err(Error::Unavailable("B local health failure"));
        }
        match self.phase {
            Phase::Cells(i) => {
                self.round.schedule.completed_before(self.ingress_end())?;
                // Failed A can omit remaining cells and use its original +11
                // control slot. Inspect only an untouched fixed TLS header;
                // full signature/context validation still occurs in AReady.
                if matches!(
                    a.receive_progress(),
                    ReceiveProgress::Idle | ReceiveProgress::WaitingZeroBytes
                ) {
                    let Some(size) = a.peek_record_size()? else {
                        return Ok(ExitProgress::Pending);
                    };
                    if size == RecordSize::Control {
                        if Instant::now() < self.round.schedule.at(10_000_000_000)? {
                            return Ok(ExitProgress::Pending);
                        }
                        if a.selected_read().is_some() {
                            a.retire_empty(RecordSize::Cell)?;
                        }
                        self.reader = ReadSlot::default();
                        self.phase = Phase::AReady;
                        return Ok(ExitProgress::Pending);
                    }
                }
                let start = 9_000_000_000
                    + i64::try_from(i).map_err(|_| Error::Invalid("B input slot"))?
                        * self.ingress_width();
                if let Some(bytes) = self.reader.poll(
                    a,
                    &self.round.schedule,
                    (start, self.ingress_end()),
                    RecordSize::Cell,
                )? {
                    self.received_cells += 1;
                    self.collect_frame(&bytes)?;
                    self.round.schedule.completed_before(self.ingress_end())?;
                    self.reader = ReadSlot::default();
                    self.phase = if i == 31 {
                        Phase::AReady
                    } else {
                        Phase::Cells(i + 1)
                    };
                }
            }
            Phase::AReady => {
                let ready_start = if self.ingress_width() == 7_812_500 {
                    9_250_000_000
                } else {
                    10_000_000_000
                };
                if let Some(bytes) = self.reader.poll(
                    a,
                    &self.round.schedule,
                    (ready_start, self.ingress_end()),
                    RecordSize::Control,
                )? {
                    self.received_ready = true;
                    let ready = self.verify_control(&bytes, Kind::AReady, Role::A)?;
                    #[cfg(all(feature = "aip2-preparation", feature = "functional-lab"))]
                    if let Some(r2) = &mut self.r2 {
                        let c = crate::aip2_transport::PreparedR2Context::new(
                            &self.round.config,
                            self.round.manifest(),
                            &r2.profile,
                            r2.verifier.key_hash(),
                        )?;
                        let frames = std::mem::take(&mut r2.incoming)
                            .try_into()
                            .map_err(|_| Error::Unavailable("R2 incomplete ingress"))?;
                        r2.batch = Some(crate::aip2_transport::CollectedR2Batch::collect(
                            &c, frames, &ready,
                        )?);
                        self.round.schedule.completed_before(12_000_000_000)?;
                        self.a_ready = Some(ready);
                        self.reader = ReadSlot::default();
                        self.phase = Phase::R2Freeze;
                        return Ok(ExitProgress::Pending);
                    }
                    let frames = std::mem::take(&mut self.incoming)
                        .try_into()
                        .map_err(|_| Error::Unavailable("B incomplete input"))?;
                    let verified = VerifiedExitBatch::verify(
                        &self.round.context(),
                        &self.key,
                        frames,
                        &ready,
                        &self.keys,
                        self.round.schedule.at(14_000_000_000)?,
                    )?;
                    let staged = verified.seal(&self.round.context())?;
                    self.prepare_ready(ready, staged, identity, 14_000_000_000)?;
                    self.reader = ReadSlot::default();
                    self.phase = Phase::ReadyA;
                }
            }
            #[cfg(all(feature = "aip2-preparation", feature = "functional-lab"))]
            Phase::R2Freeze => {
                if a.has_extra_bytes()? {
                    return Err(Error::Invalid("R2 excess pre-gate ingress"));
                }
                if Instant::now() < self.round.schedule.at(12_000_000_000)? {
                    return Ok(ExitProgress::Pending);
                }
                self.round
                    .schedule
                    .in_window(12_000_000_000, 13_750_000_000)?;
                let r2 = self
                    .r2
                    .as_mut()
                    .ok_or(Error::Unavailable("R2 gate absent"))?;
                let c = crate::aip2_transport::PreparedR2Context::new(
                    &self.round.config,
                    self.round.manifest(),
                    &r2.profile,
                    r2.verifier.key_hash(),
                )?;
                let batch = r2
                    .batch
                    .take()
                    .ok_or(Error::Unavailable("R2 complete batch absent"))?;
                let claim = r2
                    .claims
                    .consume(
                        self.round.schedule.round(),
                        self.round.manifest().id(),
                        batch.exit_consistency(),
                    )
                    .map_err(|_| Error::Unavailable("R2 durable exit claim STOP"))?;
                let deadline = self.round.schedule.at(13_750_000_000)?;
                let cohort =
                    batch.verify_membership(&c, &self.key, &r2.verifier, claim, deadline)?;
                let verified = cohort.verify_sapling(&c, Some(&self.keys), deadline)?;
                let staged = verified.seal_for_lab(&c)?;
                r2.guard.check()?;
                let ready = self
                    .a_ready
                    .take()
                    .ok_or(Error::Unavailable("R2 original readiness absent"))?;
                self.prepare_ready(ready, staged, identity, 13_750_000_000)?;
                self.phase = Phase::ReadyA;
            }
            Phase::ReadyA => {
                if self.writer.poll(
                    a,
                    &self.round.schedule,
                    (14_000_000_000, 14_125_000_000),
                    RecordSize::Control,
                    self.b_ready
                        .as_ref()
                        .ok_or(Error::Unavailable("B readiness absent"))?
                        .bytes(),
                )? {
                    self.writer = WriteSlot::default();
                    self.phase = Phase::ReadyProducers(0);
                }
            }
            Phase::ReadyProducers(i) => {
                let control = if i % 2 == 0 {
                    &self.a_ready
                } else {
                    &self.b_ready
                };
                if self.writer.poll(
                    producers[i / 2],
                    &self.round.schedule,
                    (14_125_000_000, 15_000_000_000),
                    RecordSize::Control,
                    control
                        .as_ref()
                        .ok_or(Error::Unavailable("B producer readiness absent"))?
                        .bytes(),
                )? {
                    self.writer = WriteSlot::default();
                    self.phase = if i == 5 {
                        Phase::Staging(0, 0)
                    } else {
                        Phase::ReadyProducers(i + 1)
                    };
                }
            }
            Phase::Staging(slot, producer) => {
                let start = 15_000_000_000
                    + i64::try_from(slot).map_err(|_| Error::Invalid("B output slot"))?
                        * 31_250_000;
                if self.writer.poll(
                    producers[producer],
                    &self.round.schedule,
                    (start, start + 31_250_000),
                    RecordSize::Cell,
                    self.staged
                        .as_ref()
                        .ok_or(Error::Unavailable("B batch absent"))?
                        .frames()[slot]
                        .bytes(),
                )? {
                    self.writer = WriteSlot::default();
                    self.phase = if producer < 2 {
                        Phase::Staging(slot, producer + 1)
                    } else if slot < 31 {
                        Phase::Staging(slot + 1, 0)
                    } else {
                        Phase::Acks(0)
                    };
                }
            }
            Phase::Acks(i) => {
                if let Some(bytes) = self.reader.poll(
                    producers[i],
                    &self.round.schedule,
                    (16_000_000_000, 18_000_000_000),
                    RecordSize::Control,
                )? {
                    self.received_acks[i] = true;
                    let ack =
                        self.verify_control(&bytes, Kind::Ack, [Role::P0, Role::P1, Role::P2][i])?;
                    self.acks[i] = Some(ack);
                    if i == 2 {
                        let expected = prepare_authorization(
                            self.round.manifest(),
                            self.a()?,
                            self.b()?,
                            self.ack_refs()?,
                        )?;
                        lane.bind_expected(expected)?;
                    }
                    self.round.schedule.completed_before(18_000_000_000)?;
                    self.reader = ReadSlot::default();
                    self.phase = if i == 2 {
                        Phase::ForwardA(0)
                    } else {
                        Phase::Acks(i + 1)
                    };
                }
            }
            Phase::ForwardA(i) => {
                let start = 18_000_000_000
                    + i64::try_from(i).map_err(|_| Error::Invalid("ACK slot"))? * 125_000_000;
                if self.writer.poll(
                    a,
                    &self.round.schedule,
                    (start, start + 125_000_000),
                    RecordSize::Control,
                    self.acks[i]
                        .as_ref()
                        .ok_or(Error::Unavailable("B ACK absent"))?
                        .bytes(),
                )? {
                    self.writer = WriteSlot::default();
                    self.phase = if i == 2 {
                        Phase::ForwardProducers(0, 0)
                    } else {
                        Phase::ForwardA(i + 1)
                    };
                }
            }
            Phase::ForwardProducers(i, producer) => {
                let start = 18_500_000_000
                    + i64::try_from(i).map_err(|_| Error::Invalid("ACK fanout slot"))?
                        * 125_000_000;
                if self.writer.poll(
                    producers[producer],
                    &self.round.schedule,
                    (start, start + 125_000_000),
                    RecordSize::Control,
                    self.acks[i]
                        .as_ref()
                        .ok_or(Error::Unavailable("B ACK absent"))?
                        .bytes(),
                )? {
                    self.writer = WriteSlot::default();
                    self.phase = if producer < 2 {
                        Phase::ForwardProducers(i, producer + 1)
                    } else if i < 2 {
                        Phase::ForwardProducers(i + 1, 0)
                    } else {
                        Phase::Authorization
                    };
                }
            }
            Phase::Authorization => self.authorization_tick(a, journal, lane)?,
            Phase::AuthCopies(i) => {
                if self.writer.poll(
                    producers[i],
                    &self.round.schedule,
                    (20_000_000_000, 20_125_000_000),
                    RecordSize::Control,
                    self.authorization
                        .as_ref()
                        .ok_or(Error::Unavailable("B frozen auth absent"))?
                        .control()
                        .bytes(),
                )? {
                    self.writer = WriteSlot::default();
                    self.phase = if i == 2 {
                        Phase::CommitRelease
                    } else {
                        Phase::AuthCopies(i + 1)
                    };
                }
            }
            Phase::CommitRelease => {
                self.round
                    .schedule
                    .in_window(20_000_000_000, 20_125_000_000)?;
                // Only B-local integrity/clock/producer channels matter now. A
                // is deliberately not peeked or required to remain connected.
                self.round.schedule.clock_healthy()?;
                for producer in producers.iter() {
                    if producer.has_extra_bytes()? {
                        return Err(Error::Invalid(
                            "B unexpected producer control before release",
                        ));
                    }
                }
                let evidence = self.auth()?;
                let release = self
                    .staged
                    .as_ref()
                    .ok_or(Error::Unavailable("B batch/key absent"))?
                    .release_control(&self.round.context(), identity, &evidence)?;
                let evidence = check_release(&evidence, &release)?;
                journal.update(|j| j.release_decided(&evidence))?;
                // A slow/uncertain fsync never authorizes a late new first write.
                self.round.schedule.completed_before(20_125_000_000)?;
                self.release = Some(release);
                self.phase = Phase::Release(0);
            }
            Phase::Release(i) => {
                if i == 0
                    && !self.first_key_started
                    && Instant::now() >= self.round.schedule.at(20_125_000_000)?
                {
                    self.round.schedule.clock_healthy()?;
                    for producer in producers.iter() {
                        if producer.has_extra_bytes()? {
                            return Err(Error::Invalid("B producer fault at first key barrier"));
                        }
                    }
                    self.first_key_started = true;
                }
                if self.writer.poll(
                    producers[i],
                    &self.round.schedule,
                    (20_125_000_000, 21_000_000_000),
                    RecordSize::Control,
                    self.release
                        .as_ref()
                        .ok_or(Error::Unavailable("B committed release absent"))?
                        .bytes(),
                )? {
                    self.writer = WriteSlot::default();
                    if i == 2 {
                        journal.update(|j| j.delivery(self.round.schedule.round(), true))?;
                        self.phase = Phase::Erase;
                    } else {
                        self.phase = Phase::Release(i + 1);
                    }
                }
            }
            Phase::Erase => {
                if Instant::now() >= self.round.schedule.at(22_000_000_000)? {
                    self.release = None;
                    self.staged = None;
                    self.phase = Phase::Finished;
                    return Ok(ExitProgress::ReleasedWritten);
                }
            }
            Phase::Finished => return Ok(ExitProgress::ReleasedWritten),
            Phase::Stopped => return Err(Error::Unavailable("B round stopped")),
        }
        Ok(ExitProgress::Pending)
    }
    fn collect_frame(&mut self, bytes: &[u8]) -> Result<()> {
        #[cfg(all(feature = "aip2-preparation", feature = "functional-lab"))]
        if let Some(r2) = &mut self.r2 {
            let c = crate::aip2_transport::PreparedR2Context::new(
                &self.round.config,
                self.round.manifest(),
                &r2.profile,
                r2.verifier.key_hash(),
            )?;
            r2.incoming
                .push(crate::aip2_transport::PreparedR2Frame::decode(
                    bytes, &c, 2,
                )?);
            return Ok(());
        }
        self.incoming
            .push(Frame::decode(bytes, &self.round.context(), 2, 0)?);
        Ok(())
    }
    fn prepare_ready(
        &mut self,
        ready: SignedControl,
        staged: StagedBatch,
        identity: &Identity,
        end: i64,
    ) -> Result<()> {
        let mut body: [u8; 448] = ready.bytes()[..448]
            .try_into()
            .map_err(|_| Error::Invalid("A readiness body"))?;
        body[152..184].copy_from_slice(&staged.id());
        body[184..216].copy_from_slice(&ready.id());
        body[256..288].copy_from_slice(&staged.key_commit());
        let b_ready = identity.control(
            &self.round.config,
            self.round.schedule.round(),
            Kind::BReady,
            &body,
        )?;
        self.round.schedule.completed_before(end)?;
        self.a_ready = Some(ready);
        self.b_ready = Some(b_ready);
        self.staged = Some(staged);
        Ok(())
    }
    fn authorization_tick<P: PinRetention>(
        &mut self,
        a: &mut Transport,
        journal: &mut DurableJournal<P>,
        lane: &mut BControlLane,
    ) -> Result<()> {
        if let Some(frozen) = lane.try_freeze_current(journal)? {
            if !frozen.matches(&self.round) {
                return Err(Error::Unavailable("B frozen authorization round"));
            }
            self.authorization = Some(frozen);
            self.phase = Phase::AuthCopies(0);
            Ok(())
        } else {
            lane.poll(a)
        }
    }
    fn verify_control(&self, bytes: &[u8], kind: Kind, role: Role) -> Result<SignedControl> {
        let kind = if bytes.get(8) == Some(&(Kind::Cancel as u8)) {
            Kind::Cancel
        } else {
            kind
        };
        let control = SignedControl::verify(
            bytes,
            &self.round.config,
            self.round.schedule.round(),
            kind,
            role,
        )?;
        if control.kind() == Kind::Cancel {
            if control.bytes()[88..120] != self.round.manifest().id() {
                return Err(Error::Invalid("B CANCEL manifest mismatch"));
            }
            return Err(Error::Unavailable("B received pre-cutoff CANCEL"));
        }
        Ok(control)
    }
    fn a(&self) -> Result<&SignedControl> {
        self.a_ready
            .as_ref()
            .ok_or(Error::Unavailable("B lacks A_READY"))
    }
    fn b(&self) -> Result<&SignedControl> {
        self.b_ready
            .as_ref()
            .ok_or(Error::Unavailable("B lacks B_READY"))
    }
    fn ack_refs(&self) -> Result<[&SignedControl; 3]> {
        Ok([
            self.acks[0]
                .as_ref()
                .ok_or(Error::Unavailable("B lacks P0 ACK"))?,
            self.acks[1]
                .as_ref()
                .ok_or(Error::Unavailable("B lacks P1 ACK"))?,
            self.acks[2]
                .as_ref()
                .ok_or(Error::Unavailable("B lacks P2 ACK"))?,
        ])
    }
    fn auth(&self) -> Result<crate::control::AuthorizationEvidence<'_>> {
        self.authorization
            .as_ref()
            .ok_or(Error::Unavailable("B no timely authorization"))?
            .evidence()
    }
}
