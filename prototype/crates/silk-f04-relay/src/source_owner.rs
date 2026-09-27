//! Persistent A coordinator: one B connection, one session set and two original
//! native round leases. No phase creates a connection, key, or replacement proof.
use crate::{
    Error, Result,
    config::SignedConfig,
    driver::TwoRounds,
    epochs::{Configured, Epochs, Link, link},
    failure::{CommittedWrite, FailedControls},
    flow::{ReadSlot, WriteSlot},
    frame::HpkePrivate,
    input::{FailedSessions, InputCollector, ManifestDelivery, Sessions},
    journal::Decision,
    lifecycle::{PreparedConnections, SetupWindow},
    negotiation::{AProposal, SelectedCut},
    owner::{DurableJournal, Identity, ManifestRound, PinRetention},
    schedule::{QualifiedClockSample, Schedule},
    source::{SourceProgress, SourceRound},
    tls::{ReceiveProgress, RecordSize, Transport},
};
use std::{
    rc::Rc,
    time::{Duration, Instant},
};

#[allow(clippy::large_enum_variant)] // Exactly two bounded ~1KiB coordinator phases; data batches are boxed.
enum Phase {
    Proposal {
        cut: Option<SelectedCut<'static>>,
        proposal: Option<AProposal<'static>>,
        writer: WriteSlot,
        reader: ReadSlot,
        skipped: u8,
    },
    Delivery(ManifestDelivery),
    Input(InputCollector),
    Source(Box<SourceRound>),
    EarlyFailed {
        controls: FailedControls,
        ingress: Option<FailedSessions>,
    },
    Failed(FailedControls),
    Committed(CommittedWrite),
    Quiet,
}
enum Seal {
    Open,
    Committed,
    Written,
}
struct Round {
    phase: Option<Phase>,
    failed: bool,
    seal: Seal,
    handoff: bool,
    b: Link,
}
struct Epoch {
    config: Rc<SignedConfig>,
    identity: Identity,
    key: Rc<HpkePrivate>,
    sessions: Option<Sessions>,
    b: Link,
    repairs: Option<PreparedConnections>,
}
impl Configured for Epoch {
    fn config(&self) -> &SignedConfig {
        &self.config
    }
}

/// Source role over a retained established epoch.
///
/// Successive round admissions
/// use the same actual connections and pin-coupled journal; epoch promotion is
/// separately responsible for supplying a newly configured connection set.
pub struct SourceOwner<P: PinRetention> {
    epochs: Epochs<Epoch>,
    journal: DurableJournal<P>,
    closed: Option<(u64, bool, bool)>,
    // All remaining epoch resources drop before the actors' native guards.
    rounds: TwoRounds<Round>,
}
impl<P: PinRetention> SourceOwner<P> {
    /// Read actual retained ownership without changing any admission state.
    /// # Errors
    /// Refuses unreadable journal-lock metadata.
    #[cfg(feature = "functional-lab")]
    pub fn functional_snapshot(&self) -> Result<crate::lifecycle::FunctionalOwnerSnapshot> {
        Ok(self
            .rounds
            .functional_snapshot(Some(self.journal.functional_identity()?), |round| {
                [round.b.borrow().id(), 0, 0, 0]
            }))
    }
    /// Own an already admitted fixed epoch topology. This API alone does not
    /// attest its setup window, clock source, independent custody or native RSS.
    /// # Errors
    /// Refuses wrong role/configuration or unavailable established B connection.
    pub fn new(
        config: Rc<SignedConfig>,
        identity: Identity,
        key: Rc<HpkePrivate>,
        mut sessions: Sessions,
        mut b: Transport,
        journal: DurableJournal<P>,
    ) -> Result<Self> {
        identity.check(&config, crate::control::Role::A)?;
        journal.check_role(crate::control::Role::A)?;
        sessions.check_config(&config)?;
        b.check_endpoint(config.endpoints()[crate::control::Role::B as usize], true)?;
        let resources = crate::resources::RoleResources::adopt(crate::control::Role::A, &mut b)?;
        sessions.account(&resources)?;
        Ok(Self {
            rounds: TwoRounds::new(&config, journal.earliest_round(), resources),
            epochs: Epochs::new(Epoch {
                config,
                identity,
                key,
                sessions: Some(sessions),
                b: link(b),
                repairs: None,
            }),
            journal,
            closed: None,
        })
    }
    /// Admit the original current/successor schedule before any active work.
    /// The selected cut retains actual immutable READY-node/genesis authority.
    /// # Errors
    /// Refuses same/old rounds, wrong epoch, more than two slots or late native arming.
    pub fn admit(&mut self, schedule: Schedule, cut: SelectedCut<'static>) -> Result<()> {
        let epoch = self.epochs.for_round_mut(schedule.round())?;
        if epoch.sessions.is_none() {
            return Err(Error::Unavailable(
                "A sessions not available for next admission",
            ));
        }
        if let Some(prepared) = epoch
            .repairs
            .as_ref()
            .filter(|p| p.eligible_from() <= schedule.round())
        {
            prepared.repair_target(&epoch.config, &self.rounds.resources)?;
            if prepared.has_clients()
                && self.rounds.slots.iter().flatten().any(|s| {
                    s.lease.config.id() == epoch.config.id()
                        && matches!(
                            s.state.phase,
                            Some(
                                Phase::Proposal { .. }
                                    | Phase::Delivery(_)
                                    | Phase::Input(_)
                                    | Phase::EarlyFailed {
                                        ingress: Some(_),
                                        ..
                                    }
                            )
                        )
                })
            {
                return Err(Error::Unavailable(
                    "old A actor still owns client admission",
                ));
            }
            prepared.check_links(&[(crate::control::Role::B, &epoch.b.borrow())])?;
            prepared.check_sessions(
                epoch
                    .sessions
                    .as_ref()
                    .ok_or(Error::Unavailable("A sessions absent"))?,
            )?;
            let mut parts = epoch
                .repairs
                .take()
                .ok_or(Error::Unavailable("A repair pool absent"))?
                .repairs(schedule.round())?;
            epoch
                .sessions
                .as_mut()
                .ok_or(Error::Unavailable("A sessions absent"))?
                .replace(parts.sessions)?;
            if let Some(b) = parts.hops[crate::control::Role::B as usize].take() {
                epoch.b = link(b);
            }
        }
        self.rounds.admit(&epoch.config, Rc::new(schedule), || {
            Ok(Round {
                phase: Some(Phase::Proposal {
                    cut: Some(cut),
                    proposal: None,
                    writer: WriteSlot::default(),
                    reader: ReadSlot::default(),
                    skipped: 0,
                }),
                failed: false,
                seal: Seal::Open,
                handoff: false,
                b: Rc::clone(&epoch.b),
            })
        })
    }
    /// Shared process-wide resources for bounded listeners and future setup.
    #[must_use]
    pub fn resources(&self) -> crate::resources::RoleResources {
        self.rounds.resources.clone()
    }
    /// Reserve this actual round's single fixed maintenance window. Only missing
    /// or quarantined links are candidates; active actors retain their old links.
    /// # Errors
    /// Refuses unavailable session ownership, reused window or cross-epoch eligibility.
    pub fn maintenance_window(&self, round: u64) -> Result<SetupWindow> {
        let epoch = self.epochs.for_round(round)?;
        let sessions = epoch
            .sessions
            .as_ref()
            .ok_or(Error::Unavailable("A sessions currently owned by input"))?;
        let hops = if epoch.b.borrow().receive_progress() == ReceiveProgress::Failed {
            1 << crate::control::Role::B as u8
        } else {
            0
        };
        SetupWindow::maintenance(self.rounds.lease(round)?, hops, sessions.repairable_slots())
    }
    /// Verify a next-epoch proposal inside the original q-2 setup window.
    /// # Errors
    /// Refuses bad signatures/context, wrong timing, another proposal or missing lease.
    pub fn next_epoch_window(
        &self,
        round: u64,
        bytes: &[u8; crate::config::CONFIG_BYTES],
        roots: [crate::Digest; 2],
    ) -> Result<SetupWindow> {
        SetupWindow::epoch(self.rounds.lease(round)?, bytes, roots)
    }
    /// Install only a completed exact-window pool, keeping this sole journal and
    /// global two-round/high-water owner. Existing actors retain old connections.
    /// # Errors
    /// Refuses another signer/configuration, incomplete pool or excess epoch.
    pub fn install_next(
        &mut self,
        prepared: PreparedConnections,
        identity: Identity,
        key: Rc<HpkePrivate>,
    ) -> Result<()> {
        self.epochs.check_next(prepared.config())?;
        identity.check(prepared.config(), crate::control::Role::A)?;
        let (config, sessions, b) = prepared.source(&self.rounds.resources)?;
        self.epochs.install(Epoch {
            config,
            identity,
            key,
            sessions: Some(sessions),
            b: link(b),
            repairs: None,
        })
    }
    /// Hold completed repairs for their later wholly configured round. This does
    /// not change any active actor, TLS cursor or already selected write.
    /// # Errors
    /// Refuses another pool/configuration or non-maintenance provenance.
    pub fn stage_repairs(&mut self, prepared: PreparedConnections) -> Result<()> {
        let epoch = self.epochs.for_round_mut(prepared.eligible_from())?;
        prepared.repair_target(&epoch.config, &self.rounds.resources)?;
        if epoch.repairs.is_some() {
            return Err(Error::Unavailable("A repair pool already held"));
        }
        epoch.repairs = Some(prepared);
        Ok(())
    }
    /// Advance both retained rounds from an actually observed qualified sample.
    /// # Errors
    /// Fatal clock/resource/durability failures stop this owner without lease renewal.
    pub fn poll(&mut self, sample: &QualifiedClockSample) -> Result<Instant> {
        self.observe(|s| s.observe_clock(sample), |s| s.observe_clock(sample))?;
        self.advance(sample.utc_round())
    }
    /// Functional-only same-host observation; never upgrades clock qualification.
    /// # Errors
    /// Preserves all original phase/resource/refusal predicates.
    #[cfg(feature = "functional-lab")]
    pub fn poll_functional(&mut self) -> Result<Instant> {
        self.observe(
            Schedule::observe_functional_clock,
            SourceRound::observe_functional_clock,
        )?;
        let utc = crate::schedule::functional_utc()?.as_secs() / 30;
        self.advance(utc)
    }
    fn observe(
        &mut self,
        schedule: impl Fn(&Schedule) -> Result<()>,
        source: impl Fn(&mut SourceRound) -> Result<()>,
    ) -> Result<()> {
        for slot in self.rounds.slots.iter_mut().flatten() {
            if let Some(Phase::Source(round)) = &mut slot.state.phase {
                source(round)?;
            } else if matches!(slot.state.seal, Seal::Open) {
                schedule(&slot.schedule)?;
            }
        }
        Ok(())
    }
    fn advance(&mut self, utc: u64) -> Result<Instant> {
        let mut wake = Instant::now() + Duration::from_secs(1);
        for index in self.rounds.ordered() {
            let current = self.rounds.slots[index].as_ref();
            let predecessor_busy = self.rounds.slots.iter().flatten().any(|s| {
                current.is_some_and(|c| {
                    s.schedule.round() < c.schedule.round() && Rc::ptr_eq(&s.state.b, &c.state.b)
                }) && !s.state.handoff
            });
            let Some(slot) = &mut self.rounds.slots[index] else {
                continue;
            };
            slot.check()?;
            let epoch = self.epochs.for_round_mut(slot.schedule.round())?;
            if slot.cleanup_due()? {
                let slot = self.rounds.slots[index].take().expect("present round");
                let number = slot.schedule.round();
                let failed = slot.state.failed;
                let authorized = matches!(slot.state.seal, Seal::Written);
                slot.close(|state, schedule| {
                    drop(state);
                    self.journal.retire_live(&epoch.config, schedule)
                })?;
                self.closed = Some((number, authorized, failed));
                continue;
            }
            if predecessor_busy
                && matches!(slot.state.phase, Some(Phase::Proposal { .. }))
                && Instant::now() >= slot.schedule.at(-10_000_000_000)?
            {
                slot.schedule.completed_before(-9_000_000_000)?;
                wake = wake.min(Instant::now() + Duration::from_micros(500));
                continue;
            }
            let phase = slot
                .state
                .phase
                .take()
                .ok_or(Error::Unavailable("A owner phase absent"))?;
            let connection = Rc::clone(&slot.state.b);
            let mut b = connection
                .try_borrow_mut()
                .map_err(|_| Error::Unavailable("A stream already borrowed"))?;
            let (phase, at) = Self::tick(
                phase,
                &mut slot.state,
                &slot.schedule,
                &epoch.config,
                &epoch.identity,
                &epoch.key,
                &mut epoch.sessions,
                &mut b,
                &mut self.journal,
                utc,
            )?;
            slot.state.phase = Some(phase);
            wake = wake.min(at).min(slot.schedule.at(22_000_000_000)?);
        }
        self.epochs
            .retire(self.rounds.highest(), self.rounds.live_configs());
        Ok(wake)
    }
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn tick(
        phase: Phase,
        state: &mut Round,
        schedule: &Rc<Schedule>,
        config: &Rc<SignedConfig>,
        identity: &Identity,
        key: &Rc<HpkePrivate>,
        sessions: &mut Option<Sessions>,
        b: &mut Transport,
        journal: &mut DurableJournal<P>,
        utc: u64,
    ) -> Result<(Phase, Instant)> {
        let soon = Instant::now() + Duration::from_micros(500);
        match phase {
            Phase::Proposal {
                mut cut,
                mut proposal,
                mut writer,
                mut reader,
                mut skipped,
            } => {
                if Instant::now() < schedule.at(-10_000_000_000)? {
                    return Ok((
                        Phase::Proposal {
                            cut,
                            proposal,
                            writer,
                            reader,
                            skipped,
                        },
                        schedule.at(-10_000_000_000)?,
                    ));
                }
                let result = (|| -> Result<Option<Rc<ManifestRound>>> {
                    if proposal.is_none() {
                        match b.receive_progress() {
                            ReceiveProgress::Idle => (),
                            ReceiveProgress::WaitingZeroBytes => b.retire_expired_control()?,
                            _ => {
                                let _ = b.quarantine();
                                return Err(Error::Unavailable("A partial old control at handoff"));
                            }
                        }
                        proposal = Some(AProposal::begin(
                            cut.take().ok_or(Error::Unavailable("A cut absent"))?,
                            config,
                            schedule,
                            identity,
                            journal,
                            utc,
                        )?);
                    }
                    let p = proposal.as_ref().expect("begun proposal");
                    if !writer.poll(
                        b,
                        schedule,
                        (-10_000_000_000, -9_000_000_000),
                        RecordSize::Control,
                        p.control().bytes(),
                    )? {
                        return Ok(None);
                    }
                    if let Some(bytes) = reader.poll(
                        b,
                        schedule,
                        (-10_000_000_000, -8_000_000_000),
                        RecordSize::Control,
                    )? {
                        if crate::u64le(&bytes, 80)?.checked_add(1) == Some(schedule.round())
                            && skipped < 5
                        {
                            skipped += 1;
                            reader = ReadSlot::default();
                            return Ok(None);
                        }
                        let manifested = proposal
                            .take()
                            .expect("begun proposal")
                            .finish(&bytes, config, schedule, journal)?;
                        return ManifestRound::new(
                            Rc::clone(config),
                            manifested,
                            Rc::clone(schedule),
                        )
                        .map(Some);
                    }
                    Ok(None)
                })();
                match result {
                    Ok(Some(round)) => {
                        let set = sessions
                            .take()
                            .ok_or(Error::Unavailable("A source-session overlap"))?;
                        let mut delivery = ManifestDelivery::unclaimed(set, round);
                        if delivery.claim().is_err() {
                            return Self::early_failure(
                                delivery.into_failed(),
                                writer,
                                state,
                                config,
                                schedule,
                                identity,
                                b,
                                journal,
                            );
                        }
                        Ok((Phase::Delivery(delivery), schedule.at(-8_000_000_000)?))
                    }
                    Err(error) => {
                        // An absent or uncertain live reservation is STOP, not a
                        // license to synthesize a journal slot or signed CANCEL.
                        if journal.decision(schedule.round()).is_none() {
                            return Err(error);
                        }
                        let set = sessions
                            .take()
                            .ok_or(Error::Unavailable("A source-session overlap"))?;
                        Self::early_failure(
                            FailedSessions::unmanifested(set, Rc::clone(schedule)),
                            writer,
                            state,
                            config,
                            schedule,
                            identity,
                            b,
                            journal,
                        )
                    }
                    Ok(None) => Ok((
                        Phase::Proposal {
                            cut,
                            proposal,
                            writer,
                            reader,
                            skipped,
                        },
                        soon,
                    )),
                }
            }
            Phase::Delivery(mut delivery) => match delivery.poll() {
                Ok(false) => Ok((Phase::Delivery(delivery), soon)),
                Err(_) => Self::early_failure(
                    delivery.into_failed(),
                    WriteSlot::default(),
                    state,
                    config,
                    schedule,
                    identity,
                    b,
                    journal,
                ),
                Ok(true) => {
                    let mut input = delivery.into_input(Rc::clone(key));
                    if input.arm().is_err() {
                        return Self::early_failure(
                            input.into_failed(),
                            WriteSlot::default(),
                            state,
                            config,
                            schedule,
                            identity,
                            b,
                            journal,
                        );
                    }
                    Ok((Phase::Input(input), schedule.at(0)?))
                }
            },
            Phase::Input(mut input) => {
                if Instant::now() < schedule.at(0)? {
                    return Ok((Phase::Input(input), schedule.at(0)?));
                }
                if Instant::now() >= schedule.at(9_500_000_000)? {
                    match input.seal_batch() {
                        Err(_) => Self::early_failure(
                            input.into_failed(),
                            WriteSlot::default(),
                            state,
                            config,
                            schedule,
                            identity,
                            b,
                            journal,
                        ),
                        Ok(batch) => {
                            let (set, batch, bound) = input.into_source(batch);
                            match SourceRound::new(bound, batch, b) {
                                Ok(source) => {
                                    *sessions = Some(set);
                                    Ok((Phase::Source(Box::new(source)), soon))
                                }
                                Err(_) => Self::early_failure(
                                    FailedSessions::unmanifested(set, Rc::clone(schedule)),
                                    WriteSlot::default(),
                                    state,
                                    config,
                                    schedule,
                                    identity,
                                    b,
                                    journal,
                                ),
                            }
                        }
                    }
                } else {
                    match input.poll() {
                        Ok(()) | Err(Error::Unavailable("relay observation barrier closed")) => (),
                        Err(_) => {
                            return Self::early_failure(
                                input.into_failed(),
                                WriteSlot::default(),
                                state,
                                config,
                                schedule,
                                identity,
                                b,
                                journal,
                            );
                        }
                    }
                    Ok((Phase::Input(input), soon))
                }
            }
            Phase::Source(mut source) => match source.poll(b, identity, journal) {
                Ok(SourceProgress::AuthorizedWritten) => {
                    state.seal = Seal::Written;
                    state.handoff = true;
                    Ok((Phase::Source(source), schedule.at(22_000_000_000)?))
                }
                Ok(SourceProgress::Pending) => Ok((Phase::Source(source), soon)),
                Err(error) => {
                    if journal.decision(schedule.round()) == Some(Decision::SealedAuth) {
                        state.failed = true;
                        state.seal = Seal::Committed;
                        return Ok((
                            Phase::Committed(source.into_committed_failure(journal)?),
                            soon,
                        ));
                    }
                    if journal.decision(schedule.round()) != Some(Decision::Abort) {
                        return Err(error);
                    }
                    state.failed = true;
                    Ok((Phase::Failed(source.into_failure(identity, journal)?), soon))
                }
            },
            Phase::EarlyFailed {
                mut controls,
                mut ingress,
            } => {
                let outputs_done = controls.poll(&mut [b])?;
                if let Some(input) = &mut ingress
                    && input.poll()?
                {
                    *sessions = Some(ingress.take().expect("owned failed input").finish()?);
                }
                if outputs_done && ingress.is_none() {
                    state.handoff = true;
                    return Ok((Phase::Quiet, schedule.at(22_000_000_000)?));
                }
                let wake = ingress.as_ref().map_or_else(
                    || controls.next_wake(),
                    |input| Ok(controls.next_wake()?.min(input.next_wake()?)),
                )?;
                Ok((Phase::EarlyFailed { controls, ingress }, wake))
            }
            Phase::Failed(mut service) => {
                if service.poll(&mut [b])? {
                    state.handoff = true;
                    Ok((Phase::Quiet, schedule.at(22_000_000_000)?))
                } else {
                    let at = service.next_wake()?;
                    Ok((Phase::Failed(service), at))
                }
            }
            Phase::Committed(mut service) => {
                if service.poll(&mut [b])? {
                    state.handoff = true;
                    Ok((Phase::Quiet, schedule.at(22_000_000_000)?))
                } else {
                    Ok((Phase::Committed(service), soon))
                }
            }
            Phase::Quiet => Ok((Phase::Quiet, schedule.at(22_000_000_000)?)),
        }
    }
    #[allow(clippy::too_many_arguments)]
    fn early_failure(
        ingress: FailedSessions,
        proposal: WriteSlot,
        state: &mut Round,
        config: &Rc<SignedConfig>,
        schedule: &Rc<Schedule>,
        identity: &Identity,
        b: &Transport,
        journal: &mut DurableJournal<P>,
    ) -> Result<(Phase, Instant)> {
        // Checks current live identity, clock and pin continuity; then persists
        // ABORT before signing. No recovered or irrevocable state can enter here.
        let cancel = journal.cancel_live(config, schedule, identity)?;
        state.failed = true;
        Ok((
            Phase::EarlyFailed {
                controls: FailedControls::source_early(
                    Rc::clone(schedule),
                    cancel,
                    proposal,
                    b.id(),
                ),
                ingress: Some(ingress),
            },
            Instant::now() + Duration::from_micros(500),
        ))
    }
    /// Take one closed local round observation, not a settlement/privacy receipt.
    pub const fn take_closed(&mut self) -> Option<(u64, bool, bool)> {
        self.closed.take()
    }
}
