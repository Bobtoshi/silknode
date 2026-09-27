//! Persistent B coordinator. The A control lane owns adjacent-round reads;
//! old release slots precede successor negotiation and fanout on shared links.
use crate::{
    Error, Result,
    config::SignedConfig,
    control::SignedControl,
    drain::ExitInputDrain,
    driver::TwoRounds,
    epochs::{Configured, Epochs, Link, link},
    exit::{ExitProgress, ExitRound},
    failure::{CommittedWrite, FailedControls},
    flow::{ReadSlot, WriteSlot},
    frame::HpkePrivate,
    journal::Decision,
    lane::BControlLane,
    lifecycle::{PreparedConnections, SetupWindow},
    negotiation::{Manifested, SelectedCut},
    owner::{DurableJournal, Identity, LiveCancel, ManifestRound, PinRetention},
    schedule::{QualifiedClockSample, Schedule},
    tls::{RecordSize, Transport},
};
use silk_sapling_f04::parameters::SaplingVerificationKeys;
use std::{
    rc::Rc,
    time::{Duration, Instant},
};

#[allow(clippy::large_enum_variant)] // Two bounded control phases, not per-source queues.
enum Phase {
    Proposal {
        cut: Option<SelectedCut<'static>>,
        reader: ReadSlot,
        shared: bool,
    },
    Response {
        bound: Rc<ManifestRound>,
        response: SignedControl,
        writer: WriteSlot,
        shared: bool,
    },
    Delivery {
        bound: Rc<ManifestRound>,
        writer: WriteSlot,
        producer: usize,
        shared: bool,
    },
    Exit(Box<ExitRound>),
    Failed {
        controls: FailedControls,
        ingress: ExitInputDrain,
    },
    Committed(CommittedWrite),
    Quiet,
}
enum Delivery {
    Open,
    Unknown,
    Written,
}
struct Round {
    phase: Option<Phase>,
    delivery: Delivery,
    failed: bool,
    handoff: bool,
    a: Link,
    producers: [Link; 3],
}
struct Epoch {
    config: Rc<SignedConfig>,
    identity: Identity,
    key: Rc<HpkePrivate>,
    a: Link,
    producers: [Link; 3],
    repairs: Option<PreparedConnections>,
}
impl Configured for Epoch {
    fn config(&self) -> &SignedConfig {
        &self.config
    }
}

/// One established B epoch with a retained actual ingress and three producer
/// connections. The separate epoch pool owns setup-window admission/promotion.
pub struct ExitOwner<P: PinRetention> {
    epochs: Epochs<Epoch>,
    keys: Rc<SaplingVerificationKeys>,
    journal: DurableJournal<P>,
    lanes: [Option<BControlLane>; 2],
    closed: Option<(u64, bool, bool)>,
    // Native guards drop after all connection/epoch owners and their round state.
    rounds: TwoRounds<Round>,
}
impl<P: PinRetention> ExitOwner<P> {
    /// Read actual retained ownership without changing any admission state.
    /// # Errors
    /// Refuses unreadable journal-lock metadata.
    #[cfg(feature = "functional-lab")]
    pub fn functional_snapshot(&self) -> Result<crate::lifecycle::FunctionalOwnerSnapshot> {
        Ok(self
            .rounds
            .functional_snapshot(Some(self.journal.functional_identity()?), |round| {
                [
                    round.a.borrow().id(),
                    round.producers[0].borrow().id(),
                    round.producers[1].borrow().id(),
                    round.producers[2].borrow().id(),
                ]
            }))
    }
    /// Own only already established exact configured links and canonical keys.
    /// This does not attest independent custody, qualified UTC or epoch setup.
    /// # Errors
    /// Refuses local role/configuration or failed/foreign established endpoints.
    #[allow(clippy::too_many_arguments)] // Exact fixed-role resource bundle.
    pub fn new(
        config: Rc<SignedConfig>,
        identity: Identity,
        key: Rc<HpkePrivate>,
        keys: Rc<SaplingVerificationKeys>,
        mut a: Transport,
        mut producers: [Transport; 3],
        journal: DurableJournal<P>,
    ) -> Result<Self> {
        identity.check(&config, crate::control::Role::B)?;
        journal.check_role(crate::control::Role::B)?;
        a.check_endpoint(config.endpoints()[1], false)?;
        for (i, p) in producers.iter().enumerate() {
            p.check_endpoint(config.endpoints()[i + 2], true)?;
        }
        let resources = crate::resources::RoleResources::adopt(crate::control::Role::B, &mut a)?;
        for p in &mut producers {
            p.account(&resources)?;
        }
        Ok(Self {
            rounds: TwoRounds::new(&config, journal.earliest_round(), resources),
            epochs: Epochs::new(Epoch {
                config,
                identity,
                key,
                a: link(a),
                producers: producers.map(link),
                repairs: None,
            }),
            keys,
            journal,
            lanes: [None, None],
            closed: None,
        })
    }
    /// Admit one original current/successor schedule before its native deadline.
    /// # Errors
    /// Refuses stale/foreign/late admission or more than two retained rounds.
    pub fn admit(&mut self, schedule: Schedule, cut: SelectedCut<'static>) -> Result<()> {
        let epoch = self.epochs.for_round_mut(schedule.round())?;
        if let Some(prepared) = epoch
            .repairs
            .as_ref()
            .filter(|p| p.eligible_from() <= schedule.round())
        {
            prepared.repair_target(&epoch.config, &self.rounds.resources)?;
            prepared.check_links(&[
                (crate::control::Role::A, &epoch.a.borrow()),
                (crate::control::Role::P0, &epoch.producers[0].borrow()),
                (crate::control::Role::P1, &epoch.producers[1].borrow()),
                (crate::control::Role::P2, &epoch.producers[2].borrow()),
            ])?;
            let mut parts = epoch
                .repairs
                .take()
                .ok_or(Error::Unavailable("B repair pool absent"))?
                .repairs(schedule.round())?;
            if let Some(a) = parts.hops[crate::control::Role::A as usize].take() {
                epoch.a = link(a);
            }
            for (i, producer) in epoch.producers.iter_mut().enumerate() {
                if let Some(replacement) = parts.hops[i + 2].take() {
                    *producer = link(replacement);
                }
            }
        }
        let shared = self
            .lanes
            .iter()
            .flatten()
            .any(|l| l.is_predecessor(&epoch.config, schedule.round(), &epoch.a.borrow()))
            || self.rounds.slots.iter().flatten().any(|s| {
                s.schedule.round().checked_add(1) == Some(schedule.round())
                    && Rc::ptr_eq(&s.state.a, &epoch.a)
            });
        self.rounds.admit(&epoch.config, Rc::new(schedule), || {
            Ok(Round {
                phase: Some(Phase::Proposal {
                    cut: Some(cut),
                    reader: ReadSlot::default(),
                    shared,
                }),
                delivery: Delivery::Open,
                failed: false,
                handoff: false,
                a: Rc::clone(&epoch.a),
                producers: epoch.producers.each_ref().map(Rc::clone),
            })
        })
    }
    /// Shared role-wide socket/pending limits for both installed epochs.
    #[must_use]
    pub fn resources(&self) -> crate::resources::RoleResources {
        self.rounds.resources.clone()
    }
    /// Claim one original +24..+28 repair window for actually quarantined links.
    /// # Errors
    /// Refuses reused/missing lease or eligibility outside this configuration.
    pub fn maintenance_window(&self, round: u64) -> Result<SetupWindow> {
        let epoch = self.epochs.for_round(round)?;
        let mut hops =
            u8::from(epoch.a.borrow().receive_progress() == crate::tls::ReceiveProgress::Failed);
        for (i, p) in epoch.producers.iter().enumerate() {
            if p.borrow().receive_progress() == crate::tls::ReceiveProgress::Failed {
                hops |= 1 << (i + 2);
            }
        }
        SetupWindow::maintenance(self.rounds.lease(round)?, hops, 0)
    }
    /// Admit one next configuration within this actual q-2 round's setup window.
    /// # Errors
    /// Refuses wrong phase/mapping, reuse, bad signatures or missing original lease.
    pub fn next_epoch_window(
        &self,
        round: u64,
        bytes: &[u8; crate::config::CONFIG_BYTES],
        roots: [crate::Digest; 2],
    ) -> Result<SetupWindow> {
        SetupWindow::epoch(self.rounds.lease(round)?, bytes, roots)
    }
    /// Install a complete new-epoch pool without reopening the sole journal or
    /// replacing any old actor's actual connection snapshot.
    /// # Errors
    /// Refuses foreign/incomplete setup, wrong identity or more than two epochs.
    pub fn install_next(
        &mut self,
        prepared: PreparedConnections,
        identity: Identity,
        key: Rc<HpkePrivate>,
    ) -> Result<()> {
        self.epochs.check_next(prepared.config())?;
        identity.check(prepared.config(), crate::control::Role::B)?;
        let (config, a, producers) = prepared.exit(&self.rounds.resources)?;
        self.epochs.install(Epoch {
            config,
            identity,
            key,
            a: link(a),
            producers: producers.map(link),
            repairs: None,
        })
    }
    /// Stage completed repairs without changing either live round's snapshots.
    /// # Errors
    /// Refuses an occupied pool or a foreign/incomplete setup provenance.
    pub fn stage_repairs(&mut self, prepared: PreparedConnections) -> Result<()> {
        let epoch = self.epochs.for_round_mut(prepared.eligible_from())?;
        prepared.repair_target(&epoch.config, &self.rounds.resources)?;
        if epoch.repairs.is_some() {
            return Err(Error::Unavailable("B repair pool already held"));
        }
        epoch.repairs = Some(prepared);
        Ok(())
    }
    /// Advance from an actual qualified clock sample, preserving each old mapping.
    /// # Errors
    /// Fatal clock/resource/durability faults stop without rebasing or key retry.
    pub fn poll(&mut self, sample: &QualifiedClockSample) -> Result<Instant> {
        self.observe(|s| s.observe_clock(sample), |r| r.observe_clock(sample))?;
        self.advance(sample.utc_round())
    }
    /// Same-host functional observation, never a clock qualification.
    /// # Errors
    /// Preserves all actual phase, proof, journal and native-resource checks.
    #[cfg(feature = "functional-lab")]
    pub fn poll_functional(&mut self) -> Result<Instant> {
        self.observe(
            Schedule::observe_functional_clock,
            ExitRound::observe_functional_clock,
        )?;
        let utc = crate::schedule::functional_utc()?.as_secs() / 30;
        self.advance(utc)
    }
    fn observe(
        &mut self,
        schedule: impl Fn(&Schedule) -> Result<()>,
        exit: impl Fn(&mut ExitRound) -> Result<()>,
    ) -> Result<()> {
        for slot in self.rounds.slots.iter_mut().flatten() {
            if let Some(Phase::Exit(round)) = &mut slot.state.phase {
                exit(round)?;
            } else if matches!(slot.state.delivery, Delivery::Open) {
                schedule(&slot.schedule)?;
            }
        }
        Ok(())
    }
    #[allow(clippy::too_many_lines)] // Keep ordered two-actor polling and original cleanup together.
    fn advance(&mut self, utc: u64) -> Result<Instant> {
        let mut wake = Instant::now() + Duration::from_secs(1);
        for index in self.rounds.ordered() {
            let current = self.rounds.slots[index].as_ref();
            let predecessor_busy = self.rounds.slots.iter().flatten().any(|s| {
                current.is_some_and(|c| {
                    s.schedule.round() < c.schedule.round()
                        && s.state
                            .producers
                            .iter()
                            .zip(&c.state.producers)
                            .any(|(old, new)| Rc::ptr_eq(old, new))
                }) && !s.state.handoff
            });
            let Some(slot) = &mut self.rounds.slots[index] else {
                continue;
            };
            slot.check()?;
            let epoch = self.epochs.for_round(slot.schedule.round())?;
            let a_link = Rc::clone(&slot.state.a);
            let producer_links = slot.state.producers.each_ref().map(Rc::clone);
            let mut a = a_link
                .try_borrow_mut()
                .map_err(|_| Error::Unavailable("B A stream borrowed"))?;
            let mut p0 = producer_links[0]
                .try_borrow_mut()
                .map_err(|_| Error::Unavailable("B P0 stream borrowed"))?;
            let mut p1 = producer_links[1]
                .try_borrow_mut()
                .map_err(|_| Error::Unavailable("B P1 stream borrowed"))?;
            let mut p2 = producer_links[2]
                .try_borrow_mut()
                .map_err(|_| Error::Unavailable("B P2 stream borrowed"))?;
            let mut producers = [&mut *p0, &mut *p1, &mut *p2];
            // ExitRound's final erasure step is itself due at+22. Retain its
            // success/failure receipt while still dropping secrets before retirement.
            if slot.cleanup_due()? {
                if let Some(Phase::Exit(exit)) = &mut slot.state.phase
                    && exit.poll(
                        &mut a,
                        &mut producers,
                        &epoch.identity,
                        &mut self.journal,
                        self.lanes[index]
                            .as_mut()
                            .ok_or(Error::Unavailable("B lane absent"))?,
                    )? == ExitProgress::ReleasedWritten
                {
                    slot.state.delivery = Delivery::Written;
                }
                let slot = self.rounds.slots[index].take().expect("present B round");
                let observation = (
                    slot.schedule.round(),
                    matches!(slot.state.delivery, Delivery::Written),
                    slot.state.failed,
                );
                slot.close(|state, schedule| {
                    drop(state);
                    self.journal.retire_live(&epoch.config, schedule)
                })?;
                self.closed = Some(observation);
                continue;
            }
            if predecessor_busy
                && matches!(slot.state.phase, Some(Phase::Delivery { .. }))
                && Instant::now() >= slot.schedule.at(-8_000_000_000)?
            {
                slot.schedule.completed_before(-7_000_000_000)?;
                wake = wake.min(Instant::now() + Duration::from_micros(500));
                continue;
            }
            let phase = slot
                .state
                .phase
                .take()
                .ok_or(Error::Unavailable("B phase absent"))?;
            let (phase, at) = Self::tick(
                phase,
                &mut slot.state,
                &slot.schedule,
                &epoch.config,
                &epoch.identity,
                &epoch.key,
                &self.keys,
                &mut a,
                &mut producers,
                &mut self.journal,
                &mut self.lanes,
                index,
                utc,
            )?;
            slot.state.phase = Some(phase);
            wake = wake.min(at).min(slot.schedule.at(22_000_000_000)?);
        }
        self.epochs
            .retire(self.rounds.highest(), self.rounds.live_configs());
        for lane in &mut self.lanes {
            if lane
                .as_ref()
                .is_some_and(|l| !self.epochs.contains(l.config_id()))
            {
                *lane = None;
            }
        }
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
        keys: &Rc<SaplingVerificationKeys>,
        a: &mut Transport,
        producers: &mut [&mut Transport; 3],
        journal: &mut DurableJournal<P>,
        lanes: &mut [Option<BControlLane>; 2],
        index: usize,
        utc: u64,
    ) -> Result<(Phase, Instant)> {
        let soon = Instant::now() + Duration::from_micros(500);
        let (first, second) = lanes.split_at_mut(1);
        let (lane, previous_lane) = if index == 0 {
            (&mut first[0], &mut second[0])
        } else {
            (&mut second[0], &mut first[0])
        };
        match phase {
            Phase::Proposal {
                mut cut,
                mut reader,
                shared,
            } => {
                if Instant::now() < schedule.at(-10_000_000_000)? {
                    return Ok((
                        Phase::Proposal {
                            cut,
                            reader,
                            shared,
                        },
                        schedule.at(-10_000_000_000)?,
                    ));
                }
                let result = (|| -> Result<Option<(SignedControl, Rc<ManifestRound>)>> {
                    schedule.completed_before(-9_000_000_000)?;
                    let proposal = if shared {
                        let lane = previous_lane
                            .as_mut()
                            .ok_or(Error::Unavailable("B successor lane absent"))?;
                        lane.poll(a)?;
                        lane.take_next_proposal()?.map(|p| p.bytes().to_vec())
                    } else {
                        reader
                            .poll(
                                a,
                                schedule,
                                (-10_000_000_000, -9_000_000_000),
                                RecordSize::Control,
                            )?
                            .map(|p| p.to_vec())
                    };
                    if let Some(bytes) = proposal {
                        let (response, manifested) = Manifested::answer_selected(
                            cut.as_ref()
                                .ok_or(Error::Unavailable("B selected cut absent"))?,
                            &bytes,
                            config,
                            schedule,
                            identity,
                            journal,
                            utc,
                        )?;
                        let bound =
                            ManifestRound::new(Rc::clone(config), manifested, Rc::clone(schedule))?;
                        Ok(Some((response, bound)))
                    } else {
                        Ok(None)
                    }
                })();
                match result {
                    Ok(Some((response, bound))) => Ok((
                        Phase::Response {
                            bound,
                            response,
                            writer: WriteSlot::default(),
                            shared,
                        },
                        schedule.at(-9_000_000_000)?,
                    )),
                    Ok(None) => Ok((
                        Phase::Proposal {
                            cut,
                            reader,
                            shared,
                        },
                        soon,
                    )),
                    Err(_) => {
                        let cancel = cut
                            .take()
                            .ok_or(Error::Unavailable("B failed cut absent"))?
                            .abort_b(config, schedule, identity, journal, utc)?;
                        Self::early_failure(
                            cancel,
                            WriteSlot::default(),
                            0,
                            true,
                            state,
                            config,
                            schedule,
                            a,
                            producers,
                            lane,
                            journal,
                        )
                    }
                }
            }
            Phase::Response {
                bound,
                response,
                mut writer,
                shared,
            } => {
                let result = (|| -> Result<bool> {
                    if shared {
                        previous_lane
                            .as_ref()
                            .ok_or(Error::Unavailable("B successor lane absent"))?
                            .next_manifest_health()?;
                    }
                    writer.poll(
                        a,
                        schedule,
                        (-9_000_000_000, -8_000_000_000),
                        RecordSize::Control,
                        response.bytes(),
                    )
                })();
                match result {
                    Ok(true) => Ok((
                        Phase::Delivery {
                            bound,
                            writer: WriteSlot::default(),
                            producer: 0,
                            shared,
                        },
                        schedule.at(-8_000_000_000)?,
                    )),
                    Ok(false) => Ok((
                        Phase::Response {
                            bound,
                            response,
                            writer,
                            shared,
                        },
                        soon,
                    )),
                    Err(_) => {
                        let cancel = journal.cancel_live(config, schedule, identity)?;
                        Self::early_failure(
                            cancel, writer, 0, true, state, config, schedule, a, producers, lane,
                            journal,
                        )
                    }
                }
            }
            Phase::Delivery {
                bound,
                mut writer,
                mut producer,
                shared,
            } => {
                let result = (|| -> Result<Option<ExitRound>> {
                    if shared {
                        previous_lane
                            .as_ref()
                            .ok_or(Error::Unavailable("B successor lane absent"))?
                            .next_manifest_health()?;
                    }
                    if writer.poll(
                        producers[producer],
                        schedule,
                        (-8_000_000_000, -7_000_000_000),
                        RecordSize::Manifest,
                        bound.manifest().bytes(),
                    )? {
                        producer += 1;
                        writer = WriteSlot::default();
                        if producer == 3 {
                            *lane = Some(BControlLane::new(Rc::clone(&bound), a)?);
                            return ExitRound::new(
                                Rc::clone(&bound),
                                Rc::clone(key),
                                Rc::clone(keys),
                                a,
                                producers,
                            )
                            .map(Some);
                        }
                    }
                    Ok(None)
                })();
                match result {
                    Ok(Some(exit)) => {
                        Ok((Phase::Exit(Box::new(exit)), schedule.at(9_000_000_000)?))
                    }
                    Ok(None) => Ok((
                        Phase::Delivery {
                            bound,
                            writer,
                            producer,
                            shared,
                        },
                        soon,
                    )),
                    Err(_) => {
                        let cancel = journal.cancel_live(config, schedule, identity)?;
                        Self::early_failure(
                            cancel,
                            writer,
                            if producer < 3 { 1 + producer } else { 0 },
                            false,
                            state,
                            config,
                            schedule,
                            a,
                            producers,
                            lane,
                            journal,
                        )
                    }
                }
            }
            Phase::Exit(mut exit) => {
                if Instant::now() < schedule.at(9_000_000_000)? {
                    return Ok((Phase::Exit(exit), schedule.at(9_000_000_000)?));
                }
                let current_lane = lane
                    .as_mut()
                    .ok_or(Error::Unavailable("B current lane absent"))?;
                match exit.poll(a, producers, identity, journal, current_lane) {
                    Ok(ExitProgress::ReleasedWritten) => {
                        state.delivery = Delivery::Written;
                        Ok((Phase::Exit(exit), schedule.at(22_000_000_000)?))
                    }
                    Ok(ExitProgress::Pending) => {
                        if journal.decision(schedule.round()) == Some(Decision::Finalized) {
                            state.handoff = true;
                        }
                        Ok((Phase::Exit(exit), soon))
                    }
                    Err(error) => {
                        if matches!(
                            journal.decision(schedule.round()),
                            Some(Decision::DeliveryUnknown | Decision::Finalized)
                        ) {
                            state.failed = true;
                            state.delivery = if journal.decision(schedule.round())
                                == Some(Decision::Finalized)
                            {
                                Delivery::Written
                            } else {
                                Delivery::Unknown
                            };
                            return Ok((
                                Phase::Committed(exit.into_committed_failure(journal)?),
                                soon,
                            ));
                        }
                        if journal.decision(schedule.round()) != Some(Decision::Abort) {
                            return Err(error);
                        }
                        state.failed = true;
                        current_lane.abort_current(journal)?;
                        let ingress = exit.input_drain();
                        Ok((
                            Phase::Failed {
                                controls: exit.into_failure(identity, journal)?,
                                ingress,
                            },
                            soon,
                        ))
                    }
                }
            }
            Phase::Failed {
                mut controls,
                mut ingress,
            } => {
                let drained = ingress.poll(a, producers)?;
                if ingress.a_done() {
                    lane.as_mut()
                        .ok_or(Error::Unavailable("B failed lane absent"))?
                        .discard_poll(a)?;
                }
                let [p0, p1, p2] = producers;
                if controls.poll(&mut [a, p0, p1, p2])? && drained {
                    state.handoff = true;
                    Ok((Phase::Quiet, schedule.at(22_000_000_000)?))
                } else {
                    // Poll the shared late lane while it can own current/next
                    // records, without a pre-input/ACK idle busy loop.
                    let lane_wake = schedule.at(18_000_000_000)?.max(soon);
                    let at = controls
                        .next_wake()?
                        .min(ingress.next_wake()?)
                        .min(lane_wake);
                    Ok((Phase::Failed { controls, ingress }, at))
                }
            }
            Phase::Committed(mut service) => {
                let [p0, p1, p2] = producers;
                if service.poll(&mut [a, p0, p1, p2])? {
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
        cancel: LiveCancel,
        writer: WriteSlot,
        previous_lane: usize,
        is_response: bool,
        state: &mut Round,
        config: &Rc<SignedConfig>,
        schedule: &Rc<Schedule>,
        a: &Transport,
        producers: &[&mut Transport; 3],
        lane: &mut Option<BControlLane>,
        journal: &DurableJournal<P>,
    ) -> Result<(Phase, Instant)> {
        if lane
            .as_ref()
            .is_none_or(|old| old.round() != schedule.round())
        {
            *lane = Some(BControlLane::failed(
                Rc::clone(config),
                Rc::clone(schedule),
                a,
            )?);
        } else {
            lane.as_mut()
                .expect("current lane")
                .abort_current(journal)?;
        }
        let connections = [
            a.id(),
            producers[0].id(),
            producers[1].id(),
            producers[2].id(),
        ];
        state.failed = true;
        Ok((
            Phase::Failed {
                controls: FailedControls::exit_early(
                    Rc::clone(schedule),
                    cancel,
                    writer,
                    previous_lane,
                    is_response,
                    connections,
                ),
                ingress: ExitInputDrain::new(
                    Rc::clone(schedule),
                    connections,
                    0,
                    false,
                    [false; 3],
                ),
            },
            Instant::now() + Duration::from_micros(500),
        ))
    }
    /// One closed local delivery observation, never downstream settlement.
    pub const fn take_closed(&mut self) -> Option<(u64, bool, bool)> {
        self.closed.take()
    }
}
