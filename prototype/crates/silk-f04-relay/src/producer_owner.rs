//! Persistent producer coordinator with one bounded B-stream receive owner and
//! at most two original native round leases. Released bytes have no ledger authority.
use crate::{
    Error, Result,
    config::SignedConfig,
    control::Role,
    drain::ProducerDrain,
    driver::TwoRounds,
    epochs::{Configured, Epochs, Link, link},
    failure::FailedControls,
    frame::Payload,
    handoff::v1::ReleasedBatchV1,
    lifecycle::{PreparedConnections, SetupWindow},
    negotiation::SelectedCut,
    owner::Identity,
    producer::ProducerRound,
    schedule::{QualifiedClockSample, Schedule},
    tls::Transport,
};
use std::{
    rc::Rc,
    time::{Duration, Instant},
};

#[allow(clippy::large_enum_variant)] // Exactly two bounded failure-control owners.
enum Phase {
    Producer(Box<ProducerRound<'static>>),
    Failed(FailedControls, ProducerDrain),
    Quiet,
}
struct Round {
    phase: Option<Phase>,
    delivered: bool,
    failed: bool,
    handoff: bool,
    b: Link,
}
struct Epoch {
    config: Rc<SignedConfig>,
    identity: Identity,
    b: Link,
    repairs: Option<PreparedConnections>,
}
impl Configured for Epoch {
    fn config(&self) -> &SignedConfig {
        &self.config
    }
}

/// One producer's exact established epoch stream, never a direct wallet fallback.
pub struct ProducerOwner {
    epochs: Epochs<Epoch>,
    role: Role,
    released: Option<ReleasedBatchV1>,
    closed: Option<(u64, bool, bool)>,
    rounds: TwoRounds<Round>,
}
impl ProducerOwner {
    /// Read actual retained ownership without changing any admission state.
    #[must_use]
    #[cfg(feature = "functional-lab")]
    pub fn functional_snapshot(&self) -> crate::lifecycle::FunctionalOwnerSnapshot {
        self.rounds
            .functional_snapshot(None, |round| [round.b.borrow().id(), 0, 0, 0])
    }
    /// Fresh-process admission from an actual qualified paired clock sample.
    /// The strict future floor cannot be supplied as an arbitrary caller counter.
    /// # Errors
    /// Refuses wrong role/endpoint, exhausted future round or failed connection.
    pub fn new(
        config: Rc<SignedConfig>,
        identity: Identity,
        role: Role,
        b: Transport,
        cold_start: &QualifiedClockSample,
    ) -> Result<Self> {
        Self::with_floor(config, identity, role, b, cold_start.restart_round()?)
    }
    /// Explicit functional-only cold-start sample, not an external clock claim.
    /// # Errors
    /// Applies the same strict future floor and actual connection checks.
    #[cfg(feature = "functional-lab")]
    pub fn new_functional(
        config: Rc<SignedConfig>,
        identity: Identity,
        role: Role,
        b: Transport,
    ) -> Result<Self> {
        let utc = crate::schedule::functional_utc()?.as_secs() / 30;
        Self::with_floor(config, identity, role, b, utc)
    }
    fn with_floor(
        config: Rc<SignedConfig>,
        identity: Identity,
        role: Role,
        mut b: Transport,
        utc: u64,
    ) -> Result<Self> {
        if !matches!(role, Role::P0 | Role::P1 | Role::P2) {
            return Err(Error::Invalid("producer owner role"));
        }
        identity.check(&config, role)?;
        b.check_endpoint(config.endpoints()[role as usize], false)?;
        let floor = utc
            .checked_add(3)
            .ok_or(Error::Unavailable("producer cold floor overflow"))?;
        let resources = crate::resources::RoleResources::adopt(role, &mut b)?;
        Ok(Self {
            rounds: TwoRounds::new(&config, floor, resources),
            epochs: Epochs::new(Epoch {
                config,
                identity,
                b: link(b),
                repairs: None,
            }),
            role,
            released: None,
            closed: None,
        })
    }
    /// Admit a genuinely selected local cut and its original unclaimed schedule.
    /// # Errors
    /// Refuses stale/late/foreign rounds, excess slots or unconsumed prior delivery.
    pub fn admit(&mut self, schedule: Schedule, cut: SelectedCut<'static>) -> Result<()> {
        if self.released.is_some() {
            return Err(Error::Unavailable("producer undrained released batch"));
        }
        let schedule = Rc::new(schedule);
        let epoch = self.epochs.for_round_mut(schedule.round())?;
        if let Some(prepared) = epoch
            .repairs
            .as_ref()
            .filter(|p| p.eligible_from() <= schedule.round())
        {
            prepared.repair_target(&epoch.config, &self.rounds.resources)?;
            prepared.check_links(&[(Role::B, &epoch.b.borrow())])?;
            let mut parts = epoch
                .repairs
                .take()
                .ok_or(Error::Unavailable("producer repair pool absent"))?
                .repairs(schedule.round())?;
            if let Some(b) = parts.hops[Role::B as usize].take() {
                epoch.b = link(b);
            }
        }
        self.rounds.admit(&epoch.config, Rc::clone(&schedule), || {
            Ok(Round {
                phase: Some(Phase::Producer(Box::new(ProducerRound::new(
                    Rc::clone(&epoch.config),
                    Rc::clone(&schedule),
                    self.role,
                    cut,
                    &epoch.b.borrow(),
                )?))),
                delivered: false,
                failed: false,
                handoff: false,
                b: Rc::clone(&epoch.b),
            })
        })
    }
    /// Shared process-wide socket and two-pending-setup ledger.
    #[must_use]
    pub fn resources(&self) -> crate::resources::RoleResources {
        self.rounds.resources.clone()
    }
    /// Claim the original fixed repair window for a quarantined B connection.
    /// # Errors
    /// Refuses missing/reused native lease or cross-epoch repair eligibility.
    pub fn maintenance_window(&self, round: u64) -> Result<SetupWindow> {
        let epoch = self.epochs.for_round(round)?;
        let hops = if epoch.b.borrow().receive_progress() == crate::tls::ReceiveProgress::Failed {
            1 << Role::B as u8
        } else {
            0
        };
        SetupWindow::maintenance(self.rounds.lease(round)?, hops, 0)
    }
    /// Admit the next configuration inside this original q-2 round's setup window.
    /// # Errors
    /// Refuses late/reused/wrong-window or invalid configuration admission.
    pub fn next_epoch_window(
        &self,
        round: u64,
        bytes: &[u8; crate::config::CONFIG_BYTES],
        roots: [crate::Digest; 2],
    ) -> Result<SetupWindow> {
        SetupWindow::epoch(self.rounds.lease(round)?, bytes, roots)
    }
    /// Install an actual completed next-epoch connection without resetting the
    /// global cold-start floor or two-round/high-water owner.
    /// # Errors
    /// Refuses foreign/incomplete setup, wrong signer or excess epoch capacity.
    pub fn install_next(
        &mut self,
        prepared: PreparedConnections,
        identity: Identity,
    ) -> Result<()> {
        self.epochs.check_next(prepared.config())?;
        identity.check(prepared.config(), self.role)?;
        let (config, b) = prepared.producer(&self.rounds.resources)?;
        self.epochs.install(Epoch {
            config,
            identity,
            b: link(b),
            repairs: None,
        })
    }
    /// Stage completed repairs for a later eligible admission, never an old key.
    /// # Errors
    /// Refuses another held pool or wrong/incomplete configuration provenance.
    pub fn stage_repairs(&mut self, prepared: PreparedConnections) -> Result<()> {
        let epoch = self.epochs.for_round_mut(prepared.eligible_from())?;
        prepared.repair_target(&epoch.config, &self.rounds.resources)?;
        if epoch.repairs.is_some() {
            return Err(Error::Unavailable("producer repair pool already held"));
        }
        epoch.repairs = Some(prepared);
        Ok(())
    }
    /// Observe qualified health only while each producer's release is still open.
    /// # Errors
    /// Fatal resource/clock failures stop without exposing a partial batch.
    pub fn poll(&mut self, sample: &QualifiedClockSample) -> Result<Instant> {
        for slot in self.rounds.slots.iter().flatten() {
            if !slot.state.delivered {
                slot.schedule.observe_clock(sample)?;
            }
        }
        self.advance()
    }
    /// Functional-only same-host observation, preserving all release predicates.
    /// # Errors
    /// Never upgrades the clock, custody or native-envelope qualification.
    #[cfg(feature = "functional-lab")]
    pub fn poll_functional(&mut self) -> Result<Instant> {
        for slot in self.rounds.slots.iter().flatten() {
            if !slot.state.delivered {
                slot.schedule.observe_functional_clock()?;
            }
        }
        self.advance()
    }
    #[allow(clippy::too_many_lines)] // Keep ordered two-actor polling and original cleanup together.
    fn advance(&mut self) -> Result<Instant> {
        let mut wake = Instant::now() + Duration::from_secs(1);
        for index in self.rounds.ordered() {
            let current = self.rounds.slots[index].as_ref();
            let predecessor_busy = self.rounds.slots.iter().flatten().any(|s| {
                current.is_some_and(|c| {
                    s.schedule.round() < c.schedule.round() && Rc::ptr_eq(&s.state.b, &c.state.b)
                }) && !s.state.handoff
            });
            let successor = self
                .rounds
                .slots
                .iter()
                .flatten()
                .find(|s| {
                    current.is_some_and(|c| {
                        c.schedule.round().checked_add(1) == Some(s.schedule.round())
                            && Rc::ptr_eq(&c.state.b, &s.state.b)
                    })
                })
                .map(|s| -> Result<_> {
                    Ok((
                        s.schedule.at(-9_000_000_000)?,
                        s.schedule.at(1_000_000_000)?,
                    ))
                })
                .transpose()?;
            let Some(slot) = &mut self.rounds.slots[index] else {
                continue;
            };
            slot.check()?;
            let epoch = self.epochs.for_round(slot.schedule.round())?;
            let connection = Rc::clone(&slot.state.b);
            let mut b = connection
                .try_borrow_mut()
                .map_err(|_| Error::Unavailable("producer stream borrowed"))?;
            if slot.cleanup_due()? {
                let slot = self.rounds.slots[index]
                    .take()
                    .expect("present producer round");
                self.closed = Some((
                    slot.schedule.round(),
                    slot.state.delivered,
                    slot.state.failed,
                ));
                slot.close(|state, _| {
                    drop(state);
                    Ok(())
                })?;
                continue;
            }
            // No impossible pre-manifest polling is charged to the original CPU lease.
            if Instant::now() < slot.schedule.at(-9_000_000_000)? {
                wake = wake.min(slot.schedule.at(-9_000_000_000)?);
                continue;
            }
            if predecessor_busy {
                wake = wake.min(Instant::now() + Duration::from_micros(500));
                continue;
            }
            let phase = slot
                .state
                .phase
                .take()
                .ok_or(Error::Unavailable("producer phase absent"))?;
            let soon = Instant::now() + Duration::from_micros(500);
            let (phase, at) = match phase {
                Phase::Producer(mut producer) => {
                    if producer.poll(&mut b, &epoch.identity).is_ok() {
                        if producer.has_released() && !slot.state.delivered {
                            if self.released.is_some() {
                                return Err(Error::Unavailable("producer released queue full"));
                            }
                            self.released = Some(producer.take_released_batch_v1()?);
                            slot.state.delivered = true;
                            slot.state.handoff = true;
                        }
                        let at = if slot.state.delivered {
                            slot.schedule.at(22_000_000_000)?
                        } else if producer.awaiting_readiness() {
                            slot.schedule.at(13_125_000_000)?.max(soon)
                        } else {
                            soon
                        };
                        (Phase::Producer(producer), at)
                    } else {
                        slot.state.failed = true;
                        let (outgoing, incoming) = producer.into_failure(&epoch.identity)?;
                        (Phase::Failed(outgoing, incoming), soon)
                    }
                }
                Phase::Failed(mut outgoing, mut incoming) => {
                    let sent = outgoing.poll(&mut [&mut b])?;
                    let drained = incoming.poll(&mut b, successor)?;
                    if sent && drained {
                        slot.state.handoff = true;
                        (Phase::Quiet, slot.schedule.at(22_000_000_000)?)
                    } else {
                        let at = outgoing.next_wake()?.min(incoming.next_wake()?);
                        (Phase::Failed(outgoing, incoming), at)
                    }
                }
                Phase::Quiet => (Phase::Quiet, slot.schedule.at(22_000_000_000)?),
            };
            slot.state.phase = Some(phase);
            wake = wake.min(at).min(slot.schedule.at(22_000_000_000)?);
        }
        self.epochs
            .retire(self.rounds.highest(), self.rounds.live_configs());
        Ok(wake)
    }
    /// Move only a completely opened authorized batch to ordinary node admission.
    /// The caller must independently apply graph/work/state verification.
    pub fn take_released(&mut self) -> Option<(u64, [Payload; 32])> {
        self.released
            .take()
            .map(|batch| (batch.delivery().round, batch.into_payloads()))
    }
    /// Consume actual complete release authority for a bounded modular handoff.
    /// No partial bytes, ledger acceptance, retry or mining authority is inferred.
    pub const fn take_released_batch_v1(&mut self) -> Option<ReleasedBatchV1> {
        self.released.take()
    }
    /// Take a closed local observation; never a finality or settlement claim.
    pub const fn take_closed(&mut self) -> Option<(u64, bool, bool)> {
        self.closed.take()
    }
}
