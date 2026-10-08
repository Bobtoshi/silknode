//! Version-one client owner. Real/cover choice never changes the fixed wire slot.
use silk_f04_node::{genesis::Genesis, node::Node};
use silk_f04_relay::{
    Error, Result,
    config::{Roster, SignedConfig},
    frame::{Frame, Payload, RoundContext, client_cell},
    manifest::SignedManifest,
    negotiation::SelectedCut,
    schedule::{QualifiedClockSample, Schedule},
    tls::{ClientProfile, RecordSize, Transport},
};
use silk_f04_wallet::journal::intents::SavedOfferV1;
use silk_sapling_f04::{
    Digest,
    codec::{ENVELOPE_BYTES, EnvelopeView},
};
use std::{cell::RefCell, rc::Rc, time::Instant};
use zeroize::Zeroizing;

mod enrollment;
pub use enrollment::{EnrollmentProgressV1, EnrollmentV1};
mod lifecycle;
pub use lifecycle::ProcessV1;
#[cfg(feature = "r2-functional-lab")]
pub mod im3_lab;
pub mod preparation;
#[cfg(feature = "r2-functional-lab")]
pub mod r2_lab;
pub mod session;

/// Immutable local authority retained through one attempt. No peer cut or
/// caller-supplied validity boolean can construct a locally accepted manifest.
#[derive(Clone)]
pub enum LocalViewV1 {
    /// Complete READY node; an Rc prevents in-process mutation during the round.
    Ready(Rc<Node>),
    /// Admitted genesis, admitting cut zero only; not a later-history shortcut.
    Genesis(Rc<Genesis>),
}
impl LocalViewV1 {
    fn check(
        &self,
        manifest: &SignedManifest,
        config: &SignedConfig,
        schedule: &Schedule,
    ) -> Result<()> {
        match self {
            Self::Ready(node) => manifest.check_local_cut(node),
            Self::Genesis(genesis) => SelectedCut::from_genesis(genesis, config, schedule.round())?
                .admit_signed(manifest.bytes(), config, schedule)
                .map(|_| ()),
        }
    }
}

/// Local result available only at the fixed +22 cleanup, never a network callback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutcomeV1 {
    /// Original round, never a newly scheduled retry.
    pub round: u64,
    /// Local write fact only, not B disclosure, delivery, inclusion or settlement.
    pub status: WriteStatusV1,
}
/// A completed TLS write still permits a later relay abort or ledger rejection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteStatusV1 {
    /// A complete real cell was written locally.
    RealWriteComplete,
    /// A complete genuine cover cell was written locally.
    CoverWriteComplete,
    /// No data-cell write was attempted. Durable wallet exposure stays unchanged.
    Silent,
    /// A selected cell might have escaped; no replacement, retry or recall follows.
    WriteUncertain,
}
enum Phase {
    Waiting,
    Reading,
    Selected(Frame, bool),
    Writing(bool),
    Finished(WriteStatusV1),
}
struct Round {
    schedule: Rc<Schedule>,
    link: Option<Rc<RefCell<Transport>>>,
    view: LocalViewV1,
    offer: Option<Zeroizing<[u8; ENVELOPE_BYTES]>>,
    phase: Phase,
}
impl Round {
    fn fail(&mut self) {
        self.offer = None;
        self.phase = Phase::Finished(match self.phase {
            Phase::Writing(_) => WriteStatusV1::WriteUncertain,
            Phase::Finished(status) => status,
            _ => WriteStatusV1::Silent,
        });
    }
    fn poll(&mut self, config: &SignedConfig, slot: u8, link: &mut Transport) -> Result<()> {
        self.schedule.clock_healthy()?;
        let now = Instant::now();
        match &self.phase {
            Phase::Waiting if now >= self.schedule.at(-8_000_000_000)? => {
                self.schedule.in_window(-8_000_000_000, 1_000_000_000)?;
                link.expect(RecordSize::Manifest, self.schedule.at(1_000_000_000)?)?;
                self.phase = Phase::Reading;
            }
            Phase::Reading => {
                if let Some(bytes) = link.read_step()? {
                    self.schedule.in_window(-8_000_000_000, 1_000_000_000)?;
                    let manifest = SignedManifest::verify(&bytes, config, self.schedule.round())?;
                    // Check M's OWN locally eligible cut before comparing the offer.
                    // A valid different M selects cover, not manifest invalidity.
                    self.view.check(&manifest, config, &self.schedule)?;
                    self.schedule.completed_before(1_000_000_000)?;
                    let context = RoundContext::new(config, &manifest)?;
                    let payload = select_payload(self.offer.take(), config.domain(), &context);
                    let real = payload.is_real();
                    let frame = client_cell(&context, &payload)?;
                    self.schedule.completed_before(1_000_000_000)?;
                    if link.has_extra_bytes()? {
                        return Err(Error::Unavailable("extra client manifest"));
                    }
                    self.phase = Phase::Selected(frame, real);
                }
            }
            Phase::Selected(_, _) => {
                if link.has_extra_bytes()? {
                    return Err(Error::Unavailable("extra client input"));
                }
                let start = 1_000_000_000 + i64::from(slot) * 250_000_000;
                if now >= self.schedule.at(start)? {
                    self.schedule.in_window(start, start + 250_000_000)?;
                    let Phase::Selected(frame, real) =
                        std::mem::replace(&mut self.phase, Phase::Writing(false))
                    else {
                        unreachable!()
                    };
                    self.phase = Phase::Writing(real);
                    link.queue(
                        RecordSize::Cell,
                        frame.bytes(),
                        self.schedule.at(start + 250_000_000)?,
                    )?;
                }
            }
            Phase::Writing(real) => {
                if link.write_step()? {
                    self.phase = Phase::Finished(if *real {
                        WriteStatusV1::RealWriteComplete
                    } else {
                        WriteStatusV1::CoverWriteComplete
                    });
                }
            }
            _ => (),
        }
        Ok(())
    }
}

fn select_payload(
    offer: Option<Zeroizing<[u8; ENVELOPE_BYTES]>>,
    domain: Digest,
    context: &RoundContext<'_>,
) -> Payload {
    offer
        .and_then(|bytes| {
            let view = EnvelopeView::decode(bytes.as_ref(), &domain).ok()?;
            Payload::real_view(&view, context).ok()
        })
        .unwrap_or_else(Payload::cover)
}

/// One joined fixed-A connection, at most two consecutive original rounds and
/// two fixed-time local outcomes.
///
/// It contains no wallet key or proving worker.
/// Constructed only after actual configured TCP/TLS/Join completion.
pub struct ClientV1 {
    config: Rc<SignedConfig>,
    slot: u8,
    link: Option<Rc<RefCell<Transport>>>,
    profile: ClientProfile,
    join: Zeroizing<[u8; 128]>,
    eligible: u64,
    last_closed: Option<Rc<Schedule>>,
    highest: Option<u64>,
    rounds: [Option<Round>; 2],
    outcomes: [Option<OutcomeV1>; 2],
}
impl ClientV1 {
    /// Consume one explicit already-exposed offer (or no ready offer) for exactly
    /// this round. Failed admission also consumes it; no automatic re-export.
    /// # Errors
    /// Refuses late/stale/foreign admission or unconsumed bounded outcome capacity.
    pub fn admit(
        &mut self,
        schedule: Schedule,
        view: LocalViewV1,
        offer: Option<SavedOfferV1>,
    ) -> Result<()> {
        self.admit_bytes(schedule, view, offer.map(SavedOfferV1::into_bytes))
    }
    fn admit_bytes(
        &mut self,
        schedule: Schedule,
        view: LocalViewV1,
        offer: Option<Zeroizing<[u8; ENVELOPE_BYTES]>>,
    ) -> Result<()> {
        let round = schedule.round();
        if !self.config.contains_round(round)
            || round < self.eligible
            || self.highest.is_some_and(|r| round <= r)
            || self
                .rounds
                .iter()
                .flatten()
                .any(|r| r.schedule.round().checked_add(1) != Some(round))
            || self.rounds.iter().flatten().count() + self.outcomes.iter().flatten().count() >= 2
        {
            return Err(Error::Unavailable("client stale/foreign/full round"));
        }
        self.highest = Some(round); // Even a late/failed attempt cannot rebase this round.
        schedule.clock_healthy()?;
        schedule.completed_before(-8_000_000_000)?;
        let free = self
            .rounds
            .iter_mut()
            .find(|r| r.is_none())
            .ok_or(Error::Unavailable("client two rounds"))?;
        *free = Some(Round {
            schedule: Rc::new(schedule),
            link: self.link.as_ref().map(Rc::clone),
            view,
            offer,
            phase: Phase::Waiting,
        });
        Ok(())
    }
    /// Perform bounded nonblocking progress with a fresh qualified clock sample.
    /// Poll regularly; this never sleeps, extends a slot or reconnects a failed link.
    /// # Errors
    /// Internal fixed-schedule arithmetic failure; ordinary round/clock/I/O failure
    /// becomes a local outcome only at +22, with the connection quarantined.
    pub fn poll(&mut self, sample: &QualifiedClockSample) -> Result<()> {
        // Cleanup precedes successor -8 (old +22) reads on the shared connection.
        for slot in &mut self.rounds {
            if slot.as_ref().is_some_and(|r| {
                r.schedule
                    .at(22_000_000_000)
                    .is_ok_and(|t| Instant::now() >= t)
            }) {
                let Some(mut round) = slot.take() else {
                    continue;
                };
                if !matches!(round.phase, Phase::Finished(_)) {
                    round.fail();
                    close_snapshot(&mut round.link, &mut self.link);
                }
                let Phase::Finished(status) = round.phase else {
                    return Err(Error::Unavailable("client cleanup state"));
                };
                let free = self
                    .outcomes
                    .iter_mut()
                    .find(|o| o.is_none())
                    .ok_or(Error::Unavailable("client outcome capacity"))?;
                *free = Some(OutcomeV1 {
                    round: round.schedule.round(),
                    status,
                });
                if self
                    .last_closed
                    .as_ref()
                    .is_none_or(|last| last.round() < round.schedule.round())
                {
                    self.last_closed = Some(Rc::clone(&round.schedule));
                }
            }
        }
        for round in self.rounds.iter_mut().flatten() {
            if matches!(round.phase, Phase::Finished(_)) {
                continue;
            }
            let result = round.schedule.observe_clock(sample).and_then(|()| {
                let link = round
                    .link
                    .as_ref()
                    .map(Rc::clone)
                    .ok_or(Error::Unavailable("client link unavailable"))?;
                round.poll(&self.config, self.slot, &mut link.borrow_mut())
            });
            if result.is_err() {
                round.fail();
                close_snapshot(&mut round.link, &mut self.link);
            }
        }
        Ok(())
    }
    /// Consume a fixed-time local result. Never grants inclusion/retry authority.
    pub fn take_outcome(&mut self) -> Option<OutcomeV1> {
        let index = self
            .outcomes
            .iter()
            .enumerate()
            .filter_map(|(i, o)| o.as_ref().map(|o| (i, o.round)))
            .min_by_key(|(_, round)| *round)?
            .0;
        self.outcomes[index].take()
    }
}

fn close_snapshot(
    snapshot: &mut Option<Rc<RefCell<Transport>>>,
    current: &mut Option<Rc<RefCell<Transport>>>,
) {
    if let Some(link) = snapshot.take() {
        let _ = link.borrow_mut().quarantine();
        if current.as_ref().is_some_and(|now| Rc::ptr_eq(now, &link)) {
            *current = None;
        }
    }
}

#[cfg(test)]
mod tests;
