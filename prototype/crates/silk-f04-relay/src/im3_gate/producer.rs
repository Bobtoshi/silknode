//! Actual original B-to-producer stream, complete-chain ACK, fixed authorization
//! and release reads, and all-or-nothing native opening into ordinary carriage.
use super::*;
use super::{cycle::*, stage::CompleteIm3StagedBatch};
use crate::{
    handoff::v1::ReleasedBatchV1,
    tls::{ReceiveProgress, WireObservation},
};
use ed25519_dalek::SigningKey;

/// A producer's one immutable IM3 cycle and original B link. No injected frames,
/// controls, key, replacement connection or raw-payload handoff API exists.
pub struct Im3ProducerOwner<'c, 'a, 's, 't, P: ClaimPinRetention> {
    c: &'c MiddleContext<'a>,
    schedule: &'t Im3Schedule,
    guard: &'t Im3Guard,
    signing: &'t SigningKey,
    role: Im3Role,
    slot: usize,
    link: Transport,
    _claim: ConsumedScope<'s, P>,
    state: u8,
    read: ReadState,
    write: WriteState,
    controls: Vec<Im3Control>,
    ready: Option<Im3ReadyChain>,
    frames: Vec<Im3StagedFrame>,
    batch: Option<CompleteIm3StagedBatch>,
    ack: Option<Im3Control>,
    chain: Option<Im3AckChain>,
    auth: Option<Im3Authorization>,
    release: Option<Im3Release>,
    released: Option<ReleasedBatchV1>,
    failed: bool,
    observation: Observation,
}
impl<'c, 'a, 's, 't, P: ClaimPinRetention> Im3ProducerOwner<'c, 'a, 's, 't, P> {
    /// Bind one original producer-server TLS link and consume its one-shot scope
    /// before T-5. Stream selection is deferred to retain TLS's 30-second ceiling.
    pub(crate) fn begin(
        c: &'c MiddleContext<'a>,
        store: &'s mut PreparedScopeStore<P>,
        schedule: &'t Im3Schedule,
        guard: &'t Im3Guard,
        mut link: Transport,
        role: Im3Role,
        signing: &'t SigningKey,
    ) -> Result<Self> {
        let (slot, claim_role) = match role {
            Im3Role::P0 => (0, ClaimRole::Im3Producer0),
            Im3Role::P1 => (1, ClaimRole::Im3Producer1),
            Im3Role::P2 => (2, ClaimRole::Im3Producer2),
            _ => {
                close(&mut link);
                return Err(Error::Invalid("IM3 producer role"));
            }
        };
        let check = (|| {
            guard.check(schedule)?;
            before(schedule.at(-5_000_000_000)?)?;
            if schedule.round() != c.r2.round.manifest.round()
                || store.binding() != c.profile.claim_binding(claim_role)
                || signing.verifying_key().to_bytes()
                    != c.r2.round.config.endpoints()[slot + 2].signing
                || link.receive_progress() != ReceiveProgress::Idle
                || link.selected_read().is_some()
            {
                return Err(Error::Invalid("IM3 producer original context"));
            }
            link.check_endpoint(c.r2.round.config.endpoints()[slot + 2], false)
        })();
        if let Err(e) = check {
            close(&mut link);
            return Err(e);
        }
        let message = domain_hash(
            "SilkNode-IM3-producer-claim",
            &[
                &c.q.id(),
                &c.r2.round.manifest.id(),
                &c.r2.round.manifest.round().to_le_bytes(),
                &[role as u8],
            ],
        );
        let claim = match store.consume(schedule.round(), c.r2.round.manifest.id(), message) {
            Ok(v) => v,
            Err(_) => {
                close(&mut link);
                return Err(Error::Unavailable("IM3 producer claim"));
            }
        };
        if let Err(e) = guard
            .check(schedule)
            .and_then(|()| before(schedule.at(-5_000_000_000)?))
        {
            close(&mut link);
            return Err(e);
        }
        Ok(Self {
            c,
            schedule,
            guard,
            signing,
            role,
            slot,
            link,
            _claim: claim,
            state: 0,
            read: ReadState::default(),
            write: WriteState::default(),
            controls: Vec::with_capacity(3),
            ready: None,
            frames: Vec::with_capacity(32),
            batch: None,
            ack: None,
            chain: None,
            auth: None,
            release: None,
            released: None,
            failed: false,
            observation: None,
        })
    }
    fn stop(&mut self) {
        self.failed = true;
        close(&mut self.link);
        self.frames.clear();
        self.controls.clear();
        self.ready = None;
        self.batch = None;
        self.chain = None;
        self.auth = None;
        self.release = None;
        self.released = None;
    }
    /// Advance at most one original socket step, or a fixed native phase gate.
    /// True is scheduled cleanup only, never a promise that node settlement ran.
    pub fn poll(&mut self) -> Result<bool> {
        let result = self.poll_inner();
        if result.is_err() {
            self.stop();
        }
        result
    }
    fn poll_inner(&mut self) -> Result<bool> {
        if self.failed {
            return Err(Error::Unavailable("IM3 producer closed"));
        }
        self.guard.check(self.schedule)?;
        match self.state {
            0 => {
                if let Some(bytes) = read(
                    &mut self.link,
                    &mut self.read,
                    RecordSize::Control,
                    self.schedule.at(23_000_000_000)?,
                    self.schedule.at(26_500_000_000)?,
                    0,
                    &mut self.observation,
                )? {
                    let control = Im3Control::verify(&bytes, self.c)?;
                    let expected =
                        [Im3Kind::AReady, Im3Kind::CReady, Im3Kind::BReady][self.controls.len()];
                    if control.kind() != expected {
                        return Err(Error::Invalid("IM3 producer readiness order"));
                    }
                    self.controls.push(control);
                    if self.controls.len() == 3 {
                        let [a, c, b] = take_controls(&mut self.controls)?;
                        self.ready = Some(Im3ReadyChain::verify(self.c, a, c, b)?);
                        self.read = ReadState::default();
                        self.state = 1;
                    }
                }
            }
            1 => {
                let slot = u32::try_from(self.frames.len())
                    .map_err(|_| Error::Invalid("IM3 producer stage ordinal"))?;
                if let Some(bytes) = read(
                    &mut self.link,
                    &mut self.read,
                    RecordSize::Cell,
                    self.schedule
                        .at(26_000_000_000 + 31_250_000 * i64::from(slot))?,
                    self.schedule.at(29_500_000_000)?,
                    0,
                    &mut self.observation,
                )? {
                    self.frames
                        .push(Im3StagedFrame::decode(&bytes, self.c, slot)?);
                    if self.frames.len() == 32 {
                        let frames = std::mem::take(&mut self.frames)
                            .try_into()
                            .map_err(|_| Error::Invalid("IM3 producer complete count"))?;
                        self.batch = Some(CompleteIm3StagedBatch::collect(
                            self.c,
                            frames,
                            self.ready
                                .take()
                                .ok_or(Error::Invalid("IM3 absent producer readiness"))?,
                        )?);
                        self.state = 2;
                        self.read = ReadState::default();
                    }
                }
            }
            2 => {
                quiet(&self.link)?;
                let (start, end) = self.schedule.window(Phase::Ack)?;
                if Instant::now() < start {
                    return Ok(false);
                }
                self.schedule.require(self.guard, Phase::Ack)?;
                if self.ack.is_none() {
                    let b = &self
                        .batch
                        .as_ref()
                        .ok_or(Error::Invalid("IM3 no producer batch"))?
                        .ready
                        .b;
                    self.ack = Some(control::sign(
                        self.c,
                        Im3Kind::Ack,
                        self.role,
                        [
                            b.field(116),
                            b.field(148),
                            b.field(180),
                            b.id(),
                            b.field(244),
                            [0; 32],
                            [0; 32],
                        ],
                        self.signing,
                    )?);
                }
                if write(
                    &mut self.link,
                    &mut self.write,
                    RecordSize::Control,
                    self.ack.as_ref().expect("set").bytes(),
                    start,
                    end,
                    0,
                    &mut self.observation,
                )? {
                    self.state = 3;
                    self.read = ReadState::default();
                }
            }
            3 => {
                let ordinal = self.controls.len();
                if let Some(bytes) = read(
                    &mut self.link,
                    &mut self.read,
                    RecordSize::Control,
                    self.schedule
                        .at(31_500_000_000 + 125_000_000 * i64::try_from(ordinal).expect("3"))?,
                    self.schedule.at(34_500_000_000)?,
                    0,
                    &mut self.observation,
                )? {
                    self.controls.push(Im3Control::verify(&bytes, self.c)?);
                    if self.controls.len() == 3 {
                        let ready = copy_ready(
                            self.c,
                            &self
                                .batch
                                .as_ref()
                                .ok_or(Error::Invalid("IM3 missing complete producer batch"))?
                                .ready,
                        )?;
                        let chain =
                            Im3AckChain::verify(self.c, ready, take_controls(&mut self.controls)?)?;
                        if chain.acks[self.slot].id()
                            != self
                                .ack
                                .as_ref()
                                .ok_or(Error::Invalid("IM3 absent original ACK"))?
                                .id()
                        {
                            return Err(Error::Invalid("IM3 original producer ACK changed"));
                        }
                        self.chain = Some(chain);
                        self.state = 4;
                        self.read = ReadState::default();
                    }
                }
            }
            4 => {
                if let Some(bytes) = read(
                    &mut self.link,
                    &mut self.read,
                    RecordSize::Control,
                    self.schedule.at(36_500_000_000)?,
                    self.schedule.at(39_500_000_000)?,
                    0,
                    &mut self.observation,
                )? {
                    let control = Im3Control::verify(&bytes, self.c)?;
                    self.auth = Some(Im3Authorization::verify(
                        self.c,
                        self.chain
                            .take()
                            .ok_or(Error::Invalid("IM3 missing producer ACK chain"))?,
                        control,
                    )?);
                    self.state = 5;
                    self.read = ReadState::default();
                }
            }
            5 => {
                if let Some(bytes) = read(
                    &mut self.link,
                    &mut self.read,
                    RecordSize::Control,
                    self.schedule.at(39_000_000_000)?,
                    self.schedule.at(42_000_000_000)?,
                    0,
                    &mut self.observation,
                )? {
                    let control = Im3Control::verify(&bytes, self.c)?;
                    self.release = Some(Im3Release::verify(
                        self.c,
                        self.auth.take().ok_or(Error::Invalid(
                            "IM3 missing original producer authorization",
                        ))?,
                        control,
                    )?);
                    self.state = 6;
                }
            }
            6 => {
                quiet(&self.link)?;
                if Instant::now() < self.schedule.at(42_000_000_000)? {
                    return Ok(false);
                }
                self.schedule.require(self.guard, Phase::ProducerOpen)?;
                let payloads = self
                    .batch
                    .take()
                    .ok_or(Error::Invalid("IM3 absent complete staged batch"))?
                    .open(
                        self.c,
                        self.release
                            .as_ref()
                            .ok_or(Error::Invalid("IM3 absent original release"))?,
                        self.schedule,
                        self.guard,
                    )?;
                let role = match self.role {
                    Im3Role::P0 => crate::control::Role::P0,
                    Im3Role::P1 => crate::control::Role::P1,
                    Im3Role::P2 => crate::control::Role::P2,
                    _ => return Err(Error::Invalid("IM3 receiving producer role")),
                };
                self.schedule.require(self.guard, Phase::ProducerOpen)?;
                self.released = Some(ReleasedBatchV1::from_completed(
                    self.c.r2.round.config,
                    self.c.r2.round.manifest,
                    role,
                    payloads,
                ));
                self.state = 7;
            }
            7 => {
                if Instant::now() >= self.schedule.at(44_000_000_000)? {
                    self.link.quarantine()?;
                    self.state = 8;
                    return Ok(true);
                }
                quiet(&self.link)?;
            }
            8 => return Ok(true),
            _ => return Err(Error::Unavailable("IM3 producer state")),
        }
        self.guard.check(self.schedule)?;
        Ok(false)
    }
    /// Consume the actual full producer release once, for the ordinary bounded
    /// ProducerInboxV1/node offer. Early/duplicate extraction fails this owner.
    pub fn take_released(&mut self) -> Result<ReleasedBatchV1> {
        let result = (|| {
            self.guard.check(self.schedule)?;
            if self.failed || self.state < 7 {
                return Err(Error::Unavailable("IM3 producer not fully opened"));
            }
            self.released
                .take()
                .ok_or(Error::Unavailable("IM3 producer release already taken"))
        })();
        if result.is_err() {
            self.stop();
        }
        result
    }
    /// Last original read/write syscall interval; no source labels or C mapping.
    pub fn take_wire_observation(&mut self) -> Option<(u8, WireObservation)> {
        self.observation.take()
    }
}
impl<P: ClaimPinRetention> Drop for Im3ProducerOwner<'_, '_, '_, '_, P> {
    fn drop(&mut self) {
        close(&mut self.link);
    }
}
