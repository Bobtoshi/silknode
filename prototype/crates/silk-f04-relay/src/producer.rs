//! Honest producer staging: actual complete ciphertext before ACK, whole-chain
//! release before plaintext. A signed ACK from another producer is still an assertion.
use crate::{
    Error, Result,
    config::SignedConfig,
    control::{
        Kind, Role, SignedControl, check_authorization, check_ready_pair, check_release,
        prepare_authorization,
    },
    flow::{ReadSlot, WriteSlot},
    frame::{Frame, Payload, RoundContext},
    handoff::v1::ReleasedBatchV1,
    manifest::SignedManifest,
    negotiation::SelectedCut,
    owner::Identity,
    schedule::Schedule,
    staging::CompleteStagedBatch,
    tls::{RecordSize, Transport},
};
use std::rc::Rc;

enum Phase {
    Manifest,
    AReady,
    BReady,
    Cells(usize),
    Ack,
    References(usize),
    Authorization,
    Release,
    Opened,
    Taken,
    Stopped,
}
/// One bounded producer batch. The parent owns at most two round slots and the
/// eight-socket/512KiB staged-queue/native128MiB admission, not this local object.
pub struct ProducerRound<'a> {
    config: Rc<SignedConfig>,
    schedule: Rc<Schedule>,
    role: Role,
    connection_id: u64,
    selected: Option<SelectedCut<'a>>,
    manifest: Option<SignedManifest>,
    a_ready: Option<SignedControl>,
    b_ready: Option<SignedControl>,
    own_ack: Option<SignedControl>,
    acks: [Option<SignedControl>; 3],
    authorization: Option<SignedControl>,
    frames: Vec<Frame>,
    staged: Option<CompleteStagedBatch>,
    released: Option<[Payload; 32]>,
    phase: Phase,
    failed_phase: Option<Phase>,
    reader: ReadSlot,
    // Advance on physical TLS completion before any fallible content validation.
    // Phase/reader state alone can lag a record when later batch checks fail.
    rx_next: u8,
    writer: WriteSlot,
}
impl<'a> ProducerRound<'a> {
    pub(crate) const fn has_released(&self) -> bool {
        matches!(self.phase, Phase::Opened)
    }
    pub(crate) const fn awaiting_readiness(&self) -> bool {
        matches!(self.phase, Phase::AReady)
    }
    /// Bind a locally verified cut and exact fixed producer TLS endpoint before M.
    /// # Errors
    /// Refuses wrong role/endpoint or late/clock-unhealthy setup.
    pub fn new(
        config: Rc<SignedConfig>,
        schedule: Rc<Schedule>,
        role: Role,
        selected: SelectedCut<'a>,
        transport: &Transport,
    ) -> Result<Self> {
        if !matches!(role, Role::P0 | Role::P1 | Role::P2) {
            return Err(Error::Invalid("producer role"));
        }
        transport.check_endpoint(config.endpoints()[role as usize], false)?;
        schedule.clock_healthy()?;
        schedule.completed_before(-8_000_000_000)?;
        Ok(Self {
            config,
            schedule,
            role,
            connection_id: transport.id(),
            selected: Some(selected),
            manifest: None,
            a_ready: None,
            b_ready: None,
            own_ack: None,
            acks: std::array::from_fn(|_| None),
            authorization: None,
            frames: Vec::with_capacity(32),
            staged: None,
            released: None,
            phase: Phase::Manifest,
            failed_phase: None,
            reader: ReadSlot::default(),
            rx_next: 0,
            writer: WriteSlot::default(),
        })
    }
    /// Advance only this producer's fixed stream, never exporting partial plaintext.
    /// # Errors
    /// Any malformed, late, missing, inconsistent or local-health failure stops the round.
    pub fn poll(&mut self, transport: &mut Transport, identity: &Identity) -> Result<()> {
        identity.check(&self.config, self.role)?;
        if transport.id() != self.connection_id {
            return Err(Error::Unavailable("producer connection replaced"));
        }
        if matches!(self.phase, Phase::Stopped) {
            return Err(Error::Unavailable("producer round stopped"));
        }
        let result = self.advance(transport, identity);
        if result.is_err() {
            self.failed_phase = Some(std::mem::replace(&mut self.phase, Phase::Stopped));
            self.frames.clear();
            self.staged = None;
            self.released = None;
        }
        result
    }
    /// Erase failed staged usability and retain only this producer's remaining
    /// fixed ACK-slot cancellation, never a new connection or release attempt.
    /// # Errors
    /// Refuses nonfailed/already-exposed state or unhealthy/expired timing.
    pub(crate) fn into_failure(
        self,
        identity: &Identity,
    ) -> Result<(crate::failure::FailedControls, crate::drain::ProducerDrain)> {
        let ack_finished = match self.failed_phase {
            Some(
                Phase::Manifest | Phase::AReady | Phase::BReady | Phase::Cells(_) | Phase::Ack,
            ) => false,
            Some(Phase::References(_) | Phase::Authorization | Phase::Release) => true,
            _ => return Err(Error::Unavailable("producer no reversible failed phase")),
        };
        let cancel = crate::owner::LiveCancel::producer(
            &self.config,
            &self.schedule,
            identity,
            self.role,
            self.manifest.as_ref(),
        )?;
        let incoming = crate::drain::ProducerDrain::new(
            Rc::clone(&self.config),
            Rc::clone(&self.schedule),
            self.connection_id,
            self.rx_next,
        );
        Ok((
            crate::failure::FailedControls::producer(
                Rc::clone(&self.schedule),
                cancel,
                self.writer,
                ack_finished,
                self.connection_id,
            ),
            incoming,
        ))
    }
    #[allow(clippy::too_many_lines)]
    fn advance(&mut self, transport: &mut Transport, identity: &Identity) -> Result<()> {
        if !matches!(self.phase, Phase::Opened | Phase::Taken) {
            self.schedule.clock_healthy()?;
        }
        match self.phase {
            Phase::Manifest => {
                if let Some(bytes) = self.reader.poll(
                    transport,
                    &self.schedule,
                    (-9_000_000_000, 1_000_000_000),
                    RecordSize::Manifest,
                )? {
                    self.rx_next = 1;
                    let manifest = self
                        .selected
                        .take()
                        .ok_or(Error::Unavailable("producer selected cut absent"))?
                        .admit_signed(&bytes, &self.config, &self.schedule)?;
                    self.schedule.completed_before(1_000_000_000)?;
                    self.manifest = Some(manifest);
                    self.reader = ReadSlot::default();
                    self.phase = Phase::AReady;
                }
            }
            Phase::AReady | Phase::BReady => {
                if let Some(bytes) = self.reader.poll(
                    transport,
                    &self.schedule,
                    (13_125_000_000, 15_000_000_000),
                    RecordSize::Control,
                )? {
                    self.rx_next = if matches!(self.phase, Phase::AReady) {
                        2
                    } else {
                        3
                    };
                    let (kind, role) = if matches!(self.phase, Phase::AReady) {
                        (Kind::AReady, Role::A)
                    } else {
                        (Kind::BReady, Role::B)
                    };
                    let control = self.verify(&bytes, kind, role)?;
                    if kind == Kind::AReady {
                        self.a_ready = Some(control);
                        self.phase = Phase::BReady;
                    } else {
                        let _ = check_ready_pair(self.manifest()?, self.a()?, &control)?;
                        self.b_ready = Some(control);
                        self.phase = Phase::Cells(0);
                    }
                    self.schedule.completed_before(15_000_000_000)?;
                    self.reader = ReadSlot::default();
                }
            }
            Phase::Cells(i) => {
                let earliest = 14_000_000_000
                    + i64::try_from(i).map_err(|_| Error::Invalid("producer cell slot"))?
                        * 31_250_000;
                if let Some(bytes) = self.reader.poll(
                    transport,
                    &self.schedule,
                    (earliest, 17_000_000_000),
                    RecordSize::Cell,
                )? {
                    self.rx_next = u8::try_from(i + 4)
                        .map_err(|_| Error::Invalid("producer physical cell cursor"))?;
                    let frame = Frame::decode(
                        &bytes,
                        &self.context()?,
                        3,
                        u32::try_from(i).map_err(|_| Error::Invalid("producer cell index"))?,
                    )?;
                    self.frames.push(frame);
                    self.reader = ReadSlot::default();
                    if i == 31 {
                        let frames = std::mem::take(&mut self.frames)
                            .try_into()
                            .map_err(|_| Error::Unavailable("producer incomplete batch"))?;
                        let pair = check_ready_pair(self.manifest()?, self.a()?, self.b()?)?;
                        let batch = CompleteStagedBatch::collect(&self.context()?, frames, &pair)?;
                        let mut body: [u8; 448] = self.b()?.bytes()[..448]
                            .try_into()
                            .map_err(|_| Error::Invalid("producer ACK body"))?;
                        body[216..248].copy_from_slice(&self.b()?.id());
                        let ack = identity.control(
                            &self.config,
                            self.schedule.round(),
                            Kind::Ack,
                            &body,
                        )?;
                        self.schedule.completed_before(17_000_000_000)?;
                        self.staged = Some(batch);
                        self.own_ack = Some(ack);
                        self.phase = Phase::Ack;
                    } else {
                        self.phase = Phase::Cells(i + 1);
                    }
                }
            }
            Phase::Ack => {
                if self.writer.poll(
                    transport,
                    &self.schedule,
                    (17_000_000_000, 18_000_000_000),
                    RecordSize::Control,
                    self.own_ack
                        .as_ref()
                        .ok_or(Error::Unavailable("producer ACK absent"))?
                        .bytes(),
                )? {
                    self.writer = WriteSlot::default();
                    self.phase = Phase::References(0);
                }
            }
            Phase::References(i) => {
                let earliest = 17_500_000_000
                    + i64::try_from(i).map_err(|_| Error::Invalid("producer ACK slot"))?
                        * 125_000_000;
                if let Some(bytes) = self.reader.poll(
                    transport,
                    &self.schedule,
                    (earliest, 20_000_000_000),
                    RecordSize::Control,
                )? {
                    self.rx_next = u8::try_from(i + 36)
                        .map_err(|_| Error::Invalid("producer physical control cursor"))?;
                    let ack = self.verify(&bytes, Kind::Ack, [Role::P0, Role::P1, Role::P2][i])?;
                    if ack.role() == self.role
                        && Some(ack.id()) != self.own_ack.as_ref().map(SignedControl::id)
                    {
                        return Err(Error::Invalid("producer own ACK substituted"));
                    }
                    self.acks[i] = Some(ack);
                    self.reader = ReadSlot::default();
                    if i == 2 {
                        let _ = prepare_authorization(
                            self.manifest()?,
                            self.a()?,
                            self.b()?,
                            self.ack_refs()?,
                        )?;
                        self.schedule.completed_before(20_000_000_000)?;
                        self.phase = Phase::Authorization;
                    } else {
                        self.phase = Phase::References(i + 1);
                    }
                }
            }
            Phase::Authorization => {
                if let Some(bytes) = self.reader.poll(
                    transport,
                    &self.schedule,
                    (19_000_000_000, 21_000_000_000),
                    RecordSize::Control,
                )? {
                    self.rx_next = 39;
                    let auth = self.verify(&bytes, Kind::Authorize, Role::A)?;
                    let _ = check_authorization(
                        self.manifest()?,
                        self.a()?,
                        self.b()?,
                        self.ack_refs()?,
                        &auth,
                    )?;
                    self.schedule.completed_before(21_000_000_000)?;
                    self.authorization = Some(auth);
                    self.reader = ReadSlot::default();
                    self.phase = Phase::Release;
                }
            }
            Phase::Release => {
                if let Some(bytes) = self.reader.poll(
                    transport,
                    &self.schedule,
                    (19_125_000_000, 21_000_000_000),
                    RecordSize::Control,
                )? {
                    self.rx_next = 40;
                    let release = self.verify(&bytes, Kind::Release, Role::B)?;
                    let auth = check_authorization(
                        self.manifest()?,
                        self.a()?,
                        self.b()?,
                        self.ack_refs()?,
                        self.authorization
                            .as_ref()
                            .ok_or(Error::Unavailable("producer auth absent"))?,
                    )?;
                    let evidence = check_release(&auth, &release)?;
                    let staged = self
                        .staged
                        .take()
                        .ok_or(Error::Unavailable("producer complete staged batch absent"))?;
                    let payloads = staged.open(&self.context()?, &evidence)?;
                    self.schedule.completed_before(21_000_000_000)?;
                    self.released = Some(payloads);
                    self.phase = Phase::Opened;
                }
            }
            Phase::Opened | Phase::Taken => (),
            Phase::Stopped => return Err(Error::Unavailable("producer round stopped")),
        }
        Ok(())
    }
    /// Consume only an entirely opened authorized batch, once. This provides no
    /// graph/work/state authority; offers still require ordinary node admission.
    /// # Errors
    /// Refuses incomplete, aborted or already consumed release.
    pub fn take_released(&mut self) -> Result<[Payload; 32]> {
        Ok(self.take_released_batch_v1()?.into_payloads())
    }
    /// Consume the whole release with original context for the bounded local
    /// handoff. Never available from staged, cancelled or partial plaintext.
    /// # Errors
    /// Refuses an absent manifest/release or a previously consumed batch.
    pub fn take_released_batch_v1(&mut self) -> Result<ReleasedBatchV1> {
        self.manifest()?;
        let batch = self
            .released
            .take()
            .ok_or(Error::Unavailable("no complete producer release"))?;
        self.phase = Phase::Taken;
        Ok(ReleasedBatchV1::from_completed(
            &self.config,
            self.manifest()?,
            self.role,
            batch,
        ))
    }
    fn verify(&self, bytes: &[u8], kind: Kind, role: Role) -> Result<SignedControl> {
        let kind = if bytes.get(8) == Some(&(Kind::Cancel as u8)) {
            Kind::Cancel
        } else {
            kind
        };
        let signer = if kind == Kind::Cancel { Role::B } else { role };
        let control =
            SignedControl::verify(bytes, &self.config, self.schedule.round(), kind, signer)?;
        if control.kind() == Kind::Cancel {
            if control.bytes()[88..120] != self.manifest()?.id() {
                return Err(Error::Invalid("producer CANCEL manifest mismatch"));
            }
            return Err(Error::Unavailable("producer received CANCEL"));
        }
        Ok(control)
    }
    fn manifest(&self) -> Result<&SignedManifest> {
        self.manifest
            .as_ref()
            .ok_or(Error::Unavailable("producer manifest absent"))
    }
    fn context(&self) -> Result<RoundContext<'_>> {
        RoundContext::new(&self.config, self.manifest()?)
    }
    fn a(&self) -> Result<&SignedControl> {
        self.a_ready
            .as_ref()
            .ok_or(Error::Unavailable("producer A_READY absent"))
    }
    fn b(&self) -> Result<&SignedControl> {
        self.b_ready
            .as_ref()
            .ok_or(Error::Unavailable("producer B_READY absent"))
    }
    fn ack_refs(&self) -> Result<[&SignedControl; 3]> {
        Ok([
            self.acks[0]
                .as_ref()
                .ok_or(Error::Unavailable("producer P0 ACK absent"))?,
            self.acks[1]
                .as_ref()
                .ok_or(Error::Unavailable("producer P1 ACK absent"))?,
            self.acks[2]
                .as_ref()
                .ok_or(Error::Unavailable("producer P2 ACK absent"))?,
        ])
    }
}
