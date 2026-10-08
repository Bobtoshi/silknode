//! B's original A/three-producer streams and one-shot durable release cycle.
use super::cycle::*;
use super::*;
use crate::tls::{ReceiveProgress, WireObservation};
use ed25519_dalek::SigningKey;

/// Reserve B's original A-server and three producer-client links before T-5.
/// The release decision store is reserved, not consumed with fabricated input.
pub struct ExitControlReservation<'c, 'a, 'd, 't, R: ClaimPinRetention> {
    c: &'c MiddleContext<'a>,
    schedule: &'t Im3Schedule,
    guard: &'t Im3Guard,
    signing: &'t SigningKey,
    store: Option<&'d mut PreparedScopeStore<R>>,
    links: Option<[Transport; 4]>,
}
impl<'c, 'a, 'd, 't, R: ClaimPinRetention> ExitControlReservation<'c, 'a, 'd, 't, R> {
    /// Lane0 is the original A control link; lanes1..3 are the original P0..P2
    /// links. No later replacement connection or decoded-control injection.
    pub(crate) fn begin(
        c: &'c MiddleContext<'a>,
        store: &'d mut PreparedScopeStore<R>,
        schedule: &'t Im3Schedule,
        guard: &'t Im3Guard,
        mut links: [Transport; 4],
        signing: &'t SigningKey,
    ) -> Result<Self> {
        let check = (|| {
            guard.check(schedule)?;
            before(schedule.at(-5_000_000_000)?)?;
            if schedule.round() != c.r2.round.manifest.round()
                || store.binding() != c.profile.claim_binding(ClaimRole::Im3Release)
                || signing.verifying_key().to_bytes() != c.r2.round.config.endpoints()[1].signing
            {
                return Err(Error::Invalid("IM3 B control reservation"));
            }
            for (i, link) in links.iter().enumerate() {
                if link.receive_progress() != ReceiveProgress::Idle
                    || link.selected_read().is_some()
                {
                    return Err(Error::Invalid("IM3 B original control already selected"));
                }
                link.check_endpoint(
                    c.r2.round.config.endpoints()[if i == 0 { 1 } else { i + 1 }],
                    i != 0,
                )?;
            }
            Ok(())
        })();
        if let Err(e) = check {
            for link in &mut links {
                close(link);
            }
            return Err(e);
        }
        Ok(Self {
            c,
            schedule,
            guard,
            signing,
            store: Some(store),
            links: Some(links),
        })
    }
    /// Bind only the actual complete staged exit, under its unchanged original
    /// lease. All ACK/AUTH receive deadlines are armed before earliest input.
    pub fn bind<'s, P: ClaimPinRetention>(
        mut self,
        stage: StagedIm3Exit<'s, 't, P>,
    ) -> Result<ReleasingExitOwner<'c, 'a, 's, 'd, 't, P, R>> {
        self.schedule.require(self.guard, Phase::BGate)?;
        if !std::ptr::eq(self.schedule, stage.exit.schedule)
            || !std::ptr::eq(self.guard, stage.exit.guard)
        {
            return Err(Error::Invalid("IM3 B staged lease changed"));
        }
        stage.integrity(self.c)?;
        let links = self
            .links
            .as_mut()
            .ok_or(Error::Unavailable("IM3 B original controls absent"))?;
        for (i, link) in links.iter_mut().enumerate() {
            if link.has_extra_bytes()? {
                return Err(Error::Invalid("IM3 premature B control input"));
            }
            before(self.schedule.at(if i == 0 {
                34_000_000_000
            } else {
                29_000_000_000
            })?)?;
            link.expect(
                RecordSize::Control,
                self.schedule.at(if i == 0 {
                    37_000_000_000
                } else {
                    32_000_000_000
                })?,
            )?;
        }
        self.schedule.require(self.guard, Phase::BGate)?;
        Ok(ReleasingExitOwner {
            c: self.c,
            schedule: self.schedule,
            guard: self.guard,
            signing: self.signing,
            store: self.store.take(),
            fence: None,
            links: self
                .links
                .take()
                .ok_or(Error::Unavailable("IM3 original B links absent"))?,
            stage: Some(stage),
            state: 0,
            index: 0,
            cursor: 0,
            read: std::array::from_fn(|_| ReadState {
                armed: true,
                selected_any: true,
            }),
            write: WriteState::default(),
            acks: std::array::from_fn(|_| None),
            chain: None,
            auth: None,
            release: None,
            release_id: None,
            failed: false,
            observation: None,
        })
    }
}
impl<R: ClaimPinRetention> Drop for ExitControlReservation<'_, '_, '_, '_, R> {
    fn drop(&mut self) {
        if let Some(links) = &mut self.links {
            for link in links {
                close(link);
            }
        }
    }
}

/// Non-cloneable receipt for actual B release train and T+44 cleanup. It does
/// not assert producer delivery, node settlement or privacy.
pub struct CompletedExit {
    context: [Digest; 4],
    round: u64,
    pub(super) release_id: Digest,
}
impl CompletedExit {
    pub(super) fn matches(&self, c: &MiddleContext<'_>) -> bool {
        self.context
            == [
                c.r2.round.config.id(),
                c.profile.id(),
                c.q.id(),
                c.r2.round.manifest.id(),
            ]
            && self.round == c.r2.round.manifest.round()
    }
}

/// Actual full B release owner. All producer bytes/ACKs/A authorization use
/// original reserved TLS; partial delivery is failure, never rollback or retry.
pub struct ReleasingExitOwner<'c, 'a, 's, 'd, 't, P: ClaimPinRetention, R: ClaimPinRetention> {
    c: &'c MiddleContext<'a>,
    schedule: &'t Im3Schedule,
    guard: &'t Im3Guard,
    signing: &'t SigningKey,
    store: Option<&'d mut PreparedScopeStore<R>>,
    fence: Option<ConsumedScope<'d, R>>,
    links: [Transport; 4],
    stage: Option<StagedIm3Exit<'s, 't, P>>,
    state: u8,
    index: usize,
    cursor: usize,
    read: [ReadState; 4],
    write: WriteState,
    acks: [Option<Im3Control>; 3],
    chain: Option<Im3AckChain>,
    auth: Option<Im3Authorization>,
    release: Option<Im3Release>,
    release_id: Option<Digest>,
    failed: bool,
    observation: Observation,
}
impl<P: ClaimPinRetention, R: ClaimPinRetention> ReleasingExitOwner<'_, '_, '_, '_, '_, P, R> {
    // Test-only complete A/B/producer signed controls after B's original
    // release train was sent, before its +44 cleanup clears the chain.
    #[cfg(test)]
    pub(super) fn fixture_complete_controls(&self) -> Option<Vec<u8>> {
        if self.failed || self.state != 9 {
            return None;
        }
        let release = self.release.as_ref()?;
        let mut bytes = Vec::with_capacity(8 * 512);
        for control in release.authorization.chain.ready.controls() {
            bytes.extend_from_slice(control);
        }
        for control in release.authorization.chain.acknowledgements() {
            bytes.extend_from_slice(control);
        }
        bytes.extend_from_slice(release.authorization.control());
        bytes.extend_from_slice(release.control());
        Some(bytes)
    }
    /// Advance one original socket step or the original native release fence.
    /// True means cleanup completed, not node settlement or privacy acceptance.
    pub fn poll(&mut self) -> Result<bool> {
        let result = self.poll_inner();
        if result.is_err() {
            self.failed = true;
            for link in &mut self.links {
                close(link);
            }
            self.stage = None;
            self.release = None;
            self.release_id = None;
            self.auth = None;
            self.chain = None;
            self.acks = std::array::from_fn(|_| None);
        }
        result
    }
    fn poll_inner(&mut self) -> Result<bool> {
        if self.failed {
            return Err(Error::Unavailable("IM3 B release owner closed"));
        }
        self.guard.check(self.schedule)?;
        if self.state < 10 && Instant::now() < self.schedule.at(44_000_000_000)? {
            quiet(
                self.stage
                    .as_ref()
                    .ok_or(Error::Unavailable("IM3 B original held exit absent"))?
                    .exit
                    .input
                    .as_deref()
                    .ok_or(Error::Unavailable("IM3 B held original C link absent"))?,
            )?;
        }
        match self.state {
            0 => {
                let (start, end) = self.schedule.window(Phase::BReady)?;
                let lane = self.index % 4;
                let ordinal = self.index / 4;
                let stage = self
                    .stage
                    .as_ref()
                    .ok_or(Error::Invalid("IM3 absent B stage"))?;
                if write(
                    &mut self.links[lane],
                    &mut self.write,
                    RecordSize::Control,
                    stage.ready.controls()[ordinal],
                    start,
                    end,
                    lane as u8,
                    &mut self.observation,
                )? {
                    self.index += 1;
                    if self.index == 12 {
                        self.state = 1;
                        self.index = 0;
                    }
                }
            }
            1 => {
                let ordinal = self.index / 3;
                let lane = 1 + self.index % 3;
                let start = self
                    .schedule
                    .at(27_000_000_000 + 31_250_000 * i64::try_from(ordinal).expect("32"))?;
                let end = start + std::time::Duration::from_nanos(31_250_000);
                let stage = self
                    .stage
                    .as_ref()
                    .ok_or(Error::Invalid("IM3 absent B ciphertext"))?;
                if write(
                    &mut self.links[lane],
                    &mut self.write,
                    RecordSize::Cell,
                    stage.frames[ordinal].bytes(),
                    start,
                    end,
                    lane as u8,
                    &mut self.observation,
                )? {
                    self.index += 1;
                    if self.index == 96 {
                        self.state = 2;
                        self.index = 0;
                    }
                }
            }
            2 => {
                let ordinal = self.cursor;
                self.cursor = (self.cursor + 1) % 3;
                let lane = ordinal + 1;
                if self.acks[ordinal].is_none() {
                    if let Some(bytes) = read(
                        &mut self.links[lane],
                        &mut self.read[lane],
                        RecordSize::Control,
                        self.schedule.at(29_000_000_000)?,
                        self.schedule.at(32_000_000_000)?,
                        lane as u8,
                        &mut self.observation,
                    )? {
                        let ack = Im3Control::verify(&bytes, self.c)?;
                        ack.check(self.c, Im3Kind::Ack)?;
                        if ack.role() != [Im3Role::P0, Im3Role::P1, Im3Role::P2][ordinal] {
                            return Err(Error::Invalid("IM3 original ACK role"));
                        }
                        self.acks[ordinal] = Some(ack);
                    }
                } else {
                    quiet(&self.links[lane])?;
                }
                if self.acks.iter().all(Option::is_some) {
                    let acks = std::array::from_fn(|i| self.acks[i].take().expect("all3"));
                    self.chain = Some(Im3AckChain::verify(
                        self.c,
                        copy_ready(
                            self.c,
                            &self
                                .stage
                                .as_ref()
                                .ok_or(Error::Invalid("IM3 missing B readiness"))?
                                .ready,
                        )?,
                        acks,
                    )?);
                    self.state = 3;
                }
            }
            3 => {
                for link in &self.links[1..] {
                    quiet(link)?;
                }
                let ordinal = self.index / 4;
                let lane = self.index % 4;
                let start = self
                    .schedule
                    .at(32_500_000_000 + 125_000_000 * i64::try_from(ordinal).expect("3"))?;
                let end = start + std::time::Duration::from_nanos(125_000_000);
                if write(
                    &mut self.links[lane],
                    &mut self.write,
                    RecordSize::Control,
                    self.chain
                        .as_ref()
                        .ok_or(Error::Invalid("IM3 missing B ACK chain"))?
                        .acks[ordinal]
                        .bytes(),
                    start,
                    end,
                    lane as u8,
                    &mut self.observation,
                )? {
                    self.index += 1;
                    if self.index == 12 {
                        self.state = 4;
                        self.index = 0;
                    }
                }
            }
            4 => {
                if let Some(bytes) = read(
                    &mut self.links[0],
                    &mut self.read[0],
                    RecordSize::Control,
                    self.schedule.at(34_000_000_000)?,
                    self.schedule.at(37_000_000_000)?,
                    0,
                    &mut self.observation,
                )? {
                    self.auth = Some(Im3Authorization::verify(
                        self.c,
                        self.chain
                            .take()
                            .ok_or(Error::Invalid("IM3 absent original B ACK chain"))?,
                        Im3Control::verify(&bytes, self.c)?,
                    )?);
                    self.state = 5;
                }
            }
            5 => {
                quiet(&self.links[0])?;
                if Instant::now() < self.schedule.at(37_000_000_000)? {
                    return Ok(false);
                }
                before(self.schedule.at(37_500_000_000)?)?;
                self.state = 6;
            }
            6 => {
                let lane = 1 + self.index;
                let (start, end) = self.schedule.window(Phase::AuthorizationCopies)?;
                if write(
                    &mut self.links[lane],
                    &mut self.write,
                    RecordSize::Control,
                    self.auth
                        .as_ref()
                        .ok_or(Error::Invalid("IM3 absent original B AUTH"))?
                        .control(),
                    start,
                    end,
                    lane as u8,
                    &mut self.observation,
                )? {
                    self.index += 1;
                    if self.index == 3 {
                        self.state = 7;
                        self.index = 0;
                    }
                }
            }
            7 => {
                for link in &self.links {
                    quiet(link)?;
                }
                if Instant::now() < self.schedule.at(39_500_000_000)? {
                    return Ok(false);
                }
                self.schedule.require(self.guard, Phase::ReleaseDecision)?;
                let auth = self
                    .auth
                    .take()
                    .ok_or(Error::Invalid("IM3 absent authenticated B authorization"))?;
                let store = self
                    .store
                    .take()
                    .ok_or(Error::Unavailable("IM3 B release decision store absent"))?;
                self.fence = Some(
                    store
                        .consume(
                            self.schedule.round(),
                            self.c.r2.round.manifest.id(),
                            release_choice(self.c, &auth),
                        )
                        .map_err(|_| Error::Unavailable("IM3 B release consume/pin"))?,
                );
                self.schedule.require(self.guard, Phase::ReleaseDecision)?;
                let control = self
                    .stage
                    .as_ref()
                    .ok_or(Error::Invalid("IM3 missing B sealed key"))?
                    .release_control(
                        self.c,
                        &auth,
                        self.fence.as_ref().expect("consumed"),
                        self.signing,
                    )?;
                self.release = Some(Im3Release::verify(self.c, auth, control)?);
                self.release_id = self.release.as_ref().map(|v| v.control.id());
                self.schedule.require(self.guard, Phase::ReleaseDecision)?;
                self.state = 8;
            }
            8 => {
                let lane = 1 + self.index;
                let (start, end) = self.schedule.window(Phase::Release)?;
                if write(
                    &mut self.links[lane],
                    &mut self.write,
                    RecordSize::Control,
                    self.release
                        .as_ref()
                        .ok_or(Error::Invalid("IM3 missing native B release"))?
                        .control(),
                    start,
                    end,
                    lane as u8,
                    &mut self.observation,
                )? {
                    self.index += 1;
                    if self.index == 3 {
                        self.state = 9;
                    }
                }
            }
            9 => {
                if Instant::now() >= self.schedule.at(44_000_000_000)? {
                    for link in &mut self.links {
                        link.quarantine()?;
                    }
                    if self
                        .stage
                        .as_mut()
                        .ok_or(Error::Invalid("IM3 missing B held exit"))?
                        .exit
                        .poll_cleanup()?
                    {
                        self.release = None;
                        self.stage = None;
                        self.state = 10;
                        return Ok(true);
                    }
                } else {
                    for link in &self.links {
                        quiet(link)?;
                    }
                }
            }
            10 => return Ok(true),
            _ => return Err(Error::Unavailable("IM3 B release state")),
        }
        self.guard.check(self.schedule)?;
        Ok(false)
    }
    /// Actual original A/producer socket step, without private input mapping.
    pub fn take_wire_observation(&mut self) -> Option<(u8, WireObservation)> {
        self.observation.take()
    }
    /// Consume the actual completed B owner after original links were closed.
    pub fn into_completed(mut self) -> Result<CompletedExit> {
        if self.failed || self.state != 10 {
            return Err(Error::Unavailable("IM3 B release not cleaned up"));
        }
        let release_id = self
            .release_id
            .take()
            .ok_or(Error::Unavailable("IM3 B release ID absent"))?;
        Ok(CompletedExit {
            context: [
                self.c.r2.round.config.id(),
                self.c.profile.id(),
                self.c.q.id(),
                self.c.r2.round.manifest.id(),
            ],
            round: self.schedule.round(),
            release_id,
        })
    }
}
impl<P: ClaimPinRetention, R: ClaimPinRetention> Drop
    for ReleasingExitOwner<'_, '_, '_, '_, '_, P, R>
{
    fn drop(&mut self) {
        for link in &mut self.links {
            close(link);
        }
    }
}
