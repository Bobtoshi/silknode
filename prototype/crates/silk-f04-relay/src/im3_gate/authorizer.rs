//! A's original B-control reservation and durable full-chain authorization.
use super::cycle::*;
use super::*;
use crate::tls::{ReceiveProgress, WireObservation};
use ed25519_dalek::SigningKey;

/// Reserve A's sole original B control connection and decision store before
/// T-5. Binding the genuine ingress train cannot introduce a replacement link.
pub struct IngressControlReservation<'c, 'a, 's, 't, P: ClaimPinRetention> {
    c: &'c MiddleContext<'a>,
    schedule: &'t Im3Schedule,
    guard: &'t Im3Guard,
    store: Option<&'s mut PreparedScopeStore<P>>,
    link: Option<Transport>,
    signing: &'t SigningKey,
}
impl<'c, 'a, 's, 't, P: ClaimPinRetention> IngressControlReservation<'c, 'a, 's, 't, P> {
    /// Reserve exact original client-side B TLS and A identity. No authorization
    /// is signed here, and no previously consumed decision can be resumed.
    pub(crate) fn begin(
        c: &'c MiddleContext<'a>,
        store: &'s mut PreparedScopeStore<P>,
        schedule: &'t Im3Schedule,
        guard: &'t Im3Guard,
        mut link: Transport,
        signing: &'t SigningKey,
    ) -> Result<Self> {
        let check = (|| {
            guard.check(schedule)?;
            before(schedule.at(-5_000_000_000)?)?;
            if schedule.round() != c.r2.round.manifest.round()
                || store.binding() != c.profile.claim_binding(ClaimRole::Im3Authorization)
                || signing.verifying_key().to_bytes() != c.r2.round.config.endpoints()[0].signing
                || link.receive_progress() != ReceiveProgress::Idle
                || link.selected_read().is_some()
            {
                return Err(Error::Invalid("IM3 A control reservation"));
            }
            link.check_endpoint(c.r2.round.config.endpoints()[1], true)
        })();
        if let Err(e) = check {
            close(&mut link);
            return Err(e);
        }
        Ok(Self {
            c,
            schedule,
            guard,
            store: Some(store),
            link: Some(link),
            signing,
        })
    }
    /// Only the actual native complete ingress train can bind this reservation,
    /// during its original freeze window and under the identical native lease.
    pub fn bind(
        mut self,
        train: IngressTrain<'t>,
    ) -> Result<AuthorizingIngressOwner<'c, 'a, 's, 't, P>> {
        self.schedule.require(self.guard, Phase::AFreeze)?;
        if !std::ptr::eq(self.schedule, train.schedule) || !std::ptr::eq(self.guard, train.guard) {
            return Err(Error::Invalid("IM3 A train lease changed"));
        }
        let ready = Im3Control::verify(train.ready.bytes(), self.c)?;
        ready.check(self.c, Im3Kind::AReady)?;
        Ok(AuthorizingIngressOwner {
            c: self.c,
            schedule: self.schedule,
            guard: self.guard,
            signing: self.signing,
            store: self.store.take(),
            claim: None,
            link: self
                .link
                .take()
                .ok_or(Error::Unavailable("IM3 A original control absent"))?,
            train,
            own_ready: ready.id(),
            state: 0,
            read: ReadState::default(),
            write: WriteState::default(),
            controls: Vec::with_capacity(3),
            ready: None,
            chain: None,
            auth: None,
            failed: false,
            observation: None,
        })
    }
}
impl<P: ClaimPinRetention> Drop for IngressControlReservation<'_, '_, '_, '_, P> {
    fn drop(&mut self) {
        if let Some(link) = &mut self.link {
            close(link);
        }
    }
}

/// The full original A ingress/train plus original B control stream. A signs
/// one authorization only after six complete authenticated controls and durable
/// consume/pin. Nothing accepts caller-injected READY/ACKs or a new connection.
pub struct AuthorizingIngressOwner<'c, 'a, 's, 't, P: ClaimPinRetention> {
    c: &'c MiddleContext<'a>,
    schedule: &'t Im3Schedule,
    guard: &'t Im3Guard,
    signing: &'t SigningKey,
    store: Option<&'s mut PreparedScopeStore<P>>,
    claim: Option<ConsumedScope<'s, P>>,
    link: Transport,
    train: IngressTrain<'t>,
    own_ready: Digest,
    state: u8,
    read: ReadState,
    write: WriteState,
    controls: Vec<Im3Control>,
    ready: Option<Im3ReadyChain>,
    chain: Option<Im3AckChain>,
    auth: Option<Im3Authorization>,
    failed: bool,
    observation: Observation,
}
impl<P: ClaimPinRetention> AuthorizingIngressOwner<'_, '_, '_, '_, P> {
    /// Advance one original TLS operation or a fixed native/durable gate.
    pub fn poll(&mut self) -> Result<bool> {
        let result = self.poll_inner();
        if result.is_err() {
            self.failed = true;
            close(&mut self.link);
            self.train.stop();
            self.auth = None;
            self.chain = None;
            self.ready = None;
            self.controls.clear();
        }
        result
    }
    fn poll_inner(&mut self) -> Result<bool> {
        if self.failed {
            return Err(Error::Unavailable("IM3 authorizer closed"));
        }
        self.guard.check(self.schedule)?;
        if self.state > 0 && self.state < 6 && Instant::now() < self.schedule.at(44_000_000_000)? {
            self.train.poll_hold()?;
        }
        match self.state {
            0 => {
                if self.train.poll()? {
                    self.state = 1;
                }
                if let Some(o) = self.train.take_wire_observation() {
                    self.observation = Some((1, o));
                }
            }
            1 => {
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
                    if control.kind()
                        != [Im3Kind::AReady, Im3Kind::CReady, Im3Kind::BReady][self.controls.len()]
                    {
                        return Err(Error::Invalid("IM3 A readiness order"));
                    }
                    self.controls.push(control);
                    if self.controls.len() == 3 {
                        let [a, c, b] = take_controls(&mut self.controls)?;
                        if a.id() != self.own_ready {
                            return Err(Error::Invalid("IM3 A original readiness changed"));
                        }
                        self.ready = Some(Im3ReadyChain::verify(self.c, a, c, b)?);
                        self.state = 2;
                        self.read = ReadState::default();
                    }
                }
            }
            2 => {
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
                        self.chain = Some(Im3AckChain::verify(
                            self.c,
                            self.ready
                                .take()
                                .ok_or(Error::Invalid("IM3 A missing readiness"))?,
                            take_controls(&mut self.controls)?,
                        )?);
                        self.state = 3;
                    }
                }
            }
            3 => {
                quiet(&self.link)?;
                if Instant::now() < self.schedule.at(34_500_000_000)? {
                    return Ok(false);
                }
                self.schedule
                    .require(self.guard, Phase::AuthorizationDecision)?;
                let chain = self
                    .chain
                    .take()
                    .ok_or(Error::Invalid("IM3 A missing full chain"))?;
                let choice = authorization_choice(self.c, &chain);
                let store = self
                    .store
                    .take()
                    .ok_or(Error::Unavailable("IM3 A decision store unavailable"))?;
                self.claim = Some(
                    store
                        .consume(self.schedule.round(), self.c.r2.round.manifest.id(), choice)
                        .map_err(|_| Error::Unavailable("IM3 A decision consume/pin"))?,
                );
                self.schedule
                    .require(self.guard, Phase::AuthorizationDecision)?;
                let control = control::sign(
                    self.c,
                    Im3Kind::Authorize,
                    Im3Role::A,
                    terminal_fields(&chain, chain.ready.b.id()),
                    self.signing,
                )?;
                self.auth = Some(Im3Authorization::verify(self.c, chain, control)?);
                self.schedule
                    .require(self.guard, Phase::AuthorizationDecision)?;
                self.state = 4;
            }
            4 => {
                quiet(&self.link)?;
                let (start, end) = self.schedule.window(Phase::Authorization)?;
                if write(
                    &mut self.link,
                    &mut self.write,
                    RecordSize::Control,
                    self.auth
                        .as_ref()
                        .ok_or(Error::Invalid("IM3 A missing authorization"))?
                        .control(),
                    start,
                    end,
                    0,
                    &mut self.observation,
                )? {
                    self.state = 5;
                }
            }
            5 => {
                if Instant::now() >= self.schedule.at(44_000_000_000)? {
                    close(&mut self.link);
                    if self.train.poll_cleanup()? {
                        self.state = 6;
                        return Ok(true);
                    }
                } else {
                    quiet(&self.link)?;
                }
            }
            6 => return Ok(true),
            _ => return Err(Error::Unavailable("IM3 A authorizer state")),
        }
        self.guard.check(self.schedule)?;
        Ok(false)
    }
    /// Actual original TLS read/write observation; never a permutation map.
    pub fn take_wire_observation(&mut self) -> Option<(u8, WireObservation)> {
        self.observation.take()
    }
}
impl<P: ClaimPinRetention> Drop for AuthorizingIngressOwner<'_, '_, '_, '_, P> {
    fn drop(&mut self) {
        close(&mut self.link);
    }
}
