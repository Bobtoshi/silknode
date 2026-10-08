//! Original pre-round signed M fanout and consumed C admission. No injected
//! manifest acknowledgement or replacement data connection can advance owners.
use super::cycle::*;
use super::*;
use crate::tls::{ReceiveProgress, WireObservation};

/// A's one preclaimed M and original32 client/C links, all retained until their
/// handoff to the actual ingress owner. Original identity/admission precedes it.
pub struct ManifestFanout<'c, 'a, 's, 't, P: ClaimPinRetention> {
    c: &'c MiddleContext<'a>,
    schedule: &'t Im3Schedule,
    guard: &'t Im3Guard,
    claim: Option<ConsumedScope<'s, P>>,
    inputs: Option<&'t mut [Transport; 32]>,
    output: Option<&'t mut Transport>,
    index: usize,
    write: WriteState,
    failed: bool,
    observation: Observation,
}
impl<'c, 'a, 's, 't, P: ClaimPinRetention> ManifestFanout<'c, 'a, 's, 't, P> {
    /// Before T-9, pin one Q/M/r choice before any manifest transmission.
    pub(crate) fn begin(
        c: &'c MiddleContext<'a>,
        store: &'s mut PreparedScopeStore<P>,
        schedule: &'t Im3Schedule,
        guard: &'t Im3Guard,
        inputs: &'t mut [Transport; 32],
        output: &'t mut Transport,
    ) -> Result<Self> {
        let check = (|| {
            guard.check(schedule)?;
            before(schedule.at(-9_000_000_000)?)?;
            if schedule.round() != c.r2.round.manifest.round()
                || store.binding() != c.profile.claim_binding(ClaimRole::Im3Ingress)
            {
                return Err(Error::Invalid("IM3 ingress manifest context/store"));
            }
            output.check_endpoint(c.q.endpoint(), true)?;
            if output.receive_progress() != ReceiveProgress::Idle
                || output.selected_read().is_some()
                || output.has_extra_bytes()?
            {
                return Err(Error::Invalid("IM3 original C manifest link"));
            }
            for input in inputs.iter() {
                input.check_endpoint(c.r2.round.config.endpoints()[0], false)?;
                if input.receive_progress() != ReceiveProgress::Idle
                    || input.selected_read().is_some()
                    || input.has_extra_bytes()?
                {
                    return Err(Error::Invalid("IM3 original client manifest link"));
                }
            }
            Ok(())
        })();
        if let Err(e) = check {
            for input in inputs.iter_mut() {
                close(input);
            }
            close(output);
            return Err(e);
        }
        let choice = domain_hash(
            "SilkNode-IM3-ingress-claim",
            &[
                &c.q.id(),
                &c.r2.round.manifest.id(),
                &schedule.round().to_le_bytes(),
            ],
        );
        let claim = match store.consume(schedule.round(), c.r2.round.manifest.id(), choice) {
            Ok(v) => v,
            Err(_) => {
                for input in inputs.iter_mut() {
                    close(input);
                }
                close(output);
                return Err(Error::Unavailable("IM3 ingress manifest consume/pin"));
            }
        };
        if let Err(e) = guard
            .check(schedule)
            .and_then(|()| before(schedule.at(-9_000_000_000)?))
        {
            for input in inputs.iter_mut() {
                close(input);
            }
            close(output);
            return Err(e);
        }
        Ok(Self {
            c,
            schedule,
            guard,
            claim: Some(claim),
            inputs: Some(inputs),
            output: Some(output),
            index: 0,
            write: WriteState::default(),
            failed: false,
            observation: None,
        })
    }
    fn stop(&mut self) {
        self.failed = true;
        if let Some(inputs) = self.inputs.take() {
            for input in inputs {
                close(input);
            }
        }
        if let Some(output) = self.output.take() {
            close(output);
        }
    }
    /// One actual original write step in [-8,-7), identical signed M for all33.
    pub fn poll(&mut self) -> Result<bool> {
        let result = (|| {
            if self.failed {
                return Err(Error::Unavailable("IM3 manifest fanout closed"));
            }
            self.guard.check(self.schedule)?;
            if self.index == 33 {
                return Ok(true);
            }
            let (start, end) = self.schedule.window(Phase::Manifest)?;
            let link = if self.index < 32 {
                &mut self
                    .inputs
                    .as_deref_mut()
                    .ok_or(Error::Unavailable("IM3 manifest clients absent"))?[self.index]
            } else {
                self.output
                    .as_deref_mut()
                    .ok_or(Error::Unavailable("IM3 manifest C absent"))?
            };
            if write(
                link,
                &mut self.write,
                RecordSize::Manifest,
                self.c.r2.round.manifest.bytes(),
                start,
                end,
                u8::try_from(self.index).expect("33"),
                &mut self.observation,
            )? {
                self.index += 1;
            }
            self.guard.check(self.schedule)?;
            Ok(self.index == 33)
        })();
        if result.is_err() {
            self.stop();
        }
        result
    }
    /// Native completed fanout transfers only these exact original links to A's
    /// ingress; the consumed store remains irreversible after its borrow ends.
    pub fn receive(mut self) -> Result<ReceivingIngressOwner<'c, 'a, 't>> {
        self.guard.check(self.schedule)?;
        before(self.schedule.at(-5_000_000_000)?)?;
        if self.failed
            || self.index != 33
            || self.claim.as_ref().is_none_or(|v| {
                v.round() != self.schedule.round() || v.manifest() != self.c.r2.round.manifest.id()
            })
        {
            return Err(Error::Unavailable(
                "IM3 incomplete original manifest fanout",
            ));
        }
        let inputs = self
            .inputs
            .take()
            .ok_or(Error::Unavailable("IM3 manifest clients consumed"))?;
        let output = self
            .output
            .take()
            .ok_or(Error::Unavailable("IM3 manifest C consumed"))?;
        ReceivingIngressOwner::begin(self.c, self.schedule, self.guard, inputs, output)
    }
    /// Source-associated actual manifest-write interval at A, not client choice.
    pub fn take_wire_observation(&mut self) -> Option<(u8, WireObservation)> {
        self.observation.take()
    }
}
impl<P: ClaimPinRetention> Drop for ManifestFanout<'_, '_, '_, '_, P> {
    fn drop(&mut self) {
        self.stop();
    }
}

/// C claims its immutable local Q/P/r/M before reading actual A-delivered M.
/// Invalid/alternate/missing M cannot create a replacement or unconsume scope.
pub struct ManifestReceivingMiddle<'c, 'a, 's, 't, P: ClaimPinRetention> {
    c: &'c MiddleContext<'a>,
    schedule: &'t Im3Schedule,
    guard: &'t Im3Guard,
    owner: Option<TimedMiddleOwner<'c, 'a, 's, 't, P>>,
    input: Option<&'t mut Transport>,
    read: ReadState,
    verified: bool,
    failed: bool,
    observation: Observation,
}
impl<'c, 'a, 's, 't, P: ClaimPinRetention> ManifestReceivingMiddle<'c, 'a, 's, 't, P> {
    /// Reserve actual A-server input and original B output before T-9, consuming
    /// the same middle store used later by the genuine all32 gate exactly once.
    pub(crate) fn begin(
        c: &'c MiddleContext<'a>,
        store: &'s mut PreparedScopeStore<P>,
        schedule: &'t Im3Schedule,
        guard: &'t Im3Guard,
        input: &'t mut Transport,
        output: &'t mut Transport,
    ) -> Result<Self> {
        let check = (|| {
            guard.check(schedule)?;
            before(schedule.at(-9_000_000_000)?)?;
            input.check_endpoint(c.q.endpoint(), false)?;
            if input.receive_progress() != ReceiveProgress::Idle
                || input.selected_read().is_some()
                || input.has_extra_bytes()?
            {
                return Err(Error::Invalid("IM3 C original manifest read"));
            }
            Ok(())
        })();
        if let Err(e) = check {
            close(input);
            close(output);
            return Err(e);
        }
        let owner = match TimedMiddleOwner::begin(c, store, schedule, guard, output) {
            Ok(v) => v,
            Err(e) => {
                close(input);
                return Err(e);
            }
        };
        // Durable claim/pin retention may block. Its broader gate cutoff must
        // not let this pre-manifest reservation complete at or after T-9.
        if let Err(e) = guard
            .check(schedule)
            .and_then(|()| before(schedule.at(-9_000_000_000)?))
        {
            close(input);
            close(owner.output);
            return Err(e);
        }
        if let Err(e) = input
            .expect(RecordSize::Manifest, schedule.at(-5_000_000_000)?)
            .and_then(|()| guard.check(schedule))
            .and_then(|()| before(schedule.at(-9_000_000_000)?))
        {
            close(input);
            close(owner.output);
            return Err(e);
        }
        Ok(Self {
            c,
            schedule,
            guard,
            owner: Some(owner),
            input: Some(input),
            read: ReadState {
                armed: true,
                selected_any: true,
            },
            verified: false,
            failed: false,
            observation: None,
        })
    }
    fn stop(&mut self) {
        self.failed = true;
        if let Some(input) = self.input.take() {
            close(input);
        }
        if let Some(owner) = self.owner.take() {
            close(owner.output);
        }
    }
    /// One original manifest read, with both A/B signatures and byte-exact local
    /// M equality checked before T-5. Peer bytes cannot select a different cut.
    pub fn poll(&mut self) -> Result<bool> {
        let result = (|| {
            if self.failed {
                return Err(Error::Unavailable("IM3 C manifest admission closed"));
            }
            self.guard.check(self.schedule)?;
            before(self.schedule.at(-5_000_000_000)?)?;
            let input = self
                .input
                .as_deref_mut()
                .ok_or(Error::Unavailable("IM3 C original manifest input absent"))?;
            if self.verified {
                quiet(input)?;
                return Ok(true);
            }
            if let Some(bytes) = read(
                input,
                &mut self.read,
                RecordSize::Manifest,
                self.schedule.at(-9_000_000_000)?,
                self.schedule.at(-5_000_000_000)?,
                0,
                &mut self.observation,
            )? {
                let m =
                    SignedManifest::verify(&bytes, self.c.r2.round.config, self.schedule.round())?;
                if m.bytes() != self.c.r2.round.manifest.bytes()
                    || m.id() != self.c.r2.round.manifest.id()
                {
                    return Err(Error::Invalid("IM3 C alternate original manifest"));
                }
                self.guard.check(self.schedule)?;
                before(self.schedule.at(-5_000_000_000)?)?;
                self.verified = true;
            }
            Ok(self.verified)
        })();
        if result.is_err() {
            self.stop();
        }
        result
    }
    /// Transfer the very same already-consumed middle gate and original links;
    /// no second claim, replacement input, supplied M or renewed native lease.
    pub fn receive(mut self) -> Result<ReceivingMiddleOwner<'c, 'a, 's, 't, P>> {
        self.guard.check(self.schedule)?;
        before(self.schedule.at(-5_000_000_000)?)?;
        if self.failed || !self.verified {
            return Err(Error::Unavailable("IM3 C missing original manifest"));
        }
        ReceivingMiddleOwner::from_claimed(
            self.owner
                .take()
                .ok_or(Error::Unavailable("IM3 C manifest gate consumed"))?,
            self.input
                .take()
                .ok_or(Error::Unavailable("IM3 C manifest input consumed"))?,
        )
    }
    /// Actual original A-to-C manifest-read interval, no member/source labels.
    pub fn take_wire_observation(&mut self) -> Option<(u8, WireObservation)> {
        self.observation.take()
    }
}
impl<P: ClaimPinRetention> Drop for ManifestReceivingMiddle<'_, '_, '_, '_, P> {
    fn drop(&mut self) {
        self.stop();
    }
}
