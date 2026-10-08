//! Explicit private IM3 original-link client experiment, default off. Not epoch
//! admission, clock qualification, worker containment or an anonymity claim.
use super::{LocalViewV1, select_payload};
use silk_f04_relay::{
    Error, Result,
    aip2_claim::{ClaimPinRetention, ClaimRole, PreparedScopeStore},
    aip2_profile::PreparedProfile,
    aip2_proof::PreparedProofVerifier,
    config::SignedConfig,
    frame::RoundContext,
    im3_gate::{
        ClientProofJob, ClientProofOutput, MiddleContext, MiddleFrame, PreparedClientOwner,
        PreparedQ,
    },
    im3_schedule::Im3Schedule,
    manifest::SignedManifest,
    negotiation::SelectedCut,
    tls::{ReceiveProgress, RecordSize, Transport, WireObservation},
};
use silk_f04_wallet::journal::intents::SavedOfferV1;
use silk_sapling_f04::codec::ENVELOPE_BYTES;
use std::{rc::Rc, time::Instant};
use zeroize::Zeroizing;

/// Own the already-established original A link and receive M on that link only.
/// No injected manifest, reconnect, replacement link or recovered-job API exists.
pub struct OriginalClientLab<'a, P: ClaimPinRetention> {
    config: Rc<SignedConfig>,
    schedule: Im3Schedule,
    profile: &'a PreparedProfile,
    q: &'a PreparedQ,
    verifier: PreparedProofVerifier,
    view: LocalViewV1,
    store: Option<&'a mut PreparedScopeStore<P>>,
    link: Option<Transport>,
    slot: u8,
    offer: Option<Zeroizing<[u8; ENVELOPE_BYTES]>>,
    manifest: Option<SignedManifest>,
    reading: bool,
    failed: bool,
    observation: Option<WireObservation>,
}
impl<'a, P: ClaimPinRetention> OriginalClientLab<'a, P> {
    /// Consume an ordinary already-exposed wallet offer before T-8. Local
    /// runner must own/contain both sequential workers; this owner is not that
    /// containment. A successful established link is not Join/epoch admission.
    #[allow(clippy::too_many_arguments)]
    pub fn begin(
        config: Rc<SignedConfig>,
        schedule: Im3Schedule,
        profile: &'a PreparedProfile,
        q: &'a PreparedQ,
        verifier: PreparedProofVerifier,
        view: LocalViewV1,
        store: &'a mut PreparedScopeStore<P>,
        slot: u8,
        link: Transport,
        offer: Option<SavedOfferV1>,
    ) -> Result<Self> {
        Self::begin_bytes(
            config,
            schedule,
            profile,
            q,
            verifier,
            view,
            store,
            slot,
            link,
            offer.map(SavedOfferV1::into_bytes),
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn begin_bytes(
        config: Rc<SignedConfig>,
        schedule: Im3Schedule,
        profile: &'a PreparedProfile,
        q: &'a PreparedQ,
        verifier: PreparedProofVerifier,
        view: LocalViewV1,
        store: &'a mut PreparedScopeStore<P>,
        slot: u8,
        mut link: Transport,
        offer: Option<Zeroizing<[u8; ENVELOPE_BYTES]>>,
    ) -> Result<Self> {
        let check = (|| {
            schedule.check_client_clock()?;
            schedule.client_slot(slot)?;
            if schedule.uses_qualified_source()
                || Instant::now() >= schedule.at(-8_000_000_000)?
                || !config.contains_round(schedule.round())
                || store.binding() != profile.claim_binding(ClaimRole::Client)
                || link.receive_progress() != ReceiveProgress::Idle
            {
                return Err(Error::Unavailable("IM3 client original admission"));
            }
            link.check_endpoint(config.endpoints()[0], true)
        })();
        if let Err(e) = check {
            let _ = link.quarantine();
            return Err(e);
        }
        Ok(Self {
            config,
            schedule,
            profile,
            q,
            verifier,
            view,
            store: Some(store),
            link: Some(link),
            slot,
            offer,
            manifest: None,
            reading: false,
            failed: false,
            observation: None,
        })
    }
    fn stop(&mut self) {
        self.failed = true;
        self.offer = None;
        self.store = None;
        if let Some(link) = &mut self.link {
            let _ = link.quarantine();
        }
    }
    /// Progress only the original manifest read. Completion is verified locally
    /// before T-5, not a caller-supplied validity boolean or arrival timestamp.
    pub fn poll_manifest(&mut self) -> Result<bool> {
        let result = self.poll_manifest_inner();
        if result.is_err() {
            self.stop();
        }
        result
    }
    fn poll_manifest_inner(&mut self) -> Result<bool> {
        if self.failed {
            return Err(Error::Unavailable("IM3 client closed"));
        }
        self.schedule.observe_functional_clock()?;
        let end = self.schedule.at(-5_000_000_000)?;
        if Instant::now() >= end {
            return Err(Error::Unavailable("IM3 client manifest cutoff"));
        }
        let link = self
            .link
            .as_mut()
            .ok_or(Error::Unavailable("IM3 client original link"))?;
        if self.manifest.is_some() {
            if link.has_extra_bytes()? {
                return Err(Error::Invalid("IM3 extra manifest bytes"));
            }
            return Ok(true);
        }
        if Instant::now() < self.schedule.at(-8_000_000_000)? {
            return Ok(false);
        }
        if !self.reading {
            link.expect(RecordSize::Manifest, end)?;
            self.reading = true;
        }
        let (result, observation) = link.read_step_observed();
        self.observation = Some(observation);
        if let Some(bytes) = result? {
            let manifest = SignedManifest::verify(&bytes, &self.config, self.schedule.round())?;
            let cut = selected_cut(&self.view, &self.config, &manifest)?;
            cut.admit_im3_signed(manifest.bytes(), &self.config, &self.schedule)?;
            MiddleContext::new(
                &self.config,
                &manifest,
                self.profile,
                self.profile.claim_binding(ClaimRole::Client).vk_hash,
                self.q,
            )?;
            self.schedule.check_client_clock()?;
            if Instant::now() >= end || link.has_extra_bytes()? {
                return Err(Error::Unavailable("IM3 manifest late/extra"));
            }
            self.manifest = Some(manifest);
        }
        Ok(self.manifest.is_some())
    }
    /// Take the last actual socket-step observation, never queue/admission time.
    pub fn take_wire_observation(&mut self) -> Option<WireObservation> {
        self.observation.take()
    }
    /// Run the entire borrowed context in one scope, so M stays alive without
    /// self-references/unsafe. The closure cannot return or resume this stream.
    /// Any early return/drop closes the original link; no replacement is allowed.
    pub fn run<T>(
        mut self,
        drive: impl for<'r> FnOnce(&mut ClientStreamLab<'r, P>) -> Result<T>,
    ) -> Result<T> {
        self.schedule.observe_functional_clock()?;
        if self.failed || self.manifest.is_none() {
            self.stop();
            return Err(Error::Unavailable("IM3 no original manifest"));
        }
        let manifest = self
            .manifest
            .as_ref()
            .ok_or(Error::Unavailable("IM3 manifest"))?;
        let context = MiddleContext::new(
            &self.config,
            manifest,
            self.profile,
            self.profile.claim_binding(ClaimRole::Client).vk_hash,
            self.q,
        )?;
        let payload = select_payload(
            self.offer.take(),
            self.config.domain(),
            &RoundContext::new(&self.config, manifest)?,
        );
        let cut = selected_cut(&self.view, &self.config, manifest)?;
        let owner = PreparedClientOwner::admit(
            &context,
            &self.schedule,
            cut,
            &self.verifier,
            self.store
                .take()
                .ok_or(Error::Unavailable("IM3 client original store"))?,
            payload,
        )?;
        let mut stream = ClientStreamLab {
            owner: Some(owner),
            schedule: &self.schedule,
            link: self
                .link
                .take()
                .ok_or(Error::Unavailable("IM3 client original link"))?,
            slot: self.slot,
            frame: None,
            queued: false,
            complete: false,
            cleaned_up: false,
            failed: false,
            observation: None,
        };
        let result = drive(&mut stream);
        if result.is_ok() && !stream.cleaned_up {
            return Err(Error::Unavailable("IM3 original client cleanup incomplete"));
        }
        result
    }
}
impl<P: ClaimPinRetention> Drop for OriginalClientLab<'_, P> {
    fn drop(&mut self) {
        if let Some(link) = &mut self.link {
            let _ = link.quarantine();
        }
    }
}
fn selected_cut(
    view: &LocalViewV1,
    config: &SignedConfig,
    manifest: &SignedManifest,
) -> Result<SelectedCut<'static>> {
    match view {
        LocalViewV1::Ready(node) => SelectedCut::from_owned_ready_node(
            Rc::clone(node),
            config,
            manifest.round(),
            u64::from_le_bytes(manifest.bytes()[52..60].try_into().expect("8")),
        ),
        LocalViewV1::Genesis(genesis) => {
            SelectedCut::from_owned_genesis(Rc::clone(genesis), config, manifest.round())
        }
    }
}

/// Borrow-scoped proof preparation plus original-link fixed-slot write. Inner
/// ciphertext and final onion are private; only public statements leave to the
/// trusted local runner. No worker/backend/connection injection is possible.
pub struct ClientStreamLab<'r, P: ClaimPinRetention> {
    owner: Option<PreparedClientOwner<'r, 'r, 'r, P>>,
    schedule: &'r Im3Schedule,
    link: Transport,
    slot: u8,
    frame: Option<MiddleFrame>,
    queued: bool,
    complete: bool,
    cleaned_up: bool,
    failed: bool,
    observation: Option<WireObservation>,
}
impl<'r, P: ClaimPinRetention> ClientStreamLab<'r, P> {
    fn stop(&mut self) {
        self.failed = true;
        self.owner = None;
        self.frame = None;
        let _ = self.link.quarantine();
    }
    fn operation<T>(
        &mut self,
        f: impl FnOnce(&mut PreparedClientOwner<'r, 'r, 'r, P>) -> Result<T>,
    ) -> Result<T> {
        let result = (|| {
            self.schedule.observe_functional_clock()?;
            if self.failed || self.link.has_extra_bytes()? {
                return Err(Error::Unavailable("IM3 client closed/extra input"));
            }
            let value = f(self
                .owner
                .as_mut()
                .ok_or(Error::Unavailable("IM3 client no proof owner"))?)?;
            self.schedule.observe_functional_clock()?;
            Ok(value)
        })();
        if result.is_err() {
            self.stop();
        }
        result
    }
    /// Durable original choice before either dispatch.
    pub fn freeze(&mut self) -> Result<()> {
        self.operation(|o| o.freeze())
    }
    /// Take the one B statement with its original deadline.
    pub fn take_b_job(&mut self) -> Result<ClientProofJob> {
        self.operation(|o| o.take_b_job())
    }
    /// Native-verify original B worker output.
    pub fn complete_b(&mut self, output: ClientProofOutput) -> Result<()> {
        self.operation(|o| o.complete_b(output))
    }
    /// Freeze one private B encryption; no S_B export.
    pub fn seal_b(&mut self) -> Result<()> {
        self.operation(|o| o.seal_b())
    }
    /// Take the one C statement only after B completion/sealing.
    pub fn take_c_job(&mut self) -> Result<ClientProofJob> {
        self.operation(|o| o.take_c_job())
    }
    /// Native-verify original C worker output.
    pub fn complete_c(&mut self, output: ClientProofOutput) -> Result<()> {
        self.operation(|o| o.complete_c(output))
    }
    /// Retain the sole final onion, without handing its bytes to the caller.
    pub fn seal_onion(&mut self) -> Result<()> {
        self.operation(|o| o.seal_onion())?;
        let result = self
            .owner
            .take()
            .ok_or(Error::Unavailable("IM3 client proof owner"))?
            .into_onion();
        match result {
            Ok(frame) => {
                self.frame = Some(frame);
                Ok(())
            }
            Err(e) => {
                self.stop();
                Err(e)
            }
        }
    }
    /// Advance at most one original write step in the original .2-second slot.
    /// True is local TLS completion only, not B disclosure, delivery or settlement.
    pub fn poll_write(&mut self) -> Result<bool> {
        let result = self.poll_write_inner();
        if result.is_err() {
            self.stop();
        }
        result
    }
    fn poll_write_inner(&mut self) -> Result<bool> {
        if self.failed {
            return Err(Error::Unavailable("IM3 client write closed"));
        }
        self.schedule.observe_functional_clock()?;
        if self.link.has_extra_bytes()? {
            return Err(Error::Invalid("IM3 extra client input"));
        }
        if self.complete {
            return Ok(true);
        }
        let (start, end) = self.schedule.client_slot(self.slot)?;
        let now = Instant::now();
        if now < start {
            return Ok(false);
        }
        if now >= end {
            return Err(Error::Unavailable("IM3 original client slot missed"));
        }
        if !self.queued {
            let frame = self
                .frame
                .take()
                .ok_or(Error::Unavailable("IM3 no prepared onion"))?;
            self.queued = true;
            self.link.queue(RecordSize::Cell, frame.bytes(), end)?;
        }
        let (result, observation) = self.link.write_step_observed();
        self.observation = Some(observation);
        if result? {
            self.schedule.check_client_clock()?;
            if Instant::now() >= end {
                return Err(Error::Unavailable("IM3 original write cutoff"));
            }
            self.complete = true;
        }
        Ok(self.complete)
    }
    /// Last actual write syscall interval, including failures/partial writes.
    pub fn take_wire_observation(&mut self) -> Option<WireObservation> {
        self.observation.take()
    }
    /// Test-only missing-input arm: keep the already prepared slot-0 onion
    /// private and never queue a Cell. A's expected abort may close this
    /// original TLS link before T+44; no replacement or cleanup success is
    /// inferred from that EOF.
    #[cfg(test)]
    pub(super) fn poll_omitted_original_hold(&mut self) -> Result<Option<&'static str>> {
        if self.slot != 0
            || self.frame.is_none()
            || self.queued
            || self.complete
            || self.cleaned_up
            || self.failed
        {
            return Err(Error::Invalid("IM3 test omission state"));
        }
        self.schedule.observe_functional_clock()?;
        if Instant::now() >= self.schedule.at(44_000_000_000)? {
            self.link.quarantine()?;
            self.cleaned_up = true;
            return Ok(Some("HELD_TO_T44"));
        }
        match self.link.has_extra_bytes() {
            Ok(false) => Ok(None),
            Ok(true) => Err(Error::Invalid("IM3 test omission inbound bytes")),
            Err(Error::Unavailable("TLS peer closed")) => {
                let _ = self.link.quarantine();
                self.cleaned_up = true;
                Ok(Some("PEER_CLOSED"))
            }
            Err(Error::Io(error))
                if matches!(error.kind(), std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::NotConnected) =>
            {
                let _ = self.link.quarantine();
                self.cleaned_up = true;
                Ok(Some("PEER_IO_CLOSED"))
            }
            Err(error) => Err(error),
        }
    }
    /// Keep the original connection through T+44, even after the fixed write.
    /// A successful run requires this cleanup; early return is failed/closed.
    /// No reconnection, late replacement write or liveness renewal is allowed.
    pub fn poll_cleanup(&mut self) -> Result<bool> {
        let result = (|| {
            if self.failed || !self.complete {
                return Err(Error::Unavailable("IM3 cleanup before completed write"));
            }
            if self.cleaned_up {
                return Ok(true);
            }
            self.schedule.observe_functional_clock()?;
            if Instant::now() >= self.schedule.at(44_000_000_000)? {
                self.link.quarantine()?;
                self.cleaned_up = true;
                return Ok(true);
            }
            if self.link.has_extra_bytes()? {
                return Err(Error::Invalid("IM3 extra input during hold"));
            }
            Ok(false)
        })();
        if result.is_err() {
            self.stop();
        }
        result
    }
}
impl<P: ClaimPinRetention> Drop for ClientStreamLab<'_, P> {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests;
