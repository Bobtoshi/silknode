//! One original 32-link A ingress and fixed C train, not epoch negotiation or
//! authorization. Missing/duplicate/late input has no output capability.
use super::*;
use crate::tls::{ReceiveProgress, RecordSize, Transport, WireObservation};
use ed25519_dalek::SigningKey;

/// A owns the original 32 already-admitted client links and its sole C link.
/// Context/epoch negotiation must precede construction; this is not Join or a
/// clock/custody certificate. There is no raw-frame or replacement-link API.
pub struct ReceivingIngressOwner<'c, 'a, 't> {
    c: &'c MiddleContext<'a>,
    schedule: &'t Im3Schedule,
    guard: &'t Im3Guard,
    inputs: Option<&'t mut [Transport; 32]>,
    output: Option<&'t mut Transport>,
    frames: [Option<MiddleFrame>; 32],
    tags: BTreeSet<Digest>,
    count: u8,
    cursor: u8,
    failed: bool,
    observation: Option<(u8, WireObservation)>,
    cancel_queued: bool,
    cancel_complete: bool,
    cancel_observation: Option<WireObservation>,
    #[cfg(test)]
    cancel_bytes: Option<[u8; 512]>,
}
impl<'c, 'a, 't> ReceivingIngressOwner<'c, 'a, 't> {
    /// Bind and arm every original input before T-5, hence before T+6's early
    /// receive envelope. The one native lease was already armed before T-10.
    pub(crate) fn begin(
        c: &'c MiddleContext<'a>,
        schedule: &'t Im3Schedule,
        guard: &'t Im3Guard,
        inputs: &'t mut [Transport; 32],
        output: &'t mut Transport,
    ) -> Result<Self> {
        let check = (|| {
            guard.check(schedule)?;
            if schedule.round() != c.r2.round.manifest.round() {
                return Err(Error::Invalid("IM3 ingress round"));
            }
            before(schedule.at(-5_000_000_000)?)?;
            output.check_endpoint(c.q.endpoint(), true)?;
            for input in inputs.iter_mut() {
                input.check_endpoint(c.r2.round.config.endpoints()[0], false)?;
                if input.receive_progress() != ReceiveProgress::Idle
                    || input.selected_read().is_some()
                {
                    return Err(Error::Unavailable(
                        "IM3 ingress original input already selected",
                    ));
                }
                input.expect(RecordSize::Cell, schedule.at(15_000_000_000)?)?;
            }
            guard.check(schedule)?;
            before(schedule.at(-5_000_000_000)?)
        })();
        if let Err(e) = check {
            for input in inputs.iter_mut() {
                let _ = input.quarantine();
            }
            let _ = output.quarantine();
            return Err(e);
        }
        Ok(Self {
            c,
            schedule,
            guard,
            inputs: Some(inputs),
            output: Some(output),
            frames: std::array::from_fn(|_| None),
            tags: BTreeSet::new(),
            count: 0,
            cursor: 0,
            failed: false,
            observation: None,
            cancel_queued: false,
            cancel_complete: false,
            cancel_observation: None,
            #[cfg(test)]
            cancel_bytes: None,
        })
    }
    fn stop(&mut self) {
        self.stop_inputs();
        if let Some(output) = self.output.take() {
            let _ = output.quarantine();
        }
    }
    fn stop_inputs(&mut self) {
        self.failed = true;
        self.frames = std::array::from_fn(|_| None);
        self.tags.clear();
        if let Some(inputs) = self.inputs.take() {
            for input in inputs {
                let _ = input.quarantine();
            }
        }
    }
    /// Advance at most one actual socket step, with a source index only at A.
    /// Continue polling after count32 until freeze to detect extra bytes/EOF.
    pub fn poll(&mut self) -> Result<bool> {
        let result = self.poll_inner();
        if result.is_err() {
            // Before freeze A has emitted no C train. Keep only its original
            // output link for one fixed failure control; Drop still closes it.
            self.stop_inputs();
        }
        result
    }
    /// A pre-train ingress failure can send one context-only signed CANCEL on
    /// the original C link in the existing A_READY slot. No client data, frame,
    /// manifest replacement, or retry capability survives the failed poll.
    pub fn poll_cancel(&mut self, signing: &SigningKey) -> Result<bool> {
        if !self.failed || self.cancel_complete {
            return Err(Error::Unavailable("IM3 A CANCEL state"));
        }
        let result = (|| {
            self.guard.check(self.schedule)?;
            let start = self.schedule.at(15_750_000_000)?;
            let end = self.schedule.at(16_000_000_000)?;
            if Instant::now() < start {
                return Ok(false);
            }
            before(end)?;
            let output = self
                .output
                .as_deref_mut()
                .ok_or(Error::Unavailable("IM3 A original C link absent"))?;
            if !self.cancel_queued {
                if output.receive_progress() != ReceiveProgress::Idle
                    || output.selected_read().is_some()
                {
                    return Err(Error::Unavailable("IM3 A CANCEL link unusable"));
                }
                let cancel =
                    control::sign(self.c, Im3Kind::Cancel, Im3Role::A, [[0; 32]; 7], signing)?;
                output.queue(RecordSize::Control, cancel.bytes(), end)?;
                #[cfg(test)]
                {
                    self.cancel_bytes = Some(*cancel.bytes());
                }
                self.cancel_queued = true;
            }
            let (written, observation) = output.write_step_observed();
            self.cancel_observation = Some(observation);
            if written? {
                self.cancel_complete = true;
                return Ok(true);
            }
            Ok(false)
        })();
        if result.is_err() {
            self.stop();
        }
        result
    }
    /// Actual A-to-C socket write interval, if a CANCEL write was attempted.
    pub fn take_cancel_wire_observation(&mut self) -> Option<WireObservation> {
        self.cancel_observation.take()
    }
    /// Test-only A-owned exact local control, available only after the real
    /// owner queued it. A write observation is still required to claim send.
    #[cfg(test)]
    pub(super) fn fixture_queued_cancel(&self) -> Option<&[u8; 512]> {
        self.cancel_bytes.as_ref()
    }
    fn poll_inner(&mut self) -> Result<bool> {
        if self.failed {
            return Err(Error::Unavailable("IM3 ingress closed"));
        }
        self.guard.check(self.schedule)?;
        before(self.schedule.at(15_000_000_000)?)?;
        let i = self.cursor;
        self.cursor = (self.cursor + 1) % 32;
        let input = &mut self
            .inputs
            .as_deref_mut()
            .ok_or(Error::Unavailable("IM3 ingress original links"))?[usize::from(i)];
        if self.frames[usize::from(i)].is_some() {
            if input.has_extra_bytes()? {
                return Err(Error::Invalid("IM3 extra client input"));
            }
        } else if Instant::now()
            < self.schedule.client_slot(i)?.0 - std::time::Duration::from_secs(1)
        {
            if input.has_extra_bytes()? {
                return Err(Error::Invalid("IM3 premature client bytes"));
            }
        } else {
            let (result, observation) = input.read_step_observed();
            self.observation = Some((i, observation));
            if let Some(bytes) = result? {
                let frame = MiddleFrame::decode(&bytes, self.c, 1)?;
                if !self.tags.insert(frame.tag()) {
                    return Err(Error::Invalid("IM3 duplicate A input"));
                }
                self.frames[usize::from(i)] = Some(frame);
                self.count += 1;
            }
        }
        self.guard.check(self.schedule)?;
        before(self.schedule.at(15_000_000_000)?)?;
        Ok(self.count == 32)
    }
    /// Last original read interval, explicitly source-associated at A only.
    pub fn take_wire_observation(&mut self) -> Option<(u8, WireObservation)> {
        self.observation.take()
    }
    // Administrative test view only: bytes received on this original source,
    // before any permutation. No callable production export is added.
    #[cfg(test)]
    pub(super) fn fixture_original(&self, source: u8) -> &[u8; FRAME_BYTES] {
        assert!(!self.failed && self.count == 32);
        self.frames[usize::from(source)].as_ref().unwrap().bytes()
    }
    /// Test-only A-owned source read before the failed owner clears its batch.
    /// Absence has no substitute from the client's unsent onion.
    #[cfg(test)]
    pub(super) fn fixture_received_original(&self, source: u8) -> Option<&[u8; FRAME_BYTES]> {
        self.frames.get(usize::from(source))?.as_ref().map(MiddleFrame::bytes)
    }
    /// At T+15, freeze all32, open only A layers, privately permute the full
    /// batch, and create the sole signed A_READY/train owner. Nothing partial
    /// escapes if any opening, signature, cutoff or native lease check fails.
    pub fn freeze(mut self, hpke: &HpkePrivate, signing: &SigningKey) -> Result<IngressTrain<'t>> {
        self.schedule.require(self.guard, Phase::AFreeze)?;
        if self.failed || self.count != 32 {
            return Err(Error::Invalid("IM3 incomplete A ingress"));
        }
        for input in self
            .inputs
            .as_deref()
            .ok_or(Error::Unavailable("IM3 ingress original links"))?
        {
            if input.receive_progress() != ReceiveProgress::Idle || input.has_extra_bytes()? {
                return Err(Error::Invalid("IM3 frozen extra/partial client input"));
            }
        }
        let mut frames = Vec::with_capacity(32);
        for frame in &mut self.frames {
            frames.push(open_at_a(
                self.c,
                hpke,
                &frame.take().ok_or(Error::Invalid("IM3 A input omitted"))?,
            )?);
            self.schedule.require(self.guard, Phase::AFreeze)?;
        }
        let mut frames: [MiddleFrame; 32] = frames
            .try_into()
            .map_err(|_| Error::Invalid("IM3 A complete count"))?;
        permute_at_a(self.c, &mut frames)?;
        let hash = self.c.batch_hash("SilkNode-IM3-A-batch", &frames);
        let ready = control::sign(
            self.c,
            Im3Kind::AReady,
            Im3Role::A,
            [hash, [0; 32], [0; 32], [0; 32], [0; 32], [0; 32], [0; 32]],
            signing,
        )?;
        self.schedule.require(self.guard, Phase::AFreeze)?;
        Ok(IngressTrain {
            schedule: self.schedule,
            guard: self.guard,
            inputs: self.inputs.take(),
            output: self.output.take(),
            frames,
            ready,
            index: 0,
            queued: false,
            ready_done: false,
            hold_cursor: 0,
            cleaned_up: false,
            failed: false,
            observation: None,
        })
    }
}
impl Drop for ReceivingIngressOwner<'_, '_, '_> {
    fn drop(&mut self) {
        self.stop();
    }
}
/// Only complete original A ingress constructs this fixed-slot C train. No
/// frame/readiness export or new socket can manufacture a partial output.
pub struct IngressTrain<'t> {
    pub(super) schedule: &'t Im3Schedule,
    pub(super) guard: &'t Im3Guard,
    inputs: Option<&'t mut [Transport; 32]>,
    output: Option<&'t mut Transport>,
    frames: [MiddleFrame; 32],
    pub(super) ready: Im3Control,
    index: u8,
    queued: bool,
    ready_done: bool,
    hold_cursor: u8,
    cleaned_up: bool,
    failed: bool,
    observation: Option<WireObservation>,
}
impl IngressTrain<'_> {
    // Test-only A-owned observation: exact stage2 frames in the order A sends
    // to C. The source-ordered post-open view alone omits A's own permutation.
    #[cfg(test)]
    pub(super) fn fixture_outgoing_frames(&self) -> Vec<u8> {
        assert!(!self.failed && self.index == 0);
        self.frames
            .iter()
            .flat_map(|frame| frame.bytes().iter().copied())
            .collect()
    }
    pub(super) fn stop(&mut self) {
        self.failed = true;
        if let Some(inputs) = self.inputs.take() {
            for input in inputs {
                let _ = input.quarantine();
            }
        }
        if let Some(output) = self.output.take() {
            let _ = output.quarantine();
        }
    }
    /// Exact full ordered input commitment, not a per-source map.
    pub fn batch_hash(&self) -> Digest {
        self.ready.field(116)
    }
    /// One original write step in its exact 7.8125ms data slot, then the single
    /// original signed A_READY in [15.75,16). Never catch up missed slots.
    pub fn poll(&mut self) -> Result<bool> {
        let result = self.poll_inner();
        if result.is_err() {
            self.stop();
        }
        result
    }
    fn poll_inner(&mut self) -> Result<bool> {
        if self.failed {
            return Err(Error::Unavailable("IM3 A train closed"));
        }
        self.guard.check(self.schedule)?;
        if self.ready_done {
            return Ok(true);
        }
        let (start, end) = if self.index < 32 {
            self.schedule.relay_slot(false, self.index)?
        } else {
            (
                self.schedule.at(15_750_000_000)?,
                self.schedule.at(16_000_000_000)?,
            )
        };
        if Instant::now() < start {
            return Ok(false);
        }
        before(end)?;
        let output = self
            .output
            .as_deref_mut()
            .ok_or(Error::Unavailable("IM3 A original C link"))?;
        if !self.queued {
            if self.index < 32 {
                output.queue(
                    RecordSize::Cell,
                    self.frames[usize::from(self.index)].bytes(),
                    end,
                )?;
            } else {
                output.queue(RecordSize::Control, self.ready.bytes(), end)?;
            }
            self.queued = true;
        }
        let (result, observation) = output.write_step_observed();
        self.observation = Some(observation);
        if result? {
            self.guard.check(self.schedule)?;
            before(end)?;
            self.queued = false;
            if self.index < 32 {
                self.index += 1;
            } else {
                self.ready_done = true;
            }
        }
        Ok(self.ready_done)
    }
    /// Last actual original-link write interval; no input/output permutation.
    pub fn take_wire_observation(&mut self) -> Option<WireObservation> {
        self.observation.take()
    }
    pub(super) fn poll_hold(&mut self) -> Result<()> {
        if self.failed || !self.ready_done {
            return Err(Error::Unavailable("IM3 A hold before train"));
        }
        self.guard.check(self.schedule)?;
        let inputs = self
            .inputs
            .as_deref()
            .ok_or(Error::Unavailable("IM3 A held inputs absent"))?;
        let i = usize::from(self.hold_cursor);
        self.hold_cursor = (self.hold_cursor + 1) % 32;
        if inputs[i].has_extra_bytes()?
            || self
                .output
                .as_deref()
                .ok_or(Error::Unavailable("IM3 A held C link absent"))?
                .has_extra_bytes()?
        {
            return Err(Error::Invalid("IM3 A held original stream extra bytes"));
        }
        Ok(())
    }
    /// Hold original links until T+44; a premature drop closes them as failure.
    pub fn poll_cleanup(&mut self) -> Result<bool> {
        let result = (|| {
            if self.failed || !self.ready_done {
                return Err(Error::Unavailable("IM3 A cleanup before train"));
            }
            if self.cleaned_up {
                return Ok(true);
            }
            self.guard.check(self.schedule)?;
            if Instant::now() < self.schedule.at(44_000_000_000)? {
                return Ok(false);
            }
            self.cleaned_up = true;
            if let Some(inputs) = self.inputs.take() {
                for input in inputs {
                    input.quarantine()?;
                }
            }
            if let Some(output) = self.output.take() {
                output.quarantine()?;
            }
            Ok(true)
        })();
        if result.is_err() {
            self.stop();
        }
        result
    }
}
impl Drop for IngressTrain<'_> {
    fn drop(&mut self) {
        self.stop();
    }
}
