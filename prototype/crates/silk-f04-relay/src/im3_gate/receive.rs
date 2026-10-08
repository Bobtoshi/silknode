//! Original incoming C stream. Raw data/readiness admission is not exported.
use super::*;
use crate::tls::{ReceiveProgress, WireObservation};
use ed25519_dalek::SigningKey;

/// A single original A-to-C TLS connection and B output connection, one native
/// lease and one consumed durable round. No external frame injection or link
/// replacement is possible. TLS authenticates C to A; A_READY's application
/// signature binds the input stream to A, not a TLS client certificate.
pub struct ReceivingMiddleOwner<'c, 'a, 's, 't, P: ClaimPinRetention> {
    owner: TimedMiddleOwner<'c, 'a, 's, 't, P>,
    input: &'t mut Transport,
    count: u8,
    ready: bool,
    failed: bool,
    cancel_queued: bool,
    cancel_complete: bool,
    observation: Option<WireObservation>,
}
impl<'c, 'a, 's, 't, P: ClaimPinRetention> ReceivingMiddleOwner<'c, 'a, 's, 't, P> {
    /// Bind both already-established exact links and arm the complete input
    /// stream before T-5, hence before the T+14.5 early receive envelope. This
    /// creates no service and confers no independent clock/role qualification.
    pub(crate) fn begin(
        c: &'c MiddleContext<'a>,
        store: &'s mut PreparedScopeStore<P>,
        schedule: &'t Im3Schedule,
        guard: &'t Im3Guard,
        input: &'t mut Transport,
        output: &'t mut Transport,
    ) -> Result<Self> {
        input.check_endpoint(c.q.endpoint(), false)?;
        if input.receive_progress() != ReceiveProgress::Idle || input.selected_read().is_some() {
            return Err(Error::Unavailable("IM3 incoming stream already selected"));
        }
        let owner = TimedMiddleOwner::begin(c, store, schedule, guard, output)?;
        Self::from_claimed(owner, input)
    }
    pub(super) fn from_claimed(
        mut owner: TimedMiddleOwner<'c, 'a, 's, 't, P>,
        input: &'t mut Transport,
    ) -> Result<Self> {
        let preflight = (|| {
            owner.guard.check(owner.schedule)?;
            before(owner.schedule.at(-5_000_000_000)?)?;
            input.check_endpoint(owner.owner.c.q.endpoint(), false)?;
            if input.receive_progress() != ReceiveProgress::Idle
                || input.selected_read().is_some()
                || input.has_extra_bytes()?
            {
                return Err(Error::Unavailable("IM3 claimed input not idle"));
            }
            Ok(())
        })();
        if let Err(e) = preflight {
            let _ = input.quarantine();
            let _ = owner.output.quarantine();
            return Err(e);
        }
        if let Err(error) = input.expect(RecordSize::Cell, owner.schedule.at(17_500_000_000)?) {
            owner.owner.failed = true;
            let _ = input.quarantine();
            let _ = owner.output.quarantine();
            return Err(error);
        }
        Ok(Self {
            owner,
            input,
            count: 0,
            ready: false,
            failed: false,
            cancel_queued: false,
            cancel_complete: false,
            observation: None,
        })
    }
    /// Last actual socket read step, not arming, queue time or packet arrival.
    pub fn take_wire_observation(&mut self) -> Option<WireObservation> {
        self.observation.take()
    }
    /// Advance one original socket read. True means only the exact 32 frames
    /// and one signed readiness have completed; it grants no B output. Continue
    /// polling through the cutoff to detect extra records. EOF, partial input at
    /// cutoff, wrong record class/context, duplicate input or readiness aborts.
    pub fn poll(&mut self) -> Result<bool> {
        if self.failed {
            return Err(Error::Unavailable("IM3 incoming owner closed"));
        }
        let result = self.poll_inner();
        if result.is_err() {
            self.failed = true;
            self.owner.owner.failed = true;
            let _ = self.input.quarantine();
            // Retain only the original untouched B link for its fixed
            // failure-control window. No data or READY capability survives.
            if self.owner.output.selected_read().is_some()
                || !matches!(self.owner.output.receive_progress(), ReceiveProgress::Idle)
            {
                let _ = self.owner.output.quarantine();
            }
        }
        result
    }
    /// A failed pre-disclosure C owner may send one context-only signed CANCEL
    /// on its original B link in [20.25,20.5). An unusable/partial link stays
    /// silent. This never reopens the consumed scope or creates B output.
    pub fn poll_cancel(&mut self, signing: &SigningKey) -> Result<bool> {
        if !self.failed || self.cancel_complete {
            return Err(Error::Unavailable("IM3 C CANCEL state"));
        }
        let result = (|| {
            self.owner.guard.check(self.owner.schedule)?;
            let (start, end) = self.owner.schedule.window(Phase::CReady)?;
            if Instant::now() < start {
                return Ok(false);
            }
            before(end)?;
            if !self.cancel_queued {
                if self.owner.output.receive_progress() != ReceiveProgress::Idle
                    || self.owner.output.selected_read().is_some()
                {
                    return Err(Error::Unavailable("IM3 C CANCEL link unusable"));
                }
                let control = super::control::sign(
                    self.owner.owner.c,
                    Im3Kind::Cancel,
                    Im3Role::C,
                    [[0; 32]; 7],
                    signing,
                )?;
                self.owner
                    .output
                    .queue(RecordSize::Control, control.bytes(), end)?;
                self.cancel_queued = true;
            }
            let (written, observation) = self.owner.output.write_step_observed();
            self.observation = Some(observation);
            if written? {
                self.cancel_complete = true;
                return Ok(true);
            }
            Ok(false)
        })();
        if result.is_err() {
            let _ = self.owner.output.quarantine();
        }
        result
    }
    fn poll_inner(&mut self) -> Result<bool> {
        self.owner.guard.check(self.owner.schedule)?;
        if self.ready {
            if self.input.has_extra_bytes()? {
                return Err(Error::Invalid("IM3 extra incoming record"));
            }
            return Ok(true);
        }
        before(self.owner.schedule.at(17_500_000_000)?)?;
        let early = if self.count < 32 {
            14_500_000_000 + 7_812_500 * i64::from(self.count)
        } else {
            14_750_000_000
        };
        if Instant::now() < self.owner.schedule.at(early)? {
            if self.input.has_extra_bytes()? {
                return Err(Error::Invalid("IM3 premature incoming bytes"));
            }
            return Ok(false);
        }
        // Before any data train, A may fail its complete client ingress and
        // send only a signed context-only CANCEL in its original READY slot.
        // A 1..4-byte TLS header remains untouched until it can be classified;
        // no partially consumed Cell can be retired or assigned a new cutoff.
        if self.count == 0
            && Instant::now() >= self.owner.schedule.at(15_750_000_000)?
            && Instant::now() < self.owner.schedule.at(16_000_000_000)?
            && self
                .input
                .selected_read()
                .is_some_and(|(size, _)| size == RecordSize::Cell)
            && self.input.receive_progress() == ReceiveProgress::WaitingZeroBytes
        {
            match self.input.peek_record_size()? {
                None => return Ok(false),
                Some(RecordSize::Control) => {
                    let (_, cutoff) = self
                        .input
                        .selected_read()
                        .ok_or(Error::Unavailable("IM3 A selection absent"))?;
                    self.input.retire_empty(RecordSize::Cell)?;
                    self.input.expect(RecordSize::Control, cutoff)?;
                }
                Some(RecordSize::Cell) => {}
                Some(_) => return Err(Error::Invalid("IM3 unexpected A record class")),
            }
        }
        let (result, observation) = self.input.read_step_observed();
        self.observation = Some(observation);
        if let Some(bytes) = result? {
            if self.count == 0 && bytes.len() == RecordSize::Control.bytes() {
                let cancel = Im3Control::verify(&bytes, self.owner.owner.c)?;
                if cancel.kind() != Im3Kind::Cancel
                    || cancel.role() != Im3Role::A
                    || Instant::now() < self.owner.schedule.at(15_750_000_000)?
                    || Instant::now() >= self.owner.schedule.at(16_000_000_000)?
                {
                    return Err(Error::Invalid("IM3 A CANCEL window/role"));
                }
                return Err(Error::Unavailable("IM3 A cancelled"));
            }
            if self.count < 32 {
                self.owner.admit(&bytes)?;
                self.count += 1;
                self.input.expect(
                    if self.count == 32 {
                        RecordSize::Control
                    } else {
                        RecordSize::Cell
                    },
                    self.owner.schedule.at(17_500_000_000)?,
                )?;
            } else {
                self.owner.admit_ready(&bytes)?;
                self.ready = true;
            }
        }
        Ok(self.ready)
    }
    /// Freeze only after the input cutoff, on the same native lease. Incomplete
    /// or extra input cannot be repaired by supplying bytes or readiness here.
    /// The complete gate remains mandatory before a disclosure capability exists.
    pub fn verify(
        self,
        key: &HpkePrivate,
        verifier: &PreparedProofVerifier,
    ) -> Result<TimedMiddleVerified<'s, 't, P>> {
        match self.verify_or_cancel(key, verifier) {
            Ok(verified) => Ok(verified),
            Err((error, mut failed)) => {
                failed.close();
                Err(error)
            }
        }
    }
    /// A failed complete C gate retains only a one-way CANCEL capability on
    /// the original B link. The consumed claim, input cells, proofs and
    /// permutation never re-enter this state. Callers must drive this only in
    /// the existing C control window; silence is the fallback.
    pub fn verify_or_cancel(
        mut self,
        key: &HpkePrivate,
        verifier: &PreparedProofVerifier,
    ) -> std::result::Result<TimedMiddleVerified<'s, 't, P>, (Error, FailedMiddleCancel<'c, 'a, 't>)>
    {
        let preflight = (|| {
            self.owner
                .schedule
                .require(self.owner.guard, Phase::CGate)?;
            if self.failed
                || !self.ready
                || self.count != 32
                || self.input.receive_progress() != ReceiveProgress::Idle
                || self.input.has_extra_bytes()?
            {
                return Err(Error::Invalid("IM3 incomplete/extra frozen stream"));
            }
            Ok(())
        })();
        if preflight.is_err() {
            self.owner.owner.failed = true;
            let _ = self.input.quarantine();
        }
        let TimedMiddleOwner {
            owner,
            schedule,
            guard,
            output,
            ready,
        } = self.owner;
        let c = owner.c;
        let result = match preflight {
            Err(error) => Err(error),
            Ok(()) => (|| {
                schedule.require(guard, Phase::CGate)?;
                let ready = ready.ok_or(Error::Invalid("IM3 readiness absent at freeze"))?;
                let verified = owner.verify_complete(
                    key,
                    verifier,
                    ready,
                    schedule.window(Phase::CGate)?.1,
                )?;
                schedule.require(guard, Phase::CGate)?;
                Ok(verified)
            })(),
        };
        match result {
            Ok(verified) => Ok(TimedMiddleVerified {
                verified,
                schedule,
                guard,
                output,
            }),
            Err(error) => {
                let _ = self.input.quarantine();
                Err((
                    error,
                    FailedMiddleCancel {
                        c,
                        schedule,
                        guard,
                        output,
                        queued: false,
                        complete: false,
                        observation: None,
                    },
                ))
            }
        }
    }
}

/// Only a failed, consumed, pre-disclosure C gate can construct this one-way
/// capability. It cannot recover inputs, emit data cells or make a second
/// disclosure decision.
pub struct FailedMiddleCancel<'c, 'a, 't> {
    c: &'c MiddleContext<'a>,
    schedule: &'t Im3Schedule,
    guard: &'t Im3Guard,
    output: &'t mut Transport,
    queued: bool,
    complete: bool,
    observation: Option<WireObservation>,
}
impl FailedMiddleCancel<'_, '_, '_> {
    /// Write only a canonical signed C CANCEL in the original fixed window.
    pub fn poll(&mut self, signing: &SigningKey) -> Result<bool> {
        if self.complete {
            return Err(Error::Unavailable("IM3 C CANCEL complete"));
        }
        let result = (|| {
            self.guard.check(self.schedule)?;
            let (start, end) = self.schedule.window(Phase::CReady)?;
            if Instant::now() < start {
                return Ok(false);
            }
            before(end)?;
            if !self.queued {
                if self.output.receive_progress() != ReceiveProgress::Idle
                    || self.output.selected_read().is_some()
                {
                    return Err(Error::Unavailable("IM3 C CANCEL link unusable"));
                }
                let control = super::control::sign(
                    self.c,
                    Im3Kind::Cancel,
                    Im3Role::C,
                    [[0; 32]; 7],
                    signing,
                )?;
                self.output
                    .queue(RecordSize::Control, control.bytes(), end)?;
                self.queued = true;
            }
            let (written, observation) = self.output.write_step_observed();
            self.observation = Some(observation);
            if written? {
                self.complete = true;
                return Ok(true);
            }
            Ok(false)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Actual C-to-B socket write observation, if a write was attempted.
    pub fn take_wire_observation(&mut self) -> Option<WireObservation> {
        self.observation.take()
    }
    fn close(&mut self) {
        let _ = self.output.quarantine();
    }
}
impl Drop for FailedMiddleCancel<'_, '_, '_> {
    fn drop(&mut self) {
        self.close();
    }
}
