//! Default-off bounded dispatcher for successive original-link IM3 rounds.
//! Provider calls are explicit assumptions, not independent qualification.
use super::*;
use crate::{
    im3_schedule::{Im3Guard, Im3Schedule},
    schedule::QualifiedClockSample,
    tls::Transport,
};
use ed25519_dalek::SigningKey;
use std::path::Path;

/// The only public construction port for original-link role owners. It is
/// issued inside a consumed runner round and cannot outlive its driver call.
pub struct Im3RoundPorts<'c, 'a, 't> {
    context: &'c MiddleContext<'a>,
    schedule: &'t Im3Schedule,
    guard: &'t Im3Guard,
}
impl<'c, 'a, 't> Im3RoundPorts<'c, 'a, 't> {
    /// Exact signed round context.
    pub fn context(&self) -> &'c MiddleContext<'a> {
        self.context
    }
    /// Immutable deadlines; this does not certify external clock quality.
    pub fn schedule(&self) -> &'t Im3Schedule {
        self.schedule
    }
    /// Pre-round original A manifest fanout.
    pub fn manifest_fanout<'s, P: ClaimPinRetention>(
        &self,
        store: &'s mut PreparedScopeStore<P>,
        inputs: &'t mut [Transport; 32],
        output: &'t mut Transport,
    ) -> Result<ManifestFanout<'c, 'a, 's, 't, P>> {
        ManifestFanout::begin(
            self.context,
            store,
            self.schedule,
            self.guard,
            inputs,
            output,
        )
    }
    /// Pre-round original C manifest receive.
    pub fn manifest_middle<'s, P: ClaimPinRetention>(
        &self,
        store: &'s mut PreparedScopeStore<P>,
        input: &'t mut Transport,
        output: &'t mut Transport,
    ) -> Result<ManifestReceivingMiddle<'c, 'a, 's, 't, P>> {
        ManifestReceivingMiddle::begin(
            self.context,
            store,
            self.schedule,
            self.guard,
            input,
            output,
        )
    }
    /// Original A client ingress after manifest handoff.
    pub fn ingress(
        &self,
        inputs: &'t mut [Transport; 32],
        output: &'t mut Transport,
    ) -> Result<ReceivingIngressOwner<'c, 'a, 't>> {
        ReceivingIngressOwner::begin(self.context, self.schedule, self.guard, inputs, output)
    }
    /// Original C stream and B output.
    pub fn middle<'s, P: ClaimPinRetention>(
        &self,
        store: &'s mut PreparedScopeStore<P>,
        input: &'t mut Transport,
        output: &'t mut Transport,
    ) -> Result<ReceivingMiddleOwner<'c, 'a, 's, 't, P>> {
        ReceivingMiddleOwner::begin(
            self.context,
            store,
            self.schedule,
            self.guard,
            input,
            output,
        )
    }
    /// Original B stream from C.
    pub fn exit<'s, P: ClaimPinRetention>(
        &self,
        store: &'s mut PreparedScopeStore<P>,
        input: &'t mut Transport,
    ) -> Result<ReceivingExitOwner<'c, 'a, 's, 't, P>> {
        ReceivingExitOwner::begin(self.context, store, self.schedule, self.guard, input)
    }
    /// A's original B control reservation.
    pub fn authorization<'s, P: ClaimPinRetention>(
        &self,
        store: &'s mut PreparedScopeStore<P>,
        link: Transport,
        signing: &'t SigningKey,
    ) -> Result<IngressControlReservation<'c, 'a, 's, 't, P>> {
        IngressControlReservation::begin(
            self.context,
            store,
            self.schedule,
            self.guard,
            link,
            signing,
        )
    }
    /// B's original A/three-producer control reservation.
    pub fn release<'s, P: ClaimPinRetention>(
        &self,
        store: &'s mut PreparedScopeStore<P>,
        links: [Transport; 4],
        signing: &'t SigningKey,
    ) -> Result<ExitControlReservation<'c, 'a, 's, 't, P>> {
        ExitControlReservation::begin(
            self.context,
            store,
            self.schedule,
            self.guard,
            links,
            signing,
        )
    }
    /// One original producer link and role-specific durable claim.
    pub fn producer<'s, P: ClaimPinRetention>(
        &self,
        store: &'s mut PreparedScopeStore<P>,
        link: Transport,
        role: Im3Role,
        signing: &'t SigningKey,
    ) -> Result<Im3ProducerOwner<'c, 'a, 's, 't, P>> {
        Im3ProducerOwner::begin(
            self.context,
            store,
            self.schedule,
            self.guard,
            link,
            role,
            signing,
        )
    }
    #[cfg(test)]
    pub(super) fn parts(&self) -> (&MiddleContext<'_>, &Im3Schedule, &Im3Guard) {
        (self.context, self.schedule, self.guard)
    }
}

/// Operator-supplied role/path/capacity decision for an exact immutable round.
/// An implementation's assertion is not independent evidence of qualification.
pub trait Im3RoleAdmission {
    /// Refuse before the durable sequence claim or any owner is dispatched.
    fn admit(&mut self, context: &MiddleContext<'_>) -> Result<()>;
}

/// Operator-supplied bounded wall/monotonic observation for this exact round.
/// The caller remains responsible for the external clock/path premises.
pub trait Im3ClockSource {
    /// Produce a fresh sample, rather than rebasing an earlier round's lease.
    fn sample(&mut self, context: &MiddleContext<'_>) -> Result<QualifiedClockSample>;
}

/// One closure result after all its original-link owners have left scope.
/// An error or panic leaves the claim pending; a release requires B's opaque
/// completed-owner receipt. Abort is reason-free and carries no old links.
pub enum Im3RoundTerminal {
    /// All role owners and original links were closed by the driver.
    Abort,
    /// Actual B release train and T+44 cleanup completed.
    Release(CompletedExit),
}

/// Long-lived local dispatcher for one immutable P/epoch. The existing claim
/// retention implementation owns external-pin publication; `open` still needs
/// an independently retained pin and trusted restart round from its caller.
/// This does not create a network listener, service, or trusted administrator.
pub struct Im3RoundRunner<P: ClaimPinRetention, A: Im3RoleAdmission, C: Im3ClockSource> {
    sequence: Im3RoundSequence<P>,
    admission: A,
    clock: C,
}
impl<P: ClaimPinRetention, A: Im3RoleAdmission, C: Im3ClockSource> Im3RoundRunner<P, A, C> {
    /// Create a fresh sequence directory; no round is consumed yet.
    pub fn create(
        path: &Path,
        profile: &PreparedProfile,
        pins: P,
        admission: A,
        clock: C,
    ) -> Result<Self> {
        Ok(Self {
            sequence: Im3RoundSequence::create(path, profile, pins)?,
            admission,
            clock,
        })
    }

    /// Cold reopen never resumes a previous worker or original link.
    pub fn open(
        path: &Path,
        profile: &PreparedProfile,
        expected_pin: Digest,
        trusted_restart_round: u64,
        pins: P,
        admission: A,
        clock: C,
    ) -> Result<Self> {
        Ok(Self {
            sequence: Im3RoundSequence::open(
                path,
                profile,
                expected_pin,
                trusted_restart_round,
                pins,
            )?,
            admission,
            clock,
        })
    }

    /// Snapshot hash is not proof of independent pin custody.
    pub fn pin(&self) -> Digest {
        self.sequence.pin()
    }

    /// Durable floor, not external role or clock qualification.
    pub fn earliest_round(&self) -> u64 {
        self.sequence.earliest_round()
    }

    /// Dispatch one exact round only after admission, fresh sample, native
    /// guard and durable consumption. The closure cannot return borrowed role
    /// owners; an error leaves the round pending and blocks hot progression.
    /// Successful terminal publication follows owner scope exit, not merely
    /// a reported poll result. The driver must use the supplied original links.
    pub fn run_round<F>(&mut self, context: &MiddleContext<'_>, drive: F) -> Result<()>
    where
        F: FnOnce(&Im3RoundPorts<'_, '_, '_>) -> Result<Im3RoundTerminal>,
    {
        self.admission.admit(context)?;
        let sample = self.clock.sample(context)?;
        let schedule = Im3Schedule::new(
            context.r2.round.config,
            context.r2.round.manifest.round(),
            sample,
        )?;
        let mut guard = Im3Guard::arm(&schedule)?;
        let attempt = self.sequence.begin(context, &schedule, &mut guard)?;
        let terminal = {
            let (bound, mapped, native) = attempt.parts();
            drive(&Im3RoundPorts {
                context: bound,
                schedule: mapped,
                guard: native,
            })?
        };
        match terminal {
            Im3RoundTerminal::Abort => attempt.abort(),
            Im3RoundTerminal::Release(receipt) => attempt.finish_release(receipt),
        }
    }
}
