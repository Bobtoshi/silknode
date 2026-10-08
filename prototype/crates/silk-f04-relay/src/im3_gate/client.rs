//! Default-off local two-proof preparation owner, not a network client or
//! operational admission. No proof backend, remote witness, retry or recovery.
use super::*;
use crate::{
    frame::Payload,
    im3_schedule::{Im3Schedule, Phase},
    negotiation::SelectedCut,
};

/// Public statement for exactly one trusted LOCAL proof job. No witness, path,
/// payment or inner ciphertext is exported. Not Clone/Deserialize/resumable.
pub struct ClientProofJob {
    /// Exact root, message and domain-separated scope, in that order.
    pub statement: [Digest; 3],
    /// Original absolute cutoff; late dispatch never renews five seconds.
    pub deadline: Instant,
}
/// Untrusted proof output. The owner constructs and verifies all four inputs.
pub struct ClientProofOutput {
    /// Proof-derived canonical nullifier.
    pub nullifier: Digest,
    /// Exact native proof packing.
    pub proof: [u8; 256],
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Admitted,
    Frozen,
    BRunning,
    BVerified,
    BSealed,
    CRunning,
    CVerified,
    Ready,
    Failed,
}

/// One immutable M/Q/payload and one common P/round claim before either job.
/// Owns sequential dispatch and genuine verification, never a relay CPU lease.
/// The trusted runner must separately contain each worker to <=5 wall seconds,
/// <=4 CPU seconds and 1 GiB RSS with one preloaded bundle. This API does not
/// certify that containment, external clock/path premises or wallet exposure.
pub struct PreparedClientOwner<'c, 'a, 's, P: ClaimPinRetention> {
    c: &'c MiddleContext<'a>,
    schedule: &'c Im3Schedule,
    verifier: &'c PreparedProofVerifier,
    _cut: SelectedCut<'a>,
    store: Option<&'s mut PreparedScopeStore<P>>,
    claim: Option<ConsumedScope<'s, P>>,
    cell: Option<Box<Zeroizing<[u8; 4096]>>>,
    pending: Option<PendingMiddle<'c, 'a, 's, P>>,
    output: Option<ClientProofOutput>,
    frame: Option<MiddleFrame>,
    inputs: [Digest; 3],
    choice: Digest,
    state: State,
}
impl<'c, 'a, 's, P: ClaimPinRetention> PreparedClientOwner<'c, 'a, 's, P> {
    /// Admit actual locally selected cut before T-5, retaining its immutable
    /// node/genesis authority. Real payload must already be wallet-exposed;
    /// passing a Payload does not grant exposure or profile acceptance.
    pub fn admit(
        c: &'c MiddleContext<'a>,
        schedule: &'c Im3Schedule,
        cut: SelectedCut<'a>,
        verifier: &'c PreparedProofVerifier,
        store: &'s mut PreparedScopeStore<P>,
        payload: Payload,
    ) -> Result<Self> {
        schedule.client_before_choice()?;
        if schedule.round() != c.r2.round.manifest.round()
            || store.binding() != c.profile.claim_binding(ClaimRole::Client)
            || verifier.key_hash() != store.binding().vk_hash
        {
            return Err(Error::Invalid("IM3 client original context"));
        }
        cut.admit_im3_signed(c.r2.round.manifest.bytes(), c.r2.round.config, schedule)?;
        payload.validate(&c.r2.round)?;
        let s = crate::aip2_proof::prepare_cover_statement(
            c.profile,
            c.r2.round.manifest.id(),
            schedule.round(),
        )
        .map_err(|_| Error::Invalid("IM3 client B statement"))?;
        let mut cell = Box::new(Zeroizing::new(*s.cell()));
        if let Some(bytes) = payload.real_bytes() {
            cell[8] = 1;
            cell[416..3206].copy_from_slice(bytes);
        }
        let msg = c.r2.check_cell(&cell)?;
        let choice = domain_hash(
            "SilkNode-IM3-client-choice",
            &[&c.q.id(), &c.r2.round.manifest.id(), &msg],
        );
        schedule.client_before_choice()?;
        Ok(Self {
            c,
            schedule,
            verifier,
            _cut: cut,
            store: Some(store),
            claim: None,
            cell: Some(cell),
            pending: None,
            output: None,
            frame: None,
            inputs: [s.root(), msg, s.scope()],
            choice,
            state: State::Admitted,
        })
    }
    fn stop(&mut self) {
        self.state = State::Failed;
        self.cell = None;
        self.pending = None;
        self.output = None;
        self.frame = None;
        self.claim = None;
        self.store = None;
    }
    // Latch before every fallible operation, including duplicate/out-of-order
    // calls. Any failure destroys preparation and can never select cover/retry.
    fn enter(&mut self, expected: State, phase: Phase) -> Result<()> {
        let old = std::mem::replace(&mut self.state, State::Failed);
        if old != expected {
            self.stop();
            return Err(Error::Unavailable("IM3 client one-shot state"));
        }
        if let Err(e) = self.schedule.require_client(phase) {
            self.stop();
            return Err(e);
        }
        Ok(())
    }
    fn finish<T>(&mut self, result: Result<T>, next: State, phase: Phase) -> Result<T> {
        let result = result.and_then(|value| {
            self.schedule.require_client(phase)?;
            Ok(value)
        });
        match result {
            Ok(v) => {
                self.state = next;
                Ok(v)
            }
            Err(e) => {
                self.stop();
                Err(e)
            }
        }
    }
    /// Durably bind Q/M/Bmsg in the existing common P/round journal. No proof
    /// statement leaves this owner until both publication and pin retention pass.
    pub fn freeze(&mut self) -> Result<()> {
        self.enter(State::Admitted, Phase::ClientChoice)?;
        let result = (|| {
            let store = self
                .store
                .take()
                .ok_or(Error::Unavailable("IM3 client store"))?;
            self.claim = Some(
                store
                    .consume(
                        self.schedule.round(),
                        self.c.r2.round.manifest.id(),
                        self.choice,
                    )
                    .map_err(|_| Error::Unavailable("IM3 client durable choice"))?,
            );
            Ok(())
        })();
        self.finish(result, State::Frozen, Phase::ClientChoice)
    }
    /// Dispatch B once. A duplicate, early or late call permanently aborts.
    pub fn take_b_job(&mut self) -> Result<ClientProofJob> {
        self.enter(State::Frozen, Phase::BProof)?;
        let result = self
            .schedule
            .window(Phase::BProof)
            .map(|(_, deadline)| ClientProofJob {
                statement: self.inputs,
                deadline,
            });
        self.finish(result, State::BRunning, Phase::BProof)
    }
    fn verify(&self, output: &ClientProofOutput, inputs: [Digest; 3]) -> Result<()> {
        canonical_scalar(&output.nullifier)
            .map_err(|_| Error::Invalid("IM3 client proof scalar"))?;
        let [root, msg, scope] = inputs;
        self.verifier
            .verify(&output.proof, &[root, output.nullifier, msg, scope])
            .map_err(|_| Error::Invalid("IM3 client genuine proof"))
    }
    /// Verify the exact frozen B statement before the original proof cutoff.
    pub fn complete_b(&mut self, output: ClientProofOutput) -> Result<()> {
        self.enter(State::BRunning, Phase::BProof)?;
        let result = self.verify(&output, self.inputs);
        self.finish(result, State::BVerified, Phase::BProof)?;
        self.output = Some(output);
        Ok(())
    }
    /// Select exactly one random B encryption internally. No S_B export exists.
    pub fn seal_b(&mut self) -> Result<()> {
        self.enter(State::BVerified, Phase::BSeal)?;
        let result = (|| {
            let mut cell = self
                .cell
                .take()
                .ok_or(Error::Unavailable("IM3 client cell"))?;
            let proof = self
                .output
                .take()
                .ok_or(Error::Unavailable("IM3 client B output"))?;
            cell[128..160].copy_from_slice(&proof.nullifier);
            cell[160..416].copy_from_slice(&proof.proof);
            let claim = self
                .claim
                .take()
                .ok_or(Error::Unavailable("IM3 client claim"))?;
            self.pending = Some(PendingMiddle::from_bound_b_cell(
                self.c,
                claim,
                &cell,
                self.verifier,
                self.choice,
            )?);
            Ok(())
        })();
        self.finish(result, State::BSealed, Phase::BSeal)
    }
    /// Dispatch C once, only after B has completed and its ciphertext is frozen.
    pub fn take_c_job(&mut self) -> Result<ClientProofJob> {
        self.enter(State::BSealed, Phase::CProof)?;
        let result = (|| {
            let statement = self
                .pending
                .as_ref()
                .ok_or(Error::Unavailable("IM3 client middle"))?
                .statement();
            Ok(ClientProofJob {
                statement,
                deadline: self.schedule.window(Phase::CProof)?.1,
            })
        })();
        self.finish(result, State::CRunning, Phase::CProof)
    }
    /// A C proof is accepted only for the internally retained exact B ciphertext.
    pub fn complete_c(&mut self, output: ClientProofOutput) -> Result<()> {
        self.enter(State::CRunning, Phase::CProof)?;
        let result = (|| {
            let inputs = self
                .pending
                .as_ref()
                .ok_or(Error::Unavailable("IM3 client middle"))?
                .statement();
            self.verify(&output, inputs)
        })();
        self.finish(result, State::CVerified, Phase::CProof)?;
        self.output = Some(output);
        Ok(())
    }
    /// Seal C and A once; retain just one immutable final onion for handoff.
    pub fn seal_onion(&mut self) -> Result<()> {
        self.enter(State::CVerified, Phase::Onion)?;
        let result = (|| {
            let output = self
                .output
                .take()
                .ok_or(Error::Unavailable("IM3 client C output"))?;
            let pending = self
                .pending
                .take()
                .ok_or(Error::Unavailable("IM3 client middle"))?;
            self.frame = Some(pending.finish(output.nullifier, &output.proof, self.verifier)?);
            Ok(())
        })();
        self.finish(result, State::Ready, Phase::Onion)
    }
    /// Consume the sole final onion during its original sealing window. The
    /// transport owner must still enforce the original +7..+13.4 client slot;
    /// this preparation capability is not a TLS write or settlement receipt.
    pub fn into_onion(mut self) -> Result<MiddleFrame> {
        self.enter(State::Ready, Phase::Onion)?;
        self.frame
            .take()
            .ok_or(Error::Unavailable("IM3 client final onion"))
    }
}
