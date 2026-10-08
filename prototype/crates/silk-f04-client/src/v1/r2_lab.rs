//! Explicit unqualified one-client R2 dispatch owner. No operational admission,
//! enrollment, proof backend, reconnect, fallback, retry or recovered job exists.
//! A trusted local runner must independently enforce the worker's original
//! absolute wall deadline,4 CPU seconds and1GiB RSS; this API is not containment.
use super::{LocalViewV1, OutcomeV1, WriteStatusV1, select_payload};
use silk_f04_relay::{
    Digest, Error, Result,
    aip2_claim::{ClaimPinRetention, ClaimRole, ConsumedScope, PreparedScopeStore},
    aip2_profile::{PreparedProfile, ProfileExpectations},
    aip2_proof::{PreparedProofVerifier, prepare_cover_statement, semaphore_scalar},
    aip2_transport::{PreparedR2Context, PreparedR2Frame, seal_claimed_cell},
    config::SignedConfig,
    frame::RoundContext,
    manifest::SignedManifest,
    schedule::Schedule,
    tls::{RecordSize, Transport},
};
use silk_f04_wallet::journal::intents::SavedOfferV1;
use silk_sapling_f04::codec::{ENVELOPE_BYTES, domain_hash};
use std::{rc::Rc, time::Instant};
use zeroize::Zeroizing;

const FREEZE: i64 = -5_000_000_000;
const DISPATCH: i64 = -4_500_000_000;
const PROOF_END: i64 = 500_000_000;
const FRAME_END: i64 = 1_000_000_000;

/// Public statement only, handed to exactly one trusted LOCAL proof runner.
/// The identity/witness stays in that runner's trusted domain, never on a relay.
/// There is deliberately no Clone/Deserialize or resumption constructor.
pub struct ProofJobLab {
    /// Exact locally selected root/message/scope; nullifier is proof-derived.
    pub root: Digest,
    pub message: Digest,
    pub scope: Digest,
    pub profile: Digest,
    pub manifest: Digest,
    pub round: u64,
    /// Original absolute cutoff; dispatch delay consumes, never renews, its5s.
    pub deadline: Instant,
}

/// Untrusted mathematical output, never a validity boolean or replacement cell.
/// The owner itself builds the four inputs and verifies before HPKE selection.
pub struct ProofOutputLab {
    pub nullifier: Digest,
    pub packed_proof: [u8; 256],
}

enum Phase {
    Waiting,
    Reading,
    Manifest,
    Claimed,
    Proving,
    Proof(ProofOutputLab),
    Selected(PreparedR2Frame),
    Writing,
    Finished(WriteStatusV1),
    Taken,
}

/// Local private diagnostics for a lab receipt, not network/clock qualification.
#[derive(Default)]
pub struct TimingLab {
    pub manifest: Option<Instant>,
    pub claimed: Option<Instant>,
    pub dispatched: Option<Instant>,
    pub proof: Option<Instant>,
    pub frame: Option<Instant>,
    pub write: Option<Instant>,
}

/// One immutable schedule, one owned established link, one borrowed durable
/// claim store and one selected payload. Native runner/pump remain independent.
pub struct ClientRoundLab<'a, P: ClaimPinRetention> {
    config: Rc<SignedConfig>,
    schedule: Schedule,
    profile: &'a PreparedProfile,
    verifier: PreparedProofVerifier,
    view: LocalViewV1,
    slot: u8,
    link: Option<Transport>,
    offer: Option<Zeroizing<[u8; ENVELOPE_BYTES]>>,
    store: Option<&'a mut PreparedScopeStore<P>>,
    claim: Option<ConsumedScope<'a, P>>,
    manifest: Option<SignedManifest>,
    cell: Option<Zeroizing<[u8; 4096]>>,
    inputs: Option<[Digest; 3]>,
    real: bool,
    phase: Phase,
    timing: TimingLab,
}

impl<'a, P: ClaimPinRetention> ClientRoundLab<'a, P> {
    /// Consume an ordinary already-exposed wallet offer before the original−8
    /// boundary. This isolated owner does NOT implement epoch Join/admission.
    #[allow(clippy::too_many_arguments)]
    pub fn new_lab(
        config: Rc<SignedConfig>,
        schedule: Schedule,
        profile: &'a PreparedProfile,
        vk_bytes: &[u8],
        vk_hash: Digest,
        member_commitment: Digest,
        view: LocalViewV1,
        slot: u8,
        link: Transport,
        store: &'a mut PreparedScopeStore<P>,
        offer: Option<SavedOfferV1>,
    ) -> Result<Self> {
        Self::new_exposed_fixture_lab(
            config,
            schedule,
            profile,
            vk_bytes,
            vk_hash,
            member_commitment,
            view,
            slot,
            link,
            store,
            offer.map(SavedOfferV1::into_bytes),
        )
    }

    /// Explicit fixture seam for an already-public envelope. NOT wallet exposure
    /// authority. Operational schedules are refused, even if all bytes validate.
    #[allow(clippy::too_many_arguments)]
    pub fn new_exposed_fixture_lab(
        config: Rc<SignedConfig>,
        schedule: Schedule,
        profile: &'a PreparedProfile,
        vk_bytes: &[u8],
        vk_hash: Digest,
        member_commitment: Digest,
        view: LocalViewV1,
        slot: u8,
        link: Transport,
        store: &'a mut PreparedScopeStore<P>,
        offer: Option<Zeroizing<[u8; ENVELOPE_BYTES]>>,
    ) -> Result<Self> {
        if schedule.uses_qualified_source() || !config.contains_round(schedule.round()) {
            return Err(Error::Unavailable(
                "R2 client lab requires unqualified original schedule",
            ));
        }
        schedule.clock_healthy()?;
        schedule.completed_before(-8_000_000_000)?;
        source_interval(slot)?;
        link.check_endpoint(config.endpoints()[0], true)?;
        PreparedProfile::verify(
            profile.bytes(),
            &ProfileExpectations {
                domain: config.domain(),
                config: config.id(),
                epoch: config.epoch(),
                cohort: config.cohort(),
                vk_hash,
                role_keys: [config.endpoints()[0].signing, config.endpoints()[1].signing],
            },
        )
        .map_err(|_| Error::Invalid("R2 client profile linkage"))?;
        profile
            .check_own_commitment(member_commitment)
            .map_err(|_| Error::Invalid("R2 client own commitment"))?;
        if store.binding() != profile.claim_binding(ClaimRole::Client) {
            return Err(Error::Invalid("R2 client original claim store"));
        }
        let verifier = PreparedProofVerifier::from_canonical_vk(vk_bytes, vk_hash)
            .map_err(|_| Error::Invalid("R2 client verifier"))?;
        schedule.completed_before(-8_000_000_000)?;
        Ok(Self {
            config,
            schedule,
            profile,
            verifier,
            view,
            slot,
            link: Some(link),
            offer,
            store: Some(store),
            claim: None,
            manifest: None,
            cell: None,
            inputs: None,
            real: false,
            phase: Phase::Waiting,
            timing: TimingLab::default(),
        })
    }

    /// Nonblocking original-link progress. Any uncertainty permanently stops this
    /// owner; no valid proof arriving later can reopen it or select another cell.
    pub fn poll(&mut self) -> Result<()> {
        let result = self.poll_inner();
        if result.is_err() {
            self.stop();
        }
        result
    }

    fn poll_inner(&mut self) -> Result<()> {
        if matches!(self.phase, Phase::Finished(_) | Phase::Taken) {
            return Ok(());
        }
        self.schedule.observe_functional_clock()?;
        let now = Instant::now();
        match self.phase {
            Phase::Waiting if now >= self.schedule.at(-8_000_000_000)? => {
                self.schedule.in_window(-8_000_000_000, FREEZE)?;
                self.link
                    .as_mut()
                    .ok_or(Error::Unavailable("R2 client link"))?
                    .expect(RecordSize::Manifest, self.schedule.at(FREEZE)?)?;
                self.phase = Phase::Reading;
            }
            Phase::Reading => {
                if let Some(bytes) = self
                    .link
                    .as_mut()
                    .ok_or(Error::Unavailable("R2 client link"))?
                    .read_step()?
                {
                    let manifest =
                        SignedManifest::verify(&bytes, &self.config, self.schedule.round())?;
                    self.view.check(&manifest, &self.config, &self.schedule)?;
                    let _ = PreparedR2Context::new(
                        &self.config,
                        &manifest,
                        self.profile,
                        self.profile.claim_binding(ClaimRole::Client).vk_hash,
                    )?;
                    self.timing.manifest = Some(self.schedule.completed_before(FREEZE)?);
                    self.manifest = Some(manifest);
                    self.phase = Phase::Manifest;
                }
            }
            Phase::Manifest if now >= self.schedule.at(FREEZE)? => self.freeze()?,
            Phase::Claimed | Phase::Proving if now >= self.schedule.at(PROOF_END)? => {
                return Err(Error::Unavailable("R2 client original proof deadline"));
            }
            Phase::Proof(_) if now >= self.schedule.at(PROOF_END)? => self.frame()?,
            Phase::Selected(_) => {
                let (start, end) = source_interval(self.slot)?;
                if now >= self.schedule.at(start)? {
                    self.schedule.in_window(start, end)?;
                    let Phase::Selected(frame) = std::mem::replace(&mut self.phase, Phase::Writing)
                    else {
                        unreachable!()
                    };
                    self.link
                        .as_mut()
                        .ok_or(Error::Unavailable("R2 client link"))?
                        .queue(RecordSize::Cell, frame.bytes(), self.schedule.at(end)?)?;
                }
            }
            Phase::Writing => {
                if self
                    .link
                    .as_mut()
                    .ok_or(Error::Unavailable("R2 client link"))?
                    .write_step()?
                {
                    let (_, end) = source_interval(self.slot)?;
                    self.timing.write = Some(self.schedule.completed_before(end)?);
                    self.phase = Phase::Finished(if self.real {
                        WriteStatusV1::RealWriteComplete
                    } else {
                        WriteStatusV1::CoverWriteComplete
                    });
                }
            }
            _ => (),
        }
        if !matches!(
            self.phase,
            Phase::Reading | Phase::Waiting | Phase::Finished(_)
        ) && self
            .link
            .as_mut()
            .ok_or(Error::Unavailable("R2 client link"))?
            .has_extra_bytes()?
        {
            return Err(Error::Unavailable("R2 client extra manifest/input"));
        }
        Ok(())
    }

    fn freeze(&mut self) -> Result<()> {
        self.schedule.in_window(FREEZE, DISPATCH)?;
        let manifest = self
            .manifest
            .as_ref()
            .ok_or(Error::Unavailable("R2 client manifest"))?;
        let context = RoundContext::new(&self.config, manifest)?;
        let payload = select_payload(self.offer.take(), self.config.domain(), &context);
        self.real = payload.is_real();
        let statement = prepare_cover_statement(self.profile, manifest.id(), manifest.round())
            .map_err(|_| Error::Invalid("R2 client statement"))?;
        let mut cell = Zeroizing::new(*statement.cell());
        if let Some(envelope) = payload.real_bytes() {
            cell[8] = 1;
            cell[416..3206].copy_from_slice(envelope);
        }
        let message = selected_message(&cell);
        let store = self
            .store
            .take()
            .ok_or(Error::Unavailable("R2 client claim already attempted"))?;
        let claim = store
            .consume(manifest.round(), manifest.id(), message)
            .map_err(|_| Error::Unavailable("R2 client durable claim"))?;
        // This held receipt is the SAME one consumed by seal_claimed_cell.
        self.claim = Some(claim);
        self.inputs = Some([statement.root(), message, statement.scope()]);
        self.cell = Some(cell);
        self.timing.claimed = Some(self.schedule.completed_before(DISPATCH)?);
        self.phase = Phase::Claimed;
        Ok(())
    }

    /// Exactly one request at/after fixed−4.5. Before then: None. Afterwards:
    /// repeated calls return None, never another job. Delay consumes its deadline.
    pub fn take_job(&mut self) -> Result<Option<ProofJobLab>> {
        let result = self.take_job_inner();
        if result.is_err() {
            self.stop();
        }
        result
    }
    fn take_job_inner(&mut self) -> Result<Option<ProofJobLab>> {
        if !matches!(self.phase, Phase::Claimed) || Instant::now() < self.schedule.at(DISPATCH)? {
            return Ok(None);
        }
        self.schedule.observe_functional_clock()?;
        self.schedule.in_window(DISPATCH, PROOF_END)?;
        let [root, message, scope] = self
            .inputs
            .ok_or(Error::Unavailable("R2 client frozen inputs"))?;
        let manifest = self
            .manifest
            .as_ref()
            .ok_or(Error::Unavailable("R2 client manifest"))?;
        self.phase = Phase::Proving; // Latch BEFORE the request can escape.
        self.timing.dispatched = Some(Instant::now());
        Ok(Some(ProofJobLab {
            root,
            message,
            scope,
            profile: self.profile.id(),
            manifest: manifest.id(),
            round: manifest.round(),
            deadline: self.schedule.at(PROOF_END)?,
        }))
    }

    /// Only worker bytes can be supplied. The frozen payload and locally built
    /// proof inputs cannot be replaced by a worker's cell/public-input vector.
    pub fn complete_job(&mut self, output: ProofOutputLab) -> Result<()> {
        let result = (|| {
            if !matches!(self.phase, Phase::Proving) {
                return Err(Error::Unavailable("R2 client no original worker"));
            }
            self.schedule.observe_functional_clock()?;
            self.timing.proof = Some(self.schedule.completed_before(PROOF_END)?);
            self.phase = Phase::Proof(output);
            Ok(())
        })();
        if result.is_err() {
            self.stop();
        }
        result
    }

    fn frame(&mut self) -> Result<()> {
        self.schedule.in_window(PROOF_END, FRAME_END)?;
        let Phase::Proof(output) = std::mem::replace(&mut self.phase, Phase::Proving) else {
            return Err(Error::Unavailable("R2 client no completed proof"));
        };
        let [root, message, scope] = self.inputs.ok_or(Error::Unavailable("R2 client inputs"))?;
        self.verifier
            .verify(
                &output.packed_proof,
                &[root, output.nullifier, message, scope],
            )
            .map_err(|_| Error::Invalid("R2 client proof/context"))?;
        let mut cell = self
            .cell
            .take()
            .ok_or(Error::Unavailable("R2 client selected template"))?;
        cell[128..160].copy_from_slice(&output.nullifier);
        cell[160..416].copy_from_slice(&output.packed_proof);
        let manifest = self
            .manifest
            .as_ref()
            .ok_or(Error::Unavailable("R2 client manifest"))?;
        let context = PreparedR2Context::new(
            &self.config,
            manifest,
            self.profile,
            self.profile.claim_binding(ClaimRole::Client).vk_hash,
        )?;
        let frame = seal_claimed_cell(
            &context,
            self.claim
                .take()
                .ok_or(Error::Unavailable("R2 client claim"))?,
            &cell,
        )?;
        self.timing.frame = Some(self.schedule.completed_before(FRAME_END)?);
        self.phase = Phase::Selected(frame);
        Ok(())
    }

    /// A failed job remains consumed; no cover fallback or automatic retry.
    pub fn stop(&mut self) {
        if matches!(self.phase, Phase::Taken) {
            return;
        }
        let status = match self.phase {
            Phase::Writing => WriteStatusV1::WriteUncertain,
            Phase::Finished(status) => status,
            _ => WriteStatusV1::Silent,
        };
        self.phase = Phase::Finished(status);
        self.offer = None;
        self.cell = None;
        self.claim = None;
        self.store = None;
        self.link = None;
    }

    /// One fixed+22 local outcome, never delivery/inclusion or retry permission.
    pub fn take_outcome(&mut self) -> Result<Option<OutcomeV1>> {
        if Instant::now() < self.schedule.at(22_000_000_000)? {
            return Ok(None);
        }
        if !matches!(self.phase, Phase::Finished(_) | Phase::Taken) {
            self.stop();
        }
        if let Phase::Finished(status) = std::mem::replace(&mut self.phase, Phase::Taken) {
            Ok(Some(OutcomeV1 {
                round: self.schedule.round(),
                status,
            }))
        } else {
            Ok(None)
        }
    }
    pub const fn timing_lab(&self) -> &TimingLab {
        &self.timing
    }
    pub fn at_lab(&self, offset: i64) -> Result<Instant> {
        self.schedule.at(offset)
    }
}

fn selected_message(cell: &[u8; 4096]) -> Digest {
    semaphore_scalar(&domain_hash(
        "SilkNode-AIP2R2-message",
        &[&cell[..128], &cell[416..]],
    ))
}
fn source_interval(slot: u8) -> Result<(i64, i64)> {
    if slot >= 32 {
        return Err(Error::Invalid("R2 client slot"));
    }
    let start = FRAME_END + i64::from(slot) * 200_000_000;
    Ok((start, start + 200_000_000))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_budget_partitions_are_not_renewed() {
        assert_eq!(DISPATCH - FREEZE, 500_000_000);
        assert_eq!(PROOF_END - DISPATCH, 5_000_000_000);
        assert_eq!(FRAME_END - PROOF_END, 500_000_000);
    }
    #[test]
    fn all_source_slots_are_contiguous_200ms() {
        for i in 0..32 {
            let (a, b) = source_interval(i).unwrap();
            assert_eq!(b - a, 200_000_000);
            if i > 0 {
                assert_eq!(a, source_interval(i - 1).unwrap().1);
            }
        }
        assert_eq!(source_interval(31).unwrap(), (7_200_000_000, 7_400_000_000));
        assert!(source_interval(32).is_err());
        assert!(source_interval(255).is_err());
    }
    #[test]
    fn selected_message_binds_kind_context_and_payload_not_proof_bytes() {
        let cell = [0; 4096];
        let baseline = selected_message(&cell);
        for at in [0, 8, 16, 64, 96, 416, 3205, 4095] {
            let mut changed = cell;
            changed[at] = 1;
            assert_ne!(selected_message(&changed), baseline);
        }
        for at in [128, 159, 160, 415] {
            let mut changed = cell;
            changed[at] = 1;
            assert_eq!(selected_message(&changed), baseline);
        }
    }
}
