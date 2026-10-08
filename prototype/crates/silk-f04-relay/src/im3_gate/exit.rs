//! Original C-to-B receive and all32 membership-before-Sapling boundary. No
//! legacy staged/release conversion, plaintext getter or partial success API.
use super::*;
use crate::{
    frame::Payload,
    tls::{ReceiveProgress, WireObservation},
};
use silk_sapling_f04::{
    codec::EnvelopeView, crypto::verify_borrowed, parameters::SaplingVerificationKeys,
};

fn choice(c: &MiddleContext<'_>) -> Digest {
    domain_hash(
        "SilkNode-IM3-exit-claim",
        &[
            &c.r2.round.config.id(),
            &c.profile.id(),
            &c.q.id(),
            &c.r2.round.manifest.id(),
            &c.r2.round.manifest.round().to_le_bytes(),
        ],
    )
}
/// B retains one durably consumed P/round, its original C link, all32 encrypted
/// frames and the complete A/C controls. Construction cannot recover old work.
pub struct ReceivingExitOwner<'c, 'a, 's, 't, P: ClaimPinRetention> {
    c: &'c MiddleContext<'a>,
    claim: Option<ConsumedScope<'s, P>>,
    schedule: &'t Im3Schedule,
    guard: &'t Im3Guard,
    input: Option<&'t mut Transport>,
    frames: Vec<MiddleFrame>,
    tags: BTreeSet<Digest>,
    controls: Vec<Im3Control>,
    failed: bool,
    armed: bool,
    observation: Option<WireObservation>,
    #[cfg(test)]
    last_original_record: Option<Vec<u8>>,
    #[cfg(test)]
    capture_original_record: bool,
}
impl<'c, 'a, 's, 't, P: ClaimPinRetention> ReceivingExitOwner<'c, 'a, 's, 't, P> {
    /// Test-only B-owned complete bytes from the last original C-link read,
    /// including a failed validation. Incomplete reads remain wire metadata.
    #[cfg(test)]
    pub(super) fn take_fixture_original_record(&mut self) -> Option<Vec<u8>> {
        self.last_original_record.take()
    }
    // Test-only B-owned original ciphertext view in completed C-link read
    // order. Production retains no getter and no source-slot association.
    #[cfg(test)]
    pub(super) fn fixture_b_ciphertexts(&self) -> Result<Vec<u8>> {
        if self.frames.len() != 32 || self.controls.len() != 2 {
            return Err(Error::Invalid("IM3 fixture B ciphertext count"));
        }
        Ok(self
            .frames
            .iter()
            .flat_map(|frame| frame.bytes().iter().copied())
            .collect())
    }
    /// Test-only exact A_READY/C_READY bytes already received by B.
    #[cfg(test)]
    pub(super) fn fixture_b_received_controls(&self) -> Result<Vec<u8>> {
        if self.frames.len() != 32 || self.controls.len() != 2 {
            return Err(Error::Invalid("IM3 fixture B control count"));
        }
        Ok(self
            .controls
            .iter()
            .flat_map(|control| control.bytes().iter().copied())
            .collect())
    }
    // Test-only A+B adversary projection. The real B owner has these exact
    // plaintext cells before stripping/shuffling; production has no getter.
    #[cfg(test)]
    pub(super) fn fixture_b_plaintexts(&self, key: &HpkePrivate) -> Result<Vec<[u8; 4096]>> {
        if self.frames.len() != 32 {
            return Err(Error::Invalid("IM3 fixture B projection count"));
        }
        self.frames
            .iter()
            .map(|frame| {
                let plain = open(
                    self.c,
                    3,
                    self.c.r2.round.config.hpke_keys()[1],
                    key,
                    &frame.bytes()[64..4208],
                )?;
                plain
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::Invalid("IM3 fixture B projection size"))
            })
            .collect()
    }
    /// Consume the common exit scope and reserve the exact original B-server
    /// link before T-5. Polling arms it before +19, without widening the ordinary
    /// TLS ceiling of 30 seconds per originally selected record deadline.
    pub(crate) fn begin(
        c: &'c MiddleContext<'a>,
        store: &'s mut PreparedScopeStore<P>,
        schedule: &'t Im3Schedule,
        guard: &'t Im3Guard,
        input: &'t mut Transport,
    ) -> Result<Self> {
        let check = (|| {
            guard.check(schedule)?;
            before(schedule.at(-5_000_000_000)?)?;
            if schedule.round() != c.r2.round.manifest.round()
                || store.binding() != c.profile.claim_binding(ClaimRole::Exit)
                || input.receive_progress() != ReceiveProgress::Idle
                || input.selected_read().is_some()
            {
                return Err(Error::Invalid("IM3 exit original context/link/store"));
            }
            input.check_endpoint(c.r2.round.config.endpoints()[1], false)?;
            Ok(())
        })();
        if let Err(e) = check {
            let _ = input.quarantine();
            return Err(e);
        }
        let claim = match store.consume(
            c.r2.round.manifest.round(),
            c.r2.round.manifest.id(),
            choice(c),
        ) {
            Ok(v) => v,
            Err(_) => {
                let _ = input.quarantine();
                return Err(Error::Unavailable("IM3 exit claim"));
            }
        };
        if let Err(e) = guard
            .check(schedule)
            .and_then(|()| before(schedule.at(-5_000_000_000)?))
        {
            let _ = input.quarantine();
            return Err(e);
        }
        Ok(Self {
            c,
            claim: Some(claim),
            schedule,
            guard,
            input: Some(input),
            frames: Vec::with_capacity(32),
            tags: BTreeSet::new(),
            controls: Vec::with_capacity(2),
            failed: false,
            armed: false,
            observation: None,
            #[cfg(test)]
            last_original_record: None,
            #[cfg(test)]
            capture_original_record:
                std::env::var_os("SILK_IM3_MISSING_EXTERNAL_SLOT0").is_some(),
        })
    }
    fn stop(&mut self) {
        self.failed = true;
        self.frames.clear();
        self.tags.clear();
        self.controls.clear();
        self.claim = None;
        if let Some(input) = self.input.take() {
            let _ = input.quarantine();
        }
    }
    /// One actual original socket read. True means exactly32 cells and the two
    /// signed controls only; it grants no decryption/output capability. Continue
    /// polling through the freeze cutoff to detect trailing data/EOF.
    pub fn poll(&mut self) -> Result<bool> {
        let result = self.poll_inner();
        if result.is_err() {
            self.stop();
        }
        result
    }
    fn poll_inner(&mut self) -> Result<bool> {
        if self.failed {
            return Err(Error::Unavailable("IM3 exit closed"));
        }
        self.guard.check(self.schedule)?;
        let input = self
            .input
            .as_deref_mut()
            .ok_or(Error::Unavailable("IM3 exit original link"))?;
        if !self.armed {
            if input.has_extra_bytes()? {
                return Err(Error::Invalid("IM3 unarmed C input"));
            }
            if Instant::now() < self.schedule.at(-8_000_000_000)? {
                return Ok(false);
            }
            before(self.schedule.at(19_000_000_000)?)?;
            input.expect(RecordSize::Cell, self.schedule.at(22_000_000_000)?)?;
            self.armed = true;
        }
        if self.controls.len() == 2 {
            if input.has_extra_bytes()? {
                return Err(Error::Invalid("IM3 extra C input"));
            }
            return Ok(true);
        }
        before(self.schedule.at(22_000_000_000)?)?;
        let early = if self.frames.len() < 32 {
            19_000_000_000 + 7_812_500 * i64::try_from(self.frames.len()).expect("32")
        } else {
            19_250_000_000
        };
        if Instant::now() < self.schedule.at(early)? {
            if input.has_extra_bytes()? {
                return Err(Error::Invalid("IM3 premature C bytes"));
            }
            return Ok(false);
        }
        // A C failure may arrive in its one fixed control window even when
        // the expected data train never completed. Framing is only a hint:
        // authenticate the full canonical control before acting. A partially
        // consumed cell is never discarded or given a new deadline.
        if Instant::now() >= self.schedule.at(20_250_000_000)?
            && Instant::now() < self.schedule.at(20_500_000_000)?
            && self.frames.len() < 32
            && input
                .selected_read()
                .is_some_and(|(size, _)| size == RecordSize::Cell)
            && input.receive_progress() == ReceiveProgress::WaitingZeroBytes
        {
            match input.peek_record_size()? {
                // A 1..4-byte prefix must stay untouched: reading even one
                // byte as Cell would prevent a valid CANCEL classification.
                None => return Ok(false),
                Some(RecordSize::Control) => {
                    let (_, cutoff) = input
                        .selected_read()
                        .ok_or(Error::Unavailable("IM3 C selection absent"))?;
                    input.retire_empty(RecordSize::Cell)?;
                    input.expect(RecordSize::Control, cutoff)?;
                }
                Some(RecordSize::Cell) => {}
                Some(_) => return Err(Error::Invalid("IM3 unexpected C record class")),
            }
        }
        let (result, observation) = input.read_step_observed();
        self.observation = Some(observation);
        if let Some(bytes) = result? {
            #[cfg(test)]
            {
                if self.capture_original_record {
                    self.last_original_record = Some(bytes.to_vec());
                }
            }
            if input.selected_read().is_none() && bytes.len() == 512 {
                let control = Im3Control::verify(&bytes, self.c)?;
                if control.kind() == Im3Kind::Cancel {
                    if control.role() != Im3Role::C
                        || Instant::now() < self.schedule.at(20_250_000_000)?
                        || Instant::now() >= self.schedule.at(20_500_000_000)?
                    {
                        return Err(Error::Invalid("IM3 C CANCEL window/role"));
                    }
                    return Err(Error::Unavailable("IM3 C cancelled"));
                }
            }
            if self.frames.len() < 32 {
                let frame = MiddleFrame::decode(&bytes, self.c, 3)?;
                if !self.tags.insert(frame.tag()) {
                    return Err(Error::Invalid("IM3 duplicate B encapsulation"));
                }
                self.frames.push(frame);
            } else {
                let control = Im3Control::verify(&bytes, self.c)?;
                let expected = if self.controls.is_empty() {
                    Im3Kind::AReady
                } else {
                    Im3Kind::CReady
                };
                if control.kind() != expected {
                    return Err(Error::Invalid("IM3 exit control order"));
                }
                self.controls.push(control);
            }
            if self.controls.len() < 2 {
                input.expect(
                    if self.frames.len() < 32 {
                        RecordSize::Cell
                    } else {
                        RecordSize::Control
                    },
                    self.schedule.at(22_000_000_000)?,
                )?;
            }
        }
        self.guard.check(self.schedule)?;
        before(self.schedule.at(22_000_000_000)?)?;
        Ok(self.controls.len() == 2)
    }
    /// Last actual C-to-B read interval, not queue/arrival time or a C mapping.
    pub fn take_wire_observation(&mut self) -> Option<WireObservation> {
        self.observation.take()
    }
    /// At +22, bind the complete original stream to C's authentic chain, verify
    /// all32 genuine distinct B presentations, destroy proof/nullifier labels,
    /// privately permute, THEN check every real Sapling envelope. No partial
    /// plaintext, staging or release result exists on any failure or late return.
    pub fn verify(
        mut self,
        key: &HpkePrivate,
        verifier: &PreparedProofVerifier,
        keys: Option<&SaplingVerificationKeys>,
    ) -> Result<VerifiedIm3Exit<'s, 't, P>> {
        self.schedule.require(self.guard, Phase::BGate)?;
        let deadline = self.schedule.window(Phase::BGate)?.1;
        let input = self
            .input
            .as_deref()
            .ok_or(Error::Unavailable("IM3 exit original link"))?;
        let claim = self
            .claim
            .as_ref()
            .ok_or(Error::Unavailable("IM3 exit no claim"))?;
        if self.failed
            || self.frames.len() != 32
            || self.controls.len() != 2
            || input.receive_progress() != ReceiveProgress::Idle
            || input.has_extra_bytes()?
            || claim.binding() != self.c.profile.claim_binding(ClaimRole::Exit)
            || claim.round() != self.c.r2.round.manifest.round()
            || claim.manifest() != self.c.r2.round.manifest.id()
            || claim.message() != choice(self.c)
            || verifier.key_hash() != claim.binding().vk_hash
        {
            return Err(Error::Invalid("IM3 exit complete ownership"));
        }
        let a = &self.controls[0];
        let middle = &self.controls[1];
        if middle.field(116) != a.field(116)
            || middle.field(212) != a.id()
            || middle.field(148) != self.c.batch_hash("SilkNode-IM3-C-batch", &self.frames)
        {
            return Err(Error::Invalid("IM3 exit complete C chain/batch"));
        }
        let statement = crate::aip2_proof::prepare_cover_statement(
            self.c.profile,
            self.c.r2.round.manifest.id(),
            self.c.r2.round.manifest.round(),
        )
        .map_err(|_| Error::Invalid("IM3 exit statement"))?;
        let mut nullifiers = BTreeSet::new();
        let mut stripped = Vec::with_capacity(32);
        for frame in &self.frames {
            self.schedule.require(self.guard, Phase::BGate)?;
            let plain = open(
                self.c,
                3,
                self.c.r2.round.config.hpke_keys()[1],
                key,
                &frame.bytes()[64..4208],
            )?;
            let cell: &[u8; 4096] = plain
                .as_slice()
                .try_into()
                .map_err(|_| Error::Invalid("IM3 B plaintext size"))?;
            let msg = self.c.r2.check_cell(cell)?;
            let nullifier = cell[128..160].try_into().expect("32");
            if !nullifiers.insert(nullifier) {
                return Err(Error::Invalid("IM3 duplicate B nullifier"));
            }
            verifier
                .verify(
                    cell[160..416].try_into().expect("256"),
                    &[statement.root(), nullifier, msg, statement.scope()],
                )
                .map_err(|_| Error::Invalid("IM3 B genuine membership"))?;
            self.schedule.require(self.guard, Phase::BGate)?;
            let mut envelope = Box::new(Zeroizing::new([0; 2790]));
            envelope.copy_from_slice(&cell[416..3206]);
            stripped.push((cell[8], envelope));
        }
        // No envelope decode/real-payload construction precedes the full gate.
        self.frames.clear();
        self.tags.clear();
        drop(nullifiers);
        let mut stripped: [(u8, Box<Zeroizing<[u8; 2790]>>); 32] = stripped
            .try_into()
            .map_err(|_| Error::Invalid("IM3 complete stripped count"))?;
        shuffle(&mut stripped)?;
        let mut payloads = Vec::with_capacity(32);
        for (kind, bytes) in stripped {
            self.schedule.require(self.guard, Phase::BGate)?;
            let payload = if kind == 0 {
                Payload::cover()
            } else {
                let keys = keys.ok_or(Error::Unavailable("IM3 Sapling keys"))?;
                let view =
                    EnvelopeView::decode(bytes.as_ref().as_ref(), &self.c.r2.round.config.domain())
                        .map_err(|_| Error::Invalid("IM3 Sapling envelope framing"))?;
                let payload = Payload::real_view(&view, &self.c.r2.round)?;
                verify_borrowed(&view, keys).map_err(|e| match e {
                    silk_sapling_f04::Error::Encoding(_) | silk_sapling_f04::Error::Crypto(_) => {
                        Error::Invalid("IM3 Sapling verification")
                    }
                    _ => Error::Unavailable("IM3 Sapling capability"),
                })?;
                payload
            };
            self.schedule.require(self.guard, Phase::BGate)?;
            payloads.push(payload);
        }
        before(deadline)?;
        let controls = std::mem::take(&mut self.controls)
            .try_into()
            .map_err(|_| Error::Invalid("IM3 complete controls"))?;
        Ok(VerifiedIm3Exit {
            claim: Some(
                self.claim
                    .take()
                    .ok_or(Error::Unavailable("IM3 exit no claim"))?,
            ),
            payloads: payloads
                .try_into()
                .map_err(|_| Error::Invalid("IM3 complete payload count"))?,
            controls,
            binding: [
                self.c.r2.round.config.id(),
                self.c.profile.id(),
                self.c.q.id(),
                self.c.r2.round.manifest.id(),
            ],
            input: self.input.take(),
            schedule: self.schedule,
            guard: self.guard,
        })
    }
}
impl<P: ClaimPinRetention> Drop for ReceivingExitOwner<'_, '_, '_, '_, P> {
    fn drop(&mut self) {
        self.stop();
    }
}
/// Only the original complete genuine B gate constructs this source-free,
/// pre-staging owner. No plaintext/release/legacy-conversion API is exported.
pub struct VerifiedIm3Exit<'s, 't, P: ClaimPinRetention> {
    pub(super) claim: Option<ConsumedScope<'s, P>>,
    pub(super) payloads: [Payload; 32],
    pub(super) controls: [Im3Control; 2],
    pub(super) binding: [Digest; 4],
    pub(super) input: Option<&'t mut Transport>,
    pub(super) schedule: &'t Im3Schedule,
    pub(super) guard: &'t Im3Guard,
}
impl<P: ClaimPinRetention> VerifiedIm3Exit<'_, '_, P> {
    /// Genuine fixed complete count, not producer release authority.
    pub const fn count(&self) -> usize {
        32
    }
    /// Exit-visible real volume only, not a source association or delivery.
    pub fn real_count(&self) -> usize {
        self.payloads.iter().filter(|p| p.is_real()).count()
    }
    /// Close only the original C link at +44. This is not B release completion;
    /// no producer staging/release is constructed by this preparation owner.
    pub fn poll_cleanup(&mut self) -> Result<bool> {
        self.guard.check(self.schedule)?;
        if Instant::now() < self.schedule.at(44_000_000_000)? {
            return Ok(false);
        }
        if let Some(input) = self.input.take() {
            input.quarantine()?;
        }
        Ok(true)
    }
    #[cfg(test)]
    pub(super) fn fixture_matches(&self, bytes: &[u8]) -> bool {
        self.real_count() == 1
            && self
                .payloads
                .iter()
                .filter_map(Payload::real_bytes)
                .all(|p| p.as_slice() == bytes)
    }
}
impl<P: ClaimPinRetention> Drop for VerifiedIm3Exit<'_, '_, P> {
    fn drop(&mut self) {
        if let Some(input) = self.input.take() {
            let _ = input.quarantine();
        }
    }
}
