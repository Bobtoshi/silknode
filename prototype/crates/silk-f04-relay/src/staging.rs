//! One fresh B permutation/key/batch; no persistence, timed release or retry path.
use crate::{
    Digest, Error, Result,
    control::{Kind, ReadyPairEvidence, ReleaseEvidence, SignedControl},
    field,
    frame::{FRAME_BYTES, Frame, HpkePrivate, Payload, RoundContext, open_b, shuffle},
    message,
};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, aead::AeadInOut};
use rand_core_06::{OsRng, RngCore};
use silk_sapling_f04::{
    codec::{EnvelopeView, domain_hash},
    crypto::verify_borrowed,
    parameters::SaplingVerificationKeys,
};
use std::{collections::BTreeSet, time::Instant};
use zeroize::{Zeroize, Zeroizing};

/// B's complete sealed output.
///
/// The SAME ciphertext batch is copied to all three
/// producers; no per-producer re-encryption or persisted release key exists here.
/// Private key access is withheld pending the stateful durable-release component.
pub struct StagedBatch {
    frames: [Frame; 32],
    key: Zeroizing<[u8; 32]>,
    id: Digest,
    key_commit: Digest,
}

/// Complete B plaintext batch whose real envelopes passed genuine Sapling checks.
/// No session/source labels exist here. This is not a timely readiness decision.
pub struct VerifiedExitBatch {
    payloads: [Payload; 32],
    config: Digest,
    manifest: Digest,
}
impl VerifiedExitBatch {
    /// Consume one complete A batch; verify every HPKE layer, cut and real proof.
    ///
    /// The deadline is only a cooperative completion barrier: the role runtime
    /// must independently impose its native CPU/RSS/thread limits. No partial
    /// success object escapes. Mutable ledger spentness is deliberately not read.
    /// # Errors
    /// Refuses mismatched readiness, duplicate encapsulations, crypto or expiry.
    pub fn verify(
        context: &RoundContext<'_>,
        private: &HpkePrivate,
        frames: [Frame; 32],
        a_ready: &SignedControl,
        keys: &SaplingVerificationKeys,
        deadline: Instant,
    ) -> Result<Self> {
        completion_time(deadline)?;
        let control = a_ready.bytes();
        if a_ready.kind() != Kind::AReady
            || control[10] != 1
            || control[248] < 8
            || control[12..44] != context.config.domain()
            || control[44..76] != context.config.id()
            || control[76..80] != context.manifest.bytes()[40..44]
            || control[80..88] != context.manifest.bytes()[44..52]
            || control[88..120] != context.manifest.id()
            || control[120..152] != a_batch_id(context, &frames)?
        {
            return Err(Error::Invalid("B complete A readiness"));
        }
        let mut encapsulations = BTreeSet::new();
        let mut payloads = Vec::with_capacity(32);
        for frame in frames {
            completion_time(deadline)?;
            if !encapsulations.insert(frame.encapsulation()?) {
                return Err(Error::Invalid("B duplicate encapsulation"));
            }
            let payload = open_b(context, private, &frame)?;
            if let Some(bytes) = payload.real_bytes() {
                let envelope = EnvelopeView::decode(bytes, &context.config.domain())
                    .map_err(|_| Error::Invalid("B envelope framing"))?;
                verify_borrowed(&envelope, keys).map_err(|error| match error {
                    silk_sapling_f04::Error::Encoding(_) | silk_sapling_f04::Error::Crypto(_) => {
                        Error::Invalid("B Sapling verification")
                    }
                    _ => Error::Unavailable("B Sapling local capability"),
                })?;
            }
            completion_time(deadline)?;
            payloads.push(payload);
        }
        Ok(Self {
            payloads: payloads
                .try_into()
                .map_err(|_| Error::Unavailable("B batch length"))?,
            config: context.config.id(),
            manifest: context.manifest.id(),
        })
    }
    /// Independently permute and seal only this exact completely verified batch.
    /// # Errors
    /// Refuses changed round context or staging/entropy errors.
    pub fn seal(self, context: &RoundContext<'_>) -> Result<StagedBatch> {
        if self.config != context.config.id() || self.manifest != context.manifest.id() {
            return Err(Error::Invalid("B verified batch context"));
        }
        StagedBatch::seal(context, self.payloads)
    }
}
fn completion_time(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        return Err(Error::Unavailable("B original verification deadline"));
    }
    Ok(())
}

/// Producer-owned complete ordered ciphertext batch. No key or plaintext exists
/// here, so possession can precede the producer's scheduled ACK.
pub struct CompleteStagedBatch {
    frames: [Frame; 32],
    id: Digest,
}
impl CompleteStagedBatch {
    /// Consume exactly all32 correctly indexed cells and match signed readiness.
    /// A caller must finish this before its fixed ACK observation/send barrier.
    /// # Errors
    /// Refuses any frame/context/order/full-batch/readiness mismatch.
    pub fn collect(
        context: &RoundContext<'_>,
        frames: [Frame; 32],
        pair: &ReadyPairEvidence<'_>,
    ) -> Result<Self> {
        for (i, frame) in frames.iter().enumerate() {
            let _ = Frame::decode(
                frame.bytes(),
                context,
                3,
                u32::try_from(i).map_err(|_| Error::Invalid("stage3 slot"))?,
            )?;
        }
        let id = batch_hash("SilkNode-F0-B-batch", context, &frames);
        let control = pair.b().bytes();
        if control[12..44] != context.config.domain()
            || control[44..76] != context.config.id()
            || control[88..120] != context.manifest.id()
            || control[152..184] != id
        {
            return Err(Error::Invalid("producer complete batch/readiness"));
        }
        Ok(Self { frames, id })
    }
    /// Full ordered batch commitment, established by hashing locally retained data.
    #[must_use]
    pub const fn id(&self) -> Digest {
        self.id
    }
    /// All-or-nothing opening after complete release reference verification.
    /// # Errors
    /// Same crypto/context refusals as `open_batch`; deadlines remain external.
    pub fn open(
        self,
        context: &RoundContext<'_>,
        release: &ReleaseEvidence<'_>,
    ) -> Result<[Payload; 32]> {
        open_batch(context, release, &self.frames)
    }
}
impl Drop for StagedBatch {
    fn drop(&mut self) {
        // Explicitly erase this retained owner before its other fields are dropped.
        // Upstream cryptographic temporaries are not covered by this statement.
        self.key.zeroize();
    }
}
impl StagedBatch {
    /// Independently permute a source-label-free32-cell exit view, choose one fresh
    /// OS key, and encrypt each new output slot exactly once with r||slot nonces.
    /// # Errors
    /// Refuses context, entropy, AEAD or fixed-size failures; returns no partial batch.
    pub fn seal(context: &RoundContext<'_>, mut payloads: [Payload; 32]) -> Result<Self> {
        shuffle(&mut payloads)?;
        let mut key = Zeroizing::new([0; 32]);
        OsRng
            .try_fill_bytes(key.as_mut())
            .map_err(|_| Error::Unavailable("release key entropy"))?;
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| Error::Unavailable("release AEAD key"))?;
        let mut frames = Vec::with_capacity(32);
        for (i, payload) in payloads.into_iter().enumerate() {
            let slot = u32::try_from(i).map_err(|_| Error::Unavailable("stage3 slot"))?;
            let header = context.header(3, slot)?;
            let plain = payload.plaintext(context);
            // Recheck the real envelope's cut/domain against the current manifest.
            payload.validate(context)?;
            let mut staged = Zeroizing::new(vec![0; 8112]);
            staged[0] = plain[8];
            staged[1..2791].copy_from_slice(&plain[64..2854]);
            cipher
                .encrypt_in_place(
                    &Nonce::from(nonce(context, slot)),
                    &aad(context, &header),
                    &mut *staged,
                )
                .map_err(|_| Error::Unavailable("stage3 AEAD seal"))?;
            if staged.len() != 8128 {
                return Err(Error::Unavailable("stage3 ciphertext size"));
            }
            let mut bytes = [0; FRAME_BYTES];
            bytes[..64].copy_from_slice(&header);
            bytes[64..].copy_from_slice(&staged);
            frames.push(Frame::decode(&bytes, context, 3, slot)?);
        }
        let frames: [Frame; 32] = frames
            .try_into()
            .map_err(|_| Error::Unavailable("stage3 batch size"))?;
        Ok(Self {
            id: batch_hash("SilkNode-F0-B-batch", context, &frames),
            key_commit: domain_hash(
                "SilkNode-F0-release-key",
                &[&context.config.id(), &context.manifest.id(), key.as_ref()],
            ),
            frames,
            key,
        })
    }
    /// Immutable identical ciphertext output for all three producer channels.
    #[must_use]
    pub const fn frames(&self) -> &[Frame; 32] {
        &self.frames
    }
    /// Exact full ordered stage3 batch hash.
    #[must_use]
    pub const fn id(&self) -> Digest {
        self.id
    }
    /// Commitment to the volatile release key under this cfg/manifest.
    #[must_use]
    pub const fn key_commit(&self) -> Digest {
        self.key_commit
    }
    #[cfg(unix)]
    pub(crate) fn release_control(
        &self,
        context: &RoundContext<'_>,
        identity: &crate::owner::Identity,
        authorization: &crate::control::AuthorizationEvidence<'_>,
    ) -> Result<SignedControl> {
        identity.check(context.config, crate::control::Role::B)?;
        let auth = authorization.control().bytes();
        if auth[44..76] != context.config.id()
            || auth[88..120] != context.manifest.id()
            || auth[152..184] != self.id
            || auth[256..288] != self.key_commit
            || batch_hash("SilkNode-F0-B-batch", context, &self.frames) != self.id
            || domain_hash(
                "SilkNode-F0-release-key",
                &[
                    &context.config.id(),
                    &context.manifest.id(),
                    self.key.as_ref(),
                ],
            ) != self.key_commit
        {
            return Err(Error::Unavailable("B pre-release batch/key integrity"));
        }
        let mut body = Zeroizing::new([0; 448]);
        body.copy_from_slice(&auth[..448]);
        body[288..320].copy_from_slice(self.key.as_ref());
        identity.control(
            context.config,
            context.manifest.round(),
            Kind::Release,
            &body,
        )
    }
    // There is intentionally no public key accessor/serialization/retry method.
    #[cfg(test)]
    pub(crate) fn fixture_key(&self) -> &[u8; 32] {
        &self.key
    }
}

fn nonce(context: &RoundContext<'_>, slot: u32) -> [u8; 12] {
    let mut nonce = [0; 12];
    nonce[..8].copy_from_slice(&context.manifest.round().to_le_bytes());
    nonce[8..].copy_from_slice(&slot.to_le_bytes());
    nonce
}
fn aad(context: &RoundContext<'_>, header: &[u8; 64]) -> Vec<u8> {
    message(
        "SilkNode-F0-stage3",
        &[&context.config.id(), &context.manifest.id(), header],
    )
}
fn batch_hash(label: &'static str, context: &RoundContext<'_>, frames: &[Frame; 32]) -> Digest {
    let cfg = context.config.id();
    let mh = context.manifest.id();
    let mut parts: Vec<&[u8]> = Vec::with_capacity(34);
    parts.extend([cfg.as_slice(), mh.as_slice()]);
    parts.extend(frames.iter().map(|frame| frame.bytes().as_slice()));
    domain_hash(label, &parts)
}

/// Exact ordered A batch hash after validating all32 fixed stage2 contexts.
/// This hash is neither a possession proof nor a readiness/clock assertion.
/// # Errors
/// Refuses any foreign stage/context/padding.
pub fn a_batch_id(context: &RoundContext<'_>, frames: &[Frame; 32]) -> Result<Digest> {
    for frame in frames {
        let _ = Frame::decode(frame.bytes(), context, 2, 0)?;
    }
    Ok(batch_hash("SilkNode-F0-A-batch", context, frames))
}

/// Open ALL32 stage3 records only after complete control-chain/key verification.
///
/// No partial plaintext result escapes on error. This component still requires
/// an outer fixed-phase receiver, full-batch ACK discipline and bounded queue;
/// it does not itself grant a timely producer-exposure capability.
/// # Errors
/// Refuses context/batch/order/key/AEAD/plaintext mismatches, without partial output.
pub fn open_batch(
    context: &RoundContext<'_>,
    evidence: &ReleaseEvidence<'_>,
    frames: &[Frame; 32],
) -> Result<[Payload; 32]> {
    let control = evidence.control().bytes();
    if control[44..76] != context.config.id()
        || control[88..120] != context.manifest.id()
        || field::<32>(control, 152)? != batch_hash("SilkNode-F0-B-batch", context, frames)
    {
        return Err(Error::Invalid("released batch/context mismatch"));
    }
    let key = Zeroizing::new(field::<32>(control, 288)?);
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| Error::Unavailable("release AEAD key"))?;
    let mut payloads = Vec::with_capacity(32);
    for (i, frame) in frames.iter().enumerate() {
        let slot = u32::try_from(i).map_err(|_| Error::Unavailable("stage3 slot"))?;
        let checked = Frame::decode(frame.bytes(), context, 3, slot)?;
        let header = context.header(3, slot)?;
        let mut plain = Zeroizing::new(checked.bytes()[64..].to_vec());
        cipher
            .decrypt_in_place(
                &Nonce::from(nonce(context, slot)),
                &aad(context, &header),
                &mut *plain,
            )
            .map_err(|_| Error::Invalid("stage3 AEAD authentication"))?;
        if plain.len() != 8112 || plain[2791..].iter().any(|byte| *byte != 0) {
            return Err(Error::Invalid("stage3 plaintext padding"));
        }
        let mut b_plain = Payload::cover().plaintext(context);
        b_plain[8] = plain[0];
        b_plain[64..2854].copy_from_slice(&plain[1..2791]);
        payloads.push(Payload::decode(b_plain.as_ref(), context)?);
    }
    payloads
        .try_into()
        .map_err(|_| Error::Unavailable("complete opened batch size"))
}
