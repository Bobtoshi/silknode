//! Separate IM3 stage4 codec/AEAD and complete producer ciphertext ownership.
//! No legacy stage/release conversion; no public key or raw plaintext accessor.
use super::*;
use crate::frame::Payload;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, aead::AeadInOut};
use ed25519_dalek::SigningKey;
use rand_core_06::{OsRng, RngCore};

fn header(c: &MiddleContext<'_>, slot: u32) -> Result<[u8; 64]> {
    let mut h = c.r2.round.header(3, slot)?;
    h[..8].copy_from_slice(b"SNIM3D01");
    h[8..10].copy_from_slice(&1u16.to_le_bytes());
    h[10] = 4;
    Ok(h)
}
fn nonce(c: &MiddleContext<'_>, slot: u32) -> [u8; 12] {
    let mut n = [0; 12];
    n[..8].copy_from_slice(&c.r2.round.manifest.round().to_le_bytes());
    n[8..].copy_from_slice(&slot.to_le_bytes());
    n
}
fn aad(c: &MiddleContext<'_>, header: &[u8; 64]) -> Vec<u8> {
    message(
        "SilkNode-IM3-stage4",
        &[
            &c.r2.round.config.id(),
            &c.profile.id(),
            &c.q.id(),
            &c.r2.round.manifest.id(),
            header,
        ],
    )
}
/// Exact new stage4 encrypted producer frame. Decoding authenticates framing
/// only, not the ciphertext, complete batch, chain, release or timing.
pub struct Im3StagedFrame(Box<[u8; FRAME_BYTES]>);
impl Im3StagedFrame {
    /// Reject legacy/foreign/wrong-order/index/reserved headers and wrong length.
    pub fn decode(bytes: &[u8], c: &MiddleContext<'_>, slot: u32) -> Result<Self> {
        if bytes.len() != FRAME_BYTES || bytes[..64] != header(c, slot)? {
            return Err(Error::Invalid("IM3 stage4 frame/index"));
        }
        let mut b = Box::new([0; FRAME_BYTES]);
        b.copy_from_slice(bytes);
        Ok(Self(b))
    }
    /// Public ciphertext, not producer-exposure or release authority.
    pub fn bytes(&self) -> &[u8; FRAME_BYTES] {
        &self.0
    }
}
fn batch_hash(c: &MiddleContext<'_>, frames: &[Im3StagedFrame; 32]) -> Digest {
    let cfg = c.r2.round.config.id();
    let p = c.profile.id();
    let q = c.q.id();
    let m = c.r2.round.manifest.id();
    let r = c.r2.round.manifest.round().to_le_bytes();
    let mut parts: Vec<&[u8]> = vec![&cfg, &p, &q, &m, &r];
    parts.extend(frames.iter().map(|f| f.bytes().as_slice()));
    domain_hash("SilkNode-IM3-B-batch", &parts)
}
/// Sealed only from the genuine complete IM3 exit, while retaining that one
/// consumed round/native lease/original C link. There is no key export, public
/// release constructor, serialization or conversion to legacy StagedBatch.
pub struct StagedIm3Exit<'s, 't, P: ClaimPinRetention> {
    pub(super) exit: VerifiedIm3Exit<'s, 't, P>,
    pub(super) frames: [Im3StagedFrame; 32],
    pub(super) ready: Im3ReadyChain,
    key: Zeroizing<Digest>,
    real_count: usize,
}
impl<'s, 't, P: ClaimPinRetention> VerifiedIm3Exit<'s, 't, P> {
    /// Fresh single B permutation/key, exact Q-bound stage4 AEAD, and B_READY
    /// for the actual full ciphertext batch, within the original B gate only.
    pub fn stage(
        mut self,
        c: &MiddleContext<'_>,
        signing: &SigningKey,
    ) -> Result<StagedIm3Exit<'s, 't, P>> {
        self.schedule.require(self.guard, Phase::BGate)?;
        if self.binding
            != [
                c.r2.round.config.id(),
                c.profile.id(),
                c.q.id(),
                c.r2.round.manifest.id(),
            ]
            || self.claim.as_ref().is_none_or(|claim| {
                claim.round() != c.r2.round.manifest.round()
                    || claim.binding() != c.profile.claim_binding(ClaimRole::Exit)
            })
        {
            return Err(Error::Invalid("IM3 staged exit binding"));
        }
        let real_count = self.real_count();
        let mut payloads = std::mem::replace(
            &mut self.payloads,
            std::array::from_fn(|_| Payload::cover()),
        );
        shuffle(&mut payloads)?;
        let mut key = Zeroizing::new([0; 32]);
        OsRng
            .try_fill_bytes(key.as_mut())
            .map_err(|_| Error::Unavailable("IM3 stage key entropy"))?;
        if *key == [0; 32] {
            return Err(Error::Unavailable("IM3 zero stage key"));
        }
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| Error::Unavailable("IM3 stage AEAD key"))?;
        let mut frames = Vec::with_capacity(32);
        for (i, payload) in payloads.into_iter().enumerate() {
            self.schedule.require(self.guard, Phase::BGate)?;
            payload.validate(&c.r2.round)?;
            let slot = u32::try_from(i).expect("32");
            let h = header(c, slot)?;
            let p = payload.plaintext(&c.r2.round);
            let mut plain = Zeroizing::new(vec![0; 8112]);
            plain[0] = p[8];
            plain[1..2791].copy_from_slice(&p[64..2854]);
            cipher
                .encrypt_in_place(&Nonce::from(nonce(c, slot)), &aad(c, &h), &mut *plain)
                .map_err(|_| Error::Unavailable("IM3 stage AEAD seal"))?;
            if plain.len() != 8128 {
                return Err(Error::Unavailable("IM3 stage ciphertext size"));
            }
            let mut bytes = [0; FRAME_BYTES];
            bytes[..64].copy_from_slice(&h);
            bytes[64..].copy_from_slice(&plain);
            frames.push(Im3StagedFrame::decode(&bytes, c, slot)?);
        }
        let frames: [Im3StagedFrame; 32] = frames
            .try_into()
            .map_err(|_| Error::Unavailable("IM3 complete stage count"))?;
        let a = Im3Control::verify(self.controls[0].bytes(), c)?;
        let middle = Im3Control::verify(self.controls[1].bytes(), c)?;
        let b = control::sign(
            c,
            Im3Kind::BReady,
            Im3Role::B,
            [
                a.field(116),
                middle.field(148),
                batch_hash(c, &frames),
                middle.id(),
                control::key_commit(c, &key),
                [0; 32],
                [0; 32],
            ],
            signing,
        )?;
        let ready = Im3ReadyChain::verify(c, a, middle, b)?;
        self.schedule.require(self.guard, Phase::BGate)?;
        Ok(StagedIm3Exit {
            exit: self,
            frames,
            ready,
            key,
            real_count,
        })
    }
}
impl<P: ClaimPinRetention> StagedIm3Exit<'_, '_, P> {
    /// Source-free exit volume only. No claim of producer delivery/settlement.
    pub const fn real_count(&self) -> usize {
        self.real_count
    }
    /// Complete identical ciphertext batch for all three original producers.
    pub fn frames(&self) -> &[Im3StagedFrame; 32] {
        &self.frames
    }
    /// All three complete signed readiness controls. These do not disclose key.
    pub fn readiness(&self) -> [&[u8; 512]; 3] {
        self.ready.controls()
    }
    pub(super) fn integrity(&self, c: &MiddleContext<'_>) -> Result<()> {
        self.ready.check(c)?;
        if batch_hash(c, &self.frames) != self.ready.b.field(180)
            || control::key_commit(c, &self.key) != self.ready.b.field(244)
        {
            return Err(Error::Unavailable("IM3 staged integrity"));
        }
        Ok(())
    }
    // Only the actual original B control owner may call this, after consuming
    // and externally pinning the exact authenticated release decision. The key
    // never leaves this module except inside its canonical signed RELEASE.
    pub(super) fn release_control<R: ClaimPinRetention>(
        &self,
        c: &MiddleContext<'_>,
        auth: &Im3Authorization,
        fence: &ConsumedScope<'_, R>,
        signing: &SigningKey,
    ) -> Result<Im3Control> {
        self.exit
            .schedule
            .require(self.exit.guard, Phase::ReleaseDecision)?;
        self.integrity(c)?;
        if auth.chain.ready.b.id() != self.ready.b.id()
            || fence.binding() != c.profile.claim_binding(ClaimRole::Im3Release)
            || fence.round() != c.r2.round.manifest.round()
            || fence.manifest() != c.r2.round.manifest.id()
            || fence.message() != super::cycle::release_choice(c, auth)
        {
            return Err(Error::Invalid("IM3 durable release fence"));
        }
        let mut fields = Zeroizing::new(super::cycle::terminal_fields(
            &auth.chain,
            auth.control.id(),
        ));
        fields[5] = *self.key;
        let control = control::sign(c, Im3Kind::Release, Im3Role::B, *fields, signing)?;
        self.exit
            .schedule
            .require(self.exit.guard, Phase::ReleaseDecision)?;
        Ok(control)
    }
}
/// Only an actual producer receive owner may construct this whole-batch
/// capability. Public frame arrays, counts and READY hashes cannot substitute.
pub(super) struct CompleteIm3StagedBatch {
    pub(super) frames: [Im3StagedFrame; 32],
    pub(super) ready: Im3ReadyChain,
}
impl CompleteIm3StagedBatch {
    pub(super) fn collect(
        c: &MiddleContext<'_>,
        frames: [Im3StagedFrame; 32],
        ready: Im3ReadyChain,
    ) -> Result<Self> {
        ready.check(c)?;
        for (i, f) in frames.iter().enumerate() {
            Im3StagedFrame::decode(f.bytes(), c, u32::try_from(i).expect("32"))?;
        }
        if batch_hash(c, &frames) != ready.b.field(180) {
            return Err(Error::Invalid("IM3 complete producer batch"));
        }
        Ok(Self { frames, ready })
    }
    // The sole eventual caller is the native producer owner, AFTER its actual
    // original RELEASE read. No public raw opening or node-handoff API exists.
    pub(super) fn open(
        self,
        c: &MiddleContext<'_>,
        release: &Im3Release,
        schedule: &Im3Schedule,
        guard: &Im3Guard,
    ) -> Result<[Payload; 32]> {
        schedule.require(guard, Phase::ProducerOpen)?;
        if schedule.round() != c.r2.round.manifest.round() {
            return Err(Error::Invalid("IM3 producer opening round"));
        }
        if release.authorization.chain.ready.b.id() != self.ready.b.id()
            || batch_hash(c, &self.frames) != self.ready.b.field(180)
        {
            return Err(Error::Invalid("IM3 producer release/batch"));
        }
        let key = Zeroizing::new(release.control.field(276));
        if control::key_commit(c, &key) != self.ready.b.field(244) {
            return Err(Error::Invalid("IM3 producer release key"));
        }
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| Error::Unavailable("IM3 producer AEAD key"))?;
        let mut payloads = Vec::with_capacity(32);
        for (i, f) in self.frames.into_iter().enumerate() {
            schedule.require(guard, Phase::ProducerOpen)?;
            let slot = u32::try_from(i).expect("32");
            let mut plain = Zeroizing::new(f.bytes()[64..].to_vec());
            cipher
                .decrypt_in_place(
                    &Nonce::from(nonce(c, slot)),
                    &aad(c, &header(c, slot)?),
                    &mut *plain,
                )
                .map_err(|_| Error::Invalid("IM3 producer AEAD authentication"))?;
            if plain.len() != 8112 || plain[2791..].iter().any(|v| *v != 0) {
                return Err(Error::Invalid("IM3 producer padding"));
            }
            let mut p = Payload::cover().plaintext(&c.r2.round);
            p[8] = plain[0];
            p[64..2854].copy_from_slice(&plain[1..2791]);
            payloads.push(Payload::decode(p.as_ref(), &c.r2.round)?);
        }
        schedule.require(guard, Phase::ProducerOpen)?;
        payloads
            .try_into()
            .map_err(|_| Error::Invalid("IM3 complete producer opening"))
    }
}
